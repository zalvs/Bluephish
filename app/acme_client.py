"""Let's Encrypt (ACME, RFC 8555) para o certificado do vhost, com renovação automática.

Configurações → Certificados → Let's Encrypt: nomes, e-mail, produção ou staging
e "renovar sozinho". O desafio é o HTTP-01: a Let's Encrypt pede
`http://<nome>/.well-known/acme-challenge/<token>`, e o vhost serve essa pasta
(cert_store.challenge_dir) na porta 80. O certificado emitido passa pela mesma
validação de um importado (cert_store.install_issued) e o vhost o recarrega
sozinho.

Cinco decisões que não são óbvias lendo o código:

1. **A porta 80 tem de chegar da internet.** Uma instalação só interna (o caso de
   muito SOC) não consegue o HTTP-01; a tela diz isso, e o certificado de uma CA
   corporativa entra por PEM ou PFX.

2. **Staging por padrão, e staging é ensaio.** A produção da Let's Encrypt limita
   as emissões por domínio por semana, e uma configuração errada repetida queima o
   limite. O staging faz o pedido inteiro — desafio, emissão, validação da cadeia
   — e registra que deu certo (`stagingOkAt`), mas **não instala** o certificado:
   instalar um certificado de teste por cima de um de produção seria, com o HSTS
   já gravado nos navegadores, trancar todo mundo fora. Passar para produção é um
   clique explícito.

3. **Conta RSA, assinatura RS256.** Com ES256 a assinatura que a biblioteca devolve
   está em DER e o JWS pede `r||s` cru — o erro clássico que só aparece como
   "badSignature" do servidor. RS256 não tem essa conversão. A chave da conta fica
   em certs/private/acme-account.key.

4. **Só os hosts do diretório.** A URL do diretório é fixa (produção ou staging), e
   toda URL que o servidor devolve (pedido, autorização, desafio, certificado)
   tem de estar no mesmo host, sem redirect seguido: um diretório adulterado não
   manda a chave da conta assinar pedidos para outro lugar.

5. **Renovação: a cada 12 h, faltando 30 dias.** `renew_if_due` roda num laço da
   aplicação; depois de uma falha, espera 12 h antes de tentar de novo, e a falha
   fica no estado (`lastError`), que a tela mostra.
"""

import base64
import datetime
import hashlib
import json
import logging
import os
import time
import urllib.parse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import cert_store

log = logging.getLogger('acme_client')

PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory'
STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
TIMEOUT_SECONDS = 15
POLL_SECONDS = 2
POLL_ATTEMPTS = 30
RENEW_DAYS = 30
RETRY_HOURS = 12


class AcmeError(Exception):
	pass


def _b64(data):
	if isinstance(data, str):
		data = data.encode('utf-8')
	return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _int_bytes(number):
	return number.to_bytes((number.bit_length() + 7) // 8, 'big')


def account_key():
	path = os.path.join(cert_store.root(), 'private', 'acme-account.key')
	if os.path.isfile(path):
		with open(path, 'rb') as handle:
			return serialization.load_pem_private_key(handle.read(), None)
	key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
	cert_store.write_file(path, cert_store.key_pem(key), private = True)
	return key


def jwk(key):
	numbers = key.public_key().public_numbers()
	return {'e': _b64(_int_bytes(numbers.e)), 'kty': 'RSA', 'n': _b64(_int_bytes(numbers.n))}


def thumbprint_of_jwk(public_jwk):
	"""RFC 7638: SHA-256 do JWK com as chaves obrigatórias, em ordem, sem espaços."""
	required = {name: public_jwk[name] for name in ('e', 'kty', 'n')}
	return _b64(hashlib.sha256(json.dumps(required, sort_keys = True, separators = (',', ':')).encode()).digest())


def thumbprint(key):
	return thumbprint_of_jwk(jwk(key))


class Client(object):

	def __init__(self, directory_url, key, http = None):
		self.http = http or requests
		self.key = key
		self.kid = None
		self.host = urllib.parse.urlsplit(directory_url).netloc
		self.directory = self._json(self._get(directory_url))

	def _check(self, url):
		parts = urllib.parse.urlsplit(str(url or ''))
		if parts.scheme != 'https' or parts.netloc != self.host:
			raise AcmeError('o servidor ACME apontou para fora do diretório: {0}'.format(str(url)[:120]))
		return url

	def _get(self, url):
		return self.http.get(self._check(url), timeout = TIMEOUT_SECONDS, allow_redirects = False)

	@staticmethod
	def _json(response):
		if response.status_code >= 400:
			raise AcmeError('ACME respondeu {0}: {1}'.format(response.status_code, response.text[:300]))
		return response.json()

	def _nonce(self):
		response = self.http.head(self._check(self.directory['newNonce']), timeout = TIMEOUT_SECONDS, allow_redirects = False)
		nonce = response.headers.get('Replay-Nonce')
		if not nonce:
			raise AcmeError('o servidor ACME não deu nonce')
		return nonce

	def post(self, url, payload):
		"""JWS RS256 (RFC 8555 §6.2). payload None é o POST-as-GET."""
		protected = {'alg': 'RS256', 'nonce': self._nonce(), 'url': self._check(url)}
		if self.kid:
			protected['kid'] = self.kid
		else:
			protected['jwk'] = jwk(self.key)
		body64 = '' if payload is None else _b64(json.dumps(payload))
		for attempt in (1, 2):
			protected['nonce'] = protected['nonce'] if attempt == 1 else self._nonce()
			head64 = _b64(json.dumps(protected))
			signature = self.key.sign('{0}.{1}'.format(head64, body64).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
			response = self.http.post(url, data = json.dumps({'protected': head64, 'payload': body64, 'signature': _b64(signature)}),
				headers = {'Content-Type': 'application/jose+json'}, timeout = TIMEOUT_SECONDS, allow_redirects = False)
			# badNonce acontece de vez em quando (RFC 8555 §6.5): uma nova tentativa
			# com nonce novo, e só uma
			if response.status_code == 400 and 'badNonce' in (response.text or '') and attempt == 1:
				continue
			break
		if response.status_code >= 400:
			raise AcmeError('ACME respondeu {0}: {1}'.format(response.status_code, response.text[:300]))
		return response

	def register(self, email):
		payload = {'termsOfServiceAgreed': True}
		if email:
			payload['contact'] = ['mailto:' + email]
		response = self.post(self.directory['newAccount'], payload)
		self.kid = self._check(response.headers.get('Location'))

	def _poll(self, url, done, failed):
		for _ in range(POLL_ATTEMPTS):
			body = self.post(url, None).json()
			if body.get('status') in done:
				return body
			if body.get('status') in failed:
				raise AcmeError('ACME recusou: {0}'.format(json.dumps(body.get('error') or body)[:300]))
			time.sleep(POLL_SECONDS)
		raise AcmeError('ACME não concluiu a tempo')

	def issue(self, names, certificate_key):
		order_response = self.post(self.directory['newOrder'], {'identifiers': [{'type': 'dns', 'value': name} for name in names]})
		order = order_response.json()
		order_url = self._check(order_response.headers.get('Location'))
		written = []
		try:
			for authorization_url in order.get('authorizations') or []:
				authorization = self.post(self._check(authorization_url), None).json()
				if authorization.get('status') == 'valid':
					continue
				challenge = next((item for item in authorization.get('challenges') or [] if item.get('type') == 'http-01'), None)
				if challenge is None:
					raise AcmeError('o servidor ACME não ofereceu o desafio HTTP-01')
				token = str(challenge.get('token') or '')
				if not token or not all(char.isalnum() or char in '-_' for char in token):
					raise AcmeError('token de desafio inválido')
				path = os.path.join(cert_store.challenge_dir(), token)
				cert_store.write_file(path, '{0}.{1}'.format(token, thumbprint(self.key)).encode('ascii'))
				written.append(path)
				self.post(self._check(challenge['url']), {})
				self._poll(authorization_url, ('valid',), ('invalid', 'revoked', 'expired', 'deactivated'))
			csr = (x509.CertificateSigningRequestBuilder()
				.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
				.add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical = False)
				.sign(certificate_key, hashes.SHA256()))
			self.post(self._check(order['finalize']), {'csr': _b64(csr.public_bytes(serialization.Encoding.DER))})
			order = self._poll(order_url, ('valid',), ('invalid',))
			return self.post(self._check(order['certificate']), None).content
		finally:
			for path in written:
				try:
					os.remove(path)
				except OSError:
					pass


def _update_settings(changes):
	state = cert_store.load_state()
	entry = dict(state.get(cert_store.VHOST) or {})
	settings = dict(entry.get('letsencrypt') or {})
	settings.update(changes)
	entry['letsencrypt'] = settings
	state[cert_store.VHOST] = entry
	cert_store.save_state(state)
	return settings


def settings():
	return dict((cert_store.load_state().get(cert_store.VHOST) or {}).get('letsencrypt') or {})


def save_settings(domains, email, staging, auto_renew):
	return _update_settings({'domains': domains, 'email': email, 'staging': bool(staging), 'autoRenew': bool(auto_renew)})


def _record(error):
	_update_settings({'lastAttempt': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), 'lastError': error})


def issue_now(http = None, production = None):
	"""Emite (ou renova) o certificado do vhost com o que está configurado.

	No staging, devolve {'staging': True, ...} sem instalar nada (decisão 2).
	"""
	current = settings()
	# A renovação passa production=True: só o de produção é instalado, e é ele
	# que se renova, seja qual for o interruptor da tela agora
	staging = current.get('staging', True) if production is None else not production
	names, error = cert_store.validate_names(current.get('domains') or [], allow_ip = False)
	if error:
		raise AcmeError(error)
	try:
		client = Client(STAGING if staging else PRODUCTION, account_key(), http)
		client.register(current.get('email') or '')
		key = cert_store.new_key()
		chain = client.issue(names, key)
		if staging:
			cert_store.check_issued(chain, key)
		else:
			result = cert_store.install_issued(cert_store.VHOST, chain, key)
	except (AcmeError, cert_store.CertError, requests.RequestException, ValueError, KeyError) as failure:
		_record(str(failure)[:300])
		log.error('Let\'s Encrypt falhou: %s', failure)
		raise AcmeError(str(failure))
	_record(None)
	if staging:
		_update_settings({'stagingOkAt': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')})
		log.info('ensaio no staging da Let\'s Encrypt deu certo para %s; nada foi instalado', ', '.join(names))
		return {'staging': True, 'names': names}
	log.info('certificado do vhost emitido pela Let\'s Encrypt para %s', ', '.join(names))
	return result


def renew_if_due(now = None, http = None):
	"""Renova quando faltam RENEW_DAYS. Devolve 'renewed', 'failed' ou None."""
	entry = cert_store.load_state().get(cert_store.VHOST) or {}
	current = settings()
	if entry.get('source') != cert_store.SOURCE_LETSENCRYPT or not current.get('autoRenew'):
		return None
	left = cert_store.days_left(cert_store.VHOST)
	if left is not None and left > RENEW_DAYS:
		return None
	now = now or datetime.datetime.utcnow()
	if current.get('lastError') and current.get('lastAttempt'):
		try:
			last = datetime.datetime.strptime(current['lastAttempt'], '%Y-%m-%d %H:%M:%S')
			if now - last < datetime.timedelta(hours = RETRY_HOURS):
				return None
		except ValueError:
			pass
	try:
		issue_now(http, production = True)
	except AcmeError:
		return 'failed'
	return 'renewed'
