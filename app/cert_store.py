"""Os certificados TLS da instalação: o do vhost (público) e o interno (frontend ↔ API).

Configurações → Certificados (global_admin) lista os dois e troca cada um. Este
módulo faz o trabalho com a biblioteca `cryptography`; quem fala com a Let's
Encrypt é acme_client.py.

Onde cada coisa mora, numa pasta só (`certs/`, montada no contêiner da API em
`/root/thephish/certs` e, em partes e somente leitura, nos outros dois):

    vhost/fullchain.pem, vhost/privkey.pem   o certificado público; o vhost lê
    trust/ca.pem                             o pacote de confiança: a CA interna atual e a anterior
    acme/.well-known/acme-challenge/<token>  o desafio HTTP-01; o vhost serve na porta 80
    private/ca.pem, private/ca.key           a CA interna atual e a chave dela — só a API as vê
    private/api.pem, private/api.key         o certificado interno da API, emitido pela CA
    private/acme-account.key, private/state.json   conta e estado da Let's Encrypt

Cinco decisões que não são óbvias lendo o código:

1. **Dois certificados diferentes, de propósito.** O do vhost é o que o navegador
   vê, e pode ser da Let's Encrypt, de uma CA corporativa ou autoassinado. O da
   API é emitido por uma CA interna que só existe nesta instalação: o frontend
   só aceita uma API cujo certificado essa CA assinou, e a chave dessa CA nunca
   sai da pasta `private/`, que só a API monta. Trocar o do vhost não mexe no
   interno, e vice-versa.

2. **A chave privada nunca volta para o navegador.** A tela recebe assunto,
   emissor, nomes, validade e a impressão digital; a chave entra pelo formulário
   e vai direto para o disco, com permissão 0600.

3. **Validado antes de gravar, e gravado inteiro ou não gravado.** A chave tem de
   ser do certificado; o certificado não pode estar vencido; a cadeia é posta na
   ordem (folha primeiro) e cada elo tem de ter assinado o anterior. Um par que
   não serve deixaria o vhost sem subir no próximo reinício. Os arquivos são
   escritos ao lado e trocados com os.replace: o vhost nunca lê meio arquivo.

4. **Quem recarrega é o vhost, sozinho.** Não há socket do Docker na API (quem tem
   o socket é root no host). O vhost e o frontend conferem a cada 30 s o hash dos
   arquivos que leem e, se mudou, rodam `nginx -t && nginx -s reload`
   (docker/nginx/reload-on-change.sh). O certificado interno é lido pela API ao
   subir: trocá-lo vale no próximo reinício dela, e a tela diz isso.

5. **Os nomes do certificado vêm do formulário, e são conferidos.** Só nomes DNS
   (e, no autoassinado, IPs): nada de curinga, espaço ou barra. O mesmo
   validador serve a Let's Encrypt, que só emite para nomes que ela alcança.

6. **Trocar a CA interna não derruba o painel.** O frontend relê trust/ca.pem em
   até 30 s, mas a API só troca de certificado quando reinicia. Se o pacote
   tivesse só a CA nova, nesse intervalo o frontend recusaria a API — 502 em tudo,
   inclusive na tela que pediu a troca. O pacote leva a CA nova e a anterior.

7. **Um certificado de CA não é trocado por um autoassinado sem confirmação.**
   Servido um certificado válido, os navegadores gravam o HSTS de dois anos do
   vhost; um autoassinado depois disso é erro de certificado sem botão de
   "continuar", e ninguém chega mais à tela que desfaria a troca. A recusa
   (NeedsConfirmation) diz isso, e só passa com a confirmação explícita. A saída
   de um terminal é `manage.py cert-import`.
"""

import datetime
import ipaddress
import json
import logging
import os
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger('cert_store')

ROOT_ENV = 'BLUEPHISH_CERTS_PATH'

VHOST = 'vhost'
INTERNAL = 'internal'
TARGETS = (VHOST, INTERNAL)

SOURCE_SELF_SIGNED = 'selfsigned'
SOURCE_PEM = 'pem'
SOURCE_PFX = 'pfx'
SOURCE_LETSENCRYPT = 'letsencrypt'
SOURCE_INTERNAL_CA = 'internal-ca'

# O nome que o frontend usa para chegar na API (o serviço do compose). Tem de
# estar no certificado interno: o frontend confere (proxy_ssl_name)
API_NAMES = ('bluephish', 'api', 'localhost')
SELF_SIGNED_DAYS = 397
INTERNAL_DAYS = 825
CA_DAYS = 3650
MAX_UPLOAD_BYTES = 256 * 1024
MAX_NAMES = 20
_HOSTNAME = re.compile(r'(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*')


class CertError(Exception):
	pass


class NeedsConfirmation(CertError):
	"""Troca de um certificado de CA por um autoassinado: só com confirmação (decisão 7)."""


def root():
	return os.environ.get(ROOT_ENV) or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')


def _path(*parts):
	return os.path.join(root(), *parts)


def paths(target):
	if target == VHOST:
		return _path('vhost', 'fullchain.pem'), _path('vhost', 'privkey.pem')
	if target == INTERNAL:
		return _path('private', 'api.pem'), _path('private', 'api.key')
	raise CertError('certificado desconhecido: {0}'.format(target))


def ca_paths():
	"""(certificado, chave) da CA interna atual."""
	return _path('private', 'ca.pem'), _path('private', 'ca.key')


def trust_path():
	"""O pacote em que o frontend confia: a CA atual e a anterior (decisão 6)."""
	return _path('trust', 'ca.pem')


def challenge_dir():
	return _path('acme', '.well-known', 'acme-challenge')


def state_path():
	return _path('private', 'state.json')


def _now():
	return datetime.datetime.utcnow()


def write_file(path, data, private = False):
	"""Grava ao lado e troca, para quem lê nunca ver meio arquivo. Chave: 0600."""
	directory = os.path.dirname(path)
	os.makedirs(directory, exist_ok = True)
	if os.path.basename(directory) == 'private':
		os.chmod(directory, 0o700)
	temporary = path + '.tmp'
	handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
	try:
		os.write(handle, data)
		os.fsync(handle)
	finally:
		os.close(handle)
	os.replace(temporary, path)


def load_state():
	try:
		with open(state_path()) as handle:
			state = json.load(handle)
		return state if isinstance(state, dict) else {}
	except (OSError, ValueError):
		return {}


def save_state(state):
	write_file(state_path(), json.dumps(state, indent = '\t').encode('utf-8'), private = True)


def _set_source(target, source):
	state = load_state()
	entry = dict(state.get(target) or {})
	entry.update({'source': source, 'updatedAt': _now().strftime('%Y-%m-%d %H:%M:%S')})
	state[target] = entry
	save_state(state)


# --- Nomes --------------------------------------------------------------------

def validate_names(raw, allow_ip = True):
	"""(nomes normalizados, erro). Aceita lista ou texto separado por vírgula/linha."""
	if isinstance(raw, str):
		raw = re.split(r'[\s,]+', raw)
	names = []
	for item in raw or ():
		name = str(item).strip().lower().rstrip('.')
		if not name:
			continue
		try:
			ipaddress.ip_address(name)
			if not allow_ip:
				return None, '"{0}" é um IP; a Let\'s Encrypt só emite para nomes.'.format(name)
		except ValueError:
			if not _HOSTNAME.fullmatch(name):
				return None, '"{0}" não é um nome de host válido.'.format(name[:80])
		if name not in names:
			names.append(name)
	if not names:
		return None, 'Informe ao menos um nome.'
	if len(names) > MAX_NAMES:
		return None, 'No máximo {0} nomes por certificado.'.format(MAX_NAMES)
	return names, None


def _san(names):
	entries = []
	for name in names:
		try:
			entries.append(x509.IPAddress(ipaddress.ip_address(name)))
		except ValueError:
			entries.append(x509.DNSName(name))
	return x509.SubjectAlternativeName(entries)


# --- Geração --------------------------------------------------------------------

def new_key():
	return ec.generate_private_key(ec.SECP256R1())


def key_pem(key):
	return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _cert_pem(cert):
	return cert.public_bytes(serialization.Encoding.PEM)


def _builder(subject, issuer_name, public_key, days):
	"""`subject` é um nome comum (texto) ou um x509.Name inteiro."""
	now = _now()
	if not isinstance(subject, x509.Name):
		subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject[:64])])
	return (x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer_name)
		.public_key(public_key)
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - datetime.timedelta(minutes = 5))
		.not_valid_after(now + datetime.timedelta(days = days)))


def _guard_downgrade(target, new_leaf_self_signed, confirmed):
	if target != VHOST or not new_leaf_self_signed or confirmed:
		return
	current = describe(VHOST)
	if current.get('present') and not current.get('selfSigned'):
		raise NeedsConfirmation('O certificado atual do vhost é de uma CA ({0}). Os navegadores que já o viram guardaram '
			'o HSTS de dois anos e não deixam passar de um autoassinado: quem abrir o painel verá um erro sem botão de '
			'continuar, inclusive para desfazer a troca. Confirme só se ninguém usa o certificado atual.'.format(current.get('issuer')))


def generate_self_signed(names, confirmed = False):
	"""Autoassinado para o vhost. Serve para começar; o navegador avisa."""
	names, error = validate_names(names)
	if error:
		raise CertError(error)
	_guard_downgrade(VHOST, True, confirmed)
	key = new_key()
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64])])
	cert = (_builder(names[0], name, key.public_key(), SELF_SIGNED_DAYS)
		.add_extension(_san(names), critical = False)
		.add_extension(x509.BasicConstraints(ca = False, path_length = None), critical = True)
		.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical = False)
		.sign(key, hashes.SHA256()))
	_install(VHOST, [cert], key)
	_set_source(VHOST, SOURCE_SELF_SIGNED)
	return describe(VHOST)


def _ensure_ca():
	ca_cert_path, ca_key_path = ca_paths()
	if os.path.isfile(ca_cert_path) and os.path.isfile(ca_key_path):
		with open(ca_cert_path, 'rb') as handle:
			ca_cert = x509.load_pem_x509_certificate(handle.read())
		with open(ca_key_path, 'rb') as handle:
			ca_key = serialization.load_pem_private_key(handle.read(), None)
		return ca_cert, ca_key
	ca_key = new_key()
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'BluePhish CA interna'),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'BluePhish')])
	ca_cert = (_builder(name, name, ca_key.public_key(), CA_DAYS)
		.add_extension(x509.BasicConstraints(ca = True, path_length = 0), critical = True)
		.add_extension(x509.KeyUsage(digital_signature = True, key_cert_sign = True, crl_sign = True,
			content_commitment = False, key_encipherment = False, data_encipherment = False, key_agreement = False,
			encipher_only = False, decipher_only = False), critical = True)
		.sign(ca_key, hashes.SHA256()))
	write_file(ca_key_path, key_pem(ca_key), private = True)
	write_file(ca_cert_path, _cert_pem(ca_cert))
	log.info('CA interna gerada em %s', ca_cert_path)
	return ca_cert, ca_key


def _write_trust(current, previous = None):
	bundle = _cert_pem(current) + (_cert_pem(previous) if previous is not None else b'')
	write_file(trust_path(), bundle)


def issue_internal(rotate_ca = False):
	"""O certificado interno da API, emitido pela CA interna (gerada se faltar)."""
	previous = None
	if rotate_ca:
		if os.path.isfile(ca_paths()[0]):
			with open(ca_paths()[0], 'rb') as handle:
				previous = x509.load_pem_x509_certificate(handle.read())
		for path in ca_paths():
			if os.path.exists(path):
				os.remove(path)
	ca_cert, ca_key = _ensure_ca()
	if rotate_ca or not os.path.isfile(trust_path()):
		_write_trust(ca_cert, previous)
	key = new_key()
	cert = (_builder(API_NAMES[0], ca_cert.subject, key.public_key(), INTERNAL_DAYS)
		.add_extension(_san(list(API_NAMES) + ['127.0.0.1']), critical = False)
		.add_extension(x509.BasicConstraints(ca = False, path_length = None), critical = True)
		.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical = False)
		.sign(ca_key, hashes.SHA256()))
	_install(INTERNAL, [cert, ca_cert], key)
	_set_source(INTERNAL, SOURCE_INTERNAL_CA)
	return describe(INTERNAL)


def ensure_defaults(names = ('localhost',)):
	"""Na subida: o que faltar é gerado — o vhost autoassinado e o interno pela CA.

	Nunca substitui o que existe: um certificado importado ou da Let's Encrypt
	sobrevive a qualquer reinício.
	"""
	created = []
	if not all(os.path.isfile(path) for path in paths(INTERNAL)) or not os.path.isfile(trust_path()):
		issue_internal()
		created.append(INTERNAL)
	if not all(os.path.isfile(path) for path in paths(VHOST)):
		generate_self_signed(list(names))
		created.append(VHOST)
	return created


# --- Importação -----------------------------------------------------------------

def _load_certs(pem_bytes):
	try:
		certs = x509.load_pem_x509_certificates(pem_bytes)
	except ValueError:
		raise CertError('O certificado não é um PEM válido.')
	if not certs:
		raise CertError('Nenhum certificado no PEM enviado.')
	return certs


def _load_key(pem_bytes, password = None):
	try:
		return serialization.load_pem_private_key(pem_bytes, password.encode('utf-8') if password else None)
	except TypeError:
		raise CertError('A chave privada está protegida por senha: informe a senha.')
	except ValueError:
		raise CertError('A chave privada não é um PEM válido, ou a senha está errada.')


def _public_bytes(key):
	return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _check_key_strength(key):
	if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
		raise CertError('Chave RSA de {0} bits: o mínimo é 2048.'.format(key.key_size))
	if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
		raise CertError('Só chaves RSA ou de curva elíptica.')


def _signed_by(child, parent):
	public = parent.public_key()
	try:
		if isinstance(public, rsa.RSAPublicKey):
			public.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
		elif isinstance(public, ec.EllipticCurvePublicKey):
			public.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
		else:
			return False
	except InvalidSignature:
		return False
	return child.issuer == parent.subject


def order_chain(key, certs):
	"""A folha (o certificado da chave) primeiro, depois cada emissor. Levanta CertError."""
	target = _public_bytes(key.public_key())
	leaves = [cert for cert in certs if _public_bytes(cert.public_key()) == target]
	if not leaves:
		raise CertError('A chave privada não é a deste certificado.')
	chain = [leaves[0]]
	remaining = [cert for cert in certs if cert is not leaves[0]]
	while remaining:
		parent = next((cert for cert in remaining if _signed_by(chain[-1], cert)), None)
		if parent is None:
			raise CertError('A cadeia enviada tem um certificado que não emitiu o anterior: {0}.'.format(_cn(remaining[0])))
		chain.append(parent)
		remaining.remove(parent)
	return chain


def _validate(key, certs):
	_check_key_strength(key)
	chain = order_chain(key, certs)
	now = _now()
	leaf = chain[0]
	if _not_after(leaf) <= now:
		raise CertError('O certificado venceu em {0}.'.format(_not_after(leaf).strftime('%Y-%m-%d')))
	if _not_before(leaf) > now + datetime.timedelta(days = 1):
		raise CertError('O certificado só começa a valer em {0}.'.format(_not_before(leaf).strftime('%Y-%m-%d')))
	return chain


def _install(target, chain, key):
	cert_path, key_path = paths(target)
	write_file(key_path, key_pem(key), private = True)
	write_file(cert_path, b''.join(_cert_pem(cert) for cert in chain))


def _self_signed(cert):
	return cert.issuer == cert.subject


def import_pem(target, cert_pem, key_pem_bytes, chain_pem = b'', password = None, confirmed = False):
	for blob in (cert_pem, key_pem_bytes, chain_pem):
		if len(blob or b'') > MAX_UPLOAD_BYTES:
			raise CertError('Arquivo grande demais para um certificado.')
	key = _load_key(key_pem_bytes, password)
	certs = _load_certs(cert_pem) + (_load_certs(chain_pem) if (chain_pem or b'').strip() else [])
	chain = _validate(key, certs)
	_guard_downgrade(target, _self_signed(chain[0]), confirmed)
	_install(target, chain, key)
	_set_source(target, SOURCE_PEM)
	return describe(target)


def import_pfx(target, pfx_bytes, password = None, confirmed = False):
	if len(pfx_bytes or b'') > MAX_UPLOAD_BYTES:
		raise CertError('Arquivo grande demais para um certificado.')
	try:
		key, cert, extra = pkcs12.load_key_and_certificates(pfx_bytes, password.encode('utf-8') if password else None)
	except ValueError:
		raise CertError('O arquivo PFX não abriu: senha errada ou arquivo inválido.')
	if key is None or cert is None:
		raise CertError('O PFX precisa ter o certificado e a chave privada.')
	chain = _validate(key, [cert] + list(extra or []))
	_guard_downgrade(target, _self_signed(chain[0]), confirmed)
	_install(target, chain, key)
	_set_source(target, SOURCE_PFX)
	return describe(target)


def check_issued(chain_pem, key):
	"""A validação de install_issued, sem gravar nada (o ensaio do staging)."""
	return _validate(key, _load_certs(chain_pem))


def install_issued(target, chain_pem, key):
	"""Para o acme_client: grava o que a Let's Encrypt emitiu, com a mesma validação."""
	_install(target, check_issued(chain_pem, key), key)
	_set_source(target, SOURCE_LETSENCRYPT)
	return describe(target)


# --- Leitura ----------------------------------------------------------------------

def _cn(cert):
	values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
	return values[0].value if values else cert.subject.rfc4514_string()


def _not_after(cert):
	return cert.not_valid_after_utc.replace(tzinfo = None)


def _not_before(cert):
	return cert.not_valid_before_utc.replace(tzinfo = None)


def _names(cert):
	try:
		san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
	except x509.ExtensionNotFound:
		return []
	return [str(value) for value in san.get_values_for_type(x509.DNSName)] + \
		[str(value) for value in san.get_values_for_type(x509.IPAddress)]


def days_left(target):
	cert_path = paths(target)[0]
	if not os.path.isfile(cert_path):
		return None
	with open(cert_path, 'rb') as handle:
		leaf = x509.load_pem_x509_certificates(handle.read())[0]
	return (_not_after(leaf) - _now()).days


def describe(target):
	"""O que a tela mostra de um certificado. Nunca a chave."""
	cert_path, key_path = paths(target)
	state = load_state().get(target) or {}
	base = {'id': target, 'source': state.get('source'), 'updatedAt': state.get('updatedAt'),
		'letsencrypt': state.get('letsencrypt')}
	if not os.path.isfile(cert_path):
		return dict(base, present = False)
	with open(cert_path, 'rb') as handle:
		chain = x509.load_pem_x509_certificates(handle.read())
	leaf = chain[0]
	not_after = _not_after(leaf)
	return dict(base, **{
		'present': True,
		'subject': _cn(leaf),
		'issuer': leaf.issuer.rfc4514_string(),
		'selfSigned': leaf.issuer == leaf.subject,
		'names': _names(leaf),
		'notBefore': _not_before(leaf).strftime('%Y-%m-%d %H:%M'),
		'notAfter': not_after.strftime('%Y-%m-%d %H:%M'),
		'daysLeft': (not_after - _now()).days,
		'chainLength': len(chain),
		'fingerprint': leaf.fingerprint(hashes.SHA256()).hex(),
		'keyPresent': os.path.isfile(key_path)
	})


def describe_all():
	return [describe(target) for target in TARGETS]
