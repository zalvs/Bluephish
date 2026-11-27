"""Testes dos certificados (cert_store.py) e da Let's Encrypt (acme_client.py).

Nenhum teste fala com a Let's Encrypt: o servidor ACME é de mentira, mas confere
a assinatura RS256 de cada pedido, exige o arquivo do desafio HTTP-01 com o
thumbprint certo e assina o CSR com uma CA de teste.

O que se prende aqui, e por que cada um falharia em silêncio:

  * **Chave que não é do certificado, certificado vencido, cadeia que não fecha e
    chave RSA fraca são recusados antes de gravar** — senão o vhost não sobe no
    próximo reinício.
  * **A cadeia é posta na ordem**, folha primeiro, como o nginx exige.
  * **A chave nunca aparece no que a tela recebe**, e é gravada com 0600.
  * **PFX com senha certa entra; com a errada, não.**
  * **O certificado interno é de uma CA diferente do vhost**, com o nome que o
    frontend confere (`bluephish`).
  * **Na subida só se gera o que falta**: um importado sobrevive ao reinício.
  * **O ACME só fala com o host do diretório**, limpa o desafio depois, e a
    renovação respeita os 30 dias e a espera depois de uma falha.

Roda com:  python -m unittest test_cert_store   (a partir do diretório app/)
"""

import base64
import datetime
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import acme_client
import cert_store
import models
import test_security_policy
from test_security_policy import AUTOMATIC


def _name(cn):
	return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca():
	key = ec.generate_private_key(ec.SECP256R1())
	now = datetime.datetime.utcnow()
	cert = (x509.CertificateBuilder().subject_name(_name('CA de teste')).issuer_name(_name('CA de teste'))
		.public_key(key.public_key()).serial_number(x509.random_serial_number())
		.not_valid_before(now - datetime.timedelta(days = 1)).not_valid_after(now + datetime.timedelta(days = 365))
		.add_extension(x509.BasicConstraints(ca = True, path_length = 0), critical = True)
		.sign(key, hashes.SHA256()))
	return cert, key


def make_leaf(ca_cert, ca_key, names = ('painel.exemplo.com',), key = None, days = 90):
	key = key or ec.generate_private_key(ec.SECP256R1())
	now = datetime.datetime.utcnow()
	cert = (x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(ca_cert.subject)
		.public_key(key.public_key()).serial_number(x509.random_serial_number())
		.not_valid_before(now - datetime.timedelta(days = 2)).not_valid_after(now + datetime.timedelta(days = days))
		.add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in names]), critical = False)
		.sign(ca_key, hashes.SHA256()))
	return cert, key


def pem(item):
	if isinstance(item, x509.Certificate):
		return item.public_bytes(serialization.Encoding.PEM)
	return cert_store.key_pem(item)


def _unb64(value):
	return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


class Pasta(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-certs-')
		self.env = mock.patch.dict(os.environ, {cert_store.ROOT_ENV: self.directory})
		self.env.start()

	def tearDown(self):
		self.env.stop()
		shutil.rmtree(self.directory, ignore_errors = True)


class Importacao(Pasta):

	def setUp(self):
		super().setUp()
		self.ca_cert, self.ca_key = make_ca()
		self.leaf, self.key = make_leaf(self.ca_cert, self.ca_key)

	def test_pem_bom_entra_com_a_cadeia_em_ordem(self):
		# A cadeia vem fora de ordem, a CA antes da folha
		described = cert_store.import_pem(cert_store.VHOST, pem(self.ca_cert) + pem(self.leaf), pem(self.key))
		self.assertEqual('painel.exemplo.com', described['subject'])
		self.assertEqual(2, described['chainLength'])
		with open(cert_store.paths(cert_store.VHOST)[0], 'rb') as handle:
			chain = x509.load_pem_x509_certificates(handle.read())
		self.assertEqual(self.leaf, chain[0])

	def test_a_chave_e_0600_e_nao_vai_para_a_tela(self):
		described = cert_store.import_pem(cert_store.VHOST, pem(self.leaf), pem(self.key), pem(self.ca_cert))
		mode = stat.S_IMODE(os.stat(cert_store.paths(cert_store.VHOST)[1]).st_mode)
		self.assertEqual(0o600, mode)
		self.assertNotIn('PRIVATE KEY', json.dumps(described))

	def test_chave_de_outro_certificado_e_recusada(self):
		other = ec.generate_private_key(ec.SECP256R1())
		with self.assertRaisesRegex(cert_store.CertError, 'não é a deste certificado'):
			cert_store.import_pem(cert_store.VHOST, pem(self.leaf), pem(other))
		self.assertFalse(os.path.exists(cert_store.paths(cert_store.VHOST)[0]))

	def test_certificado_vencido_e_recusado(self):
		leaf, key = make_leaf(self.ca_cert, self.ca_key, days = -1)
		with self.assertRaisesRegex(cert_store.CertError, 'venceu'):
			cert_store.import_pem(cert_store.VHOST, pem(leaf), pem(key))

	def test_cadeia_que_nao_fecha_e_recusada(self):
		stranger, _ = make_ca()
		with self.assertRaisesRegex(cert_store.CertError, 'não emitiu'):
			cert_store.import_pem(cert_store.VHOST, pem(self.leaf), pem(self.key), pem(stranger))

	def test_rsa_fraca_e_recusada(self):
		weak = rsa.generate_private_key(public_exponent = 65537, key_size = 1024)
		leaf, _ = make_leaf(self.ca_cert, self.ca_key, key = weak)
		with self.assertRaisesRegex(cert_store.CertError, '2048'):
			cert_store.import_pem(cert_store.VHOST, pem(leaf), pem(weak))

	def test_lixo_e_recusado(self):
		with self.assertRaises(cert_store.CertError):
			cert_store.import_pem(cert_store.VHOST, b'nao e pem', pem(self.key))

	def test_pfx_com_senha(self):
		blob = pkcs12.serialize_key_and_certificates(b'painel', self.key, self.leaf, [self.ca_cert],
			serialization.BestAvailableEncryption(b'segredo'))
		with self.assertRaisesRegex(cert_store.CertError, 'senha'):
			cert_store.import_pfx(cert_store.VHOST, blob, 'errada')
		self.assertEqual(2, cert_store.import_pfx(cert_store.VHOST, blob, 'segredo')['chainLength'])
		self.assertEqual(cert_store.SOURCE_PFX, cert_store.describe(cert_store.VHOST)['source'])


class Geracao(Pasta):

	def test_na_subida_gera_os_dois_e_o_interno_e_de_outra_ca(self):
		self.assertEqual([cert_store.INTERNAL, cert_store.VHOST], cert_store.ensure_defaults(['localhost']))
		internal, vhost = cert_store.describe(cert_store.INTERNAL), cert_store.describe(cert_store.VHOST)
		self.assertIn('bluephish', internal['names'])
		self.assertFalse(internal['selfSigned'])
		self.assertTrue(vhost['selfSigned'])
		self.assertNotEqual(internal['issuer'], vhost['issuer'])
		# A chave da CA fica só na pasta privada; a confiança vai para trust/
		self.assertTrue(os.path.isfile(cert_store.trust_path()))
		self.assertTrue(cert_store.ca_paths()[1].startswith(os.path.join(self.directory, 'private')))

	def test_na_subida_nao_substitui_o_que_existe(self):
		ca_cert, ca_key = make_ca()
		leaf, key = make_leaf(ca_cert, ca_key)
		cert_store.import_pem(cert_store.VHOST, pem(leaf), pem(key))
		self.assertEqual([cert_store.INTERNAL], cert_store.ensure_defaults())
		self.assertEqual('painel.exemplo.com', cert_store.describe(cert_store.VHOST)['subject'])

	def test_o_interno_e_assinado_pela_ca_de_trust(self):
		cert_store.issue_internal()
		with open(cert_store.trust_path(), 'rb') as handle:
			ca = x509.load_pem_x509_certificate(handle.read())
		with open(cert_store.paths(cert_store.INTERNAL)[0], 'rb') as handle:
			leaf = x509.load_pem_x509_certificates(handle.read())[0]
		ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))

	def test_trocar_a_ca_mantem_a_anterior_no_pacote(self):
		# O frontend relê o pacote em 30 s; a API segue com o certificado antigo
		# até reiniciar. Os dois têm de verificar contra o pacote nesse meio-tempo
		cert_store.issue_internal()
		with open(cert_store.paths(cert_store.INTERNAL)[0], 'rb') as handle:
			old_leaf = x509.load_pem_x509_certificates(handle.read())[0]
		cert_store.issue_internal(rotate_ca = True)
		with open(cert_store.paths(cert_store.INTERNAL)[0], 'rb') as handle:
			new_leaf = x509.load_pem_x509_certificates(handle.read())[0]
		with open(cert_store.trust_path(), 'rb') as handle:
			bundle = x509.load_pem_x509_certificates(handle.read())
		self.assertEqual(2, len(bundle))
		for leaf in (old_leaf, new_leaf):
			self.assertTrue(any(cert_store._signed_by(leaf, ca) for ca in bundle))
		# E a CA atual é a nova, a que emitiu o certificado novo
		with open(cert_store.ca_paths()[0], 'rb') as handle:
			self.assertTrue(cert_store._signed_by(new_leaf, x509.load_pem_x509_certificate(handle.read())))

	def test_autoassinado_por_cima_de_um_de_ca_pede_confirmacao(self):
		ca_cert, ca_key = make_ca()
		leaf, key = make_leaf(ca_cert, ca_key)
		cert_store.import_pem(cert_store.VHOST, pem(leaf), pem(key), pem(ca_cert))
		with self.assertRaises(cert_store.NeedsConfirmation):
			cert_store.generate_self_signed('painel.exemplo.com')
		self.assertFalse(cert_store.describe(cert_store.VHOST)['selfSigned'])
		self.assertTrue(cert_store.generate_self_signed('painel.exemplo.com', confirmed = True)['selfSigned'])

	def test_autoassinado_por_cima_de_autoassinado_nao_pede(self):
		cert_store.generate_self_signed('a.exemplo.com')
		self.assertTrue(cert_store.generate_self_signed('b.exemplo.com')['selfSigned'])

	def test_autoassinado_com_nomes_validados(self):
		self.assertEqual(['painel.exemplo.com', '10.0.0.5'],
			cert_store.generate_self_signed('painel.exemplo.com, 10.0.0.5')['names'])
		for bad in ('*.exemplo.com', 'um nome/x', 'a/b', ''):
			with self.assertRaises(cert_store.CertError, msg = bad):
				cert_store.generate_self_signed(bad)


class FakeAcme(object):
	"""Um servidor ACME mínimo: confere o JWS, o desafio e emite pelo CSR."""

	BASE = 'https://acme.teste'

	class Response(object):
		def __init__(self, status = 200, body = None, headers = None, content = b''):
			self.status_code = status
			self._body = body
			self.headers = headers or {}
			self.content = content
			self.text = json.dumps(body) if body is not None else content.decode('ascii', 'replace')

		def json(self):
			return self._body

	def __init__(self, ca_cert, ca_key, challenge_dir):
		self.ca_cert, self.ca_key, self.challenge_dir = ca_cert, ca_key, challenge_dir
		self.nonce = 0
		self.account_jwk = None
		self.status = {'authz': 'pending', 'order': 'pending'}
		self.certificate = b''
		self.saw_challenge_file = False
		self.down = False

	def _nonce(self):
		self.nonce += 1
		return {'Replay-Nonce': 'n{0}'.format(self.nonce)}

	def get(self, url, **kwargs):
		assert kwargs.get('allow_redirects') is False
		base = self.BASE
		return self.Response(body = {'newNonce': base + '/nonce', 'newAccount': base + '/acct', 'newOrder': base + '/order'})

	def head(self, url, **kwargs):
		return self.Response(headers = self._nonce())

	def _verify(self, data):
		envelope = json.loads(data)
		protected = json.loads(_unb64(envelope['protected']))
		assert protected['alg'] == 'RS256'
		if 'jwk' in protected:
			self.account_jwk = protected['jwk']
		jwk = self.account_jwk
		numbers = rsa.RSAPublicNumbers(int.from_bytes(_unb64(jwk['e']), 'big'), int.from_bytes(_unb64(jwk['n']), 'big'))
		numbers.public_key().verify(_unb64(envelope['signature']),
			'{0}.{1}'.format(envelope['protected'], envelope['payload']).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
		payload = json.loads(_unb64(envelope['payload'])) if envelope['payload'] else None
		return protected, payload

	def post(self, url, data = None, **kwargs):
		assert kwargs.get('allow_redirects') is False
		if self.down:
			return self.Response(503, {'detail': 'fora do ar'})
		protected, payload = self._verify(data)
		path = url[len(self.BASE):]
		if path == '/acct':
			return self.Response(201, {'status': 'valid'}, dict(self._nonce(), Location = self.BASE + '/acct/1'))
		assert protected.get('kid') == self.BASE + '/acct/1'
		if path == '/order':
			self.status = {'authz': 'pending', 'order': 'pending'}
			return self.Response(201, {'status': 'pending', 'authorizations': [self.BASE + '/authz/1'],
				'finalize': self.BASE + '/finalize'}, dict(self._nonce(), Location = self.BASE + '/order/1'))
		if path == '/authz/1':
			return self.Response(body = {'status': self.status['authz'], 'challenges': [
				{'type': 'dns-01', 'url': self.BASE + '/chall/dns', 'token': 'outro'},
				{'type': 'http-01', 'url': self.BASE + '/chall/1', 'token': 'tok_123-abc'}]})
		if path == '/chall/1':
			with open(os.path.join(self.challenge_dir, 'tok_123-abc')) as handle:
				content = handle.read()
			self.saw_challenge_file = content == 'tok_123-abc.' + acme_client.thumbprint_of_jwk(self.account_jwk)
			self.status['authz'] = 'valid' if self.saw_challenge_file else 'invalid'
			return self.Response(body = {'status': 'processing'})
		if path == '/finalize':
			csr = x509.load_der_x509_csr(_unb64(payload['csr']))
			now = datetime.datetime.utcnow()
			leaf = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.ca_cert.subject)
				.public_key(csr.public_key()).serial_number(x509.random_serial_number())
				.not_valid_before(now - datetime.timedelta(minutes = 1)).not_valid_after(now + datetime.timedelta(days = 90))
				.add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical = False)
				.sign(self.ca_key, hashes.SHA256()))
			self.certificate = pem(leaf) + pem(self.ca_cert)
			self.status['order'] = 'valid'
			return self.Response(body = {'status': 'processing'})
		if path == '/order/1':
			return self.Response(body = {'status': self.status['order'], 'certificate': self.BASE + '/cert/1'})
		if path == '/cert/1':
			return self.Response(content = self.certificate)
		return self.Response(404, {'detail': 'não existe'})


class LetsEncrypt(Pasta):

	def setUp(self):
		super().setUp()
		self.ca_cert, self.ca_key = make_ca()
		self.server = FakeAcme(self.ca_cert, self.ca_key, cert_store.challenge_dir())
		for patch in (mock.patch.object(acme_client, 'STAGING', FakeAcme.BASE + '/directory'),
				mock.patch.object(acme_client, 'PRODUCTION', FakeAcme.BASE + '/directory'),
				mock.patch.object(acme_client, 'POLL_SECONDS', 0)):
			patch.start()
			self.addCleanup(patch.stop)
		# Produção (no servidor de mentira): é a que instala
		acme_client.save_settings(['painel.exemplo.com'], 'soc@exemplo.com', False, True)

	def test_staging_e_ensaio_e_nao_instala(self):
		cert_store.generate_self_signed('painel.exemplo.com')
		before = cert_store.describe(cert_store.VHOST)['fingerprint']
		acme_client.save_settings(['painel.exemplo.com'], '', True, True)
		result = acme_client.issue_now(self.server)
		self.assertTrue(result['staging'])
		self.assertTrue(self.server.saw_challenge_file)
		self.assertEqual(before, cert_store.describe(cert_store.VHOST)['fingerprint'])
		self.assertIn('stagingOkAt', acme_client.settings())

	def test_bad_nonce_tenta_de_novo_uma_vez(self):
		original = self.server.post
		state = {'failed': False}

		def flaky(url, data = None, **kwargs):
			if not state['failed']:
				state['failed'] = True
				return FakeAcme.Response(400, {'type': 'urn:ietf:params:acme:error:badNonce'})
			return original(url, data, **kwargs)
		self.server.post = flaky
		self.assertEqual(['painel.exemplo.com'], acme_client.issue_now(self.server)['names'])

	def test_emite_pelo_http01_e_limpa_o_desafio(self):
		described = acme_client.issue_now(self.server)
		self.assertTrue(self.server.saw_challenge_file)
		self.assertEqual(['painel.exemplo.com'], described['names'])
		self.assertEqual(cert_store.SOURCE_LETSENCRYPT, described['source'])
		self.assertEqual([], os.listdir(cert_store.challenge_dir()))
		self.assertIsNone(acme_client.settings()['lastError'])

	def test_a_conta_e_rsa_e_persiste(self):
		first = acme_client.account_key()
		self.assertIsInstance(first, rsa.RSAPrivateKey)
		self.assertEqual(first.private_numbers(), acme_client.account_key().private_numbers())

	def test_url_fora_do_host_do_diretorio_e_recusada(self):
		client = acme_client.Client(FakeAcme.BASE + '/directory', acme_client.account_key(), self.server)
		with self.assertRaises(acme_client.AcmeError):
			client.post('https://outro.host/acct', {})

	def test_ip_nao_vai_para_a_lets_encrypt(self):
		acme_client.save_settings(['10.0.0.5'], '', False, True)
		with self.assertRaisesRegex(acme_client.AcmeError, 'IP'):
			acme_client.issue_now(self.server)

	def test_nao_renova_com_mais_de_30_dias(self):
		acme_client.issue_now(self.server)
		self.assertIsNone(acme_client.renew_if_due(http = self.server))

	def test_falha_fica_registrada_e_a_renovacao_espera(self):
		acme_client.issue_now(self.server)
		with mock.patch.object(cert_store, 'days_left', return_value = 10):
			self.server.down = True
			self.assertEqual('failed', acme_client.renew_if_due(http = self.server))
			self.assertIn('503', acme_client.settings()['lastError'])
			# Logo depois da falha, não tenta de novo
			self.assertIsNone(acme_client.renew_if_due(http = self.server))
			self.server.down = False
			later = datetime.datetime.utcnow() + datetime.timedelta(hours = acme_client.RETRY_HOURS + 1)
			self.assertEqual('renewed', acme_client.renew_if_due(now = later, http = self.server))
		self.assertIsNone(acme_client.settings()['lastError'])

	def test_a_renovacao_instala_pela_producao_mesmo_com_o_staging_ligado(self):
		acme_client.issue_now(self.server)
		before = cert_store.describe(cert_store.VHOST)['fingerprint']
		acme_client.save_settings(['painel.exemplo.com'], '', True, True)
		with mock.patch.object(cert_store, 'days_left', return_value = 10):
			self.assertEqual('renewed', acme_client.renew_if_due(http = self.server))
		self.assertNotEqual(before, cert_store.describe(cert_store.VHOST)['fingerprint'])

	def test_sem_renovacao_automatica_nao_renova(self):
		acme_client.issue_now(self.server)
		acme_client.save_settings(['painel.exemplo.com'], '', False, False)
		with mock.patch.object(cert_store, 'days_left', return_value = 5):
			self.assertIsNone(acme_client.renew_if_due(http = self.server))


@unittest.skipIf(test_security_policy.thephish_app is None, 'thephish_app precisa da imagem')
class Rotas(test_security_policy.RotaSoDeGlobalAdmin):
	"""/cert-config na aplicação de verdade."""

	def setUp(self):
		super().setUp()
		self.certs = tempfile.mkdtemp(prefix = 'bluephish-certs-route-')
		self.env = mock.patch.dict(os.environ, {cert_store.ROOT_ENV: self.certs})
		self.env.start()
		self.addCleanup(self.env.stop)
		self.addCleanup(shutil.rmtree, self.certs, True)
		self.ca_cert, self.ca_key = make_ca()
		self.leaf, self.key = make_leaf(self.ca_cert, self.ca_key)

	def upload(self, client):
		return client.post('/cert-config/pem', headers = AUTOMATIC, content_type = 'multipart/form-data', data = {
			'certificate': (io.BytesIO(pem(self.leaf)), 'cert.pem'),
			'key': (io.BytesIO(pem(self.key)), 'key.pem'),
			'chain': (io.BytesIO(pem(self.ca_cert)), 'chain.pem')})

	def test_so_global_admin(self):
		for role in (models.ROLE_ANALYST, models.ROLE_ADMIN):
			client = self.signed_in(role)
			self.assertEqual(403, client.get('/cert-config', headers = AUTOMATIC).status_code)
			self.assertEqual(403, self.upload(client).status_code)
		self.assertFalse(os.path.exists(cert_store.paths(cert_store.VHOST)[0]))

	def test_global_admin_envia_pem_e_a_chave_nao_volta(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		response = self.upload(client)
		self.assertEqual(200, response.status_code)
		text = response.get_data(as_text = True)
		self.assertNotIn('PRIVATE KEY', text)
		vhost = [item for item in response.get_json()['certificates'] if item['id'] == cert_store.VHOST][0]
		self.assertEqual('painel.exemplo.com', vhost['subject'])
		self.assertIn(('cert_import', 'ok'), self.audited)

	def test_par_que_nao_serve_e_recusado_e_auditado(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		self.key = ec.generate_private_key(ec.SECP256R1())
		self.assertEqual(400, self.upload(client).status_code)
		self.assertIn(('cert_import', 'refused'), self.audited)

	def test_lets_encrypt_recusa_ip_e_grava_nomes(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		refused = client.post('/cert-config/letsencrypt', data = {'domains': '10.0.0.5'}, headers = AUTOMATIC)
		self.assertEqual(400, refused.status_code)
		saved = client.post('/cert-config/letsencrypt', data = {'domains': 'painel.exemplo.com', 'email': 'soc@exemplo.com',
			'staging': 'true', 'autoRenew': 'true'}, headers = AUTOMATIC).get_json()
		self.assertEqual(['painel.exemplo.com'], saved['letsencrypt']['domains'])
		self.assertTrue(saved['letsencrypt']['staging'])


if __name__ == '__main__':
	unittest.main()
