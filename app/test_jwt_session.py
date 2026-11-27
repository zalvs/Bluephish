"""Testes da sessão em JWT estrito (jwt_session.py).

O que se prende aqui, e por que cada um falharia em silêncio:

  * **O cookie é um JWT HS256 com iss, aud, iat, nbf, exp e jti**, e só isso vale:
    `none`, outro algoritmo, outra chave, outro emissor ou público, claim faltando,
    conteúdo adulterado, token vencido — tudo vira sessão vazia.
  * **O jti de uma sessão autenticada é o sid**, e um token que põe o sid de uma
    sessão sob outro jti é recusado.
  * **Revogação no servidor**: o token de antes do logout, reapresentado, não abre
    mais nada — nem o de antes de uma troca de senha.
  * **O login gira o jti** (fixação de sessão).
  * **O relógio que recua alguns segundos não derruba a sessão** (§7.19), e um
    token muito "do futuro" continua recusado.
  * **O cookie é HttpOnly e SameSite=Strict.**

Roda com:  python -m unittest test_jwt_session   (a partir do diretório app/)
"""

import base64
import json
import time
import unittest

import jwt
from flask.json.tag import TaggedJSONSerializer

import jwt_session
import session_clock
import test_mfa_gate
from test_mfa_gate import SENHA

KEY = 'chave-de-teste'
COOKIE = 'session'


def claims(**overrides):
	now = int(time.time())
	body = {'iss': jwt_session.ISSUER, 'aud': jwt_session.AUDIENCE, 'iat': now, 'nbf': now, 'exp': now + 600,
		'jti': 'j1', 'sess': TaggedJSONSerializer().dumps({'user': 'analista'})}
	body.update(overrides)
	return {key: value for key, value in body.items() if value is not None}


class Decodificacao(unittest.TestCase):

	def test_o_token_bom_abre(self):
		data, jti = jwt_session.decode(jwt.encode(claims(), KEY, algorithm = 'HS256'), KEY)
		self.assertEqual({'user': 'analista'}, data)
		self.assertEqual('j1', jti)

	def test_alg_none_nao_abre(self):
		header = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).rstrip(b'=')
		body = base64.urlsafe_b64encode(json.dumps(claims()).encode()).rstrip(b'=')
		self.assertEqual((None, None), jwt_session.decode((header + b'.' + body + b'.').decode(), KEY))

	def test_outro_algoritmo_nao_abre(self):
		self.assertEqual((None, None), jwt_session.decode(jwt.encode(claims(), KEY, algorithm = 'HS512'), KEY))

	def test_cabecalho_com_campo_que_esta_aplicacao_nao_emite_nao_abre(self):
		for extra in ({'crit': ['exp']}, {'kid': '../../x'}, {'jku': 'https://atacante/jwks'}):
			token = jwt.encode(claims(), KEY, algorithm = 'HS256', headers = extra)
			self.assertEqual((None, None), jwt_session.decode(token, KEY), extra)

	def test_outra_chave_nao_abre(self):
		self.assertEqual((None, None), jwt_session.decode(jwt.encode(claims(), 'outra', algorithm = 'HS256'), KEY))

	def test_outro_emissor_ou_publico_nao_abre(self):
		for override in ({'iss': 'outro'}, {'aud': 'outro'}):
			self.assertEqual((None, None), jwt_session.decode(jwt.encode(claims(**override), KEY, algorithm = 'HS256'), KEY), override)

	def test_claim_faltando_nao_abre(self):
		for name in jwt_session.REQUIRED:
			token = jwt.encode(claims(**{name: None}), KEY, algorithm = 'HS256')
			self.assertEqual((None, None), jwt_session.decode(token, KEY), name)

	def test_adulterado_nao_abre(self):
		token = jwt.encode(claims(), KEY, algorithm = 'HS256')
		header, body, signature = token.split('.')
		forged = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
		forged['sess'] = TaggedJSONSerializer().dumps({'user': 'admin'})
		body = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b'=').decode()
		self.assertEqual((None, None), jwt_session.decode('.'.join((header, body, signature)), KEY))

	def test_vencido_nao_abre(self):
		now = int(time.time())
		token = jwt.encode(claims(iat = now - 700, nbf = now - 700, exp = now - 1), KEY, algorithm = 'HS256')
		self.assertEqual((None, None), jwt_session.decode(token, KEY))

	def test_sid_sob_outro_jti_nao_abre(self):
		sess = TaggedJSONSerializer().dumps({'sid': 'sessao-a'})
		token = jwt.encode(claims(jti = 'sessao-b', sess = sess), KEY, algorithm = 'HS256')
		self.assertEqual((None, None), jwt_session.decode(token, KEY))

	def test_relogio_que_recuou_alguns_segundos_abre(self):
		now = int(time.time())
		token = jwt.encode(claims(iat = now + 5, nbf = now + 5), KEY, algorithm = 'HS256')
		jwt_session._last_warning[0] = 0.0
		with self.assertLogs('jwt_session', level = 'WARNING'):
			self.assertEqual('j1', jwt_session.decode(token, KEY)[1])

	def test_muito_do_futuro_nao_abre(self):
		ahead = int(time.time()) + session_clock.MAX_BACKWARD_SECONDS + 60
		token = jwt.encode(claims(iat = ahead, nbf = ahead, exp = ahead + 600), KEY, algorithm = 'HS256')
		self.assertEqual((None, None), jwt_session.decode(token, KEY))

	def test_o_fluxo_do_sso_cabe_no_cookie(self):
		# O cookie do itsdangerous saía comprimido; o JWT não. O fluxo do MSAL mora
		# na sessão entre a ida ao Entra ID e a volta, e passar do limite faria
		# save_session não gravar nada — o SSO morreria calado. Um auth_uri de
		# ~1,2 KB é maior que o real (~600 caracteres)
		flow = {'state': 's' * 22, 'redirect_uri': 'https://bluephish.empresa-exemplo.com.br/auth/sso/callback',
			'scope': ['openid', 'profile', 'offline_access', 'User.Read'], 'auth_uri': 'https://login.microsoftonline.com/' + 'x' * 1200,
			'code_verifier': 'v' * 86, 'nonce': 'n' * 64, 'claims_challenge': None}
		session = {'csrf_token': 'c' * 40, 'sso_flow': flow, 'sso_next': '/config/seguranca'}
		token = jwt_session.encode(session, KEY, 43200, 'j' * 32)
		self.assertLess(len(token), jwt_session.MAX_TOKEN_CHARS)

	def test_token_gigante_nao_abre(self):
		self.assertEqual((None, None), jwt_session.decode('x' * 5000, KEY))


class NaAplicacao(test_mfa_gate.Base):
	"""A sessão de verdade, montada como thephish_app a monta."""

	def cookie_name(self):
		return self.app.config.get('SESSION_COOKIE_NAME', COOKIE)

	def cookie(self):
		return self.client.get_cookie(self.cookie_name())

	def token_claims(self):
		return jwt.decode(self.cookie().value, self.app.secret_key, algorithms = ['HS256'],
			audience = jwt_session.AUDIENCE, issuer = jwt_session.ISSUER)

	def test_o_cookie_e_um_jwt_hs256(self):
		self.enrolled_user()
		self.assertEqual('HS256', jwt.get_unverified_header(self.cookie().value)['alg'])
		body = self.token_claims()
		for name in jwt_session.REQUIRED:
			self.assertIn(name, body)

	def test_o_jti_da_sessao_autenticada_e_o_sid(self):
		self.enrolled_user()
		with self.client.session_transaction() as session:
			sid = session['sid']
		self.assertEqual(sid, self.token_claims()['jti'])

	def test_o_login_gira_o_jti(self):
		self.create()
		self.login()
		before = self.token_claims()['jti']
		self.client.post('/api/auth/mfa/setup')
		self.client.post('/api/auth/mfa/activate', json = {'code': test_mfa_gate.code_for(self.secret_of('analista'))})
		self.assertNotEqual(before, self.token_claims()['jti'])

	def test_o_token_de_antes_do_logout_nao_abre_mais(self):
		self.enrolled_user()
		self.assertOpen()
		stolen = self.cookie().value
		self.client.post('/api/auth/logout')
		self.client.set_cookie(self.cookie_name(), stolen)
		self.assertBlocked()

	def test_o_token_de_antes_da_troca_de_senha_nao_abre_mais(self):
		self.enrolled_user()
		stolen = self.cookie().value
		self.client.post('/api/users/change_password', json = {'currentPassword': SENHA, 'newPassword': 'outra senha bem longa'})
		self.client.set_cookie(self.cookie_name(), stolen)
		self.assertBlocked()

	def test_o_cookie_e_httponly_e_samesite_strict(self):
		self.app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
		self.create()
		response = self.login()
		header = [value for value in response.headers.getlist('Set-Cookie') if value.startswith(self.cookie_name() + '=')][0]
		self.assertIn('HttpOnly', header)
		self.assertIn('SameSite=Strict', header)


class NaConfiguracaoDaAplicacao(unittest.TestCase):

	def test_thephish_app_usa_o_jwt_com_cookie_seguro(self):
		import test_security_policy
		app_module = test_security_policy.thephish_app
		if app_module is None:
			self.skipTest('thephish_app precisa da imagem')
		self.assertIsInstance(app_module.app.session_interface, jwt_session.JwtSessionInterface)
		# Os testes de rota desligam o Secure (o cliente fala http); o que importa
		# é o valor de fábrica, conferido no código
		with open(app_module.__file__, encoding = 'utf-8') as handle:
			source = handle.read()
		self.assertIn("app.config['SESSION_COOKIE_SECURE'] = True", source)
		self.assertIn("app.config['SESSION_COOKIE_HTTPONLY'] = True", source)
		self.assertIn("app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'", source)


if __name__ == '__main__':
	unittest.main()
