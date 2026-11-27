"""Testes de ponta a ponta do bloqueio de acesso sem segundo fator.

test_mfa.py prende a mecânica (o código, o segredo, a migração). Este arquivo
prende o que o requisito realmente pede, e prende do único jeito que vale:
falando HTTP com as rotas de verdade, pelo cliente de teste do Flask.

Os critérios de aceite, um teste cada:

  * Usuário novo — no primeiro login é interceptado e obrigado a configurar o
    MFA; o painel só abre depois de um código válido.
  * Usuário legado — conta que já existia, sem MFA, é interceptada no login
    seguinte e não passa antes de configurar.
  * Só aplicativo autenticador — não existe rota que mande código por e-mail ou
    SMS, e este teste falha se alguém acrescentar uma.

E o que sustenta os três: a senha certa, sozinha, não abre sessão nenhuma. É
por isso que os testes conferem o /list (uma rota qualquer do painel) e não só
a resposta do login — o que importa não é o que o login responde, é o que a
sessão que ele deixa consegue alcançar.

Roda com:  python -m unittest test_mfa_gate   (a partir do diretório app/)
"""

import os
import shutil
import datetime
import tempfile
import time
import unittest
from unittest import mock

import flask
import flask_login
import pyotp

import auth
import jwt_session
import mfa
import models

SENHA = 'uma senha bem longa'


# Diferente de test_mfa.py, aqui o relógio é o de verdade: quem confere é o
# endpoint, e ele chama time.time(). Um instante fixo produziria códigos que
# nunca batem — e um teste que só passa numa data
def code_for(secret, moment = None):
	moment = moment if moment is not None else time.time()
	return pyotp.TOTP(secret, digits = mfa.DIGITS, interval = mfa.PERIOD_SECONDS).at(int(moment))


def build_app():
	"""Uma aplicação mínima com as rotas reais de auth.py montadas nela.

	Não é thephish_app: importar aquele arquivo faz o monkey patch do eventlet e
	arrasta a aplicação inteira. O que se testa aqui é o blueprint de
	autenticação e o `before_request` que o acompanha — montados do mesmo jeito
	que thephish_app os monta, incluindo a mesma lista de endpoints que
	respondem antes de existir sessão.
	"""
	application = flask.Flask(__name__, template_folder = 'templates', static_folder = 'static')
	application.config['SECRET_KEY'] = 'chave-de-teste'
	# Sem Secure no cookie: o cliente de teste fala http, e um cookie Secure
	# nunca voltaria — a sessão morreria entre uma requisição e a seguinte
	application.config['SESSION_COOKIE_SECURE'] = False
	application.config['TESTING'] = True

	login_manager = flask_login.LoginManager()
	login_manager.init_app(application)

	# Flask-Limiter mudou a assinatura entre a 2.x (a da imagem) e a 3+/4.x (a
	# de quem roda os testes). O decorador @limiter.limit é o mesmo nas duas
	try:
		from flask_limiter import Limiter
		from flask_limiter.util import get_remote_address
		try:
			limiter = Limiter(application, key_func = get_remote_address, default_limits = [])
		except TypeError:
			limiter = Limiter(get_remote_address, app = application, default_limits = [])
		# O limite por IP é política de força bruta, não o que se testa aqui, e
		# ligado ele derrubaria os testes que erram o código de propósito
		limiter.enabled = False
	except ImportError:  # pragma: no cover - só se a dependência sumir
		class _NoLimiter(object):
			def limit(self, *_args, **_kwargs):
				return lambda view: view
		limiter = _NoLimiter()

	# A mesma sessão da aplicação: um JWT (jwt_session). Todo teste de
	# autenticação montado aqui roda sobre ela
	application.session_interface = jwt_session.JwtSessionInterface()
	auth.register(application, login_manager, limiter)

	@application.route('/')
	@auth.requires_analyst
	def homepage():
		return 'painel'

	# Duas rotas quaisquer do painel: é o que se tenta alcançar para provar que
	# a sessão vale (ou não vale) alguma coisa. Duas e não uma porque a recusa
	# tem duas caras — navegação de página é mandada para o login, chamada de
	# API recebe 401 —, e as duas precisam estar fechadas
	@application.route('/list')
	@auth.requires_analyst
	def protected_page():
		return flask.jsonify({'ok': True})

	@application.route('/api/list')
	@auth.requires_analyst
	def protected_api():
		return flask.jsonify({'ok': True})

	@application.before_request
	def session_policy():
		if flask.request.endpoint in ('static', 'login_page', 'api_login', 'api_logout',
				'sso_start', 'sso_callback', 'api_mfa_setup', 'api_mfa_activate', 'api_mfa_verify'):
			return None
		expired = auth.enforce_session_policy()
		if expired is not None:
			return expired
		return auth.enforce_mfa_policy()

	return application


class Base(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-gate-')
		self.previous_db = models.DB_PATH
		self.previous_log = auth.AUDIT_LOG_PATH
		models.DB_PATH = os.path.join(self.directory, 'bluephish.db')
		auth.AUDIT_LOG_PATH = os.path.join(self.directory, 'auth.log')
		models._engine = None
		models._SessionFactory = None
		auth.audit_log.handlers = []
		auth._live_sessions.clear()
		auth._mfa_challenges.clear()
		self.app = build_app()
		self.client = self.app.test_client()

	def tearDown(self):
		models.DB_PATH = self.previous_db
		auth.AUDIT_LOG_PATH = self.previous_log
		models._engine = None
		models._SessionFactory = None
		auth.audit_log.handlers = []
		shutil.rmtree(self.directory, ignore_errors = True)

	def create(self, username = 'analista', role = models.ROLE_ANALYST):
		return models.create_user(username, SENHA, role)

	def login(self, username = 'analista', password = SENHA):
		return self.client.post('/api/auth/login', json = {'username': username, 'password': password})

	def secret_of(self, username):
		session = models.get_session()
		try:
			return session.query(models.User).filter(models.User.username == username).first().mfa_secret
		finally:
			session.close()

	def assertBlocked(self):
		"""O painel está fechado para a sessão atual, pelas duas portas.

		A navegação de página é mandada para a tela de login (302), a chamada de
		API leva 401. As duas são recusa; conferir só uma deixaria a outra
		aberta sem ninguém notar
		"""
		page = self.client.get('/list')
		self.assertEqual(302, page.status_code)
		self.assertIn('/login', page.headers.get('Location', ''))
		self.assertEqual(401, self.client.get('/api/list').status_code)

	def assertOpen(self):
		self.assertEqual(200, self.client.get('/list').status_code)
		self.assertEqual(200, self.client.get('/api/list').status_code)

	def enrolled_user(self, username = 'analista', role = models.ROLE_ANALYST):
		"""Uma conta que já atravessou a configuração, como quem usa o painel."""
		self.create(username, role)
		self.login(username)
		self.client.post('/api/auth/mfa/setup')
		secret = self.secret_of(username)
		self.client.post('/api/auth/mfa/activate', json = {'code': code_for(secret)})
		return secret


class UsuarioNovo(Base):
	"""Critério de aceite: no primeiro login o usuário é obrigado a configurar."""

	def test_a_senha_certa_nao_abre_sessao(self):
		self.create()
		response = self.login()
		self.assertEqual(200, response.status_code)
		self.assertTrue(response.get_json()['mfaRequired'])
		self.assertFalse(response.get_json()['mfaEnrolled'])
		# E, principalmente: a sessão que esse login deixou não alcança nada
		self.assertBlocked()

	def test_o_painel_so_abre_depois_do_primeiro_codigo_valido(self):
		self.create()
		self.login()
		setup = self.client.post('/api/auth/mfa/setup')
		self.assertEqual(200, setup.status_code)
		body = setup.get_json()
		self.assertTrue(body['qr'].startswith('data:image/svg+xml;base64,'))
		self.assertEqual(32, len(body['secret']))

		activate = self.client.post('/api/auth/mfa/activate', json = {'code': code_for(body['secret'])})
		self.assertEqual(200, activate.status_code)
		self.assertOpen()

	def test_um_codigo_errado_nao_ativa_nem_abre_nada(self):
		self.create()
		self.login()
		setup = self.client.post('/api/auth/mfa/setup').get_json()
		wrong = '000000' if code_for(setup['secret']) != '000000' else '111111'
		self.assertEqual(401, self.client.post('/api/auth/mfa/activate', json = {'code': wrong}).status_code)
		self.assertBlocked()
		session = models.get_session()
		try:
			self.assertFalse(session.query(models.User).first().mfa_is_enrolled())
		finally:
			session.close()

	def test_sem_ter_acertado_a_senha_nao_se_pede_um_QR(self):
		"""O desafio é o que autoriza a configuração — sem ele, nada é dito."""
		self.create()
		self.assertEqual(401, self.client.post('/api/auth/mfa/setup').status_code)
		self.assertEqual(401, self.client.post('/api/auth/mfa/verify', json = {'code': '123456'}).status_code)


class UsuarioLegado(Base):
	"""Critério de aceite: quem já tinha conta é interceptado no próximo login."""

	def test_uma_conta_anterior_ao_MFA_e_interceptada(self):
		# Uma conta criada antes disto existir é, no banco, exatamente uma conta
		# com mfa_secret nulo — que é como toda conta nasce
		self.create('veterano', models.ROLE_GLOBAL_ADMIN)
		response = self.login('veterano')
		self.assertFalse(response.get_json()['mfaEnrolled'])
		self.assertBlocked()

	def test_nem_global_admin_escapa(self):
		self.create('dona', models.ROLE_GLOBAL_ADMIN)
		self.login('dona')
		self.assertEqual(401, self.client.get('/api/users').status_code)
		self.assertBlocked()

	def test_depois_de_configurar_o_login_seguinte_pede_so_o_codigo(self):
		secret = self.enrolled_user()
		self.client.post('/api/auth/logout')
		response = self.login()
		self.assertTrue(response.get_json()['mfaEnrolled'])
		self.assertBlocked()
		# Quem já configurou não ganha um QR novo por pedir: trocar um segredo
		# confirmado é reposição de credencial, e é ato de global_admin
		self.assertEqual(409, self.client.post('/api/auth/mfa/setup').status_code)
		# Um passo à frente, porque o anterior já foi usado na configuração
		later = time.time() + mfa.PERIOD_SECONDS
		self.assertEqual(200, self.client.post('/api/auth/mfa/verify',
			json = {'code': code_for(secret, later)}).status_code)
		self.assertOpen()


class Repeticao(Base):
	"""Um código já usado não abre uma segunda sessão.

	É o cenário concreto: alguém vê o código na tela do celular por cima do
	ombro, ou uma página de phishing convence a pessoa a digitá-lo. Sem a trava,
	esse código vale por até 90 segundos em outro navegador — e o segundo fator
	deixa de ser um fator para virar um atraso.
	"""

	def test_o_mesmo_codigo_nao_serve_para_entrar_duas_vezes(self):
		secret = self.enrolled_user()
		self.client.post('/api/auth/logout')

		# Um passo à frente do que a configuração consumiu, e usado uma vez
		later = time.time() + mfa.PERIOD_SECONDS
		code = code_for(secret, later)
		self.login()
		self.assertEqual(200, self.client.post('/api/auth/mfa/verify', json = {'code': code}).status_code)
		self.assertOpen()
		self.client.post('/api/auth/logout')

		# O mesmo código, ainda dentro da validade, numa sessão nova
		self.login()
		self.assertEqual(401, self.client.post('/api/auth/mfa/verify', json = {'code': code}).status_code)
		self.assertBlocked()


class SessaoAntiga(Base):
	"""A rede de proteção: cookie válido de antes do deploy não vale mais.

	Uma sessão aberta quando ainda não havia segundo fator traz um cookie
	assinado e legítimo, mas sem o carimbo de MFA. Se ela continuasse valendo, o
	requisito só alcançaria quem se deslogou — e quem não se deslogou seguiria
	dentro por até doze horas.
	"""

	def test_uma_sessao_sem_o_carimbo_e_derrubada(self):
		user_id = self.create()
		with self.client.session_transaction() as session:
			# Exatamente o que o login antigo deixava: identidade, e nada de MFA
			session['_user_id'] = str(user_id)
			session['_fresh'] = True
			session['started_at'] = '2099-01-01 00:00:00'
			session['last_seen'] = '2099-01-01 00:00:00'
			session['pwd_marker'] = ''
			session['sid'] = 'sessao-antiga'
		auth._live_sessions['sessao-antiga'] = auth._utcnow()
		self.assertBlocked()
		# E foi derrubada, não só recusada uma vez
		with self.client.session_transaction() as session:
			self.assertNotIn('_user_id', session)


class TelaDeLogin(Base):
	"""Em que passo a tela abre é decisão do servidor, nunca da URL.

	Importa porque é por aqui que o retorno do SSO chega: o provedor redireciona
	para /login, e é o desafio guardado na sessão que diz se a tela abre pedindo
	senha, pedindo o código, ou mostrando o QR. Um /login?stage=... deixaria
	qualquer um escolher.
	"""

	def test_sem_desafio_a_tela_abre_pedindo_senha(self):
		page = self.client.get('/login')
		self.assertEqual(200, page.status_code)
		self.assertIn('data-mfa-stage=""', page.get_data(as_text = True))

	def test_com_a_senha_dada_e_sem_MFA_a_tela_abre_na_configuracao(self):
		self.create()
		self.login()
		self.assertIn('data-mfa-stage="enroll"', self.client.get('/login').get_data(as_text = True))

	def test_com_MFA_configurado_a_tela_abre_pedindo_o_codigo(self):
		self.enrolled_user()
		self.client.post('/api/auth/logout')
		self.login()
		self.assertIn('data-mfa-stage="verify"', self.client.get('/login').get_data(as_text = True))

	def test_o_estagio_nao_sai_da_URL(self):
		page = self.client.get('/login?mfa_stage=verify&stage=verify')
		self.assertIn('data-mfa-stage=""', page.get_data(as_text = True))


class MetodosProibidos(Base):
	"""Critério de aceite: só aplicativo autenticador. Nada de e-mail nem SMS.

	Este teste falha no dia em que alguém acrescentar um "enviar código por
	e-mail" — que é justamente o pedido que costuma chegar depois, quando o
	primeiro usuário perde o telefone. O caminho certo para isso é a reposição
	por um global_admin (POST /api/users/<id>/mfa/reset), não um canal novo.
	"""

	def test_nenhuma_rota_de_MFA_por_outro_canal_existe(self):
		rotas = {str(rule) for rule in self.app.url_map.iter_rules()}
		mfa_rotas = {rota for rota in rotas if '/mfa' in rota}
		self.assertEqual({
			'/api/auth/mfa/setup',
			'/api/auth/mfa/activate',
			'/api/auth/mfa/verify',
			'/api/users/<int:user_id>/mfa/reset'
		}, mfa_rotas)

	def test_o_QR_e_a_unica_entrega_do_segredo(self):
		# O segredo sai uma vez, no corpo do POST que desenha o QR, para quem
		# acabou de provar a senha. Nunca por um canal que a plataforma envie
		self.create()
		self.login()
		body = self.client.post('/api/auth/mfa/setup').get_json()
		self.assertIn('qr', body)
		self.assertIn('secret', body)
		# E não volta a sair depois que a conta está configurada
		self.client.post('/api/auth/mfa/activate', json = {'code': code_for(body['secret'])})
		me = self.client.get('/api/auth/me').get_json()
		self.assertTrue(me['mfaEnrolled'])
		self.assertNotIn('secret', me)
		self.assertNotIn('mfaSecret', me)


class ReposicaoPorAdmin(Base):
	"""Telefone perdido: o único caminho de volta, e quem pode andar nele."""

	def test_um_global_admin_zera_e_a_conta_volta_a_ser_cobrada(self):
		alvo = self.create('analista')
		self.enrolled_user('dona', models.ROLE_GLOBAL_ADMIN)
		# A conta do alvo precisa estar configurada para haver o que zerar
		session = models.get_session()
		try:
			user = session.query(models.User).get(alvo)
			secret = user.start_mfa_enrollment()
			_, counter = mfa.verify(secret, code_for(secret))
			user.confirm_mfa(counter)
			session.commit()
		finally:
			session.close()

		response = self.client.post('/api/users/{0}/mfa/reset'.format(alvo))
		self.assertEqual(200, response.status_code)
		self.assertFalse(response.get_json()['mfaEnrolled'])

		# E o próximo login do alvo volta a cobrar a configuração
		self.client.post('/api/auth/logout')
		self.assertFalse(self.login('analista').get_json()['mfaEnrolled'])

	def test_um_analista_nao_zera_o_MFA_de_ninguem(self):
		alvo = self.create('outro')
		self.enrolled_user('analista', models.ROLE_ANALYST)
		self.assertEqual(403, self.client.post('/api/users/{0}/mfa/reset'.format(alvo)).status_code)


def wrong_code_for(secret):
	"""Um código de seis dígitos que não vale em nenhum passo da janela de agora."""
	valid = set(code_for(secret, time.time() + offset * mfa.PERIOD_SECONDS) for offset in (-1, 0, 1, 2))
	for candidate in ('000000', '111111', '222222', '333333', '444444'):
		if candidate not in valid:
			return candidate


class PrazoETentativas(Base):
	"""O desafio tem 45 s (2 min para parear) e 3 códigos errados.

	Os dois limites moram no servidor. É isso que os testes de repetição do
	cookie seguram: a sessão do Flask é um cookie que o navegador guarda, e um
	contador gravado nele voltaria a zero para quem reenviasse o cookie de antes
	do erro.
	"""

	def challenged(self):
		"""Conta com aplicativo pareado e um desafio de código recém-aberto."""
		secret = self.enrolled_user()
		self.client.post('/api/auth/logout')
		response = self.login()
		return secret, response.get_json()

	def later(self, seconds):
		moment = datetime.datetime.utcnow() + datetime.timedelta(seconds = seconds)
		return mock.patch.object(auth, '_utcnow', return_value = moment)

	def verify(self, code):
		return self.client.post('/api/auth/mfa/verify', json = {'code': code})

	def session_cookie(self):
		cookie = self.client.get_cookie('session')
		return cookie.value if cookie is not None else None

	def put_session_cookie(self, value):
		self.client.set_cookie('session', value)

	def failed_logins(self):
		session = models.get_session()
		try:
			return session.query(models.User).first().failed_logins
		finally:
			session.close()

	def test_o_login_diz_o_prazo_e_as_tentativas(self):
		_, body = self.challenged()
		self.assertEqual(3, body['attemptsLeft'])
		self.assertTrue(43 <= body['expiresIn'] <= 45, body['expiresIn'])

	def test_quem_ainda_vai_parear_tem_dois_minutos(self):
		self.create()
		body = self.login().get_json()
		self.assertTrue(115 <= body['expiresIn'] <= 120, body['expiresIn'])
		self.client.post('/api/auth/mfa/setup')
		secret = self.secret_of('analista')
		with self.later(110):
			self.assertEqual(200, self.client.post('/api/auth/mfa/activate',
				json = {'code': code_for(secret)}).status_code)

	def test_o_pareamento_tambem_vence(self):
		self.create()
		self.login()
		self.client.post('/api/auth/mfa/setup')
		secret = self.secret_of('analista')
		with self.later(2 * 60 + 1):
			response = self.client.post('/api/auth/mfa/activate', json = {'code': code_for(secret)})
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])

	def test_dentro_dos_45_segundos_o_codigo_entra(self):
		secret, _ = self.challenged()
		with self.later(44):
			self.assertEqual(200, self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS)).status_code)
		self.assertOpen()

	def test_depois_dos_45_segundos_nem_o_codigo_certo_entra(self):
		secret, _ = self.challenged()
		with self.later(46):
			response = self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS))
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])
		self.assertEqual(auth.MFA_END_EXPIRED, response.get_json()['reason'])
		self.assertBlocked()
		# E o desafio não volta a valer com o relógio de novo dentro do prazo
		self.assertEqual(401, self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS)).status_code)

	def test_cada_erro_diz_quantas_tentativas_restam(self):
		secret, _ = self.challenged()
		first = self.verify(wrong_code_for(secret))
		self.assertEqual(401, first.status_code)
		self.assertEqual(2, first.get_json()['attemptsLeft'])
		self.assertNotIn('restart', first.get_json())
		self.assertEqual(1, self.verify(wrong_code_for(secret)).get_json()['attemptsLeft'])

	def test_o_terceiro_erro_devolve_para_a_senha(self):
		secret, _ = self.challenged()
		self.verify(wrong_code_for(secret))
		self.verify(wrong_code_for(secret))
		third = self.verify(wrong_code_for(secret))
		self.assertEqual(401, third.status_code)
		self.assertTrue(third.get_json()['restart'])
		self.assertEqual(auth.MFA_END_ATTEMPTS, third.get_json()['reason'])
		# Nem o código certo salva o desafio encerrado
		response = self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS))
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])
		self.assertBlocked()

	def test_reenviar_o_cookie_de_antes_do_erro_nao_devolve_tentativas(self):
		secret, _ = self.challenged()
		before = self.session_cookie()
		for _ in range(2):
			self.verify(wrong_code_for(secret))
			self.put_session_cookie(before)
		third = self.verify(wrong_code_for(secret))
		self.assertTrue(third.get_json().get('restart'))
		# O cookie do começo do desafio, de novo: o servidor já o encerrou
		self.put_session_cookie(before)
		response = self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS))
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])
		self.assertBlocked()

	def test_o_cookie_de_um_desafio_ja_vencido_nao_reabre_o_passo(self):
		"""Um acerto encerra o desafio: a cópia do cookie de antes dele não vale."""
		secret, _ = self.challenged()
		before = self.session_cookie()
		self.assertEqual(200, self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS)).status_code)
		other = self.app.test_client()
		other.set_cookie('session', before)
		response = other.post('/api/auth/mfa/verify', json = {'code': code_for(secret, time.time() + 2 * mfa.PERIOD_SECONDS)})
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])

	def test_um_login_novo_substitui_o_desafio_anterior(self):
		secret, _ = self.challenged()
		other = self.app.test_client()
		other.post('/api/auth/login', json = {'username': 'analista', 'password': SENHA})
		response = self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS))
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])

	def test_um_processo_reiniciado_nao_reconhece_o_desafio(self):
		secret, _ = self.challenged()
		auth._mfa_challenges.clear()
		response = self.verify(code_for(secret, time.time() + mfa.PERIOD_SECONDS))
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['restart'])

	def test_o_bloqueio_da_conta_continua_contando_entre_desafios(self):
		"""3 por desafio não substitui os 5 por conta: dois desafios bloqueiam."""
		secret, _ = self.challenged()
		for _ in range(3):
			self.verify(wrong_code_for(secret))
		self.assertEqual(3, self.failed_logins())
		self.login()
		self.verify(wrong_code_for(secret))
		# O quinto erro da conta bloqueia, e o desafio acaba junto
		fifth = self.verify(wrong_code_for(secret))
		self.assertTrue(fifth.get_json()['restart'])
		self.assertEqual(401, self.login().status_code)

	def test_voltar_da_tela_do_codigo_encerra_o_desafio(self):
		self.challenged()
		page = self.client.get('/login?reason=mfa_cancel').get_data(as_text = True)
		self.assertIn('data-mfa-stage=""', page)
		self.assertIn('data-mfa-stage=""', self.client.get('/login').get_data(as_text = True))

	def test_a_tela_de_login_diz_por_que_a_pessoa_voltou(self):
		self.assertIn('O código foi recusado vezes demais',
			self.client.get('/login?reason=mfa_attempts').get_data(as_text = True))
		self.assertIn('O prazo para digitar o código acabou',
			self.client.get('/login?reason=mfa_expired').get_data(as_text = True))
		self.assertNotIn('vezes demais', self.client.get('/login?reason=qualquer').get_data(as_text = True))

	def test_a_tela_aberta_no_passo_do_codigo_traz_o_prazo(self):
		self.challenged()
		page = self.client.get('/login').get_data(as_text = True)
		self.assertIn('data-mfa-attempts-left="3"', page)
		self.assertRegex(page, r'data-mfa-expires-in="4[3-5]"')


if __name__ == '__main__':
	unittest.main()
