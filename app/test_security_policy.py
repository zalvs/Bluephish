"""Auto logoff configurável (Configurações → Segurança).

O que estes testes seguram, e por que cada um falharia em silêncio:

* **O piso.** Um valor abaixo do mínimo — pela tela ou à mão no arquivo — não
  pode desligar o auto logoff. O servidor recusa o formulário e, no arquivo,
  vale o limite mais próximo.
* **O valor configurado vale de verdade**, no HTTP e na pergunta do websocket
  (`auth.session_policy_holds`), porque os dois passam por
  `_session_violation`. Um número salvo que só a tela respeitasse seria um
  controle de enfeite.
* **O painel sabe quanto falta.** É do sinal de vida que sai o aviso antes de
  desligar; sem `secondsLeft` a sessão cai sem aviso.

Roda com:  python -m unittest test_security_policy   (a partir de app/)
"""

import datetime
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

import flask
import flask_login

import auth
import models
import security_policy
import test_mfa_gate as gate

try:
	import thephish_app
except Exception:  # sem as dependências da imagem (eventlet, flask...) o teste de rota fica de fora
	thephish_app = None

HUMAN = {'X-Requested-With': 'XMLHttpRequest', 'X-User-Activity': '1'}
AUTOMATIC = {'X-Requested-With': 'XMLHttpRequest'}


class ConfigFile(object):
	"""Um configuration.json temporário no lugar do real, durante um teste."""

	def __init__(self, security = None):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-security-')
		self.path = os.path.join(self.directory, 'configuration.json')
		self.writes = 0
		self.write(security)
		self.previous = security_policy.CONFIG_FILE
		security_policy.CONFIG_FILE = self.path
		self.forget()

	@staticmethod
	def forget():
		# Inclusive a última configuração boa: ela vale enquanto o arquivo estiver
		# ilegível, e a de um teste não pode valer no seguinte
		security_policy._cache.update({'key': None, 'config': None, 'good': None})

	def write(self, security):
		body = {'imap': {}}
		if security is not None:
			body['security'] = security
		with open(self.path, 'w') as handle:
			json.dump(body, handle)
		# O cache decide pelo mtime; dois writes no mesmo instante teriam o mesmo
		self.writes += 1
		moment = time.time() + self.writes
		os.utime(self.path, (moment, moment))

	def close(self):
		security_policy.CONFIG_FILE = self.previous
		self.forget()
		shutil.rmtree(self.directory, ignore_errors = True)


class Validacao(unittest.TestCase):

	def form(self, idle = '30', absolute = '12', warn = '60'):
		return {'idleMinutes': idle, 'absoluteHours': absolute, 'warnSeconds': warn}

	def test_os_valores_padrao_passam(self):
		config, error = security_policy.validate(self.form())
		self.assertIsNone(error)
		self.assertEqual({'idleMinutes': 30, 'absoluteHours': 12, 'warnSeconds': 60}, config['session'])

	def test_o_piso_da_inatividade_e_conferido_no_servidor(self):
		self.assertIsNotNone(security_policy.validate(self.form(idle = '4'))[1])
		self.assertIsNotNone(security_policy.validate(self.form(idle = '0'))[1])
		self.assertIsNotNone(security_policy.validate(self.form(idle = '241'))[1])

	def test_a_sessao_tem_piso_e_teto(self):
		self.assertIsNotNone(security_policy.validate(self.form(absolute = '0'))[1])
		self.assertIsNotNone(security_policy.validate(self.form(absolute = '25'))[1])

	def test_a_sessao_nao_pode_ser_mais_curta_que_a_inatividade(self):
		self.assertIsNotNone(security_policy.validate(self.form(idle = '90', absolute = '1'))[1])
		self.assertIsNone(security_policy.validate(self.form(idle = '60', absolute = '1'))[1])

	def test_o_aviso_tem_limites_e_cabe_na_inatividade(self):
		self.assertIsNotNone(security_policy.validate(self.form(warn = '10'))[1])
		self.assertIsNotNone(security_policy.validate(self.form(warn = '301'))[1])
		# Cinco minutos de inatividade com aviso de quatro e meio: avisaria quase sempre
		self.assertIsNotNone(security_policy.validate(self.form(idle = '5', warn = '270'))[1])

	def test_texto_nao_e_numero(self):
		self.assertIsNotNone(security_policy.validate(self.form(idle = 'trinta'))[1])
		self.assertIsNotNone(security_policy.validate({})[1])


class Arquivo(unittest.TestCase):

	def setUp(self):
		self.config = ConfigFile()

	def tearDown(self):
		self.config.close()

	def test_sem_a_chave_vale_o_padrao(self):
		self.assertEqual((30, 12, 60), security_policy.session_limits())

	def test_valor_gravado_a_mao_fora_dos_limites_nao_e_obedecido(self):
		self.config.write({'session': {'idleMinutes': 0, 'absoluteHours': 999, 'warnSeconds': 1}})
		self.assertEqual((5, 24, 30), security_policy.session_limits())

	def test_sessao_mais_curta_que_a_inatividade_e_esticada(self):
		self.config.write({'session': {'idleMinutes': 150, 'absoluteHours': 1}})
		idle, absolute, _ = security_policy.session_limits()
		self.assertEqual(150, idle)
		self.assertEqual(3, absolute)

	def test_uma_edicao_do_arquivo_vale_sem_reiniciar(self):
		self.assertEqual(30, security_policy.session_limits()[0])
		self.config.write({'session': {'idleMinutes': 10}})
		self.assertEqual(10, security_policy.session_limits()[0])

	def test_secao_com_formato_errado_nao_derruba_nada(self):
		# Um AttributeError aqui seria 500 em toda rota protegida e nenhum socket
		for broken in ({'session': 'x'}, [1], 'texto', {'session': [1]}):
			self.config.write(broken)
			with self.assertLogs('security_policy', level = 'ERROR'):
				self.assertEqual((30, 12, 60), security_policy.session_limits())

	def test_arquivo_ilegivel_mantem_a_ultima_configuracao_boa(self):
		# Uma inatividade de 5 minutos não vira 30 porque alguém deixou uma vírgula
		# sobrando, ou porque a leitura pegou o arquivo no meio de uma gravação
		self.config.write({'session': {'idleMinutes': 5, 'absoluteHours': 1, 'warnSeconds': 30}})
		self.assertEqual((5, 1, 30), security_policy.session_limits())
		with open(self.config.path, 'w') as handle:
			handle.write('{"security": {"session": {"idleMinutes": 5,}}')
		os.utime(self.config.path, (time.time() + 100, time.time() + 100))
		with self.assertLogs('security_policy', level = 'ERROR') as logged:
			self.assertEqual((5, 1, 30), security_policy.session_limits())
		self.assertIn('a última lida', logged.output[0])
		self.assertEqual((5, 1, 30), security_policy.session_limits())

	def test_a_trilha_de_auditoria_tambem_tolera_formato_errado(self):
		import audit_store
		with open(self.config.path, 'w') as handle:
			json.dump({'auditLog': 'x'}, handle)
		self.assertEqual(audit_store.DEFAULTS['retentionDays'], audit_store.load_config(self.config.path)['retentionDays'])
		with open(self.config.path, 'w') as handle:
			json.dump({'auditLog': {'syslog': 'x'}}, handle)
		self.assertFalse(audit_store.load_config(self.config.path)['syslog']['enabled'])

	def test_salvar_preserva_o_resto_da_configuracao(self):
		config, _ = security_policy.validate({'idleMinutes': '15', 'absoluteHours': '8', 'warnSeconds': '45'})
		security_policy.save_config(config)
		with open(self.config.path) as handle:
			stored = json.load(handle)
		self.assertIn('imap', stored)
		self.assertEqual((15, 8, 45), security_policy.session_limits())


class SessaoConfigurada(gate.Base):
	"""O prazo salvo é o que derruba a sessão — no HTTP e no websocket."""

	def setUp(self):
		super().setUp()
		self.config = ConfigFile({'session': {'idleMinutes': 10, 'absoluteHours': 2, 'warnSeconds': 60}})
		self.enrolled_user()

	def tearDown(self):
		self.config.close()
		super().tearDown()

	def age(self, last_seen_minutes = 0, started_minutes = 0):
		with self.client.session_transaction() as session:
			now = auth._utcnow()
			session['last_seen'] = (now - datetime.timedelta(minutes = last_seen_minutes)).strftime('%Y-%m-%d %H:%M:%S')
			session['started_at'] = (now - datetime.timedelta(minutes = started_minutes)).strftime('%Y-%m-%d %H:%M:%S')

	def tab_token(self):
		with self.client.session_transaction() as session:
			return session['tab_token']

	def heartbeat(self, headers):
		return self.client.post('/api/auth/heartbeat', headers = dict(headers, **{'X-Session-Tab': self.tab_token()})).get_json()

	def test_dentro_da_inatividade_configurada_a_sessao_vale(self):
		self.age(last_seen_minutes = 9)
		self.assertOpen()

	def test_passada_a_inatividade_configurada_a_sessao_cai(self):
		# 11 minutos: dentro do padrão de 30, fora dos 10 configurados
		self.age(last_seen_minutes = 11)
		self.assertBlocked()

	def holds_with_session_aged(self, last_seen_minutes):
		"""A pergunta do handshake do websocket, sobre uma sessão com esta idade."""
		with self.client.session_transaction() as session:
			stored = dict(session)
		db_session = models.get_session()
		try:
			user = db_session.query(models.User).first()
			with self.app.test_request_context():
				flask_login.login_user(user)
				flask.session.update(stored)
				flask.session['last_seen'] = (auth._utcnow() - datetime.timedelta(
					minutes = last_seen_minutes)).strftime('%Y-%m-%d %H:%M:%S')
				return auth.session_policy_holds()
		finally:
			db_session.close()

	def test_o_websocket_obedece_ao_mesmo_prazo(self):
		self.assertTrue(self.holds_with_session_aged(9))
		self.assertFalse(self.holds_with_session_aged(11))

	def test_a_duracao_maxima_configurada_vale_mesmo_com_uso(self):
		self.age(last_seen_minutes = 0, started_minutes = 2 * 60 + 1)
		self.assertBlocked()

	def test_o_sinal_de_vida_diz_quanto_falta(self):
		self.age(last_seen_minutes = 4)
		body = self.heartbeat(AUTOMATIC)
		self.assertEqual(60, body['warnSeconds'])
		self.assertEqual('idle', body['endsBy'])
		# Sinal automático não renova: faltam ~6 dos 10 minutos
		self.assertTrue(5 * 60 <= body['secondsLeft'] <= 6 * 60, body['secondsLeft'])

	def test_o_sinal_com_gesto_renova_e_diz_isso(self):
		self.age(last_seen_minutes = 9)
		body = self.heartbeat(HUMAN)
		self.assertTrue(body['secondsLeft'] >= 10 * 60 - 2, body['secondsLeft'])

	def test_perto_do_fim_da_sessao_o_aviso_e_dela(self):
		# Quem está trabalhando no fim da duração máxima não está inativo: o
		# painel precisa saber que o prazo que vence é o outro, que nenhum gesto adia
		self.age(last_seen_minutes = 0, started_minutes = 2 * 60 - 3)
		body = self.heartbeat(HUMAN)
		self.assertEqual('absolute', body['endsBy'])
		self.assertTrue(body['secondsLeft'] <= 3 * 60, body['secondsLeft'])

	def test_longe_do_fim_da_sessao_o_aviso_e_da_inatividade(self):
		self.age(last_seen_minutes = 8, started_minutes = 30)
		body = self.heartbeat(AUTOMATIC)
		self.assertEqual('idle', body['endsBy'])
		self.assertTrue(body['secondsLeft'] <= 2 * 60, body['secondsLeft'])


class MotivoDoFim(SessaoConfigurada):
	"""Quem diz por que a sessão caiu é o servidor, e a tela mostra isso.

	Um palpite do relógio do painel diria "inatividade" a quem teve a sessão
	revogada por troca de senha — e cada aba que recebesse o 401 primeiro
	espalharia o motivo errado para as outras.
	"""

	def test_inatividade(self):
		self.age(last_seen_minutes = 11)
		self.assertEqual('idle', self.client.get('/api/list', headers = AUTOMATIC).get_json()['reason'])

	def test_duracao_maxima(self):
		self.age(started_minutes = 2 * 60 + 1)
		self.assertEqual('expired', self.client.get('/api/list', headers = AUTOMATIC).get_json()['reason'])

	def test_troca_de_senha(self):
		db_session = models.get_session()
		try:
			user = db_session.query(models.User).first()
			user.password_changed_at = datetime.datetime.utcnow() + datetime.timedelta(seconds = 5)
			db_session.commit()
		finally:
			db_session.close()
		self.assertEqual('password', self.client.get('/api/list', headers = AUTOMATIC).get_json()['reason'])

	def test_aba_errada(self):
		body = self.client.post('/api/auth/heartbeat', headers = dict(AUTOMATIC, **{'X-Session-Tab': 'outro'})).get_json()
		self.assertEqual('tab', body['reason'])

	def test_navegacao_de_pagina_leva_o_motivo_ao_login(self):
		self.age(last_seen_minutes = 11)
		location = self.client.get('/list').headers['Location']
		self.assertIn('reason=idle', location)

	def test_sem_sessao_nenhuma_nao_ha_motivo(self):
		self.client.post('/api/auth/logout')
		self.assertNotIn('reason', self.client.get('/api/list', headers = AUTOMATIC).get_json())

	def test_os_limites_sao_lidos_uma_vez_por_requisicao(self):
		with mock.patch.object(security_policy, 'session_limits', wraps = security_policy.session_limits) as limits:
			self.heartbeat(HUMAN)
		self.assertEqual(1, limits.call_count)


class MensagensTraduzidas(unittest.TestCase):
	"""Toda recusa do formulário tem tradução: exata ou por padrão (i18n-en.js)."""

	def test_toda_recusa_da_validacao_tem_traducao(self):
		import re
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'assets', 'js', 'i18n-en.js'), encoding = 'utf-8') as handle:
			source = handle.read()
		prefix = 'window.BLUEPHISH_I18N_EN = '
		dictionary = json.loads(source[source.index(prefix) + len(prefix):].rstrip().rstrip(';'))
		patterns = [re.compile(pattern) for pattern, _ in dictionary['patterns']]
		forms = [{}, {'idleMinutes': '1', 'absoluteHours': '1', 'warnSeconds': '30'},
			{'idleMinutes': '30', 'absoluteHours': '99', 'warnSeconds': '30'},
			{'idleMinutes': '120', 'absoluteHours': '1', 'warnSeconds': '30'},
			{'idleMinutes': '30', 'absoluteHours': '12', 'warnSeconds': '5'},
			{'idleMinutes': '5', 'absoluteHours': '12', 'warnSeconds': '200'}]
		for form in forms:
			error = security_policy.validate(form)[1]
			self.assertIsNotNone(error, form)
			self.assertTrue(error in dictionary['exact'] or any(p.search(error) for p in patterns), error)
		status = 'Sai após 30 min sem uso, e em 12 h de qualquer jeito. Avisa 60 s antes.'
		self.assertTrue(any(p.search(status) for p in patterns))


class TelaDeLogin(gate.Base):

	def test_quem_caiu_por_inatividade_ve_o_motivo(self):
		page = self.client.get('/login?reason=idle').get_data(as_text = True)
		self.assertIn('encerrada por inatividade', page)
		self.assertNotIn('encerrada por inatividade', self.client.get('/login').get_data(as_text = True))

	def test_quem_teve_a_senha_trocada_ve_o_motivo(self):
		self.assertIn('A senha desta conta foi trocada', self.client.get('/login?reason=password').get_data(as_text = True))

	def test_quem_atingiu_a_duracao_maxima_nao_le_que_estava_inativo(self):
		page = self.client.get('/login?reason=expired').get_data(as_text = True)
		self.assertIn('atingiu a duração máxima', page)
		self.assertNotIn('inatividade', page)


@unittest.skipIf(thephish_app is None, 'thephish_app precisa da imagem')
class RotaSoDeGlobalAdmin(unittest.TestCase):
	"""/security-config na aplicação de verdade: o papel é cobrado no servidor.

	Esconder a aba de quem não é global_admin é conveniência; o controle é a rota
	recusar. CSRF e o limite por IP ficam desligados aqui porque não são o que se
	testa, e ligados derrubariam os logins repetidos.
	"""

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-security-route-')
		self.previous_db = models.DB_PATH
		self.previous_log = auth.AUDIT_LOG_PATH
		models.DB_PATH = os.path.join(self.directory, 'bluephish.db')
		auth.AUDIT_LOG_PATH = os.path.join(self.directory, 'auth.log')
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		auth._live_sessions.clear()
		auth._mfa_challenges.clear() if hasattr(auth, '_mfa_challenges') else None
		self.config = ConfigFile()
		app = thephish_app.app
		self.previous_flags = (app.config.get('WTF_CSRF_ENABLED', True), app.config['SESSION_COOKIE_SECURE'], thephish_app.limiter.enabled)
		app.config['WTF_CSRF_ENABLED'] = False
		app.config['SESSION_COOKIE_SECURE'] = False
		thephish_app.limiter.enabled = False
		self.audited = []
		self.audit_patch = mock.patch.object(auth, 'audit', side_effect = lambda event, *args, **kwargs: self.audited.append((event, kwargs.get('status'))))
		self.audit_patch.start()

	def tearDown(self):
		self.audit_patch.stop()
		app = thephish_app.app
		app.config['WTF_CSRF_ENABLED'], app.config['SESSION_COOKIE_SECURE'], thephish_app.limiter.enabled = self.previous_flags
		self.config.close()
		models.DB_PATH = self.previous_db
		auth.AUDIT_LOG_PATH = self.previous_log
		models._engine = None
		models._SessionFactory = None
		shutil.rmtree(self.directory, ignore_errors = True)

	def signed_in(self, role):
		username = 'pessoa-' + role
		models.create_user(username, gate.SENHA, role)
		client = thephish_app.app.test_client()
		client.post('/api/auth/login', json = {'username': username, 'password': gate.SENHA})
		client.post('/api/auth/mfa/setup')
		db_session = models.get_session()
		try:
			secret = db_session.query(models.User).filter(models.User.username == username).first().mfa_secret
		finally:
			db_session.close()
		activated = client.post('/api/auth/mfa/activate', json = {'code': gate.code_for(secret)})
		self.assertEqual(200, activated.status_code)
		with client.session_transaction() as session:
			tab = session['tab_token']
		client.environ_base['HTTP_X_SESSION_TAB'] = tab
		return client

	VALID = {'idleMinutes': '15', 'absoluteHours': '8', 'warnSeconds': '45'}

	def test_analista_e_admin_sao_recusados(self):
		for role in (models.ROLE_ANALYST, models.ROLE_ADMIN):
			client = self.signed_in(role)
			self.assertEqual(403, client.get('/security-config', headers = AUTOMATIC).status_code, role)
			self.assertEqual(403, client.post('/security-config', data = self.VALID, headers = AUTOMATIC).status_code, role)
		self.assertEqual((30, 12, 60), security_policy.session_limits())

	def test_global_admin_le_e_grava_com_antes_e_depois_na_trilha(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		self.assertEqual(30, client.get('/security-config', headers = AUTOMATIC).get_json()['session']['idleMinutes'])
		saved = client.post('/security-config', data = self.VALID, headers = AUTOMATIC).get_json()
		self.assertEqual(15, saved['session']['idleMinutes'])
		self.assertEqual((15, 8, 45), security_policy.session_limits())
		self.assertIn(('security_config_update', 'ok'), self.audited)

	def test_valor_fora_do_piso_e_recusado_e_auditado(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		body = client.post('/security-config', data = dict(self.VALID, idleMinutes = '1'), headers = AUTOMATIC).get_json()
		self.assertIn('error', body)
		self.assertEqual((30, 12, 60), security_policy.session_limits())
		self.assertIn(('security_config_update', 'refused'), self.audited)


if __name__ == '__main__':
	unittest.main()
