"""Testes do limite por IP, do banimento de IP e da lista de liberados (abuse_guard).

O que se prende aqui, e por que cada um falharia em silêncio:

  * **N falhas banem o IP**, e o IP banido não chega nem a tentar a senha certa —
    nem pelo HTTP, nem pelo handshake do websocket;
  * **o endereço que não é uma pessoa nunca é banido**: o loopback sem
    X-Forwarded-For e o gateway do Docker são todo mundo ao mesmo tempo, e banir
    um deles trancaria a instalação inteira de fora;
  * **a lista de liberados vem antes de tudo**, e liberar um IP banido o solta;
  * **o limite por minuto soma todas as rotas**, não conta os arquivos estáticos,
    e o minuto estourado conta *uma* falha, não uma por requisição;
  * **salvar a sessão não apaga a proteção** (as duas moram na mesma seção do
    configuration.json), e um valor gravado à mão fora dos limites não vale;
  * **a memória tem teto**.

Roda com:  python -m unittest test_abuse_guard   (a partir do diretório app/)
"""

import time
import unittest

import abuse_guard
import auth
import client_addr
import models
import security_policy
import test_mfa_gate
import test_security_policy
from test_security_policy import AUTOMATIC, ConfigFile

PERSON = '203.0.113.7'
OTHER = '198.51.100.9'


def policy(per_minute = 1200, rate = True, ban = True, max_failures = 3, window = 10, minutes = 30):
	return {
		'rateLimit': {'enabled': rate, 'perMinute': per_minute},
		'ban': {'enabled': ban, 'maxFailures': max_failures, 'windowMinutes': window, 'banMinutes': minutes},
		'allowlist': []
	}


class Unidade(unittest.TestCase):

	def setUp(self):
		abuse_guard.reset()
		self.addCleanup(abuse_guard.reset)

	def test_bane_na_falha_que_completa_o_limite(self):
		rules = policy(max_failures = 3)
		self.assertFalse(abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 100))
		self.assertFalse(abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 101))
		self.assertTrue(abuse_guard.record_failure(PERSON, abuse_guard.KIND_MFA, rules, 102))
		verdict = abuse_guard.check(PERSON, rules, 103)
		self.assertEqual((True, 'banned'), verdict[:2])
		self.assertEqual(30 * 60 - 1, verdict.retry_after)

	def test_falhas_fora_da_janela_nao_somam(self):
		rules = policy(max_failures = 3, window = 1)
		abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 0)
		abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 30)
		self.assertFalse(abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 61))

	def test_o_banimento_acaba_sozinho(self):
		rules = policy(max_failures = 3, minutes = 1)
		for moment in (0, 1, 2):
			abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, moment)
		self.assertTrue(abuse_guard.check(PERSON, rules, 61).refused)
		self.assertFalse(abuse_guard.check(PERSON, rules, 63).refused)
		self.assertEqual([], abuse_guard.bans(63))

	def test_banimento_desligado_nao_bane(self):
		rules = policy(ban = False, max_failures = 3)
		for moment in range(10):
			self.assertFalse(abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, moment))
		self.assertFalse(abuse_guard.check(PERSON, rules, 11).refused)

	def test_o_limite_soma_as_requisicoes_do_minuto(self):
		rules = policy(per_minute = 60)
		for _ in range(60):
			self.assertFalse(abuse_guard.check(PERSON, rules, 10).refused)
		verdict = abuse_guard.check(PERSON, rules, 10)
		self.assertEqual((True, 'limited'), verdict[:2])
		self.assertEqual(60, verdict.retry_after)
		# O minuto virou: o contador recomeça
		self.assertFalse(abuse_guard.check(PERSON, rules, 70).refused)

	def test_o_minuto_estourado_conta_uma_falha_so(self):
		rules = policy(per_minute = 60, max_failures = 3)
		for _ in range(500):
			abuse_guard.check(PERSON, rules, 10)
		self.assertEqual([], abuse_guard.bans(10))
		# O terceiro minuto estourado bane
		for start in (70, 130):
			for _ in range(61):
				verdict = abuse_guard.check(PERSON, rules, start)
		self.assertEqual('banned_now', verdict.reason)
		self.assertEqual(abuse_guard.KIND_RATE, abuse_guard.bans(131)[0]['kind'])

	def test_limite_desligado_nao_limita(self):
		rules = policy(per_minute = 60, rate = False)
		for _ in range(500):
			self.assertFalse(abuse_guard.check(PERSON, rules, 10).refused)

	def test_um_ip_nao_paga_pelo_outro(self):
		rules = policy(max_failures = 3)
		for moment in (0, 1, 2):
			abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, moment)
		self.assertFalse(abuse_guard.check(OTHER, rules, 3).refused)

	def test_desbanir_solta_e_zera_as_falhas(self):
		rules = policy(max_failures = 3)
		for moment in (0, 1, 2):
			abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, moment)
		self.assertTrue(abuse_guard.unban(PERSON))
		self.assertFalse(abuse_guard.check(PERSON, rules, 3).refused)
		self.assertFalse(abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, 4))
		self.assertFalse(abuse_guard.unban(PERSON))

	def test_liberar_um_ip_banido_o_solta(self):
		rules = policy(max_failures = 3)
		for moment in (0, 1, 2):
			abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, rules, moment)
		released = abuse_guard.release_allowed(abuse_guard.parse_allowlist(['203.0.113.0/24']))
		self.assertEqual([PERSON], released)
		self.assertFalse(abuse_guard.check(PERSON, rules, 3).refused)

	def test_a_memoria_tem_teto(self):
		rules = policy(max_failures = 50)
		previous = abuse_guard.MAX_TRACKED
		abuse_guard.MAX_TRACKED = 5
		self.addCleanup(setattr, abuse_guard, 'MAX_TRACKED', previous)
		for index in range(20):
			abuse_guard.record_failure('10.0.0.{0}'.format(index), abuse_guard.KIND_LOGIN, rules, index)
			abuse_guard.check('10.0.1.{0}'.format(index), rules, index)
		self.assertEqual(5, len(abuse_guard._failures))
		self.assertEqual(5, len(abuse_guard._windows))


class QuemEContavel(unittest.TestCase):

	TRUSTED = client_addr.parse_trusted('')

	def resolve(self, peer, forwarded = ''):
		return client_addr.resolve(peer, forwarded, self.TRUSTED)

	def test_uma_pessoa_e_contavel(self):
		self.assertTrue(abuse_guard.countable(self.resolve(PERSON), self.TRUSTED))

	def test_o_cliente_que_o_proxy_informou_e_contavel(self):
		self.assertTrue(abuse_guard.countable(self.resolve('127.0.0.1', PERSON), self.TRUSTED))

	def test_o_proxy_sem_cabecalho_nao_e(self):
		self.assertFalse(abuse_guard.countable(self.resolve('127.0.0.1'), self.TRUSTED))

	def test_o_gateway_do_docker_nao_e(self):
		self.assertFalse(abuse_guard.countable(self.resolve('172.18.0.1'), self.TRUSTED))

	def test_a_lista_de_liberados_aceita_rede_e_ipv4_dentro_de_ipv6(self):
		networks = abuse_guard.parse_allowlist(['198.51.100.0/24', 'lixo'])
		self.assertTrue(abuse_guard.is_allowed('198.51.100.20', networks))
		self.assertTrue(abuse_guard.is_allowed('::ffff:198.51.100.20', networks))
		self.assertFalse(abuse_guard.is_allowed(PERSON, networks))


class Configuracao(unittest.TestCase):

	def setUp(self):
		self.config = ConfigFile()
		self.addCleanup(self.config.close)

	FORM = {'rateLimitEnabled': 'true', 'perMinute': '600', 'banEnabled': 'true', 'maxFailures': '5',
		'windowMinutes': '15', 'banMinutes': '60', 'allowlist': '203.0.113.10\n198.51.100.0/24\n\n203.0.113.10'}

	def test_o_padrao_liga_os_dois(self):
		protection = security_policy.protection_policy()
		self.assertTrue(protection['rateLimit']['enabled'])
		self.assertTrue(protection['ban']['enabled'])
		self.assertEqual([], protection['allowlist'])

	def test_o_formulario_valido_e_normalizado(self):
		part, error = security_policy.validate_protection(self.FORM)
		self.assertIsNone(error)
		self.assertEqual(['203.0.113.10', '198.51.100.0/24'], part['protection']['allowlist'])
		self.assertEqual(600, part['protection']['rateLimit']['perMinute'])

	def test_rede_grande_demais_e_recusada(self):
		for entry in ('0.0.0.0/0', '10.0.0.0/7', '::/0', '2001:db8::/31'):
			_, error = security_policy.validate_protection(dict(self.FORM, allowlist = entry))
			self.assertIn('grande demais', error, entry)

	def test_linha_que_nao_e_endereco_e_recusada(self):
		_, error = security_policy.validate_protection(dict(self.FORM, allowlist = 'escritorio'))
		self.assertIn('não é um endereço', error)

	def test_numeros_fora_dos_limites_sao_recusados(self):
		for field, value in (('perMinute', '10'), ('maxFailures', '1'), ('windowMinutes', '0'), ('banMinutes', '99999')):
			_, error = security_policy.validate_protection(dict(self.FORM, **{field: value}))
			self.assertIsNotNone(error, field)

	def test_salvar_a_sessao_nao_apaga_a_protecao(self):
		part, _ = security_policy.validate_protection(self.FORM)
		security_policy.save_config(security_policy.merged(part))
		session, _ = security_policy.validate({'idleMinutes': '15', 'absoluteHours': '8', 'warnSeconds': '45'})
		security_policy.save_config(security_policy.merged(session))
		self.assertEqual(['203.0.113.10', '198.51.100.0/24'], security_policy.protection_policy()['allowlist'])
		self.assertEqual((15, 8, 45), security_policy.session_limits())

	def test_gravado_a_mao_fora_dos_limites_vale_o_limite(self):
		self.config.write({'protection': {'rateLimit': {'enabled': 'sim', 'perMinute': 5},
			'ban': {'maxFailures': 1000}, 'allowlist': ['0.0.0.0/0', '203.0.113.10']}})
		protection = security_policy.protection_policy()
		self.assertEqual(security_policy.MIN_PER_MINUTE, protection['rateLimit']['perMinute'])
		# Booleano estrito: "sim" não liga nem desliga, vale o padrão
		self.assertTrue(protection['rateLimit']['enabled'])
		self.assertEqual(security_policy.MAX_MAX_FAILURES, protection['ban']['maxFailures'])
		# A rede que liberaria todo mundo sai; a outra fica
		self.assertEqual(['203.0.113.10'], protection['allowlist'])

	def test_secao_com_formato_errado_mantem_a_ultima_boa(self):
		part, _ = security_policy.validate_protection(self.FORM)
		security_policy.save_config(security_policy.merged(part))
		self.assertEqual(5, security_policy.protection_policy()['ban']['maxFailures'])
		self.config.write({'protection': {'ban': 'x'}})
		self.assertEqual(5, security_policy.protection_policy()['ban']['maxFailures'])


class PeloHttp(test_mfa_gate.Base):
	"""O before_request e as falhas de verdade, na aplicação que os testes montam."""

	def setUp(self):
		super().setUp()
		abuse_guard.reset()
		self.addCleanup(abuse_guard.reset)
		self.config = ConfigFile({'protection': {'ban': {'maxFailures': 3}, 'rateLimit': {'perMinute': 60}}})
		self.addCleanup(self.config.close)
		self.client.environ_base['REMOTE_ADDR'] = PERSON

	def wrong(self, username = 'analista'):
		return self.login(username, 'senha errada de propósito')

	def test_tres_senhas_erradas_banem_e_nem_a_certa_passa(self):
		self.create()
		for _ in range(3):
			self.assertEqual(401, self.wrong().status_code)
		refused = self.login()
		self.assertEqual(403, refused.status_code)
		self.assertTrue(refused.get_json()['banned'])
		self.assertIn('Retry-After', refused.headers)

	def test_o_banimento_vale_para_contas_diferentes(self):
		# É o caso que o bloqueio por conta não pega: uma senha em cada conta
		for username in ('ana', 'bia', 'caio'):
			self.create(username)
			self.wrong(username)
		self.create('dora')
		self.assertEqual(403, self.login('dora').status_code)

	def test_a_navegacao_de_pagina_banida_recebe_texto_e_403(self):
		self.create()
		for _ in range(3):
			self.wrong()
		page = self.client.get('/login')
		self.assertEqual(403, page.status_code)
		self.assertIn('bloqueado temporariamente', page.get_data(as_text = True))

	def test_o_ban_entra_na_trilha(self):
		self.create()
		for _ in range(3):
			self.wrong()
		with open(auth.AUDIT_LOG_PATH) as handle:
			trail = handle.read()
		self.assertIn('ip_ban', trail)
		self.assertIn('ip=' + PERSON, trail)

	def test_codigo_do_segundo_fator_errado_conta(self):
		self.enrolled_user()
		self.client.post('/api/auth/logout')
		self.login()
		for _ in range(3):
			self.client.post('/api/auth/mfa/verify', json = {'code': '000000'})
		self.assertEqual(403, self.login().status_code)

	def test_o_loopback_sem_proxy_nunca_e_banido(self):
		self.client.environ_base['REMOTE_ADDR'] = '127.0.0.1'
		self.create()
		for _ in range(10):
			self.wrong()
		self.assertNotEqual(403, self.login().status_code)
		self.assertEqual([], abuse_guard.bans(time.time()))

	def test_o_gateway_do_docker_nunca_e_banido(self):
		self.client.environ_base['REMOTE_ADDR'] = '172.18.0.1'
		self.create()
		for _ in range(10):
			self.wrong()
		self.assertNotEqual(403, self.login().status_code)

	def test_ip_liberado_nao_e_banido(self):
		self.config.write({'protection': {'ban': {'maxFailures': 3}, 'allowlist': ['203.0.113.0/24']}})
		self.create()
		for _ in range(10):
			self.wrong()
		self.assertNotEqual(403, self.login().status_code)

	def test_o_limite_por_minuto_soma_as_rotas_e_responde_429(self):
		statuses = []
		for index in range(70):
			path = '/api/auth/me' if index % 2 else '/api/list'
			statuses.append(self.client.get(path, headers = AUTOMATIC).status_code)
		self.assertIn(429, statuses)
		self.assertEqual(60, len([status for status in statuses if status != 429]))

	def test_os_estaticos_nao_contam_no_limite(self):
		for _ in range(80):
			self.client.get('/static/assets/js/login.js')
		self.assertNotEqual(429, self.client.get('/api/auth/me', headers = AUTOMATIC).status_code)

	def test_o_sinal_de_vida_da_aba_nao_conta_no_limite(self):
		# Recusado por um minuto, ele mataria a sessão como "aba fechada" com a
		# carência no mínimo (60 s)
		self.enrolled_user()
		with self.client.session_transaction() as session:
			tab = session['tab_token']
		for _ in range(80):
			self.client.post('/api/auth/heartbeat', headers = dict(AUTOMATIC, **{'X-Session-Tab': tab}))
		self.assertNotEqual(429, self.client.get('/api/auth/me', headers = AUTOMATIC).status_code)

	def test_a_tela_sabe_quando_o_proxy_nao_e_confiavel(self):
		# 10.0.0.5 manda X-Forwarded-For sem estar em BLUEPHISH_TRUSTED_PROXIES: o
		# cabeçalho é ignorado (quem acessa direto escolheria o próprio IP), e a
		# tela precisa dizer que todo mundo está aparecendo como 10.0.0.5
		environ = {'REMOTE_ADDR': '10.0.0.5'}
		with self.app.test_request_context('/', environ_base = environ, headers = {'X-Forwarded-For': PERSON}):
			status = auth.address_status()
		self.assertEqual('10.0.0.5', status['ip'])
		self.assertTrue(status['countable'])
		self.assertTrue(status['forwardedIgnored'])
		with self.app.test_request_context('/', environ_base = {'REMOTE_ADDR': '127.0.0.1'}, headers = {'X-Forwarded-For': PERSON}):
			self.assertFalse(auth.address_status()['forwardedIgnored'])

	def test_o_websocket_recusa_o_banido(self):
		self.create()
		for _ in range(3):
			self.wrong()
		with self.app.test_request_context('/socket.io/', environ_base = {'REMOTE_ADDR': PERSON}):
			self.assertTrue(auth.address_refused())
		with self.app.test_request_context('/socket.io/', environ_base = {'REMOTE_ADDR': OTHER}):
			self.assertFalse(auth.address_refused())


@unittest.skipIf(test_security_policy.thephish_app is None, 'thephish_app precisa da imagem')
class RotasDaTela(test_security_policy.RotaSoDeGlobalAdmin):
	"""/security-config/protection e /unban na aplicação de verdade."""

	def setUp(self):
		super().setUp()
		abuse_guard.reset()
		self.addCleanup(abuse_guard.reset)

	FORM = Configuracao.FORM

	def test_analista_e_admin_nao_gravam_a_protecao(self):
		for role in (models.ROLE_ANALYST, models.ROLE_ADMIN):
			client = self.signed_in(role)
			self.assertEqual(403, client.post('/security-config/protection', data = self.FORM, headers = AUTOMATIC).status_code)
			self.assertEqual(403, client.post('/security-config/unban', data = {'ip': PERSON}, headers = AUTOMATIC).status_code)
		self.assertEqual([], security_policy.protection_policy()['allowlist'])

	def test_global_admin_grava_e_le_banidos_e_o_proprio_endereco(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		saved = client.post('/security-config/protection', data = self.FORM, headers = AUTOMATIC).get_json()
		self.assertEqual(5, saved['protection']['ban']['maxFailures'])
		self.assertIn('you', saved)
		self.assertEqual([], saved['bans'])
		self.assertIn(('security_config_update', 'ok'), self.audited)

	def test_salvar_a_sessao_pela_rota_nao_apaga_a_protecao(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		client.post('/security-config/protection', data = self.FORM, headers = AUTOMATIC)
		client.post('/security-config', data = self.VALID, headers = AUTOMATIC)
		self.assertEqual(['203.0.113.10', '198.51.100.0/24'], security_policy.protection_policy()['allowlist'])

	def test_desbanir_pela_tela(self):
		now = time.time()
		for moment in (0, 1, 2):
			abuse_guard.record_failure(PERSON, abuse_guard.KIND_LOGIN, policy(max_failures = 3), now + moment)
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		answer = client.post('/security-config/unban', data = {'ip': PERSON}, headers = AUTOMATIC).get_json()
		self.assertNotIn('error', answer)
		self.assertIn(('ip_unban', 'ok'), self.audited)
		self.assertIn('error', client.post('/security-config/unban', data = {'ip': PERSON}, headers = AUTOMATIC).get_json())


if __name__ == '__main__':
	unittest.main()
