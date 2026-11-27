"""Testes do reCAPTCHA v3 no login por senha (captcha.py).

Nenhum teste fala com o Google: a verificação é sempre simulada.

O que se prende aqui, e por que cada um falharia em silêncio:

  * **token ausente, inválido, de outra ação ou com nota baixa é recusado**, e a
    recusa conta para o banimento de IP;
  * **o Google fora do ar, ou recusando a chave secreta, não tranca ninguém
    fora** — o login segue, e o caso fica na trilha;
  * **as saídas de emergência funcionam**: BLUEPHISH_CAPTCHA_DISABLED, o
    `manage.py captcha-off` e a lista de liberados;
  * **a chamada vai só para o host fixo, sem redirect e sem o IP do cliente**;
  * **a CSP do painel não muda** — as origens do Google entram só na tela de
    login, e só com o captcha ligado;
  * **a chave secreta nunca volta para o navegador**, e em branco mantém a gravada.

Roda com:  python -m unittest test_captcha   (a partir do diretório app/)
"""

import argparse
import os
import time
import unittest
from unittest import mock

import requests

import abuse_guard
import auth
import captcha
import manage
import models
import security_policy
import test_mfa_gate
import test_security_policy
from test_security_policy import AUTOMATIC, ConfigFile

SITE = 'S' * 40
SECRET = 'k' * 40
CONFIG = {'enabled': True, 'siteKey': SITE, 'secret': SECRET, 'minScore': 0.5}
ON = {'captcha': CONFIG}
GOOD = {'success': True, 'action': 'login', 'score': 0.9}


class Answer(object):

	def __init__(self, body, status = 200):
		self.body = body
		self.status_code = status

	def json(self):
		if isinstance(self.body, Exception):
			raise self.body
		return self.body


def google(body, status = 200):
	"""Um requests.post de mentira que responde `body` e guarda as chamadas."""
	calls = []

	def post(url, **kwargs):
		calls.append((url, kwargs))
		return Answer(body, status)
	post.calls = calls
	return post


class Verificacao(unittest.TestCase):

	def test_token_bom_passa(self):
		self.assertEqual((True, captcha.OUTCOME_OK, 0.9), captcha.verify(CONFIG, 'token', google(GOOD)))

	def test_sem_token_nao_passa_e_nem_chama_o_google(self):
		post = google(GOOD)
		self.assertEqual((False, captcha.OUTCOME_MISSING, None), captcha.verify(CONFIG, '', post))
		self.assertEqual([], post.calls)

	def test_token_gigante_nao_passa(self):
		self.assertFalse(captcha.verify(CONFIG, 'x' * 5000, google(GOOD))[0])

	def test_nota_baixa_nao_passa(self):
		self.assertEqual((False, captcha.OUTCOME_LOW_SCORE, 0.3),
			captcha.verify(CONFIG, 't', google(dict(GOOD, score = 0.3))))

	def test_token_de_outra_acao_nao_passa(self):
		# Um token gerado para outra página do mesmo site não vale para o login
		self.assertEqual(captcha.OUTCOME_WRONG_ACTION, captcha.verify(CONFIG, 't', google(dict(GOOD, action = 'contato')))[1])

	def test_token_recusado_pelo_google_nao_passa(self):
		answer = {'success': False, 'error-codes': ['invalid-input-response']}
		self.assertEqual((False, captcha.OUTCOME_INVALID, None), captcha.verify(CONFIG, 't', google(answer)))

	def test_nota_que_nao_e_numero_nao_passa(self):
		for score in (None, '0.9', True):
			self.assertFalse(captcha.verify(CONFIG, 't', google(dict(GOOD, score = score)))[0], score)

	def test_chave_secreta_errada_deixa_passar(self):
		answer = {'success': False, 'error-codes': ['invalid-input-secret']}
		self.assertEqual((True, captcha.OUTCOME_MISCONFIGURED, None), captcha.verify(CONFIG, 't', google(answer)))

	def test_google_fora_do_ar_deixa_passar(self):
		def down(url, **kwargs):
			raise requests.ConnectionError('sem rota')
		self.assertEqual((True, captcha.OUTCOME_UNAVAILABLE, None), captcha.verify(CONFIG, 't', down))
		self.assertTrue(captcha.verify(CONFIG, 't', google(GOOD, status = 503))[0])
		self.assertTrue(captcha.verify(CONFIG, 't', google(ValueError('não é JSON')))[0])

	def test_host_fixo_sem_redirect_e_sem_o_ip_do_cliente(self):
		post = google(GOOD)
		captcha.verify(CONFIG, 'token', post)
		url, kwargs = post.calls[0]
		self.assertEqual('https://www.google.com/recaptcha/api/siteverify', url)
		self.assertIs(False, kwargs['allow_redirects'])
		self.assertEqual({'secret': SECRET, 'response': 'token'}, kwargs['data'])
		self.assertTrue(kwargs['timeout'])


class Csp(unittest.TestCase):

	def test_a_tela_de_login_ganha_so_as_origens_do_recaptcha(self):
		csp = captcha.login_csp(auth.BASE_CSP)
		self.assertIn("script-src 'self' https://cdnjs.cloudflare.com https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/", csp)
		self.assertIn('frame-src https://www.google.com/recaptcha/', csp)
		self.assertNotIn('unsafe-inline', csp.split('script-src')[1].split(';')[0])

	def test_so_o_login_com_captcha_aceita_estilo_inline(self):
		# O api.js do Google injeta estilo inline; a exceção fica só aqui
		csp = captcha.login_csp(auth.BASE_CSP)
		self.assertIn("'unsafe-inline'", csp.split('style-src')[1].split(';')[0])
		self.assertNotIn('unsafe-inline', auth.BASE_CSP)
		self.assertEqual(1, csp.count("'unsafe-inline'"))

	def test_a_csp_base_nao_tem_o_google(self):
		self.assertNotIn('google.com', auth.BASE_CSP)
		self.assertNotIn('frame-src', auth.BASE_CSP)


class Configuracao(unittest.TestCase):

	def setUp(self):
		self.config = ConfigFile()
		self.addCleanup(self.config.close)

	FORM = {'captchaEnabled': 'true', 'siteKey': SITE, 'secret': SECRET, 'minScore': '0.6'}

	def stored(self):
		return security_policy.load_config()['captcha']

	def test_desligado_por_padrao(self):
		self.assertFalse(captcha.is_active(security_policy.captcha_policy()))

	def test_ligar_sem_as_chaves_e_recusado(self):
		_, error = security_policy.validate_captcha(dict(self.FORM, secret = ''), self.stored())
		self.assertIn('informe a chave', error)

	def test_chave_com_formato_errado_e_recusada(self):
		_, error = security_policy.validate_captcha(dict(self.FORM, siteKey = 'curta demais'), self.stored())
		self.assertIn('formato', error)

	def test_nota_fora_dos_limites_e_recusada(self):
		for score in ('0', '1', 'alta'):
			self.assertIsNotNone(security_policy.validate_captcha(dict(self.FORM, minScore = score), self.stored())[1], score)

	def test_segredo_em_branco_mantem_o_gravado(self):
		part, _ = security_policy.validate_captcha(self.FORM, self.stored())
		security_policy.save_config(security_policy.merged(part))
		part, error = security_policy.validate_captcha(dict(self.FORM, secret = ''), self.stored())
		self.assertIsNone(error)
		self.assertEqual(SECRET, part['captcha']['secret'])

	def test_a_tela_nao_recebe_o_segredo(self):
		part, _ = security_policy.validate_captcha(self.FORM, self.stored())
		config = security_policy.merged(part)
		view = security_policy.captcha_view(config)
		self.assertNotIn('secret', view)
		self.assertNotIn(SECRET, str(view))
		self.assertTrue(view['hasSecret'])
		self.assertNotIn(SECRET, security_policy.captcha_summary(config))

	def test_a_variavel_de_ambiente_desliga(self):
		self.config.write(ON)
		self.assertTrue(captcha.is_active(security_policy.captcha_policy()))
		with mock.patch.dict(os.environ, {captcha.DISABLE_ENV: '1'}):
			self.assertFalse(captcha.is_active(security_policy.captcha_policy()))

	def test_manage_captcha_off_grava_o_desligamento(self):
		self.config.write(dict(ON, protection = {'allowlist': ['203.0.113.10']}))
		self.assertEqual(0, manage.cmd_captcha_off(argparse.Namespace()))
		self.assertFalse(security_policy.captcha_policy()['enabled'])
		# Desligar o captcha não apaga o resto da seção, nem a chave
		self.assertEqual(['203.0.113.10'], security_policy.protection_policy()['allowlist'])
		self.assertEqual(SECRET, security_policy.captcha_policy()['secret'])

	def test_gravado_a_mao_com_lixo_nao_liga(self):
		self.config.write({'captcha': {'enabled': 'sim', 'siteKey': '<script>', 'secret': 7, 'minScore': 5}})
		stored = security_policy.captcha_policy()
		self.assertFalse(stored['enabled'])
		self.assertEqual('', stored['siteKey'])
		self.assertEqual(security_policy.MAX_SCORE, stored['minScore'])


class PeloLogin(test_mfa_gate.Base):

	def setUp(self):
		super().setUp()
		abuse_guard.reset()
		self.addCleanup(abuse_guard.reset)
		self.config = ConfigFile(dict(ON, protection = {'ban': {'maxFailures': 3}}))
		self.addCleanup(self.config.close)
		self.client.environ_base['REMOTE_ADDR'] = '203.0.113.7'
		self.create()

	def login_with(self, token, answer = GOOD):
		with mock.patch.object(captcha.requests, 'post', google(answer)):
			return self.client.post('/api/auth/login', json = {'username': 'analista', 'password': test_mfa_gate.SENHA,
				'captchaToken': token})

	def test_sem_token_a_senha_certa_nao_entra(self):
		response = self.login_with('')
		self.assertEqual(401, response.status_code)
		self.assertTrue(response.get_json()['captcha'])

	def test_com_token_bom_vai_para_o_segundo_fator(self):
		self.assertTrue(self.login_with('token').get_json()['mfaRequired'])

	def test_nota_baixa_nao_entra(self):
		self.assertEqual(401, self.login_with('token', dict(GOOD, score = 0.1)).status_code)

	def test_reprovar_no_captcha_conta_para_o_banimento(self):
		for _ in range(3):
			self.login_with('')
		self.assertEqual(403, self.login_with('token').status_code)
		self.assertEqual(abuse_guard.KIND_CAPTCHA, abuse_guard.bans(time.time())[0]['kind'])

	def test_google_fora_do_ar_entra_e_fica_na_trilha(self):
		def down(url, **kwargs):
			raise requests.Timeout('lento')
		with mock.patch.object(captcha.requests, 'post', down):
			response = self.client.post('/api/auth/login', json = {'username': 'analista',
				'password': test_mfa_gate.SENHA, 'captchaToken': 'token'})
		self.assertTrue(response.get_json()['mfaRequired'])
		with open(auth.AUDIT_LOG_PATH) as handle:
			self.assertIn('unavailable', handle.read())

	def test_ip_liberado_nao_passa_pelo_captcha(self):
		self.config.write(dict(ON, protection = {'allowlist': ['203.0.113.0/24']}))
		self.assertTrue(self.login_with('').get_json()['mfaRequired'])

	def test_variavel_de_ambiente_desliga_no_login(self):
		with mock.patch.dict(os.environ, {captcha.DISABLE_ENV: '1'}):
			self.assertTrue(self.login_with('').get_json()['mfaRequired'])

	def test_a_tela_de_login_carrega_o_script_so_com_o_captcha_ligado(self):
		page = self.client.get('/login')
		self.assertIn('https://www.google.com/recaptcha/api.js?render=' + SITE, page.get_data(as_text = True))
		self.assertIn('frame-src https://www.google.com/recaptcha/', page.headers['Content-Security-Policy'])
		self.config.write({'captcha': dict(CONFIG, enabled = False)})
		page = self.client.get('/login')
		self.assertNotIn('recaptcha', page.get_data(as_text = True))
		self.assertNotIn('google', page.headers.get('Content-Security-Policy', ''))


@unittest.skipIf(test_security_policy.thephish_app is None, 'thephish_app precisa da imagem')
class NaAplicacaoDeVerdade(test_security_policy.RotaSoDeGlobalAdmin):
	"""A rota da tela e a CSP do painel, em thephish_app."""

	FORM = Configuracao.FORM

	def test_o_painel_segue_com_a_csp_de_sempre_com_o_captcha_ligado(self):
		client = self.signed_in(models.ROLE_ANALYST)
		# Ligado depois do login: o login de teste não manda token
		self.config.write(ON)
		self.assertEqual(auth.BASE_CSP, client.get('/list').headers['Content-Security-Policy'])

	def test_global_admin_grava_e_a_resposta_nao_traz_o_segredo(self):
		client = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		saved = client.post('/security-config/captcha', data = self.FORM, headers = AUTOMATIC)
		self.assertNotIn(SECRET, saved.get_data(as_text = True))
		self.assertTrue(saved.get_json()['captcha']['hasSecret'])
		self.assertIn(('security_config_update', 'ok'), self.audited)

	def test_analista_e_admin_nao_gravam_o_captcha(self):
		for role in (models.ROLE_ANALYST, models.ROLE_ADMIN):
			client = self.signed_in(role)
			self.assertEqual(403, client.post('/security-config/captcha', data = self.FORM, headers = AUTOMATIC).status_code)
		self.assertFalse(security_policy.captcha_policy()['enabled'])


if __name__ == '__main__':
	unittest.main()
