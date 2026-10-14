"""O score dentro de `run_analysis.terminate_analysis`, ponta a ponta.

O módulo `scoring` é puro e tem os próprios testes. O que este arquivo cobre é a
costura — o ponto em que uma nota vira (ou não vira) veredito. É o lugar onde um
erro sai caro e calado: nada aqui levanta exceção, nada aparece no log como
falha, e o sintoma é uma analista recebendo um veredito diferente do que a
evidência sustenta.

Três invariantes, e são as mesmas do módulo, agora sobre o pipeline real:

* um `Malicious` dos analisadores continua `Malicious` com qualquer score;
* um score na faixa de phishing eleva um `Safe`, mas não quando o domínio
  remetente está autenticado — o mesmo resguardo da regra 1 da escalada do LLM;
* uma falha no cálculo do score não muda veredito nenhum.

Rodar com:  python -m unittest test_scoring_pipeline   (a partir de app/)
"""

import logging
import unittest

import run_analysis
import scoring


class SilentLogger(object):
	"""O `wsl` que a análise usa para falar com o navegador. Aqui ele só guarda."""

	def __init__(self):
		self.lines = []

	def emit_info(self, message): self.lines.append(('info', message))
	def emit_warning(self, message): self.lines.append(('warning', message))
	def emit_error(self, message): self.lines.append(('error', message))

	def said(self, needle):
		return any(needle.lower() in message.lower() for _level, message in self.lines)


class NoWhitelist(object):
	"""Nenhuma regra de remetente casa. O rebaixamento não é o assunto aqui."""

	class Match(object):
		reason = ''
		rule_id = None
		def __bool__(self): return False
		__nonzero__ = __bool__

	error = ''

	def match_sender(self, *args, **kwargs):
		return self.Match()


AUTHENTICATED = {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass', 'aligned': True,
	'authenticated': True, 'raw': 'spf=pass', 'fromAddress': 'marca@exemplo.com',
	'fromDomain': 'exemplo.com', 'replyTo': ''}
UNAUTHENTICATED = {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail', 'aligned': False,
	'authenticated': False, 'raw': 'spf=fail', 'fromAddress': 'cobranca@falso.example',
	'fromDomain': 'falso.example', 'replyTo': ''}


def observable(obs_id = 'obs-0', obs_type = 'url', name = 'https://falso.example/a'):
	return {'id': obs_id, 'type': obs_type, 'name': name, 'tags': [], 'message': ''}


def finding(analyzer_id, level, obs_id = 'obs-0'):
	return {'observable_id': obs_id, 'observable_name': 'https://falso.example/a',
		'observable_type': 'url', 'analyzer_id': analyzer_id, 'analyzer_name': analyzer_id,
		'analyzer_result': level, 'analyzer_detail': '', 'analyzer_error': ''}


BULK = {'value': 0.8, 'bulk': True, 'oneClick': True, 'filtered': False, 'scl': None, 'bcl': None,
	'markers': [{'id': 'list_unsubscribe_post', 'label': 'baixa por um clique',
		'rfc': 'RFC 8058', 'weight': 0.3, 'detail': ''}]}


class TerminateAnalysisComScore(unittest.TestCase):

	def setUp(self):
		self.wsl = SilentLogger()
		self.notified = []
		self.recorded = []

		# `log` do módulo só é criado dentro de run_analysis.main(); chamando
		# terminate_analysis direto, ele ainda é None
		self._log = run_analysis.log
		run_analysis.log = logging.getLogger('test_scoring_pipeline')
		run_analysis.log.addHandler(logging.NullHandler())
		run_analysis.log.propagate = False

		self._config = run_analysis.config
		self._ruleset = run_analysis.ruleset
		self._notify = run_analysis.send_notification
		self._record = run_analysis.whitelist_state.record_analysis
		self._load = scoring.load_config
		self._custom = run_analysis.custom_analyzers.load_all

		run_analysis.config = {'llmEscalationThreshold': 'Medium', 'llmMaliciousEscalation': 'off',
			'notificationFlags': {'start': False, 'safe': False, 'malicious': False}}
		run_analysis.ruleset = NoWhitelist()
		run_analysis.send_notification = lambda *a, **k: self.notified.append(a)
		run_analysis.whitelist_state.record_analysis = lambda *a, **k: self.recorded.append(k)
		run_analysis.custom_analyzers.load_all = lambda *a, **k: []
		self.scoring_config = scoring.default_config()
		scoring.load_config = lambda *a, **k: self.scoring_config

	def tearDown(self):
		run_analysis.log = self._log
		run_analysis.config = self._config
		run_analysis.ruleset = self._ruleset
		run_analysis.send_notification = self._notify
		run_analysis.whitelist_state.record_analysis = self._record
		run_analysis.custom_analyzers.load_all = self._custom
		scoring.load_config = self._load

	def run_it(self, observables, findings, llm = None, auth = None, bulk = None):
		# Os opcionais vao por palavra-chave, e nao por posicao: `terminate_analysis`
		# ja ganhou parametro novo no meio duas vezes, e na segunda um `bulk` caiu
		# em `injection_findings` — o teste quebrou barulhento por sorte, porque o
		# outro modulo indexa o que recebeu. Uma ordem diferente que *nao* quebrasse
		# teria passado batida
		return run_analysis.terminate_analysis(
			'Assunto', 'quem@denunciou.com', observables, findings, llm, self.wsl,
			auth_results = auth, sent_log = [], observables_seen = None,
			bulk_signals = bulk)

	# --- o piso ---------------------------------------------------------------

	def test_um_observavel_malicioso_continua_malicioso(self):
		verdict, score = self.run_it([observable()],
			[finding('virustotal', 'malicious')] + [finding(b, 'safe') for b in
				('safebrowsing', 'phishtank', 'openphish', 'urlhaus', 'otx')],
			auth = UNAUTHENTICATED)
		self.assertEqual(verdict, 'Malicious')
		self.assertGreaterEqual(score['score'], score['tiers']['phishing'])

	def test_o_observavel_malicioso_e_marcado_como_ioc(self):
		observables = [observable()]
		self.run_it(observables, [finding('virustotal', 'malicious')], auth = UNAUTHENTICATED)
		self.assertTrue(observables[0]['ioc'])

	# --- a escalada -----------------------------------------------------------

	def test_a_faixa_de_phishing_eleva_um_safe(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'Critical',
			'tactics': [], 'justification': 'urgência e cobrança falsa'}
		verdict, score = self.run_it([observable()], [finding('virustotal', 'safe')],
			llm = llm, auth = UNAUTHENTICATED)
		self.assertEqual(score['tier'], 'phishing')
		self.assertEqual(verdict, 'Malicious')

	def test_remetente_autenticado_nao_e_fechado_como_malicioso_pelo_score(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'Critical',
			'tactics': [], 'justification': 'texto alarmista'}
		verdict, _score = self.run_it([observable()], [finding('virustotal', 'safe')],
			llm = llm, auth = AUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')
		self.assertTrue(self.wsl.said('autenticado'))

	def test_modo_advisory_calcula_e_nao_toca_no_veredito(self):
		# Mesmo cenário do teste acima. Em `escalate` o score leva a Malicious; em
		# `advisory` ele para em Suspicious, que é aonde a escalada do LLM já
		# tinha levado sozinha — a diferença entre os dois testes é o score, e só
		self.scoring_config['mode'] = 'advisory'
		llm = {'social_engineering_detected': True, 'risk_level': 'Critical',
			'tactics': [], 'justification': 'x'}
		verdict, score = self.run_it([observable()], [finding('virustotal', 'safe')],
			llm = llm, auth = UNAUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')
		self.assertEqual(score['tier'], 'phishing')

	def test_modo_off_nao_produz_score(self):
		self.scoring_config['mode'] = 'off'
		verdict, score = self.run_it([observable()], [finding('virustotal', 'safe')],
			auth = UNAUTHENTICATED)
		self.assertEqual(verdict, 'Safe')
		self.assertIsNone(score)

	# --- triagem de massa -----------------------------------------------------

	def test_massa_autenticada_e_rotulada_spam_e_continua_safe(self):
		verdict, score = self.run_it([observable()], [finding('virustotal', 'safe')],
			auth = AUTHENTICATED, bulk = BULK)
		self.assertEqual(verdict, 'Safe')
		self.assertEqual(score['label'], 'spam')
		self.assertTrue(self.wsl.said('spam'))

	def test_massa_forjada_em_dominio_nao_autenticado_nao_vira_spam(self):
		_verdict, score = self.run_it([observable()], [finding('virustotal', 'safe')],
			auth = UNAUTHENTICATED, bulk = BULK)
		self.assertNotEqual(score['label'], 'spam')

	def test_massa_com_anexo_malicioso_nunca_e_spam(self):
		verdict, score = self.run_it([observable('obs-0', 'hash', 'ab12')],
			[finding('virustotal', 'malicious')], auth = AUTHENTICATED, bulk = BULK)
		self.assertEqual(verdict, 'Malicious')
		self.assertNotEqual(score['label'], 'spam')

	# --- falha no cálculo -----------------------------------------------------

	def test_uma_falha_no_score_nao_muda_o_veredito(self):
		def explode(*args, **kwargs):
			raise RuntimeError('configuração ilegível')
		scoring.load_config = explode
		verdict, score = self.run_it([observable()], [finding('virustotal', 'suspicious')],
			auth = UNAUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')
		self.assertIsNone(score)
		self.assertTrue(self.wsl.said('não foi possível calcular') or self.wsl.said('nao foi possivel calcular'))

	# --- o que viaja para os destinos -----------------------------------------

	def test_o_veredito_final_viaja_junto_do_score(self):
		_verdict, score = self.run_it([observable()], [finding('virustotal', 'malicious')],
			auth = UNAUTHENTICATED)
		self.assertEqual(score['verdict'], 'Malicious')
		self.assertFalse(score['downgraded'])

	def test_a_memoria_de_calculo_nomeia_cada_fator(self):
		_verdict, score = self.run_it([observable()],
			[finding('virustotal', 'malicious'), finding('abuseipdb', 'info')],
			auth = UNAUTHENTICATED, bulk = BULK)
		ids = [factor['id'] for factor in score['factors']]
		for expected in ('virustotal', 'abuseipdb', 'signal:llm_risk',
				'signal:sender_auth', 'signal:bulk_headers'):
			self.assertIn(expected, ids)


class TagsDoCaso(unittest.TestCase):
	"""O score só ordena a fila depois de virar tag: é dela que os painéis leem."""

	def test_score_faixa_e_autenticacao_viram_tag(self):
		import tickets
		tags = tickets.analysis_tags({
			'department': 'Financeiro',
			'llm': {'risk_level': 'High', 'social_engineering_detected': True, 'tactics': ['urgency']},
			'score': {'score': 63.4, 'label': 'phishing'},
			'authentication': {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}
		})
		self.assertIn('score:63.4', tags)
		self.assertIn('tier:phishing', tags)
		self.assertIn('auth:spf=fail', tags)
		self.assertIn('auth:dmarc=fail', tags)

	def test_uma_analise_sem_score_nao_grava_tag_de_score(self):
		import tickets
		tags = tickets.analysis_tags({'department': '', 'llm': None, 'score': None,
			'authentication': None})
		self.assertEqual([tag for tag in tags if tag.startswith(('score:', 'tier:', 'auth:'))], [])

	def test_case_insights_le_de_volta_o_que_tickets_gravou(self):
		import case_insights
		case = {'tags': ['score:63.4', 'tier:phishing', 'auth:spf=fail', 'auth:dmarc=pass']}
		self.assertEqual(case_insights.case_score(case), 63.4)
		self.assertEqual(case_insights.case_tier(case), 'phishing')
		self.assertEqual(case_insights.case_auth(case), {'spf': 'fail', 'dmarc': 'pass'})

	def test_um_caso_sem_score_e_none_e_nunca_zero(self):
		import case_insights
		# Zero seria "avaliado e absolvido"; None é "nunca pontuado", e o ranking
		# trata os dois de maneiras opostas
		self.assertIsNone(case_insights.case_score({'tags': ['email']}))
		self.assertIsNone(case_insights.case_score({'tags': ['score:muito-alto']}))

	def test_as_tags_de_score_nao_poluem_as_tags_de_exibicao(self):
		import case_insights
		case = {'tags': ['email', 'campanha-x', 'score:63.4', 'tier:phishing', 'auth:spf=fail']}
		self.assertEqual(case_insights.display_tags(case), ['campanha-x'])


if __name__ == '__main__':
	unittest.main()
