"""Um e-mail que ninguém conseguiu avaliar não é Safe.

Motivado por uma reanálise do phishing de entrega da Amazon (2026-09-14 19:16):
os 26 resultados de analisador voltaram "não respondeu dentro do tempo limite",
a IA não respondeu, e o veredito saiu Safe — o mesmo veredito de um e-mail que
todos avaliaram e acharam limpo. É o §7.6 (`info` não é `safe`) aplicado à
mensagem inteira.

Rodar com:  python -m unittest test_coverage   (a partir de app/)
"""

import unittest

import run_analysis

import test_scoring_pipeline as pipeline


def timed_out(analyzer_id):
	finding = pipeline.finding(analyzer_id, 'info')
	finding['analyzer_error'] = '{0} não respondeu dentro do tempo limite.'.format(analyzer_id)
	return finding


class NothingLookedIsNotSafe(unittest.TestCase):

	def setUp(self):
		self.harness = pipeline.TerminateAnalysisComScore('run_it')
		self.harness.setUp()
		# A notificação ligada é o que torna o Safe sem avaliação perigoso
		run_analysis.config['notificationFlags'] = {'start': True, 'safe': True, 'malicious': True}

	def tearDown(self):
		self.harness.tearDown()

	def decide(self, findings, llm = None):
		trail = []
		verdict, _score = run_analysis.terminate_analysis(
			'Acompanhe sua entrega', 'quem@denunciou.com', [pipeline.observable()], findings, llm,
			self.harness.wsl, auth_results = pipeline.AUTHENTICATED, sent_log = [],
			observables_seen = None, trail = trail)
		return verdict, trail

	def test_every_analyzer_timed_out_and_no_llm_is_suspicious(self):
		verdict, trail = self.decide([timed_out('virustotal'), timed_out('urlhaus'), timed_out('phishtank')])
		self.assertEqual(verdict, 'Suspicious')
		self.assertEqual([step['stage'] for step in trail if step['verdict'] == 'Suspicious'][0], 'coverage')
		self.assertIn('3 resultado(s)', [step for step in trail if step['stage'] == 'coverage'][0]['reason'])

	def test_the_reporter_is_not_told_it_is_safe(self):
		self.decide([timed_out('virustotal')])
		self.assertEqual(self.harness.notified, [])

	def test_no_analyzer_at_all_and_no_llm_is_suspicious(self):
		verdict, trail = self.decide([])
		self.assertEqual(verdict, 'Suspicious')
		self.assertTrue(any(step['stage'] == 'coverage' for step in trail))

	def test_one_analyzer_that_answered_is_an_evaluation(self):
		verdict, trail = self.decide([timed_out('virustotal'), pipeline.finding('urlhaus', 'safe')])
		self.assertEqual(verdict, 'Safe')
		self.assertFalse(any(step['stage'] == 'coverage' for step in trail))

	def test_an_llm_that_answered_is_an_evaluation(self):
		llm = {'social_engineering_detected': False, 'risk_level': 'Low', 'tactics': [], 'justification': 'ok'}
		verdict, _trail = self.decide([timed_out('virustotal')], llm)
		self.assertEqual(verdict, 'Safe')

	def test_the_floor_never_lowers_a_verdict(self):
		verdict, _trail = self.decide([timed_out('virustotal'), pipeline.finding('urlhaus', 'malicious')])
		self.assertEqual(verdict, 'Malicious')


if __name__ == '__main__':
	unittest.main()
