"""Um e-mail que ninguém conseguiu avaliar não é Safe.

Motivado por uma reanálise do phishing de entrega da Amazon (2026-09-14 19:16):
os 26 resultados de analisador voltaram "não respondeu dentro do tempo limite",
a IA não respondeu, e o veredito saiu Safe — o mesmo veredito de um e-mail que
todos avaliaram e acharam limpo. É o §7.6 (`info` não é `safe`) aplicado à
mensagem inteira.

Rodar com:  python -m unittest test_coverage   (a partir de app/)
"""

import unittest
from unittest import mock

import run_analysis

import test_scoring_pipeline as pipeline


class TrustedSender(pipeline.NoWhitelist):
	"""Uma regra de whitelist casa com o remetente."""

	class Match(pipeline.NoWhitelist.Match):
		rule_id = 'regra-do-remetente'
		def __bool__(self): return True
		__nonzero__ = __bool__


def timed_out(analyzer_id):
	finding = pipeline.finding(analyzer_id, 'info')
	finding['analyzer_error'] = '{0} não respondeu dentro do tempo limite.'.format(analyzer_id)
	return finding


class DecidesAVerdict(unittest.TestCase):

	def setUp(self):
		self.harness = pipeline.TerminateAnalysisComScore('run_it')
		self.harness.setUp()
		# A notificação ligada é o que torna o Safe sem avaliação perigoso
		run_analysis.config['notificationFlags'] = {'start': True, 'safe': True, 'malicious': True}

	def tearDown(self):
		self.harness.tearDown()

	def decide(self, findings, llm = None, extraction_complete = True, content_key = ''):
		trail = []
		verdict, _score = run_analysis.terminate_analysis(
			'Acompanhe sua entrega', 'quem@denunciou.com', [pipeline.observable()], findings, llm,
			self.harness.wsl, auth_results = pipeline.AUTHENTICATED, sent_log = [],
			observables_seen = None, trail = trail, extraction_complete = extraction_complete,
			content_key = content_key)
		return verdict, trail


class NothingLookedIsNotSafe(DecidesAVerdict):

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


class AnUnfinishedExtractionIsNotSafe(DecidesAVerdict):
	"""Quem respondeu avaliou só o que a extração achou, e ela não leu tudo."""

	LLM = {'social_engineering_detected': False, 'risk_level': 'Low', 'tactics': [], 'justification': 'ok'}

	def test_safe_opinions_do_not_vouch_for_what_was_not_read(self):
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')], self.LLM, extraction_complete = False)
		self.assertEqual(verdict, 'Suspicious')
		reasons = [step['reason'] for step in trail if step['stage'] == 'coverage']
		self.assertTrue(any('não terminou' in reason for reason in reasons), reasons)

	def test_the_reporter_is_not_told_it_is_safe_either(self):
		self.decide([pipeline.finding('urlhaus', 'safe')], self.LLM, extraction_complete = False)
		self.assertEqual(self.harness.notified, [])

	def test_it_never_lowers_a_verdict(self):
		verdict, _trail = self.decide([pipeline.finding('urlhaus', 'malicious')], self.LLM, extraction_complete = False)
		self.assertEqual(verdict, 'Malicious')

	def test_a_finished_extraction_changes_nothing(self):
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')], self.LLM)
		self.assertEqual(verdict, 'Safe')
		self.assertFalse(any(step['stage'] == 'coverage' for step in trail))

	def test_a_whitelisted_sender_does_not_undo_the_floor(self):
		run_analysis.ruleset = TrustedSender()
		with mock.patch.object(run_analysis.whitelist_state, 'register_downgrade') as downgrade:
			verdict, _trail = self.decide([pipeline.finding('urlhaus', 'safe')], self.LLM, extraction_complete = False)
		self.assertEqual(verdict, 'Suspicious')
		downgrade.assert_not_called()

	def test_the_verdict_memory_does_not_undo_the_floor(self):
		with mock.patch.object(run_analysis.verdict_memory, 'apply') as memory:
			verdict, _trail = self.decide([pipeline.finding('urlhaus', 'safe')], self.LLM,
				extraction_complete = False, content_key = 'conteudo')
		self.assertEqual(verdict, 'Suspicious')
		memory.assert_not_called()

	def test_a_finished_extraction_can_still_be_downgraded(self):
		run_analysis.ruleset = TrustedSender()
		with mock.patch.object(run_analysis.whitelist_state, 'register_downgrade', return_value = (True, '')) as downgrade:
			verdict, _trail = self.decide([pipeline.finding('urlhaus', 'malicious')], self.LLM)
		self.assertEqual(verdict, 'Safe')
		downgrade.assert_called_once()


if __name__ == '__main__':
	unittest.main()
