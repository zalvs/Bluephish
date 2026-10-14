"""Testes do runtime do whitelist: rebaixamento, suspensão automática e simulação.

O que estes testes prendem é o laço que dá sentido ao desenho inteiro. Rebaixar
veredito por remetente confiável só é aceitável porque o rebaixamento é contado,
e porque a regra que passa a esconder vereditos ruins demais para de valer
sozinha. Se essa parte quebrar em silêncio, o sistema vira o bypass que ele
existe para não ser — e ninguém percebe, porque a consequência de um bypass é
justamente a ausência de alerta.

Rodar com:  python -m unittest test_whitelist_state   (a partir de app/)
"""

import datetime
import os
import tempfile
import unittest

import models


NOW = datetime.datetime(2026, 8, 23, 12, 0, 0)
LIMITS = {'whitelistMaliciousLimit': 3, 'whitelistTotalLimit': 5, 'whitelistWindowDays': 30}


class DatabaseBacked(unittest.TestCase):
	"""Cada teste roda contra um SQLite próprio, criado e apagado na hora."""

	def setUp(self):
		handle, self.db_path = tempfile.mkstemp(suffix = '.db')
		os.close(handle)
		self.previous_path = models.DB_PATH
		models.DB_PATH = self.db_path
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		import whitelist_state
		self.state = whitelist_state
		whitelist_state._last_prune = None

	def tearDown(self):
		models._engine = None
		models._SessionFactory = None
		models.DB_PATH = self.previous_path
		if os.path.isfile(self.db_path):
			try:
				os.remove(self.db_path)
			except OSError:
				pass


class Downgrade(DatabaseBacked):

	def test_a_downgrade_is_allowed_and_recorded(self):
		allowed, why = self.state.register_downgrade('wl_1', 'Suspicious', config = LIMITS, now = NOW)
		self.assertTrue(allowed)
		self.assertEqual(why, '')
		stats = self.state.stats_for(['wl_1'], now = NOW)['wl_1']
		self.assertEqual(stats['suppressionCount'], 1)
		self.assertEqual(stats['suppressionsInWindow'], 1)
		self.assertFalse(stats['suspended'])

	def test_the_third_malicious_suspends_the_rule_instead_of_hiding_it(self):
		# Os dois primeiros somem; o terceiro e a prova de que a regra nao serve
		for _ in range(2):
			self.assertTrue(self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)[0])
		allowed, why = self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		self.assertFalse(allowed)
		self.assertIn('Malicious', why)
		self.assertTrue(self.state.stats_for(['wl_1'], now = NOW)['wl_1']['suspended'])

	def test_the_event_that_crosses_the_limit_is_not_recorded_as_hidden(self):
		# Ele nao foi escondido: o veredito valeu. Contar como supressao mentiria
		# no relatorio do que a regra escondeu
		for _ in range(3):
			self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		self.assertEqual(len(self.state.suppressions_for('wl_1')), 2)

	def test_a_suspended_rule_stops_downgrading_from_then_on(self):
		for _ in range(3):
			self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		self.assertIn('wl_1', self.state.suspended_ids())

	def test_mixed_verdicts_trip_the_total_limit(self):
		for _ in range(4):
			self.assertTrue(self.state.register_downgrade('wl_1', 'Suspicious', config = LIMITS, now = NOW)[0])
		allowed, why = self.state.register_downgrade('wl_1', 'Suspicious', config = LIMITS, now = NOW)
		self.assertFalse(allowed)
		self.assertIn('não-Safe', why)

	def test_events_outside_the_window_do_not_count(self):
		old = NOW - datetime.timedelta(days = 60)
		for _ in range(2):
			self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = old)
		# Duas antigas + uma de hoje: a janela de 30 dias so ve a de hoje
		allowed, _why = self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		self.assertTrue(allowed)

	def test_two_rules_keep_separate_counts(self):
		for _ in range(3):
			self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		allowed, _why = self.state.register_downgrade('wl_2', 'Malicious', config = LIMITS, now = NOW)
		self.assertTrue(allowed)
		self.assertNotIn('wl_2', self.state.suspended_ids())

	def test_resuming_clears_the_suspension_and_the_window(self):
		for _ in range(3):
			self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)
		self.assertTrue(self.state.clear_suspension('wl_1'))
		self.assertNotIn('wl_1', self.state.suspended_ids())
		# A contagem recomeca do zero, senao a regra religada cairia de novo no
		# proximo e-mail e o botao nao teria servido para nada
		self.assertTrue(self.state.register_downgrade('wl_1', 'Malicious', config = LIMITS, now = NOW)[0])

	def test_a_plain_match_counts_without_hiding_anything(self):
		self.state.record_match('wl_1')
		stats = self.state.stats_for(['wl_1'], now = NOW)['wl_1']
		self.assertEqual(stats['matchCount'], 1)
		self.assertEqual(stats['suppressionCount'], 0)


class History(DatabaseBacked):

	def record(self, **overrides):
		payload = {
			'from_address': 'faturamento@empresa.com.br',
			'from_domain': 'empresa.com.br',
			'subject': 'Nota fiscal',
			'authenticated': True,
			'verdict': 'Safe',
			'observables': {'domain': ['empresa.com.br'], 'url': ['https://empresa.com.br/nf/1'], 'hash': []},
			'now': NOW,
		}
		payload.update(overrides)
		self.state.record_analysis(config = LIMITS, **payload)

	def test_a_sender_rule_is_simulated_against_the_history(self):
		self.record()
		self.record(verdict = 'Malicious', subject = 'Boleto atualizado')
		self.record(from_address = 'outro@empresa.com.br')
		result = self.state.dry_run({'type': 'sender', 'value': 'faturamento@empresa.com.br'}, now = NOW)
		self.assertEqual(result['analyzed'], 3)
		self.assertEqual(result['matched'], 2)
		# O numero que importa: quantos alertas essa regra teria calado
		self.assertEqual(result['notSafe'], 1)
		self.assertEqual(result['samples'][0]['verdict'], 'Malicious')

	def test_an_unauthenticated_sender_is_not_counted_as_matched(self):
		self.record(authenticated = False, verdict = 'Malicious')
		result = self.state.dry_run({'type': 'sender', 'value': 'faturamento@empresa.com.br'}, now = NOW)
		self.assertEqual(result['matched'], 0)

	def test_a_domain_rule_is_simulated_against_the_observables(self):
		self.record(verdict = 'Suspicious',
			observables = {'domain': ['parceiro.com.br'], 'url': [], 'hash': []})
		result = self.state.dry_run({'type': 'domain', 'value': 'parceiro.com.br'}, now = NOW)
		self.assertEqual(result['matched'], 1)
		self.assertEqual(result['notSafe'], 1)

	def test_a_url_rule_is_simulated_against_the_observables(self):
		self.record(observables = {'domain': [], 'url': ['https://intranet.empresa.com/rh/ferias'], 'hash': []})
		result = self.state.dry_run({'type': 'url', 'mode': 'prefix',
			'host_pattern': 'intranet.empresa.com', 'path_pattern': '/rh/'}, now = NOW)
		self.assertEqual(result['matched'], 1)

	def test_the_expiry_of_the_candidate_rule_does_not_affect_the_simulation(self):
		# A simulacao pergunta pelo alcance do padrao; o prazo ainda nem foi escolhido
		self.record()
		result = self.state.dry_run({'type': 'sender', 'value': 'faturamento@empresa.com.br',
			'expires_at': '2020-01-01T00:00:00Z'}, now = NOW)
		self.assertEqual(result['matched'], 1)

	def test_pruning_drops_what_is_past_the_retention(self):
		self.record(now = NOW - datetime.timedelta(days = 120))
		self.record(now = NOW)
		self.state._last_prune = None
		self.state.prune({'whitelistHistoryRetentionDays': 90}, NOW)
		result = self.state.dry_run({'type': 'sender', 'value': 'faturamento@empresa.com.br'},
			days = 365, now = NOW)
		self.assertEqual(result['analyzed'], 1)

	def test_the_observable_list_is_capped_per_type(self):
		self.record(observables = {'domain': ['d{0}.com'.format(i) for i in range(200)], 'url': [], 'hash': []})
		result = self.state.dry_run({'type': 'domain', 'value': 'd0.com'}, now = NOW)
		self.assertEqual(result['matched'], 1)
		result = self.state.dry_run({'type': 'domain', 'value': 'd199.com'}, now = NOW)
		self.assertEqual(result['matched'], 0)


if __name__ == '__main__':
	unittest.main()
