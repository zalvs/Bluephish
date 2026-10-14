"""Testes da memória de vereditos: o laço que faz uma correção humana valer depois.

O que estes testes prendem é o que tornaria a memória um bypass se quebrasse em
silêncio. Rebaixar veredito a partir de uma decisão de uma pessoa só é aceitável
porque o rebaixamento é contado, suspenso quando esconde demais, revogado quando
a decisão é desfeita, nunca aplicado a anexo malicioso — e porque liberar um
remetente inteiro não é algo que esta memória faça sozinha.

Rodar com:  python -m unittest test_verdict_memory   (a partir de app/)
"""

import datetime
import os
import tempfile
import unittest

import models


NOW = datetime.datetime(2026, 9, 15, 12, 0, 0)
LIMITS = {'whitelistMaliciousLimit': 3, 'whitelistTotalLimit': 5, 'whitelistWindowDays': 30}
KEYS = {'contentKey': 'c' * 64, 'bodyKey': 'b' * 64, 'senderKey': 'cobranca@exemplo.com',
	'reporter': 'ana@empresa.com', 'subject': 'Sua fatura', 'reportKey': '4127'}


def decision(verdict = 'Safe', previous = 'Suspicious', decision_id = 7):
	return {'id': decision_id, 'recordRef': '4127', 'action': 'reclassify',
		'previousVerdict': previous, 'verdict': verdict, 'reason': 'confirmado com o fornecedor por telefone'}


class DatabaseBacked(unittest.TestCase):

	def setUp(self):
		handle, self.db_path = tempfile.mkstemp(suffix = '.db')
		os.close(handle)
		self.previous_path = models.DB_PATH
		models.DB_PATH = self.db_path
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		import verdict_memory
		self.memory = verdict_memory

	def tearDown(self):
		models._engine = None
		models._SessionFactory = None
		models.DB_PATH = self.previous_path
		if os.path.isfile(self.db_path):
			try:
				os.remove(self.db_path)
			except OSError:
				pass

	def apply(self, verdict = 'Suspicious', key = KEYS['contentKey'], attachment = False, now = NOW):
		return self.memory.apply(verdict, key, attachment, message_from = 'cobranca@exemplo.com',
			subject = 'Sua fatura', config = LIMITS, now = now)


class Learning(DatabaseBacked):

	def test_the_content_scope_learns_the_identical_message(self):
		learned = self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)
		self.assertEqual([m['scope'] for m in learned], ['content'])
		self.assertEqual(learned[0]['key'], KEYS['contentKey'])

	def test_the_sender_scope_learns_the_message_and_proposes_the_sender(self):
		learned = self.memory.learn(decision(), KEYS, 'sender', 'ana', now = NOW)
		scopes = sorted(m['scope'] for m in learned)
		self.assertEqual(scopes, ['content', 'sender'])
		sender = [m for m in learned if m['scope'] == 'sender'][0]
		self.assertEqual(sender['proposalStatus'], 'pending')

	def test_the_case_scope_learns_nothing(self):
		self.assertEqual(self.memory.learn(decision(), KEYS, 'case', 'ana', now = NOW), [])

	def test_confirming_malicious_is_never_learned(self):
		# Só rebaixa, nunca condena
		self.assertEqual(self.memory.learn(decision(verdict = 'Malicious'), KEYS, 'content', 'ana', now = NOW), [])

	def test_a_record_without_keys_learns_nothing(self):
		# Uma chave vazia casaria com toda mensagem sem chave
		self.assertEqual(self.memory.learn(decision(), {}, 'content', 'ana', now = NOW), [])
		self.assertEqual(self.memory.learn(decision(), dict(KEYS, contentKey = ''), 'content', 'ana', now = NOW), [])

	def test_an_unknown_scope_learns_nothing(self):
		self.assertEqual(self.memory.learn(decision(), KEYS, 'domain', 'ana', now = NOW), [])

	def test_a_memory_expires(self):
		learned = self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)
		self.assertTrue(learned[0]['expiresAt'])
		later = NOW + datetime.timedelta(days = self.memory.DEFAULT_TTL_DAYS + 1)
		self.assertIsNone(self.memory.match_content(KEYS['contentKey'], now = later))


class Applying(DatabaseBacked):

	def setUp(self):
		super().setUp()
		self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)

	def test_the_identical_message_is_lowered_to_safe(self):
		verdict, note, memory = self.apply('Suspicious')
		self.assertEqual(verdict, 'Safe')
		self.assertIn('ana', note)
		self.assertIsNotNone(memory)

	def test_a_malicious_verdict_is_lowered_too_and_counted(self):
		verdict, _note, memory = self.apply('Malicious')
		self.assertEqual(verdict, 'Safe')
		import whitelist_state
		stats = whitelist_state.stats_for([self.memory.rule_id_of(memory['id'])], now = NOW)
		self.assertEqual(stats[self.memory.rule_id_of(memory['id'])]['suppressionCount'], 1)

	def test_a_hit_is_counted_on_the_memory(self):
		self.apply('Suspicious')
		self.apply('Suspicious', now = NOW + datetime.timedelta(minutes = 1))
		self.assertEqual(self.memory.match_content(KEYS['contentKey'], now = NOW)['hits'], 2)

	def test_another_message_is_not_lowered(self):
		verdict, note, memory = self.apply('Suspicious', key = 'd' * 64)
		self.assertEqual((verdict, note, memory), ('Suspicious', None, None))

	def test_a_safe_verdict_is_left_alone_and_not_counted(self):
		verdict, note, _memory = self.apply('Safe')
		self.assertEqual(verdict, 'Safe')
		self.assertIsNone(note)

	def test_a_malicious_attachment_is_never_lowered(self):
		verdict, note, memory = self.apply('Malicious', attachment = True)
		self.assertEqual(verdict, 'Malicious')
		self.assertIn('anexo malicioso', note)
		self.assertIsNotNone(memory)

	def test_a_memory_that_hides_too_much_suspends_itself(self):
		# Três Malicious escondidos na janela suspendem, e o terceiro não é escondido
		self.assertEqual(self.apply('Malicious')[0], 'Safe')
		self.assertEqual(self.apply('Malicious', now = NOW + datetime.timedelta(hours = 1))[0], 'Safe')
		verdict, note, _memory = self.apply('Malicious', now = NOW + datetime.timedelta(hours = 2))
		self.assertEqual(verdict, 'Malicious')
		self.assertIn('SUSPENSA', note)
		# E continua suspensa depois
		verdict, _note, _memory = self.apply('Suspicious', now = NOW + datetime.timedelta(hours = 3))
		self.assertEqual(verdict, 'Suspicious')

	def test_an_empty_key_never_matches(self):
		self.assertEqual(self.apply('Suspicious', key = '')[0], 'Suspicious')


class TheSenderIsNeverLoweredByMemory(DatabaseBacked):

	def test_a_sender_proposal_does_not_lower_another_message_from_that_sender(self):
		self.memory.learn(decision(), KEYS, 'sender', 'ana', now = NOW)
		# Outra mensagem, mesmo remetente: a chave de conteúdo é outra
		verdict, _note, memory = self.apply('Suspicious', key = 'e' * 64)
		self.assertEqual(verdict, 'Suspicious')
		self.assertIsNone(memory)

	def test_a_sender_key_is_never_consulted_as_content(self):
		self.memory.learn(decision(), KEYS, 'sender', 'ana', now = NOW)
		self.assertIsNone(self.memory.match_content(KEYS['senderKey'], now = NOW))


class Revoking(DatabaseBacked):

	def test_undoing_the_decision_revokes_what_it_taught(self):
		self.memory.learn(decision(decision_id = 7), KEYS, 'sender', 'ana', now = NOW)
		self.assertEqual(self.memory.revoke_for_decision(7, 'admin', '4127', now = NOW), 2)
		self.assertEqual(self.apply('Suspicious')[0], 'Suspicious')
		sender = [m for m in self.memory.for_decision(7) if m['scope'] == 'sender'][0]
		self.assertEqual(sender['proposalStatus'], 'dismissed')

	def test_revoking_one_memory(self):
		learned = self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)
		self.assertIsNotNone(self.memory.revoke(learned[0]['id'], 'admin', now = NOW))
		self.assertEqual(self.apply('Suspicious')[0], 'Suspicious')
		# Revogar de novo não é revogar
		self.assertIsNone(self.memory.revoke(learned[0]['id'], 'admin', now = NOW))

	def test_revoking_a_decision_that_taught_nothing_is_zero(self):
		self.assertEqual(self.memory.revoke_for_decision(99, 'admin', '4127', now = NOW), 0)
		self.assertEqual(self.memory.revoke_for_decision(None, 'admin', '4127', now = NOW), 0)

	def test_a_foreign_decision_id_does_not_revoke_another_record(self):
		# Uma decisão embutida num report.json de outra instalação traz o id do
		# banco de lá; se ele coincide com uma decisão daqui, a lição daqui fica
		self.memory.learn(decision(decision_id = 7), KEYS, 'content', 'ana', now = NOW)
		self.assertEqual(self.memory.revoke_for_decision(7, 'admin', 'disk:outro-registro', now = NOW), 0)
		self.assertEqual(self.apply('Suspicious')[0], 'Safe')

	def test_a_memory_is_found_by_id(self):
		learned = self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)
		self.assertEqual(self.memory.get(learned[0]['id'])['key'], KEYS['contentKey'])
		self.assertIsNone(self.memory.get(99999))


class Proposals(DatabaseBacked):

	def test_accepting_a_proposal_records_the_rule(self):
		learned = self.memory.learn(decision(), KEYS, 'sender', 'ana', now = NOW)
		sender = [m for m in learned if m['scope'] == 'sender'][0]
		resolved = self.memory.resolve_proposal(sender['id'], True, 'admin', 'wl_abc', now = NOW)
		self.assertEqual(resolved['proposalStatus'], 'accepted')
		self.assertEqual(resolved['whitelistRuleId'], 'wl_abc')

	def test_a_proposal_is_resolved_once(self):
		learned = self.memory.learn(decision(), KEYS, 'sender', 'ana', now = NOW)
		sender = [m for m in learned if m['scope'] == 'sender'][0]
		self.memory.resolve_proposal(sender['id'], False, 'admin', now = NOW)
		self.assertIsNone(self.memory.resolve_proposal(sender['id'], True, 'admin', 'wl_x', now = NOW))

	def test_a_content_memory_is_not_a_proposal(self):
		learned = self.memory.learn(decision(), KEYS, 'content', 'ana', now = NOW)
		self.assertIsNone(self.memory.resolve_proposal(learned[0]['id'], True, 'admin', 'wl_x', now = NOW))


class FailingClosed(unittest.TestCase):
	"""Sem banco, nada é rebaixado."""

	def test_an_unreachable_database_lowers_nothing(self):
		import verdict_memory
		original = models.get_session
		def broken():
			raise RuntimeError('banco fora')
		models.get_session = broken
		try:
			verdict, note, memory = verdict_memory.apply('Suspicious', 'c' * 64, False, config = LIMITS, now = NOW)
			self.assertEqual((verdict, note, memory), ('Suspicious', None, None))
			self.assertTrue(verdict_memory.is_suspended(1))
		finally:
			models.get_session = original


if __name__ == '__main__':
	unittest.main()
