"""Testes do escopo: o que conta como "a mesma mensagem", e o que não se conta.

Duas classes de erro aqui mudam uma decisão sem produzir exceção nenhuma.

A primeira é **contar demais**: um resumo frouxo junta duas campanhas distintas
e a tela diz "40 pessoas denunciaram" sobre um e-mail que 1 pessoa denunciou. A
segunda é **contar de menos**: um resumo estrito demais trata cada denúncia da
mesma campanha como um caso isolado, que é exatamente o estado anterior a este
módulo — e aí o número novo não acrescenta nada.

A terceira, e a pior, é **contar quando não se sabe**. Um registro sem impressão
digital gravada precisa responder `None`. Um zero ali é uma contagem que ninguém
fez, apresentada como se fosse.

Rodar com:  python -m unittest test_case_scope   (a partir de app/)
"""

import datetime
import os
import tempfile
import unittest

import models


NOW = datetime.datetime(2026, 9, 15, 12, 0, 0)


def observables(*urls):
	return [{'type': 'url', 'value': url} for url in urls]


class Fingerprints(unittest.TestCase):
	"""A parte pura: o que dois e-mails precisam ter em comum para casar."""

	def setUp(self):
		import case_scope
		self.scope = case_scope

	def key(self, subject, sender, body, urls = ()):
		return self.scope.content_key(subject, sender, body, observables(*urls))

	def test_the_same_campaign_matches_across_forwarding_prefixes(self):
		first = self.key('ENC: Sua fatura venceu', 'cobranca@exemplo.com',
			'Prezado, acesse o portal.', ['http://mal.example/pagar'])
		second = self.key('RES: Sua fatura venceu', 'cobranca@exemplo.com',
			'Prezado, acesse o portal.', ['http://mal.example/pagar'])
		self.assertEqual(first, second)

	def test_a_per_recipient_number_does_not_split_a_campaign(self):
		# Boleto, protocolo e id de rastreio mudam por pessoa; a mensagem não
		first = self.key('Fatura 998877 vencida', 'cobranca@exemplo.com',
			'Sua fatura 998877 venceu.')
		second = self.key('Fatura 112233 vencida', 'cobranca@exemplo.com',
			'Sua fatura 112233 venceu.')
		self.assertEqual(first, second)

	def test_the_sender_case_does_not_split_a_campaign(self):
		first = self.key('Aviso', 'Cobranca@Exemplo.COM', 'texto')
		second = self.key('Aviso', 'cobranca@exemplo.com', 'texto')
		self.assertEqual(first, second)

	def test_whitespace_does_not_split_a_campaign(self):
		self.assertEqual(self.key('Aviso', 'a@b.com', 'um  dois\n\ttrês'),
			self.key('Aviso', 'a@b.com', 'um dois três'))

	def test_a_tracking_parameter_does_not_split_a_campaign(self):
		# O host é o que entra no resumo, não a query com o id de quem abriu
		first = self.key('Aviso', 'a@b.com', 'texto', ['http://mal.example/p?id=1'])
		second = self.key('Aviso', 'a@b.com', 'texto', ['http://mal.example/p?id=2'])
		self.assertEqual(first, second)

	def test_a_different_body_is_a_different_message(self):
		self.assertNotEqual(self.key('Aviso', 'a@b.com', 'pague aqui'),
			self.key('Aviso', 'a@b.com', 'sua conta foi bloqueada'))

	def test_a_different_sender_is_a_different_message(self):
		self.assertNotEqual(self.key('Aviso', 'a@b.com', 'texto'),
			self.key('Aviso', 'outro@b.com', 'texto'))

	def test_a_different_host_is_a_different_message(self):
		self.assertNotEqual(self.key('Aviso', 'a@b.com', 'texto', ['http://um.example/p']),
			self.key('Aviso', 'a@b.com', 'texto', ['http://dois.example/p']))

	def test_the_order_the_urls_were_extracted_in_is_not_a_fact(self):
		self.assertEqual(
			self.key('Aviso', 'a@b.com', 'texto', ['http://um.example/p', 'http://dois.example/q']),
			self.key('Aviso', 'a@b.com', 'texto', ['http://dois.example/q', 'http://um.example/p']))

	def test_a_message_with_neither_subject_nor_body_has_no_content_key(self):
		# Senão toda mensagem vazia casaria com toda mensagem vazia, e é esta
		# chave que rebaixa veredito
		self.assertEqual(self.key('', 'a@b.com', ''), '')

	def test_the_body_key_ignores_the_subject(self):
		first = self.scope.body_key('Prezado, acesse o portal.')
		second = self.scope.body_key('Prezado,  acesse o portal.')
		self.assertEqual(first, second)
		self.assertNotEqual(first, self.scope.body_key('outra coisa'))

	def test_an_empty_body_has_no_body_key(self):
		self.assertEqual(self.scope.body_key('   '), '')

	def test_the_sender_key_is_the_one_the_whitelist_writes(self):
		import whitelist
		self.assertEqual(self.scope.sender_key(' Cobranca@Exemplo.COM '),
			whitelist.normalize_address('Cobranca@Exemplo.COM'))

	def test_a_sender_that_is_not_an_address_has_no_key(self):
		self.assertEqual(self.scope.sender_key('Departamento Financeiro'), '')


class DatabaseBacked(unittest.TestCase):

	def setUp(self):
		handle, self.db_path = tempfile.mkstemp(suffix = '.db')
		os.close(handle)
		self.previous_path = models.DB_PATH
		models.DB_PATH = self.db_path
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		import case_scope
		self.scope = case_scope

	def tearDown(self):
		models._engine = None
		models._SessionFactory = None
		models.DB_PATH = self.previous_path
		if os.path.isfile(self.db_path):
			try:
				os.remove(self.db_path)
			except OSError:
				pass

	def report(self, refs, case_ref, reporter, subject = 'Sua fatura venceu',
			sender = 'cobranca@exemplo.com', body = 'Prezado, acesse o portal.',
			urls = ('http://mal.example/pagar',), verdict = 'Suspicious', now = NOW):
		return self.scope.record(refs, case_ref, subject, sender, reporter, body,
			observables(*urls), verdict, now = now)


class Scope(DatabaseBacked):

	def test_a_record_nobody_else_reported_counts_one_person(self):
		self.report(['4127'], '4127', 'ana@empresa.com')
		scope = self.scope.scope_for('4127')
		self.assertTrue(scope['known'])
		self.assertEqual(scope['reporters'], 1)
		self.assertEqual(scope['reports'], 1)

	def test_three_people_reporting_the_same_campaign_count_three(self):
		# O número de fatura muda por destinatário e existe em todas as cópias
		self.report(['4127'], '4127', 'ana@empresa.com', subject = 'Sua fatura 1111 venceu')
		self.report(['4128'], '4128', 'bruno@empresa.com',
			subject = 'ENC: Sua fatura 2222 venceu')
		self.report(['4129'], '4129', 'carla@empresa.com',
			subject = 'Sua fatura 3333 venceu')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reporters'], 3)
		self.assertEqual(scope['reports'], 3)
		self.assertEqual(scope['match'], 'content')

	def test_the_same_person_reporting_twice_is_one_person(self):
		self.report(['4127'], '4127', 'ana@empresa.com')
		self.report(['4128'], '4128', 'Ana@Empresa.com')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reporters'], 1)
		self.assertEqual(scope['reports'], 2)

	def test_another_campaign_is_not_counted_in(self):
		self.report(['4127'], '4127', 'ana@empresa.com')
		self.report(['4200'], '4200', 'bruno@empresa.com',
			subject = 'Outra coisa', body = 'nada a ver', urls = ('http://outro.example/x',))
		self.assertEqual(self.scope.scope_for('4127')['reporters'], 1)
		self.assertEqual(self.scope.scope_for('4200')['reporters'], 1)

	def test_a_rewritten_subject_still_matches_on_the_body(self):
		self.report(['4127'], '4127', 'ana@empresa.com')
		self.report(['4128'], '4128', 'bruno@empresa.com',
			subject = 'Olha isso que chegou pra mim, é golpe?')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reporters'], 2)
		self.assertEqual(scope['match'], 'body')

	def test_a_few_rewritten_subjects_do_not_undercount_the_campaign(self):
		self.report(['4127'], '4127', 'ana@empresa.com')
		self.report(['4128'], '4128', 'bruno@empresa.com')
		self.report(['4129'], '4129', 'carla@empresa.com', subject = 'isso é golpe?')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reporters'], 3)
		self.assertEqual(scope['match'], 'body')

	def test_two_destinations_of_one_analysis_are_one_report(self):
		# TheHive e disco ligados gravam duas linhas para a mesma denúncia
		self.report(['4127', 'disk:2026-09-15T12-00-00-caso'], '4127', 'ana@empresa.com')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reports'], 1)
		self.assertEqual(scope['reporters'], 1)
		# E a referência do disco responde o mesmo escopo
		self.assertEqual(self.scope.scope_for('disk:2026-09-15T12-00-00-caso')['reports'], 1)

	def test_first_and_last_seen_bracket_the_campaign(self):
		early = NOW - datetime.timedelta(hours = 3)
		late = NOW + datetime.timedelta(hours = 1)
		self.report(['4127'], '4127', 'ana@empresa.com', now = early)
		self.report(['4128'], '4128', 'bruno@empresa.com', now = late)
		scope = self.scope.scope_for('4127')
		self.assertTrue(scope['firstSeen'].startswith(early.replace(microsecond = 0).isoformat()))
		self.assertTrue(scope['lastSeen'].startswith(late.replace(microsecond = 0).isoformat()))


class WhatIsNotKnown(DatabaseBacked):
	"""A contagem que não existe responde None, e nunca zero."""

	def test_a_record_without_a_fingerprint_is_unknown_not_zero(self):
		scope = self.scope.scope_for('nunca-analisado')
		self.assertFalse(scope['known'])
		self.assertIsNone(scope['reporters'])
		self.assertIsNone(scope['reports'])

	def test_reports_without_a_reporter_still_count_as_reports(self):
		# Uma instalação que nunca preencheu o denunciante sabe quantas denúncias
		# houve e não sabe quantas pessoas. As duas respostas são diferentes
		self.report(['4127'], '4127', '')
		self.report(['4128'], '4128', '')
		scope = self.scope.scope_for('4127')
		self.assertEqual(scope['reports'], 2)
		self.assertIsNone(scope['reporters'])

	def test_recording_without_a_reference_writes_nothing(self):
		keys = self.report([], '', 'ana@empresa.com')
		self.assertTrue(keys['contentKey'])
		self.assertFalse(self.scope.scope_for('4127')['known'])


class Keys(DatabaseBacked):

	def test_the_keys_of_a_record_come_back_for_the_verdict_memory(self):
		written = self.report(['4127'], '4127', 'ana@empresa.com')
		read = self.scope.keys_for('4127')
		self.assertEqual(read['contentKey'], written['contentKey'])
		self.assertEqual(read['senderKey'], written['senderKey'])
		self.assertEqual(read['reporter'], 'ana@empresa.com')

	def test_a_reanalysis_under_the_report_key_is_not_a_new_report(self):
		self.report(['4127', 'disk:2026-09-15T12-00-00-caso'], '4127', 'ana@empresa.com')
		# A mesa abriu o caso pela cópia em disco; a chave de denúncia é a mesma
		report_key = self.scope.keys_for('disk:2026-09-15T12-00-00-caso')['reportKey']
		self.report(['4300'], report_key, 'ana@empresa.com')
		self.assertEqual(self.scope.scope_for('4127')['reports'], 1)

	def test_an_unknown_record_has_no_keys(self):
		self.assertIsNone(self.scope.keys_for('4127'))

	def test_the_latest_analysis_of_a_record_wins(self):
		# Reanalisar um caso grava outra impressão digital sob a mesma referência
		self.report(['4127'], '4127', 'ana@empresa.com', body = 'antigo')
		second = self.report(['4127'], '4127', 'ana@empresa.com', body = 'depois da reanálise')
		self.assertEqual(self.scope.keys_for('4127')['contentKey'], second['contentKey'])


if __name__ == '__main__':
	unittest.main()
