"""Testes do acervo de mensagens originais.

O que estas regras protegem: reanalisar um caso e ver o e-mail como ele chegou
dependem de o `.eml` estar lá e ser o certo. Um acervo que devolve a mensagem de
outro caso, ou que cresce até encher o volume, falha de um jeito que ninguém vê
até ser tarde. Então os testes são sobre isso — retenção, orçamento de bytes,
metadado que faz a entrada existir, e escrita interrompida não deixando rastro.

Rodar com:  python -m unittest test_eml_store   (do diretório app/)
"""

import io
import os
import shutil
import tempfile
import time
import unittest

import eml_store


def message(text):
	return ('From: quem@exemplo.com\r\nSubject: ' + text + '\r\n\r\ncorpo').encode('utf-8')


class StoreTestCase(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.directory, ignore_errors = True)

	def store(self, max_bytes = eml_store.MAX_BYTES, retention_days = eml_store.RETENTION_DAYS):
		return eml_store.EmlStore(self.directory, max_bytes = max_bytes, retention_days = retention_days)

	def files(self):
		return sorted(os.listdir(self.directory))


class ReadingBack(StoreTestCase):

	def test_what_is_stored_comes_back_byte_for_byte(self):
		store = self.store()
		self.assertTrue(store.put('4127', message('a')))
		self.assertEqual(store.get('4127'), message('a'))

	def test_a_reference_that_was_never_stored_answers_none(self):
		store = self.store()
		self.assertIsNone(store.get('4127'))
		self.assertFalse(store.has('4127'))

	def test_has_answers_from_the_index_without_reading_the_file(self):
		store = self.store()
		store.put('disk:2026-09-15T10-00-00-abc', message('a'))
		self.assertTrue(store.has('disk:2026-09-15T10-00-00-abc'))
		self.assertEqual(store.size_of('disk:2026-09-15T10-00-00-abc'), len(message('a')))

	def test_a_reference_with_slashes_and_colons_is_a_legal_key(self):
		# jira:SOC-12 e disk:<pasta> chegam da URL; nenhum deles pode virar caminho
		store = self.store()
		store.put('jira:SOC-12', message('jira'))
		store.put('disk:2026-09-15T10-00-00-caso', message('disco'))
		self.assertEqual(store.get('jira:SOC-12'), message('jira'))
		self.assertEqual(store.get('disk:2026-09-15T10-00-00-caso'), message('disco'))
		for name in self.files():
			self.assertNotIn(':', name)
			self.assertNotIn('/', name)

	def test_rewriting_a_reference_replaces_what_was_there(self):
		store = self.store()
		store.put('4127', message('antiga'))
		store.put('4127', message('nova'))
		self.assertEqual(store.get('4127'), message('nova'))
		self.assertEqual(store.count(), 1)

	def test_a_number_and_its_string_are_the_same_reference(self):
		store = self.store()
		store.put(4127, message('a'))
		self.assertEqual(store.get('4127'), message('a'))


class WhatIsRefused(StoreTestCase):

	def test_an_empty_message_is_not_stored(self):
		store = self.store()
		self.assertFalse(store.put('4127', b''))
		self.assertFalse(store.has('4127'))

	def test_an_empty_reference_is_not_stored(self):
		store = self.store()
		self.assertFalse(store.put('', message('a')))
		self.assertEqual(self.files(), [])

	def test_a_message_over_the_ceiling_is_refused_without_raising(self):
		store = self.store()
		huge = b'x' * (eml_store.MAX_MESSAGE_BYTES + 1)
		self.assertFalse(store.put('4127', huge))
		self.assertFalse(store.has('4127'))

	def test_refusing_does_not_destroy_what_was_already_there(self):
		store = self.store()
		store.put('4127', message('boa'))
		store.put('4127', b'')
		self.assertEqual(store.get('4127'), message('boa'))


class TheBudget(StoreTestCase):

	def test_the_oldest_leaves_first_when_the_budget_is_exceeded(self):
		store = self.store(max_bytes = len(message('a')) * 2 + 10)
		store.put('1', message('a'))
		store.put('2', message('b'))
		store.put('3', message('c'))
		self.assertFalse(store.has('1'))
		self.assertTrue(store.has('3'))

	def test_what_was_just_written_is_never_the_one_evicted(self):
		store = self.store(max_bytes = 1)
		store.put('1', message('a'))
		# Cabe zero, mas quem acabou de chegar não é despejado para caber a si
		self.assertTrue(store.has('1'))

	def test_an_evicted_entry_leaves_no_file_behind(self):
		store = self.store(max_bytes = len(message('a')) + 10)
		store.put('1', message('a'))
		store.put('2', message('b'))
		self.assertFalse(store.has('1'))
		# Restam só os dois arquivos da entrada que ficou
		self.assertEqual(len(self.files()), 2)


class Retention(StoreTestCase):

	def test_an_entry_older_than_the_window_is_pruned(self):
		store = self.store(retention_days = 90)
		old = time.time() - 91 * eml_store.SECONDS_PER_DAY
		store.put('velho', message('a'), now = old)
		store.put('novo', message('b'))
		self.assertEqual(store.prune(), 1)
		self.assertFalse(store.has('velho'))
		self.assertTrue(store.has('novo'))

	def test_retention_zero_keeps_everything_the_budget_allows(self):
		store = self.store(retention_days = 0)
		ancient = time.time() - 4000 * eml_store.SECONDS_PER_DAY
		store.put('antigo', message('a'), now = ancient)
		self.assertEqual(store.prune(), 0)
		self.assertTrue(store.has('antigo'))

	def test_prune_also_applies_the_byte_budget(self):
		store = self.store(max_bytes = len(message('a')) + 10, retention_days = 0)
		store.put('1', message('a'))
		# Escrito direto no índice para escapar do despejo do put
		store.max_bytes = 1
		self.assertEqual(store.prune(), 1)
		self.assertEqual(store.count(), 0)


class SharedPayloads(StoreTestCase):
	"""Uma análise gravada no TheHive e no disco produz duas referências, um arquivo."""

	def test_two_references_to_the_same_message_share_one_file(self):
		store = self.store()
		store.put('4127', message('a'))
		store.put('disk:2026-09-15T10-00-00-caso', message('a'))
		self.assertEqual(store.count(), 2)
		# Dois metadados e um payload
		self.assertEqual(len([n for n in self.files() if n.endswith(eml_store.PAYLOAD_SUFFIX)]), 1)
		self.assertEqual(store.total_bytes(), len(message('a')))

	def test_both_references_read_the_message_back(self):
		store = self.store()
		store.put('4127', message('a'))
		store.put('jira:SOC-12', message('a'))
		self.assertEqual(store.get('4127'), message('a'))
		self.assertEqual(store.get('jira:SOC-12'), message('a'))

	def test_discarding_one_reference_keeps_the_file_for_the_other(self):
		store = self.store()
		store.put('4127', message('a'))
		store.put('jira:SOC-12', message('a'))
		store.discard('4127')
		self.assertIsNone(store.get('4127'))
		self.assertEqual(store.get('jira:SOC-12'), message('a'))

	def test_the_file_goes_when_the_last_reference_goes(self):
		store = self.store()
		store.put('4127', message('a'))
		store.put('jira:SOC-12', message('a'))
		store.discard('4127')
		store.discard('jira:SOC-12')
		self.assertEqual(self.files(), [])

	def test_replacing_the_content_of_a_reference_collects_the_old_file(self):
		store = self.store()
		store.put('4127', message('antiga'))
		store.put('4127', message('nova'))
		self.assertEqual(len([n for n in self.files() if n.endswith(eml_store.PAYLOAD_SUFFIX)]), 1)
		self.assertEqual(store.get('4127'), message('nova'))

	def test_replacing_one_of_two_references_keeps_the_shared_file(self):
		store = self.store()
		store.put('4127', message('a'))
		store.put('jira:SOC-12', message('a'))
		store.put('4127', message('b'))
		self.assertEqual(store.get('jira:SOC-12'), message('a'))
		self.assertEqual(store.get('4127'), message('b'))
		self.assertEqual(len([n for n in self.files() if n.endswith(eml_store.PAYLOAD_SUFFIX)]), 2)

	def test_a_shared_file_survives_a_restart_once(self):
		first = self.store()
		first.put('4127', message('a'))
		first.put('jira:SOC-12', message('a'))
		second = self.store()
		self.assertEqual(second.get('4127'), message('a'))
		self.assertEqual(second.get('jira:SOC-12'), message('a'))
		self.assertEqual(second.total_bytes(), len(message('a')))


class SurvivingARestart(StoreTestCase):

	def test_the_index_is_rebuilt_from_disk(self):
		first = self.store()
		first.put('4127', message('a'))
		second = self.store()
		self.assertTrue(second.has('4127'))
		self.assertEqual(second.get('4127'), message('a'))

	def test_a_payload_without_metadata_was_never_an_entry(self):
		store = self.store()
		store.put('4127', message('a'))
		meta = [n for n in self.files() if n.endswith(eml_store.META_SUFFIX)][0]
		os.remove(os.path.join(self.directory, meta))
		reopened = self.store()
		self.assertFalse(reopened.has('4127'))
		# E o payload órfão foi recolhido, não deixado ocupando o volume
		self.assertEqual(self.files(), [])

	def test_metadata_without_a_payload_is_discarded(self):
		store = self.store()
		store.put('4127', message('a'))
		payload = [n for n in self.files() if n.endswith(eml_store.PAYLOAD_SUFFIX)][0]
		os.remove(os.path.join(self.directory, payload))
		reopened = self.store()
		self.assertFalse(reopened.has('4127'))
		self.assertEqual(self.files(), [])

	def test_an_interrupted_write_leaves_nothing_on_the_next_start(self):
		store = self.store()
		store.put('4127', message('a'))
		key = store.index['4127']['key']
		with io.open(os.path.join(self.directory, key + '.outro' + eml_store.TEMP_SUFFIX), 'wb') as handle:
			handle.write(b'metade')
		reopened = self.store()
		self.assertTrue(reopened.has('4127'))
		self.assertFalse(any(n.endswith(eml_store.TEMP_SUFFIX) for n in self.files()))

	def test_unreadable_metadata_is_not_an_entry(self):
		store = self.store()
		store.put('4127', message('a'))
		meta = [n for n in self.files() if n.endswith(eml_store.META_SUFFIX)][0]
		with io.open(os.path.join(self.directory, meta), 'wb') as handle:
			handle.write(b'{nao e json')
		reopened = self.store()
		self.assertFalse(reopened.has('4127'))

	def test_the_sequence_continues_where_the_last_run_stopped(self):
		# Sem isto, depois de um restart toda entrada nova nasce com sequência 1 e
		# o despejo escolhe pela ordem errada
		first = self.store()
		first.put('1', message('a'))
		first.put('2', message('b'))
		second = self.store(max_bytes = len(message('a')) * 2 + 10)
		second.put('3', message('c'))
		self.assertFalse(second.has('1'))
		self.assertTrue(second.has('3'))


class Discarding(StoreTestCase):

	def test_discarding_removes_both_files(self):
		store = self.store()
		store.put('4127', message('a'))
		store.discard('4127')
		self.assertFalse(store.has('4127'))
		self.assertEqual(self.files(), [])

	def test_discarding_something_unknown_is_not_an_error(self):
		store = self.store()
		store.discard('nunca-existiu')
		self.assertEqual(self.files(), [])


if __name__ == '__main__':
	unittest.main()
