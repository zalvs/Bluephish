"""Tests for the on-disk store of "as delivered" layouts.

Every rule here exists because breaking it shows an analyst the wrong email laid
out and complete, rather than failing. So the tests are about that: stamps, the
better copy winning, and a write that is interrupted leaving nothing behind.

Run with:  python -m unittest test_render_store   (from the app/ directory)
"""

import os
import shutil
import tempfile
import unittest

import render_store


def layout(text):
	return {'html': '<p>' + text + '</p>', 'source': 'message'}


class StoreTestCase(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp()

	def tearDown(self):
		shutil.rmtree(self.directory, ignore_errors = True)

	def store(self, max_bytes = render_store.MAX_BYTES):
		return render_store.RenderStore(self.directory, max_bytes = max_bytes)

	def files(self):
		return sorted(os.listdir(self.directory))


class ReadingBack(StoreTestCase):

	def test_what_is_stored_comes_back_with_its_kind(self):
		store = self.store()
		store.put('4127', 1000, layout('a'), layout_only = True)
		payload, layout_only = store.get('4127', 1000)
		self.assertEqual(payload, layout('a'))
		self.assertTrue(layout_only)
		self.assertEqual(store.status('4127', 1000), 'layout')

	def test_a_recycled_id_is_deleted_not_served(self):
		# Same sequence number, another message: the arrival time disagrees
		store = self.store()
		store.put('4127', 1000, layout('somebody else'), layout_only = True)
		self.assertEqual(store.get('4127', 2000), (None, None))
		self.assertEqual(self.files(), [])
		self.assertIsNone(store.status('4127', 1000))

	def test_the_status_of_a_recycled_id_is_nothing(self):
		store = self.store()
		store.put('4127', 1000, layout('a'), layout_only = False)
		self.assertIsNone(store.status('4127', 2000))

	def test_an_email_without_a_readable_date_is_still_stored(self):
		store = self.store()
		store.put('9', None, layout('a'), layout_only = True)
		self.assertEqual(store.get('9', None)[0], layout('a'))

	def test_a_payload_that_vanished_from_disk_is_forgotten(self):
		store = self.store()
		store.put('1', 1, layout('a'), layout_only = True)
		for name in self.files():
			if not name.endswith(render_store.META_SUFFIX):
				os.remove(os.path.join(self.directory, name))
		self.assertEqual(store.get('1', 1), (None, None))
		self.assertEqual(self.files(), [])

	def test_a_long_graph_id_with_awkward_characters_is_stored(self):
		store = self.store()
		graph_id = 'AAMkAGI2TG93AAA=/+sub/../AAA' * 8
		store.put(graph_id, 5, layout('a'), layout_only = True)
		self.assertEqual(store.get(graph_id, 5)[0], layout('a'))
		for name in self.files():
			self.assertNotIn('/', name)
			self.assertNotIn('..', name)


class TheBetterCopyWins(StoreTestCase):

	def test_a_layout_without_images_does_not_replace_one_with_them(self):
		# The click fetched the remote images; the background pass must not
		# throw that away on its next round
		store = self.store()
		store.put('1', 1, layout('with images'), layout_only = False)
		self.assertFalse(store.put('1', 1, layout('without'), layout_only = True))
		payload, layout_only = store.get('1', 1)
		self.assertEqual(payload, layout('with images'))
		self.assertFalse(layout_only)

	def test_a_layout_with_images_replaces_one_without(self):
		store = self.store()
		store.put('1', 1, layout('without'), layout_only = True)
		self.assertTrue(store.put('1', 1, layout('with images'), layout_only = False))
		self.assertEqual(store.status('1', 1), 'full')

	def test_a_recycled_id_is_overwritten_even_by_a_layout_only_copy(self):
		# The "better" copy belongs to another message, so it is not better
		store = self.store()
		store.put('1', 1, layout('old message'), layout_only = False)
		self.assertTrue(store.put('1', 2, layout('new message'), layout_only = True))
		self.assertEqual(store.get('1', 2)[0], layout('new message'))


class SurvivingARestart(StoreTestCase):

	def test_a_new_process_finds_what_the_last_one_stored(self):
		self.store().put('1', 1, layout('a'), layout_only = True)
		reopened = self.store()
		self.assertEqual(reopened.status('1', 1), 'layout')
		self.assertEqual(reopened.get('1', 1)[0], layout('a'))

	def test_a_write_killed_before_its_metadata_leaves_nothing(self):
		store = self.store()
		store.put('1', 1, layout('a'), layout_only = True)
		for name in self.files():
			if name.endswith(render_store.META_SUFFIX):
				os.remove(os.path.join(self.directory, name))
		reopened = self.store()
		self.assertIsNone(reopened.status('1', 1))
		self.assertEqual(self.files(), [])

	def test_a_temporary_file_from_an_interrupted_write_is_removed(self):
		with open(os.path.join(self.directory, 'abc.json.tmp'), 'wb') as handle:
			handle.write(b'{')
		self.store()
		self.assertEqual(self.files(), [])

	def test_corrupt_metadata_is_dropped_rather_than_trusted(self):
		store = self.store()
		store.put('1', 1, layout('a'), layout_only = True)
		for name in self.files():
			if name.endswith(render_store.META_SUFFIX):
				with open(os.path.join(self.directory, name), 'w') as handle:
					handle.write('not json')
		self.assertIsNone(self.store().status('1', 1))

	def test_eviction_order_continues_after_a_restart(self):
		# The sequence is persisted, so "oldest" still means oldest
		first = self.store()
		first.put('old', 1, layout('a' * 400), layout_only = True)
		second = render_store.RenderStore(self.directory, max_bytes = 10 ** 9)
		second.put('new', 1, layout('b' * 400), layout_only = True)
		second.max_bytes = second.index['new']['bytes'] + 10
		second._evict(keep = None)
		self.assertIsNone(second.status('old', 1))
		self.assertEqual(second.status('new', 1), 'layout')


class Housekeeping(StoreTestCase):

	def test_only_what_the_listing_still_holds_is_kept(self):
		store = self.store()
		store.put('analyzed', 1, layout('a'), layout_only = True)
		store.put('recycled', 1, layout('b'), layout_only = True)
		store.put('pending', 1, layout('c'), layout_only = True)
		store.retain({'recycled': 2, 'pending': 1})
		self.assertIsNone(store.status('analyzed', 1))
		self.assertIsNone(store.status('recycled', 2))
		self.assertEqual(store.status('pending', 1), 'layout')
		self.assertEqual(len(self.files()), 2)

	def test_the_byte_budget_evicts_the_oldest_first(self):
		one = len(render_store.json.dumps(layout('x' * 100)).encode('utf-8'))
		store = self.store(max_bytes = one * 2 + 1)
		store.put('1', 1, layout('x' * 100), layout_only = True)
		store.put('2', 1, layout('x' * 100), layout_only = True)
		store.put('3', 1, layout('x' * 100), layout_only = True)
		self.assertIsNone(store.status('1', 1))
		self.assertEqual(store.status('2', 1), 'layout')
		self.assertEqual(store.status('3', 1), 'layout')
		self.assertLessEqual(store.total_bytes(), store.max_bytes)

	def test_the_entry_just_written_is_never_the_one_evicted(self):
		store = self.store(max_bytes = 10)
		store.put('big', 1, layout('x' * 1000), layout_only = True)
		self.assertEqual(store.status('big', 1), 'layout')

	def test_discarding_an_unknown_id_is_harmless(self):
		self.store().discard('never stored')


if __name__ == '__main__':
	unittest.main()
