"""Tests for the inbox pages and for what the background loader reads next.

These rules decide which report an analyst finds ready when they land on a page,
and nothing in them needs eventlet, libmagic or a mailbox — so they run on a bare
checkout, which the modules around them cannot.

Run with:  python -m unittest test_inbox_pages   (from the app/ directory)
"""

import unittest

import inbox_pages


def uids(count):
	# Listing order: index 0 is one end of the mailbox, the last index the other
	return [str(number) for number in range(1, count + 1)]


class PageSize(unittest.TestCase):

	def test_an_allowed_size_is_kept(self):
		for size in inbox_pages.PAGE_SIZES:
			self.assertEqual(inbox_pages.normalize_page_size(size), size)

	def test_it_is_read_from_the_configuration_as_text_too(self):
		self.assertEqual(inbox_pages.normalize_page_size('40'), 40)

	def test_a_size_outside_the_set_falls_back_to_the_default(self):
		self.assertEqual(inbox_pages.normalize_page_size(35), inbox_pages.DEFAULT_PAGE_SIZE)
		self.assertEqual(inbox_pages.normalize_page_size(None), inbox_pages.DEFAULT_PAGE_SIZE)
		self.assertEqual(inbox_pages.normalize_page_size('many'), inbox_pages.DEFAULT_PAGE_SIZE)

	def test_the_old_setting_is_carried_over_to_the_closest_size(self):
		# An installation tuned maxEmails and never saw pageSize: what it chose
		# survives the upgrade instead of silently becoming the default
		self.assertEqual(inbox_pages.normalize_page_size(None, legacy = 30), 30)
		self.assertEqual(inbox_pages.normalize_page_size(None, legacy = 200), 50)
		self.assertEqual(inbox_pages.normalize_page_size(None, legacy = 1), 20)
		self.assertEqual(inbox_pages.normalize_page_size(None, legacy = 44), 40)

	def test_the_new_setting_wins_over_the_old_one(self):
		self.assertEqual(inbox_pages.normalize_page_size(20, legacy = 200), 20)

	def test_the_largest_page_is_a_batch_the_scan_accepts(self):
		# "Select every row on this page" must always be something
		# POST /analysis-selected will run, and it refuses more than 50
		self.assertLessEqual(max(inbox_pages.PAGE_SIZES), 50)


class PagePlan(unittest.TestCase):

	def test_it_alternates_the_two_ends_page_by_page(self):
		plan = inbox_pages.page_plan(uids(12), 3)
		self.assertEqual([(end, number) for end, number, _ in plan], [
			('front', 1), ('back', 1),
			('front', 2), ('back', 2)
		])

	def test_the_first_page_at_each_end_is_what_each_filter_shows_first(self):
		plan = inbox_pages.page_plan(uids(12), 3)
		self.assertEqual(plan[0][2], ['1', '2', '3'])
		# The back end in the order "Mais antigos" displays it: the last listed first
		self.assertEqual(plan[1][2], ['12', '11', '10'])

	def test_every_message_is_planned_exactly_once(self):
		for count in (1, 5, 29, 30, 31, 61, 100):
			for size in inbox_pages.PAGE_SIZES:
				planned = [uid for _, _, page in inbox_pages.page_plan(uids(count), size) for uid in page]
				self.assertEqual(sorted(planned, key = int), uids(count), (count, size))

	def test_when_the_ends_meet_the_second_page_keeps_only_what_is_left(self):
		# Seven messages, pages of three: the middle one would otherwise be
		# downloaded twice, against the provider's daily budget
		plan = inbox_pages.page_plan(uids(7), 3)
		self.assertEqual(plan[0][2], ['1', '2', '3'])
		self.assertEqual(plan[1][2], ['7', '6', '5'])
		self.assertEqual(plan[2][2], ['4'])
		self.assertEqual(len(plan), 3)

	def test_an_empty_queue_has_no_pages(self):
		self.assertEqual(inbox_pages.page_plan([], 30), [])


class NextBatch(unittest.TestCase):

	def test_it_starts_on_the_first_page_of_the_newest_end(self):
		end, number, batch = inbox_pages.next_batch(uids(100), 20, ready = set(), limit = 10)
		self.assertEqual((end, number), ('front', 1))
		self.assertEqual(batch, uids(10))

	def test_it_finishes_a_page_before_the_other_end(self):
		end, number, batch = inbox_pages.next_batch(uids(100), 20, ready = set(uids(10)), limit = 10)
		self.assertEqual((end, number), ('front', 1))
		self.assertEqual(batch, [str(n) for n in range(11, 21)])

	def test_then_the_oldest_end_gets_its_first_page(self):
		end, number, batch = inbox_pages.next_batch(uids(100), 20, ready = set(uids(20)), limit = 10)
		self.assertEqual((end, number), ('back', 1))
		self.assertEqual(batch, [str(n) for n in range(100, 90, -1)])

	def test_a_message_that_could_not_be_read_does_not_pin_the_loader(self):
		skip = set(uids(20))
		end, number, _ = inbox_pages.next_batch(uids(100), 20, ready = set(), skip = skip)
		self.assertEqual((end, number), ('back', 1))

	def test_a_new_arrival_puts_page_one_back_at_the_head_of_the_line(self):
		# The loader was deep in the mailbox; one report lands at the top
		listing = uids(200)
		ready = set(listing[:180])
		arrived = ['new'] + listing
		_, number, batch = inbox_pages.next_batch(arrived, 20, ready = ready)
		self.assertEqual(number, 1)
		self.assertEqual(batch, ['new'])

	def test_nothing_left_is_none(self):
		self.assertIsNone(inbox_pages.next_batch(uids(50), 20, ready = set(uids(50))))
		self.assertIsNone(inbox_pages.next_batch([], 20, ready = set()))


class Progress(unittest.TestCase):

	def test_it_counts_only_what_is_still_listed(self):
		# A body kept for an email that has since been analyzed is not progress
		self.assertEqual(inbox_pages.progress(['1', '2', '3'], {'2', '3', 'gone'}),
			{'ready': 2, 'total': 3})


class PushEnvelope(unittest.TestCase):

	def test_a_long_body_travels_as_a_snippet(self):
		mail = {'mailUID': '1', 'body': 'x' * 5000, 'bodyLoaded': True}
		entry = inbox_pages.envelope_for_push(mail, snippet_chars = 100)
		self.assertEqual(len(entry['body']), 100)
		self.assertTrue(entry['bodyTruncated'])

	def test_the_server_copy_is_not_touched(self):
		mail = {'mailUID': '1', 'body': 'x' * 5000, 'bodyLoaded': True}
		inbox_pages.envelope_for_push(mail, snippet_chars = 100)
		self.assertEqual(len(mail['body']), 5000)
		self.assertNotIn('bodyTruncated', mail)

	def test_a_short_body_and_an_envelope_travel_whole(self):
		self.assertFalse(inbox_pages.envelope_for_push({'body': 'hi'})['bodyTruncated'])
		stub = inbox_pages.envelope_for_push({'body': '', 'bodyLoaded': False})
		self.assertFalse(stub['bodyTruncated'])
		self.assertFalse(stub['bodyLoaded'])


if __name__ == '__main__':
	unittest.main()
