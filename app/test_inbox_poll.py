"""Tests for the mailbox listing envelope and the lazy body loading.

Three things are worth pinning down here.

The first is the envelope: a listing has to say how many unread messages the
mailbox holds, how many of them it actually downloaded, and which of the two
lists an entry came from. Showing a queue as if every row on it were a message
already in hand is how an analyst reads an empty preview as an empty email.

The second is the order. It is a server-side filter rather than a client-side
sort, because it decides which end of the mailbox gets downloaded whole — so
"newest first" and "oldest first" have to name the same set the interface then
shows, or the bodies end up loaded for the rows nobody is looking at.

The third is the on-demand load itself: a body fetched by /email/<uid> has to
survive the next polling tick, or the one download it was worth making is undone
a minute later.

`thephish_app` cannot be imported here (it monkeypatches the world at import
time and pulls in Flask), so the state rules are exercised through a small copy
of its state and the functions that move it, kept in step by construction: the
assertions below are about the rule, not about the wiring.

Run with:  python -m unittest test_inbox_poll   (from the app/ directory)
"""

import io
import unittest

# email_provider imports eventlet, which only exists inside the image. The
# state tests below need nothing from it, so a developer running the suite on
# a bare checkout still gets them; the envelope tests skip instead of erroring.
try:
	import email_provider
except ImportError:
	email_provider = None

# list_emails needs eventlet and libmagic, so it only imports inside the image.
# Everything below that touches it skips rather than errors on a bare checkout
try:
	import list_emails
except Exception:
	list_emails = None


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class ListingEnvelope(unittest.TestCase):

	def test_it_reports_what_was_downloaded_and_what_is_pending(self):
		listing = email_provider.listing([('1', b'a'), ('2', b'b')], 40, True)
		self.assertEqual(len(listing['messages']), 2)
		self.assertEqual(listing['total'], 40)
		self.assertTrue(listing['exact'])

	def test_a_paged_source_reports_a_lower_bound(self):
		# Graph only ever answers "there is at least one more", so the total is
		# not a count and the interface must not print it as one
		listing = email_provider.listing([('1', b'a')], 2, False)
		self.assertFalse(listing['exact'])

	def test_the_listing_carries_the_emails_it_did_not_download(self):
		# The whole point of the split: the queue shows every unread report, and
		# only the ones at the chosen end of the mailbox cost a download
		stubs = [email_provider.stub('3', 'a@b', 'hi', '', None)]
		listing = email_provider.listing([('1', b'a'), ('2', b'b')], 3, True, stubs)
		self.assertEqual(len(listing['messages']), 2)
		self.assertEqual(len(listing['stubs']), 1)

	def test_a_listing_without_stubs_still_answers_a_list(self):
		# The automatic analysis asks for none; nothing downstream should have to
		# check for None before iterating
		self.assertEqual(email_provider.listing([], 0, True)['stubs'], [])


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class Stubs(unittest.TestCase):
	"""An envelope-only entry is the same shape as a downloaded one, minus a body."""

	def test_it_is_marked_as_not_loaded(self):
		entry = email_provider.stub('7', 'a@b', 'hi', 'Mon, 1 Jan 2024 10:00:00 +0000', 1)
		self.assertFalse(entry['bodyLoaded'])

	def test_every_key_a_downloaded_email_has_is_present_and_empty(self):
		# A stub and a downloaded email have to be interchangeable everywhere
		# except the one place that checks bodyLoaded, so nothing downstream has
		# to branch on a key being absent
		entry = email_provider.stub('7', 'a@b', 'hi', '', None)
		for key in ('mailUID', 'from', 'subject', 'date', 'receivedAt', 'body', 'attachedMail', 'attachedFrom', 'email_type'):
			self.assertIn(key, entry)
		self.assertEqual(entry['body'], '')
		self.assertEqual(entry['email_type'], '')

	def test_it_is_built_from_a_raw_header_block(self):
		headers = (b'From: Alice <alice@example.com>\r\n'
			b'Subject: =?utf-8?q?relat=C3=B3rio?=\r\n'
			b'Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\n')
		entry = email_provider.stub_from_headers('12', headers)
		self.assertEqual(entry['from'], 'Alice <alice@example.com>')
		self.assertEqual(entry['subject'], 'relatório')
		self.assertEqual(entry['receivedAt'], 1704103200000)
		self.assertFalse(entry['bodyLoaded'])

	def test_an_unreadable_date_does_not_lose_the_entry(self):
		# A mail client that writes a Date header nothing can parse still gets
		# its report listed: the raw header travels on, the number does not
		entry = email_provider.stub_from_headers('12', b'From: a@b\r\nDate: yesterday\r\n\r\n')
		self.assertIsNone(entry['receivedAt'])
		self.assertEqual(entry['date'], 'yesterday')


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class Order(unittest.TestCase):

	def test_the_default_is_the_newest_first(self):
		self.assertEqual(email_provider.normalize_order(None), email_provider.ORDER_NEWEST)

	def test_an_unknown_order_falls_back_instead_of_failing(self):
		# The value reaches this from a query string, so it is attacker-shaped
		self.assertEqual(email_provider.normalize_order('sideways'), email_provider.ORDER_NEWEST)

	def test_oldest_first_is_honoured(self):
		self.assertEqual(email_provider.normalize_order('oldest'), email_provider.ORDER_OLDEST)


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class ImapOrdering(unittest.TestCase):
	"""IMAP answers ids oldest first; the newest-first queue is that reversed.

	This is the arithmetic that decides which emails are downloaded whole, so it
	is worth stating separately from the code that performs the fetch.
	"""

	def ordered(self, ids, order):
		return list(ids) if order == email_provider.ORDER_OLDEST else list(reversed(ids))

	def test_newest_first_downloads_the_last_arrivals(self):
		ordered = self.ordered([b'1', b'2', b'3', b'4'], email_provider.ORDER_NEWEST)
		self.assertEqual(ordered[:2], [b'4', b'3'])
		self.assertEqual(ordered[2:], [b'2', b'1'])

	def test_oldest_first_downloads_the_backlog(self):
		ordered = self.ordered([b'1', b'2', b'3', b'4'], email_provider.ORDER_OLDEST)
		self.assertEqual(ordered[:2], [b'1', b'2'])
		self.assertEqual(ordered[2:], [b'3', b'4'])


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class HeaderFetchParsing(unittest.TestCase):
	"""A batched FETCH answers in whatever order the server likes."""

	def test_the_sequence_numbers_are_mapped_back(self):
		data = [
			(b'7 (BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {12}', b'From: a@b\r\n'),
			b')',
			(b'3 (BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {12}', b'From: c@d\r\n'),
			b')'
		]
		parsed = email_provider._parse_header_fetch(data)
		self.assertEqual(sorted(parsed.keys()), ['3', '7'])
		self.assertEqual(parsed['3'], b'From: c@d\r\n')

	def test_a_malformed_entry_is_skipped_rather_than_raising(self):
		# One unparsable line must not cost the whole batch its envelopes
		parsed = email_provider._parse_header_fetch([b')', (b'no-number (', b'x'), None])
		self.assertEqual(parsed, {})


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class EnvelopesBeforeBodies(unittest.TestCase):
	"""The cheap half of the listing must not be hostage to the expensive half.

	Learned from a live mailbox: with 2366 unread and a generous download limit,
	the whole-operation ceiling fired partway through the body downloads and the
	envelope fetch never ran at all - so the queue fell back to a fraction of the
	mailbox and the rest was invisible, which is the exact failure this feature
	exists to remove. Envelopes cost a few batched header fetches; bodies cost
	megabytes each. The cheap, complete half goes first.
	"""

	class FakeConnection:
		def __init__(self, calls):
			self.calls = calls

		def select(self, folder):
			pass

		def search(self, charset, criteria):
			return 'OK', [b'1 2 3 4']

		def fetch(self, ids, spec):
			# A real batched header FETCH answers one (prefix, payload) tuple per
			# message, with a closing b')' between them
			if 'HEADER.FIELDS' in spec:
				self.calls.append('headers')
				answer = []
				for num in ids.split(b','):
					answer.append((num + b' (BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {20}',
						b'From: a@b\r\nDate: \r\n\r\n'))
					answer.append(b')')
				return 'OK', answer
			self.calls.append('body')
			return 'OK', [(ids + b' (RFC822 {14}', b'From: a@b\r\n\r\nhi')]

		def store(self, *args):
			pass

	def listing_calls(self, limit):
		calls = []
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		provider._with_connection = lambda func, on_timeout = None: func(self.FakeConnection(calls))
		provider.list_unread(all_unread = True, limit = limit)
		return calls

	def listing_result(self, limit):
		calls = []
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		provider._with_connection = lambda func, on_timeout = None: func(self.FakeConnection(calls))
		return provider.list_unread(all_unread = True, limit = limit)

	def test_the_headers_are_fetched_before_any_body(self):
		# Limit of one, so the two downloaded ends leave a middle to enumerate
		calls = self.listing_calls(1)
		self.assertIn('headers', calls)
		self.assertIn('body', calls)
		self.assertLess(calls.index('headers'), calls.index('body'))

	def test_nothing_is_listed_from_envelopes_when_everything_is_downloaded(self):
		# limit covers the whole mailbox: there is no middle to describe, and
		# asking the server for it would be a round trip for an empty answer
		self.assertNotIn('headers', self.listing_calls(10))


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class BothEndsAreDownloaded(unittest.TestCase):
	"""The filter reverses a list the browser already has, so both ends need bodies.

	Downloading only the front meant that flipping to the other order put the
	analyst on a screenful of rows with nothing behind them - every one of which
	would then have to be fetched on click. Paying for one more `limit` on a
	listing that is already reading the whole mailbox's envelopes is what makes
	the switch free.
	"""

	def listing_of(self, ids, limit, order = None):
		calls = []
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')

		class Connection(EnvelopesBeforeBodies.FakeConnection):
			def search(self, charset, criteria):
				return 'OK', [b' '.join(ids)]

		provider._with_connection = lambda func, on_timeout = None: func(Connection(calls))
		kwargs = {'all_unread': True, 'limit': limit}
		if order is not None:
			kwargs['order'] = order
		return provider.list_unread(**kwargs)

	def test_the_far_end_is_downloaded_too(self):
		result = self.listing_of([b'1', b'2', b'3', b'4', b'5', b'6'], 2)
		# newest first: ids 6,5 at the front and 2,1 at the back, 4 and 3 listed
		self.assertEqual([uid for uid, _ in result['messages']], ['6', '5', '2', '1'])
		self.assertEqual(result['head'], 2)
		self.assertEqual([stub['mailUID'] for stub in result['stubs']], ['4', '3'])

	def test_the_far_end_follows_the_requested_direction(self):
		result = self.listing_of([b'1', b'2', b'3', b'4', b'5', b'6'], 2,
			order = email_provider.ORDER_OLDEST)
		self.assertEqual([uid for uid, _ in result['messages']], ['1', '2', '5', '6'])
		self.assertEqual([stub['mailUID'] for stub in result['stubs']], ['3', '4'])

	def test_the_two_ends_never_overlap(self):
		# Five messages, limit of three: the ends would otherwise both claim the
		# middle one and it would be downloaded - and listed - twice
		result = self.listing_of([b'1', b'2', b'3', b'4', b'5'], 3)
		uids = [uid for uid, _ in result['messages']]
		self.assertEqual(len(uids), len(set(uids)))
		self.assertEqual(sorted(uids), ['1', '2', '3', '4', '5'])
		self.assertEqual(result['stubs'], [])

	def test_head_says_where_the_front_of_the_listing_ends(self):
		# list_emails puts the stubs between the two halves using this number;
		# getting it wrong would scatter the envelopes through the queue
		result = self.listing_of([b'1', b'2', b'3', b'4', b'5', b'6'], 1)
		self.assertEqual(result['head'], 1)
		self.assertEqual(result['messages'][0][0], '6')
		self.assertEqual(result['messages'][1][0], '1')

	def test_the_automatic_analysis_still_gets_one_end_only(self):
		# It analyzes what it downloads and reads no stubs, so a second end would
		# be bodies pulled for a list nothing looks at
		calls = []
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		provider._with_connection = lambda func, on_timeout = None: func(
			EnvelopesBeforeBodies.FakeConnection(calls))
		result = provider.list_unread(limit = 2, include_stubs = False)
		self.assertEqual(len(result['messages']), 2)
		self.assertEqual(result['stubs'], [])
		self.assertNotIn('headers', calls)


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class BodiesAlreadyInHandAreNotDownloadedAgain(unittest.TestCase):
	"""A polling cycle must not re-buy what it already owns.

	Found on a live Gmail mailbox. The cycle pulled the full body of `maxEmails`
	messages at each end every interval, whether or not anything had changed:
	4.4 MB a minute, 6.3 GB a day, against the 2.5 GB a day Gmail allows an
	account over IMAP. Past that limit Gmail accepts the TCP connection and
	closes it before the greeting, which surfaces as `socket error: EOF` raised
	from inside imaplib's constructor - three frames and no mention of a quota
	away from the thing that actually went wrong.

	So the caller says what it is still holding, and the listing describes those
	from their envelope instead of downloading them again. They stay in the queue
	and in their place: the caller lays its own copy back over the envelope.
	"""

	class Connection(EnvelopesBeforeBodies.FakeConnection):
		def __init__(self, calls, ids):
			EnvelopesBeforeBodies.FakeConnection.__init__(self, calls)
			self.ids = ids
			self.downloaded = []
			self.stored = []

		def search(self, charset, criteria):
			return 'OK', [b' '.join(self.ids)]

		def fetch(self, ids, spec):
			if 'HEADER.FIELDS' not in spec:
				self.downloaded.extend(num.decode() for num in ids.split(b','))
			return EnvelopesBeforeBodies.FakeConnection.fetch(self, ids, spec)

		def store(self, *args):
			self.stored.append(args)

	def listing_of(self, ids, limit, have = None):
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		connection = self.Connection([], [item.encode() for item in ids])
		provider._with_connection = lambda func, on_timeout = None: func(connection)
		result = provider.list_unread(all_unread = True, limit = limit, have = have)
		return result, connection

	def test_a_body_the_caller_still_holds_is_not_fetched(self):
		# Newest first: 6 and 5 at the front, 2 and 1 at the back. 6 and 1 are
		# already in hand, so only 5 and 2 cost a download
		result, connection = self.listing_of(
			['1', '2', '3', '4', '5', '6'], 2, have = {'6', '1'})
		self.assertEqual(sorted(connection.downloaded), ['2', '5'])
		self.assertEqual(sorted(uid for uid, _ in result['messages']), ['2', '5'])

	def test_a_body_it_does_not_hold_is_still_fetched(self):
		result, connection = self.listing_of(['1', '2', '3', '4', '5', '6'], 2, have = {'4'})
		# 4 is in the middle: it was never going to be downloaded, and saying it
		# is held must not stop the two ends from being
		self.assertEqual(sorted(connection.downloaded), ['1', '2', '5', '6'])

	def test_the_message_it_skipped_is_still_listed(self):
		# Skipping the download must not drop the row: the queue would lose a
		# report every cycle, and the count on screen would drift from the mailbox
		result, _ = self.listing_of(['1', '2', '3', '4', '5', '6'], 2, have = {'6'})
		self.assertIn('6', [stub['mailUID'] for stub in result['stubs']])
		self.assertEqual(len(result['messages']) + len(result['stubs']), 6)

	def test_the_listing_says_what_order_it_listed_in(self):
		# Without this the caller has no way to put the skipped message back in
		# its place - the ends and the middle no longer line up with the lists
		result, _ = self.listing_of(['1', '2', '3', '4', '5', '6'], 2, have = {'6'})
		self.assertEqual(result['ids'], ['6', '5', '4', '3', '2', '1'])

	def test_the_head_count_covers_only_what_was_downloaded(self):
		result, _ = self.listing_of(['1', '2', '3', '4', '5', '6'], 2, have = {'6'})
		self.assertEqual(result['head'], 1)
		self.assertEqual(result['messages'][0][0], '5')

	def test_holding_everything_costs_no_body_fetch_at_all(self):
		result, connection = self.listing_of(
			['1', '2', '3', '4', '5', '6'], 2, have = {'1', '2', '5', '6'})
		self.assertEqual(connection.downloaded, [])
		self.assertEqual(result['messages'], [])
		self.assertEqual(len(result['stubs']), 6)

	def test_nothing_is_skipped_when_the_caller_holds_nothing(self):
		result, connection = self.listing_of(['1', '2', '3', '4', '5', '6'], 2)
		self.assertEqual(sorted(connection.downloaded), ['1', '2', '5', '6'])

	def test_the_body_fetch_leaves_the_message_unread_without_a_second_round_trip(self):
		# RFC822 sets \Seen, so this used to STORE the flag back off on every
		# message: a second round trip per body, and a window in which a crash
		# left a message the analyst never saw out of the UNSEEN search - out of
		# the queue for good. BODY.PEEK[] returns the same bytes and sets nothing
		_, connection = self.listing_of(['1', '2'], 2)
		self.assertEqual(connection.stored, [])

	def test_the_automatic_analysis_is_unaffected(self):
		# It downloads in order to analyze, and its caller never says it holds
		# anything; a listing without `have` must behave exactly as before
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		connection = self.Connection([], [b'1', b'2', b'3', b'4'])
		provider._with_connection = lambda func, on_timeout = None: func(connection)
		result = provider.list_unread(limit = 2, include_stubs = False)
		self.assertEqual(len(result['messages']), 2)
		self.assertEqual(result['stubs'], [])

	def test_a_caller_that_takes_no_envelopes_never_skips_a_body(self):
		# Skipping is only safe because the message comes back as an envelope
		# instead. Honouring `have` for a caller that reads no envelopes would
		# hand the automatic analysis a listing with the message simply missing
		provider = email_provider.ImapProvider('imap.example.com', 993, 'u', 'p', 'basic', 'inbox')
		connection = self.Connection([], [b'1', b'2', b'3', b'4'])
		provider._with_connection = lambda func, on_timeout = None: func(connection)
		result = provider.list_unread(limit = 2, include_stubs = False, have = {'4', '3'})
		self.assertEqual(sorted(uid for uid, _ in result['messages']), ['3', '4'])
		self.assertEqual(result['stubs'], [])


@unittest.skipIf(list_emails is None, 'list_emails only imports inside the image')
class QueueAssembly(unittest.TestCase):
	"""Where each listed email lands once an end can be part envelope."""

	def assemble(self, head, stubs, tail, ids):
		return list_emails.assemble_queue(head, stubs, tail, ids)

	def entries(self, *uids):
		return [{'mailUID': uid} for uid in uids]

	def test_a_skipped_body_keeps_its_place_at_the_front(self):
		# '6' was downloaded on an earlier cycle, so it arrives as a stub. Filing
		# it with the envelopes would move the newest report to the middle of the
		# queue - on a screen the analyst had just been reading top-down
		queue = self.assemble(self.entries('5'), self.entries('6', '4', '3'),
			self.entries('2', '1'), ['6', '5', '4', '3', '2', '1'])
		self.assertEqual([entry['mailUID'] for entry in queue],
			['6', '5', '4', '3', '2', '1'])

	def test_a_malformed_message_is_left_out_rather_than_faked(self):
		# The parse skips a message it cannot read; the id still comes back in the
		# order. Inventing a row for it would put an entry with no sender, no
		# subject and no body on an analyst's queue
		queue = self.assemble(self.entries('5'), self.entries('4'), [], ['6', '5', '4'])
		self.assertEqual([entry['mailUID'] for entry in queue], ['5', '4'])

	def test_a_provider_that_names_no_order_falls_back_to_the_three_lists(self):
		queue = self.assemble(self.entries('6', '5'), self.entries('4', '3'),
			self.entries('2', '1'), None)
		self.assertEqual([entry['mailUID'] for entry in queue],
			['6', '5', '4', '3', '2', '1'])


class DisplayOrder(unittest.TestCase):
	"""What the interface does with the two directions.

	The server says which way it built the listing; the analyst says which way
	they want to read it. The displayed queue is one or the other, and neither
	value is allowed to overwrite the other - that overwrite is what made a
	click on the filter snap back whenever a polling tick landed on top of it.
	"""

	def display(self, queue, queue_order, inbox_order):
		return queue if inbox_order == queue_order else list(reversed(queue))

	def test_matching_directions_show_the_listing_as_sent(self):
		self.assertEqual(self.display(['a', 'b', 'c'], 'newest', 'newest'), ['a', 'b', 'c'])

	def test_opposite_directions_reverse_it(self):
		self.assertEqual(self.display(['a', 'b', 'c'], 'newest', 'oldest'), ['c', 'b', 'a'])

	def test_a_listing_built_the_other_way_needs_no_reversal(self):
		# The configured direction can change under the interface; what decides
		# is the direction of the listing in hand, not the setting
		self.assertEqual(self.display(['a', 'b', 'c'], 'oldest', 'oldest'), ['a', 'b', 'c'])

	def test_the_far_end_of_a_reversed_queue_is_a_downloaded_one(self):
		# Both ends carry bodies, so whichever way it is read the top rows are
		# ready - this is the property that lets the reversal be instant
		queue = [{'bodyLoaded': True}, {'bodyLoaded': False}, {'bodyLoaded': True}]
		for order in ('newest', 'oldest'):
			self.assertTrue(self.display(queue, 'newest', order)[0]['bodyLoaded'])


class ListingState(unittest.TestCase):
	"""The rules the polling state applies, in isolation from Flask and eventlet."""

	def setUp(self):
		self.state = {'maxEmails': 2, 'emails': [], 'count': 0, 'loaded': 0, 'total': 0}
		self.hydrated = {}

	def record(self, emails, total):
		present = set()
		for index, mail in enumerate(emails):
			present.add(mail['mailUID'])
			if not mail.get('bodyLoaded') and mail['mailUID'] in self.hydrated:
				emails[index] = self.hydrated[mail['mailUID']]
		for uid in [uid for uid in list(self.hydrated) if uid not in present]:
			del self.hydrated[uid]
		# Every body this listing carries is kept, not only the ones an analyst
		# clicked for: this cache is what the next cycle sends as `have`, and
		# what it does not hold is what the mail server is asked for again
		for mail in emails:
			if mail.get('bodyLoaded'):
				self.hydrated[mail['mailUID']] = mail
		self.state['emails'] = emails
		self.state['count'] = len(emails)
		self.state['loaded'] = len([mail for mail in emails if mail.get('bodyLoaded')])
		self.state['total'] = total

	def remember(self, uid, entry):
		self.hydrated[uid] = entry
		for index, mail in enumerate(self.state['emails']):
			if mail['mailUID'] == uid:
				self.state['emails'][index] = entry
				break
		self.state['loaded'] = len([mail for mail in self.state['emails'] if mail.get('bodyLoaded')])

	def release(self, uid):
		remaining = [mail for mail in self.state['emails'] if mail['mailUID'] != uid]
		if len(remaining) == len(self.state['emails']):
			return
		self.hydrated.pop(uid, None)
		self.state['emails'] = remaining
		self.state['count'] = len(remaining)
		self.state['loaded'] = len([mail for mail in remaining if mail.get('bodyLoaded')])
		self.state['total'] = max(0, self.state['total'] - 1)

	def listing(self, loaded, deferred):
		return ([{'mailUID': uid, 'bodyLoaded': True, 'body': 'x'} for uid in loaded]
			+ [{'mailUID': uid, 'bodyLoaded': False, 'body': ''} for uid in deferred])

	def test_the_whole_mailbox_is_listed_even_past_the_download_limit(self):
		self.record(self.listing(['1', '2'], ['3', '4', '5']), 5)
		self.assertEqual(self.state['count'], 5)
		self.assertEqual(self.state['loaded'], 2)

	def test_a_body_loaded_on_demand_survives_the_next_tick(self):
		# Otherwise the one download it was worth making is undone a minute later
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.remember('3', {'mailUID': '3', 'bodyLoaded': True, 'body': 'loaded'})
		self.assertEqual(self.state['loaded'], 3)
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.assertEqual(self.state['emails'][2]['body'], 'loaded')
		self.assertEqual(self.state['loaded'], 3)

	def test_a_body_the_listing_downloaded_is_kept_for_the_next_cycle(self):
		# This cache is what travels back to the provider as `have`. If only the
		# on-demand loads went into it, every cycle would re-download both ends of
		# the mailbox - which is the 6.3 GB a day that got the account cut off
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.assertEqual(sorted(self.hydrated), ['1', '2'])

	def test_a_body_that_came_back_as_an_envelope_is_laid_back_over_it(self):
		# The cycle after the one above: 1 and 2 were not downloaded again, so
		# they arrive as envelopes and the held copies go back on top. Without
		# this the queue would empty its own bodies out one tick after filling them
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.record(self.listing([], ['1', '2', '3']), 3)
		self.assertEqual(self.state['loaded'], 2)
		self.assertEqual([mail['mailUID'] for mail in self.state['emails'] if mail['bodyLoaded']],
			['1', '2'])

	def test_an_email_that_left_the_mailbox_leaves_the_cache_with_it(self):
		self.record(self.listing(['1'], ['3']), 2)
		self.remember('3', {'mailUID': '3', 'bodyLoaded': True, 'body': 'loaded'})
		self.record(self.listing(['1'], []), 1)
		# '1' is still in the mailbox and still held on purpose; what has to be
		# gone is '3', which is not there any more
		self.assertNotIn('3', self.hydrated)

	def test_analyzing_an_email_takes_it_out_of_the_queue(self):
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.release('2')
		self.assertEqual(self.state['count'], 2)
		self.assertEqual(self.state['total'], 2)
		self.assertEqual(self.state['loaded'], 1)

	def test_analyzing_an_email_drops_its_loaded_body(self):
		self.record(self.listing(['1'], ['3']), 2)
		self.remember('3', {'mailUID': '3', 'bodyLoaded': True, 'body': 'loaded'})
		self.release('3')
		self.assertNotIn('3', self.hydrated)
		self.assertEqual(self.state['loaded'], 1)

	def test_analyzing_an_email_that_is_not_in_the_queue_changes_nothing(self):
		self.record(self.listing(['1', '2'], ['3']), 3)
		self.release('99')
		self.assertEqual(self.state['count'], 3)
		self.assertEqual(self.state['total'], 3)

	def test_the_total_never_goes_negative(self):
		self.record(self.listing(['1'], []), 1)
		self.release('1')
		self.release('1')
		self.assertEqual(self.state['total'], 0)

	def test_a_backlog_larger_than_the_listing_is_still_reported(self):
		# The envelope backstop is the only truncation left, and the interface
		# has to be able to say it happened
		self.record(self.listing(['1', '2'], ['3']), 900)
		self.assertEqual(self.state['count'], 3)
		self.assertEqual(self.state['total'], 900)


@unittest.skipIf(email_provider is None, 'eventlet is not installed outside the image')
class HeaderDecoding(unittest.TestCase):
	"""A header is read whole, or the analyst reads something that is not there.

	`list_emails` used to take only the last encoded-word of From and Subject
	(`decode_header(...)[-1]`). Everything before it was dropped in silence, and
	the fragments an attacker controls are exactly the ones that carry meaning:
	the display name, and a prefix like "[EXTERNAL]". These pin the decoder both
	call sites now share.
	"""

	def test_a_display_name_survives_the_address_that_follows_it(self):
		# Two fragments: the encoded name, then the plain " <addr>". Taking the
		# last one lost the name - and, because that fragment arrives as bytes
		# with no charset, str() over it printed the literal b'...' repr
		decoded = email_provider.decode_header_field(
			'=?UTF-8?B?Sm/Do28gU2lsdmE=?= <vitima@empresa.example>')
		self.assertEqual(decoded, 'João Silva <vitima@empresa.example>')
		self.assertNotIn("b'", decoded)

	def test_a_plain_prefix_before_an_encoded_word_is_kept(self):
		# The banner a mail gateway stamps on external mail is a plain-ASCII
		# fragment
		# that precedes the encoded subject. Losing it hides, from the analyst,
		# the single word saying the message came from outside
		self.assertEqual(
			email_provider.decode_header_field('[EXTERNAL] =?UTF-8?B?RGVuw7puY2lh?='),
			'[EXTERNAL] Denúncia')

	def test_a_charset_that_does_not_exist_does_not_raise(self):
		# The attacker writes this header. Raising here dropped the whole report
		# from the queue, with one line in the log and nothing on screen
		self.assertEqual(
			email_provider.decode_header_field('=?charset-que-nao-existe?B?QcOnw6Nv?='),
			'Ação')

	def test_an_absent_header_reads_as_empty_rather_than_raising(self):
		self.assertEqual(email_provider.decode_header_field(None), '')

	def test_list_emails_decodes_through_the_shared_helper(self):
		# The four above pin the decoder; this one pins the call sites, which is
		# where the bug actually lived. It has to read the source instead of
		# calling the function: list_emails imports eventlet and libmagic, so it
		# cannot be imported on a bare checkout - which is also why the defect
		# survived so long with a green suite
		import os
		source = io.open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
			'list_emails.py'), encoding = 'utf-8').read()
		# assertFalse rather than assertNotIn: the latter prints the haystack,
		# and the haystack here is the whole module
		self.assertFalse('decode_header(' in source,
			'list_emails must decode headers through email_provider.decode_header_field: '
			'a local decode_header() call is how the [-1] truncation came back')


if __name__ == '__main__':
	unittest.main()
