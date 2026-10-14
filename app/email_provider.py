import datetime
import email
import email.header
import email.utils
import imaplib
import logging
import re
import eventlet
import m365_auth
import graph_mail

log = logging.getLogger(__name__)

# Overall time budget (in seconds) for a whole IMAP operation: connect, login,
# select, search, and - for list_unread() - fetching up to IMAP_MAX_MESSAGES
# full messages in a loop. imaplib.IMAP4_SSL's constructor performs the TCP
# connect and TLS handshake with no timeout of its own on Python 3.8 (the
# runtime used by this image), so a socket-level timeout set after the fact
# would not cover a stall during connection. eventlet.Timeout instead bounds
# the whole call regardless of which blocking operation it is stuck in (the
# app already runs eventlet-monkeypatched, so this raises inside the greenlet
# like a normal exception). This is a backstop against a fully stuck
# connection: IMAP_FETCH_TIMEOUT and IMAP_HEADER_TIMEOUT below are what
# actually protect a listing from a single slow message or header batch, so
# this can afford to be generous. When it does fire, list_unread() answers with
# whatever it had rather than nothing: a partial queue is still a queue.
IMAP_TIMEOUT = 240

# Per-message budget (in seconds) for a single fetch inside list_unread()'s
# batch loop. A single slow or oversized message (a large attachment, or in
# "raw" analysis mode a newsletter with several MB of embedded images) must
# not consume the whole batch's time budget and cost every other message in
# it: that single message is skipped (logged, retried on the next cycle or
# "List emails" click) instead of aborting the entire call.
IMAP_FETCH_TIMEOUT = 20

# Default number of unread emails whose full RFC822 body list_unread() downloads
# in a single call, used when the caller names no limit of its own.
#
# This is no longer a ceiling on the listing: every unread email is enumerated
# (see ENVELOPE_MAX_MESSAGES), but only the first IMAP_MAX_MESSAGES in the
# requested order are downloaded whole. The rest are listed from their envelope
# alone and their body is fetched by peek() the moment an analyst opens one.
# Downloading the full body of every unread message is what did not scale to a
# regular inbox with thousands of unread emails; enumerating them does.
IMAP_MAX_MESSAGES = 50

# Backstop on how many envelopes a single listing enumerates. Enumerating is
# cheap (one batched header FETCH per IMAP_HEADER_BATCH messages, or one Graph
# page per 100), but it is not free, and a listing has to fit in memory and in
# a websocket frame. A mailbox with more unread messages than this reports the
# overflow through the listing envelope (`total`/`exact`) instead of silently
# pretending the queue ends here.
ENVELOPE_MAX_MESSAGES = 5000

# How many message ids go into a single batched header FETCH. IMAP takes a
# sequence set, so the envelopes of a whole inbox cost a handful of round trips
# rather than one per message.
IMAP_HEADER_BATCH = 250

# Per-batch budget (in seconds) for one of those header fetches. Headers are
# small, so a batch that does not come back in this time is a stalled
# connection, not a slow message.
IMAP_HEADER_TIMEOUT = 30

# Which end of the mailbox the listing starts from. The order decides both what
# the analyst sees first and which messages are the ones downloaded whole, so it
# travels with the request rather than being applied on the client.
ORDER_NEWEST = 'newest'
ORDER_OLDEST = 'oldest'


def normalize_order(order):
	"""The requested order, or the default when it is missing or unknown."""
	return ORDER_OLDEST if order == ORDER_OLDEST else ORDER_NEWEST


# Decode a possibly RFC2047-encoded header value into a readable string.
# Lives here rather than in list_emails because the providers build the
# envelope-only entries themselves, and list_emails imports this module (not the
# other way round)
def decode_header_field(raw_value):
	if raw_value is None:
		return ''
	return ''.join(_decode_fragment(data, charset) for data, charset in email.header.decode_header(raw_value))


# Um pedaço de cabeçalho vira texto. Com charset declarado ele é usado; se o
# charset não existe ou os bytes não batem com ele, nada se perde: os bytes saem
# como UTF-8 com os caracteres inválidos trocados. Sem charset, o pedaço já é texto
# ou são bytes puros, tratados do mesmo jeito
def _decode_fragment(data, charset):
	if charset is not None:
		try:
			return data.decode(charset)
		except (LookupError, UnicodeDecodeError):
			return data.decode(errors = 'replace')
	if isinstance(data, str):
		return data
	return data.decode(errors = 'replace')


def received_at(raw_date):
	"""The Date header as epoch milliseconds, or None when it cannot be read.

	The header itself keeps travelling in `date`, but it arrives in whatever
	format and timezone the reporter's mail client wrote it, which is why the
	listing used to show only a day. This is the same instant as a number, so the
	interface can show the analyst the hour the report came in - in their own
	timezone - instead of asking them to parse "+0530" by eye.
	"""
	if not raw_date:
		return None
	try:
		parsed = email.utils.parsedate_to_datetime(raw_date)
	except Exception:
		return None
	if parsed is None:
		return None
	try:
		# A Date header with no timezone is read as local time, which is the best
		# available reading of it: nothing in the message says otherwise
		return int(parsed.timestamp() * 1000)
	except Exception:
		return None


def stub(mail_uid, from_field, subject_field, date_field, received):
	"""A listing entry built from the envelope alone, with no body behind it.

	`bodyLoaded` is what tells the rest of the application - and the interface -
	that this entry is a promise rather than a message: the body, the attached
	report and the email type are only known once peek() has downloaded it. The
	keys are all present and empty on purpose, so that a stub and a downloaded
	email are the same shape and nothing downstream has to branch on absence.
	"""
	return {
		'mailUID': mail_uid,
		'from': from_field or '',
		'subject': subject_field or '',
		'date': date_field or '',
		'receivedAt': received,
		'body': '',
		'attachedMail': '',
		'attachedFrom': '',
		'email_type': '',
		'bodyLoaded': False
	}


def stub_from_headers(mail_uid, raw_headers):
	"""Build a stub out of the raw header block returned by a header FETCH."""
	message = email.message_from_bytes(raw_headers)
	return stub(
		mail_uid,
		decode_header_field(message['From']),
		decode_header_field(message['Subject']),
		message['Date'] or '',
		received_at(message['Date'])
	)

# Provider abstraction used by list_emails and case_from_email to obtain the
# raw RFC822 messages, so that the parsing logic is independent from the way
# the mailbox is accessed (Microsoft Graph API or IMAP)
#
# Every provider exposes:
# - describe():    human readable description used for logging
# - list_unread(): the unread emails, without marking them as read, as the
#                  listing dict below
# - peek(uid):     raw MIME bytes of a single email WITHOUT marking it as read,
#                  used to load the body of a listed email on demand
# - fetch(uid):    raw MIME bytes of a single email, marking it as read, or
#                  None when the email has already been read/analyzed


def listing(messages, total, exact, stubs = None, head = None, ids = None):
	"""What list_unread() answers.

	`messages` is what was downloaded whole, bounded by the caller's limit. When
	the listing is for an analyst it covers BOTH ends of the mailbox - the first
	`head` entries belong at the front, the rest at the back - so that switching
	the order filter is a reversal the interface can do on the spot instead of a
	minute-long round trip. `stubs` is every unread message between those two
	ends, described by its envelope alone: it is listed on screen straight away
	and its body is fetched by peek() when — and only when — somebody opens it. Splitting
	the listing this way is what lets the queue show a whole mailbox without
	paying to download a whole mailbox.

	`total` is how many unread messages the mailbox holds, including any past
	ENVELOPE_MAX_MESSAGES that neither list carries. `exact` says whether that
	number is the real total (IMAP answers the whole id list) or only a lower
	bound (Graph is paged, so past the backstop all that is known is that there is
	at least one more).

	`ids` is every listed message in the order the queue shows them, downloaded
	or not. It exists because "the bodies are the two ends and the stubs are the
	middle" stopped being true the moment `have` let an end skip a download it
	had already paid for: a skipped message is a stub sitting in the middle of
	the head, and slicing `messages` in two would scatter it to the far end of
	the queue. The caller assembles by this list instead of by position.
	"""
	# `head` says how many of `messages` belong at the FRONT of the listing; the
	# rest belong at the back, after the stubs
	return {
		'messages': messages,
		'total': total,
		'exact': exact,
		'stubs': stubs or [],
		'head': len(messages) if head is None else head,
		'ids': ids
	}


# Reads the mailbox through the Microsoft Graph API using an app-only token
# (OAuth 2.0 client credentials flow). Used when the provider is Microsoft 365
class GraphProvider:

	def __init__(self, tenant_id, client_id, client_secret, mailbox, folder = 'inbox'):
		self.tenant_id = tenant_id
		self.client_id = client_id
		self.client_secret = client_secret
		self.mailbox = mailbox
		self.folder = folder or 'inbox'

	def describe(self):
		return 'Microsoft Graph mailbox {0}/{1} (application authentication)'.format(self.mailbox, self.folder)

	# `all_unread` (the manual hybrid listing) changes nothing here: the Graph
	# listing always covers every unread message. `limit` is the number that is
	# downloaded whole; everything past it is listed from its envelope alone
	def list_unread(self, all_unread = False, limit = None, order = ORDER_NEWEST, include_stubs = True, have = None):
		limit = limit or IMAP_MAX_MESSAGES
		order = normalize_order(order)
		# A skipped body is only skippable because it comes back as an envelope
		# instead. A caller that takes no envelopes would simply lose the message,
		# so for that caller - the automatic analysis - `have` does not apply
		held = set(have or ()) if include_stubs else set()
		envelopes, more = graph_mail.list_unread_envelopes(
			self.tenant_id, self.client_id, self.client_secret, self.mailbox, self.folder,
			ascending = order == ORDER_OLDEST,
			max_messages = ENVELOPE_MAX_MESSAGES if include_stubs else limit)
		# Graph is paged: past the backstop all that was learned is that one more
		# id existed, so the total is a lower bound rather than a count
		total = len(envelopes) + (1 if more else 0)
		headers = graph_mail.auth_headers(self.tenant_id, self.client_id, self.client_secret)
		# Both ends are downloaded, so that flipping the order filter is a
		# reversal the interface does on the spot - see ImapProvider.list_unread
		head = envelopes[:limit]
		tail = envelopes[max(limit, len(envelopes) - limit):] if include_stubs else []
		middle = envelopes[len(head):len(envelopes) - len(tail)]
		messages = []
		skipped = []
		head_count = 0
		for index, envelope in enumerate(head + tail):
			# Already downloaded on an earlier cycle and still held by the caller:
			# it is described from its envelope and the caller puts its own copy
			# back. See ImapProvider.list_unread for why this is not an optimization
			if envelope['id'] in held:
				skipped.append(envelope)
				continue
			messages.append((envelope['id'], graph_mail.download_mime(headers, self.mailbox, envelope['id'])))
			if index < len(head):
				head_count += 1
		stubs = [_graph_stub(envelope) for envelope in skipped + middle] if include_stubs else []
		ids = [envelope['id'] for envelope in (head + middle + tail if include_stubs else head)]
		return listing(messages, total, not more, stubs, head_count, ids)

	def peek(self, mail_uid):
		return graph_mail.peek_message(self.tenant_id, self.client_id, self.client_secret, self.mailbox, mail_uid)

	def fetch(self, mail_uid):
		return graph_mail.fetch_message(self.tenant_id, self.client_id, self.client_secret, self.mailbox, mail_uid)


# Graph answers structured fields rather than a raw header block, so the stub is
# built from them directly. `receivedDateTime` is ISO 8601 in UTC, which
# email.utils cannot parse, hence the separate conversion
def _graph_stub(envelope):
	sender = ((envelope.get('from') or {}).get('emailAddress') or {})
	name = sender.get('name') or ''
	address = sender.get('address') or ''
	if name and address and name != address:
		from_field = '{0} <{1}>'.format(name, address)
	else:
		from_field = address or name
	received = envelope.get('receivedDateTime') or ''
	return stub(envelope['id'], from_field, envelope.get('subject') or '', received, _iso_to_epoch_ms(received))


def _iso_to_epoch_ms(value):
	"""An ISO 8601 timestamp as epoch milliseconds, or None when unreadable."""
	if not value:
		return None
	text = value.strip()
	# Graph writes a trailing Z and sometimes fractional seconds; datetime only
	# learned to read the first in 3.11 and never liked more than six digits of
	# the second, so both are normalized away before parsing
	text = re.sub(r'\.\d+', '', text)
	text = re.sub(r'Z$', '+0000', text)
	text = re.sub(r'([+-]\d{2}):(\d{2})$', lambda m: m.group(1) + m.group(2), text)
	for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S'):
		try:
			parsed = datetime.datetime.strptime(text, fmt)
		except ValueError:
			continue
		if parsed.tzinfo is None:
			parsed = parsed.replace(tzinfo = datetime.timezone.utc)
		return int(parsed.timestamp() * 1000)
	return None


# Reads the mailbox through IMAP. Used for Gmail (basic authentication with an
# App Password) and kept for the legacy Microsoft 365 IMAP XOAUTH2 configuration
class ImapProvider:

	def __init__(self, host, port, user, password, auth_type, folder, oauth_tenant_id = '', oauth_client_id = '', oauth_client_secret = '', analysis_mode = 'attachment'):
		self.host = host
		self.port = int(port)
		self.user = user
		self.password = password
		self.auth_type = auth_type or 'basic'
		self.folder = folder or 'inbox'
		self.oauth_tenant_id = oauth_tenant_id
		self.oauth_client_id = oauth_client_id
		self.oauth_client_secret = oauth_client_secret
		self.analysis_mode = analysis_mode or 'attachment'

	def describe(self):
		return 'email {0} server {1}:{2}/{3} ({4} authentication)'.format(self.user, self.host, self.port, self.folder, self.auth_type)

	def _connect(self):
		connection = imaplib.IMAP4_SSL(self.host, self.port)
		if self.auth_type == 'oauth2':
			# Modern Authentication (OAuth 2.0 client credentials flow with SASL XOAUTH2)
			m365_auth.oauth2_login(connection, self.user, self.oauth_tenant_id, self.oauth_client_id, self.oauth_client_secret)
		else:
			connection.login(self.user, self.password)
		return connection

	# Always close the connection, even if the wrapped block raises: an IMAP
	# session left open (no logout) is not released until the server times it
	# out, which is what eventually made a fresh connection attempt itself hang
	#
	# When the overall ceiling fires and on_timeout is given, its return value
	# is used instead of letting the timeout propagate - used by list_unread()
	# so that a batch already mostly fetched is returned as-is (partial
	# success) rather than discarded entirely just because the last few
	# messages did not fit in the budget
	def _with_connection(self, func, on_timeout = None):
		timeout = eventlet.Timeout(IMAP_TIMEOUT)
		connection = None
		try:
			connection = self._connect()
			return func(connection)
		except eventlet.Timeout as t:
			if t is not timeout:
				raise
			log.warning('IMAP operation exceeded the %ss ceiling', IMAP_TIMEOUT)
			if on_timeout is not None:
				return on_timeout()
			raise TimeoutError('IMAP operation timed out after {}s'.format(IMAP_TIMEOUT))
		finally:
			timeout.cancel()
			if connection is not None:
				try:
					connection.close()
				except Exception:
					pass
				try:
					connection.logout()
				except Exception:
					pass

	# Search for the unread messages worth fetching
	# In the default "attachment" analysis mode ThePhish only acts on emails that
	# carry a forwarded report as an attachment, so on Gmail the search is
	# narrowed server-side to unread messages that have an attachment. This keeps
	# a large personal inbox (thousands of unread newsletters) from hiding the
	# forwarded reports and avoids downloading the full body of every unread
	# email. In the "raw" analysis mode, or when the caller asks for every
	# unread message (the manual hybrid listing), the narrowing must not be
	# applied. Other IMAP servers (e.g. Exchange) use plain UNSEEN.
	def _search_unread_ids(self, connection, all_unread = False):
		if 'gmail' in self.host and self.analysis_mode != 'raw' and not all_unread:
			try:
				typ, dat = connection.search(None, 'X-GM-RAW', '"is:unread has:attachment"')
				if typ == 'OK':
					return dat[0].split()
			except Exception:
				log.warning('Gmail attachment search (X-GM-RAW) failed, falling back to UNSEEN', exc_info=True)
		typ, dat = connection.search(None, '(UNSEEN)')
		return dat[0].split()

	# The listing covers every unread message the mailbox holds, up to the
	# ENVELOPE_MAX_MESSAGES backstop, but only `limit` of them are downloaded
	# whole at each end. The middle comes back as stubs built from one batched
	# header FETCH per IMAP_HEADER_BATCH messages, which is what turns "list the
	# whole inbox" from hundreds of megabytes into a handful of round trips
	def list_unread(self, all_unread = False, limit = None, order = ORDER_NEWEST, include_stubs = True, have = None):
		# Shared with the on_timeout callback below: if the overall ceiling
		# fires partway through, whatever has already been fetched is still
		# returned instead of being discarded
		messages = []
		stubs = []
		head_count = [0]
		# The order the queue is shown in, filled in by _do. Also shared with
		# on_timeout: a listing cut short still says what it was listing
		queue_ids = []
		# The search answers the whole id list, so the count is exact even when
		# only part of it is downloaded
		total = [0]
		limit = limit or IMAP_MAX_MESSAGES
		order = normalize_order(order)
		# A skipped body is only skippable because it comes back as an envelope
		# instead. A caller that takes no envelopes would simply lose the message,
		# so for that caller - the automatic analysis - `have` does not apply
		held = set(have or ()) if include_stubs else set()
		def _do(connection):
			connection.select(self.folder)
			ids = self._search_unread_ids(connection, all_unread)
			total[0] = len(ids)
			# IMAP sequence numbers/UIDs increase with arrival time, so the search
			# answers oldest first; the newest-first order is that list reversed
			ordered = list(ids) if order == ORDER_OLDEST else list(reversed(ids))
			if len(ordered) > ENVELOPE_MAX_MESSAGES:
				log.info('%d unread message(s) found, listing only the first %d in %s order',
					len(ordered), ENVELOPE_MAX_MESSAGES, order)
				ordered = ordered[:ENVELOPE_MAX_MESSAGES]

			# Both ends of the mailbox are downloaded, not just the front.
			# Whichever way the analyst points the order filter, the emails at the
			# top of their screen already have their bodies - so flipping it is a
			# reversal the interface does on the spot, instead of a fresh read of
			# the mailbox they would wait out for a minute. The extra cost is one
			# more `limit` worth of messages on a listing that is already reading
			# the whole mailbox's envelopes.
			head = ordered[:limit]
			tail = ordered[max(limit, len(ordered) - limit):] if include_stubs else []
			middle = ordered[len(head):len(ordered) - len(tail)]
			queue_ids.extend(num.decode() for num in (head + middle + tail if include_stubs else head))

			# What the caller already holds is not downloaded again. This is not
			# a nicety: a polling cycle re-pulled the same `limit` bodies at each
			# end every interval, over a mailbox that had not changed. On the
			# mailbox this was found on that was 4.4 MB a minute — 6.3 GB a day
			# against Gmail's 2.5 GB daily IMAP budget, which the account spends
			# by mid-afternoon. Past it Gmail stops answering: the connection is
			# accepted and closed before the greeting, and imaplib reports it as
			# `socket error: EOF` from inside IMAP4_SSL's constructor, three
			# frames away from anything about quota. The cure is to stop asking
			# for what is already in hand.
			#
			# A skipped message is still listed — from its envelope, like the
			# middle — and the caller puts its own copy back over the stub. It
			# re-keys by arrival time when it does, so an IMAP sequence number
			# that has been recycled onto another message fails the check and the
			# row stays an envelope rather than showing somebody else's email.
			head_download = [num for num in head if num.decode() not in held]
			tail_download = [num for num in tail if num.decode() not in held]
			described = [num for num in head + tail if num.decode() in held]
			if middle or described:
				log.info('Listing %d message(s) from their envelope, downloading %d whole (%d already held, %d at each end)',
					len(middle) + len(described), len(head_download) + len(tail_download), len(described), limit)

			# The envelopes are fetched BEFORE the bodies, and deliberately so.
			# They are the cheap half (a handful of batched header fetches) and
			# they are what makes the whole queue visible; the bodies are the
			# expensive, optional half. When the whole-operation ceiling fires
			# partway through - which is what a large mailbox and a generous
			# `limit` will do - the analyst is far better served by every report
			# on screen and some of them still to open than by a fraction of the
			# mailbox with its bodies ready and the rest invisible.
			if include_stubs and (middle or described):
				stubs.extend(self._fetch_stubs(connection, described + middle))
			self._fetch_bodies(connection, head_download, messages, head_count)
			self._fetch_bodies(connection, tail_download, messages, None)
			return messages
		fetched = self._with_connection(_do, on_timeout = lambda: messages)
		# total[0] stays 0 only when the search itself never ran; reporting fewer
		# pending than were downloaded would be worse than reporting the download
		return listing(fetched, max(total[0], len(fetched) + len(stubs)), True, stubs, head_count[0],
			queue_ids or None)

	# Download the full body of each id, appending (uid, raw) to messages.
	# `counter` counts the ones that belong at the front of the listing, and is
	# incremented as they land rather than at the end, so a timeout partway
	# through still leaves the caller with a truthful split
	#
	# BODY.PEEK[] rather than RFC822: the two return the same bytes, but RFC822
	# sets \Seen and this had to unset it again with a STORE on every message.
	# That was a second round trip per body — and a window: a process that died
	# between the two left a message the analyst never saw marked as read, out of
	# the UNSEEN search and out of the queue for good. peek() and _fetch_stubs()
	# below already read this way; this is the same rule applied here. Marking a
	# message read is fetch()'s job, because there reading IS analyzing
	def _fetch_bodies(self, connection, ids, messages, counter):
		for i, num in enumerate(ids):
			fetch_timeout = eventlet.Timeout(IMAP_FETCH_TIMEOUT)
			try:
				typ, dat_fetch = connection.fetch(num, '(BODY.PEEK[])')
			except eventlet.Timeout as t:
				if t is not fetch_timeout:
					raise
				log.warning('Skipping message %s: fetch did not complete within %ss (will be retried on the next cycle)', num.decode(errors='replace'), IMAP_FETCH_TIMEOUT)
				continue
			except TimeoutError:
				# The outer, whole-operation ceiling firing mid-fetch: not ours to
				# handle here, let _with_connection's on_timeout return what we have
				raise
			except Exception:
				log.warning('Skipping message %s: fetch failed', num.decode(errors='replace'), exc_info=True)
				continue
			finally:
				fetch_timeout.cancel()
			if typ != 'OK' or not dat_fetch or not isinstance(dat_fetch[0], tuple):
				continue
			messages.append((num.decode(), dat_fetch[0][1]))
			if counter is not None:
				counter[0] += 1
			if (i + 1) % 10 == 0:
				log.info('Fetched %d/%d unread message(s)', i + 1, len(ids))

	# Envelope-only entries for the messages that are listed but not downloaded.
	# BODY.PEEK never sets the \Seen flag, so unlike the RFC822 fetch above this
	# needs no compensating store() - and a batch that fails is dropped rather
	# than aborting the listing: a queue missing a few rows still beats no queue
	def _fetch_stubs(self, connection, ids):
		stubs = []
		for start in range(0, len(ids), IMAP_HEADER_BATCH):
			chunk = ids[start:start + IMAP_HEADER_BATCH]
			header_timeout = eventlet.Timeout(IMAP_HEADER_TIMEOUT)
			try:
				typ, dat = connection.fetch(b','.join(chunk), '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
			except eventlet.Timeout as t:
				if t is not header_timeout:
					raise
				log.warning('Skipping a batch of %d envelope(s): the header fetch did not complete within %ss', len(chunk), IMAP_HEADER_TIMEOUT)
				continue
			except TimeoutError:
				raise
			except Exception:
				log.warning('Skipping a batch of %d envelope(s): the header fetch failed', len(chunk), exc_info=True)
				continue
			finally:
				header_timeout.cancel()
			if typ != 'OK':
				continue
			by_id = _parse_header_fetch(dat)
			for num in chunk:
				raw_headers = by_id.get(num.decode())
				if raw_headers is None:
					continue
				stubs.append(stub_from_headers(num.decode(), raw_headers))
		return stubs

	# Read the body of a single listed email without marking it as read: this is
	# what the interface calls when an analyst opens an email that was listed
	# from its envelope alone, and opening an email is not analyzing it
	def peek(self, mail_uid):
		def _do(connection):
			connection.select(self.folder)
			# The same guard fetch() applies: ids here are sequence numbers, and
			# one that has since been read belongs to a message somebody else has
			# already dealt with. Showing its body would be showing the wrong email
			typ, dat = connection.search(None, '(UNSEEN)')
			if typ != 'OK' or mail_uid.encode() not in dat[0].split():
				return None
			typ, dat_fetch = connection.fetch(mail_uid.encode(), '(BODY.PEEK[])')
			if typ != 'OK' or not dat_fetch or not isinstance(dat_fetch[0], tuple):
				return None
			return dat_fetch[0][1]
		return self._with_connection(_do)

	# peek() for several listed emails over ONE connection: {uid: raw bytes}.
	#
	# The inbox loader reads the whole mailbox a page at a time, and peek() opens
	# and logs in a connection per call. Two thousand logins in a row is exactly
	# the burst a provider throttles; one per batch is what it expects from a mail
	# client. The UNSEEN guard is peek()'s, run once for the batch: an id that has
	# since been read belongs to a message somebody already dealt with, and is
	# left out rather than shown.
	#
	# A message that does not come back within IMAP_FETCH_TIMEOUT is left out too,
	# and when the whole-operation ceiling fires what was already read is returned
	# — the caller retries whatever is missing on its next batch
	def peek_many(self, mail_uids):
		found = {}
		wanted = [str(mail_uid) for mail_uid in mail_uids]
		def _do(connection):
			connection.select(self.folder)
			typ, dat = connection.search(None, '(UNSEEN)')
			if typ != 'OK':
				return found
			unseen = set(dat[0].split())
			for mail_uid in wanted:
				if mail_uid.encode() not in unseen:
					continue
				fetch_timeout = eventlet.Timeout(IMAP_FETCH_TIMEOUT)
				try:
					typ, dat_fetch = connection.fetch(mail_uid.encode(), '(BODY.PEEK[])')
				except eventlet.Timeout as t:
					if t is not fetch_timeout:
						raise
					log.warning('Skipping message %s: peek did not complete within %ss', mail_uid, IMAP_FETCH_TIMEOUT)
					continue
				except TimeoutError:
					raise
				except Exception:
					log.warning('Skipping message %s: peek failed', mail_uid, exc_info = True)
					continue
				finally:
					fetch_timeout.cancel()
				if typ != 'OK' or not dat_fetch or not isinstance(dat_fetch[0], tuple):
					continue
				found[mail_uid] = dat_fetch[0][1]
			return found
		return self._with_connection(_do, on_timeout = lambda: found)

	def fetch(self, mail_uid):
		def _do(connection):
			connection.select(self.folder)
			typ, dat = connection.search(None, '(UNSEEN)')
			if mail_uid.encode() not in dat[0].split():
				# Already fetched (and therefore flagged as seen) by a previous analysis
				return None
			typ, dat_fetch = connection.fetch(mail_uid.encode(), '(RFC822)')
			if typ != 'OK':
				return None
			# The fetch operation flags the message as seen, which is the wanted behavior here
			return dat_fetch[0][1]
		return self._with_connection(_do)


# imaplib answers a batched FETCH as a flat list where every message contributes
# a (prefix, payload) tuple - the prefix carrying the sequence number the server
# replied about, which is not necessarily the order they were asked for. This
# maps them back so the caller can keep the order the analyst chose
def _parse_header_fetch(data):
	headers = {}
	for item in data or []:
		if not isinstance(item, tuple) or len(item) < 2:
			continue
		prefix, payload = item[0], item[1]
		if not isinstance(prefix, (bytes, bytearray)) or payload is None:
			continue
		match = re.match(br'\s*(\d+)\s', bytes(prefix))
		if not match:
			continue
		headers[match.group(1).decode()] = bytes(payload)
	return headers

# Build the provider described by the "email_sync" section of configuration.json
# When the section is missing (installations that predate the settings panel),
# fall back to the legacy "imap" + "oauth2" sections
def create_provider(conf_dict):
	sync_conf = conf_dict.get('email_sync') or {}
	provider_name = sync_conf.get('provider', '')
	# "attachment" (default): analyze the .eml forwarded as an attachment
	# "raw": analyze the mailbox email itself
	analysis_mode = sync_conf.get('analysisMode', 'attachment')
	if provider_name == 'm365':
		m365_conf = sync_conf.get('m365', {})
		return GraphProvider(
			m365_conf.get('tenantId', ''),
			m365_conf.get('clientId', ''),
			m365_conf.get('clientSecret', ''),
			m365_conf.get('mailbox', ''),
			m365_conf.get('folder', 'inbox')
		)
	if provider_name == 'gmail':
		gmail_conf = sync_conf.get('gmail', {})
		return ImapProvider(
			'imap.gmail.com', 993,
			gmail_conf.get('user', ''),
			gmail_conf.get('appPassword', ''),
			'basic',
			gmail_conf.get('folder', 'inbox'),
			analysis_mode = analysis_mode
		)
	# Legacy configuration (no email_sync section)
	imap_conf = conf_dict['imap']
	oauth_conf = conf_dict.get('oauth2', {})
	return ImapProvider(
		imap_conf['host'], int(imap_conf['port']),
		imap_conf['user'], imap_conf.get('password', ''),
		imap_conf.get('authType', 'basic'),
		imap_conf['folder'],
		oauth_conf.get('tenantId', ''),
		oauth_conf.get('clientId', ''),
		oauth_conf.get('clientSecret', ''),
		analysis_mode = analysis_mode
	)
