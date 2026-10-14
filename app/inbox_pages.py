"""Paging the inbox queue, and deciding what the background loader reads next.

Kept apart from thephish_app and list_emails on purpose. Those import eventlet
and libmagic, which only exist inside the image, and on a developer's machine
importing them does not fail with ImportError — it takes the interpreter down.
Everything here is plain Python over lists of mail UIDs, so the rules that decide
which report an analyst finds ready are tested where the code is written, not
only inside a container.

Two ideas live here:

* **A page is a slice of the queue as the analyst reads it.** The listing is
  built newest first; the order filter reverses it in the browser. So page N of
  "Mais recentes" is the Nth slice from the front of the listing and page N of
  "Mais antigos" is the Nth slice from the back.
* **The loader walks the pages alternating the two ends** — newest page 1,
  oldest page 1, newest page 2, oldest page 2 — so whichever way the filter
  points, the analyst finds the page they are on ready before the ones they are
  not, and switching the filter never lands them on a screen of rows that still
  have to be fetched one by one.
"""

# What an admin may choose. A closed set rather than a range: these are the
# sizes that fit a list column without the page turning into a scroll again,
# and 50 is also the most POST /analysis-selected accepts in one call, so
# "select every row on this page" is always a batch the server will run.
PAGE_SIZES = (20, 30, 40, 50)
DEFAULT_PAGE_SIZE = 30

# How many messages the loader takes per trip to the mail server. One trip is one
# IMAP login and one hold of the analysis semaphore, so this is the trade-off
# between logins — a provider throttles bursts of them — and how long a click on
# an email that is not ready yet can wait behind the loader: at most one batch.
LOAD_BATCH = 10

# Characters of body carried by the websocket push.
#
# Once the loader has been through the mailbox every entry holds its full body,
# and a full push is every row of the mailbox: at 2000 characters a row that
# would be several megabytes per open tab each time the queue changes. The push
# carries the start of each body, which is where a subject line is restated and
# where the queue search mostly needs to look; the full body is one request away,
# served from the cache that already holds it, and the preview asks for it when
# it opens an email.
SNIPPET_CHARS = 500


def _as_int(value):
	try:
		return int(value)
	except (TypeError, ValueError):
		return None


def normalize_page_size(value, legacy = None):
	"""A page size from PAGE_SIZES.

	`value` is `inboxPolling.pageSize`. `legacy` is the `maxEmails` this setting
	replaces: an installation that tuned the old knob and never saw the new one
	gets the allowed size closest to what it chose — 30 stays 30, 200 becomes 50 —
	instead of silently falling back to the default.
	"""
	number = _as_int(value)
	if number in PAGE_SIZES:
		return number
	legacy_number = _as_int(legacy)
	if legacy_number is not None and legacy_number > 0:
		return min(PAGE_SIZES, key = lambda size: (abs(size - legacy_number), size))
	return DEFAULT_PAGE_SIZE


def page_plan(uids, page_size):
	"""Every page of the queue, in the order the loader should work through them.

	`uids` is the listing in order: one end of the mailbox at index 0, the other
	at the last index. Returns `(end, number, uids)` tuples, `end` being 'front'
	or 'back' and `number` counting from 1 at that end.

	Each UID is claimed once. On a short queue the two ends meet in the middle,
	and the page that reaches it second only keeps what the first did not take —
	loading a message twice is a second download of the same bytes against the
	provider's daily budget.
	"""
	size = max(1, _as_int(page_size) or DEFAULT_PAGE_SIZE)
	front = [uids[start:start + size] for start in range(0, len(uids), size)]
	backwards = list(reversed(uids))
	back = [backwards[start:start + size] for start in range(0, len(backwards), size)]

	plan = []
	claimed = set()
	for index in range(max(len(front), len(back))):
		for end, pages in (('front', front), ('back', back)):
			if index >= len(pages):
				continue
			page = [uid for uid in pages[index] if uid not in claimed]
			claimed.update(page)
			if page:
				plan.append((end, index + 1, page))
	return plan


def next_batch(uids, page_size, ready, skip = (), limit = LOAD_BATCH):
	"""The next messages the loader should read, or None when there are none.

	Taken from the earliest page in the plan that still has work, so a report
	that arrives at the top of the mailbox puts page 1 back at the head of the
	line on the next pass instead of waiting for the loader to finish page 90.

	`ready` holds the UIDs already done. `skip` holds the ones that could not be
	read — gone from the mailbox, or a parse that failed — so a single bad
	message cannot pin the loader to the same page forever.
	"""
	for end, number, page in page_plan(uids, page_size):
		pending = [uid for uid in page if uid not in ready and uid not in skip]
		if pending:
			return end, number, pending[:max(1, limit)]
	return None


def progress(uids, ready):
	"""How much of the listing is ready, as the interface reports it."""
	return {
		'ready': sum(1 for uid in uids if uid in ready),
		'total': len(uids)
	}


def envelope_for_push(mail, snippet_chars = SNIPPET_CHARS):
	"""A copy of a listing entry for the websocket, with the body cut to a snippet.

	Never mutates the entry it was given: that one is the server's copy, and the
	full body is what `GET /email/<uid>` answers from.
	"""
	entry = dict(mail)
	body = entry.get('body') or ''
	if len(body) > snippet_chars:
		entry['body'] = body[:snippet_chars]
		entry['bodyTruncated'] = True
	else:
		entry['bodyTruncated'] = False
	return entry
