import logging.config
import json
import config_file
import email
import email.utils
import base64
import traceback
import bs4
import magic
import email_provider
import email_render

# Global variable used for logging
log = None


# Extract the human-readable text from an HTML email body
# BeautifulSoup's get_text() works on any HTML structure, unlike indexing a
# fixed body/div/p/span path which only matches the specific markup produced
# by some mail clients and raises AttributeError on any other (e.g. the HTML
# newsletters/marketing emails found in a regular, non-dedicated mailbox)
def _extract_html_text(html):
	soup = bs4.BeautifulSoup(html, 'html.parser')
	return soup.get_text(separator=' ', strip=True)


# Fetch all the unread emails and return their information
# The messages argument is a list of (uid, raw MIME bytes) tuples produced by the provider
# Every message is inspected: the ones that carry an EML attachment (a forwarded
# report) are tagged with email_type "Attached .eml", the others with "Raw Email"
# When include_raw is False (the automatic analysis in attachment mode) the raw
# entries are not returned, keeping the original attachment-only behavior
def retrieve_emails(messages, include_raw = True):
	if not messages:
		return []
	log.info("{} unread messages to process".format(len(messages)))

	# Variable that will contain the information related to the unread emails to show on the web interface
	emails_info = []

	# For each unread email parse the RFC822 message
	# A single malformed/unusual message must not abort the whole batch
	for num, message in messages:
		try:
			# _process_one_message appends an entry only when the message carries
			# an EML attachment; otherwise the message is listed as a raw email
			if not _process_one_message(num, message, emails_info) and include_raw:
				_process_raw_message(num, message, emails_info)
		except Exception as e:
			log.error("Error while trying to process the message with UID {0}: {1}".format(num, traceback.format_exc()))

	# Everything that got this far was downloaded whole, so its body is on the
	# entry. The listing also carries entries that were not (see email_provider's
	# stubs), and the interface has to be able to tell the two apart
	for email_info in emails_info:
		email_info['bodyLoaded'] = True

	return emails_info


# Both helpers live in email_provider now: the providers build the envelope-only
# listing entries themselves and need the same decoding, and the dependency only
# runs one way (this module imports email_provider, never the reverse)
_received_at = email_provider.received_at
_decode_header_field = email_provider.decode_header_field


# Build the listing entry for a message in the "raw" analysis mode: the mailbox
# email itself is the email to analyze, so no EML attachment is required and the
# entry describes the message directly
def _process_raw_message(num, message, emails_info):
	msg = email.message_from_bytes(message)
	from_field = _decode_header_field(msg['From'])
	subject_field = _decode_header_field(msg['Subject'])
	log.info("Message from: {0} with subject: {1}".format(from_field, subject_field))

	# Extract a readable body preview: the first text/plain part is preferred,
	# with the text extracted from the first text/html part as fallback
	body = None
	html_body = None
	for part in msg.walk():
		mimetype = part.get_content_type()
		if mimetype == 'text/plain' and body is None:
			try:
				body = part.get_payload(decode=True).decode()
			except UnicodeDecodeError:
				body = part.get_payload(decode=True).decode('ISO-8859-1')
		elif mimetype == 'text/html' and html_body is None:
			try:
				html_body = part.get_payload(decode=True).decode()
			except UnicodeDecodeError:
				html_body = part.get_payload(decode=True).decode('ISO-8859-1')
	if body is None and html_body is not None:
		body = _extract_html_text(html_body)

	email_info = {}
	email_info['mailUID'] = num
	email_info['from'] = from_field
	email_info['subject'] = subject_field
	email_info['date'] = msg['Date']
	email_info['body'] = body
	# The email to analyze is the message itself
	email_info['attachedMail'] = subject_field
	email_info['attachedFrom'] = from_field
	email_info['email_type'] = 'Raw Email'
	for key in email_info:
		if email_info[key] is None:
			email_info[key] = ''
		email_info[key] = email_info[key].encode("unicode-escape").decode().replace(r'\x92', '\'').encode().decode("unicode-escape")
	# Added after the escaping loop above, which only knows how to handle strings
	email_info['receivedAt'] = _received_at(msg['Date'])
	emails_info.append(email_info)


# Parse a single RFC822 message and, if it has an EML attachment, append its info to emails_info
def _process_one_message(num, message, emails_info):
	# Obtain the Subject and From fields of the email
	msg = email.message_from_bytes(message)
	# A long non-ASCII header travels as several encoded-words, and taking only
	# the last one ([-1]) threw away everything before it: the display name of
	# the From, and prefixes like "[EXTERNAL]" or "Re:" on the Subject. Worse,
	# the else branch ran str() over bytes, so an address arrived at the analyst
	# as the literal b'<...>'. The helper joins every fragment
	from_field = _decode_header_field(msg['From'])
	subject_field = _decode_header_field(msg['Subject'])
	log.info("Message from: {0} with subject: {1}".format(from_field, subject_field))

	# This will contain the body of the email
	body = None

	# True if an EML attachment is found for the current email
	eml_attachment_found = False

	# True if there is a text/plain part in the email multipart structure
	is_there_text = False

	# Walk the multipart structure of the email
	# If there is a text/plain part, set the corresponding variable to True
	# However, if that text/plain part is found after the message/rfc822, then it is the text/plain part of the EML attachment and must not be considered
	for part in msg.walk():
		if part.get_content_type() == "text/plain":
			is_there_text = True
		elif part.get_content_type() == "message/rfc822":
			break

	# This will contain the Subject field of the email
	attached_mail_subject = ''
	# And this its From field
	attached_mail_from = ''

	# Walk the multipart structure of the email again
	for part in msg.walk():
		mimetype = part.get_content_type()
		# If the content type of this part is the rfc822 message, then stop because the EML attachment is the last part
		# If there is any other part after the rfc822 part, then it may be related to the internal email, so it must not be considered
		# Both message/rfc822 and application/octet-stream types are considered due to differences in how the attachment is handled by different mail clients
		if mimetype in ['application/octet-stream', 'message/rfc822']:
			# Obtain the internal EML file in both cases
			if mimetype == 'application/octet-stream':
				eml_payload = part.get_payload(decode=1)
				internal_msg = email.message_from_bytes(eml_payload)
				# Use the magic module to obtain the mimetype after the decoding procedure
				# If it was octet-stream before the decode, it must become rfc/822, else that means that it was not an EML attachment and must be ignored
				if magic.from_buffer(eml_payload, mime=True) not in ['text/plain', 'message/rfc822']:
					continue
			elif mimetype == 'message/rfc822':
				eml_payload = part.get_payload(decode=0)[0]
				try:
					internal_msg = email.message_from_string(base64.b64decode(str(eml_payload)).decode()) 
				except:
					internal_msg = eml_payload
			
			# Set to true to consider this as an email to include in the list to return to the client
			eml_attachment_found = True

			# The subject of the attached report - the one the analyst reads. Same
			# helper: an attacker writes these headers, and both a charset that does
			# not exist and a missing Subject used to raise from here. The raise was
			# caught per message upstream, so the reported phishing simply vanished
			# from the queue with one line in the log - an evasion primitive
			attached_mail_subject = _decode_header_field(internal_msg['Subject'])
			# O remetente do e-mail denunciado, lido do mesmo .eml que já está em
			# mãos: é ele — e não o colega que encaminhou — que o alerta de volume
			# agrupa. Nenhum download a mais
			attached_mail_from = _decode_header_field(internal_msg['From'])
			log.info("Found attached mail with subject: {0} ({1})".format(attached_mail_subject, mimetype))

			# If the EML attachment has been found, then break the for
			break

		# If it is not an EML attachment, then check if it is multipart/mixed, but only if there is no text/plain part before 
		# the EML attachment, because in that case the body will be obtained from the text/plain part
		elif mimetype == "multipart/mixed":
			if is_there_text == False:
				part_payload = part.get_payload()[0]
				# Variabile per vedere se c'e' un text plain in questomultipart mixed (visto che fuori non ci stava)
				# True if there is a text/plain part in this multipart/mixed, since there was no text/plain part before
				is_there_text_in_multipart = False
				# Walk the subparts of this multipart 
				# If there is a text/plain part here, set the corresponding variable to True
				for subpart in part_payload.walk():
					if subpart.get_content_type() == "text/plain":
						is_there_text_in_multipart = True
				# Walk the subparts of this multipart again 
				# If the first part is a text/plain part then use it to populate the body
				# Else, if the first part is text/html and there is a text/plain part, then it will be skipped
				# because the text/plain part might be located after the current text/html part
				# Otherwise, if the first part is text/html and there is no text/plain part, then use it to populate the body
				for subpart in part_payload.walk():
					if subpart.get_content_type() == "text/plain":
						if not body:
							try:
								body = subpart.get_payload(decode=True).decode()
							except UnicodeDecodeError:
								body = subpart.get_payload(decode=True).decode('ISO-8859-1')
					# Use the bs4 module to obtain the text from the text/html part
					elif subpart.get_content_type() == "text/html":
						if is_there_text_in_multipart == False:
							try:
								html = subpart.get_payload(decode=True).decode()
							except UnicodeDecodeError:
								html = subpart.get_payload(decode=True).decode('ISO-8859-1')
							if not body:
								soup = bs4.BeautifulSoup(html, 'html.parser')
								body = _extract_html_text(html)
		# Else if there was a text/plain part outside of the multipart/mixed part, the branch related to the multipart/mixed part is not executed
		# The body will in fact be populated from this text/plain part
		elif mimetype == "text/plain":
			if is_there_text == True:
				if not body:
					try:
						body = part.get_payload(decode=True).decode()
					except UnicodeDecodeError:
						body = part.get_payload(decode=True).decode('ISO-8859-1')
		# If neither a text/plain part nor a multipart/mixed part has been encountered before this text/html part
		# then use it to populate the body using the bs4 module
		elif mimetype == "text/html":
			try:
				html = part.get_payload(decode=True).decode()
			except UnicodeDecodeError:
				html = part.get_payload(decode=True).decode('ISO-8859-1')
			if not body:
				soup = bs4.BeautifulSoup(html, 'html.parser')
				body = _extract_html_text(html)

	# If there is an eml attachment in this email, then add to the list of emails the information on this email, which are:
	# - UID of the email in the mailbox
	# - From and Subject field of the external email
	# - Arrival date of the external email
	# - Body of the external email
	# - Subject field of the internal email (EML attachment)
	# Returns True when an entry has been appended (an EML attachment was found),
	# so that the caller can fall back to the raw-email listing otherwise
	if (eml_attachment_found == True):
		email_info = {}
		email_info['mailUID'] = num
		email_info['from'] = from_field
		email_info['subject'] = subject_field
		email_info['date'] = msg['Date']
		email_info['body'] = body
		email_info['attachedMail'] = attached_mail_subject
		email_info['attachedFrom'] = attached_mail_from
		email_info['email_type'] = 'Attached .eml'

		# Problematic characters substitution
		for key in email_info:
			# single quote
			if email_info[key] is None:
				email_info[key] = ''
			email_info[key] = email_info[key].encode("unicode-escape").decode().replace(r'\x92', '\'').encode().decode("unicode-escape")
		# Added after the escaping loop above, which only knows how to handle strings
		email_info['receivedAt'] = _received_at(msg['Date'])
		emails_info.append(email_info)
	return eml_attachment_found

# Main function called from outside
# all_pending=True (the manual "List emails" button and the mailbox poll) lists
# every unread email, each tagged with its email_type, and is strictly read-only:
# no analysis is started here. all_pending=False (the automatic analysis) scopes
# the listing with the configured analysis mode: "attachment" only enumerates the
# emails that carry a forwarded .eml report, "raw" enumerates every unread email
#
# `limit` is not a ceiling on the listing: it is how many of the listed emails
# are downloaded whole. Every other unread email is still listed, from its
# envelope alone, and its body is loaded by load_one() the moment somebody opens
# it - which is what lets this screen show a full mailbox without downloading
# one. Both ends are downloaded, not just the front, so that reversing the order
# on screen never lands the analyst on rows whose bodies are missing.
#
# `order` is the direction the listing comes back in; the interface is free to
# reverse it, which is exactly why both ends carry their bodies.
#
# `have` is the set of mail UIDs whose body the caller is still holding from an
# earlier listing. Those are not downloaded again: they come back as envelopes
# and the caller lays its own copy back over them. A polling cycle that does not
# pass this re-pulls the same megabytes every interval from a mailbox that has
# not changed, which is what spends a Gmail account's daily IMAP budget before
# the afternoon - see ImapProvider.list_unread.
#
# Returns None when the mailbox could not be read, otherwise:
#
#   {'emails': [...],   every listed email: the downloaded end, the envelopes,
#                       then the downloaded far end
#    'loaded': n,       how many of them arrived with their body
#    'total': n,        unread messages the mailbox holds, listed or not
#    'exact': bool,     whether `total` is a count or a lower bound
#    'order': str,      the order that was applied
#    'limit': n}        the download limit that was applied
#
# The caller needs `total` to tell a queue that is complete from one that was cut
# at the envelope backstop - showing a truncated list as if it were the whole
# mailbox is how a report sits unseen behind fifty others
def assemble_queue(head_info, stubs, tail_info, order_ids):
	"""The listed emails in the order the queue shows them.

	"The downloaded front, then the envelopes, then the downloaded back" was the
	whole shape of a listing until `have` let an end skip a body it already had.
	A skipped message is an envelope sitting *inside* the head, and concatenating
	the three lists would file it with the far end of the mailbox — the analyst
	would watch a report they had just been reading jump to the bottom of the
	queue on the next tick, for no reason they could see.

	So the provider says which UIDs it listed and in what order, and the queue is
	built from that rather than from where each piece happens to sit. A UID that
	nothing answers for was a malformed message the parse skipped: it is left out
	here, which is what happened to it before too. A provider that names no order
	falls back to the concatenation.
	"""
	if not order_ids:
		return head_info + stubs + tail_info
	by_uid = dict((entry['mailUID'], entry) for entry in head_info + stubs + tail_info)
	return [by_uid[uid] for uid in order_ids if uid in by_uid]


def main(all_pending = False, limit = None, order = None, have = None):

	global log

	log = _configure_logging()
	if log is None:
		return

	conf = _read_configuration()
	if conf is None:
		return
	provider, analysis_mode = conf
	order = email_provider.normalize_order(order)

	# Retrieve the unread messages through the configured provider
	# The manual listing covers every unread email regardless of the analysis mode
	# The automatic analysis only ever acts on what it downloads, so it asks for
	# no stubs: enumerating the rest of the mailbox would cost it a round trip
	# per batch to build a list nothing would read
	try:
		log.info('Reading {0} ({1} analysis mode, {2}, {3} first, downloading at most {4} message(s))'.format(
			provider.describe(), analysis_mode,
			'manual listing' if all_pending else 'automatic analysis',
			order, limit or email_provider.IMAP_MAX_MESSAGES))
		result = provider.list_unread(all_unread = all_pending, limit = limit, order = order,
			include_stubs = all_pending, have = have)
	except Exception as e:
		log.error("Error while trying to connect to the email server: {}".format(traceback.format_exc()))
		return

	# Call the retrieve_emails function
	# The raw entries are included in the manual listing and, for the automatic
	# analysis, only when the raw analysis mode is configured
	# The provider downloads both ends of the mailbox and describes the middle,
	# so the two halves of `messages` are parsed separately and the stubs go
	# between them. Parsing them as one list and slicing afterwards would not
	# work: a malformed message is skipped rather than listed, so the split
	# index would no longer mean what it meant before parsing
	head_count = result.get('head', len(result['messages']))
	include_raw = all_pending or analysis_mode == 'raw'
	try:
		head_info = retrieve_emails(result['messages'][:head_count], include_raw = include_raw)
		tail_info = retrieve_emails(result['messages'][head_count:], include_raw = include_raw)
	except Exception as e:
		log.error("Error while trying to retrieve the emails: {}".format(traceback.format_exc()))
		return
	stubs = result.get('stubs') or []
	return {
		'emails': assemble_queue(head_info, stubs, tail_info, result.get('ids')),
		'loaded': len(head_info) + len(tail_info),
		'total': result['total'],
		'exact': result['exact'],
		'order': order,
		'limit': limit or email_provider.IMAP_MAX_MESSAGES
	}


# Load one listed email that was not downloaded with the rest, and return the
# same entry shape the listing carries - body, attached report subject and email
# type included. Strictly read-only: peek() leaves the message unread, so an
# analyst opening an email to look at it does not take it out of the queue or
# out of anybody else's queue.
#
# Returns None when the mailbox could not be read or the email is no longer
# there (already analyzed by somebody else, or moved out of the folder)
def load_one(mail_uid):

	global log

	log = _configure_logging()
	if log is None:
		return

	conf = _read_configuration()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Loading the body of the email with UID {0} on demand'.format(mail_uid))
		message = provider.peek(mail_uid)
	except Exception as e:
		log.error("Error while trying to load the email with UID {0}: {1}".format(mail_uid, traceback.format_exc()))
		return
	if not message:
		return

	# include_raw is unconditional here: the analyst asked for this specific
	# email, so it is shown whether or not it carries a forwarded .eml
	emails_info = retrieve_emails([(mail_uid, message)], include_raw = True)
	return emails_info[0] if emails_info else None


# Build the "as delivered" view of one listed email: the sanitized markup, the
# inline images, the blocked remote hosts and the attachment manifest.
#
# Deliberately not part of the listing. The polling cycle already lost a race
# with IMAP_TIMEOUT once by doing expensive work over every message it touched
# (see BLUEPHISH_ARCHITECTURE.md 7.10), and hashing attachments plus base64-ing
# logos for a hundred emails a minute is exactly that cost again - paid for
# emails nobody has opened. It costs one peek, on the click that asks for it.
#
# Strictly read-only for the same reason load_one() is: peek() leaves the message
# unread, so looking at how an email was laid out is still not analyzing it.
#
# Returns None when the mailbox could not be read or the email has left it
def render_one(mail_uid):

	global log

	log = _configure_logging()
	if log is None:
		return

	conf = _read_configuration()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Rendering the email with UID {0} as delivered'.format(mail_uid))
		message = provider.peek(mail_uid)
	except Exception as e:
		log.error("Error while trying to load the email with UID {0}: {1}".format(mail_uid, traceback.format_exc()))
		return
	if not message:
		return

	return email_render.render(message)


# Read several listed emails for the inbox loader, without marking any as read:
# {uid: raw bytes}, or None when the mailbox could not be read at all.
#
# This is the half that talks to the mail server, and the only half the caller
# holds the analysis semaphore for. Parsing and laying the messages out happen in
# entry_and_layout(), outside it — a page of newsletters through BeautifulSoup is
# CPU time that no polling cycle or analysis needs to queue behind.
#
# A provider that can read a batch over one connection does (IMAP: one login per
# batch instead of one per message). One that cannot is asked message by message;
# for Graph that is an HTTP request on a cached token, not a login.
def peek_many(mail_uids):

	global log

	log = _configure_logging()
	if log is None:
		return

	conf = _read_configuration()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Loading {0} email(s) in the background: {1}'.format(len(mail_uids), ', '.join(mail_uids)))
		if hasattr(provider, 'peek_many'):
			return provider.peek_many(mail_uids)
		found = {}
		for mail_uid in mail_uids:
			try:
				message = provider.peek(mail_uid)
			except Exception:
				log.warning('Could not load the email with UID {0}: {1}'.format(mail_uid, traceback.format_exc()))
				continue
			if message:
				found[mail_uid] = message
		return found
	except Exception as e:
		log.error("Error while trying to load emails in the background: {}".format(traceback.format_exc()))
		return


# The listing entry and the "as delivered" layout of one message the loader has
# already read, from the same bytes: one download serves both tabs.
#
# The layout is built with `fetch_remote = False`, and that is a decision, not a
# shortcut. A remote image fetched by the container still tells whoever sent the
# email that somebody looked (§7.11) — acceptable when an analyst opened the
# email, not for every message in the mailbox, unattended. Remote images are
# replaced by a placeholder naming their host; the click that opens "Como
# entregue" fetches them.
#
# Returns (entry, layout). `entry` is None when the message could not be parsed
# into a listing entry; the layout never raises (email_render.render's contract).
def entry_and_layout(mail_uid, message):

	global log

	if log is None:
		log = _configure_logging()

	entries = retrieve_emails([(mail_uid, message)], include_raw = True)
	entry = entries[0] if entries else None
	layout = email_render.render(message, fetch_remote = False)
	return entry, layout


def _configure_logging():
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception as e:
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return None
	return logging.getLogger(__name__)


# The configured provider and analysis mode, or None when configuration.json
# cannot be read. Email synchronization is Microsoft 365 through the Graph API,
# Gmail through IMAP, or the legacy imap/oauth2 sections, selected by
# email_provider
def _read_configuration():
	try:
		conf_dict = config_file.read('configuration.json')
		provider = email_provider.create_provider(conf_dict)
		analysis_mode = (conf_dict.get('email_sync') or {}).get('analysisMode', 'attachment')
	except Exception as e:
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		return None
	return provider, analysis_mode
