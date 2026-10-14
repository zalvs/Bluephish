import base64
import email
import json
import logging.config
import traceback

import bs4
import magic

import email_provider
import email_render

# O logger do módulo nasce vazio e é montado por _configure_logging()
log = None

# Tipos de parte que podem carregar o e-mail denunciado. Os dois entram porque
# cada cliente de e-mail anexa a mensagem encaminhada de um jeito
EML_CARRIER_TYPES = ('application/octet-stream', 'message/rfc822')

# O que o libmagic diz de um octet-stream que, de fato, é um .eml
EML_MAGIC_TYPES = ('text/plain', 'message/rfc822')


# Extract the human-readable text from an HTML email body
# BeautifulSoup's get_text() works on any HTML structure, unlike indexing a
# fixed body/div/p/span path which only matches the specific markup produced
# by some mail clients and raises AttributeError on any other (e.g. the HTML
# newsletters/marketing emails found in a regular, non-dedicated mailbox)
def _extract_html_text(html):
	return bs4.BeautifulSoup(html, 'html.parser').get_text(separator = ' ', strip = True)


# O texto de uma parte text/*. Quem não é UTF-8 costuma ser ISO-8859-1, que
# decodifica qualquer sequência de bytes
def _decode_payload(part):
	payload = part.get_payload(decode = True)
	try:
		return payload.decode()
	except UnicodeDecodeError:
		return payload.decode('ISO-8859-1')


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

	emails_info = []
	for num, message in messages:
		# A single malformed/unusual message must not abort the whole batch
		try:
			_list_message(num, message, emails_info, include_raw)
		except Exception:
			log.error("Error while trying to process the message with UID {0}: {1}".format(num, traceback.format_exc()))

	# Everything that got this far was downloaded whole, so its body is on the
	# entry. The listing also carries entries that were not (see email_provider's
	# stubs), and the interface has to be able to tell the two apart
	for email_info in emails_info:
		email_info['bodyLoaded'] = True

	return emails_info


# Uma mensagem vira uma entrada da lista: pelo .eml que carrega ou, sem ele (e se
# o modo pedir), como e-mail "raw"
def _list_message(num, message, emails_info, include_raw):
	if _process_one_message(num, message, emails_info):
		return
	if include_raw:
		_process_raw_message(num, message, emails_info)


# Both helpers live in email_provider now: the providers build the envelope-only
# listing entries themselves and need the same decoding, and the dependency only
# runs one way (this module imports email_provider, never the reverse)
_received_at = email_provider.received_at
_decode_header_field = email_provider.decode_header_field


# Um campo da entrada passa por aqui antes de ir para a tela: o texto é escapado
# e desescapado para neutralizar caracteres de controle, e o \x92 (aspa curva do
# Windows, que chega mal codificada) vira apóstrofo
def _tidy_text(value):
	if value is None:
		value = ''
	return value.encode("unicode-escape").decode().replace(r'\x92', '\'').encode().decode("unicode-escape")


# A entrada da lista para uma mensagem. `attached_*` descrevem o e-mail
# denunciado: o anexo, quando há, ou a própria mensagem no modo raw
def _listing_entry(num, msg, from_field, subject_field, body, attached_subject, attached_from, email_type):
	entry = {
		'mailUID': num,
		'from': from_field,
		'subject': subject_field,
		'date': msg['Date'],
		'body': body,
		'attachedMail': attached_subject,
		'attachedFrom': attached_from,
		'email_type': email_type
	}
	entry = {key: _tidy_text(value) for key, value in entry.items()}
	# Added after the escaping above, which only knows how to handle strings
	entry['receivedAt'] = _received_at(msg['Date'])
	return entry


# O primeiro text/plain e o primeiro text/html da mensagem, já decodificados
def _first_text_parts(msg):
	plain = None
	html = None
	for part in msg.walk():
		mimetype = part.get_content_type()
		if mimetype == 'text/plain' and plain is None:
			plain = _decode_payload(part)
		elif mimetype == 'text/html' and html is None:
			html = _decode_payload(part)
	return plain, html


# Build the listing entry for a message in the "raw" analysis mode: the mailbox
# email itself is the email to analyze, so no EML attachment is required and the
# entry describes the message directly
def _process_raw_message(num, message, emails_info):
	msg = email.message_from_bytes(message)
	from_field = _decode_header_field(msg['From'])
	subject_field = _decode_header_field(msg['Subject'])
	log.info("Message from: {0} with subject: {1}".format(from_field, subject_field))

	# A prévia do corpo: o primeiro text/plain, ou o texto do primeiro text/html
	# quando não há nenhum
	body, html_body = _first_text_parts(msg)
	if body is None and html_body is not None:
		body = _extract_html_text(html_body)

	# O e-mail a analisar é a própria mensagem
	emails_info.append(_listing_entry(num, msg, from_field, subject_field, body, subject_field, from_field, 'Raw Email'))


# Há algum text/plain antes do .eml anexado? Um text/plain que vem depois do
# message/rfc822 é o do próprio anexo e não conta como corpo do e-mail externo
def _has_text_before_eml(msg):
	for part in msg.walk():
		mimetype = part.get_content_type()
		if mimetype == 'text/plain':
			return True
		if mimetype == 'message/rfc822':
			return False
	return False


# A mensagem denunciada que uma parte carrega, ou None quando a parte não é um
# .eml. Um octet-stream traz os bytes (e só vale se o libmagic reconhecer um e-mail
# depois da decodificação); um message/rfc822 traz a mensagem já aberta ou, em
# alguns clientes, o texto dela em base64
def _embedded_report(part, mimetype):
	if mimetype == 'application/octet-stream':
		payload = part.get_payload(decode = 1)
		internal_msg = email.message_from_bytes(payload)
		if magic.from_buffer(payload, mime = True) not in EML_MAGIC_TYPES:
			return None
		return internal_msg
	embedded = part.get_payload(decode = 0)[0]
	try:
		return email.message_from_string(base64.b64decode(str(embedded)).decode())
	except Exception:
		return embedded


# O corpo escrito dentro de um multipart/mixed, quando o e-mail externo não tem
# text/plain solto. Só a primeira subparte conta. Um text/plain ali dentro ganha;
# um text/html só entra se o multipart não tiver nenhum text/plain (ele pode vir
# depois do html)
def _body_inside_mixed(container, body):
	nested = container.get_payload()[0]
	nested_has_plain = any(sub.get_content_type() == 'text/plain' for sub in nested.walk())
	for sub in nested.walk():
		mimetype = sub.get_content_type()
		if mimetype == 'text/plain':
			if not body:
				body = _decode_payload(sub)
		elif mimetype == 'text/html' and not nested_has_plain:
			html = _decode_payload(sub)
			if not body:
				body = _extract_html_text(html)
	return body


# Parse a single RFC822 message and, if it has an EML attachment, append its info to emails_info
# Returns True when an entry has been appended (an EML attachment was found),
# so that the caller can fall back to the raw-email listing otherwise
def _process_one_message(num, message, emails_info):
	msg = email.message_from_bytes(message)
	# A long non-ASCII header travels as several encoded-words, and taking only
	# the last one ([-1]) threw away everything before it: the display name of
	# the From, and prefixes like "[EXTERNAL]" or "Re:" on the Subject. Worse,
	# the else branch ran str() over bytes, so an address arrived at the analyst
	# as the literal b'<...>'. The helper joins every fragment
	from_field = _decode_header_field(msg['From'])
	subject_field = _decode_header_field(msg['Subject'])
	log.info("Message from: {0} with subject: {1}".format(from_field, subject_field))

	has_text = _has_text_before_eml(msg)
	body = None
	attached_subject = ''
	attached_from = ''
	report_found = False

	for part in msg.walk():
		mimetype = part.get_content_type()
		if mimetype in EML_CARRIER_TYPES:
			internal_msg = _embedded_report(part, mimetype)
			if internal_msg is None:
				continue
			report_found = True
			# The subject of the attached report - the one the analyst reads. Same
			# helper: an attacker writes these headers, and both a charset that does
			# not exist and a missing Subject used to raise from here. The raise was
			# caught per message upstream, so the reported phishing simply vanished
			# from the queue with one line in the log - an evasion primitive
			attached_subject = _decode_header_field(internal_msg['Subject'])
			# O remetente do e-mail denunciado, lido do mesmo .eml que já está em
			# mãos: é ele — e não o colega que encaminhou — que o alerta de volume
			# agrupa. Nenhum download a mais
			attached_from = _decode_header_field(internal_msg['From'])
			log.info("Found attached mail with subject: {0} ({1})".format(attached_subject, mimetype))
			# O .eml é a última parte que importa: o que vier depois pode ser do
			# e-mail interno
			break
		if mimetype == 'multipart/mixed':
			# Só olha dentro dele se nenhum text/plain veio antes do anexo: nesse
			# caso o corpo sai do text/plain
			if not has_text:
				body = _body_inside_mixed(part, body)
		elif mimetype == 'text/plain':
			if has_text and not body:
				body = _decode_payload(part)
		elif mimetype == 'text/html':
			html = _decode_payload(part)
			if not body:
				body = _extract_html_text(html)

	if report_found:
		emails_info.append(_listing_entry(num, msg, from_field, subject_field, body, attached_subject, attached_from, 'Attached .eml'))
	return report_found


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
	by_uid = {entry['mailUID']: entry for entry in head_info + stubs + tail_info}
	return [by_uid[uid] for uid in order_ids if uid in by_uid]


# Liga o log e lê a configuração, que é o que toda entrada deste módulo precisa
# antes de falar com a caixa. Devolve (provedor, modo de análise), ou None quando
# um dos dois passos falhou (e já foi registrado)
def _open_mailbox():
	global log
	log = _configure_logging()
	if log is None:
		return None
	return _read_configuration()


def main(all_pending = False, limit = None, order = None, have = None):

	conf = _open_mailbox()
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
	except Exception:
		log.error("Error while trying to connect to the email server: {}".format(traceback.format_exc()))
		return

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
	except Exception:
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

	conf = _open_mailbox()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Loading the body of the email with UID {0} on demand'.format(mail_uid))
		message = provider.peek(mail_uid)
	except Exception:
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
# (see THEPHISH_ARCHITECTURE.md 7.10), and hashing attachments plus base64-ing
# logos for a hundred emails a minute is exactly that cost again - paid for
# emails nobody has opened. It costs one peek, on the click that asks for it.
#
# Strictly read-only for the same reason load_one() is: peek() leaves the message
# unread, so looking at how an email was laid out is still not analyzing it.
#
# Returns None when the mailbox could not be read or the email has left it
def render_one(mail_uid):

	conf = _open_mailbox()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Rendering the email with UID {0} as delivered'.format(mail_uid))
		message = provider.peek(mail_uid)
	except Exception:
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

	conf = _open_mailbox()
	if conf is None:
		return
	provider = conf[0]

	try:
		log.info('Loading {0} email(s) in the background: {1}'.format(len(mail_uids), ', '.join(mail_uids)))
		if hasattr(provider, 'peek_many'):
			return provider.peek_many(mail_uids)
		return _peek_one_by_one(provider, mail_uids)
	except Exception:
		log.error("Error while trying to load emails in the background: {}".format(traceback.format_exc()))
		return


# Lê as mensagens uma a uma, pulando as que falham: uma não derruba o lote
def _peek_one_by_one(provider, mail_uids):
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
			logging.config.dictConfig(json.load(log_conf))
	except Exception:
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return None
	return logging.getLogger(__name__)


# The configured provider and analysis mode, or None when configuration.json
# cannot be read. Email synchronization is Microsoft 365 through the Graph API,
# Gmail through IMAP, or the legacy imap/oauth2 sections, selected by
# email_provider
def _read_configuration():
	try:
		with open('configuration.json') as conf_file:
			conf_dict = json.load(conf_file)
		provider = email_provider.create_provider(conf_dict)
		analysis_mode = (conf_dict.get('email_sync') or {}).get('analysisMode', 'attachment')
	except Exception:
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		return None
	return provider, analysis_mode
