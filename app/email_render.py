"""Render a reported email the way its recipient saw it, without letting it act.

The queue preview has always shown extracted text: every `text/html` part run
through BeautifulSoup's `get_text()`. That is the right default — it is the
fastest thing to read and it cannot lie about what is written — but it throws
away the half of a phishing email that does the convincing. A forged bank
letterhead, a button that says "Regularizar" over a link to a lookalike domain,
a logo pulled from a tracking host: none of that survives `get_text()`, and all
of it is evidence.

So this module produces the second view: the message laid out as delivered.
Everything here exists to make that view inert.

Threat model
------------
The input is an email an attacker wrote, and the reader is an analyst inside the
SOC console. Four things must be impossible:

1. **Script execution.** The markup is allow-listed — `<script>`, `<iframe>`,
   `<object>`, `<embed>`, `<form>`, `<svg>` and every `on*` attribute are
   removed, not escaped. The interface then renders the result inside a
   `sandbox`ed iframe with no `allow-scripts`, and the page CSP
   (`script-src 'self'`) is inherited by the `srcdoc` document. Three
   independent layers, because this one is unforgiving.

2. **Any request from the analyst's browser.** Not "any request at all" — that
   was the first version of this module, and it was wrong in the field: a
   phishing email whose entire message is one hosted image rendered as a blank
   rectangle, which is not a safer triage, it is no triage. So remote images are
   fetched, and the whole point is *who* fetches them.

   The **server** does, never the browser. What the analyst's workstation would
   have leaked — its address, its user agent, whatever a request from a real
   workstation says about the organization — never leaves, and the message can
   still not reach the console's origin. The container's outbound request does
   tell the sender that somebody looked, which is the same thing `unshorten.py`
   already tells them when it resolves a link out of the same email; that cost
   is accepted here for the same reason, and the hosts contacted are reported so
   it is never silent.

   Because the URL comes from an attacker, **every fetch goes through
   `custom_analyzers.validate_destination()`** — the same guard chain, with the
   internal network never allowed and redirects refused rather than followed.
   Fetching an attacker-chosen address from the server is SSRF by construction;
   this is the only thing standing between a phishing email and the cloud
   metadata service. Inline `cid:` parts are still embedded straight from the
   message, with no request at all. The inherited CSP (`img-src 'self' data:`)
   means everything reaching the browser is a data URI either way.

3. **Navigation.** Every `href` is removed. The destination is kept as
   `data-url` so the interface can print it next to the link text, which is what
   an analyst actually needs — and when the visible text names one domain while
   the destination is another, the anchor is marked so the mismatch is not
   something anybody has to notice by hand.

4. **Unbounded work.** A message is attacker-sized. Every loop here is capped
   (see the constants below) and says so in the payload when it truncates,
   because a silently shortened email is a wrong one.

Attachments are described, never returned: name, declared and real MIME type,
size and SHA-256. The hash is the artifact — it goes into VirusTotal or MISP
without the sample ever reaching the analyst's disk.
"""

import email
import hashlib
import logging
import re
import time
import traceback

import bs4
import magic

import custom_analyzers
import pinned_http


log = logging.getLogger(__name__)


# --- Bounds ------------------------------------------------------------------
#
# Every one of these is a ceiling on work done over bytes an attacker chose. The
# payload reports whichever ones it hit, because an email that was cut and an
# email that was short must not look the same.

# Markup handed to the parser. Past this the HTML is cut and flagged.
MAX_HTML_BYTES = 1024 * 1024

# One inline image, and all of them together. A 5 MB "logo" is not a logo.
MAX_INLINE_IMAGE_BYTES = 512 * 1024
MAX_INLINE_TOTAL_BYTES = 4 * 1024 * 1024

# Parts walked, elements rewritten, attachments described.
MAX_PARTS = 400
MAX_ELEMENTS = 8000
MAX_ATTACHMENTS = 60

# Attachment bytes that get hashed. Past it the entry carries its size and says
# the hash was skipped rather than making the peek pay for hundreds of megabytes.
MAX_HASH_BYTES = 64 * 1024 * 1024

# Remote images. A message can name any number of them, at any size, on hosts
# that may never answer — so the count, the bytes and the wait are all capped,
# and an image that busts a cap becomes a placeholder saying which one it was.
REMOTE_IMAGE_TIMEOUT = (4, 8)
MAX_REMOTE_IMAGES = 40
MAX_REMOTE_IMAGE_BYTES = 2 * 1024 * 1024
MAX_REMOTE_TOTAL_BYTES = 8 * 1024 * 1024

# Wall clock for the whole round of fetches, and the cap that actually matters.
#
# The count and byte ceilings bound the *work*; neither bounds the *wait*. Forty
# images against a host that accepts the connection and then says nothing is
# forty read timeouts in a row — minutes, on one message, with the mailbox
# semaphore held the whole time. This was not theory: a warm-up pass sat 49
# seconds on a single old newsletter before this existed.
#
# Past the deadline the remaining images become placeholders saying so, which is
# the same contract as every other ceiling here — an email that was cut says it
# was cut.
MAX_REMOTE_SECONDS = 20

# Image types that are only images. SVG is deliberately absent: it is a document
# that can carry script and external references, and while the sandbox and the
# CSP would both stop it running, inlining a hostile document as if it were a
# picture is not something to be defended in depth against — it is something not
# to do. An SVG becomes a placeholder naming its host, like a refused fetch.
FETCHABLE_IMAGE_TYPES = frozenset([
	'image/png', 'image/jpeg', 'image/gif', 'image/webp',
	'image/bmp', 'image/x-icon', 'image/vnd.microsoft.icon', 'image/tiff',
])


# --- Allow lists -------------------------------------------------------------

# Tags kept. HTML email is table-layout email, so the table set is not optional.
#
# `html`, `head` and `body` are deliberately absent: the result is a fragment
# that the interface drops into a document of its own, and keeping a second
# `<body>` inside the first is how a renderer starts guessing. They are unwrapped
# rather than dropped, so a `<style>` block the sender put in `<head>` survives —
# most of the layout of a real HTML email lives there.
ALLOWED_TAGS = frozenset([
	'a', 'abbr', 'address', 'area', 'b', 'big', 'blockquote', 'br',
	'caption', 'center', 'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'dfn',
	'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'font', 'h1', 'h2', 'h3',
	'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins', 'kbd', 'label',
	'legend', 'li', 'map', 'mark', 'ol', 'p', 'pre', 'q', 's', 'samp', 'small',
	'span', 'strike', 'strong', 'style', 'sub', 'sup', 'table', 'tbody', 'td',
	'tfoot', 'th', 'thead', 'tr', 'tt', 'u', 'ul', 'var', 'wbr',
])

# Tags removed together with everything inside them. Unwrapping these would keep
# the payload of a `<script>` as visible text, which is worse than dropping it —
# and `<title>` would print the document title in the middle of the message.
DROP_WITH_CONTENT = frozenset([
	'script', 'noscript', 'template', 'iframe', 'frame', 'frameset', 'object',
	'embed', 'applet', 'audio', 'video', 'source', 'track', 'canvas', 'svg',
	'math', 'form', 'input', 'button', 'select', 'option', 'optgroup',
	'textarea', 'fieldset', 'base', 'link', 'meta', 'param', 'portal', 'slot',
	'dialog', 'marquee', 'title',
])

# Attributes kept, by tag. Anything not listed is dropped — including every
# `on*` handler, `srcset`, `background`, `poster`, `formaction` and `xlink:href`,
# none of which need to be enumerated because the list works the other way round.
GLOBAL_ATTRS = frozenset(['style', 'class', 'title', 'dir', 'lang', 'align', 'valign'])
TAG_ATTRS = {
	'img': frozenset(['src', 'alt', 'width', 'height', 'border', 'hspace', 'vspace']),
	'a': frozenset(['name']),
	'table': frozenset(['width', 'height', 'border', 'cellpadding', 'cellspacing', 'bgcolor']),
	'td': frozenset(['width', 'height', 'colspan', 'rowspan', 'bgcolor', 'nowrap']),
	'th': frozenset(['width', 'height', 'colspan', 'rowspan', 'bgcolor', 'nowrap']),
	'tr': frozenset(['bgcolor', 'height']),
	'col': frozenset(['width', 'span']),
	'colgroup': frozenset(['width', 'span']),
	'tbody': frozenset(['bgcolor']),
	'thead': frozenset(['bgcolor']),
	'tfoot': frozenset(['bgcolor']),
	'body': frozenset(['bgcolor', 'text']),
	'font': frozenset(['color', 'face', 'size']),
	'hr': frozenset(['width', 'size', 'noshade']),
	'ol': frozenset(['type', 'start']),
	'ul': frozenset(['type']),
	'td_': frozenset([]),
}

# `url(...)` inside a style attribute or a <style> block: same outbound request
# as an <img src>, so it gets the same treatment.
CSS_URL = re.compile(r'url\(\s*([\'"]?)([^\'")]*)\1\s*\)', re.IGNORECASE)
CSS_IMPORT = re.compile(r'@import[^;]*;', re.IGNORECASE)

# A bare domain in the visible text of a link. Used only to compare against the
# real destination — not to validate anything.
TEXT_DOMAIN = re.compile(r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b', re.IGNORECASE)

# Schemes an <img src> may carry after rewriting. Everything else (javascript:,
# vbscript:, file:, and the rest) is dropped rather than sanitized.
SAFE_IMAGE_PREFIXES = ('data:image/',)


class RemoteImageFetcher:
	"""Pulls the images a message points at, from the server, under every cap.

	One instance per render. It holds the per-render budget (count, bytes) and
	the memo of URLs already resolved, because a message that shows the same
	logo in its header and its footer must cost one request, not two.

	Every refusal is kept with its reason. An analyst looking at a placeholder
	needs to know whether the host refused, the guard refused, or the file was
	simply too big — those are three different facts about the message.
	"""

	def __init__(self):
		self.deadline = time.monotonic() + MAX_REMOTE_SECONDS
		self.by_url = {}          # url -> data URI, or None when it could not be had
		self.reasons = {}         # url -> why not
		self.fetched_hosts = {}   # host -> how many images came from it
		self.blocked_hosts = {}   # host -> how many did not
		self.total_bytes = 0
		self.count = 0

	def fetch(self, url):
		"""(data URI, None) or (None, reason). Never raises, never redirects."""
		if url in self.by_url:
			return self.by_url[url], self.reasons.get(url)
		uri, reason = self._fetch_once(url)
		self.by_url[url] = uri
		if reason:
			self.reasons[url] = reason
		host = _host_of(url)
		if host:
			bucket = self.fetched_hosts if uri else self.blocked_hosts
			bucket[host] = bucket.get(host, 0) + 1
		return uri, reason

	def _fetch_once(self, url):
		if self.count >= MAX_REMOTE_IMAGES:
			return None, 'limite de {0} imagens por e-mail'.format(MAX_REMOTE_IMAGES)
		if self.total_bytes >= MAX_REMOTE_TOTAL_BYTES:
			return None, 'limite de tamanho total atingido'
		remaining = self.deadline - time.monotonic()
		if remaining <= 0:
			return None, 'tempo de busca esgotado ({0}s por e-mail)'.format(MAX_REMOTE_SECONDS)

		# The guard chain, unchanged and not relaxed. `require_https = False`
		# because a phishing image is as often on http as on https and nothing
		# secret is being sent — the same reasoning unshorten.py applies to a
		# shortener. `allow_internal` is never passed: an address written by an
		# attacker must not be able to make this container talk to the inside of
		# the network, and the cloud metadata service stays refused regardless.
		ok, error = custom_analyzers.validate_destination(url, require_https = False)
		if not ok:
			return None, error or 'destino recusado'

		try:
			# O timeout de leitura encolhe junto com o que resta do orçamento: a
			# última imagem de uma mensagem lenta não pode esperar os 8s inteiros
			# depois de os outros 20s já terem sido gastos
			timeout = (REMOTE_IMAGE_TIMEOUT[0], min(REMOTE_IMAGE_TIMEOUT[1], remaining))
			# allow_internal não é passado aqui nem na conexão: o endereço foi escrito
			# por quem mandou o phishing, e a conexão vai para o IP que a trava
			# julgou — não para o que o DNS dele responder da segunda vez
			response = pinned_http.get(url, timeout = timeout,
				allow_redirects = False, stream = True,
				headers = {'Accept': 'image/*'})
		except pinned_http.DestinationRefused as refused:
			return None, 'destino recusado: {0}'.format(refused)
		except Exception:
			log.info('Could not fetch remote image {0}: {1}'.format(url, traceback.format_exc()))
			return None, 'o host não respondeu'

		try:
			# Refused rather than followed: the address behind a redirect never
			# passed the guard, and 169.254.169.254 is one Location header away
			if response.status_code in (301, 302, 303, 307, 308):
				return None, 'respondeu com redirecionamento, que não é seguido'
			if response.status_code != 200:
				return None, 'HTTP {0}'.format(response.status_code)

			declared = (response.headers.get('Content-Type') or '').split(';')[0].strip().lower()
			if declared and not declared.startswith('image/'):
				return None, 'respondeu {0}, que não é imagem'.format(declared)

			data = self._read_capped(response)
			if data is None:
				return None, 'maior que {0} MB'.format(MAX_REMOTE_IMAGE_BYTES // (1024 * 1024))
			if not data:
				return None, 'resposta vazia'
		finally:
			response.close()

		# The type comes from the bytes, never from what the host said they were.
		# A server that labels an HTML page as image/png is describing what it
		# wants the browser to believe, not what it sent.
		try:
			real = (magic.from_buffer(data[:8192], mime = True) or '').lower()
		except Exception:
			real = ''
		if real not in FETCHABLE_IMAGE_TYPES:
			return None, 'o conteúdo é {0}, não uma imagem exibível'.format(real or 'de tipo desconhecido')

		self.total_bytes += len(data)
		self.count += 1
		return _data_uri(real, data), None

	def _read_capped(self, response):
		"""The body, or None if it goes past the per-image ceiling.

		Read in chunks against a running total rather than by trusting
		Content-Length, which an attacker writes.
		"""
		chunks, size = [], 0
		for chunk in response.iter_content(64 * 1024):
			if not chunk:
				continue
			size += len(chunk)
			if size > MAX_REMOTE_IMAGE_BYTES:
				return None
			chunks.append(chunk)
		return b''.join(chunks)


def render(message_bytes, prefer_attachment = True, fetch_remote = True):
	"""Build the delivered-mail view of one raw RFC822 message.

	`prefer_attachment` follows the shape of the queue: when the mailbox message
	carries a forwarded `.eml`, the email the analyst is triaging is the
	attachment, not the covering note somebody wrote around it. That inner
	message is what gets rendered, and the payload says which one it picked —
	confusing the report with the reported email is the one mistake this view
	could make that would matter.

	Never raises: a message that cannot be parsed comes back as a payload with
	`error` set, exactly like an analyzer that reports `info`. The caller has an
	analyst waiting on it, and a traceback in the container log is not an answer.
	"""
	payload = _empty_payload()
	fetcher = RemoteImageFetcher() if fetch_remote else None
	try:
		outer = email.message_from_bytes(message_bytes)
	except Exception:
		log.error('Could not parse the message for rendering: {0}'.format(traceback.format_exc()))
		payload['error'] = 'unparseable'
		return payload

	target = outer
	payload['source'] = 'message'
	if prefer_attachment:
		inner = _find_attached_eml(outer)
		if inner is not None:
			target = inner
			payload['source'] = 'attachment'

	try:
		_render_into(payload, target, fetcher)
	except Exception:
		log.error('Could not render the message: {0}'.format(traceback.format_exc()))
		payload['error'] = 'render_failed'
	return payload


def _empty_payload():
	return {
		# 'attachment' when this is the forwarded .eml, 'message' when it is the
		# mailbox message itself. The interface says which, in words.
		'source': 'message',
		'headers': [],
		'html': None,
		'text': None,
		'attachments': [],
		# Hosts the message pointed at and that could not be reached — the guard
		# refused the address, the host never answered, the file was too big.
		'blockedHosts': [],
		'blockedCount': 0,
		# Hosts the server did contact, and what came back. This is the half an
		# analyst writes down: an image that renders is still an image served
		# from somebody's infrastructure.
		'fetchedHosts': [],
		'fetchedCount': 0,
		'fetchedBytes': 0,
		'inlineCount': 0,
		# Every ceiling this render hit, so the interface can say what is missing
		# instead of showing a shortened email as a whole one.
		'truncated': [],
		'error': None,
	}


def _find_attached_eml(msg):
	"""The forwarded report inside a covering message, or None.

	Mirrors what `list_emails._process_one_message` accepts, including the
	`application/octet-stream` case: mail clients disagree about how to label a
	forwarded `.eml`, and the analyst should not have to care which one the
	reporter used.
	"""
	seen = 0
	for part in msg.walk():
		seen += 1
		if seen > MAX_PARTS:
			return None
		mimetype = part.get_content_type()
		if mimetype == 'message/rfc822':
			payload = part.get_payload()
			if isinstance(payload, list) and payload:
				return payload[0]
		elif mimetype == 'application/octet-stream':
			try:
				raw = part.get_payload(decode = True)
			except Exception:
				continue
			if not raw:
				continue
			# Same guard as the listing: only treat it as a forwarded email when
			# the decoded bytes really are one
			try:
				if magic.from_buffer(raw, mime = True) not in ['text/plain', 'message/rfc822']:
					continue
			except Exception:
				continue
			try:
				return email.message_from_bytes(raw)
			except Exception:
				continue
	return None


def _render_into(payload, msg, fetcher):
	html_part = None
	text_part = None
	inline = {}
	inline_total = 0
	seen = 0

	for part in msg.walk():
		seen += 1
		if seen > MAX_PARTS:
			payload['truncated'].append('parts')
			break
		if part.get_content_maintype() == 'multipart':
			continue

		mimetype = part.get_content_type()
		disposition = (part.get_content_disposition() or '').lower()
		filename = part.get_filename()

		# An inline image referenced from the markup by Content-ID. Embedded as a
		# data URI so a real letterhead renders with no request made.
		cid = (part.get('Content-ID') or '').strip().strip('<>')
		if part.get_content_maintype() == 'image' and (cid or disposition == 'inline'):
			data = _payload_bytes(part)
			if data is None:
				continue
			if len(data) > MAX_INLINE_IMAGE_BYTES:
				payload['truncated'].append('inline_image_size')
				continue
			if inline_total + len(data) > MAX_INLINE_TOTAL_BYTES:
				payload['truncated'].append('inline_total_size')
				continue
			inline_total += len(data)
			uri = _data_uri(mimetype, data)
			if cid:
				inline['cid:' + cid.lower()] = uri
			if filename:
				inline['cid:' + filename.lower()] = uri
			continue

		if disposition == 'attachment' or (filename and mimetype not in ('text/plain', 'text/html')):
			_describe_attachment(payload, part, filename, mimetype)
			continue

		if mimetype == 'text/html' and html_part is None:
			html_part = _decode_text(part)
		elif mimetype == 'text/plain' and text_part is None:
			text_part = _decode_text(part)

	# A forwarded .eml nested one level deeper is an attachment of the email
	# being read, and the analyst needs its hash like any other
	payload['headers'] = _headers(msg)
	payload['text'] = text_part
	payload['inlineCount'] = len(set(inline.values()))

	if html_part is not None:
		if len(html_part) > MAX_HTML_BYTES:
			html_part = html_part[:MAX_HTML_BYTES]
			payload['truncated'].append('html')
		payload['html'] = _sanitize(payload, html_part, inline, fetcher)


def _payload_bytes(part):
	try:
		return part.get_payload(decode = True)
	except Exception:
		return None


def _decode_text(part):
	raw = _payload_bytes(part)
	if raw is None:
		return None
	charset = part.get_content_charset()
	for candidate in [charset, 'utf-8', 'ISO-8859-1']:
		if not candidate:
			continue
		try:
			return raw.decode(candidate)
		except Exception:
			continue
	return raw.decode('utf-8', 'replace')


def _data_uri(mimetype, data):
	import base64
	return 'data:{0};base64,{1}'.format(mimetype, base64.b64encode(data).decode('ascii'))


def _headers(msg):
	"""The envelope of the message actually being rendered.

	Shown above the body because the point of this view is "as it was
	delivered", and a delivered email is its header block plus its body. The
	fields are the ones a triage decision turns on; the decoding is
	`email_provider`'s, so a non-ASCII display name arrives whole.
	"""
	import email_provider
	fields = [
		('De', 'From'),
		('Para', 'To'),
		('Responder para', 'Reply-To'),
		('Assunto', 'Subject'),
		('Data', 'Date'),
	]
	out = []
	for label, name in fields:
		try:
			value = email_provider.decode_header_field(msg.get(name))
		except Exception:
			value = msg.get(name)
		if value:
			out.append({'label': label, 'value': str(value)})
	return out


def _describe_attachment(payload, part, filename, declared_mime):
	"""Name, real type, size and SHA-256 — never the bytes.

	The hash is what an analyst pastes into VirusTotal or MISP. Returning the
	file instead would put a live sample on the workstation of the person whose
	job is to not run it, and some browsers would open it on the way down.

	The declared MIME type is kept next to the one `magic` reads off the content,
	because a `.pdf` that is really a `application/x-dosexec` is not a detail —
	it is the finding.
	"""
	if len(payload['attachments']) >= MAX_ATTACHMENTS:
		if 'attachments' not in payload['truncated']:
			payload['truncated'].append('attachments')
		return
	data = _payload_bytes(part)
	if data is None:
		return
	entry = {
		'name': filename or '(sem nome)',
		'declaredType': declared_mime or '',
		'realType': '',
		'size': len(data),
		'sha256': '',
	}
	try:
		entry['realType'] = magic.from_buffer(data[:8192], mime = True) or ''
	except Exception:
		entry['realType'] = ''
	if len(data) <= MAX_HASH_BYTES:
		entry['sha256'] = hashlib.sha256(data).hexdigest()
	payload['attachments'].append(entry)


# --- Sanitizer ---------------------------------------------------------------

def _sanitize(payload, html, inline, fetcher):
	"""Allow-list the markup and neutralize every way out of the frame."""
	soup = bs4.BeautifulSoup(html, 'html.parser')

	for tag in soup.find_all(list(DROP_WITH_CONTENT)):
		tag.decompose()

	# Comments can carry conditional markup that some renderers act on
	for node in soup.find_all(string = lambda s: isinstance(s, bs4.Comment)):
		node.extract()

	blocked = {}
	seen = 0
	for tag in soup.find_all(True):
		seen += 1
		if seen > MAX_ELEMENTS:
			if 'elements' not in payload['truncated']:
				payload['truncated'].append('elements')
			break

		name = (tag.name or '').lower()
		if name not in ALLOWED_TAGS:
			# Kept as its contents: an unknown wrapper is layout, and dropping
			# the text inside it would silently shorten the email
			tag.unwrap()
			continue

		if name == 'style':
			# Not get_text(): since bs4 4.9 it deliberately skips the contents of
			# <style> and <script>, so reading a stylesheet that way returns the
			# empty string and every url() inside it sails through unexamined.
			# The result goes back as a Stylesheet node for the same class of
			# reason — a plain string would be HTML-escaped on output and
			# `td > p` would come out as `td &gt; p`
			cleaned = _clean_css(tag.decode_contents(), blocked)
			tag.clear()
			tag.append(_css_node(cleaned))
			continue

		_clean_attributes(soup, tag, name, inline, blocked, fetcher)

	payload['blockedHosts'] = [
		{'host': host, 'count': blocked[host]}
		for host in sorted(blocked, key = lambda h: (-blocked[h], h))
	]
	payload['blockedCount'] = sum(blocked.values())

	if fetcher is not None:
		payload['fetchedHosts'] = [
			{'host': host, 'count': fetcher.fetched_hosts[host]}
			for host in sorted(fetcher.fetched_hosts, key = lambda h: (-fetcher.fetched_hosts[h], h))
		]
		payload['fetchedCount'] = fetcher.count
		payload['fetchedBytes'] = fetcher.total_bytes

	return str(soup)


def _clean_attributes(soup, tag, name, inline, blocked, fetcher):
	allowed = GLOBAL_ATTRS | TAG_ATTRS.get(name, frozenset())

	# `href` never survives, but the destination is the single most useful thing
	# in a phishing email — so it is carried as data and printed next to the
	# link text instead of being followed
	href = None
	if name == 'a':
		href = (tag.get('href') or '').strip()

	for attribute in list(tag.attrs.keys()):
		if attribute.lower() not in allowed:
			del tag.attrs[attribute]

	if 'style' in tag.attrs:
		tag.attrs['style'] = _clean_css(tag.attrs['style'], blocked)

	if name == 'img':
		_clean_image(soup, tag, inline, blocked, fetcher)

	if name == 'a':
		_annotate_link(tag, href)


def _clean_image(soup, tag, inline, blocked, fetcher):
	src = (tag.get('src') or '').strip()
	lowered = src.lower()

	if lowered.startswith('cid:'):
		embedded = inline.get(lowered)
		if embedded:
			tag['src'] = embedded
			tag['class'] = _add_class(tag, 'bp-inline')
			return
		# Referenced but not present in the message: an image nobody can show
		_replace_with_placeholder(soup, tag, 'bp-missing', 'imagem embutida ausente')
		return

	if lowered.startswith(SAFE_IMAGE_PREFIXES):
		tag['class'] = _add_class(tag, 'bp-inline')
		return

	# A remote image. The server goes and gets it — see the module docstring for
	# why it is the server and not the browser, and for the guard chain the URL
	# has to clear on the way.
	host = _host_of(src)
	if fetcher is not None:
		uri, reason = fetcher.fetch(src)
		if uri:
			tag['src'] = uri
			tag['class'] = _add_class(tag, 'bp-remote')
			# The host stays on the element. An image that renders is still an
			# image that came from somewhere, and where from is the part of it
			# an analyst may need to write down
			tag['data-note'] = host or 'origem remota'
			return
		# Could not be had. The placeholder carries the reason, because "the
		# guard refused this address", "the host never answered" and "it was too
		# big" are three different facts about the message
		if host:
			blocked[host] = blocked.get(host, 0) + 1
		_replace_with_placeholder(soup, tag, 'bp-blocked',
			(host or 'origem remota') + ' · ' + (reason or 'não pôde ser carregada'))
		return

	# Fetching switched off for this render: the element is replaced rather than
	# blanked, because the useful thing is then not the picture but the host the
	# message wanted to contact — often the only piece of the sender's
	# infrastructure that appears anywhere in the message — and an element with a
	# `src` cannot show text.
	if host:
		blocked[host] = blocked.get(host, 0) + 1
	_replace_with_placeholder(soup, tag, 'bp-blocked', host or 'origem remota')


def _replace_with_placeholder(soup, tag, class_name, note):
	placeholder = soup.new_tag('span')
	placeholder['class'] = [class_name]
	alt = (tag.get('alt') or '').strip()
	placeholder.string = (alt + ' · ' + note) if alt else note
	tag.replace_with(placeholder)


def _annotate_link(tag, href):
	if not href:
		return
	lowered = href.lower()
	if lowered.startswith(('javascript:', 'vbscript:', 'data:')):
		tag['data-url'] = '(esquema bloqueado) ' + href[:200]
		tag['class'] = _add_class(tag, 'bp-link bp-mismatch')
		return
	if lowered.startswith('#') or lowered.startswith('cid:'):
		return

	tag['data-url'] = href[:400]
	classes = 'bp-link'

	# The classic tell: the text says one domain, the destination is another.
	# Marking it here is not a verdict — it is the comparison an analyst would
	# make by hand on every link, done for all of them at once.
	destination = _host_of(href)
	text = tag.get_text(' ', strip = True)
	claimed = TEXT_DOMAIN.search(text or '')
	if destination and claimed:
		claimed_host = claimed.group(1).lower()
		if not _same_site(claimed_host, destination):
			classes += ' bp-mismatch'
	tag['class'] = _add_class(tag, classes)


def _same_site(a, b):
	"""Registrable-domain comparison, deliberately loose.

	This decides whether to draw attention, never whether something is
	malicious, so the last two labels are enough: `mail.google.com` and
	`google.com` do not deserve a warning, `bradesco.com.br.secure-login.tk`
	does. A public-suffix list would make it stricter; nothing downstream acts on
	the answer, so the dependency is not worth carrying.
	"""
	a_parts = a.lower().split('.')
	b_parts = b.lower().split('.')
	return a_parts[-2:] == b_parts[-2:]


def _host_of(url):
	try:
		import urllib.parse
		parsed = urllib.parse.urlparse(url)
		return (parsed.hostname or '').lower()
	except Exception:
		return ''


def _clean_css(css, blocked):
	"""Strip anything in CSS that reaches the network.

	`url()` in a stylesheet is the same beacon as an `<img src>`, and `@import`
	is worse — it pulls a whole stylesheet. Both are counted against the same
	host list, so the blocked-hosts line covers the message rather than just its
	images.
	"""
	if not css:
		return ''
	css = CSS_IMPORT.sub('', css)

	def replace(match):
		value = (match.group(2) or '').strip()
		if value.lower().startswith('data:image/'):
			return match.group(0)
		host = _host_of(value)
		if host:
			blocked[host] = blocked.get(host, 0) + 1
		return 'none'

	return CSS_URL.sub(replace, css)


def _css_node(css):
	"""CSS as a node the serializer will not HTML-escape."""
	try:
		return bs4.element.Stylesheet(css)
	except AttributeError:
		return bs4.element.NavigableString(css)


def _add_class(tag, extra):
	existing = tag.get('class') or []
	if isinstance(existing, str):
		existing = existing.split()
	for name in extra.split():
		if name not in existing:
			existing.append(name)
	return existing
