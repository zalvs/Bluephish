import logging.config
import io
import os
import json
import config_file
import base64
import bs4
import hashlib
import ipaddress
import re
import time
import email
import emoji
import urllib.parse
import traceback
import eventlet
import analyzers
import ioc_extract
import email_provider
import spam_headers
import whitelist
import whitelist_state

# Global variable used for logging
log = None

# Global variable needed to use the API

# Global variable used for the configuration.
#
# `main()` preenche este dicionario chave a chave e nunca o reatribui, entao ele
# nao declara `global config` — mutar um objeto do modulo dispensa a declaracao,
# e a declaracao a mais nao e inofensiva: ela afirma uma reatribuicao que nao
# acontece, e o flake8 do CI a reprova (F824). Se algum dia for preciso trocar o
# dicionario inteiro (`config = {...}`), ai sim a declaracao volta, junto com a
# atribuicao — sem ela o nome viraria local e a configuracao ficaria vazia em
# silencio.
config = {}

# O conjunto de regras carregado para esta análise (whitelist.Ruleset). Fica
# global pelo mesmo motivo que o `whitelist` do v1 ficava: a extração acontece
# em funções espalhadas por este arquivo. A diferença é que agora só existe um
# matcher, aqui e no run_analysis — o v1 tinha dois, com regras sutilmente
# diferentes (case_from_email.is_whitelisted e run_analysis.is_url_whitelisted)
ruleset = whitelist.empty_ruleset()

# Os observables vistos nesta análise, por tipo. Alimentam o histórico curto de
# que a simulação de uma regra nova precisa (whitelist_state.dry_run)
seen_observables = {'domain': [], 'url': [], 'hash': [], 'ip': []}
# O mesmo conteúdo em conjunto: procurar na lista a cada observável é quadrático,
# e quem decide quantos domínios um e-mail traz é quem o escreveu
_seen_index = {key: set() for key in seen_observables}


def reset_seen_observables():
	for key, values in seen_observables.items():
		del values[:]
		_seen_index[key].clear()


def _remember(obs_type, value):
	values = seen_observables.get(obs_type)
	if values is not None and value not in _seen_index[obs_type]:
		_seen_index[obs_type].add(value)
		values.append(value)


# Uma regra que suprime observable também conta como uso: é o que faz a interface
# saber quais regras ainda servem para alguma coisa e quais viraram entulho
def _suppressed_by(match, obs_type, obs_value, wsl):
	if not match:
		return False
	log.info("Skipped whitelisted observable {0}: {1} (regra {2})".format(obs_type, obs_value, match.rule_id))
	wsl.emit_info("Skipped whitelisted observable {0}: {1}".format(obs_type, obs_value))
	whitelist_state.record_match(match.rule_id)
	return True


# Limits for the images sent to the LLM for the visual analysis.
# Only images that travel inside the email (attached or embedded/inline) are
# collected: a remote image is merely a URL in the HTML and never a MIME part,
# so walking the parts excludes it by construction. Images below the minimum
# size are tracking pixels, spacers and bullets, and the count/total size are
# capped so a newsletter full of graphics cannot blow up the request
IMAGE_MIN_BYTES = 8 * 1024
IMAGE_MAX_COUNT = 3
IMAGE_MAX_TOTAL_BYTES = 4 * 1024 * 1024


# Collect one embedded/attached image part for the visual analysis, unless its
# SHA256 is whitelisted. Recurring images such as a corporate signature logo are
# whitelisted once by hash (Settings > Data & Tuning > Whitelist, "Exact - hash")
# and then never sent to the model again
def collect_image_part(part, images, wsl):
	if len(images) >= IMAGE_MAX_COUNT:
		return
	try:
		payload = part.get_payload(decode=True)
	except Exception:
		return
	if not payload or len(payload) < IMAGE_MIN_BYTES:
		return
	if sum(image['bytes'] for image in images) + len(payload) > IMAGE_MAX_TOTAL_BYTES:
		return
	digest = hashlib.sha256(payload).hexdigest()
	filename = part.get_filename() or '(inline image)'
	_remember('hash', digest)
	image_match = ruleset.match_hash(digest)
	if image_match:
		log.info("Skipped whitelisted image {0} (sha256 {1})".format(filename, digest))
		wsl.emit_info("Skipped whitelisted image {0} (sha256 {1})".format(filename, digest))
		whitelist_state.record_match(image_match.rule_id)
		return
	images.append({
		'mimetype': part.get_content_type(),
		'name': filename,
		'sha256': digest,
		'bytes': len(payload),
		'base64': base64.b64encode(payload).decode()
	})
	# The hash is logged so the analyst can whitelist a recurring image (a
	# signature logo, a newsletter header) straight from the analysis output
	log.info("Found image {0} ({1} bytes) for the visual analysis, sha256 {2}".format(filename, len(payload), digest))
	wsl.emit_info("Found image {0} ({1} bytes) for the visual analysis, sha256 {2}".format(filename, len(payload), digest))


# Extract the SPF / DKIM / DMARC results that the receiving mail server recorded
# in the message headers, plus the domain alignment between the DKIM signature
# and the From address (the check DMARC itself performs).
#
# Only the FIRST Authentication-Results header is read: it is the one added by
# the server that received the message. Any further header of the same name
# travelled with the message and can be forged by the sender, so trusting it
# would let an attacker declare their own phishing "authenticated".
def extract_authentication_results(msg):
	auth = {
		'spf': 'none', 'dkim': 'none', 'dmarc': 'none',
		'fromAddress': '', 'fromDomain': '', 'dkimDomain': '', 'replyTo': '',
		'aligned': False, 'authenticated': False, 'raw': ''
	}

	# Domain of the From address, used for the alignment check.
	# O endereço inteiro e o Reply-To viajam junto porque é deles que a regra de
	# remetente confiável precisa: a confiança é por caixa, e um From confiável
	# com resposta indo para fora é BEC clássico (whitelist.Ruleset.match_sender)
	try:
		from_address = email.utils.parseaddr(str(msg.get('From', '')))[1]
		auth['fromAddress'] = (from_address or '').strip().strip('>').lower()
		if '@' in from_address:
			auth['fromDomain'] = from_address.rsplit('@', 1)[1].strip().lower().strip('>')
	except Exception:
		pass
	try:
		auth['replyTo'] = (email.utils.parseaddr(str(msg.get('Reply-To', '')))[1] or '').strip().lower()
	except Exception:
		pass

	headers = msg.get_all('Authentication-Results') or []
	if headers:
		raw = ' '.join(str(headers[0]).split())
		auth['raw'] = raw[:400]
		dkim_entries = []
		for segment in raw.split(';'):
			match = re.match(r'\s*(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)', segment.strip(), re.IGNORECASE)
			if not match:
				continue
			method = match.group(1).lower()
			verdict = match.group(2).lower()
			if method == 'dkim':
				domain_match = re.search(r'header\.i=@?([A-Za-z0-9._-]+)', segment)
				dkim_entries.append((verdict, domain_match.group(1).lower() if domain_match else ''))
			elif method == 'spf':
				# Keep a pass over a weaker result when the server reports several
				if auth['spf'] == 'none' or verdict == 'pass':
					auth['spf'] = verdict
			elif method == 'dmarc':
				auth['dmarc'] = verdict
		# A message can carry several DKIM signatures (e.g. the brand and its ESP):
		# it counts as signed when at least one passes, and as aligned when a
		# passing signature belongs to the From domain (or a parent/subdomain of it)
		if dkim_entries:
			auth['dkim'] = 'pass' if any(v == 'pass' for v, _d in dkim_entries) else dkim_entries[0][0]
			for verdict, domain in dkim_entries:
				if verdict != 'pass' or not domain or not auth['fromDomain']:
					continue
				if domain == auth['fromDomain'] or auth['fromDomain'].endswith('.' + domain) or domain.endswith('.' + auth['fromDomain']):
					auth['aligned'] = True
					auth['dkimDomain'] = domain
					break
			if not auth['dkimDomain'] and dkim_entries[0][1]:
				auth['dkimDomain'] = dkim_entries[0][1]
	else:
		# No Authentication-Results: fall back to the Received-SPF header, which is
		# also written by the receiving server
		spf_headers = msg.get_all('Received-SPF') or []
		if spf_headers:
			match = re.match(r'\s*([A-Za-z]+)', str(spf_headers[0]))
			if match:
				auth['spf'] = match.group(1).lower()

	# DMARC pass already implies an aligned, authenticated sender; otherwise the
	# email counts as authenticated only when a DKIM signature of the From domain
	# itself passed. SPF alone is not enough: it validates the envelope sender,
	# which a phishing campaign controls independently of the displayed From
	auth['authenticated'] = auth['dmarc'] == 'pass' or (auth['dkim'] == 'pass' and auth['aligned'])
	return auth


def _is_public_ip(value):
	try:
		address = ipaddress.ip_address(str(value).strip())
	except ValueError:
		return False
	return not (address.is_private or address.is_loopback or address.is_link_local
		or address.is_reserved or address.is_multicast or address.is_unspecified)


# Quanto a extração de uma mensagem inteira pode durar. Não é o custo normal (1 MB
# de texto leva poucos segundos): é o teto para o que nenhuma regra de
# `ioc_extract` previu, porque a extração segura o `analysis_semaphore`, e com ele
# a leitura da caixa. Estourar não descarta a análise: ela segue com o que foi
# achado e não pode fechar como Safe (run_analysis.terminate_analysis)
EXTRACTION_BUDGET_SECONDS = 45

# A cada quantos observáveis o laço devolve a vez ao resto do servidor
YIELD_EVERY_OBSERVABLES = 200


def _cooperatively(items):
	"""Percorre `items` sem prender o hub quando um e-mail traz milhares deles."""
	for index, item in enumerate(items, 1):
		yield item
		if index % YIELD_EVERY_OBSERVABLES == 0:
			eventlet.sleep(0)


def _html_text(html):
	return bs4.BeautifulSoup(html, 'html.parser').get_text(separator = ' ', strip = True)


# Extract observables from a string buffer and add to the list only if they are
# not whitelisted. -> (observables, whether the whole buffer was read)
#
# A extração roda fora do hub (`analyzers.run_off_hub`): é CPU pura sobre texto do
# atacante, e no hub ela pararia a interface, o log e a leitura da caixa. Só ela
# vai para a thread; o resto emite no websocket, e isso é trabalho do hub
def search_observables(buffer, wsl, deadline):
	# A header value parsed from a malformed email (non-ASCII bytes in a header
	# declared us-ascii) comes back as an email.header.Header object rather than
	# a plain str, and ioc_finder calls .lower() on it. Coerce to its decoded
	# string form so the extraction never crashes (a no-op on real strings).
	buffer = str(buffer)
	observables = []
	iocs = analyzers.run_off_hub(ioc_extract.extract, buffer, deadline)
	# Endereços e IPs não são mais suprimíveis. No v1 uma entrada de `mail`
	# significava "não extraia este endereço"; no v2 remetente é confiança, não
	# conveniência, e ela é decidida no veredito, depois de a análise inteira ter
	# rodado. Suprimir o endereço aqui apagaria o observable de que essa decisão
	# precisa
	for mail in _cooperatively(iocs.email_addresses):
		log.info("Found observable mail: {0}".format(mail))
		wsl.emit_info("Found observable mail: {0}".format(mail))
		observables.append({'type': 'mail', 'value': mail})
	for ip in _cooperatively(iocs.ipv4s):
		# Endereço que não é roteável na internet nunca vai para analisador de
		# reputação, e isso não é regra de whitelist nem deve ser configurável:
		# nenhum serviço tem opinião sobre 192.168.0.10, e mandar a topologia
		# interna para fora é vazamento sem contrapartida. Por isso a regra de IP
		# só aceita endereço roteável — para o resto ela seria decorativa
		if not _is_public_ip(ip):
			log.info("Skipped non-public ip: {0}".format(ip))
			continue
		_remember('ip', ip)
		if _suppressed_by(ruleset.match_ip(ip), 'ip', ip, wsl):
			continue
		log.info("Found observable ip: {0}".format(ip))
		wsl.emit_info("Found observable ip: {0}".format(ip))
		observables.append({'type': 'ip', 'value': ip})
	# O id de pacote de um link de loja de aplicativo tem forma de domínio e não é
	# domínio de ninguém (ver ioc_noise.py): mandado a um analisador de reputação,
	# ele só produz ruído sobre uma marca legítima
	for domain in _cooperatively(iocs.domains):
		if domain in iocs.package_only:
			log.info("Skipped an app store package id that looks like a domain: {0}".format(domain))
			continue
		_remember('domain', domain)
		if _suppressed_by(ruleset.match_domain(domain), 'domain', domain, wsl):
			continue
		log.info("Found observable domain: {0}".format(domain))
		wsl.emit_info("Found observable domain: {0}".format(domain))
		observables.append({'type': 'domain', 'value': domain})
	for url in _cooperatively(iocs.urls):
		_remember('url', url)
		if _suppressed_by(ruleset.match_url(url), 'url', url, wsl):
			continue
		log.info("Found observable url: {0}".format(url))
		wsl.emit_info("Found observable url: {0}".format(url))
		observables.append({'type': 'url', 'value': url})
	return observables, iocs.complete


# Parse the raw message fetched by the provider and extract the internal EML attachment
def obtain_eml(message, mail_uid, wsl):

		# The provider fetch marks the message as read
		log.info("Message {0} flagged as read".format(mail_uid))
		wsl.emit_info("Message {0} flagged as read".format(mail_uid))

		# Obtain the From field of the external email that will be used to send the verdict to the user
		msg = email.message_from_bytes(message)
		decode = email.header.decode_header(msg['From'])[0]
		if decode[1] is not None:
			external_from_field = decode[0].decode(decode[1])
		else:
			external_from_field = str(decode[0])
		parsed_from_field = email.utils.parseaddr(external_from_field)
		if len(parsed_from_field) > 1:
			external_from_field = parsed_from_field[1]

		# Variable used to detect the mimetype of the email parts
		mimetype = None

		# Variable that will contain the internal EML file
		internal_msg = None
		
		# Walk the multipart structure of the email (now only the EML part is needed)
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
				elif mimetype == 'message/rfc822':
					eml_payload = part.get_payload(decode=0)[0]
					try:
						internal_msg = email.message_from_string(base64.b64decode(str(eml_payload)).decode())
					except:
						internal_msg = eml_payload

				# If the EML attachment has been found, then break the for
				break

		return internal_msg, external_from_field


# "Raw" analysis: the mailbox email itself is the email to analyze
# The raw RFC822 source fetched by the provider is written to a temporary .eml
# file in the working directory and parsed from there, so that the rest of the
# pipeline consumes it exactly as if it had arrived as an attachment. The
# operation is strictly read-only towards the mail server: the provider fetch
# only downloads the MIME source (and flags the message as read), the original
# email is never modified or deleted
def obtain_raw_eml(message, mail_uid, wsl, log_read = True):

	# The provider fetch marks the message as read
	# (already logged by obtain_eml when this is a fallback call)
	if log_read:
		log.info("Message {0} flagged as read".format(mail_uid))
		wsl.emit_info("Message {0} flagged as read".format(mail_uid))

	# Write the raw source to a temporary .eml file in the working directory
	# The analyses are serialized by the application semaphore, so a fixed name
	# cannot collide; the file is removed after the message has been parsed
	temp_eml_path = 'raw_message_under_analysis.eml'
	with open(temp_eml_path, 'wb') as temp_eml_file:
		temp_eml_file.write(message)
	log.info("Raw email source saved to temporary file {0} ({1} bytes)".format(temp_eml_path, len(message)))
	wsl.emit_info("Raw email source saved to a temporary .eml file ({0} bytes)".format(len(message)))

	# Parse the message back from the temporary file
	try:
		with open(temp_eml_path, 'rb') as temp_eml_file:
			internal_msg = email.message_from_binary_file(temp_eml_file)
	finally:
		try:
			os.remove(temp_eml_path)
		except OSError:
			pass

	# In raw mode there is no external "reporter" email: the caller replaces the
	# notification target with the monitored mailbox address
	return internal_msg, None



# Parse the EML file and extract the observables
def parse_eml(internal_msg, wsl):

	# Obtain the subject of the internal email
	# This is not straightforward since the subject might be splitted in two or more parts
	decode_subj = email.header.decode_header(internal_msg['Subject'])
	decoded_elements_subj = []
	for decode_elem in decode_subj:
		if decode_elem[1] is not None:
			if str(decode_elem[1]) == 'unknown-8bit':
				decoded_elements_subj.append(decode_elem[0].decode())
			else:
				decoded_elements_subj.append(decode_elem[0].decode(decode_elem[1]))
		else:
			if(isinstance(decode_elem[0], str)):
				decoded_elements_subj.append(str(decode_elem[0]))
			else:
				decoded_elements_subj.append(decode_elem[0].decode())
		subject_field = ''.join(decoded_elements_subj)

	log.info("Analyzing attached message with subject: {}".format(subject_field))
	wsl.emit_info("Analyzing attached message with subject: {}".format(subject_field))

	# List of attachments of the internal email
	attachments = []

	# List of attachment hashes
	hashes_attachments = []

	# List of observables found in the body of the internal email
	observables_body = []

	# Lists of clean text fragments extracted from the body parts
	# They are used to build the body text sent to the LLM for the social engineering analysis
	body_text_parts = []
	html_text_parts = []

	# Embedded/attached images collected for the visual analysis performed by the LLM
	images = []

	# Um orçamento para a mensagem inteira, e não por campo: um por campo seria
	# multiplicado pelo número de cabeçalhos `Received` que o remetente escrevesse
	deadline = time.monotonic() + EXTRACTION_BUDGET_SECONDS
	extraction_complete = True

	def scan(text):
		nonlocal extraction_complete
		found, complete = search_observables(text, wsl, deadline)
		extraction_complete = extraction_complete and complete
		return found

	# Dictionary containing a list of observables found in each header field
	observables_header = {}

	# List of header fields to consider when searching for observables in the header
	header_fields_list = [
		'To', 
		'From', 
		'Sender',
		'Cc',
		'Delivered-To',
		'Return-Path', 
		'Reply-To',
		'Bounces-to',
		'Received', 
		'X-Received', 
		'X-OriginatorOrg', 
		'X-Sender-IP', 
		'X-Originating-IP',
		'X-SenderIP',
		'X-Originating-Email'
	]
	
	# Extract header fields
	# The bytes-based parser/serializer pair is used on purpose: real phishing
	# emails are often malformed (e.g. a part declared us-ascii that carries
	# non-ASCII bytes), and the str-based as_string() re-encodes the payloads,
	# raising UnicodeEncodeError on such messages. as_bytes() writes the raw
	# payload through untouched.
	parser = email.parser.BytesHeaderParser()
	header_fields = parser.parsebytes(internal_msg.as_bytes())

	# Search the observables in the values of all the selected header fields
	# Since a field may appear more than one time (e.g. Received:), the lists need to be initialized and then extended
	#
	# Uma passada só: `keys()` e `values()` remontam a lista inteira a cada chamada,
	# e indexar por elas num laço era quadrático no número de cabeçalhos, que quem
	# escolhe é o remetente
	for header_name, header_value in header_fields.items():
		if header_name in header_fields_list:
			observables_header.setdefault(header_name, []).extend(scan(header_value))
	
	# Walk the multipart structure of the internal email
	for part in internal_msg.walk():
		mimetype = part.get_content_type()
		content_disposition = part.get_content_disposition()
		# Images that travel with the email (attached or inline) are collected for
		# the visual analysis, independently of the attachment handling below
		if part.get_content_maintype() == 'image':
			collect_image_part(part, images, wsl)
		if content_disposition != "attachment":
			# Extract the observables from the body (from both text/plain and text/html parts) using the search_observables function
			if mimetype == "text/plain":
				try:
					body = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					body = part.get_payload(decode=True).decode('ISO-8859-1')
				observables_body.extend(scan(body))
				body_text_parts.append(body)
			elif mimetype == "text/html":
				try:
					html = part.get_payload(decode=True).decode()
				except UnicodeDecodeError:
					html = part.get_payload(decode=True).decode('ISO-8859-1')
				# Handle URL encoding
				html_urldecoded = urllib.parse.unquote(html.replace("&amp;", "&"))
				observables_body.extend(scan(html_urldecoded))
				# Extract the clean text from the HTML part for the social engineering analysis
				html_text_parts.append(analyzers.run_off_hub(_html_text, html))
		# Extract attachments
		else:
			filename = part.get_filename()
			if filename and mimetype:
				# O anexo é liberado por SHA-256, e só. Os tipos `filename` e
				# `filetype` do v1 saíram do modelo: liberar por nome é liberar o
				# que quem ataca escolhe chamar de `fatura.pdf`, e liberar por MIME
				# libera todo anexo daquele formato de uma vez
				payload = part.get_payload(decode=1)
				sha256 = hashlib.sha256()
				sha256.update(payload)
				digest = sha256.hexdigest()
				_remember('hash', digest)
				if _suppressed_by(ruleset.match_hash(digest), 'hash', digest, wsl):
					continue
				inmem_file = io.BytesIO(payload)
				attachments.append((inmem_file, filename))
				log.info("Found observable file: {0}".format(filename))
				wsl.emit_info("Found observable file: {0}".format(filename))
				hashes_attachments.append({'hashValue': digest, 'hashedAttachment': filename})
				log.info("Found observable hash {0} calculated from file: {1}".format(digest, filename))
				wsl.emit_info("Found observable hash {0} calculated from file: {1}".format(digest, filename))

	if not extraction_complete:
		log.warning("Indicator extraction did not finish within {0} s: the analysis continues with what was found".format(EXTRACTION_BUDGET_SECONDS))
		wsl.emit_warning("A extração de indicadores não terminou no tempo limite: a análise segue com o que foi "
			"encontrado, e este e-mail não será classificado como seguro.")

	# Create a tuple containing the eml file and the name it should have as an observable
	filename = subject_field + ".eml"
	inmem_file = io.BytesIO()
	gen = email.generator.BytesGenerator(inmem_file)
	gen.flatten(internal_msg)
	eml_file_tuple = (inmem_file, filename)

	# Workaround to prevent HTML tags to appear inside the URLs (splits on < or >)
	for observable_body in observables_body:
		if observable_body['type'] == "url":
			observable_body['value'] = observable_body['value'].replace(">", "<").split("<")[0]

	# Build the clean body text used for the social engineering analysis
	# The text/plain parts are preferred, with the text extracted from the HTML parts as fallback
	email_body = '\n'.join(body_text_parts).strip()
	if not email_body:
		email_body = '\n'.join(html_text_parts).strip()

	return subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, email_body, images, extraction_complete


# Turn everything parse_eml found into one flat list of observables.
#
# This used to be create_case(): the observables were pushed straight into a
# TheHive case, and the analysis then read them back from there. TheHive was
# therefore intermediate storage for data this process already had in memory,
# which is what made it impossible to run without it.
#
# Now they stay here, and TheHive is a place the finished analysis is *recorded*
# (tickets.py), like Jira or the disk. The shape below is the contract the whole
# pipeline speaks:
#
#   id        local and stable for this analysis only — the analyzers key their
#             reports to it, nothing outside this run ever sees it
#   type      'url' | 'domain' | 'ip' | 'mail' | 'hash' | 'file' |
#             'file_message/rfc822' (the forwarded .eml, which only YARA judges)
#   name      the value itself, or the filename when it is a file
#   content   the bytes, for a file observable — this is what lets YARA run and
#             the disk destination store the attachment without asking anybody
#   ioc       filled in later, once the analyzers have spoken
def collect_observables(observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl):

	observables = []

	def add(observable_type, name, tags, message, content = None):
		observables.append({
			'id': 'obs-{0}'.format(len(observables)),
			'type': observable_type,
			'name': name,
			'tags': tags,
			'message': message,
			'content': content,
			'ioc': False
		})

	# Found in the mail header
	for header_field in observables_header:
		for observable_header in observables_header[header_field]:
			add(observable_header['type'], observable_header['value'],
				['email', 'email_header', 'email_header_{}'.format(header_field)],
				'Found in the {} field of the email header'.format(header_field))

	# Found in the mail body
	for observable_body in observables_body:
		add(observable_body['type'], observable_body['value'],
			['email', 'email_body'], 'Found in the email body')

	# Attachments, carried as bytes so that nothing has to be downloaded later
	for attachment in attachments:
		add('file', attachment[1], ['email', 'email_attachment'],
			'Found as email attachment', attachment[0].getvalue())

	# Hashes of those attachments
	for hash_attachment in hashes_attachments:
		add('hash', hash_attachment['hashValue'],
			['email', 'email_attachment_hash'],
			'Hash of attachment "{}"'.format(hash_attachment['hashedAttachment']))

	# The forwarded message itself. Its own type keeps it away from the reputation
	# analyzers — submitting the hash of a whole reported email says nothing —
	# while YARA can still match rules against it
	if eml_file_tuple:
		add('file_message/rfc822', eml_file_tuple[1], ['email', 'email_sample'],
			'Attached email in eml format', eml_file_tuple[0].getvalue())

	log.info('Collected {0} observable(s) from the email'.format(len(observables)))
	wsl.emit_info('Collected {0} observable(s) from the email'.format(len(observables)))
	return observables


# Main function called from outside 
# The wsl is not a global variable to support multiple tabs 
def prepare(wsl):
	"""Logging, configuração e whitelist: o que toda análise precisa antes da mensagem.

	Devolve (ok, provedor). O provedor pode ser None com ok verdadeiro — a
	reanálise parte da mensagem guardada e não precisa de caixa nenhuma, então
	uma caixa mal configurada não pode impedir de reanalisar.
	"""

	global ruleset
	global log

	# Logging configuration
	try:
		with open('logging_conf.json') as log_conf:
			log_conf_dict = json.load(log_conf)
			logging.config.dictConfig(log_conf_dict)
	except Exception as e: 
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return False, None
	log = logging.getLogger(__name__)

	try:
		conf_dict = config_file.read('configuration.json')

		# Nothing about TheHive is read here any more: this module extracts
		# observables and no longer stores them anywhere. Where the finished
		# analysis gets recorded is tickets.py's business.

		# Analysis mode: "attachment" (default, analyze the forwarded .eml)
		# or "raw" (analyze the mailbox email itself)
		sync_conf = conf_dict.get('email_sync') or {}
		config['analysisMode'] = sync_conf.get('analysisMode', 'attachment')
		# Address of the monitored mailbox, used as the notification target in
		# raw mode (the sender of an analyzed email must never be notified: in
		# raw mode that would mean emailing the verdict to the phisher)
		if sync_conf.get('provider') == 'gmail':
			config['mailboxAddress'] = sync_conf.get('gmail', {}).get('user', '')
		elif sync_conf.get('provider') == 'm365':
			config['mailboxAddress'] = sync_conf.get('m365', {}).get('mailbox', '')
		else:
			config['mailboxAddress'] = conf_dict.get('imap', {}).get('user', '')

	except Exception as e:
		log.error("Error while trying to open the file 'configuration.json': {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to open the file 'configuration.json'")
		return False, None

	# Email synchronization configuration (Microsoft 365 via Graph API, Gmail via
	# IMAP or the legacy imap/oauth2 sections, selected by email_provider)
	try:
		provider = email_provider.create_provider(conf_dict)
	except Exception:
		log.error("Error while configuring the email provider: {}".format(traceback.format_exc()))
		provider = None

	# Carrega o whitelist v2. A leitura não levanta exceção e não interrompe a
	# análise: um arquivo ausente, quebrado ou ainda no v1 devolve um conjunto
	# vazio, nada é liberado e o pipeline segue. No v1 o mesmo erro abortava a
	# análise inteira, transformando um JSON malformado em indisponibilidade
	ruleset = whitelist.load(suspended_ids = whitelist_state.suspended_ids())
	if ruleset.error:
		log.error("Whitelist não carregada, nada será liberado nesta análise: {0}".format(ruleset.error))
		wsl.emit_error("Whitelist não carregada, nada será liberado nesta análise: {0}".format(ruleset.error))
	else:
		log.info("Whitelist v2 carregada com {0} regras".format(len(ruleset.rules)))
	reset_seen_observables()
	return True, provider


def main(wsl, mail_uid):

	ok, provider = prepare(wsl)
	if not ok:
		return
	if provider is None:
		wsl.emit_error("Error while trying to open the file 'configuration.json'")
		return

	# Fetch the selected email through the configured provider (this marks it as read)
	try:
		log.info('Reading {0}'.format(provider.describe()))
		wsl.emit_info('Reading {0}'.format(provider.describe()))
		message = provider.fetch(mail_uid)
	except Exception as e:
		log.error("Error while trying to connect to the email server: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to connect to the email server")
		return

	# Handle multiple analysts that select the same email from more than one tab
	if message is None:
		log.error("The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))
		wsl.emit_error("The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))
		return

	# Obtain the email to analyze, auto-detected per message:
	# - a message carrying a forwarded .eml attachment is analyzed through the
	#   attachment (original behavior); the reporter gets the notifications
	# - a message without an .eml attachment is analyzed as a raw email: the
	#   fetched message itself is converted to a temporary .eml file. The
	#   notifications go to the monitored mailbox itself, never to the sender
	#   of the analyzed email (that would mean emailing the verdict to the
	#   phisher)
	try:
		internal_msg, external_from_field = obtain_eml(message, mail_uid, wsl)
		if internal_msg is None:
			log.info("No .eml attachment found in message {0}: analyzing the raw email itself".format(mail_uid))
			wsl.emit_info("No .eml attachment found in message {0}: analyzing the raw email itself".format(mail_uid))
			internal_msg, _unused = obtain_raw_eml(message, mail_uid, wsl, log_read = False)
			external_from_field = config.get('mailboxAddress', '')
	except Exception as e:
		log.error("Error while trying to obtain the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to obtain the internal eml file")
		return

	return analyze_message(wsl, internal_msg, external_from_field)


def main_from_eml(wsl, eml_bytes, reporter):
	"""A mesma extração, a partir da mensagem denunciada já guardada.

	É a entrada da reanálise. `eml_bytes` é a mensagem interna — a que foi
	denunciada, e não o envelope de encaminhamento —, porque é o que
	`run_analysis` recebe e guarda em `case_evidence`. Por isso nada aqui
	procura um `.eml` anexado: um phishing que carrega um `.eml` dentro de si
	seria analisado pelo anexo do atacante, e não pela mensagem que alguém
	denunciou.

	`reporter` é quem denunciou da primeira vez, lido da impressão digital: a
	caixa já não tem a mensagem de encaminhamento para dizer.
	"""
	ok, _provider = prepare(wsl)
	if not ok:
		return
	try:
		internal_msg = email.message_from_bytes(eml_bytes)
	except Exception:
		log.error("The stored message could not be parsed: {}".format(traceback.format_exc()))
		wsl.emit_error("A mensagem original guardada não pôde ser lida")
		return
	return analyze_message(wsl, internal_msg, reporter or '')


def analyze_message(wsl, internal_msg, external_from_field):
	"""Autenticação, sinais de massa, parse e observáveis de uma mensagem já obtida."""

	# Read the sender authentication recorded by the receiving mail server
	# (SPF/DKIM/DMARC). It tells apart a genuine message from a brand and one
	# merely impersonating it, which the content alone cannot do. A failure here
	# must not stop the analysis
	try:
		auth_results = extract_authentication_results(internal_msg)
		log.info("Sender authentication: spf={0}, dkim={1}, dmarc={2}, aligned={3} (from domain {4})".format(auth_results['spf'], auth_results['dkim'], auth_results['dmarc'], auth_results['aligned'], auth_results['fromDomain'] or 'unknown'))
		wsl.emit_info("Sender authentication: SPF={0}, DKIM={1}, DMARC={2}{3}".format(auth_results['spf'], auth_results['dkim'], auth_results['dmarc'], '' if auth_results['authenticated'] else ' (the sender domain is NOT authenticated)'))
	except Exception as e:
		log.warning("Unable to read the sender authentication headers: {}".format(traceback.format_exc()))
		auth_results = None

	# Marcadores de correspondencia em massa nos cabecalhos (RFC 2369/8058/3098).
	# E sinal, nao veredito: tudo que esta varredura le foi escrito por quem
	# enviou, e quem manda phishing tambem sabe escrever List-Unsubscribe. Quem
	# transforma isso em classificacao e scoring.py, e a promocao a `spam` exige a
	# autenticacao lida acima, que o remetente nao controla
	try:
		bulk_signals = spam_headers.scan(internal_msg, str(internal_msg.get('Subject', '') or ''))
		# A única parte desta leitura que o remetente não escreve sozinho: a baixa
		# por um clique coberta por DKIM do próprio domínio (RFC 8058 §4). É ela,
		# e não a presença do cabeçalho, que run_analysis usa para não elevar
		# marketing autenticado com risco Medium da IA
		bulk_signals['oneClickSigned'] = spam_headers.one_click_signed(
			internal_msg, (auth_results or {}).get('fromDomain', ''))
		if bulk_signals['markers']:
			log.info('Bulk mail markers: {0}'.format(spam_headers.summary(bulk_signals)))
			wsl.emit_info('Cabecalhos de massa: {0}'.format(spam_headers.summary(bulk_signals)))
	except Exception:
		log.warning('Unable to scan the bulk mail headers: {}'.format(traceback.format_exc()))
		bulk_signals = None

	# Call the parse_eml function
	try:
		subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, email_body, images, extraction_complete = parse_eml(internal_msg, wsl)
	except Exception as e:
		log.error("Error while trying to parse the internal eml file: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while trying to parse the internal eml file")
		return

	# Flatten everything into the in-memory observable list the analysis consumes
	try:
		observables = collect_observables(observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl)
	except Exception as e:
		log.error("Error while collecting the observables: {}".format(traceback.format_exc()))
		wsl.emit_error("Error while collecting the observables")
		return

	# The raw .eml travels back too. It is what lets a ticket destination store or
	# attach the original message without asking TheHive for it — which is the
	# whole point of the disk destination existing (tickets.py). Reading the
	# BytesIO again is harmless: collect_observables took its bytes with
	# getvalue(), which does not move the stream.
	try:
		eml_bytes = eml_file_tuple[0].getvalue()
	except Exception:
		eml_bytes = None

	# The subject and the clean body text are also returned so that they can be sent to the LLM for the social engineering analysis
	# O retrato dos observables vai junto, e não por variável global: a análise
	# roda fora do semáforo que serializa a extração, então duas abas analisando
	# ao mesmo tempo escreveriam uma por cima da outra
	observables_seen = {key: list(values) for key, values in seen_observables.items()}
	return observables, external_from_field, subject_field, email_body, auth_results, images, eml_bytes, observables_seen, bulk_signals, extraction_complete