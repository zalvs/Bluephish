import base64
import contextlib
import email
import email.generator
import email.header
import email.parser
import email.utils
import hashlib
import io
import ipaddress
import json
import logging.config
import os
import re
import traceback
import urllib.parse

import bs4
import emoji
import ioc_finder

import email_provider
import ioc_noise
import spam_headers
import whitelist
import whitelist_state

# O logger do módulo nasce vazio e é montado por prepare(), depois de ler logging_conf.json
log = None


# Registra a mesma linha no log e na tela do analista
def _info(text, wsl):
	log.info(text)
	wsl.emit_info(text)


# Registra uma falha no log (com o detalhe, quando há) e avisa o analista só do resumo
def _error(wsl, text, detail = None):
	log.error(text if detail is None else '{0}: {1}'.format(text, detail))
	wsl.emit_error(text)



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


def reset_seen_observables():
	for values in seen_observables.values():
		del values[:]


def _remember(obs_type, value):
	values = seen_observables.get(obs_type)
	if values is not None and value not in values:
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


# Anuncia um observável aceito no log e na tela e devolve o registro dele
def _found(kind, value, wsl):
	_info("Found observable {0}: {1}".format(kind, value), wsl)
	return {'type': kind, 'value': value}


# Extrai os observáveis de um texto com o ioc_finder e devolve só os que a whitelist não suprimiu
def search_observables(buffer, wsl):
	# Um cabeçalho lido de e-mail malformado (bytes não ASCII num cabeçalho
	# declarado us-ascii) chega como email.header.Header, e o ioc_finder chama
	# .lower() nele. Converter para str não muda nada para quem já é str
	buffer = str(buffer)
	addresses = ioc_finder.parse_email_addresses(buffer)
	ips = ioc_finder.parse_ipv4_addresses(buffer)
	domains = ioc_finder.parse_domain_names(buffer)
	# Sem esquema (https://) a URL não é aceita
	urls = ioc_finder.parse_urls(buffer, parse_urls_without_scheme = False)

	found = []
	# Endereços e IPs não são mais suprimíveis. No v1 uma entrada de `mail`
	# significava "não extraia este endereço"; no v2 remetente é confiança, não
	# conveniência, e ela é decidida no veredito, depois de a análise inteira ter
	# rodado. Suprimir o endereço aqui apagaria o observable de que essa decisão
	# precisa
	for address in addresses:
		found.append(_found('mail', address, wsl))
	for ip in ips:
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
		found.append(_found('ip', ip, wsl))
	# O id de pacote de um link de loja de aplicativo tem forma de domínio e não é
	# domínio de ninguém (ver ioc_noise.py): mandado a um analisador de reputação,
	# ele só produz ruído sobre uma marca legítima
	packages = ioc_noise.app_package_ids(buffer)
	for domain in domains:
		if ioc_noise.is_app_package_only(domain, buffer, packages):
			log.info("Skipped an app store package id that looks like a domain: {0}".format(domain))
			continue
		_remember('domain', domain)
		if _suppressed_by(ruleset.match_domain(domain), 'domain', domain, wsl):
			continue
		found.append(_found('domain', domain, wsl))
	for url in urls:
		_remember('url', url)
		if _suppressed_by(ruleset.match_url(url), 'url', url, wsl):
			continue
		found.append(_found('url', url, wsl))
	return found



# Tipos de parte que podem carregar o .eml denunciado. Os dois entram porque
# cada cliente de e-mail anexa a mensagem encaminhada de um jeito
EML_CARRIER_TYPES = ('application/octet-stream', 'message/rfc822')

# Arquivo temporário da análise "raw". As análises são serializadas pelo
# semáforo da aplicação, então um nome fixo não colide
RAW_EML_PATH = 'raw_message_under_analysis.eml'


# Endereço de quem encaminhou, lido do From: é para ele que o veredito volta
def _reporter_address(msg):
	text, charset = email.header.decode_header(msg['From'])[0]
	shown = text.decode(charset) if charset is not None else str(text)
	return email.utils.parseaddr(shown)[1]


# A mensagem embutida numa parte. Um octet-stream traz o .eml como bytes; um
# message/rfc822 traz a mensagem já aberta, ou, em alguns clientes, o texto dela
# em base64
def _embedded_message(part, content_type):
	if content_type == 'application/octet-stream':
		return email.message_from_bytes(part.get_payload(decode = 1))
	embedded = part.get_payload(decode = 0)[0]
	try:
		return email.message_from_string(base64.b64decode(str(embedded)).decode())
	except Exception:
		return embedded


# Abre a mensagem buscada pelo provedor e devolve (o .eml anexado, quem encaminhou)
def obtain_eml(message, mail_uid, wsl):
	# Buscar pelo provedor já marca a mensagem como lida
	_info("Message {0} flagged as read".format(mail_uid), wsl)

	msg = email.message_from_bytes(message)
	reporter = _reporter_address(msg)

	# Só interessa o primeiro anexo desse tipo: o .eml é a última parte, e o que
	# vier depois pode ser do e-mail interno, e não deve ser considerado
	internal_msg = None
	for part in msg.walk():
		content_type = part.get_content_type()
		if content_type in EML_CARRIER_TYPES:
			internal_msg = _embedded_message(part, content_type)
			break

	return internal_msg, reporter


# Análise "raw": o próprio e-mail da caixa é o e-mail a analisar.
# O código-fonte RFC822 buscado pelo provedor é gravado num .eml temporário no
# diretório de trabalho e relido de lá, para que o resto do pipeline o consuma
# exatamente como se tivesse chegado por anexo. A operação é somente leitura
# para o servidor de e-mail: o provedor só baixa o MIME (e marca como lido),
# nunca altera nem apaga o original
def obtain_raw_eml(message, mail_uid, wsl, log_read = True):
	# Quando isto é o plano B de obtain_eml, a leitura já foi registrada lá
	if log_read:
		_info("Message {0} flagged as read".format(mail_uid), wsl)

	with open(RAW_EML_PATH, 'wb') as raw_file:
		raw_file.write(message)
	log.info("Raw email source saved to temporary file {0} ({1} bytes)".format(RAW_EML_PATH, len(message)))
	wsl.emit_info("Raw email source saved to a temporary .eml file ({0} bytes)".format(len(message)))

	try:
		with open(RAW_EML_PATH, 'rb') as raw_file:
			internal_msg = email.message_from_binary_file(raw_file)
	finally:
		with contextlib.suppress(OSError):
			os.remove(RAW_EML_PATH)

	# No modo raw não há "denunciante": quem chama põe o endereço da caixa
	# monitorada como destino das notificações
	return internal_msg, None



# Campos do cabeçalho em que se procuram observáveis. Os demais (Subject, Date,
# Message-ID...) não carregam endereço de quem enviou, só ruído
HEADER_FIELDS_TO_SEARCH = (
	'To', 'From', 'Sender', 'Cc', 'Delivered-To', 'Return-Path', 'Reply-To',
	'Bounces-to', 'Received', 'X-Received', 'X-OriginatorOrg', 'X-Sender-IP',
	'X-Originating-IP', 'X-SenderIP', 'X-Originating-Email'
)


# O assunto como texto. Ele pode vir partido em vários pedaços, cada um com seu
# charset, então o cabeçalho é decodificado pedaço a pedaço e depois emendado
def _decode_subject(message):
	pieces = []
	for data, charset in email.header.decode_header(message['Subject']):
		if charset is None:
			pieces.append(data if isinstance(data, str) else data.decode())
		elif str(charset) == 'unknown-8bit':
			pieces.append(data.decode())
		else:
			pieces.append(data.decode(charset))
	return ''.join(pieces)


# Observáveis de cada campo de cabeçalho que importa, por nome do campo.
# A mensagem é relida como bytes de propósito: e-mail de phishing costuma ser
# malformado (parte declarada us-ascii com bytes não ASCII) e o as_string()
# reencoda o conteúdo, levantando UnicodeEncodeError nesses casos. O as_bytes()
# escreve o payload como veio
def _header_observables(message, wsl):
	headers = email.parser.BytesHeaderParser().parsebytes(message.as_bytes())
	by_field = {}
	# Um campo pode aparecer várias vezes (Received:), então a lista é acumulada
	for field, value in headers.items():
		if field in HEADER_FIELDS_TO_SEARCH:
			by_field.setdefault(field, []).extend(search_observables(value, wsl))
	return by_field


# O texto de uma parte text/*. Quem não é UTF-8 costuma ser ISO-8859-1, que
# decodifica qualquer sequência de bytes
def _text_of(part):
	payload = part.get_payload(decode = True)
	try:
		return payload.decode()
	except UnicodeDecodeError:
		return payload.decode('ISO-8859-1')


# Um anexo vira (arquivo em memória, nome) e o registro do seu SHA-256, ou None
# quando não tem nome ou a whitelist o libera.
# O anexo é liberado por SHA-256, e só. Os tipos `filename` e `filetype` do v1
# saíram do modelo: liberar por nome é liberar o que quem ataca escolhe chamar
# de `fatura.pdf`, e liberar por MIME libera todo anexo daquele formato de uma vez
def _attachment_of(part, wsl):
	filename = part.get_filename()
	if not filename:
		return None
	payload = part.get_payload(decode = 1)
	hasher = hashlib.sha256()
	hasher.update(payload)
	digest = hasher.hexdigest()
	_remember('hash', digest)
	if _suppressed_by(ruleset.match_hash(digest), 'hash', digest, wsl):
		return None
	_info("Found observable file: {0}".format(filename), wsl)
	_info("Found observable hash {0} calculated from file: {1}".format(digest, filename), wsl)
	return (io.BytesIO(payload), filename), {'hashValue': digest, 'hashedAttachment': filename}


# Um link extraído do HTML pode vir colado ao próximo marcador ("...x>z"); o
# valor termina onde aparece o primeiro < ou >
def _cut_at_markup(url):
	return url.replace(">", "<").split("<")[0]


# Lê a mensagem denunciada e devolve, nesta ordem: assunto, observáveis por
# campo de cabeçalho, observáveis do corpo, anexos, hashes dos anexos, o .eml
# como (arquivo, nome), o texto limpo do corpo e as imagens para a análise visual
def parse_eml(internal_msg, wsl):
	subject_field = _decode_subject(internal_msg)
	_info("Analyzing attached message with subject: {}".format(subject_field), wsl)

	observables_header = _header_observables(internal_msg, wsl)

	attachments = []
	hashes_attachments = []
	observables_body = []
	# Pedaços de texto limpo do corpo, que compõem o texto enviado ao LLM
	body_text_parts = []
	html_text_parts = []
	# Imagens embutidas ou anexadas, para a análise visual do LLM
	images = []

	for part in internal_msg.walk():
		mimetype = part.get_content_type()
		# Imagem que viaja com o e-mail (anexa ou embutida) é coletada para a
		# análise visual, independentemente do tratamento de anexo abaixo
		if part.get_content_maintype() == 'image':
			collect_image_part(part, images, wsl)
		if part.get_content_disposition() == "attachment":
			attached = _attachment_of(part, wsl)
			if attached:
				attachments.append(attached[0])
				hashes_attachments.append(attached[1])
		elif mimetype == "text/plain":
			body = _text_of(part)
			observables_body.extend(search_observables(body, wsl))
			body_text_parts.append(body)
		elif mimetype == "text/html":
			html = _text_of(part)
			# O HTML chega com URL codificada, então se decodifica antes de procurar
			observables_body.extend(search_observables(urllib.parse.unquote(html.replace("&amp;", "&")), wsl))
			html_text_parts.append(bs4.BeautifulSoup(html, 'html.parser').get_text(separator = ' ', strip = True))

	# O .eml e o nome que ele terá como observable
	eml_buffer = io.BytesIO()
	email.generator.BytesGenerator(eml_buffer).flatten(internal_msg)
	eml_file_tuple = (eml_buffer, subject_field + ".eml")

	for observable in observables_body:
		if observable['type'] == "url":
			observable['value'] = _cut_at_markup(observable['value'])

	# Texto limpo para a análise de engenharia social: o text/plain é preferido e
	# o texto extraído do HTML entra quando não há nenhum
	email_body = '\n'.join(body_text_parts).strip() or '\n'.join(html_text_parts).strip()

	return subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, email_body, images



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

	# (tipo, nome, tags, mensagem, conteúdo) na ordem em que a análise os lê
	entries = []

	# Found in the mail header
	for header_field, found in observables_header.items():
		for observable in found:
			entries.append((observable['type'], observable['value'],
				['email', 'email_header', 'email_header_{}'.format(header_field)],
				'Found in the {} field of the email header'.format(header_field), None))

	# Found in the mail body
	for observable in observables_body:
		entries.append((observable['type'], observable['value'],
			['email', 'email_body'], 'Found in the email body', None))

	# Attachments, carried as bytes so that nothing has to be downloaded later
	for attachment_file, attachment_name in attachments:
		entries.append(('file', attachment_name, ['email', 'email_attachment'],
			'Found as email attachment', attachment_file.getvalue()))

	# Hashes of those attachments
	for hashed in hashes_attachments:
		entries.append(('hash', hashed['hashValue'], ['email', 'email_attachment_hash'],
			'Hash of attachment "{}"'.format(hashed['hashedAttachment']), None))

	# The forwarded message itself. Its own type keeps it away from the reputation
	# analyzers — submitting the hash of a whole reported email says nothing —
	# while YARA can still match rules against it
	if eml_file_tuple:
		entries.append(('file_message/rfc822', eml_file_tuple[1], ['email', 'email_sample'],
			'Attached email in eml format', eml_file_tuple[0].getvalue()))

	observables = [{
		'id': 'obs-{0}'.format(position),
		'type': kind,
		'name': name,
		'tags': tags,
		'message': message,
		'content': content,
		'ioc': False
	} for position, (kind, name, tags, message, content) in enumerate(entries)]

	_info('Collected {0} observable(s) from the email'.format(len(observables)), wsl)
	return observables



# Lê logging_conf.json e monta o logger do módulo. Sem isso nada mais registra
# o que acontece, então a falha aqui interrompe a análise antes de começar
def _configure_logging():
	global log
	try:
		with open('logging_conf.json') as conf_file:
			logging.config.dictConfig(json.load(conf_file))
	except Exception:
		print("[ERROR]_[list_emails]: Error while trying to open the file 'logging_conf.json'. It cannot be read or it is not valid: {}".format(traceback.format_exc()))
		return False
	log = logging.getLogger(__name__)
	return True


# O endereço da caixa monitorada, de onde o veredito de uma análise "raw" é
# notificado (nunca de quem mandou o e-mail: seria avisar o phisher)
def _mailbox_address(conf_dict, sync_conf):
	provider_name = sync_conf.get('provider')
	if provider_name == 'gmail':
		return sync_conf.get('gmail', {}).get('user', '')
	if provider_name == 'm365':
		return sync_conf.get('m365', {}).get('mailbox', '')
	return conf_dict.get('imap', {}).get('user', '')


def _read_configuration(wsl):
	try:
		with open('configuration.json') as conf_file:
			conf_dict = json.load(conf_file)
		# Nada sobre o TheHive é lido aqui: este módulo extrai observáveis e não
		# os guarda em lugar nenhum. Onde a análise pronta é registrada é assunto
		# do tickets.py.
		# Modo de análise: "attachment" (padrão, analisa o .eml encaminhado) ou
		# "raw" (analisa o próprio e-mail da caixa)
		sync_conf = conf_dict.get('email_sync') or {}
		config['analysisMode'] = sync_conf.get('analysisMode', 'attachment')
		config['mailboxAddress'] = _mailbox_address(conf_dict, sync_conf)
	except Exception:
		_error(wsl, "Error while trying to open the file 'configuration.json'", traceback.format_exc())
		return None
	return conf_dict


def prepare(wsl):
	"""Logging, configuração e whitelist: o que toda análise precisa antes da mensagem.

	Devolve (ok, provedor). O provedor pode ser None com ok verdadeiro — a
	reanálise parte da mensagem guardada e não precisa de caixa nenhuma, então
	uma caixa mal configurada não pode impedir de reanalisar.
	"""

	global ruleset

	if not _configure_logging():
		return False, None

	conf_dict = _read_configuration(wsl)
	if conf_dict is None:
		return False, None

	# Sincronização de e-mail (Microsoft 365 pela Graph API, Gmail por IMAP ou as
	# seções legadas imap/oauth2), escolhida pelo email_provider
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
		_error(wsl, "Whitelist não carregada, nada será liberado nesta análise: {0}".format(ruleset.error))
	else:
		log.info("Whitelist v2 carregada com {0} regras".format(len(ruleset.rules)))
	reset_seen_observables()
	return True, provider


# Busca a mensagem escolhida pelo provedor (o que também a marca como lida).
# Devolve (mensagem, continua): `continua` é False quando já foi dito ao analista
# por que não dá para seguir
def _fetch_message(provider, mail_uid, wsl):
	try:
		_info('Reading {0}'.format(provider.describe()), wsl)
		message = provider.fetch(mail_uid)
	except Exception:
		_error(wsl, "Error while trying to connect to the email server", traceback.format_exc())
		return None, False
	# Vários analistas podem escolher o mesmo e-mail em abas diferentes
	if message is None:
		_error(wsl, "The email with UID {} has already been analyzed. Please refresh the page and retry.".format(mail_uid))
		return None, False
	return message, True


# Decide qual e-mail analisar, mensagem a mensagem:
# - com um .eml anexado, analisa-se o anexo (comportamento original) e quem
#   denunciou recebe as notificações;
# - sem anexo, o próprio e-mail buscado é convertido num .eml temporário e as
#   notificações vão para a caixa monitorada, nunca para quem o enviou (seria
#   mandar o veredito ao phisher)
def _choose_message(message, mail_uid, wsl):
	internal_msg, external_from_field = obtain_eml(message, mail_uid, wsl)
	if internal_msg is None:
		_info("No .eml attachment found in message {0}: analyzing the raw email itself".format(mail_uid), wsl)
		internal_msg, _unused = obtain_raw_eml(message, mail_uid, wsl, log_read = False)
		external_from_field = config.get('mailboxAddress', '')
	return internal_msg, external_from_field


# Ponto de entrada chamado de fora. O wsl não é global para suportar várias abas
def main(wsl, mail_uid):
	ok, provider = prepare(wsl)
	if not ok:
		return
	if provider is None:
		wsl.emit_error("Error while trying to open the file 'configuration.json'")
		return

	message, proceed = _fetch_message(provider, mail_uid, wsl)
	if not proceed:
		return

	try:
		internal_msg, external_from_field = _choose_message(message, mail_uid, wsl)
	except Exception:
		_error(wsl, "Error while trying to obtain the internal eml file", traceback.format_exc())
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


# Read the sender authentication recorded by the receiving mail server
# (SPF/DKIM/DMARC). It tells apart a genuine message from a brand and one
# merely impersonating it, which the content alone cannot do. A failure here
# must not stop the analysis
def _read_authentication(internal_msg, wsl):
	try:
		results = extract_authentication_results(internal_msg)
		log.info("Sender authentication: spf={0}, dkim={1}, dmarc={2}, aligned={3} (from domain {4})".format(results['spf'], results['dkim'], results['dmarc'], results['aligned'], results['fromDomain'] or 'unknown'))
		wsl.emit_info("Sender authentication: SPF={0}, DKIM={1}, DMARC={2}{3}".format(results['spf'], results['dkim'], results['dmarc'], '' if results['authenticated'] else ' (the sender domain is NOT authenticated)'))
	except Exception:
		log.warning("Unable to read the sender authentication headers: {}".format(traceback.format_exc()))
		return None
	return results


# Marcadores de correspondencia em massa nos cabecalhos (RFC 2369/8058/3098).
# E sinal, nao veredito: tudo que esta varredura le foi escrito por quem
# enviou, e quem manda phishing tambem sabe escrever List-Unsubscribe. Quem
# transforma isso em classificacao e scoring.py, e a promocao a `spam` exige a
# autenticacao lida acima, que o remetente nao controla
def _read_bulk_signals(internal_msg, auth_results, wsl):
	try:
		signals = spam_headers.scan(internal_msg, str(internal_msg.get('Subject', '') or ''))
		# A única parte desta leitura que o remetente não escreve sozinho: a baixa
		# por um clique coberta por DKIM do próprio domínio (RFC 8058 §4). É ela,
		# e não a presença do cabeçalho, que run_analysis usa para não elevar
		# marketing autenticado com risco Medium da IA
		signals['oneClickSigned'] = spam_headers.one_click_signed(
			internal_msg, (auth_results or {}).get('fromDomain', ''))
		if signals['markers']:
			log.info('Bulk mail markers: {0}'.format(spam_headers.summary(signals)))
			wsl.emit_info('Cabecalhos de massa: {0}'.format(spam_headers.summary(signals)))
	except Exception:
		log.warning('Unable to scan the bulk mail headers: {}'.format(traceback.format_exc()))
		return None
	return signals


def analyze_message(wsl, internal_msg, external_from_field):
	"""Autenticação, sinais de massa, parse e observáveis de uma mensagem já obtida."""

	auth_results = _read_authentication(internal_msg, wsl)
	bulk_signals = _read_bulk_signals(internal_msg, auth_results, wsl)

	# Call the parse_eml function
	try:
		subject_field, observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, email_body, images = parse_eml(internal_msg, wsl)
	except Exception:
		_error(wsl, "Error while trying to parse the internal eml file", traceback.format_exc())
		return

	# Flatten everything into the in-memory observable list the analysis consumes
	try:
		observables = collect_observables(observables_header, observables_body, attachments, hashes_attachments, eml_file_tuple, wsl)
	except Exception:
		_error(wsl, "Error while collecting the observables", traceback.format_exc())
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
	return observables, external_from_field, subject_field, email_body, auth_results, images, eml_bytes, observables_seen, bulk_signals
