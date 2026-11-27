"""O panorama externo: o que a comunidade de segurança publica sobre phishing.

Os insights da Visão Executiva (case_insights.py) contam o que aconteceu aqui.
Este módulo lê o que fornecedores de pesquisa, imprensa especializada e centros
de resposta publicaram no mesmo período, classifica por um vocabulário fechado e
cruza com os casos. Não é analisador: nada daqui muda um veredito.

Mesma divisão de case_insights.py e feeds.py. Este arquivo é puro — catálogo,
leitura do XML, classificação e agregação, dado entra e dado sai — e por isso é
testável sem rede. A coleta (download, gravação, intervalo) fica em
threat_intel_sync.py; as rotas, em thephish_app.py.

Nada aqui inventa valor. Tema sem sinal medível no ambiente responde None, e uma
janela anterior ao começo da coleta é dita parcial, nunca um mês tranquilo
(BLUEPHISH_ARCHITECTURE.md §4.8.2).
"""

import calendar
import datetime
import email.utils
import hashlib
import html
import re
import urllib.parse
import xml.parsers.expat

MIB = 1024 * 1024

# Catálogo fechado. O endereço fica no código de propósito: não existe campo para
# digitar um, então a coleta não é mais um jeito de fazer o servidor chamar um
# endereço que alguém escolheu (a cadeia de SSRF do CLAUDE.md). Cada endereço foi
# conferido em 30/10/2026 respondendo 200 sem redirecionamento — a coleta recusa
# redirect, e um endereço que passe a redirecionar aparece como fonte com falha.
#
# `kind` agrupa na tela; `recommended` é o pacote de um clique, escolhido por
# publicar sobre phishing com frequência e responder rápido.
SOURCES = [
	{'id': 'knowbe4', 'name': 'KnowBe4', 'kind': 'research', 'lang': 'en',
		'url': 'https://blog.knowbe4.com/rss.xml', 'site': 'https://blog.knowbe4.com/', 'recommended': True},
	{'id': 'cofense', 'name': 'Cofense', 'kind': 'research', 'lang': 'en',
		'url': 'https://cofense.com/feed/', 'site': 'https://cofense.com/blog/', 'recommended': True},
	{'id': 'talos', 'name': 'Cisco Talos', 'kind': 'research', 'lang': 'en',
		'url': 'https://blog.talosintelligence.com/rss/', 'site': 'https://blog.talosintelligence.com/',
		'recommended': True},
	{'id': 'unit42', 'name': 'Unit 42 (Palo Alto)', 'kind': 'research', 'lang': 'en',
		'url': 'https://unit42.paloaltonetworks.com/feed/', 'site': 'https://unit42.paloaltonetworks.com/',
		'recommended': True},
	{'id': 'microsoft', 'name': 'Microsoft Security', 'kind': 'research', 'lang': 'en',
		'url': 'https://www.microsoft.com/en-us/security/blog/feed/',
		'site': 'https://www.microsoft.com/en-us/security/blog/', 'recommended': True},
	{'id': 'huntress', 'name': 'Huntress', 'kind': 'research', 'lang': 'en',
		'url': 'https://www.huntress.com/blog/rss.xml', 'site': 'https://www.huntress.com/blog', 'recommended': True},
	{'id': 'checkpoint', 'name': 'Check Point Research', 'kind': 'research', 'lang': 'en',
		'url': 'https://research.checkpoint.com/feed/', 'site': 'https://research.checkpoint.com/',
		'recommended': False},
	{'id': 'sentinellabs', 'name': 'SentinelLABS', 'kind': 'research', 'lang': 'en',
		'url': 'https://www.sentinelone.com/labs/feed/', 'site': 'https://www.sentinelone.com/labs/',
		'recommended': False},
	{'id': 'securelist', 'name': 'Securelist (Kaspersky)', 'kind': 'research', 'lang': 'en',
		'url': 'https://securelist.com/feed/', 'site': 'https://securelist.com/', 'recommended': False},
	{'id': 'malwarebytes', 'name': 'Malwarebytes Labs', 'kind': 'research', 'lang': 'en',
		'url': 'https://www.malwarebytes.com/blog/feed/index.xml', 'site': 'https://www.malwarebytes.com/blog',
		'recommended': False},
	{'id': 'recordedfuture', 'name': 'Recorded Future', 'kind': 'research', 'lang': 'en',
		'url': 'https://www.recordedfuture.com/feed', 'site': 'https://www.recordedfuture.com/research',
		'recommended': False},
	{'id': 'bleepingcomputer', 'name': 'BleepingComputer', 'kind': 'press', 'lang': 'en',
		'url': 'https://www.bleepingcomputer.com/feed/', 'site': 'https://www.bleepingcomputer.com/',
		'recommended': True},
	{'id': 'thehackernews', 'name': 'The Hacker News', 'kind': 'press', 'lang': 'en',
		'url': 'https://feeds.feedburner.com/TheHackersNews', 'site': 'https://thehackernews.com/',
		'recommended': False},
	{'id': 'darkreading', 'name': 'Dark Reading', 'kind': 'press', 'lang': 'en',
		'url': 'https://www.darkreading.com/rss.xml', 'site': 'https://www.darkreading.com/', 'recommended': False},
	{'id': 'therecord', 'name': 'The Record', 'kind': 'press', 'lang': 'en',
		'url': 'https://therecord.media/feed', 'site': 'https://therecord.media/', 'recommended': False},
	{'id': 'krebs', 'name': 'Krebs on Security', 'kind': 'press', 'lang': 'en',
		'url': 'https://krebsonsecurity.com/feed/', 'site': 'https://krebsonsecurity.com/', 'recommended': False},
	{'id': 'sans_isc', 'name': 'SANS Internet Storm Center', 'kind': 'cert', 'lang': 'en',
		'url': 'https://isc.sans.edu/rssfeed_full.xml', 'site': 'https://isc.sans.edu/', 'recommended': True},
	{'id': 'certpl', 'name': 'CERT Polska', 'kind': 'cert', 'lang': 'en',
		'url': 'https://cert.pl/en/rss.xml', 'site': 'https://cert.pl/en/', 'recommended': False},
	{'id': 'certbr', 'name': 'CERT.br', 'kind': 'cert', 'lang': 'pt',
		'url': 'https://cert.br/rss/certbr-rss.xml', 'site': 'https://cert.br/', 'recommended': False},
	{'id': 'welivesecurity_pt', 'name': 'WeLiveSecurity (ESET, em português)', 'kind': 'brazil', 'lang': 'pt',
		'url': 'https://www.welivesecurity.com/pt/rss/feed/', 'site': 'https://www.welivesecurity.com/pt/',
		'recommended': True},
	{'id': 'kaspersky_br', 'name': 'Kaspersky Brasil', 'kind': 'brazil', 'lang': 'pt',
		'url': 'https://www.kaspersky.com.br/blog/feed/', 'site': 'https://www.kaspersky.com.br/blog/',
		'recommended': False},
	{'id': 'cisoadvisor', 'name': 'CISO Advisor', 'kind': 'brazil', 'lang': 'pt',
		'url': 'https://www.cisoadvisor.com.br/feed/', 'site': 'https://www.cisoadvisor.com.br/', 'recommended': True},
	{'id': 'minutodaseguranca', 'name': 'Minuto da Segurança', 'kind': 'brazil', 'lang': 'pt',
		'url': 'https://minutodaseguranca.blog.br/feed/', 'site': 'https://minutodaseguranca.blog.br/',
		'recommended': False},
	{'id': 'convergenciadigital', 'name': 'Convergência Digital', 'kind': 'brazil', 'lang': 'pt',
		'url': 'https://convergenciadigital.com.br/feed/', 'site': 'https://convergenciadigital.com.br/',
		'recommended': False}
]

BY_ID = dict((source['id'], source) for source in SOURCES)

# Teto por documento. O maior do catálogo (Talos) tinha 1 MB em 30/10/2026
MAX_FEED_BYTES = 4 * MIB
# Um feed com milhares de itens (o da Huntress traz o blog inteiro) só tem os
# primeiros lidos: são os mais recentes, e o resto já foi visto ou é antigo
MAX_ITEMS_PER_FEED = 300
MAX_ELEMENTS = 200000
MAX_TITLE = 300
MAX_EXCERPT = 400
RETENTION_DAYS = 365
MAX_STORED_ITEMS = 20000

# Data fora deste intervalo não é data: a Huntress publica itens com 01/01/1970
EARLIEST_PLAUSIBLE = calendar.timegm((2000, 1, 1, 0, 0, 0))
FUTURE_TOLERANCE_SECONDS = 86400


def _rx(*patterns):
	return re.compile('|'.join('(?:{0})'.format(pattern) for pattern in patterns), re.IGNORECASE)


# O vocabulário fechado. Cada tema casa por termos em inglês e em português, e a
# mesma regra roda na coleta, na tela e nos testes. Mudar um padrão muda a
# leitura de todo o histórico na próxima consulta, sem baixar nada de novo: a
# classificação é feita na leitura, não gravada no item.
THEMES = [
	{'key': 'calendar_invite', 'label': 'Convite de calendário (.ics)',
		'rx': _rx(r'calendar[- ]invit', r'\.ics\b', r'\bics (?:file|attachment)', r'calendar (?:file|event|lure)',
			r'meeting invit', r'\brsvp\b', r'convites? de (?:calend|reuni)', r'arquivos? \.?ics\b')},
	{'key': 'qr_code', 'label': 'QR code (quishing)',
		'rx': _rx(r'\bqr[- ]?codes?\b', r'quishing')},
	{'key': 'device_code', 'label': 'Código de dispositivo e consentimento OAuth',
		'rx': _rx(r'device[- ]code', r'\boauth\b', r'consent phishing', r'illicit consent', r'token theft',
			r'c[oó]digo de dispositivo')},
	{'key': 'aitm', 'label': 'AitM e kits de phishing',
		'rx': _rx(r'\baitm\b', r'adversary[- ]in[- ]the[- ]middle', r'phishing[- ]as[- ]a[- ]service', r'\bphaas\b',
			r'phishing[- ]kits?', r'evilproxy', r'evilginx', r'tycoon ?2fa', r'mfa bypass', r'kits? de phishing',
			r'reverse[- ]proxy phishing')},
	{'key': 'bec', 'label': 'Fraude de pagamento e BEC',
		'rx': _rx(r'\bbec\b', r'business email compromise', r'invoice fraud', r'fake invoices?', r'wire fraud',
			r'payment diversion', r'faturas? falsas?', r'boletos? falsos?', r'golpe do (?:pix|boleto)', r'\bpix\b')},
	{'key': 'vishing', 'label': 'Vishing e falso help desk',
		'rx': _rx(r'vishing', r'help ?desk', r'callback phishing', r'\btoad\b', r'telephone[- ]oriented',
			r'voice phishing', r'golpe (?:por|de) (?:telefone|liga)')},
	{'key': 'clickfix', 'label': 'ClickFix e CAPTCHA falso',
		'rx': _rx(r'clickfix', r'filefix', r'fake captcha', r'captcha falso')},
	{'key': 'rmm', 'label': 'Abuso de ferramenta de acesso remoto (RMM)',
		'rx': _rx(r'\brmms?\b', r'remote (?:monitoring|access) (?:and management )?tools?', r'screenconnect',
			r'anydesk', r'connectwise', r'simplehelp')},
	{'key': 'legit_infra', 'label': 'Abuso de serviço legítimo',
		'rx': _rx(r'legitimate (?:infrastructure|services?|platforms?)', r'trusted (?:platforms?|services?)',
			r'sharepoint', r'onedrive', r'google (?:drive|docs|sites|forms)', r'docusign', r'power bi', r'calendly',
			r'dropbox', r'servi[cç]os? leg[ií]timos?')},
	{'key': 'ai_lure', 'label': 'Isca ou conteúdo gerado por IA',
		'rx': _rx(r'ai[- ]generated', r'generative ai', r'\bgenai\b', r'deepfakes?', r'synthetic media', r'ai[- ]themed',
			r'gerad[oa]s? (?:por|com) ia', r'intelig[eê]ncia artificial')},
	{'key': 'html_svg', 'label': 'Anexo HTML ou SVG',
		'rx': _rx(r'\bsvgs?\b', r'html smuggling', r'html attachments?', r'anexos? html')},
	{'key': 'thread_hijack', 'label': 'Sequestro de conversa',
		'rx': _rx(r'thread[- ]hijack', r'reply[- ]chain', r'email threads?', r'conversation hijack',
			r'sequestro de (?:conversa|thread)')},
	{'key': 'smishing', 'label': 'SMS e mensageiros (smishing)',
		'rx': _rx(r'smishing', r'\bsms\b', r'text messages?', r'whatsapp')}
]

THEME_BY_KEY = dict((theme['key'], theme) for theme in THEMES)

# Temas fortes o bastante para tornar uma publicação relevante sozinhos. Os
# demais (OAuth, SharePoint, IA, RMM) aparecem em notícia de todo tipo e só
# contam quando a publicação também fala de phishing
STRONG_THEMES = frozenset(['calendar_invite', 'qr_code', 'aitm', 'bec', 'vishing', 'clickfix',
	'thread_hijack', 'smishing'])

PHISHING_RX = _rx(r'phish', r'smishing', r'vishing', r'quishing', r'\bbec\b', r'business email compromise',
	r'credential (?:theft|harvest|steal)', r'social engineering', r'engenharia social', r'\bgolpes?\b',
	r'\blures?\b', r'\biscas?\b', r'spoof', r'impersonat', r'e-?mails? maliciosos?', r'malicious e-?mails?',
	r'malspam', r'account takeover', r'fraudulent e-?mails?')

SECTORS = [
	{'key': 'finance', 'label': 'Financeiro',
		'rx': _rx(r'\bbank', r'financial', r'fintech', r'\bbancos?\b', r'financeir', r'banc[aá]ri')},
	{'key': 'healthcare', 'label': 'Saúde',
		'rx': _rx(r'healthcare', r'hospitals?', r'\bsa[uú]de\b', r'hospitais', r'\bpharma')},
	{'key': 'government', 'label': 'Governo',
		'rx': _rx(r'government', r'public sector', r'federal agenc', r'\bgoverno', r'setor p[uú]blico',
			r'minist[eé]rio', r'prefeitura')},
	{'key': 'education', 'label': 'Educação',
		'rx': _rx(r'universit', r'education', r'\bschools?\b', r'educa[cç][aã]o', r'\bescolas?\b')},
	{'key': 'retail', 'label': 'Varejo e e-commerce',
		'rx': _rx(r'\bretail', r'e-?commerce', r'\bvarejo', r'\blojas? virtua')},
	{'key': 'manufacturing', 'label': 'Indústria',
		'rx': _rx(r'manufactur', r'ind[uú]stria')},
	{'key': 'energy', 'label': 'Energia',
		'rx': _rx(r'\benergy\b', r'oil and gas', r'\butilities\b', r'\benergia\b')},
	{'key': 'legal', 'label': 'Jurídico',
		'rx': _rx(r'law firms?', r'legal sector', r'jur[ií]dic', r'advocacia')},
	{'key': 'crypto', 'label': 'Criptoativos',
		'rx': _rx(r'\bcrypto', r'bitcoin', r'binance', r'criptomoeda', r'criptoativ')},
	{'key': 'hospitality', 'label': 'Turismo e hotelaria',
		'rx': _rx(r'hospitality', r'\bhotels?\b', r'booking\.com', r'\bturismo\b', r'hotelaria')},
	{'key': 'hr', 'label': 'RH e candidatos a vaga',
		'rx': _rx(r'job seekers?', r'recruit', r'\bhiring\b', r'candidatos?', r'recrutamento', r'\bvagas? de emprego')}
]

SECTOR_BY_KEY = dict((sector['key'], sector) for sector in SECTORS)

BRAZIL_RX = _rx(r'\bbrazil', r'\bbrasil', r'brasileir', r'latin america', r'\blatam\b', r'am[eé]rica latina', r'\bpix\b')

# Grupos citados. Um padrão de nomenclatura cobre a maior parte (UNC1151, TA577,
# Storm-1234, UAT-11985, APT29, FIN7, DEV-0537), e uma lista curta cobre os nomes
# próprios mais citados em phishing, inclusive os trojans bancários brasileiros
# distribuídos por e-mail. O prefixo é sensível a maiúsculas: "ta 2026" não é grupo.
ACTOR_CODE_RX = re.compile(r'\b(?:UNC|TA|UAT|APT|FIN|DEV|Storm)-?\d{2,5}\b')
ACTOR_NAMES = ['Scattered Spider', 'ShinyHunters', 'Lazarus', 'Kimsuky', 'Ghostwriter', 'Midnight Blizzard',
	'Star Blizzard', 'Void Blizzard', 'Octo Tempest', 'Muddled Libra', 'Fancy Bear', 'Cozy Bear', 'Lapsus$',
	'Black Basta', 'Mustang Panda', 'Grandoreiro', 'Astaroth', 'Coyote', 'Mekotio', 'Casbaneiro', 'Guildma',
	'Lumma', 'Rhadamanthys', 'DarkGate', 'Qakbot', 'Emotet', 'Remcos', 'AsyncRAT']
ACTOR_NAME_RX = re.compile(r'\b(' + '|'.join(re.escape(name) for name in ACTOR_NAMES) + r')(?![\w$])')
ACTOR_CANONICAL = dict((name.lower(), name) for name in ACTOR_NAMES)


# =============================================================================
# Leitura do XML
# =============================================================================

class FeedError(ValueError):
	"""O documento não é um feed que dê para ler. A mensagem vai para a tela."""


def _local(tag):
	return tag.rsplit('}', 1)[-1].rsplit(':', 1)[-1].lower()


def _refuse_dtd(*_args):
	raise FeedError('o documento declara DTD ou entidade, o que nenhum feed precisa')


def parse_xml(raw):
	"""Árvore mínima do documento, com DTD recusado. -> {'tag', 'attrs', 'text', 'children'}

	Expat direto em vez de ElementTree: o ElementTree acelerado não expõe os
	handlers, e recusar DOCTYPE e declaração de entidade é o que fecha XXE e
	"billion laughs" sem instalar defusedxml na imagem (§7.2).
	"""
	parser = xml.parsers.expat.ParserCreate(namespace_separator = '}')
	parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
	parser.StartDoctypeDeclHandler = _refuse_dtd
	parser.EntityDeclHandler = _refuse_dtd
	parser.UnparsedEntityDeclHandler = _refuse_dtd
	parser.ExternalEntityRefHandler = _refuse_dtd
	parser.buffer_text = True

	root = {'tag': '', 'attrs': {}, 'text': [], 'children': []}
	stack = [root]
	counter = [0]

	def start(tag, attrs):
		counter[0] += 1
		if counter[0] > MAX_ELEMENTS:
			raise FeedError('o documento tem elementos demais')
		node = {'tag': _local(tag), 'attrs': dict((_local(k), v) for k, v in attrs.items()),
			'text': [], 'children': []}
		stack[-1]['children'].append(node)
		stack.append(node)

	def end(_tag):
		node = stack.pop()
		node['text'] = ''.join(node['text'])

	def data(text):
		stack[-1]['text'].append(text)

	parser.StartElementHandler = start
	parser.EndElementHandler = end
	parser.CharacterDataHandler = data
	try:
		parser.Parse(raw, True)
	except xml.parsers.expat.ExpatError as error:
		raise FeedError('XML inválido ({0})'.format(xml.parsers.expat.ErrorString(error.code)))
	if not root['children']:
		raise FeedError('o documento está vazio')
	return root['children'][0]


def _child(node, *names):
	for child in node['children']:
		if child['tag'] in names:
			return child
	return None


def _child_text(node, *names):
	child = _child(node, *names)
	return (child['text'] or '').strip() if child else ''


def _walk_items(node):
	for child in node['children']:
		if child['tag'] in ('item', 'entry'):
			yield child
		elif child['tag'] in ('channel', 'feed', 'rdf'):
			for item in _walk_items(child):
				yield item


# `[^<>]` e não `[^>]`: com `[^>]`, um texto de muitos "<" sem nenhum ">" faz cada
# "<" varrer até o fim — quadrático, e o `re` não solta o GIL, então nem o tpool
# protege o hub. 80 mil "<" levavam 3 s; um documento no limite levaria horas.
_TAG_RX = re.compile(r'<[^<>]*>')
_SPACE_RX = re.compile(r'\s+')
# Teto do texto de um nó antes de limpar: o que se guarda é um trecho de 400
# caracteres, e nada justifica levar megabytes de um nó só até as regex
MAX_NODE_TEXT = 8 * MAX_EXCERPT


def strip_html(text):
	"""Texto puro: tags fora, entidades resolvidas, espaços colapsados."""
	text = _TAG_RX.sub(' ', (text or '')[:MAX_NODE_TEXT])
	return _SPACE_RX.sub(' ', html.unescape(text)).strip()


def clip(text, limit):
	if len(text) <= limit:
		return text
	cut = text[:limit].rsplit(' ', 1)[0]
	return (cut or text[:limit]).rstrip(' ,.;:') + '…'


def safe_link(url):
	"""O link, se for http(s) com host; senão ''. É a única coisa que o navegador segue."""
	url = (url or '').strip()
	try:
		parts = urllib.parse.urlsplit(url)
	except ValueError:
		return ''
	if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
		return ''
	return url


def parse_date(text, now = None):
	"""Epoch em segundos, ou None quando a data falta, não se lê ou não é plausível."""
	text = (text or '').strip()
	if not text:
		return None
	moment = None
	try:
		moment = email.utils.parsedate_to_datetime(text)
	except (TypeError, ValueError, IndexError):
		moment = None
	if moment is None:
		iso = text.replace('Z', '+00:00').replace('z', '+00:00')
		# fromisoformat do 3.8 (o Python da imagem até 11/2026) só aceitava fração com 3
		# ou 6 dígitos; a normalização para 6 continua válida no 3.14
		iso = re.sub(r'\.(\d+)', lambda match: '.' + (match.group(1) + '000000')[:6], iso)
		try:
			moment = datetime.datetime.fromisoformat(iso)
		except ValueError:
			return None
	if moment.tzinfo is None:
		moment = moment.replace(tzinfo = datetime.timezone.utc)
	epoch = int(moment.timestamp())
	if epoch < EARLIEST_PLAUSIBLE:
		return None
	if now is not None and epoch > now + FUTURE_TOLERANCE_SECONDS:
		return None
	return epoch


def _item_link(item):
	for child in item['children']:
		if child['tag'] != 'link':
			continue
		href = child['attrs'].get('href')
		# Atom: o link da página é o `alternate` (ou o sem `rel`)
		if href is not None:
			if child['attrs'].get('rel', 'alternate') == 'alternate':
				return href
			continue
		if (child['text'] or '').strip():
			return child['text'].strip()
	guid = _child(item, 'guid', 'id')
	if guid is not None and (guid['text'] or '').strip().startswith('http'):
		return guid['text'].strip()
	return ''


def item_id(link):
	return hashlib.sha1(link.encode('utf-8')).hexdigest()[:16]  # id de item, não segurança; usedforsecurity só no 3.9+  # nosec B324


def parse_feed(raw, now = None):
	"""Os itens de um documento RSS 2.0, RSS 1.0 ou Atom. -> [{'id', 'title', 'link', 'published', 'excerpt'}]

	Item sem link http(s) ou sem título fica de fora: sem link a tela não tem
	como levar à fonte, e uma alegação sem fonte é exatamente o que não se mostra.
	"""
	root = parse_xml(raw)
	if root['tag'] not in ('rss', 'feed', 'rdf'):
		raise FeedError('o documento não é RSS nem Atom (raiz <{0}>)'.format(root['tag']))
	items = []
	seen = set()
	for node in _walk_items(root):
		if len(items) >= MAX_ITEMS_PER_FEED:
			break
		title = clip(strip_html(_child_text(node, 'title')), MAX_TITLE)
		link = safe_link(_item_link(node))
		if not title or not link:
			continue
		identifier = item_id(link)
		if identifier in seen:
			continue
		seen.add(identifier)
		summary = _child_text(node, 'description', 'summary') or _child_text(node, 'encoded', 'content')
		categories = [strip_html(child['text'] or child['attrs'].get('term', ''))
			for child in node['children'] if child['tag'] in ('category', 'subject')]
		items.append({
			'id': identifier,
			'title': title,
			'link': link,
			'published': parse_date(_child_text(node, 'pubdate', 'published', 'date', 'issued', 'updated'), now),
			'excerpt': clip(strip_html(summary), MAX_EXCERPT),
			'categories': [category for category in categories if category][:8]
		})
	return items


# =============================================================================
# Classificação
# =============================================================================

def classify(item):
	"""O que uma publicação diz, pelo vocabulário fechado. Sem modelo, sem palpite."""
	text = ' '.join([item.get('title') or '', item.get('excerpt') or '', ' '.join(item.get('categories') or [])])
	themes = [theme['key'] for theme in THEMES if theme['rx'].search(text)]
	phishing = bool(PHISHING_RX.search(text))
	actors = []
	for match in ACTOR_CODE_RX.finditer(text):
		if match.group(0) not in actors:
			actors.append(match.group(0))
	for match in ACTOR_NAME_RX.finditer(text):
		name = ACTOR_CANONICAL[match.group(1).lower()]
		if name not in actors:
			actors.append(name)
	return {
		'relevant': phishing or any(theme in STRONG_THEMES for theme in themes),
		'themes': themes,
		'sectors': [sector['key'] for sector in SECTORS if sector['rx'].search(text)],
		'brazil': bool(BRAZIL_RX.search(text)),
		'actors': actors
	}


def item_time(item):
	"""Quando a publicação saiu; sem data, quando a coleta a viu pela primeira vez."""
	return item.get('published') or item.get('seenAt') or 0


# =============================================================================
# Acúmulo
# =============================================================================

def merge(stored, source_id, fetched, now):
	"""Itens guardados mais os recém-baixados de uma fonte, sem duplicar e sem os vencidos.

	Devolve uma lista nova: quem chama troca o arquivo inteiro de uma vez.
	"""
	horizon = now - RETENTION_DAYS * 86400
	by_id = {}
	for item in stored:
		if item_time(item) >= horizon:
			by_id[item['id']] = item
	for item in fetched:
		previous = by_id.get(item['id'])
		entry = dict(item, source = source_id, seenAt = previous['seenAt'] if previous else now)
		if not entry.get('categories'):
			entry.pop('categories', None)
		if item_time(entry) >= horizon:
			by_id[item['id']] = entry
	# O arquivo inteiro é lido a cada consulta sem cache, então tem teto: vinte mil
	# publicações são um ano das fontes do catálogo com folga, e o excedente é o
	# mais antigo
	return sorted(by_id.values(), key = item_time, reverse = True)[:MAX_STORED_ITEMS]


def valid_stored(item):
	"""Um registro do armazenamento que dá para usar. Um items.json corrompido não
	pode derrubar a coleta nem a tela por causa de um registro sem id."""
	return isinstance(item, dict) and isinstance(item.get('id'), str) and isinstance(item.get('title'), str) \
		and bool(safe_link(item.get('link'))) and isinstance(item.get('seenAt'), (int, float))


# =============================================================================
# Períodos
# =============================================================================

PERIOD_DAYS = {'7d': 7, '30d': 30, '90d': 90}
DEFAULT_PERIOD = '30d'
MONTH_RX = re.compile(r'^(\d{4})-(0[1-9]|1[0-2])$')
MONTHS_OFFERED = 3

MONTH_NAMES = ['janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho', 'julho', 'agosto', 'setembro',
	'outubro', 'novembro', 'dezembro']


def _month_start(year, month):
	return calendar.timegm((year, month, 1, 0, 0, 0))


def offered_months(now):
	"""Os meses que a tela oferece: o corrente e os dois anteriores, o mais recente primeiro."""
	today = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
	year, month = today.year, today.month
	months = []
	for _ in range(MONTHS_OFFERED):
		months.append('{0:04d}-{1:02d}'.format(year, month))
		month -= 1
		if month == 0:
			year, month = year - 1, 12
	return months


def normalize_period(period, now):
	if period in PERIOD_DAYS or period in offered_months(now):
		return period
	return DEFAULT_PERIOD


def period_bounds(period, now):
	"""(início, fim, rótulo) do período em epoch segundos. O fim do mês corrente é agora."""
	match = MONTH_RX.match(period or '')
	if match:
		year, month = int(match.group(1)), int(match.group(2))
		start = _month_start(year, month)
		end = _month_start(year + 1, 1) if month == 12 else _month_start(year, month + 1)
		return start, min(end, now), '{0} de {1}'.format(MONTH_NAMES[month - 1], year)
	days = PERIOD_DAYS.get(period, PERIOD_DAYS[DEFAULT_PERIOD])
	return now - days * 86400, now, 'últimos {0} dias'.format(days)


def offered_periods(now):
	periods = [{'key': key, 'label': '{0} dias'.format(days)} for key, days in
		sorted(PERIOD_DAYS.items(), key = lambda pair: pair[1])]
	for key in offered_months(now):
		label = period_bounds(key, now)[2]
		periods.append({'key': key, 'label': label[0].upper() + label[1:]})
	return periods


def covering_range(start, now, range_days):
	"""A menor janela de case_insights (`range_days`) que cobre `start`."""
	needed = (now - start) / 86400.0
	for key, days in sorted(range_days.items(), key = lambda pair: pair[1]):
		if days >= needed:
			return key
	return 'all'


# =============================================================================
# O ambiente
# =============================================================================

def _extension(name):
	name = (name or '').strip().lower()
	return name.rsplit('.', 1)[-1] if '.' in name else ''


def _host_of(value):
	value = (value or '').strip().lower()
	if '://' in value:
		try:
			return (urllib.parse.urlsplit(value).hostname or '').lower()
		except ValueError:
			return ''
	return value


def _on_shared_platform(host, shared_hosts):
	return bool(host) and any(host == shared or host.endswith('.' + shared) for shared in shared_hosts)


def _matches_signal(signal, observables, shared_hosts):
	for obs in observables or []:
		data_type = obs.get('dataType', '')
		value = obs.get('data') or (obs.get('attachment') or {}).get('name') or ''
		if signal == 'ics' and data_type == 'file' and _extension(value) == 'ics':
			return True
		if signal == 'html_svg' and data_type == 'file' and _extension(value) in ('html', 'htm', 'shtml', 'svg'):
			return True
		if signal == 'shared_host' and data_type in ('url', 'domain') and _on_shared_platform(
				_host_of(value), shared_hosts):
			return True
	return False


# Tema → sinal que dá para contar nos observáveis dos casos de ameaça. Tema fora
# desta tabela não tem como ser medido aqui e responde None, nunca zero: zero
# diria que o ambiente foi olhado e não tinha nada. QR code fica de fora porque a
# análise não decodifica QR em imagem.
THEME_SIGNALS = {
	'calendar_invite': {'signal': 'ics', 'label': 'com anexo .ics'},
	'html_svg': {'signal': 'html_svg', 'label': 'com anexo .html ou .svg'},
	'legit_infra': {'signal': 'shared_host', 'label': 'com link em plataforma compartilhada'}
}


def local_signals(threat_cases, observables_by_case, verdict_of, started_of, start_ms, end_ms, shared_hosts):
	"""Quantos casos de ameaça do período carregam o sinal de cada tema medível.

	`threat_cases` já vem filtrado (case_insights.threat_cases); `verdict_of` e
	`started_of` são as funções de case_insights, passadas para este módulo não
	depender do histórico. -> {'threatCases': n, 'themes': {tema: {'cases', 'malicious', 'label'}}}
	"""
	in_window = [case for case in threat_cases
		if started_of(case) is None or start_ms <= started_of(case) <= end_ms]
	themes = {}
	for theme, spec in THEME_SIGNALS.items():
		cases = [case for case in in_window
			if _matches_signal(spec['signal'], observables_by_case.get(case.get('_id')), shared_hosts)]
		themes[theme] = {
			'cases': len(cases),
			'malicious': sum(1 for case in cases if verdict_of(case) == 'Malicious'),
			'label': spec['label']
		}
	return {'threatCases': len(in_window), 'themes': themes}


# =============================================================================
# O panorama
# =============================================================================

# Quantos itens o payload carrega por grupo, e no total. A tela focada lista as
# alegações; mais do que isso num mês vira leitura que ninguém faz
ITEMS_PER_GROUP = 8
MAX_ITEMS_IN_PAYLOAD = 200
TOP_ACTORS = 12
# Um tema "em alta" precisa de pelo menos este tanto de publicações no período
TRENDING_MIN = 2


def _base_domain(host):
	labels = (host or '').lower().rstrip('.').split('.')
	# com.br, co.uk, gov.br: o domínio registrável tem três rótulos
	size = 3 if len(labels) >= 3 and labels[-2] in ('com', 'org', 'gov', 'net', 'co', 'edu') else 2
	return '.'.join(labels[-size:])


def link_host(link):
	try:
		return (urllib.parse.urlsplit(link or '').hostname or '').lower()
	except ValueError:
		return ''


def offsite(item, source):
	"""O link da publicação sai do domínio da fonte? Um feed comprometido que plante
	um link de phishing apareceria sob um nome confiável; a tela avisa em vez de calar."""
	site = link_host(source.get('site'))
	host = link_host(item.get('link'))
	return bool(site and host) and _base_domain(host) != _base_domain(site)


def _view(item, classification):
	source = BY_ID.get(item.get('source')) or {}
	return {
		'host': link_host(item.get('link')),
		'offsite': offsite(item, source),
		'id': item['id'],
		'title': item.get('title', ''),
		'link': item.get('link', ''),
		'source': item.get('source', ''),
		'sourceName': source.get('name', item.get('source', '')),
		'lang': source.get('lang', ''),
		'published': item_time(item),
		'excerpt': item.get('excerpt', ''),
		'themes': classification['themes'],
		'sectors': classification['sectors'],
		'actors': classification['actors'],
		'brazil': classification['brazil']
	}


def _relevant_between(items, start, end):
	found = []
	for item in items:
		moment = item_time(item)
		if not (start <= moment <= end):
			continue
		classification = classify(item)
		if classification['relevant']:
			found.append((item, classification))
	return found


def _group(entries, key_of):
	groups = {}
	for item, classification in entries:
		for key in key_of(classification):
			group = groups.setdefault(key, {'count': 0, 'sources': set(), 'items': []})
			group['count'] += 1
			group['sources'].add(item.get('source'))
			if len(group['items']) < ITEMS_PER_GROUP:
				group['items'].append(item['id'])
	return groups


def build_panorama(items, collecting_since, period, now, local = None, source_states = None):
	"""O payload do panorama de um período. Puro: tudo o que precisa entra por parâmetro.

	`items` vem do armazenamento, do mais recente para o mais antigo. `local` é o
	resultado de local_signals(), ou None quando os casos não puderam ser lidos.
	`source_states` é {id: source_status()} das fontes ligadas.
	"""
	period = normalize_period(period, now)
	start, end, label = period_bounds(period, now)
	previous_start = start - (end - start)

	current = _relevant_between(items, start, end)
	previous = _relevant_between(items, previous_start, start - 1)

	# A comparação com o período anterior só vale se a coleta já rodava nele
	# inteiro. Antes disso o "anterior" é vazio por falta de coleta, e qualquer
	# tema pareceria em alta
	compare = bool(collecting_since) and collecting_since <= previous_start
	previous_themes = _group(previous, lambda c: c['themes']) if compare else {}

	theme_groups = _group(current, lambda c: c['themes'])
	local_themes = (local or {}).get('themes') or {}
	themes = []
	for key, group in theme_groups.items():
		previous_count = previous_themes.get(key, {}).get('count', 0) if compare else None
		measured = local_themes.get(key) if local is not None else None
		themes.append({
			'key': key,
			'label': THEME_BY_KEY[key]['label'],
			'count': group['count'],
			'sources': len(group['sources']),
			'previous': previous_count,
			# "Em alta" afirma uma subida, e subida só existe com o período anterior
			# coletado. Sem ele, um tema frequente é só frequente
			'trending': compare and group['count'] >= TRENDING_MIN and group['count'] > previous_count,
			'items': group['items'],
			'measurable': key in THEME_SIGNALS,
			'local': dict(measured, threatCases = local['threatCases']) if measured else None
		})
	themes.sort(key = lambda theme: (theme['count'], theme['sources'], theme['key']), reverse = True)

	actor_groups = _group(current, lambda c: c['actors'])
	actors = sorted(({'name': name, 'count': group['count'], 'sources': len(group['sources']),
		'items': group['items']} for name, group in actor_groups.items()),
		key = lambda actor: (actor['count'], actor['name']), reverse = True)[:TOP_ACTORS]

	sector_groups = _group(current, lambda c: c['sectors'])
	sectors = sorted(({'key': key, 'label': SECTOR_BY_KEY[key]['label'], 'count': group['count'],
		'items': group['items']} for key, group in sector_groups.items()),
		key = lambda sector: (sector['count'], sector['key']), reverse = True)

	brazil = [item['id'] for item, classification in current if classification['brazil']]

	# O corte de itens não pode deixar de fora um que algum grupo cita: a tela
	# resolve o id para mostrar o título e o link da fonte
	cited = set(brazil[:ITEMS_PER_GROUP])
	for groups in (theme_groups, actor_groups, sector_groups):
		for group in groups.values():
			cited.update(group['items'])
	listed = [(item, classification) for index, (item, classification) in enumerate(current)
		if index < MAX_ITEMS_IN_PAYLOAD or item['id'] in cited]

	states = source_states or {}
	failing = sorted(source_id for source_id, state in states.items()
		if state.get('status') in ('failed', 'failing', 'stale'))
	return {
		'period': {'key': period, 'label': label, 'start': start, 'end': end},
		'periods': offered_periods(now),
		'collectingSince': collecting_since,
		# A janela começa antes da coleta: o que está na tela é parte do período
		'partial': not collecting_since or collecting_since > start,
		'compared': compare,
		'totals': {
			'relevant': len(current),
			'sources': len(set(item.get('source') for item, _ in current)),
			'enabledSources': len(states)
		},
		'themes': themes,
		'actors': actors,
		'sectors': sectors,
		'brazil': {'count': len(brazil), 'items': brazil[:ITEMS_PER_GROUP]},
		'items': [_view(item, classification) for item, classification in listed],
		'local': local,
		'sourcesFailing': failing
	}
