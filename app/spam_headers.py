"""Marcadores de correspondência em massa nos cabeçalhos do e-mail.

O que este módulo responde é uma pergunta estreita e mecânica: **esta mensagem
tem o formato de correio em massa legítimo?** Não é "isto é spam", e muito menos
"isto é seguro". A diferença importa, porque tudo aqui é escrito por quem enviou
a mensagem — e quem manda phishing também sabe escrever `List-Unsubscribe`.

Por isso o módulo devolve *sinal*, nunca veredito. Quem transforma sinal em
classificação é `scoring.py`, e a promoção a `spam` exige o que o remetente não
controla: a autenticação registrada pelo servidor que recebeu (SPF/DKIM/DMARC,
lida em `case_from_email.extract_authentication_results`). Um `List-Unsubscribe`
num domínio não autenticado não vale nada; num domínio com DMARC pass, vale a
triagem que evita a analista abrir a mesma newsletter quarenta vezes por semana.

Duas famílias de marcador, de origens diferentes e com pesos diferentes:

* **De quem enviou** — a gramática de gestão de listas: `List-Unsubscribe` e
  companhia (RFC 2369), `List-Id` (RFC 2919), a baixa por um clique
  (RFC 8058), `Precedence: bulk`, `Auto-Submitted` (RFC 3834) e a etiquetagem
  de publicidade que a RFC 3098 recomenda (`X-Advertisement`, prefixo `ADV:`
  no assunto). Falsificável linha por linha.
* **De quem recebeu** — o veredito do antispam do próprio servidor:
  `X-Spam-Flag`, `X-Spam-Status`, o SCL do Exchange Online. Não é falsificável
  pelo remetente, mas só existe quando o servidor de entrada escreve.

`scan()` é pura: recebe um mapeamento de cabeçalhos e devolve um dicionário.
Nada de rede, nada de configuração, nada de `email.message` — o que permite
testá-la com um dicionário literal, que é como `test_spam_headers.py` faz.
"""

import re


# --------------------------------------------------------------------------- #
# Regras                                                                       #
# --------------------------------------------------------------------------- #
#
# `header` é comparado em minúsculas: ou igualdade exata (str) ou casamento de
# padrão (regex compilada), porque a família `X-...-Campaign-Id` de cada ESP tem
# um nome diferente e enumerá-los todos seria uma lista que envelhece sozinha.
#
# `value` restringe o conteúdo quando a presença do cabeçalho, sozinha, não diz
# nada: `Precedence` existe em mensagem pessoal, `Precedence: bulk` não.
#
# `weight` é o quanto aquele marcador soma no sinal [0,1], que satura em 1.0. Os
# valores não são arbitrários: quanto mais caro for falsificar o marcador, mais
# ele pesa. `List-Unsubscribe-Post` é o mais caro de todos — a baixa por um
# clique exige que o remetente aceite e honre um POST, infraestrutura que uma
# campanha descartável de duas semanas não monta.

SENDER_RULES = [
	{
		'id': 'list_unsubscribe_post',
		'header': 'list-unsubscribe-post',
		'value': re.compile(r'list-unsubscribe\s*=\s*one-click', re.IGNORECASE),
		'weight': 0.30,
		'rfc': 'RFC 8058',
		'label': 'baixa por um clique (One-Click)'
	},
	{
		'id': 'list_unsubscribe',
		'header': 'list-unsubscribe',
		'value': None,
		'weight': 0.25,
		'rfc': 'RFC 2369',
		'label': 'endereço de descadastramento'
	},
	{
		'id': 'list_id',
		'header': 'list-id',
		'value': None,
		'weight': 0.25,
		'rfc': 'RFC 2919',
		'label': 'identificador de lista'
	},
	{
		'id': 'list_management',
		'header': re.compile(r'^list-(help|subscribe|owner|archive|post)$'),
		'value': None,
		'weight': 0.10,
		'rfc': 'RFC 2369',
		'label': 'cabeçalho de gestão de lista'
	},
	{
		'id': 'precedence_bulk',
		'header': 'precedence',
		'value': re.compile(r'^\s*(bulk|junk|list)\s*$', re.IGNORECASE),
		'weight': 0.20,
		'rfc': 'uso histórico',
		'label': 'Precedence: bulk/junk/list'
	},
	{
		'id': 'auto_submitted',
		'header': 'auto-submitted',
		'value': re.compile(r'auto-(generated|replied|notified)', re.IGNORECASE),
		'weight': 0.15,
		'rfc': 'RFC 3834',
		'label': 'mensagem gerada automaticamente'
	},
	# RFC 3098 — a recomendação de como anunciar sem ser confundido com abuso.
	# Quem etiqueta a própria publicidade não está escondendo nada, e é o
	# marcador mais explícito que existe: quase ninguém o usa, e quem usa, usa
	# de propósito
	{
		'id': 'advertisement_header',
		'header': re.compile(r'^x-(advertisement|advertising|promotion)$'),
		'value': None,
		'weight': 0.35,
		'rfc': 'RFC 3098',
		'label': 'autoetiquetagem de publicidade'
	},
	{
		'id': 'bulk_mail_header',
		'header': re.compile(r'^(x-)?bulk-?mail$'),
		'value': None,
		'weight': 0.20,
		'rfc': 'uso histórico',
		'label': 'marcação de envio em massa'
	},
	# Impressão digital de plataforma de envio: SendGrid, Mailgun, Amazon SES,
	# Mailchimp/Mandrill, Google, e o esquema de reclamação da CSA. Nenhum
	# individualmente prova nada; juntos descrevem uma infraestrutura de envio
	# em massa que existe antes desta mensagem
	{
		'id': 'esp_fingerprint',
		'header': re.compile(
			r'^(feedback-id|x-feedback-id|x-csa-complaints|x-report-abuse(-to)?|'
			r'x-sg-eid|x-sg-campaign-id|x-mailgun-[a-z-]+|x-ses-[a-z-]+|'
			r'x-mandrill-user|x-mc-user|x-campaign(-?id)?|x-mailer-campaign|'
			r'x-marketing-?(id|campaign)|x-mailchimp-[a-z-]+)$'),
		'value': None,
		'weight': 0.20,
		'rfc': 'convenção de mercado',
		'label': 'identificação de plataforma de disparo'
	}
]


# O veredito do antispam de quem recebeu. Origem diferente da lista acima, e é
# por isso que mora num registro separado: o remetente não escreve estes.
FILTER_RULES = [
	{
		'id': 'spam_flag',
		'header': 'x-spam-flag',
		'value': re.compile(r'^\s*yes\s*$', re.IGNORECASE),
		'weight': 0.50,
		'rfc': 'SpamAssassin',
		'label': 'marcado como spam pelo servidor de entrada'
	},
	{
		'id': 'spam_status',
		'header': 'x-spam-status',
		'value': re.compile(r'^\s*yes\b', re.IGNORECASE),
		'weight': 0.50,
		'rfc': 'SpamAssassin',
		'label': 'X-Spam-Status: Yes'
	},
	{
		'id': 'spam_level',
		'header': 'x-spam-level',
		'value': re.compile(r'^\s*\*{5,}'),
		'weight': 0.40,
		'rfc': 'SpamAssassin',
		'label': 'pontuação alta no filtro de entrada'
	}
]


# O SCL do Exchange Online não cabe numa regra de presença: o cabeçalho existe em
# toda mensagem que passa pelo Microsoft 365 e o que importa é o número dentro
# dele. 5 é o limiar em que o próprio EOP começa a tratar como massa indesejada;
# abaixo disso o cabeçalho não diz nada
SCL_HEADERS = ('x-microsoft-antispam', 'x-forefront-antispam-report')
SCL_PATTERN = re.compile(r'\bSCL[:=]\s*(-?\d+)', re.IGNORECASE)
SCL_BULK_MIN = 5

# BCL (Bulk Complaint Level) é a leitura da Microsoft para "massa legítima com
# reclamações". Acima de 4 o próprio EOP considera envio em massa
BCL_PATTERN = re.compile(r'\bBCL[:=]\s*(\d+)', re.IGNORECASE)
BCL_BULK_MIN = 4

# RFC 3098 §2: o prefixo no assunto é a outra metade da autoetiquetagem, e é a
# única regra deste módulo que não olha para um cabeçalho de gestão de lista
SUBJECT_ADV_PATTERN = re.compile(r'^\s*(\[)?adv(ert|ertisement)?(\])?\s*[:\-]', re.IGNORECASE)

# Os marcadores que caracterizam gestão de lista de verdade — os que fazem a
# mensagem ser *correspondência em massa* e não apenas "automática". É este
# conjunto, e não a soma dos pesos, que autoriza a triagem como spam: uma
# mensagem com apenas `Auto-Submitted` é uma resposta automática de férias
LIST_MARKERS = frozenset(['list_unsubscribe_post', 'list_unsubscribe', 'list_id',
	'list_management', 'precedence_bulk', 'advertisement_header', 'bulk_mail_header'])


def _matches(rule, name, value):
	header = rule['header']
	if isinstance(header, str):
		if name != header:
			return False
	elif not header.match(name):
		return False
	if rule['value'] is None:
		return True
	return bool(rule['value'].search(value))


def _iter_headers(headers):
	"""Pares (nome minúsculo, valor texto) a partir de qualquer forma de cabeçalho.

	Aceita um `email.message.Message` (que tem `items()` e repete um nome quando
	ele aparece duas vezes), um dicionário comum ou uma lista de pares. Um valor
	que não seja texto vira texto: cabeçalho malformado é comum em phishing e não
	pode derrubar a varredura.
	"""
	if headers is None:
		return []
	items = None
	if hasattr(headers, 'items'):
		try:
			items = list(headers.items())
		except Exception:
			items = None
	if items is None:
		try:
			items = list(headers)
		except Exception:
			return []
	pairs = []
	for item in items:
		try:
			name, value = item
		except (TypeError, ValueError):
			continue
		try:
			pairs.append((str(name).strip().lower(), str(value)))
		except Exception:
			continue
	return pairs


def scan(headers, subject = ''):
	"""Varre os cabeçalhos e devolve o sinal de correspondência em massa.

	Devolve sempre a mesma forma, inclusive quando não encontra nada:

	    {'value': 0.0..1.0,     # sinal saturado, o que `scoring.py` consome
	     'bulk': bool,          # tem gramática de gestão de lista
	     'oneClick': bool,      # tem baixa por um clique (RFC 8058)
	     'filtered': bool,      # o servidor de entrada já o marcou como spam
	     'markers': [...],      # o que casou, para a tela mostrar
	     'scl': int|None, 'bcl': int|None}

	`markers` é o que aparece na interface, e existe por uma razão de operação:
	uma triagem automática que a analista não consegue auditar vira uma caixa
	preta que ela desliga no primeiro falso positivo.
	"""
	result = {'value': 0.0, 'bulk': False, 'oneClick': False, 'filtered': False,
		'markers': [], 'scl': None, 'bcl': None}
	pairs = _iter_headers(headers)

	seen = set()
	total = 0.0

	def record(rule, detail = ''):
		# Um marcador conta uma vez. `List-Unsubscribe` repetido três vezes é o
		# mesmo fato, e somá-lo três vezes só inflaria o sinal
		if rule['id'] in seen:
			return
		seen.add(rule['id'])
		result['markers'].append({
			'id': rule['id'], 'label': rule['label'], 'rfc': rule['rfc'],
			'weight': rule['weight'], 'detail': detail[:120]
		})

	for name, value in pairs:
		for rule in SENDER_RULES:
			if _matches(rule, name, value):
				record(rule, '{0}: {1}'.format(name, ' '.join(value.split())))
		for rule in FILTER_RULES:
			if _matches(rule, name, value):
				record(rule, '{0}: {1}'.format(name, ' '.join(value.split())))
				result['filtered'] = True
		if name in SCL_HEADERS:
			match = SCL_PATTERN.search(value)
			if match:
				try:
					scl = int(match.group(1))
				except ValueError:
					scl = None
				if scl is not None and (result['scl'] is None or scl > result['scl']):
					result['scl'] = scl
			match = BCL_PATTERN.search(value)
			if match:
				try:
					bcl = int(match.group(1))
				except ValueError:
					bcl = None
				if bcl is not None and (result['bcl'] is None or bcl > result['bcl']):
					result['bcl'] = bcl

	if result['scl'] is not None and result['scl'] >= SCL_BULK_MIN:
		record({'id': 'scl', 'label': 'SCL {0} no filtro do Exchange Online'.format(result['scl']),
			'rfc': 'Microsoft 365', 'weight': 0.45}, 'SCL={0}'.format(result['scl']))
		result['filtered'] = True
	if result['bcl'] is not None and result['bcl'] >= BCL_BULK_MIN:
		record({'id': 'bcl', 'label': 'BCL {0} — envio em massa'.format(result['bcl']),
			'rfc': 'Microsoft 365', 'weight': 0.25}, 'BCL={0}'.format(result['bcl']))

	if subject and SUBJECT_ADV_PATTERN.match(str(subject)):
		record({'id': 'subject_adv', 'label': 'assunto com prefixo ADV:',
			'rfc': 'RFC 3098', 'weight': 0.35}, str(subject)[:120])

	for marker in result['markers']:
		total += marker['weight']
		if marker['id'] in LIST_MARKERS:
			result['bulk'] = True
		if marker['id'] == 'list_unsubscribe_post':
			result['oneClick'] = True

	# Satura em 1.0: os fatores do score vivem em [0,1] por definição, e deixar
	# um deles passar disso quebraria a normalização em silêncio
	result['value'] = round(min(1.0, total), 4)
	return result


_AR_DKIM_PASS = re.compile(r'^\s*dkim\s*=\s*pass\b(.*)$', re.IGNORECASE)
_AR_DKIM_DOMAIN = re.compile(r'header\.(?:d|i)\s*=\s*([^\s;]+)', re.IGNORECASE)
_DKIM_TAG = re.compile(r'(?:^|;)\s*([A-Za-z]+)\s*=\s*([^;]*)')


def _related_domains(first, second):
	return bool(first) and bool(second) and (
		first == second or first.endswith('.' + second) or second.endswith('.' + first))


def one_click_signed(headers, from_domain):
	"""Se a baixa por um clique vem assinada pelo próprio remetente — RFC 8058 §4.

	A RFC 8058 exige que `List-Unsubscribe` e `List-Unsubscribe-Post` estejam
	cobertos por uma assinatura DKIM válida: sem isso um intermediário poderia
	trocar o endereço de descadastramento, e o provedor de caixa postal não pode
	disparar o POST. É o que Gmail e Yahoo cobram de todo remetente em massa desde
	fevereiro de 2024, e é o que torna o sinal caro de imitar: não basta escrever
	o cabeçalho, é preciso assiná-lo com uma chave publicada no DNS de um domínio
	alinhado ao From, e que o servidor de entrada tenha validado.

	Verdadeiro quando, ao mesmo tempo:
	  * os dois cabeçalhos existem;
	  * o PRIMEIRO Authentication-Results (o do servidor que recebeu — os demais
	    viajaram com a mensagem e são falsificáveis, a mesma regra de
	    case_from_email.extract_authentication_results) registra dkim=pass para
	    um domínio;
	  * uma DKIM-Signature desse domínio, alinhado ao From, lista os dois
	    cabeçalhos em h=.

	Medido nas 12 mensagens de marca com baixa por um clique desta instalação
	(2026-09-15): todas passam. O phishing do mesmo período não trazia nenhum dos
	dois cabeçalhos.
	"""
	from_domain = str(from_domain or '').strip().lower()
	if not from_domain:
		return False
	pairs = _iter_headers(headers)
	names = set(name for name, _value in pairs)
	if 'list-unsubscribe' not in names or 'list-unsubscribe-post' not in names:
		return False

	results = [value for name, value in pairs if name == 'authentication-results']
	if not results:
		return False
	passing = set()
	for segment in ' '.join(results[0].split()).split(';'):
		match = _AR_DKIM_PASS.match(segment)
		if not match:
			continue
		domain = _AR_DKIM_DOMAIN.search(match.group(1))
		if domain:
			# header.i pode vir como endereço inteiro; o domínio é o que vem depois do @
			passing.add(domain.group(1).rsplit('@', 1)[-1].strip().lower())

	for name, value in pairs:
		if name != 'dkim-signature':
			continue
		tags = {}
		for key, tag_value in _DKIM_TAG.findall(' '.join(value.split())):
			tags[key.lower()] = tag_value.strip()
		domain = tags.get('d', '').lower()
		if domain not in passing or not _related_domains(domain, from_domain):
			continue
		signed = set(item.strip().lower() for item in tags.get('h', '').replace(' ', '').split(':'))
		if 'list-unsubscribe' in signed and 'list-unsubscribe-post' in signed:
			return True
	return False


def summary(signals):
	"""Uma linha de prosa sobre o que a varredura encontrou, para log e para tela."""
	signals = signals or {}
	markers = signals.get('markers') or []
	if not markers:
		return 'nenhum marcador de correspondência em massa nos cabeçalhos'
	names = ', '.join(marker['label'] for marker in markers[:4])
	if len(markers) > 4:
		names += ' e mais {0}'.format(len(markers) - 4)
	return '{0} marcador(es) de massa: {1}'.format(len(markers), names)
