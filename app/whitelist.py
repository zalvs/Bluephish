"""Whitelist v2 — as quatro formas de liberação e o que cada uma pode fazer.

O v1 tinha um significado só para "whitelist": não extraia esse observable. Era
redução de ruído, e todo tipo (mail, ip, domain, url, filename, filetype, hash)
fazia a mesma coisa. O v2 separa dois efeitos de risco muito diferente:

- `suppress` — o observable não entra na análise. É o comportamento do v1, e
  vale para domínio, URL e hash.
- `downgrade` — a análise roda inteira, o veredito é calculado normalmente e
  **depois** rebaixado para Safe, com o rebaixamento registrado. Só `sender`.

Só `sender` rebaixa veredito, e isso não é configurável. É o único tipo cuja
identidade o servidor de e-mail autentica criptograficamente (DKIM/DMARC);
domínio, URL e hash aparecem no corpo, que quem ataca escreve. Fixar o efeito no
tipo impede que alguém crie sem perceber um "confie em qualquer e-mail que
contenha esta URL".

O arquivo guarda só a declaração — o que quem administra escreveu. Contadores,
última correspondência e suspensão automática vivem no banco, porque o caminho
da análise não pode reescrever o arquivo que a interface acabou de editar. O
estado efetivo de uma regra é:

    declarada e habilitada  ∧  não expirada  ∧  não suspensa

Falha fechada: se o arquivo não abrir, não validar ou vier de uma versão
desconhecida, `load()` devolve um conjunto vazio cujos matchers nunca casam. A
análise segue normalmente e nada é liberado — ao contrário do v1, onde um JSON
malformado abortava a análise inteira (case_from_email.py:606).
"""

import datetime
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import urllib.parse


# --- Esquema ---------------------------------------------------------------

SCHEMA_VERSION = 2

TYPE_SENDER = 'sender'
TYPE_DOMAIN = 'domain'
TYPE_URL = 'url'
TYPE_HASH = 'hash'
TYPE_IP = 'ip'
TYPES = [TYPE_SENDER, TYPE_DOMAIN, TYPE_URL, TYPE_HASH, TYPE_IP]

EFFECT_DOWNGRADE = 'downgrade'
EFFECT_SUPPRESS = 'suppress'

# O efeito é propriedade do tipo, não um campo que se escolhe
EFFECT_BY_TYPE = {
	TYPE_SENDER: EFFECT_DOWNGRADE,
	TYPE_DOMAIN: EFFECT_SUPPRESS,
	TYPE_URL: EFFECT_SUPPRESS,
	TYPE_HASH: EFFECT_SUPPRESS,
	TYPE_IP: EFFECT_SUPPRESS,
}

URL_MODE_PREFIX = 'prefix'
URL_MODE_REGEX = 'regex'
URL_MODES = [URL_MODE_PREFIX, URL_MODE_REGEX]

# Prazo cravado no servidor quando quem cria não informa nada: a pressa do dia a
# dia não deve produzir regra eterna por acidente
DEFAULT_TTL_DAYS = 180
MAX_TTL_DAYS = 365 * 5

# Uma regra permanente (expires_at nulo) exige justificativa escrita e cargo de
# global_admin. É a trava contra o "permanente por preguiça de renovar"
PERMANENT_REASON_MIN_LENGTH = 15
REASON_MAX_LENGTH = 500

# Teto do que se aceita casar. Uma URL de 8 KB fabricada por quem ataca não pode
# virar tempo de CPU dentro do worker de análise
MAX_URL_LENGTH = 2048
MAX_VALUE_LENGTH = 512
MAX_PATTERN_LENGTH = 256


# Sufixos sob os quais qualquer pessoa registra um nome em minutos: hospedagem
# multi-inquilino, túneis, DNS dinâmico e os sufixos públicos de país. Um
# curinga aqui não libera "um parceiro", libera quem criar uma conta grátis
# agora. Estar na lista bloqueia a entrada; ser pai de um destes só gera aviso,
# porque recusar `google.com` inteiro por causa de `sites.google.com` seria
# demais
PUBLIC_SUFFIXES = {
	# Sufixos públicos de país mais usados por aqui
	'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'blog.br',
	'co.uk', 'org.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.jp',
	'com.mx', 'com.ar', 'com.co', 'com.pt', 'co.in', 'co.za', 'com.cn',
	# Hospedagem e plataformas onde cada inquilino ganha um subdomínio
	'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
	'myshopify.com', 'squarespace.com', 'webflow.io', 'notion.site',
	'sharepoint.com', 'onmicrosoft.com', 'azurewebsites.net',
	'blob.core.windows.net', 'web.core.windows.net', 'cloudapp.azure.com',
	'amazonaws.com', 's3.amazonaws.com', 'cloudfront.net',
	'elasticbeanstalk.com', 'herokuapp.com', 'netlify.app', 'vercel.app',
	'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'r2.dev',
	'github.io', 'gitlab.io', 'glitch.me', 'repl.co', 'replit.dev',
	'onrender.com', 'fly.dev', '000webhostapp.com', 'googleusercontent.com',
	'sites.google.com', 'appspot.com', 'translate.goog',
	# Túneis e DNS dinâmico
	'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'serveo.net',
	'localtunnel.me', 'duckdns.org', 'no-ip.com', 'noip.com', 'hopto.org',
	'zapto.org', 'ddns.net', 'sytes.net', 'myftp.org',
}


# --- Normalização ----------------------------------------------------------

def _labels(domain):
	return [label for label in (domain or '').split('.') if label]


def _is_ascii(text):
	# str.isascii() só existe a partir do 3.7; a imagem roda 3.8, mas a forma
	# explícita também documenta o que está sendo checado
	try:
		(text or '').encode('ascii')
		return True
	except UnicodeEncodeError:
		return False


def normalize_domain(raw):
	"""Devolve o domínio em minúsculas e ASCII (punycode), ou '' se não for um.

	O ponto final é removido (a forma absoluta do DNS) e cada rótulo não-ASCII
	vira punycode. Guardar sempre a forma ASCII é o que faz `рaypal.com` com "р"
	cirílico e `paypal.com` serem, no arquivo, dois valores visivelmente
	diferentes em vez de dois textos que ninguém distingue na tela.
	"""
	text = (raw or '').strip().lower().rstrip('.')
	if not text or len(text) > MAX_VALUE_LENGTH:
		return ''
	if '/' in text or '@' in text or ' ' in text or ':' in text:
		return ''
	encoded = []
	for label in text.split('.'):
		if not label:
			return ''
		if _is_ascii(label):
			encoded.append(label)
			continue
		try:
			encoded.append(label.encode('idna').decode('ascii'))
		except Exception:
			return ''
	result = '.'.join(encoded)
	if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$', result):
		return ''
	return result


def has_non_ascii(raw):
	return not _is_ascii(raw)


def normalize_address(raw):
	"""Devolve o endereço como `local@dominio`, domínio em punycode, minúsculo.

	A parte local também vai a minúsculas. A RFC a define sensível a maiúsculas,
	mas nenhum provedor real trata assim, e aqui ela só estreita uma confiança
	que o alinhamento DKIM já concedeu ao domínio — casar `Faturamento@` com
	`faturamento@` não amplia nada.

	O rótulo de sub-endereçamento (`nome+etiqueta@`) NÃO é removido: apagá-lo
	faria a regra `nome@` valer para `nome+qualquer-coisa@`, uma ampliação
	silenciosa do que se escreveu.
	"""
	text = (raw or '').strip().lower()
	if not text or len(text) > MAX_VALUE_LENGTH or '@' not in text:
		return ''
	local, _sep, domain = text.rpartition('@')
	domain = normalize_domain(domain)
	if not local or not domain or ' ' in local or '@' in local:
		return ''
	return '{0}@{1}'.format(local, domain)


def normalize_hash(raw):
	"""Devolve o SHA-256 em minúsculas, ou '' quando não é um SHA-256."""
	text = (raw or '').strip().lower()
	if re.match(r'^[0-9a-f]{64}$', text):
		return text
	return ''


# Faixa larga demais deixa de ser "o gateway do parceiro" e vira "metade de um
# provedor de nuvem". O piso recusa; o teto de conforto só avisa
IPV4_MIN_PREFIX = 16
IPV4_WARN_PREFIX = 24
IPV6_MIN_PREFIX = 32
IPV6_WARN_PREFIX = 48


def normalize_ip(raw):
	"""Devolve o endereço ou a rede em forma canônica, ou '' se não for nenhum.

	Aceita endereço solto (`203.0.113.7`) e CIDR (`203.0.113.0/24`). O endereço
	solto é guardado como rede /32 (ou /128), para que exista um só caminho de
	comparação.
	"""
	text = (raw or '').strip().lower()
	if not text or len(text) > MAX_VALUE_LENGTH:
		return ''
	try:
		# strict=False aceita 203.0.113.7/24 e guarda a rede 203.0.113.0/24, em
		# vez de recusar o que a pessoa quis dizer
		network = ipaddress.ip_network(text, strict = False)
	except ValueError:
		return ''
	return str(network)


def is_public_ip_value(value):
	"""Se a rede tem algo roteável na internet. Vale para endereço e para CIDR."""
	try:
		network = ipaddress.ip_network(value, strict = False)
	except ValueError:
		return False
	return network.is_global


def _ip_covers(rule_value, observed):
	try:
		network = ipaddress.ip_network(rule_value, strict = False)
		address = ipaddress.ip_address(observed)
	except ValueError:
		return False
	# Versões diferentes nunca se cobrem, e o operador `in` levanta se misturar
	if network.version != address.version:
		return False
	return address in network


def _clean_path(path):
	"""Resolve `.`, `..` e um nível de percent-encoding no caminho."""
	try:
		decoded = urllib.parse.unquote(path or '')
	except Exception:
		decoded = path or ''
	parts = []
	for segment in decoded.split('/'):
		if segment in ('', '.'):
			continue
		if segment == '..':
			if parts:
				parts.pop()
			continue
		parts.append(segment)
	return '/' + '/'.join(parts)


def normalize_url(raw):
	"""Devolve (host, alvo) — o host autoritativo e `caminho[?consulta]`.

	Casar contra o texto cru da URL é o erro que abre todas as evasões
	clássicas: `http://exemplo.com@evil.com` (o host é evil.com),
	`http://evil.com#exemplo.com` (o fragmento nem chega ao servidor),
	`%65xemplo`, `..` no caminho, porta padrão explícita. Aqui a URL é
	desmontada e o que volta é o que o navegador realmente visitaria: o host que
	`urlsplit` extrai depois do último `@`, sem porta, em punycode; e o caminho
	já resolvido.

	A consulta entra no alvo porque é onde mora o redirecionamento aberto —
	`/url?q=<phishing>` precisa ser distinguível de `/url`.

	Devolve (None, None) quando não dá para ler a URL.
	"""
	text = (raw or '').strip()
	if not text or len(text) > MAX_URL_LENGTH:
		return None, None
	if '://' not in text:
		text = 'http://' + text
	try:
		split = urllib.parse.urlsplit(text)
		host = split.hostname or ''
	except ValueError:
		return None, None
	host = normalize_domain(host)
	if not host:
		return None, None
	target = _clean_path(split.path)
	if split.query:
		target = '{0}?{1}'.format(target, split.query)
	return host, target


# Domínio reservado pela RFC 2606 para exemplo: nunca resolve, nunca é de
# ninguém. As variantes de evasão precisam de um "atacante" que não possa por
# acidente ser um host real de quem está testando
EVASION_HOST = 'evil-exemplo.test'


def evasion_variants(url):
	"""Reescreve uma URL nas formas clássicas de enganar quem casa texto cru.

	Existe para responder "essa regra vai ser efetiva?" com fato em vez de
	opinião: se alguma destas casar, o padrão está frouxo e libera phishing. A
	normalização já fecha as quatro, então o esperado é que nenhuma case — e ver
	isso na tela é o que dá confiança na regra.
	"""
	host, target = normalize_url(url)
	if not host:
		return []
	target = target or '/'
	return [
		{'label': 'userinfo antes do @ (o host real é {0})'.format(EVASION_HOST),
			'url': 'http://{0}@{1}{2}'.format(host, EVASION_HOST, target)},
		{'label': 'domínio como sufixo de outro',
			'url': 'http://{0}.{1}{2}'.format(host, EVASION_HOST, target)},
		{'label': 'domínio no fragmento, que nem chega ao servidor',
			'url': 'http://{0}{1}#{2}'.format(EVASION_HOST, target, host)},
		{'label': 'domínio na consulta, como redirecionamento',
			'url': 'http://{0}/r?destino=https://{1}{2}'.format(EVASION_HOST, host, target)},
	]


# Quantos hosts ou caminhos cabem numa alternância antes de o padrão virar
# ilegível. Passando disso, a sugestão estreita o que dá e avisa
MAX_ALTERNATIVES = 8


def _host_pattern_for(hosts):
	r"""Deriva o padrão de host de um conjunto de hosts já normalizados.

	Quando eles só diferem no primeiro rótulo — `nf.empresa.com.br` e
	`rh.empresa.com.br` — o padrão sai como `(nf|rh)\.empresa\.com\.br`, que é
	o que uma pessoa escreveria à mão. Fora disso, alterna os hosts inteiros:
	verboso, mas nunca mais amplo do que o que foi colado.
	"""
	unique = sorted(set(hosts))
	if len(unique) == 1:
		return re.escape(unique[0])

	split = [_labels(host) for host in unique]
	tails = {tuple(labels[1:]) for labels in split}
	heads = [labels[0] for labels in split]
	if len(tails) == 1 and len(unique) <= MAX_ALTERNATIVES and all(len(labels) > 1 for labels in split):
		tail = '.'.join(next(iter(tails)))
		return '({0})\\.{1}'.format('|'.join(re.escape(head) for head in sorted(heads)), re.escape(tail))

	return '({0})'.format('|'.join(re.escape(host) for host in unique[:MAX_ALTERNATIVES]))


def _common_path_prefix(targets):
	"""O maior começo de caminho comum, cortado no `/`.

	Cortar no separador é o que impede a sugestão de propor `/relat` a partir de
	`/relatorios` e `/relatos` — um prefixo que casa metade de um nome de pasta
	não descreve nada que alguém queira liberar.
	"""
	paths = [target.split('?', 1)[0] for target in targets]
	if not paths:
		return ''
	segments = [[part for part in path.split('/') if part] for path in paths]
	common = []
	for index in range(min(len(item) for item in segments)):
		current = segments[0][index]
		if any(item[index] != current for item in segments):
			break
		common.append(current)
	if not common:
		return ''
	return '/' + '/'.join(common) + '/'


def suggest_url_patterns(urls):
	"""Sugere padrões de host e caminho a partir de URLs cruas.

	O analista cola o endereço que quer liberar e recebe o padrão pronto, em três
	alcances, com o porquê de cada escolha. Existe porque escrever a regex à mão é
	onde nascem os dois erros que este módulo passa a vida barrando: o ponto sem
	escapar, que transforma `empresa.com.br` em algo que também aceita
	`empresaXcomYbr`, e o `.*` frouxo nas pontas, que deixa o host virar sufixo de
	outro domínio.

	Devolve (sugestões, hosts, problemas).
	"""
	readable = []
	problems = []
	for url in urls:
		host, target = normalize_url(url)
		if not host:
			problems.append('Não dá para ler esta URL: {0}'.format(url[:120]))
			continue
		readable.append((url, host, target or '/'))

	if not readable:
		return [], [], problems

	hosts = [item[1] for item in readable]
	targets = [item[2] for item in readable]
	host_pattern = _host_pattern_for(hosts)
	unique_hosts = sorted(set(hosts))

	if len(set(hosts)) > MAX_ALTERNATIVES:
		problems.append('Foram colados {0} hosts diferentes; a sugestão usa os {1} primeiros. '
			'Vale quebrar em mais de uma regra.'.format(len(set(hosts)), MAX_ALTERNATIVES))

	why_host = [
		'Os pontos vão escapados (`\\.`). Sem a barra, `.` casa qualquer caractere, e '
		'`empresa.com.br` passaria a aceitar também `empresaXcomYbr` — que é typosquatting.',
		'O host é casado sozinho e por inteiro (fullmatch), sobre o endereço já desmontado. '
		'É isso que faz `nf.empresa.com.br@evil.com` não passar: o host real dessa URL é evil.com.',
	]
	if len(unique_hosts) > 1:
		why_host.append('Os {0} hosts colados viraram alternância, e não um `.*` no lugar do '
			'subdomínio: `.*` aceitaria qualquer subdomínio, inclusive um que ainda não '
			'existe.'.format(len(unique_hosts)))

	suggestions = []

	# --- estrito ---
	exact_targets = sorted(set(targets))
	if len(exact_targets) <= MAX_ALTERNATIVES:
		strict_path = ('({0})'.format('|'.join(re.escape(item) for item in exact_targets))
			if len(exact_targets) > 1 else re.escape(exact_targets[0]))
		suggestions.append({
			'level': 'strict',
			'label': 'Estrito',
			'host_pattern': host_pattern,
			'path_pattern': strict_path,
			'scope': 'só {0} endereço(s), exatamente como colado(s)'.format(len(exact_targets)),
			'why': why_host + ['O caminho também vai literal: nada além do que foi colado é liberado. '
				'Serve para uma página fixa; se o endereço tiver data ou id que muda, ela para de casar.'],
		})

	# --- equilibrado ---
	prefix = _common_path_prefix(targets)
	if prefix and prefix != '/':
		suggestions.append({
			'level': 'balanced',
			'label': 'Equilibrado',
			'host_pattern': host_pattern,
			'path_pattern': re.escape(prefix) + '.*',
			'scope': 'tudo abaixo de {0} nesses hosts'.format(prefix),
			'why': why_host + ['O caminho vira o trecho comum mais `.*`, então acompanha o que muda '
				'(data, id, número da página) sem liberar o site inteiro.',
				'O `.*` fica só no fim. No começo ele deixaria o caminho de qualquer página casar.'],
		})

	# --- amplo ---
	suggestions.append({
		'level': 'broad',
		'label': 'Amplo',
		'host_pattern': host_pattern,
		'path_pattern': '',
		'scope': 'qualquer caminho nesses hosts',
		'why': why_host + ['Sem padrão de caminho, qualquer página desses hosts é liberada — '
			'inclusive um redirecionamento aberto, se o site tiver um. Só use quando o host '
			'inteiro for confiável.',
			'Se é isso que você quer, uma regra de domínio diz a mesma coisa de forma mais '
			'simples, e ela ainda barra curinga em sufixo público.'],
	})

	return suggestions, unique_hosts, problems


def probe_ruleset(host_pattern, path_pattern):
	"""Um conjunto com uma regra de URL só, sempre ativa, para testar um padrão.

	Passa pelo mesmo `normalize_rule` e pelo mesmo matcher da análise de
	verdade. É o que impede o testador de mentir: reimplementar o casamento no
	navegador daria uma resposta que diverge da produção no primeiro caso
	interessante.
	"""
	return Ruleset(rules = [normalize_rule({
		'type': TYPE_URL, 'mode': URL_MODE_REGEX,
		'host_pattern': host_pattern, 'path_pattern': path_pattern,
		'expires_at': None, 'permanent_reason': 'padrão em teste'})])


# --- Proteção contra regex explosiva ---------------------------------------

# Uma regex de quem administra rodando contra uma URL de quem ataca é um DoS
# esperando acontecer: o `re` do Python faz retrocesso, e `(a+)+$` contra uma
# entrada que não casa custa tempo exponencial. A sonda cresce em degraus e
# desiste no primeiro que estourar o orçamento, então um padrão catastrófico é
# recusado na hora de salvar em vez de derrubar o worker meses depois
REDOS_BUDGET_SECONDS = 0.3
REDOS_PROBE_LENGTHS = [16, 20, 24]


def pattern_is_safe(compiled):
	spent = 0.0
	for length in REDOS_PROBE_LENGTHS:
		for probe in ('a' * length + '!', ('a/' * (length // 2)) + '!'):
			start = time.monotonic()
			try:
				compiled.fullmatch(probe)
			except Exception:
				pass
			spent += time.monotonic() - start
			if spent > REDOS_BUDGET_SECONDS:
				return False
	return True


# --- Validação -------------------------------------------------------------

def _parse_timestamp(value):
	if not value:
		return None
	try:
		text = str(value).strip()
		if text.endswith('Z'):
			text = text[:-1]
		return datetime.datetime.fromisoformat(text)
	except Exception:
		return None


def _format_timestamp(moment):
	return moment.replace(microsecond = 0).isoformat() + 'Z'


def default_expiry(now = None):
	return _format_timestamp((now or datetime.datetime.utcnow()) + datetime.timedelta(days = DEFAULT_TTL_DAYS))


def _non_ascii_message(value):
	"""Mostra o punycode do que foi digitado, em vez de só recusar.

	Quem cola `рaypal.com` com "р" cirílico acredita ter digitado paypal.com.
	Ver `xn--aypal-uve.com` na tela é o que revela a diferença — e uma entrada
	com homóglifo aceita em silêncio seria uma porta dos fundos permanente.
	"""
	try:
		converted = []
		for label in value.split('.'):
			if not label:
				continue
			converted.append(label if _is_ascii(label) else label.encode('idna').decode('ascii'))
		punycode = '.'.join(converted)
	except Exception:
		punycode = '(não foi possível converter)'
	return ('O valor tem caracteres fora do ASCII, que podem ser homóglifos de outro alfabeto. '
		'Em punycode ele é {0} — cole essa forma se for mesmo o domínio que você quer.').format(punycode)


def _public_suffix_errors(domain):
	if domain in PUBLIC_SUFFIXES:
		return [('{0} é um sufixo público: qualquer pessoa registra um nome sob ele em minutos. '
			'Libere o domínio específico do parceiro, não o sufixo.').format(domain)]
	return []


def _public_suffix_warnings(domain):
	"""Avisa quando a entrada é PAI de um sufixo multi-inquilino conhecido.

	`google.com` cobre `sites.google.com`, que hospeda a página de quem quiser.
	Recusar google.com seria exagero; deixar passar calado, não.
	"""
	suffix = '.' + domain
	covered = sorted(item for item in PUBLIC_SUFFIXES if item.endswith(suffix))
	if covered:
		return [('Esta entrada também cobre {0}, onde qualquer pessoa publica uma página. '
			'Considere liberar só os subdomínios de que você precisa.').format(', '.join(covered[:3]))]
	return []


def _ip_range_errors(value):
	network = ipaddress.ip_network(value, strict = False)
	floor = IPV4_MIN_PREFIX if network.version == 4 else IPV6_MIN_PREFIX
	if network.prefixlen < floor:
		return [('{0} cobre {1} endereços. Uma faixa desse tamanho não descreve um parceiro, '
			'descreve um pedaço de provedor. O mínimo aceito é /{2}.').format(
			value, network.num_addresses, floor)]
	return []


def _ip_range_warnings(value):
	network = ipaddress.ip_network(value, strict = False)
	ceiling = IPV4_WARN_PREFIX if network.version == 4 else IPV6_WARN_PREFIX
	if network.prefixlen < ceiling:
		return [('{0} libera {1} endereços de uma vez. Confirme que a faixa inteira é '
			'de quem você pensa que é.').format(value, network.num_addresses)]
	return []


def _host_pattern_suffix_warnings(compiled):
	r"""Avisa quando o padrão do host aceita qualquer inquilino de um sufixo público.

	A aba de domínio recusa `*.sharepoint.com` na digitação. Sem esta checagem o
	mesmo alcance sairia pela aba de URL escrevendo `.*\.sharepoint\.com`, e a
	trava viraria decoração. Um padrão específico como `contoso\.sharepoint\.com`
	não casa a sonda e passa limpo.
	"""
	hit = []
	for suffix in sorted(PUBLIC_SUFFIXES):
		try:
			if compiled.fullmatch('inquilino-qualquer.' + suffix):
				hit.append(suffix)
		except Exception:
			return []
		if len(hit) >= 3:
			break
	if hit:
		return [('Este padrão de host aceita qualquer inquilino de {0}, onde qualquer pessoa '
			'publica uma página em minutos. Restrinja ao host exato do parceiro.').format(', '.join(hit))]
	return []


def _validate_url_rule(rule):
	"""Devolve (erros, avisos) para uma regra de URL."""
	errors = []
	warnings = []
	mode = (rule.get('mode') or URL_MODE_REGEX).strip()
	if mode not in URL_MODES:
		return ['Modo de URL desconhecido: {0}.'.format(mode)], warnings

	host_pattern = (rule.get('host_pattern') or '').strip()
	path_pattern = (rule.get('path_pattern') or '').strip()

	if not host_pattern:
		errors.append('Informe o padrão do host.')
	if len(host_pattern) > MAX_PATTERN_LENGTH or len(path_pattern) > MAX_PATTERN_LENGTH:
		errors.append('Os padrões passam de {0} caracteres.'.format(MAX_PATTERN_LENGTH))
		return errors, warnings

	# O modo prefixo não é mais oferecido na interface; continua aceito para que
	# um arquivo exportado antes ainda importe sem sumir com regras em silêncio
	if mode == URL_MODE_PREFIX:
		if host_pattern and not normalize_domain(host_pattern[2:] if host_pattern.startswith('*.') else host_pattern):
			errors.append('O host precisa ser um domínio válido.')
		if not path_pattern.startswith('/') or path_pattern == '/':
			errors.append('Informe um prefixo de caminho, como /notas-fiscais/. '
				'Para liberar o host inteiro use uma regra de domínio.')
		return errors, warnings

	for label, pattern in (('host', host_pattern), ('caminho', path_pattern)):
		if not pattern:
			continue
		try:
			compiled = re.compile(pattern)
		except re.error as regex_error:
			errors.append('Expressão regular do {0} inválida: {1}'.format(label, regex_error))
			continue
		if not pattern_is_safe(compiled):
			errors.append(('A expressão regular do {0} tem retrocesso explosivo: uma URL fabricada '
				'travaria a análise. Reescreva sem quantificador dentro de quantificador.').format(label))
			continue
		if label == 'host':
			warnings.extend(_host_pattern_suffix_warnings(compiled))
	return errors, warnings


def validate_rule(rule, allow_permanent = False, now = None):
	"""Confere uma regra e devolve (erros, avisos), ambos listas de texto.

	Erro impede o salvamento; aviso precisa de confirmação de quem administra.
	`allow_permanent` reflete o cargo: só global_admin cria regra sem prazo.
	"""
	errors = []
	warnings = []
	now = now or datetime.datetime.utcnow()

	rule_type = (rule.get('type') or '').strip()
	if rule_type not in TYPES:
		return ['Tipo desconhecido: {0}.'.format(rule_type or '(vazio)')], warnings

	raw_value = (rule.get('value') or '').strip()
	if rule_type != TYPE_URL:
		if not raw_value or '\n' in raw_value or '\r' in raw_value:
			return ['O valor deve ser uma única linha não vazia.'], warnings
		if len(raw_value) > MAX_VALUE_LENGTH:
			return ['O valor passa de {0} caracteres.'.format(MAX_VALUE_LENGTH)], warnings

	if rule_type == TYPE_SENDER:
		if has_non_ascii(raw_value):
			errors.append(_non_ascii_message(raw_value))
		elif not normalize_address(raw_value):
			errors.append('Informe um endereço completo, como faturamento@empresa.com.br.')

	elif rule_type == TYPE_DOMAIN:
		bare = raw_value[2:] if raw_value.startswith('*.') else raw_value
		if has_non_ascii(bare):
			errors.append(_non_ascii_message(bare))
		else:
			normalized = normalize_domain(bare)
			if not normalized or '.' not in normalized:
				errors.append('Informe um domínio como empresa.com.br, sem esquema nem caminho.')
			else:
				errors.extend(_public_suffix_errors(normalized))
				warnings.extend(_public_suffix_warnings(normalized))

	elif rule_type == TYPE_URL:
		url_errors, url_warnings = _validate_url_rule(rule)
		errors.extend(url_errors)
		warnings.extend(url_warnings)

	elif rule_type == TYPE_IP:
		normalized = normalize_ip(raw_value)
		if not normalized:
			errors.append('Informe um IP (203.0.113.7) ou uma faixa em CIDR (203.0.113.0/24).')
		elif not is_public_ip_value(normalized):
			# Endereço não roteável já é descartado na extração, sem regra
			# nenhuma (case_from_email._is_public_ip). Uma regra para ele não
			# libera nada que já não estivesse liberado, e ocuparia a tela
			# sugerindo uma proteção que não existe
			errors.append('Endereços privados, de loopback e reservados já são ignorados em toda análise, '
				'sem precisar de regra. Cadastre aqui só endereço roteável na internet.')
		else:
			errors.extend(_ip_range_errors(normalized))
			warnings.extend(_ip_range_warnings(normalized))

	elif rule_type == TYPE_HASH:
		cleaned = raw_value.lower()
		if re.match(r'^[0-9a-f]{32}$', cleaned) or re.match(r'^[0-9a-f]{40}$', cleaned):
			errors.append('MD5 e SHA-1 têm colisão prática e não servem para liberar um anexo. Use SHA-256.')
		elif not normalize_hash(cleaned):
			errors.append('Informe um SHA-256: 64 caracteres hexadecimais.')

	# --- prazo (as três camadas: padrão, data escolhida, permanente) ---
	if 'expires_at' in rule and rule.get('expires_at') is None:
		if not allow_permanent:
			errors.append('Regra permanente exige o cargo global_admin.')
		justification = (rule.get('permanent_reason') or '').strip()
		if len(justification) < PERMANENT_REASON_MIN_LENGTH:
			errors.append('Regra permanente exige justificativa escrita de pelo menos {0} caracteres.'.format(
				PERMANENT_REASON_MIN_LENGTH))
	elif rule.get('expires_at'):
		moment = _parse_timestamp(rule.get('expires_at'))
		if moment is None:
			errors.append('Data de expiração inválida.')
		elif moment <= now:
			errors.append('A data de expiração já passou.')
		elif moment > now + datetime.timedelta(days = MAX_TTL_DAYS):
			errors.append('A expiração não pode passar de {0} anos.'.format(MAX_TTL_DAYS // 365))

	if len((rule.get('reason') or '').strip()) > REASON_MAX_LENGTH:
		errors.append('O motivo passa de {0} caracteres.'.format(REASON_MAX_LENGTH))

	return errors, warnings


# --- Normalização de uma regra completa ------------------------------------

def new_rule_id():
	return 'wl_' + secrets.token_hex(4)


def _normalize_scope(scope):
	if not isinstance(scope, dict):
		return {'kind': 'global', 'department': None}
	kind = (scope.get('kind') or 'global').strip()
	if kind not in ('global', 'department'):
		kind = 'global'
	department = (scope.get('department') or '').strip() or None
	return {'kind': kind, 'department': department if kind == 'department' else None}


def normalize_rule(rule, now = None):
	"""Devolve a regra com todo campo do esquema presente e o valor normalizado.

	Chamada tanto ao salvar quanto ao carregar, para que o casamento nunca
	dependa de como o valor foi digitado.
	"""
	now = now or datetime.datetime.utcnow()
	rule_type = (rule.get('type') or '').strip()
	raw_value = (rule.get('value') or '').strip()

	if rule_type == TYPE_SENDER:
		value = normalize_address(raw_value)
	elif rule_type == TYPE_DOMAIN:
		wildcard = raw_value.startswith('*.')
		normalized = normalize_domain(raw_value[2:] if wildcard else raw_value)
		value = ('*.' + normalized) if (wildcard and normalized) else normalized
	elif rule_type == TYPE_HASH:
		value = normalize_hash(raw_value)
	elif rule_type == TYPE_IP:
		value = normalize_ip(raw_value)
	else:
		value = raw_value

	normalized_rule = {
		'id': (rule.get('id') or '').strip() or new_rule_id(),
		'type': rule_type,
		'value': value,
		'enabled': bool(rule.get('enabled', True)),
		'reason': (rule.get('reason') or '').strip(),
		'expires_at': rule.get('expires_at') if 'expires_at' in rule else default_expiry(now),
		'permanent_reason': (rule.get('permanent_reason') or '').strip() or None,
		'scope': _normalize_scope(rule.get('scope')),
		'created_by': (rule.get('created_by') or '').strip(),
		'created_at': rule.get('created_at') or _format_timestamp(now),
		'updated_by': (rule.get('updated_by') or '').strip() or None,
		'updated_at': rule.get('updated_at') or None,
	}

	if rule_type == TYPE_SENDER:
		# O alinhamento do Reply-To é o que separa um remetente confiável de um
		# BEC que usa o From real e manda a resposta para fora. Ligado por padrão
		normalized_rule['require_reply_to_alignment'] = bool(rule.get('require_reply_to_alignment', True))
	elif rule_type == TYPE_URL:
		mode = (rule.get('mode') or URL_MODE_REGEX).strip()
		host_pattern = (rule.get('host_pattern') or '').strip()
		normalized_rule['mode'] = mode if mode in URL_MODES else URL_MODE_REGEX
		if normalized_rule['mode'] == URL_MODE_PREFIX:
			normalized_rule['host_pattern'] = normalize_domain(host_pattern) or host_pattern
		else:
			normalized_rule['host_pattern'] = host_pattern
		normalized_rule['path_pattern'] = (rule.get('path_pattern') or '').strip()
		normalized_rule['value'] = '{0}{1}'.format(normalized_rule['host_pattern'], normalized_rule['path_pattern'])
	elif rule_type == TYPE_HASH:
		normalized_rule['algo'] = 'sha256'

	return normalized_rule


def effect_of(rule):
	return EFFECT_BY_TYPE.get(rule.get('type'), EFFECT_SUPPRESS)


# --- Casamento -------------------------------------------------------------

def _domain_covers(rule_value, observed):
	"""Casa por rótulo, nunca por texto.

	`endswith('.' + dominio)` ou `dominio in valor` são os dois erros clássicos:
	o primeiro deixa passar `dominio.com.atacante.net` conforme se escreva, o
	segundo libera `evil-dominio.com`. Comparar as listas de rótulos a partir do
	fim não tem esse buraco.

	Três formas, e a diferença entre elas é só o apex:
	- `empresa.com`    → o próprio domínio e tudo abaixo dele
	- `*.empresa.com`  → só o que está abaixo, não o próprio
	- `nf.empresa.com` → esse subdomínio e tudo abaixo dele
	"""
	wildcard_only = rule_value.startswith('*.')
	rule_labels = _labels(rule_value[2:] if wildcard_only else rule_value)
	observed_labels = _labels(observed)
	if not rule_labels or not observed_labels:
		return False
	if len(observed_labels) < len(rule_labels):
		return False
	if observed_labels[-len(rule_labels):] != rule_labels:
		return False
	if len(observed_labels) == len(rule_labels):
		return not wildcard_only
	return True


def domains_aligned(first, second):
	"""Mesma noção de alinhamento que o DKIM usa em case_from_email.py:148."""
	first = normalize_domain(first)
	second = normalize_domain(second)
	if not first or not second:
		return False
	return first == second or first.endswith('.' + second) or second.endswith('.' + first)


class Match:
	"""O resultado de uma consulta: a regra que casou, ou o motivo de não casar.

	O motivo importa tanto quanto o casamento. "existe regra para este remetente,
	mas o domínio não está autenticado" é o que a analista precisa ler no log
	quando pergunta por que a liberação não valeu.
	"""

	def __init__(self, rule = None, reason = ''):
		self.rule = rule
		self.reason = reason

	def __bool__(self):
		return self.rule is not None

	@property
	def rule_id(self):
		return self.rule.get('id') if self.rule else None


class Ruleset:
	"""As regras carregadas, já normalizadas, com os matchers de cada tipo.

	`suspended_ids` vem do banco (fase 3) e entra por parâmetro para que este
	módulo continue sem dependência de banco: quem chama decide se consulta o
	estado ou não.
	"""

	def __init__(self, rules = None, error = '', suspended_ids = None):
		self.error = error
		self.rules = rules or []
		self.suspended_ids = set(suspended_ids or ())
		self._compiled = {}
		self._by_type = {rule_type: [] for rule_type in TYPES}
		for rule in self.rules:
			if rule.get('type') in self._by_type:
				self._by_type[rule['type']].append(rule)

	# --- estado efetivo ---

	def is_active(self, rule, now = None):
		if not rule.get('enabled', True):
			return False, 'desabilitada'
		if rule.get('id') in self.suspended_ids:
			return False, 'suspensa automaticamente'
		expires_at = rule.get('expires_at')
		if expires_at is not None:
			moment = _parse_timestamp(expires_at)
			# A expiração é avaliada aqui, no momento do casamento, e não por uma
			# rotina de limpeza: se o trabalho semanal falhar, a regra vencida já
			# não libera nada
			if moment is None or moment <= (now or datetime.datetime.utcnow()):
				return False, 'expirada'
		return True, ''

	def active_rules(self, rule_type, now = None):
		now = now or datetime.datetime.utcnow()
		for rule in self._by_type.get(rule_type, []):
			active, _reason = self.is_active(rule, now)
			if active:
				yield rule

	# --- casamento por tipo ---

	def match_sender(self, from_address, auth_results, reply_to = '', now = None):
		"""A única consulta que pode rebaixar veredito, e a mais exigente.

		Três condições, todas obrigatórias:
		1. o endereço bate com uma regra ativa;
		2. o servidor de e-mail autenticou o domínio remetente — a definição de
		   `authenticated` de case_from_email.py:163 (DMARC pass, ou DKIM pass
		   alinhado com o From). SPF sozinho não conta: valida o envelope, que
		   quem faz phishing controla à parte do From exibido;
		3. o Reply-To está vazio ou no mesmo domínio, quando a regra pede. Um
		   From confiável com resposta indo para fora é BEC clássico.
		"""
		address = normalize_address(from_address)
		if not address:
			return Match(reason = 'endereço remetente ilegível')

		candidate = None
		for rule in self.active_rules(TYPE_SENDER, now):
			if rule.get('value') == address:
				candidate = rule
				break
		if candidate is None:
			return Match()

		if not (auth_results or {}).get('authenticated'):
			return Match(reason = 'existe regra para {0}, mas o domínio remetente não está autenticado '
				'(DMARC/DKIM alinhado)'.format(address))

		if candidate.get('require_reply_to_alignment', True):
			reply_address = normalize_address(reply_to)
			if reply_address:
				reply_domain = reply_address.rpartition('@')[2]
				from_domain = address.rpartition('@')[2]
				if not domains_aligned(reply_domain, from_domain):
					return Match(reason = 'existe regra para {0}, mas o Reply-To aponta para {1}'.format(
						address, reply_domain))

		return Match(rule = candidate)

	def match_domain(self, domain, now = None):
		observed = normalize_domain(domain)
		if not observed:
			return Match()
		for rule in self.active_rules(TYPE_DOMAIN, now):
			if _domain_covers(rule.get('value') or '', observed):
				return Match(rule = rule)
		return Match()

	def match_url(self, url, now = None):
		host, target = normalize_url(url)
		if not host:
			return Match()
		# Uma regra de domínio cobre toda URL daquele domínio: é a mesma
		# liberação, escrita no lugar onde as travas de sufixo público existem
		domain_match = self.match_domain(host, now)
		if domain_match:
			return domain_match
		for rule in self.active_rules(TYPE_URL, now):
			if self._url_rule_matches(rule, host, target):
				return Match(rule = rule)
		return Match()

	def match_ip(self, address, now = None):
		observed = (address or '').strip()
		if not observed:
			return Match()
		for rule in self.active_rules(TYPE_IP, now):
			if _ip_covers(rule.get('value') or '', observed):
				return Match(rule = rule)
		return Match()

	def match_hash(self, digest, now = None):
		observed = normalize_hash(digest)
		if not observed:
			return Match()
		for rule in self.active_rules(TYPE_HASH, now):
			if rule.get('value') == observed:
				return Match(rule = rule)
		return Match()

	# --- interno ---

	def _url_rule_matches(self, rule, host, target):
		if rule.get('mode') == URL_MODE_REGEX:
			host_pattern = self._compile(rule.get('id'), 'host', rule.get('host_pattern'))
			path_pattern = self._compile(rule.get('id'), 'path', rule.get('path_pattern'))
			if host_pattern is None:
				return False
			# fullmatch, nunca search: `paypal\.com` com search casaria
			# `http://evil.com/?ref=paypal.com`, e é exatamente o que uma pessoa
			# escreve achando que está liberando o PayPal
			if not host_pattern.fullmatch(host):
				return False
			if path_pattern is None:
				return not (rule.get('path_pattern') or '')
			return bool(path_pattern.fullmatch(target))
		expected_host = rule.get('host_pattern') or ''
		if not _domain_covers(expected_host, host):
			return False
		prefix = rule.get('path_pattern') or ''
		return bool(prefix) and target.startswith(prefix)

	def _compile(self, rule_id, slot, pattern):
		if not pattern:
			return None
		key = (rule_id, slot)
		if key not in self._compiled:
			try:
				self._compiled[key] = re.compile(pattern)
			except re.error:
				self._compiled[key] = None
		return self._compiled[key]


# --- Persistência ----------------------------------------------------------

WHITELIST_PATH = os.environ.get('BLUEPHISH_WHITELIST_PATH',
	os.path.join(os.path.dirname(os.path.abspath(__file__)), 'whitelist.json'))

# Processo único (socketio.run com eventlet), várias threads: um lock em memória
# basta para serializar as escritas, e a troca atômica cuida do resto
_save_lock = threading.Lock()


def empty_ruleset(error = ''):
	return Ruleset(rules = [], error = error)


def load(path = None, suspended_ids = None):
	"""Lê o arquivo e devolve um Ruleset. Nunca levanta exceção.

	Qualquer falha — arquivo ausente, JSON quebrado, versão desconhecida —
	devolve um conjunto vazio com `error` preenchido. Nada é liberado e a análise
	segue: falhar fechado, e sem derrubar o pipeline junto.
	"""
	path = path or WHITELIST_PATH
	try:
		with open(path, encoding = 'utf-8') as whitelist_file:
			document = json.load(whitelist_file)
	except FileNotFoundError:
		return empty_ruleset('whitelist.json não encontrado em {0}'.format(path))
	except Exception as error:
		return empty_ruleset('whitelist.json ilegível: {0}'.format(error))

	if not isinstance(document, dict):
		return empty_ruleset('whitelist.json não contém um objeto')
	version = document.get('version')
	if version != SCHEMA_VERSION:
		return empty_ruleset('whitelist.json está na versão {0}; esperada a {1}. '
			'Rode a migração antes de usar.'.format(version, SCHEMA_VERSION))
	raw_rules = document.get('rules')
	if not isinstance(raw_rules, list):
		return empty_ruleset('whitelist.json não traz uma lista de regras')

	rules = []
	for raw_rule in raw_rules:
		if not isinstance(raw_rule, dict):
			continue
		rule = normalize_rule(raw_rule)
		# Uma regra cujo valor não sobreviveu à normalização não casa com nada;
		# guardá-la só criaria uma linha morta na interface
		if rule.get('type') in TYPES and rule.get('value'):
			rules.append(rule)
	return Ruleset(rules = rules, suspended_ids = suspended_ids)


def save(rules, path = None):
	"""Grava as regras sob lock, atômico quando o sistema de arquivos deixa.

	O v1 escrevia direto por cima do arquivo (thephish_app.py:1551): duas
	pessoas salvando ao mesmo tempo perdiam uma entrada, e uma queda no meio do
	`json.dump` deixava um JSON truncado que derrubava toda análise seguinte.

	A troca atômica resolve os dois, mas **não funciona sobre um bind mount de
	arquivo único**, que é como o compose entrega este arquivo ao container
	(`./thephish_conf_files/whitelist.json:/root/thephish/whitelist.json`).
	Renomear por cima do ponto de montagem devolve EBUSY, e o container é
	justamente onde isto roda de verdade. Então: tenta renomear, e se o sistema
	de arquivos recusar, grava por cima.

	O caminho de reserva perde a atomicidade e não tem como não perder — não
	existe rename sobre mount point. O que ele preserva é o resto: o conteúdo já
	foi serializado inteiro e validado no temporário antes de qualquer byte
	tocar o arquivo real, então um erro de serialização não chega a truncar
	nada. Só uma queda de energia no meio do write final ainda machuca, e para
	essa o `load()` falha fechado.
	"""
	path = path or WHITELIST_PATH
	document = {
		'version': SCHEMA_VERSION,
		'rules': [normalize_rule(rule) for rule in rules],
	}
	body = json.dumps(document, indent = '\t', ensure_ascii = False)
	temporary = path + '.tmp'
	with _save_lock:
		with open(temporary, 'w', encoding = 'utf-8') as whitelist_file:
			whitelist_file.write(body)
			whitelist_file.flush()
			os.fsync(whitelist_file.fileno())
		try:
			os.replace(temporary, path)
		except OSError:
			# EBUSY (bind mount de arquivo único) ou EXDEV (temporário em outro
			# dispositivo): escreve no lugar e remove o temporário
			with open(path, 'w', encoding = 'utf-8') as whitelist_file:
				whitelist_file.write(body)
				whitelist_file.flush()
				os.fsync(whitelist_file.fileno())
			try:
				os.remove(temporary)
			except OSError:
				pass
	return document
