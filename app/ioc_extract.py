"""Extração de indicadores com custo limitado sobre texto escrito pelo atacante.

O `ioc_finder` tenta a gramática a partir de cada início de palavra. Num token
longo sem separador (`a.a.a.a...`) cada tentativa percorre o resto do token, e o
custo vira quadrático: 2 KB custaram 5,8 s, e 100 KB seriam horas (medido em
2026-11-23). Quem escolhe esse texto é quem mandou o phishing.

Três regras saem daí, e a ordem delas importa:

  * **Nada é cortado às cegas.** Limitar o tamanho do texto criaria uma evasão:
    bastaria colocar lixo antes da URL maliciosa. Um token longo é trocado pelos
    pedaços dele que ainda podem ser um domínio ou um endereço, e texto sem token
    longo chega à biblioteca exatamente como veio.

  * **URL só é reescrita acima de 8 KiB num token só.** Uma URL longa é legítima,
    e reescrevê-la mudaria o valor que vai para os analisadores de reputação.
    Acima disso, cada `esquema://` vira um candidato próprio. A versão 6.0.1 da
    biblioteca testa centenas de esquemas em cada início de palavra, então nem a
    busca por URL pode receber um token hostil inteiro.

  * **O tempo é um orçamento, e estourar é um fato que se declara.** Entre um
    bloco e outro o prazo é conferido. `complete = False` chega até o veredito,
    que não fecha como Safe o que não foi lido inteiro (`run_analysis`).

Puro, sem rede, sem eventlet e sem libmagic, para ser testado fora da imagem.
"""

import re
import time
from typing import Callable, FrozenSet, Iterable, Iterator, List, NamedTuple, Optional, Pattern, Tuple

import ioc_finder

import ioc_noise


# RFC 1035 e RFC 5321: nada maior que isso é um nome ou uma parte local válida
MAX_HOSTNAME_CHARS = 253
MAX_LABEL_CHARS = 63
MAX_LOCAL_PART_CHARS = 64
# Entre dois blocos o prazo é conferido. Pequeno o bastante para o pior caso
# dentro de um bloco custar poucos segundos depois de o orçamento acabar
CHUNK_CHARS = 8 * 1024
# Até aqui um token chega inteiro à busca de URL, com o valor que tem
MAX_URL_TOKEN_CHARS = 8 * 1024
MAX_SCHEME_CHARS = 32

# O lookbehind ancora no início do token: sem ele, um token curto seria tentado de
# novo a partir de cada um dos seus caracteres
_LONG_TOKEN = re.compile(r'(?<!\S)\S{%d,}' % (MAX_HOSTNAME_CHARS + 1))
_LONG_URL_TOKEN = re.compile(r'(?<!\S)\S{%d,}' % (MAX_URL_TOKEN_CHARS + 1))
_SCHEME_END = re.compile(r'[A-Za-z0-9+.-]{1,%d}$' % MAX_SCHEME_CHARS)
# As mesmas fronteiras da gramática: não colado em letra, dígito ou ponto antes, e
# depois nem em letra ou dígito, nem em `.` seguido de mais texto
_IPV4_CANDIDATE = re.compile(r'(?<![A-Za-z0-9.])\d{1,3}(?:\.\d{1,3}){3}(?![A-Za-z0-9])(?!\.\S)')
_NOT_HOST_CHARS = re.compile(r'[^A-Za-z0-9_.-]+')
_EMPTY_LABEL = re.compile(r'\.{2,}')
_LOCAL_PART_END = re.compile(r'[A-Za-z0-9+_.-]{1,%d}$' % MAX_LOCAL_PART_CHARS)
_BRACKET_HOST = re.compile(r'\[[^\]\s]{1,64}\]')
_HOST_RUN = re.compile(r'[A-Za-z0-9_.-]+')
# O começo e o fim de um rótulo longo demais que a biblioteca ainda aproveita: o
# começo como TLD quando vem antes de `-` ou `_`, o fim como início de outro nome
_LABEL_HEAD = re.compile(r'[A-Za-z0-9]{1,%d}(?=[-_])' % MAX_LABEL_CHARS)
_LABEL_TAIL = re.compile(r'[-_]([A-Za-z0-9][A-Za-z0-9_-]{0,%d})$' % (MAX_LABEL_CHARS - 1))
_WHITESPACE = re.compile(r'\s')


class Extraction(NamedTuple):
	email_addresses: List[str]
	ipv4s: List[str]
	domains: List[str]
	urls: List[str]
	# Candidatos a domínio que só existem como id de loja de aplicativo (ioc_noise)
	package_only: FrozenSet[str]
	# False quando o orçamento acabou antes de o texto inteiro ser lido
	complete: bool


def _label_chains(run: str) -> Iterator[str]:
	"""As sequências de rótulos de `run` em que a biblioteca pode achar um nome.

	Um rótulo maior que 63 encerra a sequência, e não a descarta: `evil.com-----`
	é `evil.com` para a gramática, e tratar a sequência inteira como lixo daria a
	quem manda o phishing um jeito de esconder o domínio atrás de uma linha de
	hífens.
	"""
	chain = []
	for label in run.split('.'):
		if len(label) <= MAX_LABEL_CHARS:
			chain.append(label)
			continue
		head = _LABEL_HEAD.match(label)
		# Na dúvida o candidato vai para a gramática, que decide: a mais, um
		# candidato é descartado por ela; a menos, é um domínio que ninguém analisa
		if chain:
			yield '.'.join(chain + [head.group()] if head else chain)
		tail = _LABEL_TAIL.search(label, len(label) - MAX_LABEL_CHARS - 1)
		chain = [tail.group(1)] if tail else []
	if chain:
		yield '.'.join(chain)


def _fit_hostname(chain: str) -> str:
	"""O final de `chain` que cabe num nome, em fronteira de rótulo.

	O final é a parte registrável, e a que quem esconde um domínio atrás de lixo
	precisa manter para o endereço funcionar.
	"""
	if len(chain) <= MAX_HOSTNAME_CHARS:
		return chain
	cut = chain.find('.', len(chain) - MAX_HOSTNAME_CHARS - 1)
	return chain[cut + 1:] if cut >= 0 else ''


def _host_candidates(token: str) -> Iterator[str]:
	"""Os trechos de um token longo que ainda podem ser um domínio."""
	for piece in _NOT_HOST_CHARS.split(token):
		for run in _EMPTY_LABEL.split(piece):
			for chain in _label_chains(run.strip('.')):
				host = _fit_hostname(chain)
				if '.' in host:
					yield host


def _address_host(token: str, start: int) -> str:
	"""O host que começa logo depois da arroba, ou '' se ali não começa um."""
	bracket = _BRACKET_HOST.match(token, start)
	if bracket:
		return bracket.group()
	run = _HOST_RUN.match(token, start)
	if not run:
		return ''
	first = _EMPTY_LABEL.split(run.group(), 1)[0].rstrip('.')
	chain = next(_label_chains(first), '')
	# Uma sequência que recomeça no meio de um rótulo longo não está colada na arroba
	return _fit_hostname(chain) if chain and first.startswith(chain) else ''


def _address_candidates(token: str) -> Iterator[str]:
	"""Os `parte@host` de um token longo, um por arroba."""
	position = token.find('@')
	while position >= 0:
		local = _LOCAL_PART_END.search(token, max(0, position - MAX_LOCAL_PART_CHARS), position)
		host = _address_host(token, position + 1)
		if local and host:
			yield '{0}@{1}'.format(local.group(), host)
		position = token.find('@', position + 1)


def _url_candidates(token: str) -> Iterator[str]:
	"""Um trecho por `esquema://`, de um esquema até o próximo, com teto de tamanho."""
	starts = []
	position = token.find('://')
	while position >= 0:
		scheme = _SCHEME_END.search(token, max(0, position - MAX_SCHEME_CHARS), position)
		if scheme:
			starts.append(scheme.start())
		position = token.find('://', position + 3)
	for start, following in zip(starts, starts[1:] + [len(token)]):
		yield token[start:min(following, start + MAX_URL_TOKEN_CHARS)]


def _bounded(text: str, candidates_of: Callable[[str], Iterable[str]], long_token: Pattern = _LONG_TOKEN) -> str:
	"""O texto com cada token longo trocado pelos seus candidatos."""
	return long_token.sub(lambda token: ' '.join(dict.fromkeys(candidates_of(token.group()))), text)


def _chunks(text: str) -> Iterator[str]:
	"""Blocos cortados em espaço em branco: nenhum indicador atravessa um espaço.

	Do segundo em diante o bloco leva um espaço na frente. A gramática só aceita um
	`_` como início de palavra na posição 0 do texto, e sem o espaço cada bloco
	teria uma posição 0 que o texto original não tem.
	"""
	start, size = 0, len(text)
	while start < size:
		boundary = _WHITESPACE.search(text, min(start + CHUNK_CHARS, size))
		end = boundary.end() if boundary else size
		yield text[start:end] if start == 0 else ' ' + text[start:end]
		start = end


def _scan(parse: Callable[[str], Iterable[str]], text: str, deadline: float) -> Tuple[List[str], bool]:
	"""(valores sem repetição, na ordem em que apareceram; se o texto foi até o fim)."""
	found = {}
	for chunk in _chunks(text):
		if time.monotonic() >= deadline:
			return list(found), False
		for value in parse(chunk):
			found.setdefault(value)
	return list(found), True


def _parse_urls(chunk: str) -> List[str]:
	# Sem `://` não há URL com esquema, e a gramática gastaria o bloco para dizer isso
	return ioc_finder.parse_urls(chunk, parse_urls_without_scheme = False) if '://' in chunk else []


def _parse_ipv4s(chunk: str) -> List[str]:
	return ioc_finder.parse_ipv4_addresses(chunk) if _IPV4_CANDIDATE.search(chunk) else []


def _ipv4_candidates(token: str) -> List[str]:
	return _IPV4_CANDIDATE.findall(token)


def _parse_addresses(chunk: str) -> List[str]:
	# Sem arroba não há endereço, e a gramática custaria o bloco inteiro para dizer isso
	return ioc_finder.parse_email_addresses(chunk) if '@' in chunk else []


def _package_only(domains: List[str], text: str, deadline: float) -> FrozenSet[str]:
	"""Sem tempo para filtrar, o candidato fica: sobra um observável, não falta um."""
	packages = ioc_noise.app_package_ids(text)
	if not packages:
		return frozenset()
	only = []
	for domain in domains:
		if time.monotonic() >= deadline:
			break
		if ioc_noise.is_app_package_only(domain, text, packages):
			only.append(domain)
	return frozenset(only)


def extract(text: str, deadline: Optional[float] = None) -> Extraction:
	"""Os indicadores de `text`. `deadline` é um instante de `time.monotonic()`.

	URLs vêm primeiro porque são o que mais pesa no veredito: se o orçamento
	acabar, o que ficou por ler é o que menos falta faz.
	"""
	limit = float('inf') if deadline is None else deadline
	if text and time.monotonic() >= limit:
		return Extraction([], [], [], [], frozenset(), False)
	urls, urls_done = _scan(_parse_urls, _bounded(text, _url_candidates, _LONG_URL_TOKEN), limit)
	addresses, addresses_done = _scan(_parse_addresses, _bounded(text, _address_candidates), limit)
	ipv4s, ipv4s_done = _scan(_parse_ipv4s, _bounded(text, _ipv4_candidates), limit)
	domains, domains_done = _scan(ioc_finder.parse_domain_names, _bounded(text, _host_candidates), limit)
	return Extraction(
		email_addresses = addresses,
		ipv4s = ipv4s,
		domains = domains,
		urls = urls,
		package_only = _package_only(domains, text, limit),
		complete = urls_done and addresses_done and ipv4s_done and domains_done)
