"""O endereço de quem fez a requisição, para a trilha de auditoria e o limitador.

Plain Python, sem Flask: a regra que decide em quem confiar é testada onde é
escrita (test_client_addr.py), e não só dentro do contêiner.

Três regras, nesta ordem:

* **Só um proxy confiável pode dizer quem é o cliente.** `X-Forwarded-For` é
  escrito por quem fez a requisição; de um par que não está na lista de proxies
  confiáveis ele é ignorado, e vale o endereço do próprio socket. Antes isto
  honrava a primeira entrada de qualquer par — quem acessava direto escolhia o
  IP que a auditoria registrava e o que o limitador de tentativas contava.
* **Atrás de proxy, o cliente é a entrada mais à direita que não é proxy.** A
  primeira entrada é a que o cliente escreveu; a última é a que o proxy
  acrescentou. Cada proxy confiável da cadeia é descontado, da direita para a
  esquerda.
* **O gateway da bridge do Docker sem cabeçalho não é uma pessoa.** Quando a
  porta é publicada e o Docker faz o encaminhamento por um proxy em userland, o
  par que o processo vê é o gateway da rede (172.x.0.1) e o IP real se perdeu
  antes de chegar aqui. Nada neste código recupera isso; o que ele faz é marcar
  o caso (`docker_gateway`) para a trilha dizer a verdade em vez de exibir o
  gateway como se fosse o cliente.

A lista de proxies confiáveis vem de `BLUEPHISH_TRUSTED_PROXIES` (CIDRs ou
endereços, separados por vírgula). O padrão é só o loopback.
"""

import collections
import ipaddress
import logging
import os
import re

TRUSTED_ENV = 'BLUEPHISH_TRUSTED_PROXIES'
DEFAULT_TRUSTED = ('127.0.0.0/8', '::1/128')
MAX_IP_CHARS = 45
_ADDRESS_TEXT = re.compile(r'[0-9A-Fa-f:.]{2,45}')

log = logging.getLogger(__name__)

# Os blocos que o Docker usa para redes bridge definidas pelo usuário e para a
# docker0. O gateway é sempre o primeiro endereço do bloco da rede. O
# 192.168.0.0/16 fica de fora de propósito: é a rede de casa de qualquer um, e o
# .1 dela é o roteador.
_DOCKER_BRIDGES = (ipaddress.ip_network('172.16.0.0/12'),)

Resolved = collections.namedtuple('Resolved', ['ip', 'source', 'docker_gateway'])


def parse_trusted(raw, report = None):
	"""Redes confiáveis a partir do texto da variável.

	Entrada inválida é descartada, mas não em silêncio: um erro de digitação
	aqui faz o proxy deixar de ser confiável, e todo cliente passa a ter o IP
	dele — `report` recebe cada entrada recusada para o chamador registrar.
	"""
	networks = [ipaddress.ip_network(entry) for entry in DEFAULT_TRUSTED]
	for entry in str(raw or '').split(','):
		entry = entry.strip()
		if not entry:
			continue
		try:
			networks.append(ipaddress.ip_network(entry, strict = False))
		except ValueError:
			if report:
				report(entry)
	return networks


_reported = set()


def configured_trusted():
	problems = []
	networks = parse_trusted(os.environ.get(TRUSTED_ENV, ''), report = problems.append)
	for entry in problems:
		if entry not in _reported:
			_reported.add(entry)
			log.warning('%s: entrada ignorada por não ser um endereço ou rede: %r', TRUSTED_ENV, entry)
	return networks


def _strip_port(text):
	"""Tira a porta de "1.2.3.4:51234" e de "[2001:db8::7]:443"."""
	text = text.strip()
	bracketed = re.fullmatch(r'\[([^\]]+)\](?::\d{1,5})?', text)
	if bracketed:
		return bracketed.group(1)
	if text.count(':') == 1:
		host, _, port = text.partition(':')
		if port.isdigit():
			return host
	return text


def _as_address(text):
	"""O endereço, ou None. Só devolve algo que cabe num campo da trilha.

	O `%` de escopo do IPv6 (fe80::1%eth0) é recusado: o Python aceita qualquer
	texto depois dele, e esse texto iria para um registro de uma linha só, lido de
	volta por espaço. Um IPv4 dentro de IPv6 (::ffff:10.0.0.2) vira o IPv4 —
	um socket dual-stack entrega o par neste formato, e sem isso o proxy
	confiável nunca casaria com a rede IPv4 configurada.
	"""
	text = str(text).strip()
	if not _ADDRESS_TEXT.fullmatch(text):
		return None
	try:
		parsed = ipaddress.ip_address(text)
	except ValueError:
		return None
	mapped = getattr(parsed, 'ipv4_mapped', None)
	return mapped if mapped is not None else parsed


def is_trusted(address, networks):
	parsed = _as_address(address)
	if parsed is None:
		return False
	return any(parsed in network for network in networks if network.version == parsed.version)


def _looks_like_bridge_gateway(address):
	parsed = _as_address(address)
	if parsed is None or parsed.version != 4:
		return False
	for network in _DOCKER_BRIDGES:
		if parsed in network:
			# 172.18.0.1: o último octeto é 1 e o terceiro é o da rede
			return int(parsed) & 0xff == 1
	return False


def resolve(remote_addr, forwarded_for, trusted):
	"""O IP do cliente, de onde veio a informação e se é o gateway do Docker."""
	peer = _as_address(remote_addr or '')
	if peer is None:
		return Resolved('-', 'peer', False)
	peer_text = str(peer)
	peer_trusted = is_trusted(peer_text, trusted)

	if peer_trusted and forwarded_for:
		for entry in reversed([item for item in forwarded_for.split(',')]):
			address = _as_address(_strip_port(entry))
			if address is None:
				# Lixo no cabeçalho: não adivinhamos o que ele quis dizer
				break
			if not is_trusted(str(address), trusted):
				# O vhost repassa o par que viu. Se foi o gateway do Docker (o
				# userland-proxy esconde o cliente), é o mesmo caso do par direto:
				# todos chegariam com esse IP, e banir um trancaria todos
				text = str(address)
				return Resolved(text[:MAX_IP_CHARS], 'forwarded', _looks_like_bridge_gateway(text))

	return Resolved(peer_text, 'peer', _looks_like_bridge_gateway(peer_text) and not peer_trusted)
