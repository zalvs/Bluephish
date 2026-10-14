"""HTTP que conecta no endereço que a trava de SSRF aprovou, e em nenhum outro.

custom_analyzers.validate_destination() resolve o nome e decide. Até este módulo
existir, a biblioteca HTTP resolvia o mesmo nome de novo, por conta própria, na
hora de conectar — duas perguntas independentes ao DNS. Um DNS hostil responde
uma coisa a cada uma: o IP público para a trava, 169.254.169.254 para a conexão
(DNS rebinding, BP-SEC-03). A §4.5.1 chamava isso de risco residual.

Aqui a resolução e a conexão são uma coisa só. A conexão pergunta ao DNS uma
vez, julga TODOS os endereços da resposta com a mesma regra da trava
(custom_analyzers._is_forbidden_address) e conecta num deles — pelo IP, sem
perguntar de novo. Endereço recusado levanta DestinationRefused antes de
qualquer pacote sair, inclusive o handshake TLS. O nome original continua sendo
o do cabeçalho Host, do SNI e da validação do certificado: só o socket é que
vai para o IP.

validate_destination() continua existindo e continua sendo chamada antes: é
ela que dá a mensagem de erro clara ao salvar, e que recusa o esquema errado.
Este módulo é a garantia de que o que ela aprovou é o que a conexão faz.

Proxy: uma requisição que o ambiente manda por proxy (HTTP_PROXY/HTTPS_PROXY,
que o README recomenda para a saída do contêiner) conecta no proxy, e quem
resolve o destino é ele. Esse caminho não é fixado aqui — conferir o IP do
proxy não diria nada sobre o destino —, e a política de saída do proxy é o
controle. A trava de validate_destination() continua valendo antes dele.

Consumidores (a tabela da §4.5.1): custom_analyzers, connectors, tickets (Jira),
responders (gerência de firewall), unshorten e email_render. O TheHive fica de
fora: thehive4py chama o requests por dentro, sem sessão que se possa trocar, e
o endereço dele é digitado por um admin com a rede interna liberada — o que a
fixação acrescentaria ali é só a recusa do serviço de metadados.
"""

import socket

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError

import custom_analyzers


class DestinationRefused(Exception):
	"""O nome resolveu, na hora de conectar, para um endereço que a trava recusa.

	Não é um OSError de propósito: a urllib3 embrulha erros de socket em
	"Connection aborted" e a mensagem se perde. Os consumidores pegam esta
	exceção pelo nome e dizem "Destino recusado", como dizem para a trava.
	"""


def _refusal(host, address, allow_internal):
	if custom_analyzers.is_metadata_address(address):
		return ('{0} resolveu para {1} na hora de conectar — o serviço de metadados da nuvem, '
			'recusado mesmo com a rede interna liberada.'.format(host, address))
	if allow_internal:
		return '{0} resolveu para {1} na hora de conectar, que não é um destino.'.format(host, address)
	return ('{0} resolveu para {1} na hora de conectar, que não é um endereço público. '
		'Se a validação tinha aprovado este nome, o DNS respondeu diferente para ela e '
		'para a conexão.'.format(host, address))


def _pinned(connection_cls, allow_internal):
	class Pinned(connection_cls):

		def _new_conn(self):
			# _dns_host é o nome como veio na URL; é o que a urllib3 passaria ao
			# DNS. Guardado antes de ser trocado pelo IP, e devolvido depois
			name = self._dns_host
			host = name.rstrip('.')
			infos = socket.getaddrinfo(host, self.port, 0, socket.SOCK_STREAM)
			addresses = []
			for info in infos:
				address = info[4][0]
				# Basta um proibido para recusar, como em validate_destination: não
				# se controla qual deles uma nova tentativa usaria
				if custom_analyzers._is_forbidden_address(address, allow_internal):
					raise DestinationRefused(_refusal(host, address, allow_internal))
				if address not in addresses:
					addresses.append(address)
			if not addresses:
				raise NewConnectionError(self, 'Failed to establish a new connection: {0} did not resolve'.format(host))

			error = None
			for address in addresses:
				# O socket vai para o IP julgado. `host` (a propriedade) lê
				# _dns_host, e é dela que saem o SNI e a conferência do certificado:
				# por isso a troca dura só o tempo de abrir o socket
				self._dns_host = address
				try:
					return super()._new_conn()
				except NewConnectionError as failure:
					error = failure
				finally:
					self._dns_host = name
			raise error

	Pinned.__name__ = 'Pinned' + connection_cls.__name__
	return Pinned


class PinnedAdapter(HTTPAdapter):

	def __init__(self, allow_internal = False, **kwargs):
		self.allow_internal = allow_internal
		super().__init__(**kwargs)

	def init_poolmanager(self, *args, **kwargs):
		super().init_poolmanager(*args, **kwargs)
		plain = type('PinnedHTTPConnectionPool', (HTTPConnectionPool,),
			{'ConnectionCls': _pinned(HTTPConnection, self.allow_internal)})
		secure = type('PinnedHTTPSConnectionPool', (HTTPSConnectionPool,),
			{'ConnectionCls': _pinned(HTTPSConnection, self.allow_internal)})
		self.poolmanager.pool_classes_by_scheme = {'http': plain, 'https': secure}


def session(allow_internal = False):
	"""Uma sessão nova, fixada. Para quem precisa de estado entre chamadas — o
	unshorten segue uma cadeia de saltos numa sessão só."""
	http = requests.Session()
	adapter = PinnedAdapter(allow_internal)
	http.mount('http://', adapter)
	http.mount('https://', adapter)
	return http


def request(method, url, allow_internal = False, **kwargs):
	"""requests.request, com a conexão fixada no endereço aprovado.

	Uma sessão por chamada, fechada no fim — exatamente o que requests.request
	faz. Não é descuido com o keep-alive: no requests 2.26 da imagem, uma
	conexão aberta com verify=False (um conector com certificado próprio) volta
	ao pool e seria reaproveitada por outra chamada ao mesmo host que exige a
	validação (CVE-2024-35195). Sessão compartilhada entre consumidores com
	`verify` diferentes seria esse rebaixamento.
	"""
	with session(allow_internal) as http:
		return http.request(method, url, **kwargs)


def get(url, allow_internal = False, **kwargs):
	return request('GET', url, allow_internal, **kwargs)


def post(url, allow_internal = False, **kwargs):
	return request('POST', url, allow_internal, **kwargs)
