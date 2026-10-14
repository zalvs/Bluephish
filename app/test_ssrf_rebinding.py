"""DNS rebinding contra os seis consumidores da trava de SSRF (BP-SEC-03).

validate_destination() resolve o nome e decide. Até aqui, a biblioteca HTTP
resolvia o mesmo nome de novo, por conta própria, na hora de conectar — e um DNS
hostil responde uma coisa a cada pergunta: um IP público para a trava, o
endereço interno para a conexão. É o risco que a §4.5.1 chamava de residual.

O que se prende aqui é o comportamento de cada consumidor, pela porta da frente
dele, contra um DNS que troca de resposta entre a primeira pergunta e as
seguintes. A rede não é simulada: há um servidor de verdade escutando em
127.0.0.1, e o que se afere é se alguém chegou a conectar nele. O único falso é
o DNS — que é justamente a peça que o atacante controla.

Nos consumidores que liberam a rede interna por construção (tickets, responders),
a segunda resposta é 0.0.0.0: recusado mesmo com a rede interna aberta, e que no
Linux conecta no loopback — então a falta da trava aparece como uma conexão no
servidor de teste, não só como uma mensagem diferente.

Roda com:  python -m unittest test_ssrf_rebinding   (a partir do diretório app/)
"""

import socket
import threading
import unittest
from unittest import mock

import analyzers
import connectors
import custom_analyzers
import responders
import tickets
import unshorten

try:
	import email_render
except Exception:  # pragma: no cover - libmagic só existe na imagem
	email_render = None

PUBLIC = '93.184.216.34'
_real_getaddrinfo = socket.getaddrinfo


class Listener(object):
	"""Um servidor TCP que conta quem conectou e guarda o que chegou."""

	def __init__(self):
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind(('127.0.0.1', 0))
		self.server.listen(16)
		self.port = self.server.getsockname()[1]
		self.accepted = 0
		self.requests = []
		self.thread = threading.Thread(target = self._serve, daemon = True)
		self.thread.start()

	def _serve(self):
		while True:
			try:
				conn, _ = self.server.accept()
			except OSError:
				return
			self.accepted += 1
			try:
				conn.settimeout(2)
				data = b''
				while b'\r\n\r\n' not in data:
					chunk = conn.recv(4096)
					if not chunk:
						break
					data += chunk
				self.requests.append(data.decode('latin-1'))
				conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
					b'Content-Length: 2\r\nConnection: close\r\n\r\n{}')
			except OSError:
				pass
			finally:
				conn.close()

	def close(self):
		self.server.close()


class RebindingDNS(object):
	"""`host` resolve para `first` na primeira pergunta e para `then` nas outras."""

	def __init__(self, host, first, then):
		self.host = host
		self.first = first
		self.then = then
		self.calls = 0

	def __call__(self, host, port, *args, **kwargs):
		if host != self.host:
			return _real_getaddrinfo(host, port, *args, **kwargs)
		self.calls += 1
		address = self.first if self.calls == 1 else self.then
		return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (address, port or 0))]


class Base(unittest.TestCase):

	# O que o DNS responde depois da primeira pergunta
	THEN = '127.0.0.1'

	def setUp(self):
		self.listener = Listener()
		self.host = 'rebind.test'
		self.dns = RebindingDNS(self.host, PUBLIC, self.THEN)
		patcher = mock.patch('socket.getaddrinfo', self.dns)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.addCleanup(self.listener.close)

	def url(self, scheme = 'https', path = '/'):
		return '{0}://{1}:{2}{3}'.format(scheme, self.host, self.listener.port, path)

	def assertNobodyConnected(self):
		self.assertEqual(0, self.listener.accepted,
			'a conexão chegou ao endereço interno: {0}'.format(self.listener.requests))

	def assertRefused(self, text):
		self.assertIn('recusad', str(text).lower())


class RedeInternaNuncaLiberada(Base):
	"""Os quatro que recusam a rede interna: um endereço interno na segunda resposta."""

	def test_unshorten(self):
		result = unshorten.resolve(self.url('http', '/curto'))
		self.assertNobodyConnected()
		self.assertRefused(result['error'])

	@unittest.skipIf(email_render is None, 'email_render precisa de libmagic (roda na imagem)')
	def test_email_render(self):
		uri, reason = email_render.RemoteImageFetcher().fetch(self.url('http', '/logo.png'))
		self.assertIsNone(uri)
		self.assertNobodyConnected()
		self.assertRefused(reason)

	def test_analisador_customizado(self):
		definition = {'url': self.url('https', '/v1?i={value}'), 'method': 'GET',
			'authType': 'none', 'allowInternal': False, 'valuePath': 'x', 'levelMap': []}
		with self.assertRaises(analyzers.AnalyzerError) as caught:
			custom_analyzers.query(definition, 'domain', 'exemplo.com')
		self.assertNobodyConnected()
		self.assertRefused(caught.exception)

	def test_conector(self):
		import test_connectors
		outcome = connectors.deliver(test_connectors.definition(url = self.url('https', '/api')),
			test_connectors.report())
		self.assertFalse(outcome['ok'])
		self.assertNobodyConnected()
		self.assertRefused(outcome['error'])


class RedeInternaLiberada(Base):
	"""Os dois que liberam a rede interna: o que continua fechado é o que nunca é destino."""

	THEN = '0.0.0.0'

	def test_jira(self):
		entry = {'url': self.url('https'), 'authType': 'bearer', 'token': 't', 'verifyTls': 'sim'}
		with self.assertRaises(tickets.TicketError) as caught:
			tickets._jira_call(entry, 'GET', '/rest/api/2/myself')
		self.assertNobodyConnected()
		self.assertRefused(caught.exception)

	def test_firewall(self):
		entry = {'url': self.url('https'), 'apiToken': 't', 'verifyTls': 'sim', 'vdom': 'root'}
		with self.assertRaises(responders.ResponderError) as caught:
			responders._fortigate_call(entry, 'GET', '/api/v2/monitor/system/status')
		self.assertNobodyConnected()
		self.assertRefused(caught.exception)


class ConexaoFixadaNoEnderecoValidado(Base):
	"""O controle positivo: o que a trava aceita continua chegando, pelo nome certo."""

	def setUp(self):
		super().setUp()
		# Um nome que resolve sempre para o loopback, num consumidor que libera a
		# rede interna: tem de conectar, e no endereço que foi validado
		self.dns.first = self.dns.then = '127.0.0.1'

	def test_o_destino_aceito_recebe_a_requisicao_com_o_host_original(self):
		entry = {'url': self.url('http'), 'authType': 'bearer', 'token': 't', 'verifyTls': 'sim'}
		try:
			tickets._jira_call(entry, 'GET', '/rest/api/2/myself')
		except tickets.TicketError:
			pass
		self.assertEqual(1, self.listener.accepted)
		self.assertIn('Host: {0}:{1}'.format(self.host, self.listener.port), self.listener.requests[0])


if __name__ == '__main__':
	unittest.main()
