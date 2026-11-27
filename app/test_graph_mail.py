"""A paginação do Microsoft Graph só segue o `@odata.nextLink` que continua no Graph.

O token Bearer vai no cabeçalho de cada página. O `nextLink` vem do corpo da
resposta: se ele apontar para outro host (resposta adulterada por um proxy, um
espelho mal configurado), o token seguiria junto — o `requests` só tira o
`Authorization` em redirect, não em uma chamada nova. Um `nextLink` fora do Graph
é falha, não um caminho a seguir.

Run with:  python -m unittest test_graph_mail   (from the app/ directory)
"""

import sys
import unittest
from unittest import mock

# m365_auth importa o msal só para obter token; aqui nenhum token é pedido
try:
	import msal  # noqa: F401
except ImportError:
	sys.modules['msal'] = mock.MagicMock()

import graph_mail

PAGE_URL = graph_mail.GRAPH_BASE_URL + '/users/box/mailFolders/inbox/messages?$skiptoken=abc'


class Page:

	# As leituras do Graph recusam 3xx (graph_mail._no_redirect): a página falsa
	# precisa dizer que é um 200
	status_code = 200

	def __init__(self, values, next_link = None):
		self._body = {'value': values}
		if next_link:
			self._body['@odata.nextLink'] = next_link

	def raise_for_status(self):
		pass

	def json(self):
		return self._body


def collect(pages, wanted = 10):
	with mock.patch.object(graph_mail.requests, 'get', side_effect = pages) as get:
		result = graph_mail._page_through(graph_mail.GRAPH_BASE_URL + '/users/box/messages', {'Authorization': 'Bearer t'}, {}, wanted)
	return result, get


class NextLinkStaysOnGraph(unittest.TestCase):

	def test_follows_a_next_link_on_the_graph_host(self):
		result, get = collect([Page([{'id': 1}], PAGE_URL), Page([{'id': 2}])])
		self.assertEqual([m['id'] for m in result], [1, 2])
		self.assertEqual(get.call_count, 2)
		self.assertEqual(get.call_args_list[1].args[0], PAGE_URL)

	def test_refuses_a_next_link_on_another_host(self):
		for link in ('https://evil.example/v1.0/users', 'http://graph.microsoft.com/v1.0/users',
				'https://graph.microsoft.com.evil.example/v1.0/users', 'https://graph.microsoft.com@evil.example/x',
				'https://graph.microsoft.com:8443/v1.0/users', '//evil.example/x'):
			with self.subTest(link = link):
				with self.assertRaises(graph_mail.UnsafeNextLink):
					collect([Page([{'id': 1}], link), Page([{'id': 2}])])

	def test_the_token_is_never_sent_to_the_refused_link(self):
		with mock.patch.object(graph_mail.requests, 'get', side_effect = [Page([{'id': 1}], 'https://evil.example/x')]) as get:
			with self.assertRaises(graph_mail.UnsafeNextLink):
				graph_mail._page_through(graph_mail.GRAPH_BASE_URL + '/users/box/messages', {'Authorization': 'Bearer t'}, {}, 10)
		self.assertEqual(get.call_count, 1)


if __name__ == '__main__':
	unittest.main()
