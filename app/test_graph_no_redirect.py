"""As leituras do Microsoft Graph (caixa e diretório) não seguem redirect.

Todas levam o token de aplicativo do tenant. O `requests` só tira o cabeçalho
`Authorization` quando o redirect muda de host; para o mesmo host, ou num
downgrade de esquema controlado por quem responde, ele segue. Um 3xx também não
pode virar um e-mail vazio para analisar: `raise_for_status()` não reclama de 3xx
e o corpo viria vazio. Aqui o 3xx é falha, nunca resultado.

Run with:  python -m unittest test_graph_no_redirect   (from the app/ directory)
"""

import sys
import types
import unittest
from unittest import mock

try:
	import msal  # noqa: F401
except ImportError:  # fora da imagem não há msal; o token é simulado em cada teste
	sys.modules['msal'] = types.ModuleType('msal')

import graph_directory
import graph_mail


class FakeResponse:

	def __init__(self, status = 200, payload = None):
		self.status_code = status
		self.ok = status < 400
		self.headers = {'Location': 'http://elsewhere.example/steal'}
		self.content = b''
		self._payload = payload if payload is not None else {}

	def raise_for_status(self):
		if self.status_code >= 400:
			raise graph_mail.requests.HTTPError('HTTP {0}'.format(self.status_code), response = self)

	def json(self):
		return self._payload


def refused(call):
	return call.kwargs.get('allow_redirects') is False


class MailReadsRefuseRedirects(unittest.TestCase):

	def setUp(self):
		patcher = mock.patch.object(graph_mail.m365_auth, 'get_access_token', return_value = 'tok')
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_every_get_and_patch_disables_redirects(self):
		answers = [FakeResponse(200, {'isRead': False})]
		with mock.patch.object(graph_mail.requests, 'get', return_value = FakeResponse(200, {'isRead': False, 'value': []})) as get, \
				mock.patch.object(graph_mail.requests, 'patch', return_value = FakeResponse(200)) as patch:
			graph_mail.list_unread_envelopes('t', 'c', 's', 'a@b.example')
			graph_mail.fetch_message('t', 'c', 's', 'a@b.example', 'id1')
			graph_mail.peek_message('t', 'c', 's', 'a@b.example', 'id1')
		self.assertTrue(get.call_args_list)
		for call in get.call_args_list + patch.call_args_list:
			self.assertTrue(refused(call), call)

	def test_a_redirect_on_the_mime_download_is_an_error_not_an_empty_email(self):
		with mock.patch.object(graph_mail.requests, 'get', return_value = FakeResponse(302)):
			with self.assertRaises(graph_mail.GraphRedirectError):
				graph_mail.download_mime({'Authorization': 'Bearer x'}, 'a@b.example', 'id1')

	def test_a_redirect_on_the_listing_is_an_error(self):
		with mock.patch.object(graph_mail.m365_auth, 'get_access_token', return_value = 'tok'), \
				mock.patch.object(graph_mail.requests, 'get', return_value = FakeResponse(307)):
			with self.assertRaises(graph_mail.GraphRedirectError):
				graph_mail.list_unread_envelopes('t', 'c', 's', 'a@b.example')

	def test_a_redirect_when_marking_as_read_is_an_error(self):
		with mock.patch.object(graph_mail.m365_auth, 'get_access_token', return_value = 'tok'), \
				mock.patch.object(graph_mail.requests, 'get', return_value = FakeResponse(200, {'isRead': False})), \
				mock.patch.object(graph_mail.requests, 'patch', return_value = FakeResponse(308)):
			with self.assertRaises(graph_mail.GraphRedirectError):
				graph_mail.fetch_message('t', 'c', 's', 'a@b.example', 'id1')


class DirectoryReadsRefuseRedirects(unittest.TestCase):

	def setUp(self):
		patcher = mock.patch.object(graph_directory.m365_auth, 'get_access_token', return_value = 'tok')
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_lookup_and_probe_disable_redirects(self):
		with mock.patch.object(graph_directory.requests, 'get', return_value = FakeResponse(200, {'department': 'TI', 'id': '1'})) as get:
			graph_directory.lookup_user('t', 'c', 's', 'a@b.example')
			graph_directory.probe('t', 'c', 's')
		self.assertEqual(len(get.call_args_list), 2)
		for call in get.call_args_list:
			self.assertTrue(refused(call), call)

	def test_a_redirect_is_a_directory_error_not_an_unattributed_report(self):
		with mock.patch.object(graph_directory.requests, 'get', return_value = FakeResponse(302)):
			with self.assertRaises(graph_directory.DirectoryError) as caught:
				graph_directory.lookup_user('t', 'c', 's', 'a@b.example')
			self.assertIn('redirecionamento', str(caught.exception))
			with self.assertRaises(graph_directory.DirectoryError):
				graph_directory.probe('t', 'c', 's')


if __name__ == '__main__':
	unittest.main()
