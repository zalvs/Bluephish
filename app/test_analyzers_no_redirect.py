"""Os analisadores nativos não seguem redirect.

Cada cliente manda a chave de API do fornecedor num cabeçalho próprio
(`x-apikey`, `Key`, `X-OTX-API-KEY`...). O `requests` só tira o `Authorization`
quando o redirect muda de host; o resto da chave viaja junto para onde a
resposta mandar. Uma resposta 3xx de um fornecedor é falha (`info` com erro,
nunca `safe`), não um caminho a seguir.

Run with:  python -m unittest test_analyzers_no_redirect   (from the app/ directory)
"""

import unittest
from unittest import mock

import analyzers


class RedirectAnswer:

	status_code = 302
	is_redirect = True
	headers = {'Location': 'http://elsewhere.example/steal'}
	text = ''

	def raise_for_status(self):
		pass

	def json(self):
		return {}


ENTRY = {'enabled': True, 'apiKey': 'k', 'clientId': 'c', 'clientSecret': 's', 'tenantId': 't'}


def record_calls():
	calls = []

	def fake(url, *args, **kwargs):
		calls.append(kwargs)
		return RedirectAnswer()

	return calls, fake


class NativeAnalyzersRefuseRedirects(unittest.TestCase):

	def test_every_vendor_call_refuses_redirects(self):
		for analyzer_id, client in analyzers.CLIENTS.items():
			calls, fake = record_calls()
			with self.subTest(analyzer = analyzer_id), \
					mock.patch.object(analyzers.requests, 'get', side_effect = fake), \
					mock.patch.object(analyzers.requests, 'post', side_effect = fake):
				try:
					client(dict(ENTRY), 'url', 'http://phish.example/x')
				except Exception:
					pass
				for kwargs in calls:
					self.assertIs(kwargs.get('allow_redirects'), False)

	def test_a_redirect_answer_is_info_with_an_error_not_safe(self):
		calls, fake = record_calls()
		with mock.patch.object(analyzers.requests, 'get', side_effect = fake), \
				mock.patch.object(analyzers.requests, 'post', side_effect = fake):
			result = analyzers.run('virustotal', 'url', 'http://phish.example/x',
				{'virustotal': dict(ENTRY)})
		self.assertEqual(result['level'], 'info')
		self.assertTrue(result['error'])


if __name__ == '__main__':
	unittest.main()
