"""O endereço do feed do OpenPhish passa pela trava de SSRF.

`feedUrl` é o único endereço que um admin digita num analisador nativo. Sem a
trava, `http://169.254.169.254/...` ou um host da rede interna seria buscado
pelo servidor e a resposta, tratada como lista de URLs. Aqui o feed é externo:
rede interna recusada, metadados recusados, conexão fixada no IP aprovado e
redirect nunca seguido. Um feed que não pôde ser lido é `info` com erro, nunca
`safe`.

Run with:  python -m unittest test_openphish_feed_guard   (from the app/ directory)
"""

import unittest
from unittest import mock

import analyzers
import pinned_http


class FeedAnswer:

	def __init__(self, status_code = 200, text = 'http://bad.example/x\n'):
		self.status_code = status_code
		self.text = text

	def raise_for_status(self):
		pass


def entry(feed_url):
	return {'openphish': {'enabled': True, 'feedUrl': feed_url}}


class OpenPhishFeedGuard(unittest.TestCase):

	def setUp(self):
		analyzers._openphish_cache.clear()
		self.addCleanup(analyzers._openphish_cache.clear)

	def run_with(self, feed_url, **patches):
		plain_requests = mock.Mock()
		with mock.patch.object(analyzers.requests, 'get', plain_requests), \
				mock.patch.object(pinned_http, 'get', **patches) as pinned:
			result = analyzers.run('openphish', 'url', 'http://bad.example/x', entry(feed_url))
		plain_requests.assert_not_called()
		return result, pinned

	def test_internal_and_metadata_addresses_are_not_fetched(self):
		for feed_url in ('https://127.0.0.1/feed.txt', 'https://10.1.2.3/feed.txt',
				'https://169.254.169.254/latest/meta-data/', 'http://openphish.example/feed.txt'):
			with self.subTest(feed_url = feed_url):
				result, pinned = self.run_with(feed_url, return_value = FeedAnswer())
				pinned.assert_not_called()
				self.assertEqual(result['level'], 'info')
				self.assertTrue(result['error'])

	def test_public_feed_goes_through_the_pinned_connection_without_redirects(self):
		with mock.patch('custom_analyzers.validate_destination', return_value = (True, '')):
			result, pinned = self.run_with('https://feed.example/feed.txt',
				return_value = FeedAnswer())
		self.assertEqual(pinned.call_count, 1)
		self.assertIs(pinned.call_args.kwargs.get('allow_redirects'), False)
		self.assertFalse(pinned.call_args.args[1:] and pinned.call_args.args[1])
		self.assertEqual(result['level'], 'malicious')

	def test_dns_that_changes_its_mind_at_connect_time_is_info_not_safe(self):
		with mock.patch('custom_analyzers.validate_destination', return_value = (True, '')):
			result, _ = self.run_with('https://feed.example/feed.txt',
				side_effect = pinned_http.DestinationRefused('resolveu para 169.254.169.254'))
		self.assertEqual(result['level'], 'info')
		self.assertTrue(result['error'])

	def test_a_redirect_from_the_feed_is_info_not_safe(self):
		with mock.patch('custom_analyzers.validate_destination', return_value = (True, '')):
			result, _ = self.run_with('https://feed.example/feed.txt',
				return_value = FeedAnswer(status_code = 302))
		self.assertEqual(result['level'], 'info')
		self.assertTrue(result['error'])


if __name__ == '__main__':
	unittest.main()
