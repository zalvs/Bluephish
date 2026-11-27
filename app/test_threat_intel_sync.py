"""Testes da coleta do panorama externo: o que é guardado, o que é recusado e o estado da fonte.

Como em test_feeds, o download roda contra um servidor HTTP de verdade em
127.0.0.1, e não contra um falso do `requests`: os casos que importam (um 304, um
redirect, um corpo acima do limite) são justamente os que um falso erraria do
mesmo jeito que o código.

Run with:  python -m unittest test_threat_intel_sync   (from the app/ directory)
"""

import calendar
import http.server
import json
import os
import shutil
import tempfile
import threading
import unittest

import threat_intel as ti
import threat_intel_sync as sync

NOW = calendar.timegm((2026, 10, 30, 12, 0, 0))


def rss(*links):
	items = ''.join('<item><title>Phishing campaign {0}</title><link>https://news.test/{0}</link>'
		'<pubDate>Fri, 23 Oct 2026 14:00:00 GMT</pubDate></item>'.format(link) for link in links)
	return '<?xml version="1.0"?><rss><channel>{0}</channel></rss>'.format(items).encode()


class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		state = self.server.state
		state['requests'].append(dict(self.headers))
		status, headers, body = state['answer']()
		self.send_response(status)
		for name, value in headers.items():
			self.send_header(name, value)
		if not state.get('no_length'):
			self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, *args):
		pass


class SyncTestCase(unittest.TestCase):
	def setUp(self):
		self.httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		self.httpd.state = {'requests': [], 'answer': lambda: (200, {}, rss('a', 'b'))}
		self.thread = threading.Thread(target = self.httpd.serve_forever, daemon = True)
		self.thread.start()
		self.state = self.httpd.state
		self.base = tempfile.mkdtemp()
		self.source = dict(ti.BY_ID['knowbe4'],
			url = 'http://127.0.0.1:{0}/rss'.format(self.httpd.server_address[1]))

	def tearDown(self):
		self.httpd.shutdown()
		self.httpd.server_close()
		shutil.rmtree(self.base, ignore_errors = True)

	def serve(self, body, status = 200, headers = None):
		self.state['answer'] = lambda: (status, dict(headers or {}), body)

	def refresh(self, now = NOW):
		return sync.refresh(self.source, self.base, now)

	def stored_links(self):
		return sorted(item['link'] for item in sync.read_store(self.base)['items'])


class RefreshTest(SyncTestCase):
	def test_first_fetch_stores_items_and_marks_collection_start(self):
		result = self.refresh()
		self.assertTrue(result['ok'])
		self.assertEqual(result['added'], 2)
		store = sync.read_store(self.base)
		self.assertEqual(store['collectingSince'], NOW)
		self.assertEqual(self.stored_links(), ['https://news.test/a', 'https://news.test/b'])
		self.assertEqual(store['items'][0]['source'], 'knowbe4')

	def test_items_accumulate_across_fetches(self):
		self.refresh(NOW - 7200)
		self.serve(rss('b', 'c'))
		result = self.refresh()
		self.assertEqual(result['added'], 1)
		self.assertEqual(self.stored_links(), ['https://news.test/a', 'https://news.test/b', 'https://news.test/c'])
		self.assertEqual(sync.read_store(self.base)['collectingSince'], NOW - 7200)

	def test_conditional_request_and_304(self):
		self.serve(rss('a'), headers = {'ETag': '"v1"'})
		self.refresh(NOW - 7200)
		self.serve(b'', status = 304)
		result = self.refresh()
		self.assertTrue(result['ok'])
		self.assertEqual(self.state['requests'][-1].get('If-None-Match'), '"v1"')
		self.assertEqual(self.stored_links(), ['https://news.test/a'])
		self.assertEqual(sync.read_state(self.base)['knowbe4']['checkedAt'], NOW)

	def test_redirect_is_refused_and_items_are_kept(self):
		self.refresh(NOW - 7200)
		self.serve(b'', status = 302, headers = {'Location': 'http://169.254.169.254/'})
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('redirecionamento', result['error'])
		self.assertEqual(len(self.state['requests']), 2)
		self.assertEqual(self.stored_links(), ['https://news.test/a', 'https://news.test/b'])

	def test_declared_size_over_limit(self):
		self.serve(b'x' * 10, headers = {'Content-Length': str(ti.MAX_FEED_BYTES + 1)})
		self.state['no_length'] = True
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('limite', result['error'])

	def test_streamed_size_over_limit_is_cut(self):
		self.state['no_length'] = True
		self.serve(b'<rss>' + b' ' * (ti.MAX_FEED_BYTES + 10))
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('limite', result['error'])

	def test_not_a_feed_is_a_failure_with_reason(self):
		self.serve(b'<html><body>login</body></html>')
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('RSS', result['error'])
		self.assertEqual(sync.read_state(self.base)['knowbe4']['lastError'], result['error'])

	def test_http_error_is_recorded(self):
		self.serve(b'', status = 503)
		result = self.refresh()
		self.assertIn('503', result['error'])

	def test_network_failure_never_raises(self):
		self.source['url'] = 'http://127.0.0.1:1/rss'
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('falha de rede', result['error'])


class StatusAndScheduleTest(SyncTestCase):
	def test_never_fetched_has_no_count(self):
		status = sync.source_status(self.source, {}, NOW)
		self.assertEqual(status['status'], 'never')
		self.assertIsNone(status['count'])

	def test_fresh_failing_stale(self):
		self.refresh(NOW)
		self.assertEqual(sync.source_status(self.source, sync.read_state(self.base), NOW)['status'], 'fresh')
		self.serve(b'', status = 500)
		self.refresh(NOW + 60)
		self.assertEqual(sync.source_status(self.source, sync.read_state(self.base), NOW + 60)['status'], 'failing')
		later = NOW + (sync.STALE_AFTER_INTERVALS + 1) * sync.INTERVAL_MINUTES * 60
		self.assertEqual(sync.source_status(self.source, sync.read_state(self.base), later)['status'], 'stale')

	def test_is_due(self):
		self.assertTrue(sync.is_due(None, NOW))
		self.assertFalse(sync.is_due({'checkedAt': NOW - 60}, NOW))
		self.assertTrue(sync.is_due({'checkedAt': NOW - sync.INTERVAL_MINUTES * 60}, NOW))
		# Depois de uma falha, espera antes de tentar de novo
		self.assertFalse(sync.is_due({'lastError': 'x', 'lastAttempt': NOW - 60}, NOW))

	def test_refresh_due_only_touches_enabled_sources(self):
		config = sync.default_config()
		calls = []
		original = sync.refresh
		sync.refresh = lambda source, *args: calls.append(source['id']) or {'ok': True}
		try:
			sync.refresh_due(config, self.base, NOW)
			self.assertEqual(calls, [])
			config['sources']['knowbe4'] = True
			sync.refresh_due(config, self.base, NOW)
			self.assertEqual(calls, ['knowbe4'])
		finally:
			sync.refresh = original


class ConfigTest(unittest.TestCase):
	def setUp(self):
		self.dir = tempfile.mkdtemp()
		self.path = os.path.join(self.dir, 'configuration.json')
		with open(self.path, 'w') as conf_file:
			json.dump({'imap': {'password': 'segredo'}, 'llm_analysis': {'api_key': 'k'}}, conf_file)

	def tearDown(self):
		shutil.rmtree(self.dir, ignore_errors = True)

	def test_default_is_everything_off(self):
		config = sync.load_config(self.path)
		self.assertFalse(any(config['sources'].values()))
		self.assertFalse(config['summary']['enabled'])

	def test_unknown_source_is_dropped_and_rest_of_file_survives(self):
		saved = sync.save_config({'sources': {'knowbe4': True, 'evil': True}, 'summary': {'enabled': True}}, self.path)
		self.assertTrue(saved['sources']['knowbe4'])
		self.assertNotIn('evil', saved['sources'])
		self.assertIs(saved['summary']['enabled'], True)
		with open(self.path) as conf_file:
			whole = json.load(conf_file)
		self.assertEqual(whole['imap']['password'], 'segredo')
		self.assertEqual(whole['llm_analysis']['api_key'], 'k')

	def test_garbage_section_is_default(self):
		self.assertEqual(sync.normalize_config('nope'), sync.default_config())

	def test_only_a_real_boolean_turns_something_on(self):
		# bool("false") é True: um corpo mal formado não pode ligar fonte nem resumo
		config = sync.normalize_config({'sources': {'knowbe4': 'false', 'cofense': 1},
			'summary': {'enabled': 'false'}})
		self.assertFalse(config['sources']['knowbe4'])
		self.assertFalse(config['sources']['cofense'])
		self.assertFalse(config['summary']['enabled'])


class CorruptStoreTest(SyncTestCase):
	def test_corrupt_records_are_skipped_and_collection_goes_on(self):
		os.makedirs(self.base, exist_ok = True)
		with open(os.path.join(self.base, 'items.json'), 'w') as target:
			json.dump({'collectingSince': 'ontem', 'items': [{'title': 'sem id'}, 'texto', None,
				{'id': 'x', 'title': 't', 'link': 'javascript:alert(1)', 'seenAt': 1}]}, target)
		self.assertEqual(sync.read_store(self.base), {'collectingSince': None, 'items': []})
		result = self.refresh()
		self.assertTrue(result['ok'])
		self.assertEqual(self.stored_links(), ['https://news.test/a', 'https://news.test/b'])


if __name__ == '__main__':
	unittest.main()
