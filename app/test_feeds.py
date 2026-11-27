"""Tests for the public feeds: what is stored, what is refused, and what a lookup says.

The downloader is exercised against a real HTTP server on 127.0.0.1 rather than a
hand-written fake of `requests`: a fake only proves it matches the code, while
the cases that matter here (a 304, a redirect, a body past the size cap) are
exactly the ones a fake would get wrong in the same way the code does.

Run with:  python -m unittest test_feeds   (from the app/ directory)
"""

import http.server
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

import analyzers as an
import analyzer_guides as guides
import feeds
import scoring


# --------------------------------------------------------------------------- #
# A server whose answers the test chooses                                      #
# --------------------------------------------------------------------------- #

class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		state = self.server.state
		state['requests'].append(dict(self.headers))
		route = state['routes'].get(self.path) or state['routes']['/']
		status, headers, body = route()
		self.send_response(status)
		for name, value in headers.items():
			self.send_header(name, value)
		# HTTP/1.0 closes the connection to end the body, so a server can also
		# leave the length undeclared — the case that has to be cut mid-stream
		if not state.get('no_length'):
			self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, *args):
		pass


class Server(object):
	def __init__(self):
		self.httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
		self.httpd.state = {'requests': [], 'routes': {}}
		self.thread = threading.Thread(target = self.httpd.serve_forever, daemon = True)
		self.thread.start()
		self.state = self.httpd.state

	def url(self, path = '/'):
		return 'http://127.0.0.1:{0}{1}'.format(self.httpd.server_address[1], path)

	def serve(self, body, status = 200, headers = None, path = '/'):
		self.state['routes'][path] = lambda: (status, dict(headers or {}), body)

	def close(self):
		self.httpd.shutdown()
		self.httpd.server_close()


def domains(count, start = 0):
	return ''.join('host{0}.example-phish.test\n'.format(n) for n in range(start, start + count))


def feed_for(server, **overrides):
	feed = dict(feeds.BY_ID['certpl_domains'])
	feed.update({'url': server.url(), 'minCount': 3, 'maxBytes': 1024 * 1024})
	feed.update(overrides)
	return feed


class FeedTestCase(unittest.TestCase):
	def setUp(self):
		self.directory = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.directory, True)
		self.server = Server()
		self.addCleanup(self.server.close)
		self.now = 1790000000.0


# --------------------------------------------------------------------------- #
# Pure                                                                         #
# --------------------------------------------------------------------------- #

class Normalization(unittest.TestCase):
	def test_a_domain_is_lowercased_and_loses_its_trailing_dot(self):
		self.assertEqual(feeds.normalize('domain', 'Exemplo.COM.'), 'exemplo.com')

	def test_an_internationalized_domain_is_stored_as_punycode(self):
		self.assertEqual(feeds.normalize('domain', 'bücher.example'), 'xn--bcher-kva.example')

	def test_things_that_are_not_domains_are_dropped(self):
		for value in ('', '   ', 'a b.com', 'http://x.com', 'user@x.com', 'x.com:80'):
			self.assertEqual(feeds.normalize('domain', value), '', value)

	def test_a_url_ignores_scheme_case_fragment_and_trailing_slash(self):
		forms = ['http://Exemplo.com/Pagar/', 'https://exemplo.com/Pagar', 'HTTPS://EXEMPLO.COM/Pagar#topo']
		self.assertEqual(set(feeds.normalize('url', form) for form in forms), {'exemplo.com/Pagar'})

	def test_a_url_keeps_its_query_because_that_is_where_redirects_hide(self):
		self.assertEqual(feeds.normalize('url', 'http://a.com/r?to=b'), 'a.com/r?to=b')
		self.assertNotEqual(feeds.normalize('url', 'http://a.com/r?to=b'), feeds.normalize('url', 'http://a.com/r'))

	def test_the_userinfo_trick_resolves_to_the_real_host(self):
		self.assertEqual(feeds.normalize('url', 'http://paypal.com@evil.test/x'), 'evil.test/x')

	def test_an_unknown_kind_normalizes_to_nothing(self):
		self.assertEqual(feeds.normalize('hash', 'abc'), '')

	def test_build_and_lookup_use_the_same_function(self):
		# Whatever the list contains must be findable by the same text typed back
		line = 'Mixed.Case-Domain.TEST.'
		self.assertEqual(list(feeds.parse_lines('domain', [line])), [feeds.normalize('domain', line)])


class Parsing(unittest.TestCase):
	def test_comments_blanks_and_junk_are_skipped(self):
		lines = ['# header', '', '   ', 'a.com', 'not a domain', 'B.com']
		self.assertEqual(list(feeds.parse_lines('domain', lines)), ['a.com', 'b.com'])

	def test_an_absurdly_long_line_is_skipped(self):
		self.assertEqual(list(feeds.parse_lines('domain', ['a' * (feeds.MAX_LINE_LENGTH + 1) + '.com'])), [])


class SwapPolicy(unittest.TestCase):
	def test_a_list_below_the_minimum_is_refused(self):
		ok, reason = feeds.accept_swap(10, None, 1000)
		self.assertFalse(ok)
		self.assertIn('mínimo', reason)

	def test_a_first_download_above_the_minimum_is_accepted(self):
		self.assertEqual(feeds.accept_swap(5000, None, 1000), (True, ''))

	def test_a_list_that_lost_more_than_half_is_refused(self):
		ok, reason = feeds.accept_swap(400, 1000, 100)
		self.assertFalse(ok)
		self.assertIn('encolheu', reason)

	def test_a_list_that_shrank_a_little_is_accepted(self):
		self.assertTrue(feeds.accept_swap(900, 1000, 100)[0])

	def test_a_list_that_grew_is_accepted(self):
		self.assertTrue(feeds.accept_swap(2000, 1000, 100)[0])


class Freshness(unittest.TestCase):
	def test_never_downloaded_is_missing_not_stale(self):
		self.assertEqual(feeds.freshness(None, 100, 60), 'missing')
		self.assertEqual(feeds.freshness({}, 100, 60), 'missing')

	def test_within_three_intervals_is_fresh(self):
		self.assertEqual(feeds.freshness({'checkedAt': 1}, 1 + 3 * 60 * 60, 60), 'fresh')

	def test_past_three_intervals_is_stale(self):
		self.assertEqual(feeds.freshness({'checkedAt': 1}, 1 + 3 * 60 * 60 + 1, 60), 'stale')

	def test_due_when_never_tried(self):
		self.assertTrue(feeds.is_due(None, 100, 60))

	def test_not_due_before_the_interval(self):
		self.assertFalse(feeds.is_due({'checkedAt': 1000}, 1000 + 59 * 60, 60))

	def test_due_after_the_interval(self):
		self.assertTrue(feeds.is_due({'checkedAt': 1000}, 1000 + 60 * 60, 60))

	def test_a_recent_failure_is_not_retried_at_once(self):
		meta = {'checkedAt': 1, 'lastError': 'boom', 'lastAttempt': 10000}
		self.assertFalse(feeds.is_due(meta, 10000 + 60, 60))

	def test_a_failure_is_retried_after_the_wait(self):
		meta = {'checkedAt': 1, 'lastError': 'boom', 'lastAttempt': 10000}
		self.assertTrue(feeds.is_due(meta, 10000 + feeds.RETRY_AFTER_FAILURE_MINUTES * 60 + 1, 60))


# --------------------------------------------------------------------------- #
# Download                                                                     #
# --------------------------------------------------------------------------- #

class Refresh(FeedTestCase):
	def refresh(self, feed = None, now = None):
		return feeds.refresh(feed or feed_for(self.server), self.directory, now or self.now)

	def lookup(self, value, feed = None, now = None):
		return feeds.lookup(feed or feed_for(self.server), 'domain', value, self.directory, now or self.now)

	def test_a_first_download_indexes_the_list_and_finds_a_listed_domain(self):
		self.server.serve(('# comment\n' + domains(10)).encode())
		result = self.refresh()
		self.assertTrue(result['ok'], result)
		self.assertEqual(result['count'], 10)
		found = self.lookup('HOST3.example-phish.test')
		self.assertEqual((found['status'], found['listed']), ('fresh', True))

	def test_a_domain_that_is_not_in_the_list_is_not_listed(self):
		self.server.serve(domains(10).encode())
		self.refresh()
		self.assertFalse(self.lookup('innocent.test')['listed'])

	def test_before_any_download_the_state_is_missing_with_no_count(self):
		found = self.lookup('host1.example-phish.test')
		self.assertEqual((found['status'], found['listed'], found['count']), ('missing', False, None))
		self.assertIsNone(feeds.status(feed_for(self.server), self.directory, self.now)['count'])

	def test_a_download_leaves_no_temporary_file_behind(self):
		self.server.serve(domains(10).encode())
		self.refresh()
		leftovers = [n for n in os.listdir(os.path.join(self.directory, 'certpl_domains')) if n.endswith('.tmp')]
		self.assertEqual(leftovers, [])

	def test_a_second_request_is_conditional_and_a_304_keeps_the_index(self):
		self.server.serve(domains(10).encode(), headers = {'ETag': '"v1"'})
		self.refresh()
		self.server.serve(b'', status = 304)
		result = self.refresh(now = self.now + 3600)
		self.assertTrue(result['ok'])
		self.assertFalse(result['changed'])
		self.assertEqual(self.server.state['requests'][-1].get('If-None-Match'), '"v1"')
		self.assertTrue(self.lookup('host1.example-phish.test', now = self.now + 3600)['listed'])
		self.assertEqual(feeds.read_meta(self.directory, feed_for(self.server))['checkedAt'], self.now + 3600)

	def test_a_list_that_shrank_too_much_is_refused_and_the_old_one_is_kept(self):
		self.server.serve(domains(100).encode())
		self.refresh()
		self.server.serve(domains(10).encode())
		result = self.refresh(now = self.now + 3600)
		self.assertFalse(result['ok'])
		self.assertIn('encolheu', result['error'])
		self.assertTrue(self.lookup('host99.example-phish.test', now = self.now + 3600)['listed'])
		self.assertIn('encolheu', feeds.status(feed_for(self.server), self.directory, self.now)['error'])

	def test_a_list_below_the_minimum_is_not_installed(self):
		self.server.serve(domains(2).encode())
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertEqual(self.lookup('host1.example-phish.test')['status'], 'missing')

	def test_a_download_past_the_size_limit_is_cut(self):
		self.server.serve(domains(500).encode())
		result = self.refresh(feed_for(self.server, maxBytes = 1000))
		self.assertFalse(result['ok'])
		self.assertIn('limite', result['error'])
		self.assertEqual(self.lookup('host1.example-phish.test')['status'], 'missing')

	def test_an_undeclared_length_is_cut_mid_stream_at_the_limit(self):
		self.server.state['no_length'] = True
		self.server.serve(domains(500).encode())
		result = self.refresh(feed_for(self.server, maxBytes = 1000))
		self.assertFalse(result['ok'])
		self.assertIn('interrompido', result['error'])
		self.assertEqual(self.lookup('host1.example-phish.test')['status'], 'missing')

	def test_a_redirect_is_not_followed(self):
		self.server.serve(domains(10).encode(), path = '/real')
		self.server.serve(b'', status = 302, headers = {'Location': self.server.url('/real')})
		result = self.refresh()
		self.assertFalse(result['ok'])
		self.assertIn('302', result['error'])
		self.assertEqual(self.lookup('host1.example-phish.test')['status'], 'missing')

	def test_an_http_error_is_recorded_and_the_old_index_survives(self):
		self.server.serve(domains(10).encode())
		self.refresh()
		self.server.serve(b'oops', status = 503)
		result = self.refresh(now = self.now + 3600)
		self.assertFalse(result['ok'])
		self.assertIn('503', result['error'])
		self.assertTrue(self.lookup('host1.example-phish.test', now = self.now + 3600)['listed'])

	def test_an_unreachable_server_fails_without_raising(self):
		url = self.server.url()
		self.server.close()
		self.server = Server()
		result = feeds.refresh(feed_for(self.server, url = url), self.directory, self.now)
		self.assertFalse(result['ok'])
		self.assertTrue(result['error'])

	def test_a_second_refresh_while_one_runs_reports_busy(self):
		feed = feed_for(self.server)
		lock = feeds._lock_for(feed)
		lock.acquire()
		try:
			self.assertTrue(feeds.refresh(feed, self.directory, self.now)['busy'])
			self.assertTrue(feeds.status(feed, self.directory, self.now)['refreshing'])
		finally:
			lock.release()

	def test_the_user_agent_identifies_the_application(self):
		self.server.serve(domains(10).encode())
		self.refresh()
		self.assertIn('BluePhish', self.server.state['requests'][0].get('User-Agent', ''))

	def test_refresh_due_skips_disabled_feeds(self):
		self.assertEqual(feeds.refresh_due({}, self.directory, self.now), {})
		self.assertEqual(feeds.refresh_due({'certpl_domains': {'enabled': False}}, self.directory, self.now), {})


class SharedPlatforms(FeedTestCase):
	def test_a_shared_platform_is_never_convicted_by_a_domain_list(self):
		self.server.serve(('sites.google.com\nBit.ly\n' + domains(10)).encode())
		feed = feed_for(self.server)
		self.assertTrue(feeds.refresh(feed, self.directory, self.now)['ok'])
		for host in ('sites.google.com', 'BIT.LY', 'bit.ly.'):
			found = feeds.lookup(feed, 'domain', host, self.directory, self.now)
			self.assertEqual((found['listed'], found['shared']), (False, True), host)

	def test_an_ordinary_domain_in_the_same_list_is_still_listed(self):
		self.server.serve(('sites.google.com\n' + domains(10)).encode())
		feed = feed_for(self.server)
		feeds.refresh(feed, self.directory, self.now)
		self.assertTrue(feeds.lookup(feed, 'domain', 'host1.example-phish.test', self.directory, self.now)['listed'])

	def test_a_subdomain_of_a_shared_platform_is_judged_on_its_own(self):
		self.server.serve(('evil.pages.dev\n' + domains(10)).encode())
		feed = feed_for(self.server)
		feeds.refresh(feed, self.directory, self.now)
		self.assertTrue(feeds.lookup(feed, 'domain', 'evil.pages.dev', self.directory, self.now)['listed'])

	def test_the_shared_list_holds_only_normalized_hosts(self):
		for host in feeds.SHARED_HOSTS:
			self.assertEqual(feeds.normalize('domain', host), host)


class UrlFeed(FeedTestCase):
	def test_a_url_is_found_whatever_its_scheme(self):
		feed = dict(feeds.BY_ID['phishingdb_links'])
		feed.update({'url': self.server.url(), 'minCount': 2, 'maxBytes': 1024 * 1024})
		self.server.serve(b'http://bad.test/login\nhttps://worse.test/a/b/\n')
		self.assertTrue(feeds.refresh(feed, self.directory, self.now)['ok'])
		for typed in ('https://BAD.test/login', 'http://worse.test/a/b', 'worse.test/a/b/'):
			self.assertTrue(feeds.lookup(feed, 'url', typed, self.directory, self.now)['listed'], typed)
		self.assertFalse(feeds.lookup(feed, 'url', 'http://bad.test/other', self.directory, self.now)['listed'])


# --------------------------------------------------------------------------- #
# As analyzers                                                                 #
# --------------------------------------------------------------------------- #

class AsAnalyzers(FeedTestCase):
	def setUp(self):
		FeedTestCase.setUp(self)
		previous = feeds.FEEDS_DIR
		feeds.FEEDS_DIR = self.directory
		self.addCleanup(setattr, feeds, 'FEEDS_DIR', previous)
		self.config = {'certpl_domains': {'enabled': True, 'observables': ['domain']}}

	def install(self, count = 10):
		self.server.serve(domains(count).encode())
		self.assertTrue(feeds.refresh(feed_for(self.server), self.directory, time.time())['ok'])

	def age_the_copy(self):
		feed = feeds.BY_ID['certpl_domains']
		meta = feeds.read_meta(self.directory, feed)
		meta['checkedAt'] = time.time() - 4 * 60 * 60
		feeds._write_meta(self.directory, feed, meta)

	def run_feed(self, value, feed_id = 'certpl_domains'):
		return an.run(feed_id, 'domain', value, self.config)

	def test_a_listed_domain_takes_the_level_the_feed_declares(self):
		self.install()
		result = self.run_feed('host2.example-phish.test')
		self.assertEqual((result['level'], result['error']), ('malicious', ''))

	def test_not_listed_is_info_and_never_safe(self):
		self.install()
		result = self.run_feed('innocent.test')
		self.assertEqual((result['level'], result['error']), ('info', ''))

	def test_a_feed_never_downloaded_says_so_instead_of_answering(self):
		result = self.run_feed('innocent.test')
		self.assertEqual(result['level'], 'info')
		self.assertIn('ainda não foi baixada', result['error'])

	def test_a_stale_copy_does_not_vouch_for_what_it_does_not_list(self):
		self.install()
		self.age_the_copy()
		result = self.run_feed('innocent.test')
		self.assertEqual(result['level'], 'info')
		self.assertIn('desatualizada', result['error'])

	def test_a_stale_copy_still_convicts_what_it_lists(self):
		self.install()
		self.age_the_copy()
		result = self.run_feed('host2.example-phish.test')
		self.assertEqual(result['level'], 'malicious')
		self.assertIn('desatualizada', result['detail'])

	def test_a_disabled_feed_does_not_answer(self):
		self.install()
		self.config['certpl_domains']['enabled'] = False
		self.assertEqual(self.run_feed('host2.example-phish.test')['level'], 'info')

	def test_the_lower_confidence_feed_raises_suspicion_not_a_conviction(self):
		self.assertEqual(an.level_for('phishingdb_domains', {}, {'listed': True}), 'suspicious')

	def test_a_feed_does_not_receive_a_type_it_does_not_hold(self):
		self.assertFalse(an.supports('certpl_domains', 'url'))
		self.assertTrue(an.supports('phishingdb_links', 'url'))


# --------------------------------------------------------------------------- #
# Registry invariants                                                          #
# --------------------------------------------------------------------------- #

class Registry(unittest.TestCase):
	def test_every_feed_is_a_registered_analyzer_of_the_feed_family(self):
		for feed in feeds.FEEDS:
			self.assertEqual(an.BY_ID[feed['id']]['family'], 'feed')

	def test_every_feed_downloads_over_https_from_a_fixed_address(self):
		for feed in feeds.FEEDS:
			self.assertTrue(feed['url'].startswith('https://'), feed['id'])

	def test_no_feed_asks_the_analyst_for_an_address(self):
		for feed in feeds.FEEDS:
			self.assertEqual(an.BY_ID[feed['id']]['credentials'], [], feed['id'])

	def test_every_feed_has_a_weight_of_its_own(self):
		for feed in feeds.FEEDS:
			self.assertIn(feed['id'], scoring.DEFAULT_ANALYZER_WEIGHTS)

	def test_every_feed_states_its_licence(self):
		for feed in feeds.FEEDS:
			self.assertTrue(feed['license'].get('note'), feed['id'])
			self.assertTrue(feed['license'].get('url', '').startswith('https://'), feed['id'])

	def test_feed_ids_are_unique(self):
		ids = [feed['id'] for feed in feeds.FEEDS]
		self.assertEqual(len(ids), len(set(ids)))

	def test_the_large_list_is_not_in_the_recommended_pack(self):
		self.assertFalse(feeds.BY_ID['phishingdb_links']['recommended'])

	def test_only_a_feed_with_a_clear_licence_is_in_the_recommended_pack(self):
		# The pack promises "no legal problem for a company": a licence that says
		# "confirm" is exactly the one that must be turned on on purpose
		for feed in feeds.FEEDS:
			if feed['recommended']:
				self.assertEqual(feed['license']['class'], 'free', feed['id'])

	def test_the_licence_class_is_one_the_screen_knows(self):
		for feed in feeds.FEEDS:
			self.assertIn(feed['license']['class'], ('free', 'confirm'), feed['id'])

	def test_every_feed_has_a_guide(self):
		for feed in feeds.FEEDS:
			self.assertTrue(guides.guide_for(feed['id']), feed['id'])

	def test_the_feed_logger_is_configured(self):
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logging_conf.json')) as conf:
			self.assertIn('feeds', json.load(conf)['loggers'])


if __name__ == '__main__':
	unittest.main()
