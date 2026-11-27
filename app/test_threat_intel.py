"""Testes da parte pura do panorama externo: leitura do feed, classificação e acúmulo.

Os documentos de exemplo reproduzem a forma dos feeds reais do catálogo (RSS 2.0
de WordPress, Atom, RSS 1.0), com títulos tirados do que eles publicavam em
outubro de 2026 — inclusive o alerta da KnowBe4 sobre convite de calendário, que é
o caso que motivou o recurso.

Run with:  python -m unittest test_threat_intel   (from the app/ directory)
"""

import calendar
import time
import unittest

import threat_intel as ti

NOW = calendar.timegm((2026, 10, 30, 12, 0, 0))

RSS = b'''<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel><title>KnowBe4</title>
<item>
  <title>Warning: Attackers Are Using Calendar Invite Files to Evade Security Filters</title>
  <link>https://blog.knowbe4.com/calendar-invite-files</link>
  <pubDate>Fri, 23 Oct 2026 14:00:00 GMT</pubDate>
  <description><![CDATA[<p>Phishing campaigns attach <b>.ics</b> files &amp; bypass filters.</p>]]></description>
  <category>Phishing</category>
</item>
<item>
  <title>Golpe do falso TSE cobra Pix por debito eleitoral</title>
  <link>https://www.welivesecurity.com/pt/golpe-tse</link>
  <pubDate>Tue, 27 Oct 2026 10:00:00 -0300</pubDate>
  <description>Golpistas miram eleitores brasileiros.</description>
</item>
<item>
  <title>Sem link nenhum</title>
  <description>fica de fora</description>
</item>
<item>
  <title>Link perigoso</title>
  <link>javascript:alert(1)</link>
</item>
</channel></rss>'''

ATOM = b'''<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Talos</title>
  <entry>
    <title type="html">UAT-11985: AI-assisted event lures delivering real-time Google AitM phishing</title>
    <link rel="replies" href="https://blog.example/comments"/>
    <link rel="alternate" href="https://blog.talosintelligence.com/uat-11985/"/>
    <published>2026-10-08T10:00:00.1234567Z</published>
    <summary>Storm-2990 and Lumma are mentioned too.</summary>
  </entry>
</feed>'''

RDF = b'''<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
  xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel><title>x</title></channel>
  <item><title>Quishing hits hospitals</title><link>https://example.org/q</link>
  <dc:date>2026-10-01T00:00:00+00:00</dc:date></item>
</rdf:RDF>'''


class ParseFeedTest(unittest.TestCase):
	def test_reads_rss_items_with_link_title_date_and_clean_excerpt(self):
		items = ti.parse_feed(RSS, NOW)
		self.assertEqual(len(items), 2)
		first = items[0]
		self.assertEqual(first['link'], 'https://blog.knowbe4.com/calendar-invite-files')
		self.assertEqual(first['published'], calendar.timegm((2026, 10, 23, 14, 0, 0)))
		self.assertEqual(first['excerpt'], 'Phishing campaigns attach .ics files & bypass filters.')
		self.assertEqual(first['categories'], ['Phishing'])
		self.assertEqual(first['id'], ti.item_id(first['link']))

	def test_item_without_http_link_is_dropped(self):
		titles = [item['title'] for item in ti.parse_feed(RSS, NOW)]
		self.assertNotIn('Sem link nenhum', titles)
		self.assertNotIn('Link perigoso', titles)

	def test_reads_atom_alternate_link_and_long_fraction(self):
		items = ti.parse_feed(ATOM, NOW)
		self.assertEqual(items[0]['link'], 'https://blog.talosintelligence.com/uat-11985/')
		self.assertEqual(items[0]['published'], calendar.timegm((2026, 10, 8, 10, 0, 0)))

	def test_reads_rss_1_0(self):
		items = ti.parse_feed(RDF, NOW)
		self.assertEqual(items[0]['title'], 'Quishing hits hospitals')
		self.assertEqual(items[0]['published'], calendar.timegm((2026, 10, 1, 0, 0, 0)))

	def test_doctype_is_refused(self):
		bomb = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
			b'<rss><channel><item><title>&lol2;</title><link>https://x.test/</link></item></channel></rss>')
		with self.assertRaises(ti.FeedError):
			ti.parse_feed(bomb, NOW)

	def test_external_entity_is_refused(self):
		xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
			b'<rss><channel><item><title>&x;</title><link>https://x.test/</link></item></channel></rss>')
		with self.assertRaises(ti.FeedError):
			ti.parse_feed(xxe, NOW)

	def test_html_page_is_not_a_feed(self):
		with self.assertRaises(ti.FeedError):
			ti.parse_feed(b'<html><body>nope</body></html>', NOW)

	def test_broken_xml_raises_feed_error(self):
		with self.assertRaises(ti.FeedError):
			ti.parse_feed(b'<rss><channel><item>', NOW)

	def test_item_cap(self):
		body = b'<rss><channel>' + b''.join(
			'<item><title>t{0}</title><link>https://x.test/{0}</link></item>'.format(n).encode()
			for n in range(ti.MAX_ITEMS_PER_FEED + 20)) + b'</channel></rss>'
		self.assertEqual(len(ti.parse_feed(body, NOW)), ti.MAX_ITEMS_PER_FEED)

	def test_duplicate_links_in_one_document_count_once(self):
		body = (b'<rss><channel><item><title>a</title><link>https://x.test/1</link></item>'
			b'<item><title>b</title><link>https://x.test/1</link></item></channel></rss>')
		self.assertEqual(len(ti.parse_feed(body, NOW)), 1)


class HostileTextTest(unittest.TestCase):
	def test_many_open_brackets_do_not_take_quadratic_time(self):
		# Com `<[^>]*>`, 80 mil "<" levavam 3 s e um documento no limite, horas — com
		# o hub inteiro parado, porque o `re` não solta o GIL
		started = time.time()
		ti.strip_html('<' * 400000)
		body = ('<rss><channel><item><title>t</title><link>https://x.test/</link><description><![CDATA['
			+ '<' * 400000 + ']]></description></item></channel></rss>').encode()
		ti.parse_feed(body, NOW)
		self.assertLess(time.time() - started, 2)

	def test_offsite_link_is_flagged(self):
		knowbe4 = ti.BY_ID['knowbe4']
		self.assertFalse(ti.offsite({'link': 'https://blog.knowbe4.com/x'}, knowbe4))
		self.assertFalse(ti.offsite({'link': 'https://www.knowbe4.com/x'}, knowbe4))
		self.assertTrue(ti.offsite({'link': 'https://knowbe4-login.test/x'}, knowbe4))
		certbr = ti.BY_ID['certbr']
		self.assertFalse(ti.offsite({'link': 'https://cartilha.cert.br/fasciculos/'}, certbr))
		cisoadvisor = ti.BY_ID['cisoadvisor']
		self.assertTrue(ti.offsite({'link': 'https://evil.com.br/x'}, cisoadvisor))


class ParseDateTest(unittest.TestCase):
	def test_epoch_zero_is_not_a_date(self):
		# A Huntress publica itens com 01/01/1970
		self.assertIsNone(ti.parse_date('1970-01-01T00:00:00Z', NOW))

	def test_far_future_is_not_a_date(self):
		self.assertIsNone(ti.parse_date('2031-01-01T00:00:00Z', NOW))

	def test_garbage_is_none(self):
		self.assertIsNone(ti.parse_date('ontem à tarde', NOW))
		self.assertIsNone(ti.parse_date('', NOW))

	def test_any_fraction_length_is_read(self):
		# O fromisoformat do Python 3.8 (a imagem até 11/2026) só lia 3 ou 6 dígitos de fração
		expected = calendar.timegm((2026, 10, 8, 10, 0, 0))
		for fraction in ('.1', '.12', '.1234', '.123456789'):
			self.assertEqual(ti.parse_date('2026-10-08T10:00:00' + fraction + 'Z', NOW), expected, fraction)

	def test_naive_iso_is_utc(self):
		self.assertEqual(ti.parse_date('2026-10-01T03:00:00', NOW), calendar.timegm((2026, 10, 1, 3, 0, 0)))


class SafeLinkTest(unittest.TestCase):
	def test_only_http_with_host(self):
		self.assertEqual(ti.safe_link('https://a.test/x'), 'https://a.test/x')
		self.assertEqual(ti.safe_link('http://a.test'), 'http://a.test')
		for bad in ('javascript:alert(1)', 'data:text/html,x', 'https://', '/relative', 'ftp://a.test/', ''):
			self.assertEqual(ti.safe_link(bad), '', bad)


class ClassifyTest(unittest.TestCase):
	def classify(self, title, excerpt = ''):
		return ti.classify({'title': title, 'excerpt': excerpt})

	def test_calendar_invite_campaign(self):
		result = self.classify('Warning: Attackers Are Using Calendar Invite Files to Evade Security Filters')
		self.assertIn('calendar_invite', result['themes'])
		self.assertTrue(result['relevant'])

	def test_rsvp_lure_is_calendar_invite(self):
		self.assertIn('calendar_invite', self.classify('RSVP to Disaster: How One Click Installs a RAT')['themes'])

	def test_brazilian_pix_scam(self):
		result = self.classify('Golpe do falso TSE cobra Pix por débito eleitoral inexistente')
		self.assertTrue(result['relevant'])
		self.assertTrue(result['brazil'])
		self.assertIn('bec', result['themes'])

	def test_named_groups_by_code_and_by_name(self):
		result = self.classify('UAT-11985 and Storm-2990 use Lumma; TA577 too', 'and Lapsus$ and APT29')
		for actor in ('UAT-11985', 'Storm-2990', 'TA577', 'APT29', 'Lumma', 'Lapsus$'):
			self.assertIn(actor, result['actors'])

	def test_lowercase_code_is_not_a_group(self):
		self.assertEqual(self.classify('ta 2026 report on phishing')['actors'], [])

	def test_generic_theme_alone_is_not_relevant(self):
		# OAuth sozinho aparece em notícia de produto; só conta com phishing junto
		self.assertFalse(self.classify('New OAuth library release')['relevant'])
		self.assertTrue(self.classify('OAuth consent phishing targets M365')['relevant'])

	def test_unrelated_news_is_not_relevant(self):
		self.assertFalse(self.classify('Binance probes potential crypto-theft hack')['relevant'])

	def test_sector(self):
		self.assertIn('healthcare', self.classify('Quishing wave hits hospitals')['sectors'])
		self.assertIn('hr', self.classify('Calendly phishing pages are targeting job seekers')['sectors'])


class MergeTest(unittest.TestCase):
	def item(self, link, published = None):
		return {'id': ti.item_id(link), 'title': 't', 'link': link, 'published': published, 'excerpt': ''}

	def test_dedup_keeps_first_seen(self):
		first = ti.merge([], 'knowbe4', [self.item('https://a.test/1', NOW - 100)], NOW - 50)
		again = ti.merge(first, 'knowbe4', [self.item('https://a.test/1', NOW - 100)], NOW)
		self.assertEqual(len(again), 1)
		self.assertEqual(again[0]['seenAt'], NOW - 50)
		self.assertEqual(again[0]['source'], 'knowbe4')

	def test_retention_drops_old_items(self):
		old = self.item('https://a.test/old', NOW - (ti.RETENTION_DAYS + 1) * 86400)
		fresh = self.item('https://a.test/new', NOW - 86400)
		merged = ti.merge([], 'x', [old, fresh], NOW)
		self.assertEqual([item['link'] for item in merged], ['https://a.test/new'])

	def test_sorted_newest_first_and_input_untouched(self):
		stored = [dict(self.item('https://a.test/1', NOW - 3000), source = 'x', seenAt = NOW - 3000)]
		snapshot = [dict(item) for item in stored]
		merged = ti.merge(stored, 'x', [self.item('https://a.test/2', NOW - 10)], NOW)
		self.assertEqual(merged[0]['link'], 'https://a.test/2')
		self.assertEqual(stored, snapshot)

	def test_store_is_capped_keeping_the_newest(self):
		fetched = [self.item('https://a.test/{0}'.format(n), NOW - n) for n in range(ti.MAX_STORED_ITEMS + 5)]
		merged = ti.merge([], 'x', fetched, NOW)
		self.assertEqual(len(merged), ti.MAX_STORED_ITEMS)
		self.assertEqual(merged[0]['link'], 'https://a.test/0')

	def test_item_without_date_uses_first_seen(self):
		merged = ti.merge([], 'x', [self.item('https://a.test/nodate')], NOW)
		self.assertEqual(ti.item_time(merged[0]), NOW)


class CatalogTest(unittest.TestCase):
	def test_every_source_is_https_and_unique(self):
		ids = [source['id'] for source in ti.SOURCES]
		self.assertEqual(len(ids), len(set(ids)))
		for source in ti.SOURCES:
			self.assertTrue(source['url'].startswith('https://'), source['id'])
			self.assertTrue(source['site'].startswith('https://'), source['id'])
			self.assertIn(source['kind'], ('research', 'press', 'cert', 'brazil'))

	def test_recommended_pack_exists_and_has_brazilian_source(self):
		recommended = [source for source in ti.SOURCES if source['recommended']]
		self.assertTrue(recommended)
		self.assertTrue(any(source['kind'] == 'brazil' for source in recommended))


def stored(link, title, published, source = 'knowbe4', excerpt = ''):
	return {'id': ti.item_id(link), 'title': title, 'link': link, 'published': published, 'excerpt': excerpt,
		'source': source, 'seenAt': published}


DAY = 86400


class PeriodTest(unittest.TestCase):
	def test_month_bounds_and_label(self):
		start, end, label = ti.period_bounds('2026-09', NOW)
		self.assertEqual(start, calendar.timegm((2026, 9, 1, 0, 0, 0)))
		self.assertEqual(end, calendar.timegm((2026, 10, 1, 0, 0, 0)))
		self.assertEqual(label, 'setembro de 2026')

	def test_current_month_ends_now(self):
		self.assertEqual(ti.period_bounds('2026-10', NOW)[1], NOW)

	def test_only_offered_months_are_accepted(self):
		self.assertEqual(ti.offered_months(NOW), ['2026-10', '2026-09', '2026-08'])
		self.assertEqual(ti.normalize_period('2025-01', NOW), ti.DEFAULT_PERIOD)
		self.assertEqual(ti.normalize_period('../etc', NOW), ti.DEFAULT_PERIOD)
		self.assertEqual(ti.normalize_period('2026-08', NOW), '2026-08')

	def test_january_wraps_to_previous_year(self):
		january = calendar.timegm((2027, 1, 15, 0, 0, 0))
		self.assertEqual(ti.offered_months(january), ['2027-01', '2026-12', '2026-11'])

	def test_covering_range(self):
		days = {'7d': 7, '30d': 30, '90d': 90, '180d': 180}
		self.assertEqual(ti.covering_range(NOW - 5 * DAY, NOW, days), '7d')
		self.assertEqual(ti.covering_range(NOW - 45 * DAY, NOW, days), '90d')
		self.assertEqual(ti.covering_range(NOW - 400 * DAY, NOW, days), 'all')


class LocalSignalsTest(unittest.TestCase):
	def run_signals(self, observables):
		cases = [{'_id': 'c1', 'v': 'Malicious', 't': (NOW - DAY) * 1000},
			{'_id': 'c2', 'v': 'Suspicious', 't': (NOW - 2 * DAY) * 1000},
			{'_id': 'old', 'v': 'Malicious', 't': (NOW - 90 * DAY) * 1000}]
		return ti.local_signals(cases, observables, lambda case: case['v'], lambda case: case['t'],
			(NOW - 30 * DAY) * 1000, NOW * 1000, {'sites.google.com', 'bit.ly'})

	def test_ics_attachment_counted_in_window_only(self):
		result = self.run_signals({
			'c1': [{'dataType': 'file', 'attachment': {'name': 'Convite.ICS'}}],
			'c2': [{'dataType': 'file', 'data': 'reuniao.ics'}],
			'old': [{'dataType': 'file', 'data': 'antigo.ics'}]})
		self.assertEqual(result['threatCases'], 2)
		self.assertEqual(result['themes']['calendar_invite']['cases'], 2)
		self.assertEqual(result['themes']['calendar_invite']['malicious'], 1)

	def test_shared_platform_and_html(self):
		result = self.run_signals({
			'c1': [{'dataType': 'url', 'data': 'https://sites.google.com/view/x'}],
			'c2': [{'dataType': 'file', 'data': 'fatura.svg'}, {'dataType': 'domain', 'data': 'evil.test'}]})
		self.assertEqual(result['themes']['legit_infra']['cases'], 1)
		self.assertEqual(result['themes']['html_svg']['cases'], 1)

	def test_lookalike_host_is_not_shared_platform(self):
		result = self.run_signals({'c1': [{'dataType': 'domain', 'data': 'notbit.ly'}]})
		self.assertEqual(result['themes']['legit_infra']['cases'], 0)


class BuildPanoramaTest(unittest.TestCase):
	def items(self):
		return [
			stored('https://k.test/ics', 'Attackers Are Using Calendar Invite Files', NOW - 7 * DAY),
			stored('https://c.test/rsvp', 'RSVP to Disaster: phishing lure', NOW - 17 * DAY, source = 'cofense'),
			stored('https://w.test/pix', 'Golpe do falso TSE cobra Pix', NOW - 3 * DAY, source = 'welivesecurity_pt'),
			stored('https://t.test/uat', 'UAT-11985 AitM phishing', NOW - 22 * DAY, source = 'talos'),
			stored('https://b.test/hack', 'Binance probes crypto-theft hack', NOW - 1 * DAY,
				source = 'bleepingcomputer'),
			stored('https://k.test/old', 'Calendar invite phishing returns', NOW - 50 * DAY)
		]

	def test_themes_count_sources_and_skip_unrelated(self):
		payload = ti.build_panorama(self.items(), NOW - 100 * DAY, '30d', NOW)
		themes = dict((theme['key'], theme) for theme in payload['themes'])
		self.assertEqual(themes['calendar_invite']['count'], 2)
		self.assertEqual(themes['calendar_invite']['sources'], 2)
		self.assertEqual(payload['totals']['relevant'], 4)
		self.assertNotIn('https://b.test/hack', [item['link'] for item in payload['items']])
		self.assertEqual(payload['themes'][0]['key'], 'calendar_invite')

	def test_previous_window_compared_only_when_collected(self):
		covered = ti.build_panorama(self.items(), NOW - 100 * DAY, '30d', NOW)
		calendar_theme = [t for t in covered['themes'] if t['key'] == 'calendar_invite'][0]
		self.assertTrue(covered['compared'])
		self.assertEqual(calendar_theme['previous'], 1)
		self.assertTrue(calendar_theme['trending'])

		recent = ti.build_panorama(self.items(), NOW - 10 * DAY, '30d', NOW)
		self.assertFalse(recent['compared'])
		self.assertTrue(recent['partial'])
		recent_theme = [t for t in recent['themes'] if t['key'] == 'calendar_invite'][0]
		self.assertIsNone(recent_theme['previous'])
		# Sem o período anterior, não há subida para afirmar
		self.assertFalse(recent_theme['trending'])

	def test_never_collected_is_partial(self):
		payload = ti.build_panorama([], None, '30d', NOW)
		self.assertTrue(payload['partial'])
		self.assertEqual(payload['themes'], [])
		self.assertEqual(payload['totals']['relevant'], 0)

	def test_local_is_none_for_unmeasurable_themes_and_without_cases(self):
		local = {'threatCases': 12, 'themes': {'calendar_invite': {'cases': 3, 'malicious': 2, 'label': 'x'},
			'html_svg': {'cases': 0, 'malicious': 0, 'label': 'y'},
			'legit_infra': {'cases': 0, 'malicious': 0, 'label': 'z'}}}
		payload = ti.build_panorama(self.items(), NOW - 100 * DAY, '30d', NOW, local)
		themes = dict((theme['key'], theme) for theme in payload['themes'])
		self.assertEqual(themes['calendar_invite']['local']['cases'], 3)
		self.assertEqual(themes['calendar_invite']['local']['threatCases'], 12)
		self.assertIsNone(themes['aitm']['local'])
		self.assertFalse(themes['aitm']['measurable'])

		unread = ti.build_panorama(self.items(), NOW - 100 * DAY, '30d', NOW, None)
		self.assertIsNone([t for t in unread['themes'] if t['key'] == 'calendar_invite'][0]['local'])

	def test_actors_brazil_and_month(self):
		payload = ti.build_panorama(self.items(), NOW - 100 * DAY, '2026-10', NOW)
		self.assertEqual(payload['period']['label'], 'outubro de 2026')
		self.assertIn('UAT-11985', [actor['name'] for actor in payload['actors']])
		self.assertEqual(payload['brazil']['count'], 1)

	def test_every_cited_item_is_in_the_payload(self):
		many = [stored('https://n.test/{0}'.format(n), 'phishing wave {0}'.format(n), NOW - DAY - n)
			for n in range(ti.MAX_ITEMS_IN_PAYLOAD + 50)]
		many.append(stored('https://k.test/ics-old', 'Calendar invite phishing', NOW - 25 * DAY))
		payload = ti.build_panorama(many, NOW - 100 * DAY, '30d', NOW)
		ids = set(item['id'] for item in payload['items'])
		for theme in payload['themes']:
			self.assertTrue(set(theme['items']) <= ids, theme['key'])

	def test_failing_sources_are_listed(self):
		states = {'knowbe4': {'status': 'fresh'}, 'cofense': {'status': 'failing'}, 'talos': {'status': 'never'}}
		payload = ti.build_panorama(self.items(), NOW - 100 * DAY, '30d', NOW, None, states)
		self.assertEqual(payload['sourcesFailing'], ['cofense'])
		self.assertEqual(payload['totals']['enabledSources'], 3)


if __name__ == '__main__':
	unittest.main()
