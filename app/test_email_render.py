"""Tests for the "as delivered" rendering of a reported email.

This module hands attacker-written markup to a browser. Everything asserted
below is a way that could go wrong, and each one has a reason to be here rather
than a coverage number:

- Script execution. The sandboxed iframe and the inherited CSP are the other two
  layers, but neither is visible from Python, so this one is the layer the test
  suite can actually hold: `<script>`, `on*` handlers, `javascript:` and the
  embedding tags must not survive the sanitizer at all.
- Outbound requests. Remote images are fetched by the **server**, and the whole
  security of that rests on one thing: the URL was written by an attacker, so
  every fetch has to clear `custom_analyzers.validate_destination()` and refuse
  redirects. A regression there turns this module into an SSRF proxy aimed at
  the cloud metadata service. Those tests touch no network — the guard and the
  transport are both replaced, because what is asserted is that they get
  *called*, not what the internet answers.
- Navigation. No `href` survives. The destination is kept as data so the
  interface can print it, and a link whose text names a different site than its
  destination is marked.
- Picking the right message. When the report carries a forwarded `.eml`, the
  email to look at is the attachment, not the note somebody wrote around it.
  Rendering the wrapper would show the analyst the wrong email while looking
  entirely correct.
- Bounds. Every loop over attacker-sized input is capped, and the payload says
  when a cap was hit.

`magic` only exists inside the image, so the module skips rather than errors on
a bare checkout.

Run with:  python -m unittest test_email_render   (from the app/ directory)
"""

import hashlib
import unittest

import requests

try:
	import email_render
except ImportError:
	email_render = None


def message(body, content_type = 'text/html', charset = 'utf-8'):
	"""A minimal single-part message carrying `body`."""
	return (
		'From: Cobranca <aviso@exemplo-falso.test>\r\n'
		'To: vitima@empresa.test\r\n'
		'Subject: Aviso\r\n'
		'Date: Fri, 28 Aug 2026 14:32:07 -0300\r\n'
		'MIME-Version: 1.0\r\n'
		'Content-Type: {0}; charset={1}\r\n'
		'\r\n'
		'{2}'
	).format(content_type, charset, body).encode('utf-8')


def render_html(body, fetch_remote = False):
	"""Renderiza sem buscar nada por padrão.

	Os testes de sanitização falam de marcação; deixar a busca ligada faria cada
	um deles depender de rede e de um host que não existe. A busca tem a sua
	própria classe de testes, com o `requests` trocado.
	"""
	payload = email_render.render(message(body), fetch_remote = fetch_remote)
	return payload, (payload['html'] or '')


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class NothingCanRun(unittest.TestCase):

	def test_script_blocks_are_removed_with_their_contents(self):
		payload, html = render_html('<p>ola</p><script>fetch("//evil.test")</script>')
		self.assertNotIn('script', html.lower())
		self.assertNotIn('evil.test', html)
		self.assertIn('ola', html)

	def test_event_handler_attributes_are_removed(self):
		payload, html = render_html('<div onclick="steal()" onmouseover="x()">clique</div>')
		self.assertNotIn('onclick', html.lower())
		self.assertNotIn('onmouseover', html.lower())
		self.assertIn('clique', html)

	def test_embedding_tags_are_removed(self):
		for tag in ['iframe', 'object', 'embed', 'form', 'svg', 'meta', 'base']:
			payload, html = render_html('<{0}></{0}>texto'.format(tag))
			self.assertNotIn('<' + tag, html.lower(), tag)
			self.assertIn('texto', html, tag)

	def test_javascript_urls_never_become_hrefs(self):
		# The destination is still shown, and deliberately: a link that carries a
		# script payload is the finding, and hiding it would leave the analyst
		# reading "Clique aqui" with nothing behind it. It travels as data on a
		# tag with no href, printed as text, in a frame where nothing executes
		payload, html = render_html('<a href="javascript:alert(1)">clique</a>')
		self.assertNotIn('href=', html.lower())
		self.assertIn('esquema bloqueado', html)
		self.assertIn('bp-mismatch', html)

	def test_unknown_tags_keep_their_text(self):
		# Dropping an unrecognized wrapper together with its contents would
		# silently shorten the email, which is a different email
		payload, html = render_html('<custom-block>importante</custom-block>')
		self.assertIn('importante', html)
		self.assertNotIn('custom-block', html)


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class NothingReachesTheNetwork(unittest.TestCase):

	def test_remote_image_is_replaced_and_its_host_reported(self):
		# Com a busca desligada, o host é o que fica no lugar da imagem
		payload, html = render_html('<img src="https://beacon.evil.test/p.gif?u=vitima">')
		self.assertNotIn('beacon.evil.test/p.gif', html)
		self.assertIn('bp-blocked', html)
		self.assertEqual(payload['blockedCount'], 1)
		self.assertEqual([h['host'] for h in payload['blockedHosts']], ['beacon.evil.test'])

	def test_repeated_beacons_from_one_host_are_counted_together(self):
		payload, html = render_html(
			'<img src="https://t.evil.test/1.gif">'
			'<img src="https://t.evil.test/2.gif">'
			'<img src="https://outro.test/3.gif">')
		self.assertEqual(payload['blockedCount'], 3)
		hosts = dict((h['host'], h['count']) for h in payload['blockedHosts'])
		self.assertEqual(hosts, {'t.evil.test': 2, 'outro.test': 1})

	def test_css_url_and_import_are_stripped_and_counted(self):
		payload, html = render_html(
			'<style>@import url("https://css.evil.test/a.css");'
			'body{background:url(https://bg.evil.test/b.png)}</style>ola')
		self.assertNotIn('@import', html)
		self.assertNotIn('css.evil.test', html)
		self.assertNotIn('bg.evil.test', html)
		hosts = [h['host'] for h in payload['blockedHosts']]
		self.assertIn('bg.evil.test', hosts)

	def test_style_attribute_background_is_stripped(self):
		payload, html = render_html('<div style="background-image:url(https://bg.evil.test/x.png)">a</div>')
		self.assertNotIn('bg.evil.test', html)

	def test_inline_cid_image_is_embedded_as_a_data_uri(self):
		raw = (
			'From: a@b.test\r\n'
			'Subject: com logo\r\n'
			'MIME-Version: 1.0\r\n'
			'Content-Type: multipart/related; boundary="B"\r\n'
			'\r\n'
			'--B\r\n'
			'Content-Type: text/html; charset=utf-8\r\n'
			'\r\n'
			'<img src="cid:logo123">\r\n'
			'--B\r\n'
			'Content-Type: image/gif\r\n'
			'Content-ID: <logo123>\r\n'
			'Content-Transfer-Encoding: base64\r\n'
			'\r\n'
			'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7\r\n'
			'--B--\r\n'
		).encode('utf-8')
		payload = email_render.render(raw)
		self.assertIn('data:image/gif;base64,', payload['html'])
		self.assertEqual(payload['blockedCount'], 0)
		self.assertEqual(payload['inlineCount'], 1)

	def test_referenced_but_absent_inline_image_says_so(self):
		payload, html = render_html('<img src="cid:naoexiste" alt="logo">')
		self.assertIn('bp-missing', html)
		self.assertIn('logo', html)


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class LinksAreReadableNotFollowable(unittest.TestCase):

	def test_destination_is_kept_as_data_not_as_href(self):
		payload, html = render_html('<a href="https://login.banco-falso.test/x">Acessar</a>')
		self.assertNotIn('href=', html.lower())
		self.assertIn('data-url="https://login.banco-falso.test/x"', html)
		self.assertIn('Acessar', html)

	def test_text_naming_another_domain_is_marked(self):
		payload, html = render_html('<a href="https://coleta.evil.test/x">www.bradesco.com.br</a>')
		self.assertIn('bp-mismatch', html)

	def test_subdomain_of_the_same_site_is_not_marked(self):
		payload, html = render_html('<a href="https://mail.google.com/x">google.com</a>')
		self.assertIn('bp-link', html)
		self.assertNotIn('bp-mismatch', html)

	def test_link_without_a_domain_in_its_text_is_not_marked(self):
		payload, html = render_html('<a href="https://exemplo.test/x">Clique aqui</a>')
		self.assertNotIn('bp-mismatch', html)


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class TheRightMessageIsRendered(unittest.TestCase):

	def build_report_with_attachment(self):
		inner = (
			'From: Falso Banco <aviso@banco-falso.test>\r\n'
			'To: vitima@empresa.test\r\n'
			'Subject: Sua conta sera bloqueada\r\n'
			'MIME-Version: 1.0\r\n'
			'Content-Type: text/html; charset=utf-8\r\n'
			'\r\n'
			'<p>ESTE E O EMAIL DENUNCIADO</p>\r\n'
		)
		return (
			'From: Funcionario <pessoa@empresa.test>\r\n'
			'To: phishing@empresa.test\r\n'
			'Subject: Fwd: suspeito\r\n'
			'MIME-Version: 1.0\r\n'
			'Content-Type: multipart/mixed; boundary="B"\r\n'
			'\r\n'
			'--B\r\n'
			'Content-Type: text/html; charset=utf-8\r\n'
			'\r\n'
			'<p>ESTE E O BILHETE DE QUEM DENUNCIOU</p>\r\n'
			'--B\r\n'
			'Content-Type: message/rfc822\r\n'
			'\r\n'
			+ inner +
			'--B--\r\n'
		).encode('utf-8')

	def test_the_forwarded_eml_is_what_gets_rendered(self):
		payload = email_render.render(self.build_report_with_attachment())
		self.assertEqual(payload['source'], 'attachment')
		self.assertIn('ESTE E O EMAIL DENUNCIADO', payload['html'])
		self.assertNotIn('ESTE E O BILHETE', payload['html'])

	def test_headers_belong_to_the_rendered_message(self):
		payload = email_render.render(self.build_report_with_attachment())
		values = ' | '.join(h['value'] for h in payload['headers'])
		self.assertIn('banco-falso.test', values)
		self.assertNotIn('pessoa@empresa.test', values)

	def test_a_message_without_an_attachment_renders_itself(self):
		payload, html = render_html('<p>direto</p>')
		self.assertEqual(payload['source'], 'message')
		self.assertIn('direto', html)

	def test_prefer_attachment_false_renders_the_wrapper(self):
		payload = email_render.render(self.build_report_with_attachment(), prefer_attachment = False)
		self.assertEqual(payload['source'], 'message')
		self.assertIn('ESTE E O BILHETE', payload['html'])


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class AttachmentsAreDescribedNotReturned(unittest.TestCase):

	def build_with_attachment(self, filename, declared, payload_bytes):
		import base64
		return (
			'From: a@b.test\r\n'
			'Subject: com anexo\r\n'
			'MIME-Version: 1.0\r\n'
			'Content-Type: multipart/mixed; boundary="B"\r\n'
			'\r\n'
			'--B\r\n'
			'Content-Type: text/html; charset=utf-8\r\n'
			'\r\n'
			'<p>veja o anexo</p>\r\n'
			'--B\r\n'
			'Content-Type: {0}\r\n'
			'Content-Disposition: attachment; filename="{1}"\r\n'
			'Content-Transfer-Encoding: base64\r\n'
			'\r\n'
			'{2}\r\n'
			'--B--\r\n'
		).format(declared, filename, base64.b64encode(payload_bytes).decode('ascii')).encode('utf-8')

	def test_hash_and_size_are_reported_and_bytes_are_not(self):
		content = b'%PDF-1.4 fake pdf content'
		payload = email_render.render(self.build_with_attachment('boleto.pdf', 'application/pdf', content))
		self.assertEqual(len(payload['attachments']), 1)
		entry = payload['attachments'][0]
		self.assertEqual(entry['name'], 'boleto.pdf')
		self.assertEqual(entry['size'], len(content))
		self.assertEqual(entry['sha256'], hashlib.sha256(content).hexdigest())
		# No field carries the file itself
		self.assertNotIn('data', entry)
		self.assertNotIn('content', entry)

	def test_declared_and_real_type_are_both_reported(self):
		# A "PDF" that is really a Windows executable is the finding, and it only
		# shows up when the two types are kept side by side
		content = b'MZ\x90\x00' + b'\x00' * 200
		payload = email_render.render(self.build_with_attachment('boleto.pdf', 'application/pdf', content))
		entry = payload['attachments'][0]
		self.assertEqual(entry['declaredType'], 'application/pdf')
		self.assertNotEqual(entry['realType'], 'application/pdf')


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class BoundsAreReported(unittest.TestCase):

	def test_oversized_html_is_cut_and_flagged(self):
		body = '<p>a</p>' * (email_render.MAX_HTML_BYTES // 4)
		payload = email_render.render(message(body))
		self.assertIn('html', payload['truncated'])

	def test_a_message_that_cannot_be_parsed_answers_instead_of_raising(self):
		payload = email_render.render(b'\xff\xfe not a message at all')
		self.assertIsInstance(payload, dict)
		self.assertIsNone(payload['html'])

	def test_a_short_message_reports_no_truncation(self):
		payload, html = render_html('<p>curto</p>')
		self.assertEqual(payload['truncated'], [])
		self.assertIsNone(payload['error'])


@unittest.skipIf(email_render is None, 'python-magic is not installed outside the image')
class FetchingRemoteImagesIsGuarded(unittest.TestCase):
	"""Uma URL escrita por um atacante, buscada pelo servidor.

	Isto é SSRF por construção, e o que separa a visualização de um e-mail de um
	proxy para a rede interna é a trava. Estes testes trocam tanto a trava quanto
	o transporte: o que se afirma é que a trava é *consultada* e que a resposta
	é tratada com desconfiança — não o que a internet responde.
	"""

	GIF = (b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!'
		b'\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x01D\x00;')

	class Response(object):
		def __init__(self, body = b'', status = 200, content_type = 'image/gif'):
			self.body = body
			self.status_code = status
			self.headers = {'Content-Type': content_type} if content_type else {}

		def iter_content(self, size):
			for start in range(0, len(self.body), size):
				yield self.body[start:start + size]

		def close(self):
			pass

	def setUp(self):
		self.requested = []
		self.validated = []
		self.real_get = email_render.pinned_http.get
		self.real_validate = email_render.custom_analyzers.validate_destination
		self.response = self.Response(self.GIF)
		self.allow = (True, None)

		def fake_get(url, **kwargs):
			self.requested.append((url, kwargs))
			return self.response

		def fake_validate(url, **kwargs):
			self.validated.append((url, kwargs))
			return self.allow

		email_render.pinned_http.get = fake_get
		email_render.custom_analyzers.validate_destination = fake_validate

	def tearDown(self):
		email_render.pinned_http.get = self.real_get
		email_render.custom_analyzers.validate_destination = self.real_validate

	def fetched(self, body):
		payload = email_render.render(message(body), fetch_remote = True)
		return payload, (payload['html'] or '')

	def test_the_image_is_inlined_and_its_host_reported(self):
		payload, html = self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertIn('data:image/gif;base64,', html)
		self.assertIn('bp-remote', html)
		self.assertNotIn('cdn.evil.test/logo.png', html)
		self.assertEqual(payload['fetchedCount'], 1)
		self.assertEqual([h['host'] for h in payload['fetchedHosts']], ['cdn.evil.test'])

	def test_the_guard_runs_before_any_request(self):
		self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertEqual(len(self.validated), 1)
		self.assertEqual(self.validated[0][0], 'https://cdn.evil.test/logo.png')

	def test_the_guard_never_gets_the_internal_network_allowed(self):
		# allow_internal ausente ou falso, sempre: um endereço escrito por um
		# atacante não pode fazer este contêiner falar com o lado de dentro
		self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertFalse(self.validated[0][1].get('allow_internal', False))

	def test_a_refused_destination_is_never_requested(self):
		self.allow = (False, '169.254.169.254 é o serviço de metadados da nuvem')
		payload, html = self.fetched('<img src="http://169.254.169.254/latest/meta-data/">')
		self.assertEqual(self.requested, [])
		self.assertIn('bp-blocked', html)
		self.assertIn('metadados', html)
		self.assertEqual(payload['fetchedCount'], 0)

	def test_redirects_are_refused_not_followed(self):
		# Seguir levaria a um endereço que nunca passou pela trava
		self.response = self.Response(b'', status = 302)
		payload, html = self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertFalse(self.requested[0][1]['allow_redirects'])
		self.assertIn('redirecionamento', html)
		self.assertEqual(payload['fetchedCount'], 0)

	def test_the_type_comes_from_the_bytes_not_from_the_header(self):
		# Um host que rotula uma página HTML como image/png está descrevendo o
		# que quer que o navegador acredite, não o que mandou
		self.response = self.Response(b'<html><body>nao sou imagem</body></html>',
			content_type = 'image/png')
		payload, html = self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertEqual(payload['fetchedCount'], 0)
		self.assertIn('bp-blocked', html)
		self.assertNotIn('nao sou imagem', html)

	def test_an_svg_is_refused(self):
		# SVG é documento, não figura: carrega script e referência externa
		self.response = self.Response(
			b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
			content_type = 'image/svg+xml')
		payload, html = self.fetched('<img src="https://cdn.evil.test/logo.svg">')
		self.assertEqual(payload['fetchedCount'], 0)
		self.assertNotIn('alert(1)', html)

	def test_an_oversized_image_is_cut_off_mid_download(self):
		self.response = self.Response(b'GIF89a' + b'\x00' * (email_render.MAX_REMOTE_IMAGE_BYTES + 1024))
		payload, html = self.fetched('<img src="https://cdn.evil.test/enorme.gif">')
		self.assertEqual(payload['fetchedCount'], 0)
		self.assertIn('MB', html)

	def test_the_same_url_costs_one_request(self):
		# Cabeçalho e rodapé costumam trazer a mesma logomarca
		payload, html = self.fetched(
			'<img src="https://cdn.evil.test/logo.png">'
			'<img src="https://cdn.evil.test/logo.png">')
		self.assertEqual(len(self.requested), 1)
		self.assertEqual(html.count('data:image/gif;base64,'), 2)

	def test_the_number_of_images_is_capped(self):
		body = ''.join('<img src="https://cdn.evil.test/{0}.png">'.format(n)
			for n in range(email_render.MAX_REMOTE_IMAGES + 10))
		payload, html = self.fetched(body)
		self.assertEqual(len(self.requested), email_render.MAX_REMOTE_IMAGES)
		self.assertEqual(payload['fetchedCount'], email_render.MAX_REMOTE_IMAGES)

	def test_a_host_that_never_answers_becomes_a_placeholder(self):
		def explode(url, **kwargs):
			raise requests.exceptions.ConnectionError('sem rota')
		email_render.pinned_http.get = explode
		payload, html = self.fetched('<img src="https://cdn.evil.test/logo.png">')
		self.assertIn('bp-blocked', html)
		self.assertIn('não respondeu', html)
		self.assertEqual(payload['blockedCount'], 1)

	def test_the_round_of_fetches_has_a_wall_clock_budget(self):
		# Contagem e bytes limitam o *trabalho*; nenhum dos dois limita a *espera*.
		# Quarenta imagens contra um host que aceita a conexão e não responde são
		# quarenta timeouts de leitura em fila — minutos numa mensagem só, com o
		# semáforo da caixa na mão. Aconteceu: uma passada de pré-carregamento
		# ficou 49 segundos numa newsletter antiga antes deste teto existir.
		clock = [0.0]
		real_monotonic = email_render.time.monotonic
		email_render.time.monotonic = lambda: clock[0]
		try:
			def slow_get(url, **kwargs):
				clock[0] += 9.0     # cada host demora a responder
				return self.response
			email_render.pinned_http.get = slow_get

			body = ''.join('<img src="https://cdn.evil.test/{0}.png">'.format(n)
				for n in range(20))
			payload, html = self.fetched(body)
		finally:
			email_render.time.monotonic = real_monotonic

		# Para bem antes das vinte, e diz por quê no lugar das que faltaram
		self.assertLess(payload['fetchedCount'], 20)
		self.assertIn('tempo de busca esgotado', html)

	def test_the_read_timeout_shrinks_with_the_remaining_budget(self):
		# A última imagem de uma mensagem lenta não pode esperar os 8s inteiros
		# depois de o orçamento já ter sido quase todo gasto
		clock = [0.0]
		real_monotonic = email_render.time.monotonic
		email_render.time.monotonic = lambda: clock[0]
		try:
			def ticking_get(url, **kwargs):
				self.requested.append((url, kwargs))
				clock[0] += 6.0
				return self.response
			email_render.pinned_http.get = ticking_get
			# Quatro a 6s: as três primeiras ainda cabem nos 8s de leitura, a
			# quarta só tem 2s de orçamento restante
			self.fetched(''.join('<img src="https://cdn.evil.test/{0}.png">'.format(n)
				for n in range(4)))
		finally:
			email_render.time.monotonic = real_monotonic

		waits = [kwargs['timeout'][1] for _url, kwargs in self.requested]
		self.assertEqual(waits[0], email_render.REMOTE_IMAGE_TIMEOUT[1])
		self.assertLess(waits[-1], waits[0])

	def test_fetching_can_be_switched_off_entirely(self):
		email_render.render(message('<img src="https://cdn.evil.test/logo.png">'),
			fetch_remote = False)
		self.assertEqual(self.requested, [])
		self.assertEqual(self.validated, [])


if __name__ == '__main__':
	unittest.main()
