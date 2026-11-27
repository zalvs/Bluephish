"""A Content-Security-Policy fecha o que `default-src` não cobre (`BLUEPHISH_ARCHITECTURE.md` §4.5).

`default-src 'self'` não vale para quatro coisas, e as quatro falham em silêncio —
não há erro, log nem teste vermelho quando faltam:

**`frame-ancestors`.** Quem impede a página de ser embutida em outro site. Hoje só
o `X-Frame-Options: DENY` faz isso, e ele é o cabeçalho legado: o navegador dá
preferência à CSP quando as duas existem.

**`base-uri`.** Um `<base href>` injetado muda para onde apontam todos os caminhos
relativos da página — inclusive o do `<script src>` e o do `action` do login.

**`object-src`.** `<object>`/`<embed>` herdam `default-src`, mas o plugin que carregam
não segue a regra; `'none'` fecha a porta de vez.

**`form-action`.** Um formulário injetado que posta para fora leva o que o analista
digitar. O login é o único formulário e só posta para a própria origem; o SSO é um
link (GET), não um formulário, então `'self'` não o atrapalha.

Roda com:  python -m unittest test_security_headers   (a partir do diretório app/)
"""

import glob
import io
import os
import re
import unittest

import security_headers

BASE = os.path.dirname(os.path.abspath(__file__))


def read(path):
	with io.open(path, encoding = 'utf-8') as handle:
		return handle.read()


def directives(policy):
	"""A política como {diretiva: [fontes]}."""
	parsed = {}
	for part in policy.split(';'):
		tokens = part.split()
		if tokens:
			parsed[tokens[0]] = tokens[1:]
	return parsed


class ThePolicyClosesWhatDefaultSrcDoesNotCover(unittest.TestCase):

	def setUp(self):
		self.policy = directives(security_headers.CONTENT_SECURITY_POLICY)

	def test_the_page_cannot_be_framed(self):
		self.assertEqual(self.policy.get('frame-ancestors'), ["'none'"])

	def test_a_base_tag_cannot_repoint_relative_urls(self):
		self.assertEqual(self.policy.get('base-uri'), ["'self'"])

	def test_plugins_are_closed(self):
		self.assertEqual(self.policy.get('object-src'), ["'none'"])

	def test_forms_only_post_to_this_origin(self):
		self.assertEqual(self.policy.get('form-action'), ["'self'"])

	def test_inline_javascript_stays_forbidden(self):
		# O contrato do §7.4: nada de 'unsafe-inline' em script-src
		self.assertNotIn("'unsafe-inline'", self.policy.get('script-src', []))
		self.assertEqual(self.policy.get('default-src'), ["'self'"])

	def test_inline_styles_are_forbidden_too(self):
		# Sem 'unsafe-inline' em style-src, nenhum style="" vale; é o que tira o
		# aviso dos avaliadores de cabeçalho (A+)
		self.assertNotIn("'unsafe-inline'", self.policy.get('style-src', []))
		self.assertNotIn("'unsafe-eval'", ' '.join(sum(self.policy.values(), [])))

	def test_the_sources_the_pages_already_use_are_kept(self):
		self.assertIn('https://cdnjs.cloudflare.com', self.policy['script-src'])
		self.assertIn('https://fonts.googleapis.com', self.policy['style-src'])
		self.assertIn('https://fonts.gstatic.com', self.policy['font-src'])
		self.assertEqual(self.policy['connect-src'], ["'self'"])


class TheAppSendsThatPolicyAndTheTemplatesRespectIt(unittest.TestCase):

	def test_the_after_request_hook_sends_the_shared_constant(self):
		source = read(os.path.join(BASE, 'thephish_app.py'))
		self.assertRegex(source, r"setdefault\('Content-Security-Policy',\s*security_headers\.CONTENT_SECURITY_POLICY\)")

	def test_no_template_declares_a_base_tag(self):
		for path in glob.glob(os.path.join(BASE, 'templates', '*.html')):
			self.assertIsNone(re.search(r'<base[\s>]', read(path), re.I), path)

	def test_no_template_has_inline_style(self):
		# style-src sem 'unsafe-inline': um style="" ou <style> seria ignorado pelo
		# navegador sem erro nenhum, e o layout quebraria em silêncio. Use uma classe u-*
		for path in glob.glob(os.path.join(BASE, 'templates', '*.html')):
			text = read(path)
			self.assertIsNone(re.search(r'\sstyle\s*=', text, re.I), path)
			self.assertIsNone(re.search(r'<style[\s>]', text, re.I), path)

	def test_the_scripts_do_not_set_the_style_attribute(self):
		# setAttribute("style") é recusado pela CSP; node.style.cssText (CSSOM) não
		for path in glob.glob(os.path.join(BASE, 'static', 'assets', 'js', '*.js')):
			text = read(path)
			self.assertIsNone(re.search(r'setAttribute\(\s*["\']style["\']', text), path)
			self.assertIsNone(re.search(r'\sstyle\s*=\s*\\?["\']', text), path)

	def test_every_utility_class_used_in_the_templates_exists(self):
		css = read(os.path.join(BASE, 'static', 'assets', 'css', 'bluephish.css'))
		defined = set(re.findall(r'^\.(u-[\w-]+)\s*\{', css, re.M))
		for path in glob.glob(os.path.join(BASE, 'templates', '*.html')):
			for name in set(re.findall(r'\b(u-[a-z0-9][\w-]*)', read(path))):
				self.assertIn(name, defined, '{0}: {1}'.format(path, name))

	def test_every_form_posts_to_a_path_on_this_origin(self):
		# Com form-action 'self', um action absoluto seria bloqueado sem aviso
		for path in glob.glob(os.path.join(BASE, 'templates', '*.html')):
			for action in re.findall(r'<form\b[^>]*\baction="([^"]*)"', read(path), re.I):
				self.assertTrue(action.startswith('/') and not action.startswith('//'), '{0}: {1}'.format(path, action))


if __name__ == '__main__':
	unittest.main()
