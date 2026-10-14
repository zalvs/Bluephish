"""Testes de estrutura dos templates HTML.

Existem por causa de uma falha real: um `</div>` a mais em `index.html` deixou a
aplicação inteira em branco. O navegador não reclama — ele fecha o que dá,
reaninha o resto e entrega uma página vazia. Nenhum erro de JavaScript, nenhum
log, nenhum teste vermelho. Só a tela branca.

A causa foi uma edição por fatiamento de índice: `text.index('\\t</div>\\n')`
casou **dentro** de `\\t\\t</div>\\n`, porque um é sufixo do outro. O fechamento
duplicado sobrou, fechou `<div class="app">` cedo demais, e tudo que vinha
depois — barra lateral, painéis, telas — foi parar fora do contêiner que carrega
o layout.

Este arquivo é o guarda-corpo dessa classe de erro. Ele não valida HTML inteiro;
valida o que quebra em silêncio quando alguém (pessoa ou agente) edita o
template com substituição de texto.

Rodar com:  python -m unittest test_templates   (a partir de app/)
"""

import io
import os
import re
import unittest


TEMPLATES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# Elementos que não têm fechamento em HTML
VOID = {
	'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
	'link', 'meta', 'param', 'source', 'track', 'wbr',
}

TAG = re.compile(r'<(/?)([a-zA-Z][a-zA-Z0-9]*)\b[^>]*?(/?)>')


def read_markup(name):
	"""O template sem comentários e sem o miolo dos SVG.

	Comentário pode conter marcação de exemplo, e SVG tem o próprio vocabulário
	de tags: nenhum dos dois participa do aninhamento que interessa aqui.
	"""
	with io.open(os.path.join(TEMPLATES, name), encoding='utf-8') as handle:
		markup = handle.read()
	markup = re.sub(r'<!--.*?-->', '', markup, flags = re.S)
	markup = re.sub(r'<svg\b.*?</svg>', '<span></span>', markup, flags = re.S)
	return markup


def imbalances(markup):
	"""Devolve a lista de problemas de aninhamento, em ordem de aparição."""
	stack = []
	problems = []
	for match in TAG.finditer(markup):
		closing, tag, self_closing = match.group(1), match.group(2).lower(), match.group(3)
		if tag in VOID or self_closing:
			continue
		line = markup[:match.start()].count('\n') + 1
		if not closing:
			stack.append((tag, line))
			continue
		if not stack:
			problems.append('linha {0}: </{1}> sem abertura'.format(line, tag))
			continue
		if stack[-1][0] != tag:
			problems.append('linha {0}: </{1}> fecha, mas o aberto é <{2}> da linha {3}'.format(
				line, tag, stack[-1][0], stack[-1][1]))
			for index in range(len(stack) - 1, -1, -1):
				if stack[index][0] == tag:
					stack = stack[:index]
					break
		else:
			stack.pop()
	for tag, line in stack:
		problems.append('linha {0}: <{1}> aberta e nunca fechada'.format(line, tag))
	return problems


class Nesting(unittest.TestCase):

	def test_every_template_is_balanced(self):
		for name in ('index.html', 'login.html'):
			problems = imbalances(read_markup(name))
			self.assertEqual(problems, [], '{0}: {1}'.format(name, ' | '.join(problems)))

	def test_the_div_count_matches(self):
		# Uma checagem grosseira que pega o caso comum — sobra ou falta de um
		# fechamento — mesmo quando o aninhamento se recupera por acidente
		for name in ('index.html', 'login.html'):
			markup = read_markup(name)
			opened = len(re.findall(r'<div\b', markup))
			closed = len(re.findall(r'</div>', markup))
			self.assertEqual(opened, closed,
				'{0}: {1} <div> para {2} </div>'.format(name, opened, closed))


class Landmarks(unittest.TestCase):
	"""O que a navegação assistiva precisa achar, e onde a aplicação vive."""

	def setUp(self):
		self.markup = read_markup('index.html')

	def test_the_content_lives_inside_the_app_container(self):
		# `.app` carrega o layout: se <main> escapar dele, a tela renderiza em
		# branco mesmo com todo o conteúdo presente no documento
		app = self.markup.index('<div class="app">')
		main_open = self.markup.index('<main')
		main_close = self.markup.index('</main>')
		self.assertLess(app, main_open, '<main> precisa abrir depois de <div class="app">')
		self.assertLess(main_close, self.markup.index('</div>', main_close),
			'</main> precisa fechar antes do </div> do contêiner')

	def test_there_is_exactly_one_main_and_one_h1(self):
		self.assertEqual(self.markup.count('<main'), 1)
		self.assertEqual(self.markup.count('</main>'), 1)
		self.assertEqual(len(re.findall(r'<h1\b', self.markup)), 1)

	def test_the_skip_link_points_at_the_main_landmark(self):
		self.assertIn('class="skip-link" href="#conteudo"', self.markup)
		self.assertIn('id="conteudo"', self.markup)

	def test_there_is_a_live_region_for_what_happens_off_focus(self):
		self.assertIn('aria-live', self.markup)

	def test_the_document_declares_its_language(self):
		self.assertIn('lang="pt-BR"', self.markup)


if __name__ == '__main__':
	unittest.main()
