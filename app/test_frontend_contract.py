"""Contratos da interface que quebram em silêncio.

Três classes de erro que não produzem exceção, log nem teste vermelho — e por
isso precisam de um teste de texto sobre os arquivos.

**A CSP proíbe JavaScript embutido** (`BLUEPHISH_ARCHITECTURE.md` §7.4). Um
`onclick=` no template é bloqueado pelo navegador sem aviso: o botão
simplesmente não faz nada. Já aconteceu duas vezes aqui — uma delas mandou as
credenciais do login pela URL.

**Todo `data-click` precisa existir em `HANDLERS`.** O despacho é por nome, e um
nome que não está no mapa também não faz nada. Um controle novo com um erro de
digitação passa por revisão inteiro, porque o código está todo lá — só não está
ligado.

**O e-mail renderizado é conteúdo hostil.** A visualização "Como entregue" mostra
marcação escrita por quem enviou o phishing. O `iframe` que a exibe não pode
ganhar `allow-scripts` nem `allow-same-origin` — e a tentação de acrescentar um
deles é real, porque `allow-same-origin` deixaria a página medir a altura do
documento e trocar a rolagem interna por um enquadramento perfeito. O preço
seria dar a origem desta aplicação para a marcação do atacante.

Rodar com:  python -m unittest test_frontend_contract   (a partir de app/)
"""

import io
import os
import re
import unittest


BASE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(BASE, 'templates', 'index.html')
SCRIPT = os.path.join(BASE, 'static', 'assets', 'js', 'bluephish.js')


def read(path):
	with io.open(path, encoding='utf-8') as handle:
		return handle.read()


def without_comments(markup):
	return re.sub(r'<!--.*?-->', '', markup, flags = re.S)


class InlineJavaScriptIsForbidden(unittest.TestCase):
	"""script-src 'self': nada disso chega a executar."""

	def test_no_inline_event_handler_attributes(self):
		markup = without_comments(read(TEMPLATE))
		found = re.findall(r'\son[a-z]+\s*=\s*["\']', markup)
		self.assertEqual(found, [], 'atributo de evento embutido: {0}'.format(found))

	def test_no_inline_script_blocks(self):
		markup = without_comments(read(TEMPLATE))
		# <script src="..."> é o único formato permitido
		for tag in re.findall(r'<script\b[^>]*>', markup):
			self.assertIn('src=', tag, 'bloco <script> embutido: {0}'.format(tag))

	def test_no_javascript_urls(self):
		self.assertNotIn('javascript:', without_comments(read(TEMPLATE)))


class EveryDeclaredActionIsWired(unittest.TestCase):
	"""Um data-click sem entrada no mapa é um botão morto, sem erro nenhum."""

	def handler_names(self):
		script = read(SCRIPT)
		start = script.index('const HANDLERS = {')
		depth = 0
		for index in range(start, len(script)):
			if script[index] == '{':
				depth += 1
			elif script[index] == '}':
				depth -= 1
				if depth == 0:
					break
		body = script[start:index]
		return set(re.findall(r'^\s*([A-Za-z_][\w]*)\s*:', body, flags = re.M))

	def declared_actions(self):
		markup = without_comments(read(TEMPLATE))
		names = set()
		for attribute in ['data-click', 'data-change', 'data-input', 'data-enter']:
			names.update(re.findall(attribute + r'="([^"]+)"', markup))
		return names

	def test_every_action_in_the_template_has_a_handler(self):
		missing = sorted(self.declared_actions() - self.handler_names())
		self.assertEqual(missing, [], 'ação declarada sem handler: {0}'.format(missing))

	def test_every_info_tip_is_wired_and_named(self):
		# O "i" é o único caminho até o texto explicativo que saiu da tela. Um
		# botão sem handler, ou sem nome acessível, esconde esse texto de vez
		self.assertIn('toggle_info_tip', self.handler_names())
		markup = without_comments(read(TEMPLATE))
		buttons = re.findall(r'<button class="info-tip"[^>]*>', markup)
		self.assertEqual(len(buttons), 1, 'o botão do "i" deve existir só na macro info()')
		self.assertIn('aria-label="Mais informações"', buttons[0])
		self.assertIn('data-click="toggle_info_tip"', buttons[0])
		self.assertIn('"data-click": "toggle_info_tip"', read(SCRIPT))

	def test_the_new_inbox_actions_are_among_them(self):
		# Explícito porque estes quatro são o que este trabalho acrescentou, e um
		# teste genérico continuaria verde se o template e o mapa sumissem juntos
		handlers = self.handler_names()
		for name in ['filter_queue_debounced', 'clear_queue_query',
				'set_preview_mode', 'toggle_preview_frame']:
			self.assertIn(name, handlers)

	def test_the_inbox_pager_is_wired(self):
		# Four buttons, one handler: a typo in either the template or the map
		# leaves the queue stuck on page 1 with nothing in the console
		self.assertIn('go_inbox_page', self.handler_names())
		markup = without_comments(read(TEMPLATE))
		for where in ['first', 'prev', 'next', 'last']:
			self.assertIn('data-click="go_inbox_page" data-arg="{0}"'.format(where), markup)


class TheRenderedEmailStaysInert(unittest.TestCase):
	"""O iframe da visualização "Como entregue" segura marcação de um atacante."""

	def frame_tag(self):
		markup = read(TEMPLATE)
		match = re.search(r'<iframe\b[^>]*id="previewFrame"[^>]*>', markup)
		self.assertIsNotNone(match, 'o iframe da visualização não está no template')
		return match.group(0)

	def test_the_frame_is_sandboxed(self):
		self.assertIn('sandbox', self.frame_tag())

	def test_the_sandbox_grants_nothing(self):
		# `sandbox` sem valor é a restrição máxima. Qualquer allow- aqui devolve
		# ao documento hostil alguma das capacidades que este atributo tirou
		tag = self.frame_tag()
		self.assertNotIn('allow-scripts', tag)
		self.assertNotIn('allow-same-origin', tag)
		self.assertNotIn('allow-forms', tag)
		self.assertNotIn('allow-popups', tag)
		self.assertNotIn('allow-top-navigation', tag)
		self.assertNotIn('allow-modals', tag)

	def test_the_markup_is_assigned_as_a_property_not_an_attribute(self):
		# frame.srcdoc = ... é atribuição de propriedade. setAttribute('srcdoc')
		# seria escrever marcação de terceiro dentro de outra marcação
		script = read(SCRIPT)
		self.assertIn('frame.srcdoc =', script)
		self.assertNotIn("setAttribute(\"srcdoc\"", script)
		self.assertNotIn("setAttribute('srcdoc'", script)

	def test_the_text_view_is_the_default(self):
		# Abrir uma denúncia já dentro do layout escolhido pelo atacante é coisa
		# que se pede, não coisa em que se cai
		script = read(SCRIPT)
		self.assertIn('let preview_mode = "text";', script)
		markup = without_comments(read(TEMPLATE))
		modes = re.search(r'id="previewModes".*?</div>', markup, flags = re.S).group(0)
		first = re.search(r'data-arg="(\w+)"', modes).group(1)
		self.assertEqual(first, 'text')


if __name__ == '__main__':
	unittest.main()
