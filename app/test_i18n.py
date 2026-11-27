"""Idioma da interface: português por padrão, inglês por botão (i18n.js).

O que estes testes seguram, e por que cada um falharia em silêncio:

* **Texto novo sem tradução.** O português é a fonte e o inglês é um dicionário.
  Um rótulo escrito num template e esquecido no dicionário não dá erro: aparece
  em português no meio de uma tela em inglês. O teste lê os dois templates e
  exige que todo texto em português esteja no dicionário.
* **Dicionário quebrado.** Uma vírgula a mais em i18n-en.js e o arquivo inteiro
  deixa de carregar — a tela fica em português sem avisar nada.
* **O botão sem o script.** Sem i18n.js carregado antes do script da página, o
  botão existe e não faz nada.
* **Formatação presa ao português.** Datas e números escritos com "pt-BR" fixo
  continuam em português com a interface em inglês.
* **A CSP.** O botão não pode virar `onclick=`, e `i18n.js` não pode usar eval.

Rodar com:  python -m unittest test_i18n   (a partir de app/)
"""

import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser


BASE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = [os.path.join(BASE, 'templates', name) for name in ('index.html', 'login.html')]
DICTIONARY = os.path.join(BASE, 'static', 'assets', 'js', 'i18n-en.js')
ENGINE = os.path.join(BASE, 'static', 'assets', 'js', 'i18n.js')
SCRIPT = os.path.join(BASE, 'static', 'assets', 'js', 'bluephish.js')

PREFIX = 'window.BLUEPHISH_I18N_EN = '
ATTRIBUTES = ('title', 'placeholder', 'aria-label', 'alt')
# Acento ou palavra que só existe em português: é o que separa "Salvar" de
# "GET / POST /scheduler", que são iguais nos dois idiomas
PORTUGUESE = re.compile(
	r'[áéíóúâêôãõçÁÉÍÓÚÂÊÔÃÕÇ]|\b(não|para|com|sem|ou|uma|nenhum|nenhuma|este|esta|caso|carregando|erro|'
	r'salvar|cancelar|enviar|buscar|limpar|todos|todas|clique|selecione|ainda|quando|foi|são)\b', re.I)


def read(path):
	with io.open(path, encoding = 'utf-8') as handle:
		return handle.read()


def load_dictionary():
	source = read(DICTIONARY)
	start = source.index(PREFIX) + len(PREFIX)
	return json.loads(source[start:].rstrip().rstrip(';'))


class TemplateStrings(HTMLParser):
	"""Os textos que uma pessoa lê num template, sem o que o Jinja monta."""

	def __init__(self):
		super().__init__(convert_charrefs = True)
		self.found = []
		self.skip = 0

	def handle_starttag(self, tag, attrs):
		if tag in ('script', 'style'):
			self.skip += 1
		for name, value in attrs:
			if name in ATTRIBUTES and value and '¤' not in value:
				self.found.append(re.sub(r'\s+', ' ', value).strip())

	def handle_endtag(self, tag):
		if tag in ('script', 'style'):
			self.skip -= 1

	def handle_data(self, data):
		if self.skip:
			return
		text = re.sub(r'\s+', ' ', data).strip()
		if text and '¤' not in text:
			self.found.append(text)


def template_strings(path):
	raw = read(path)
	raw = re.sub(r'\{#.*?#\}', ' ', raw, flags = re.S)
	raw = re.sub(r'\{%.*?%\}', '\n', raw, flags = re.S)
	raw = re.sub(r'\{\{.*?\}\}', '¤', raw, flags = re.S)
	parser = TemplateStrings()
	parser.feed(raw)
	return parser.found


class Dictionary(unittest.TestCase):
	def test_the_file_is_valid_json_with_the_three_sections(self):
		data = load_dictionary()
		for section in ('exact', 'patterns', 'after'):
			self.assertIn(section, data)
		self.assertGreater(len(data['exact']), 1000)

	def test_no_entry_is_empty_or_a_no_op(self):
		for key, value in load_dictionary()['exact'].items():
			self.assertTrue(key.strip(), 'chave vazia')
			self.assertTrue(value.strip(), 'tradução vazia para {0!r}'.format(key))
			self.assertNotEqual(key, value, 'entrada que não traduz: {0!r}'.format(key))

	def test_keys_are_normalized_the_way_the_engine_looks_them_up(self):
		# O motor normaliza espaços antes de procurar; uma chave com espaço duplo
		# ou nas pontas nunca seria encontrada
		for key in load_dictionary()['exact']:
			self.assertEqual(key, re.sub(r'\s+', ' ', key).strip(), repr(key))

	def test_regex_rules_compile(self):
		data = load_dictionary()
		for pattern, _replacement in data['patterns'] + data['after']:
			re.compile(pattern)


class Coverage(unittest.TestCase):
	@staticmethod
	def is_example(text):
		# Endereço, URL ou host de exemplo num placeholder: "empresa.com.br" tem um
		# "com" que não é a palavra, e traduzi-lo seria inventar um domínio
		return ' ' not in text and any(mark in text for mark in ('@', '/', '.'))

	def test_every_portuguese_text_in_the_templates_is_translated(self):
		known = load_dictionary()['exact']
		missing = []
		for path in TEMPLATES:
			for text in template_strings(path):
				if self.is_example(text):
					continue
				if PORTUGUESE.search(text) and text not in known:
					missing.append((os.path.basename(path), text))
		self.assertEqual(missing, [], 'textos sem tradução em inglês: {0}'.format(missing[:8]))


class Wiring(unittest.TestCase):
	def test_both_pages_load_the_dictionary_and_engine_before_their_own_script(self):
		for path, own in zip(TEMPLATES, ('bluephish.js', 'login.js')):
			markup = read(path)
			dictionary = markup.index('assets/js/i18n-en.js')
			engine = markup.index('assets/js/i18n.js')
			page = markup.index('assets/js/' + own)
			self.assertLess(dictionary, engine)
			self.assertLess(engine, page)

	def test_both_pages_have_the_language_button_without_inline_handlers(self):
		for path in TEMPLATES:
			markup = read(path)
			button = re.search(r'<button[^>]*data-lang-toggle[^>]*>', markup).group(0)
			# data-click exigiria um handler em bluephish.js, que pode nem ter carregado
			self.assertNotIn('data-click', button)
			self.assertNotIn('onclick', button)
			# O texto do botão já nasce no idioma de destino: o tradutor não o toca
			self.assertIn('data-i18n-skip', button)

	def test_portuguese_is_the_default_markup_language(self):
		for path in TEMPLATES:
			self.assertIn('lang="pt-BR"', read(path))

	def test_the_engine_does_not_run_text_as_code(self):
		engine = read(ENGINE)
		for forbidden in ('eval(', 'new Function', 'innerHTML', 'document.write'):
			self.assertNotIn(forbidden, engine)

	def test_the_engine_skips_code_but_not_placeholders_and_options(self):
		# Placeholder e <option> são texto de interface; só o que é código ou o que
		# a pessoa digitou fica de fora. Pular INPUT/SELECT inteiros deixava
		# "Buscar remetente…" e "Sucesso/Falha" em português com o dicionário completo
		engine = read(ENGINE)
		for tag in ('SCRIPT', 'STYLE', 'TEXTAREA'):
			self.assertIn(tag + ': 1', engine)
		for tag in ('INPUT', 'SELECT', 'OPTION'):
			self.assertNotIn(tag + ': 1', engine)

	def test_dates_and_numbers_follow_the_interface_language(self):
		script = read(SCRIPT)
		self.assertNotRegex(script, r'toLocale(?:Date|Time)?String\("pt-BR"')
		self.assertNotIn('"pt-BR")', script)


ENGINE_PROBE = r"""
const fs = require("fs");
const dir = process.argv[2];
const store = {"bluephish.lang": "en"};
global.window = global;
global.localStorage = {getItem: k => store[k] || null, setItem: (k, v) => { store[k] = v; }};
global.navigator = {language: "pt-BR"};
global.CustomEvent = class { constructor(n, o){ this.type = n; this.detail = o && o.detail; } };
global.document = {readyState: "complete", title: "", documentElement: {setAttribute(){}}, body: null,
	addEventListener(){}, querySelectorAll(){ return []; }, dispatchEvent(){} };
eval(fs.readFileSync(dir + "/i18n-en.js", "utf8"));
eval(fs.readFileSync(dir + "/i18n.js", "utf8"));
const t = window.t;
const started = Date.now();
const long = ("Fatura em aberto - Confirmar pagamento urgente " ).repeat(60);
const slow = t(long);
const elapsed = Date.now() - started;
console.log(JSON.stringify({
	exact: t("Salvar"),
	edges: t("  Reanalisar  "),
	fragments: t("60 de 120 caso(s)"),
	known_fragments_only: t("Pelo menos 3 e-mails da fila tiverem"),
	subject_with_known_word: t("Fatura em aberto - Confirmar pagamento"),
	unknown: t("Texto totalmente desconhecido xyz"),
	long_untouched: slow === long,
	elapsed: elapsed
}));
"""


class EngineBehaviour(unittest.TestCase):
	"""O motor rodando de verdade, num DOM mínimo, quando há Node disponível."""

	@classmethod
	def setUpClass(cls):
		node = shutil.which('node')
		if not node:
			raise unittest.SkipTest('node não está instalado')
		scripts = os.path.dirname(DICTIONARY)
		with tempfile.NamedTemporaryFile('w', suffix = '.js', delete = False, encoding = 'utf-8') as handle:
			handle.write(ENGINE_PROBE)
		try:
			out = subprocess.run([node, handle.name, scripts], capture_output = True, text = True, timeout = 30)
		finally:
			os.unlink(handle.name)
		if out.returncode != 0:
			raise AssertionError(out.stderr)
		cls.result = json.loads(out.stdout.strip().splitlines()[-1])

	def test_exact_text_is_translated_and_edges_are_kept(self):
		self.assertEqual(self.result['exact'], 'Save')
		self.assertEqual(self.result['edges'], '  Reanalyze  ')

	def test_a_message_made_only_of_known_fragments_is_translated(self):
		self.assertEqual(self.result['fragments'], '60 of 120 case(s)')
		self.assertEqual(self.result['known_fragments_only'], 'At least 3 emails in the queue have')

	def test_text_that_merely_contains_a_known_word_is_left_alone(self):
		# Assunto de e-mail é evidência: "Confirmar" dentro dele não pode virar
		# "Confirm", ou a analista lê uma mensagem que o remetente não escreveu
		self.assertEqual(self.result['subject_with_known_word'], 'Fatura em aberto - Confirmar pagamento')
		self.assertEqual(self.result['unknown'], 'Texto totalmente desconhecido xyz')

	def test_a_long_untranslatable_text_costs_almost_nothing(self):
		self.assertTrue(self.result['long_untouched'])
		self.assertLess(self.result['elapsed'], 100)


if __name__ == '__main__':
	unittest.main()
