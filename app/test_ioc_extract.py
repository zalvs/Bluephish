"""Um e-mail hostil não para o servidor nem esconde indicador.

Motivado por uma medição de 2026-11-23: 2 KB de `a.a.a.` no corpo prenderam o
`ioc_finder` por 5,8 s no mesmo loop que atende a interface e lê a caixa, e o
tempo quadruplica cada vez que o texto dobra. Quem escreve esse texto é quem
mandou o phishing.

A correção não pode ser cortar o texto: lixo antes da URL maliciosa viraria um
jeito de escondê-la. Por isso metade destes testes prova o contrário do que o
nome do módulo sugere: o que é indicador continua saindo.

Rodar com:  python -m unittest test_ioc_extract   (a partir de app/)
"""

import json
import os
import subprocess
import sys
import time
import unittest

import ioc_finder

import ioc_extract
import ioc_noise


# [prefixo, unidade]: a unidade, repetida até 64 KB, levava minutos ou horas no
# extrator cru. Os com prefixo são um token só que começa como indicador
HOSTILE_SHAPES = [
	['', 'a.'], ['', 'a-'], ['', 'a_'], ['', 'a+'], ['', 'a/'], ['', 'a%'], ['', 'a..'],
	['', 'a.b-'], ['', '1.'], ['', 'a@'], ['', 'http://'], ['', 'http://a.'],
	['http://', 'a.'], ['http://a.b/', 'x/'], ['x@', 'a.'], ['evil.com', '-'],
]
HOSTILE_CHARS = 64 * 1024
# Folgado de propósito: o CI é mais lento que uma máquina de trabalho, e o defeito
# que este teste pega custa horas, não segundos
HOSTILE_LIMIT_SECONDS = 120

# Em processo separado porque uma regressão aqui não falha: ela não termina
HOSTILE_PROBE = """
import json, sys, time
import ioc_extract
for prefix, unit in json.loads(sys.argv[1]):
	text = prefix + unit * (int(sys.argv[2]) // len(unit))
	started = time.perf_counter()
	ioc_extract.extract(text)
	print(json.dumps([prefix + unit, round(time.perf_counter() - started, 2)]), flush = True)
"""

REALISTIC = ' '.join([
	'Prezado cliente, sua conta foi bloqueada.',
	'Acesse https://portal-seguro.example.com/login?id=42 ainda hoje',
	'ou fale com suporte@atendimento.example.org.',
	'Servidor de origem 203.0.113.9, espelho em golpe-exemplo.com.',
	'<a href="http://outro.example.net/a/b.php?x=1&y=2">clique</a>',
]) + ' '


def by_library(text):
	return {
		'urls': set(ioc_finder.parse_urls(text, parse_urls_without_scheme = False)),
		'email_addresses': set(ioc_finder.parse_email_addresses(text)),
		'ipv4s': set(ioc_finder.parse_ipv4_addresses(text)),
		'domains': set(ioc_finder.parse_domain_names(text)),
	}


def by_module(text):
	found = ioc_extract.extract(text)
	return {
		'urls': set(found.urls),
		'email_addresses': set(found.email_addresses),
		'ipv4s': set(found.ipv4s),
		'domains': set(found.domains),
	}


class HostileTextHasABoundedCost(unittest.TestCase):

	def test_no_hostile_shape_takes_long(self):
		here = os.path.dirname(os.path.abspath(__file__))
		try:
			done = subprocess.run(
				[sys.executable, '-c', HOSTILE_PROBE, json.dumps(HOSTILE_SHAPES), str(HOSTILE_CHARS)],
				cwd = here, capture_output = True, text = True, timeout = HOSTILE_LIMIT_SECONDS)
		except Exception as error:
			# Com o eventlet carregado por outro teste, a classe não é a de `subprocess`
			if type(error).__name__ != 'TimeoutExpired':
				raise
			self.fail('Texto hostil de 64 KB não terminou em {0} s. Concluídos: {1}'.format(
				HOSTILE_LIMIT_SECONDS, error.stdout))
		self.assertEqual(done.returncode, 0, done.stderr)
		finished = {json.loads(line)[0] for line in done.stdout.splitlines()}
		self.assertEqual(finished, {prefix + unit for prefix, unit in HOSTILE_SHAPES})

	def test_the_app_store_filter_does_not_rescan_a_hostile_link(self):
		text = 'play.google.com/store/apps/details?' * 6000
		started = time.perf_counter()
		ioc_noise.app_package_ids(text)
		self.assertLess(time.perf_counter() - started, 5)


class IndicatorsSurviveTheLimit(unittest.TestCase):

	def test_junk_before_the_indicators_does_not_hide_them(self):
		text = 'a.' * 20000 + ' https://golpe-exemplo.com/login vitima@golpe-exemplo.com 203.0.113.9'
		found = ioc_extract.extract(text)
		self.assertIn('https://golpe-exemplo.com/login', found.urls)
		self.assertIn('vitima@golpe-exemplo.com', found.email_addresses)
		self.assertIn('203.0.113.9', found.ipv4s)
		self.assertIn('golpe-exemplo.com', found.domains)
		self.assertTrue(found.complete)

	def test_a_domain_glued_to_the_end_of_the_junk_is_kept(self):
		found = ioc_extract.extract('a.' * 5000 + 'golpe-exemplo.com')
		self.assertTrue(any(domain.endswith('golpe-exemplo.com') for domain in found.domains), found.domains)
		self.assertTrue(all(len(domain) <= ioc_extract.MAX_HOSTNAME_CHARS for domain in found.domains))

	def test_a_domain_in_the_middle_of_the_junk_is_kept(self):
		found = ioc_extract.extract('a.' * 3000 + '.golpe-exemplo.com..' + 'b.' * 3000)
		self.assertIn('golpe-exemplo.com', found.domains)

	def test_an_address_inside_a_long_token_is_kept(self):
		found = ioc_extract.extract('a/' * 3000 + 'vitima@golpe-exemplo.com' + '/b' * 3000)
		self.assertIn('vitima@golpe-exemplo.com', found.email_addresses)

	def test_an_address_at_the_end_of_a_chain_of_at_signs_is_kept(self):
		found = ioc_extract.extract('x@' * 400 + 'vitima@golpe-exemplo.com')
		self.assertIn('vitima@golpe-exemplo.com', found.email_addresses)

	def test_a_line_of_hyphens_after_a_domain_does_not_hide_it(self):
		for separator in ('-' * 300, '_' * 300, '-a' * 200, '.' + '-' * 300):
			found = ioc_extract.extract('golpe-exemplo.com' + separator)
			self.assertIn('golpe-exemplo.com', found.domains, separator[:4])

	def test_a_line_of_hyphens_after_an_address_does_not_hide_it(self):
		for separator in ('-' * 300, '-a' * 200):
			found = ioc_extract.extract('vitima@golpe-exemplo.com' + separator)
			self.assertIn('vitima@golpe-exemplo.com', found.email_addresses, separator[:4])

	def test_a_domain_after_an_oversized_label_is_kept(self):
		found = ioc_extract.extract('x-' * 200 + 'golpe-exemplo.com')
		self.assertTrue(any(domain.endswith('golpe-exemplo.com') for domain in found.domains), found.domains)

	def test_no_address_is_invented_from_the_middle_of_a_long_label(self):
		found = ioc_extract.extract('x@' + 'a-' * 200 + 'golpe-exemplo.com')
		self.assertEqual(found.email_addresses, [])

	def test_a_url_glued_inside_a_huge_token_is_kept(self):
		found = ioc_extract.extract('a.' * 6000 + 'https://golpe-exemplo.com/login' + '/b' * 3000)
		self.assertTrue(any(url.startswith('https://golpe-exemplo.com/login') for url in found.urls), found.urls)

	def test_a_second_url_in_a_huge_token_is_found(self):
		text = 'https://um-exemplo.com/?u=' + 'x' * 9000 + '"https://golpe-exemplo.com/z'
		found = ioc_extract.extract(text)
		self.assertTrue(any(url.startswith('https://um-exemplo.com/') for url in found.urls), found.urls)
		self.assertIn('https://golpe-exemplo.com/z', found.urls)

	def test_a_url_below_the_limit_keeps_its_whole_value(self):
		url = 'https://golpe-exemplo.com/' + 'a/' * 3500 + 'fim'
		self.assertLess(len(url), ioc_extract.MAX_URL_TOKEN_CHARS)
		self.assertEqual(ioc_extract.extract(url).urls, [url])

	def test_an_ip_inside_a_long_token_is_kept(self):
		found = ioc_extract.extract('a/' * 200 + '203.0.113.9' + '/b' * 200)
		self.assertIn('203.0.113.9', found.ipv4s)

	def test_no_ip_is_invented_from_a_long_run_of_numbers(self):
		self.assertEqual(ioc_extract.extract('1.' * 400 + '1').ipv4s, [])

	def test_an_ordinary_message_extracts_exactly_what_the_library_does(self):
		self.assertEqual(by_module(REALISTIC), by_library(REALISTIC))

	def test_a_message_longer_than_a_chunk_loses_nothing_at_the_seams(self):
		text = REALISTIC * (2 * ioc_extract.CHUNK_CHARS // len(REALISTIC) + 1)
		text += 'https://ultimo.example.com/fim final@ultimo.example.org'
		self.assertGreater(len(text), ioc_extract.CHUNK_CHARS)
		self.assertEqual(by_module(text), by_library(text))

	def test_a_long_tracking_link_extracts_exactly_what_the_library_does(self):
		text = ('Veja https://click.example.com/track/' + 'Ab3-' * 150
			+ '/?u=https%3A%2F%2Fgolpe-exemplo.com&to=vitima@golpe-exemplo.com fim')
		self.assertEqual(by_module(text), by_library(text))

	def test_an_app_store_id_is_still_told_apart(self):
		text = 'https://play.google.com/store/apps/details?id=com.linkedin.android '
		found = ioc_extract.extract(text)
		self.assertIn('com.linkedin.android', found.package_only)


class TheBudgetIsReported(unittest.TestCase):

	def test_an_expired_budget_is_not_a_complete_extraction(self):
		found = ioc_extract.extract(REALISTIC, deadline = time.monotonic() - 1)
		self.assertFalse(found.complete)

	def test_a_budget_with_time_left_is_complete(self):
		found = ioc_extract.extract(REALISTIC, deadline = time.monotonic() + 60)
		self.assertTrue(found.complete)

	def test_empty_text_is_complete_and_empty(self):
		found = ioc_extract.extract('')
		self.assertTrue(found.complete)
		self.assertEqual(found.urls, [])


class ThePipelineUsesIt(unittest.TestCase):
	"""`case_from_email` não importa fora da imagem no Windows: a prova é no fonte."""

	@classmethod
	def setUpClass(cls):
		here = os.path.dirname(os.path.abspath(__file__))
		with open(os.path.join(here, 'case_from_email.py'), encoding = 'utf-8') as source:
			cls.source = source.read()

	def test_nothing_calls_the_extractor_on_the_server_loop(self):
		self.assertNotIn('ioc_finder.parse_', self.source)
		self.assertIn('run_off_hub(ioc_extract.extract', self.source)

	def test_the_html_is_read_off_the_server_loop(self):
		self.assertNotIn("html_text_parts.append(bs4.BeautifulSoup", self.source)

	def test_the_header_loop_is_a_single_pass(self):
		self.assertNotIn('header_fields.keys()[', self.source)
		self.assertNotIn('header_fields.values()[', self.source)

	def test_the_message_has_one_budget(self):
		self.assertEqual(self.source.count('time.monotonic() + EXTRACTION_BUDGET_SECONDS'), 1)


if __name__ == '__main__':
	unittest.main()
