"""A entrada das rotas de análise (BP-SEC-07).

`flask.escape(None)` devolve o texto 'None'. POST /analysis sem mailUID abria uma
sessão IMAP procurando a mensagem "None" — gastando cota do provedor (§7.7.1) e
segurando o semáforo da caixa — e o erro aparecia como falha de análise, não
como requisição inválida. E, ao contrário de /email/<uid>, a rota aceitava
qualquer id da caixa, não só os da fila.

thephish_app não é importável fora da imagem (eventlet e libmagic), e nenhum
teste da suíte o importa. Então o que se prende aqui é o fonte; o comportamento
da rota é conferido com o app de verdade, dentro da imagem, na entrega.

Roda com:  python -m unittest test_analysis_input   (a partir do diretório app/)
"""

import io
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def source(name):
	with io.open(os.path.join(HERE, name), encoding = 'utf-8') as handle:
		return handle.read()


def function_body(text, name):
	match = re.search(r'\ndef {0}\(.*?(?=\n(?:@|def |# ))'.format(name), text, re.S)
	if match is None:
		raise AssertionError('{0} não encontrada'.format(name))
	return match.group(0)


class Entrada(unittest.TestCase):

	def assertBefore(self, body, first, then):
		self.assertIn(first, body)
		self.assertIn(then, body)
		self.assertLess(body.find(first), body.find(then))

	def test_nenhum_flask_escape_sobre_entrada(self):
		# escape é de saída HTML; sobre entrada ele só inventa o texto 'None' e
		# troca & por &amp; num id que vai para o IMAP. É também o que prendia o
		# Flask em 2.0.1 (removido no Flask 3)
		for name in os.listdir(HERE):
			if name.endswith('.py') and not name.startswith('test_'):
				self.assertNotRegex(source(name), r'flask\.escape\(', name)

	def test_analysis_recusa_uid_ausente_antes_de_ir_a_caixa(self):
		body = function_body(source('thephish_app.py'), 'analyze_email')
		self.assertBefore(body, 'if not mail_uid', 'case_from_email.main')
		self.assertIn('400', body[body.find('if not mail_uid'):body.find('case_from_email.main')])

	def test_analysis_so_aceita_uid_da_fila(self):
		body = function_body(source('thephish_app.py'), 'analyze_email')
		self.assertBefore(body, 'queued_mail_uids()', 'case_from_email.main')

	def test_lote_so_aceita_uid_da_fila(self):
		body = function_body(source('thephish_app.py'), 'analyze_selected_emails')
		self.assertBefore(body, 'not in queued', 'analyze_one_email(')


if __name__ == '__main__':
	unittest.main()
