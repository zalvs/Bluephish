"""O que a varredura de cabeçalhos de massa pode e não pode afirmar.

O erro que este arquivo existe para impedir é um só, e ele é silencioso: tratar
`List-Unsubscribe` como prova de que a mensagem é inofensiva. Todo cabeçalho
lido aqui foi escrito por quem enviou, e escrever `List-Unsubscribe` numa
campanha de phishing custa uma linha. Por isso a varredura devolve sinal, e a
decisão de rotular como spam mora em `scoring.py`, onde a autenticação do
remetente — que o remetente não escreve — é condição.

Rodar com:  python -m unittest test_spam_headers   (a partir de app/)
"""

import unittest

import spam_headers


class VarreduraEncontraOsMarcadores(unittest.TestCase):

	def test_sem_cabecalho_nenhum_o_sinal_e_zero(self):
		result = spam_headers.scan({})
		self.assertEqual(result['value'], 0.0)
		self.assertEqual(result['markers'], [])
		self.assertFalse(result['bulk'])

	def test_one_click_da_rfc_8058_e_reconhecido(self):
		result = spam_headers.scan({
			'List-Unsubscribe': '<https://esp.example/u/abc>',
			'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
		})
		ids = [marker['id'] for marker in result['markers']]
		self.assertIn('list_unsubscribe_post', ids)
		self.assertIn('list_unsubscribe', ids)
		self.assertTrue(result['oneClick'])
		self.assertTrue(result['bulk'])

	def test_list_unsubscribe_post_sem_one_click_nao_conta(self):
		# O cabeçalho existe mas não declara o único valor que a RFC define; ele
		# não prova infraestrutura de baixa nenhuma
		result = spam_headers.scan({'List-Unsubscribe-Post': 'algo=outra-coisa'})
		self.assertEqual([m['id'] for m in result['markers']], [])
		self.assertFalse(result['oneClick'])

	def test_precedence_so_conta_quando_e_bulk(self):
		self.assertEqual(spam_headers.scan({'Precedence': 'bulk'})['markers'][0]['id'],
			'precedence_bulk')
		self.assertEqual(spam_headers.scan({'Precedence': 'first-class'})['markers'], [])

	def test_rfc_3098_autoetiquetagem_de_publicidade(self):
		por_cabecalho = spam_headers.scan({'X-Advertisement': 'yes'})
		self.assertEqual([m['id'] for m in por_cabecalho['markers']], ['advertisement_header'])
		self.assertEqual(por_cabecalho['markers'][0]['rfc'], 'RFC 3098')

		por_assunto = spam_headers.scan({}, subject = 'ADV: promoção de inverno')
		self.assertEqual([m['id'] for m in por_assunto['markers']], ['subject_adv'])

	def test_assunto_que_apenas_comeca_com_adv_nao_casa(self):
		# "Advogado" começa com as três letras e não é publicidade autoetiquetada:
		# a RFC pede o prefixo seguido de separador
		self.assertEqual(spam_headers.scan({}, subject = 'Advogado enviou o contrato')['markers'], [])

	def test_o_sinal_satura_em_um(self):
		result = spam_headers.scan({
			'List-Unsubscribe': '<https://esp.example/u>',
			'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
			'List-Id': '<news.example.com>',
			'List-Help': '<mailto:help@example.com>',
			'Precedence': 'bulk',
			'X-Advertisement': 'yes',
			'Feedback-ID': '1:2:3:esp'
		})
		self.assertEqual(result['value'], 1.0)

	def test_um_marcador_repetido_conta_uma_vez(self):
		# Uma mensagem pode trazer o mesmo cabeçalho duas vezes; é o mesmo fato
		result = spam_headers.scan([
			('List-Unsubscribe', '<https://a.example/u>'),
			('List-Unsubscribe', '<mailto:u@a.example>')
		])
		self.assertEqual(len(result['markers']), 1)


class VereditoDeQuemRecebeu(unittest.TestCase):

	def test_spam_flag_marca_filtered(self):
		result = spam_headers.scan({'X-Spam-Flag': 'YES'})
		self.assertTrue(result['filtered'])
		# É veredito do servidor de entrada, não gramática de lista: não é `bulk`
		self.assertFalse(result['bulk'])

	def test_scl_abaixo_do_limiar_nao_diz_nada(self):
		baixo = spam_headers.scan({'X-Forefront-Antispam-Report': 'CIP:1.2.3.4;SCL:1;CTRY:BR'})
		self.assertEqual(baixo['markers'], [])
		self.assertEqual(baixo['scl'], 1)

		alto = spam_headers.scan({'X-Forefront-Antispam-Report': 'CIP:1.2.3.4;SCL:6;CTRY:BR'})
		self.assertEqual([m['id'] for m in alto['markers']], ['scl'])
		self.assertTrue(alto['filtered'])

	def test_bcl_alto_indica_massa(self):
		result = spam_headers.scan({'X-Microsoft-Antispam': 'BCL:7;'})
		self.assertEqual([m['id'] for m in result['markers']], ['bcl'])
		self.assertEqual(result['bcl'], 7)


class EntradaHostilNaoDerrubaAVarredura(unittest.TestCase):
	"""Cabeçalho malformado é rotina em phishing, e não pode virar exceção."""

	def test_none_e_lista_vazia(self):
		self.assertEqual(spam_headers.scan(None)['value'], 0.0)
		self.assertEqual(spam_headers.scan([])['value'], 0.0)

	def test_valores_que_nao_sao_texto(self):
		result = spam_headers.scan([('List-Unsubscribe', 12345), ('X-Coisa', None)])
		self.assertEqual([m['id'] for m in result['markers']], ['list_unsubscribe'])

	def test_pares_malformados_sao_ignorados(self):
		result = spam_headers.scan(['nao-e-um-par', ('Precedence', 'bulk')])
		self.assertEqual([m['id'] for m in result['markers']], ['precedence_bulk'])

	def test_mensagem_de_email_de_verdade(self):
		import email
		msg = email.message_from_string(
			'From: news@example.com\r\n'
			'Subject: Novidades\r\n'
			'List-Unsubscribe: <https://example.com/u>\r\n'
			'List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n'
			'\r\ncorpo\r\n')
		result = spam_headers.scan(msg, msg.get('Subject'))
		self.assertTrue(result['oneClick'])
		self.assertTrue(result['bulk'])


class ResumoEmProsa(unittest.TestCase):

	def test_sem_marcador(self):
		self.assertIn('nenhum marcador', spam_headers.summary(spam_headers.scan({})))

	def test_com_marcadores(self):
		texto = spam_headers.summary(spam_headers.scan({'Precedence': 'bulk'}))
		self.assertIn('1 marcador', texto)


if __name__ == '__main__':
	unittest.main()
