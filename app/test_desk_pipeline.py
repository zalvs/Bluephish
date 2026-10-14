"""O que a análise deixa para a mesa de trabalho, e os dois erros que já cometeu.

Os dois foram achados rodando o fluxo inteiro dentro da imagem, e nenhum deles
produzia erro:

  * **A referência de um registro em disco.** O destino Disco devolve como `ref`
    o caminho inteiro da pasta; a listagem conhece o registro só pelo nome dela.
    Gravar o caminho fazia escopo, original guardado, "Como entregue" e errata
    nunca acharem um registro em disco — a tela dizia "não guardado" sobre uma
    mensagem que estava guardada.
  * **O parâmetro sombreado.** `main` recebia `outcome` para devolver as
    referências produzidas, e o laço de despacho usa `outcome` para o resultado
    de cada destino. As referências iam parar no dicionário do último destino, e
    a reanálise dizia que nenhum registro novo tinha sido gravado.

Rodar com:  python -m unittest test_desk_pipeline   (a partir de app/)
"""

import inspect
import unittest

import history
import run_analysis


class RecordReference(unittest.TestCase):

	def test_a_disk_record_is_referenced_by_its_folder_name(self):
		ref = run_analysis.record_reference(history.DISK,
			'/root/thephish/data/analises/2026-09-16T14-00-10-Sua-conta')
		self.assertEqual(ref, 'disk:2026-09-16T14-00-10-Sua-conta')

	def test_the_disk_reference_matches_what_the_listing_uses(self):
		folder = '2026-09-16T14-00-10-Sua-conta'
		self.assertEqual(run_analysis.record_reference(history.DISK, '/a/b/' + folder + '/'),
			history.record_id(history.DISK, folder))

	def test_a_thehive_case_is_referenced_by_its_bare_number(self):
		self.assertEqual(run_analysis.record_reference(history.THEHIVE, '4127'), '4127')

	def test_a_jira_issue_keeps_its_key(self):
		self.assertEqual(run_analysis.record_reference(history.JIRA, 'SOC-12'), 'jira:SOC-12')

	def test_no_reference_is_no_reference(self):
		self.assertEqual(run_analysis.record_reference(history.DISK, ''), '')
		self.assertEqual(run_analysis.record_reference('connector', 'x'), '')


class TheProducedReferencesReachTheCaller(unittest.TestCase):

	def test_main_does_not_take_a_parameter_the_dispatch_loop_reuses(self):
		parameters = inspect.signature(run_analysis.main).parameters
		self.assertIn('produced', parameters)
		source = inspect.getsource(run_analysis.main)
		for name in parameters:
			self.assertNotRegex(source, r'for [^\n]*\b' + name + r'\b[^\n]* in ',
				'o parâmetro {0} é reusado como variável de laço dentro de main'.format(name))


class SenderOf(unittest.TestCase):

	def test_the_capital_f_tag_is_matched(self):
		# RFC 5322 escreve From com F maiúsculo; comparar pelo literal em minúsculas
		# já deixou a coluna de remetente vazia em toda tela
		self.assertEqual(run_analysis.sender_of([{'tags': ['email_header_From'], 'value': 'a@b.com'}]), 'a@b.com')

	def test_both_observable_shapes_are_read(self):
		self.assertEqual(run_analysis.sender_of([{'tags': ['email_header_from'], 'name': 'a@b.com'}]), 'a@b.com')

	def test_no_sender_is_empty(self):
		self.assertEqual(run_analysis.sender_of([{'tags': ['other'], 'value': 'x'}]), '')


if __name__ == '__main__':
	unittest.main()
