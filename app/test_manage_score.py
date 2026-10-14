"""Os dois comandos de inspeção do score em `manage.py`.

Eles existem para calibrar peso sem gastar cota de fornecedor nem uma análise
real, e é justamente isso que os torna perigosos se derivarem: um número que sai
daqui e não bate com o que o pipeline produz é pior do que nenhum número, porque
alguém vai ajustar peso confiando nele.

Por isso o que se testa aqui não é formatação. É que a linha de comando fala com
os mesmos módulos, na mesma ordem, com a mesma configuração — e que as amostras
versionadas continuam demonstrando o que o README delas afirma.

Rodar com:  python -m unittest test_manage_score   (a partir de app/)
"""

import argparse
import contextlib
import io as io_module
import os
import unittest

import manage
import scoring


SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samples')


def run(command, **kwargs):
	"""Roda um subcomando e devolve (codigo de saida, o que ele imprimiu)."""
	buffer = io_module.StringIO()
	args = argparse.Namespace(**kwargs)
	with contextlib.redirect_stdout(buffer):
		code = command(args)
	return code, buffer.getvalue()


def score(eml, analyzer = None, llm = None, llm_clean = False, as_json = False):
	return run(manage.cmd_score, eml = os.path.join(SAMPLES, eml), analyzer = analyzer,
		llm = llm, llm_clean = llm_clean, json = as_json)


class NiveisInformadosNaLinhaDeComando(unittest.TestCase):

	def test_um_par_valido_vira_relatorio(self):
		reports, error = manage._parse_analyzer_levels(['virustotal=malicious'])
		self.assertIsNone(error)
		self.assertEqual(reports[0]['analyzer_id'], 'virustotal')
		self.assertEqual(reports[0]['analyzer_result'], 'malicious')

	def test_um_id_que_nao_existe_e_recusado(self):
		# Descartar em silencio produziria um score que a pessoa atribui ao
		# analisador que ela pensou ter informado
		_reports, error = manage._parse_analyzer_levels(['virustotaal=malicious'])
		self.assertIn('desconhecido', error)

	def test_um_nivel_que_nao_existe_e_recusado(self):
		_reports, error = manage._parse_analyzer_levels(['virustotal=pessimo'])
		self.assertIn('Nivel invalido', error)

	def test_forma_sem_igual_e_recusada(self):
		_reports, error = manage._parse_analyzer_levels(['virustotal'])
		self.assertIn('id=nivel', error)

	def test_nenhum_par_e_valido(self):
		reports, error = manage._parse_analyzer_levels(None)
		self.assertIsNone(error)
		self.assertEqual(reports, [])


class VeredictoBaseEOMesmoDoPipeline(unittest.TestCase):
	"""Mesma regra de `run_analysis.terminate_analysis`, e é o ponto."""

	def test_um_malicioso_convicta(self):
		self.assertEqual(manage._baseline_verdict(
			[{'analyzer_result': 'safe'}, {'analyzer_result': 'malicious'}]), 'Malicious')

	def test_um_suspeito_abre_o_caso(self):
		self.assertEqual(manage._baseline_verdict(
			[{'analyzer_result': 'safe'}, {'analyzer_result': 'suspicious'}]), 'Suspicious')

	def test_info_nao_vale_veredito(self):
		self.assertEqual(manage._baseline_verdict([{'analyzer_result': 'info'}]), 'Safe')

	def test_sem_relatorio_nenhum(self):
		self.assertEqual(manage._baseline_verdict([]), 'Safe')


class AsAmostrasDemonstramOQueOReadmeDiz(unittest.TestCase):
	"""Se uma amostra deixar de demonstrar seu caso, o README dela vira mentira."""

	def test_a_newsletter_autenticada_sai_da_fila_como_spam(self):
		code, output = score('newsletter.eml', analyzer = ['virustotal=safe'], as_json = True)
		self.assertEqual(code, 0)
		import json
		payload = json.loads(output)
		self.assertTrue(payload['authentication']['authenticated'])
		self.assertTrue(payload['bulk']['oneClick'])
		self.assertEqual(payload['score']['label'], 'spam')
		self.assertEqual(payload['verdictAfter'], 'Safe')

	def test_o_unsubscribe_forjado_nao_compra_triagem(self):
		# O par com o teste acima é o que justifica a regra inteira: mesma família
		# de cabeçalho, e aqui o domínio não está autenticado
		import json
		code, output = score('phishing.eml', analyzer = ['virustotal=safe'], as_json = True)
		self.assertEqual(code, 0)
		payload = json.loads(output)
		self.assertFalse(payload['authentication']['authenticated'])
		self.assertTrue(payload['bulk']['bulk'])
		self.assertNotEqual(payload['score']['label'], 'spam')

	def test_sem_evidencia_o_phishing_vai_para_a_fila_e_nao_para_o_arquivo(self):
		import json
		code, output = score('phishing.eml', analyzer = ['virustotal=safe'], as_json = True)
		payload = json.loads(output)
		self.assertTrue(payload['score']['capped'])
		self.assertEqual(payload['verdictAfter'], 'Suspicious')

	def test_com_o_conteudo_julgado_ele_e_condenado(self):
		import json
		_code, output = score('phishing.eml', analyzer = ['virustotal=safe'], llm = 'High',
			as_json = True)
		payload = json.loads(output)
		self.assertEqual(payload['score']['tier'], 'phishing')
		self.assertEqual(payload['verdictAfter'], 'Malicious')

	def test_o_resguardo_do_remetente_autenticado_vale_aqui_tambem(self):
		import json
		_code, output = score('newsletter.eml', llm = 'Critical', as_json = True)
		payload = json.loads(output)
		self.assertEqual(payload['score']['tier'], 'phishing')
		self.assertEqual(payload['verdictAfter'], 'Suspicious')
		self.assertIn('autenticado', payload['reason'])

	def test_correspondencia_interna_limpa_pontua_zero(self):
		import json
		_code, output = score('interno.eml', analyzer = ['virustotal=safe'],
			llm = 'Low', llm_clean = True, as_json = True)
		payload = json.loads(output)
		self.assertEqual(payload['score']['score'], 0.0)
		self.assertEqual(payload['score']['label'], 'legitimate')
		self.assertEqual(payload['bulk']['markers'], [])


class SaidaParaHumano(unittest.TestCase):

	def test_a_memoria_de_calculo_aparece(self):
		code, output = score('phishing.eml', analyzer = ['virustotal=safe'], llm = 'High')
		self.assertEqual(code, 0)
		for expected in ('MEMORIA DE CALCULO', 'SCORE', 'FAIXA', 'VEREDITO',
				'CABECALHOS DE MASSA', 'AUTENTICACAO'):
			self.assertIn(expected, output)

	def test_um_arquivo_que_nao_existe_falha_com_codigo(self):
		code, output = run(manage.cmd_score, eml = '/tmp/nao-existe-mesmo.eml',
			analyzer = None, llm = None, llm_clean = False, json = False)
		self.assertEqual(code, 1)
		self.assertIn('Nao foi possivel ler', output)

	def test_risco_invalido_falha_com_codigo(self):
		code, output = score('interno.eml', llm = 'Altissimo')
		self.assertEqual(code, 1)
		self.assertIn('Risco invalido', output)

	def test_o_ranking_de_pesos_lista_todo_o_registro(self):
		import analyzers
		code, output = run(manage.cmd_weights)
		self.assertEqual(code, 0)
		for spec in analyzers.ANALYZERS:
			self.assertIn(spec['name'], output)
		for factor in scoring.SIGNAL_FACTORS:
			self.assertIn(factor['name'], output)


if __name__ == '__main__':
	unittest.main()
