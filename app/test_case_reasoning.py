"""Por que um e-mail foi classificado como foi — e a analista discordando disso.

O que estes testes prendem falha calado se quebrar:

* **O passo a passo do veredito chega à tela.** `run_analysis` o grava, o
  relatório o carrega, o markdown o escreve e o TheHive só o devolve como texto.
  Se o formato escrito e o lido divergirem numa vírgula, o detalhe do caso volta
  a dizer "não registrado" sobre uma análise que registrou tudo.
* **Não saber não é zero.** Um registro que não diz qual analisador marcou um
  IOC responde `None`, nunca uma lista vazia — vazia leria como "nenhum
  analisador marcou" sobre um observável marcado.
* **A reclassificação vale em todo lugar e não apaga nada.** O veredito da
  análise sobrevive ao lado da decisão, a decisão mais recente vence, e a cópia
  em disco de um caso do TheHive segue a decisão tomada sobre ele.

Rodar com:  python -m unittest test_case_reasoning   (a partir de app/)
"""

import datetime
import json
import os
import shutil
import tempfile
import unittest

import case_insights
import history
import llm_analysis
import llm_council
import models
import reclassification
import run_analysis
import tickets

import test_scoring_pipeline as pipeline


TRAIL = [
	{'stage': 'analyzers', 'verdict': 'Suspicious', 'reason': '0 observável(is) com resultado malicioso e 1 suspeito(s)'},
	{'stage': 'llm', 'verdict': 'Malicious', 'reason': 'Um observável suspeito somado à IA com risco High: elevado para Malicious'}
]


def reasoned_report(**overrides):
	arguments = dict(
		subject = 'Sua conta será bloqueada',
		verdict = 'Malicious',
		reporter = 'quem@denunciou.com',
		observables_info = [
			{'id': 'o1', 'type': 'url', 'name': 'http://mau.exemplo/login', 'ioc': True},
			{'id': 'o2', 'type': 'ip', 'name': '8.8.8.8'}
		],
		reports_observables = [
			{'observable_id': 'o1', 'observable_type': 'url', 'observable_name': 'http://mau.exemplo/login',
			 'analyzer_name': 'Google Safe Browsing', 'analyzer_result': 'malicious',
			 'analyzer_detail': 'SOCIAL_ENGINEERING', 'analyzer_error': ''},
			{'observable_id': 'o2', 'observable_type': 'ip', 'observable_name': '8.8.8.8',
			 'analyzer_name': 'AbuseIPDB', 'analyzer_result': 'safe',
			 'analyzer_detail': 'confiança 0/100', 'analyzer_error': ''}
		],
		llm_result = {'risk_level': 'High', 'social_engineering_detected': True,
			'justification': 'Urgência e pedido de credencial.\nLink para domínio recém-criado.',
			'tactics': ['urgency', 'credential_harvesting'],
			'evidence': ['"sua conta será bloqueada em 24h"', 'link para mau.exemplo/login']},
		verdict_trail = TRAIL)
	arguments.update(overrides)
	return tickets.build_report(**arguments)


class ReportMarkdownRoundTrip(unittest.TestCase):
	"""O TheHive devolve a análise só como o texto que esta aplicação escreveu."""

	def test_the_reasoning_survives_the_round_trip(self):
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(reasoned_report()))
		self.assertEqual(parsed['verdict'], 'Malicious')
		self.assertEqual(parsed['verdictTrail'], TRAIL)
		self.assertEqual(parsed['llm']['risk_level'], 'High')
		self.assertTrue(parsed['llm']['social_engineering_detected'])
		self.assertEqual(parsed['llm']['tactics'], ['urgency', 'credential_harvesting'])
		self.assertEqual(parsed['llm']['evidence'], ['"sua conta será bloqueada em 24h"', 'link para mau.exemplo/login'])

	def test_a_multiline_justification_is_read_back_whole(self):
		# Uma quebra de linha no meio partia a justificativa: a segunda metade
		# virava uma linha que nenhuma seção reconhece
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(reasoned_report()))
		self.assertEqual(parsed['llm']['justification'],
			'Urgência e pedido de credencial. Link para domínio recém-criado.')

	def test_only_the_flagging_analyzers_come_back(self):
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(reasoned_report()))
		self.assertEqual(len(parsed['findings']), 1)
		finding = parsed['findings'][0]
		self.assertEqual(finding['analyzer'], 'Google Safe Browsing')
		self.assertEqual(finding['observable'], 'http://mau.exemplo/login')
		self.assertEqual(finding['level'], 'malicious')
		self.assertEqual(finding['detail'], 'SOCIAL_ENGINEERING')

	def test_nothing_flagged_is_an_empty_list_not_unknown(self):
		report = reasoned_report(verdict = 'Safe', reports_observables = [], llm_result = None)
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(report))
		self.assertEqual(parsed['findings'], [])
		self.assertIsNone(parsed['llm'])

	def test_a_report_from_before_the_trail_says_it_did_not_record_one(self):
		report = reasoned_report(verdict_trail = None)
		report['llm'].pop('evidence')
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(report))
		self.assertIsNone(parsed['verdictTrail'])
		self.assertIsNone(parsed['llm']['evidence'])

	def test_an_empty_evidence_list_in_a_new_report_is_known_to_be_empty(self):
		report = reasoned_report()
		report['llm']['evidence'] = []
		parsed = tickets.parse_report_markdown(tickets.report_as_markdown(report))
		self.assertEqual(parsed['llm']['evidence'], [])

	def test_text_that_is_not_a_report_parses_to_nothing(self):
		parsed = tickets.parse_report_markdown('mailto:alguem@exemplo.com\nObrigado pelo envio.')
		self.assertEqual(parsed, {'verdict': None, 'llm': None, 'findings': None, 'verdictTrail': None})


class LlmEvidence(unittest.TestCase):
	"""Texto de modelo que leu um e-mail hostil: limitado em quantidade e tamanho."""

	def test_evidence_is_parsed_and_bounded(self):
		items = ['indício {0}'.format(i) for i in range(10)] + ['x' * 900]
		result = llm_analysis.parse_llm_response(json.dumps({'risk_level': 'High', 'evidence': items}))
		self.assertEqual(len(result['evidence']), llm_analysis.MAX_EVIDENCE)
		self.assertTrue(all(len(item) <= llm_analysis.MAX_EVIDENCE_CHARS for item in result['evidence']))

	def test_unusable_evidence_is_an_empty_list(self):
		for raw in ('um texto', None, [1, {'a': 2}, '   ']):
			result = llm_analysis.parse_llm_response(json.dumps({'risk_level': 'Low', 'evidence': raw}))
			self.assertEqual(result['evidence'], [])

	def test_the_contract_asks_for_it(self):
		self.assertIn('"evidence"', llm_analysis.ANALYSIS_OUTPUT_CONTRACT)

	def test_the_council_keeps_what_every_agent_pointed_at(self):
		merged = llm_council._merge([
			{'role': 'analyst', 'risk_level': 'High', 'social_engineering_detected': True,
			 'tactics': [], 'justification': 'a', 'evidence': ['link falso', 'urgência']},
			{'role': 'skeptic', 'risk_level': 'Medium', 'social_engineering_detected': True,
			 'tactics': [], 'justification': 'b', 'evidence': ['urgência', 'remetente trocado']}
		])
		self.assertEqual(merged['evidence'], ['link falso', 'urgência', 'remetente trocado'])


class FlaggedBy(unittest.TestCase):

	def setUp(self):
		self.observables = [
			{'type': 'domain', 'value': 'ok.exemplo', 'ioc': False},
			{'type': 'url', 'value': 'http://mau.exemplo/login', 'ioc': True},
			{'type': 'ip', 'value': '203.0.113.9', 'ioc': False}
		]
		self.findings = [
			{'observable': 'http://mau.exemplo/login', 'analyzer': 'VirusTotal', 'level': 'malicious', 'detail': '12/70'},
			{'observable': '203.0.113.9', 'analyzer': 'AbuseIPDB', 'level': 'suspicious', 'detail': ''},
			{'observable': 'ok.exemplo', 'analyzer': 'OTX', 'level': 'safe', 'detail': ''}
		]

	def test_what_matters_comes_first(self):
		ranked = case_insights.flagged_by(self.observables, self.findings)
		self.assertEqual([obs['value'] for obs in ranked],
			['http://mau.exemplo/login', '203.0.113.9', 'ok.exemplo'])
		self.assertEqual([obs['level'] for obs in ranked], ['malicious', 'suspicious', None])

	def test_each_observable_names_who_flagged_it(self):
		ranked = case_insights.flagged_by(self.observables, self.findings)
		self.assertEqual(ranked[0]['flaggedBy'], [{'analyzer': 'VirusTotal', 'level': 'malicious', 'detail': '12/70'}])
		# Um analisador que respondeu `safe` não "marcou" nada
		self.assertEqual(ranked[2]['flaggedBy'], [])

	def test_a_source_that_does_not_say_answers_none(self):
		ranked = case_insights.flagged_by(self.observables, None)
		self.assertTrue(all(obs['flaggedBy'] is None for obs in ranked))
		# O IOC continua IOC, e continua no topo
		self.assertEqual(ranked[0]['value'], 'http://mau.exemplo/login')
		self.assertEqual(ranked[0]['level'], 'malicious')


class TheTrailIsRecorded(unittest.TestCase):
	"""O passo a passo sai de terminate_analysis, a mesma função que decide."""

	def setUp(self):
		self.harness = pipeline.TerminateAnalysisComScore('run_it')
		self.harness.setUp()

	def tearDown(self):
		self.harness.tearDown()

	def decide(self, findings, llm = None):
		trail = []
		verdict, _score = run_analysis.terminate_analysis(
			'Assunto', 'quem@denunciou.com', [pipeline.observable()], findings, llm, self.harness.wsl,
			auth_results = pipeline.UNAUTHENTICATED, sent_log = [], observables_seen = None, trail = trail)
		return verdict, trail

	def test_the_last_step_carries_the_final_verdict(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'High', 'tactics': [], 'justification': 'x'}
		verdict, trail = self.decide([pipeline.finding('virustotal', 'suspicious')], llm)
		self.assertEqual(verdict, 'Malicious')
		self.assertEqual(trail[-1]['verdict'], verdict)
		self.assertEqual(trail[0]['stage'], 'analyzers')

	def test_the_step_that_raised_the_verdict_says_so(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'High', 'tactics': [], 'justification': 'x'}
		_verdict, trail = self.decide([pipeline.finding('virustotal', 'suspicious')], llm)
		llm_steps = [step for step in trail if step['stage'] == 'llm']
		self.assertEqual(len(llm_steps), 1)
		self.assertEqual(llm_steps[0]['verdict'], 'Malicious')
		self.assertIn('elevado para Malicious', llm_steps[0]['reason'])

	def test_a_model_that_did_not_run_is_a_step_too(self):
		_verdict, trail = self.decide([pipeline.finding('virustotal', 'safe')])
		self.assertTrue(any(step['stage'] == 'llm' and 'não avaliou' in step['reason'] for step in trail))


class ReclassificationRules(unittest.TestCase):

	def test_a_reason_is_required(self):
		self.assertTrue(reclassification.normalize_reason('ok')[1])
		self.assertTrue(reclassification.normalize_reason('   ' + ' ' * 40)[1])
		reason, error = reclassification.normalize_reason('  fornecedor   confirmou por telefone  ')
		self.assertEqual((reason, error), ('fornecedor confirmou por telefone', ''))

	def test_a_reason_padded_to_the_minimum_with_spaces_is_refused(self):
		self.assertTrue(reclassification.normalize_reason('a     b     c     d')[1])

	def test_only_threat_verdicts_can_become_legitimate(self):
		self.assertTrue(reclassification.can_reclassify('Malicious'))
		self.assertTrue(reclassification.can_reclassify('Suspicious'))
		self.assertFalse(reclassification.can_reclassify('Safe'))
		self.assertFalse(reclassification.can_reclassify('Other'))


def decision(decision_id, record_ref, verdict = 'Safe', previous = 'Malicious', action = 'reclassify', case_ref = ''):
	return {'id': decision_id, 'recordRef': record_ref, 'caseRef': case_ref, 'action': action,
		'previousVerdict': previous, 'verdict': verdict, 'reason': 'motivo suficiente aqui',
		'by': 'ana', 'at': '2026-09-14T10:00:00Z', 'outcomes': []}


class Overlay(unittest.TestCase):

	def hive(self, number, verdict = 'TruePositive'):
		return {'_id': '~{0}'.format(number), 'source': 'thehive', 'number': number,
			'resolutionStatus': verdict, 'status': 'Resolved', 'tags': []}

	def test_the_decision_replaces_the_verdict_and_keeps_the_original(self):
		cases = [self.hive(27)]
		reclassification.overlay(cases, [decision(1, '27')])
		self.assertEqual(case_insights.case_verdict(cases[0]), 'Safe')
		row = case_insights.case_row(cases[0], [])
		self.assertEqual(row['verdict'], 'Safe')
		self.assertEqual(row['originalVerdict'], 'Malicious')
		self.assertEqual(row['reclassification']['by'], 'ana')

	def test_the_counts_follow_the_decision(self):
		cases = [self.hive(27), self.hive(28)]
		reclassification.overlay(cases, [decision(1, '27')])
		counts = case_insights.count_verdicts(cases)
		self.assertEqual(counts.get('Safe'), 1)
		self.assertEqual(counts.get('Malicious'), 1)

	def test_the_latest_decision_wins(self):
		cases = [self.hive(27)]
		reclassification.overlay(cases, [
			decision(1, '27'),
			decision(2, '27', verdict = 'Malicious', previous = 'Safe', action = 'revert')])
		self.assertEqual(case_insights.case_verdict(cases[0]), 'Malicious')
		self.assertIsNone(case_insights.case_row(cases[0], [])['reclassification'])

	def test_a_reverted_decision_outranks_a_stale_destination(self):
		# O caso reaberto no TheHive conserva a resolução FalsePositive
		cases = [self.hive(27, verdict = 'FalsePositive')]
		reclassification.overlay(cases, [
			decision(1, '27'),
			decision(2, '27', verdict = 'Suspicious', previous = 'Safe', action = 'revert')])
		self.assertEqual(case_insights.case_verdict(cases[0]), 'Suspicious')

	def test_the_disk_copy_of_a_thehive_case_follows_it(self):
		disk = {'_id': 'disk:2026-09-09T19-26-39-x', 'source': 'disk', 'ref': '2026-09-09T19-26-39-x',
			'verdict': 'Malicious', 'caseRef': '27', 'tags': []}
		reclassification.overlay([disk], [decision(1, '27', case_ref = '27')])
		self.assertEqual(disk['verdict'], 'Safe')

	def test_an_unrelated_record_is_untouched(self):
		cases = [self.hive(30)]
		reclassification.overlay(cases, [decision(1, '27', case_ref = '27')])
		self.assertEqual(case_insights.case_verdict(cases[0]), 'Malicious')
		self.assertIsNone(case_insights.case_row(cases[0], [])['originalVerdict'])


class ReclassificationStorage(pipeline.unittest.TestCase):
	"""Contra um SQLite próprio, como test_whitelist_state."""

	def setUp(self):
		handle, self.db_path = tempfile.mkstemp(suffix = '.db')
		os.close(handle)
		self.previous_path = models.DB_PATH
		models.DB_PATH = self.db_path
		models._engine = None
		models._SessionFactory = None
		models.init_db()

	def tearDown(self):
		models._engine = None
		models._SessionFactory = None
		models.DB_PATH = self.previous_path
		try:
			os.remove(self.db_path)
		except OSError:
			pass

	def test_nothing_is_overwritten(self):
		first = reclassification.record('27', '27', 'reclassify', 'Malicious', 'Safe', 'confirmado com o fornecedor', 'ana')
		reclassification.record('27', '27', 'revert', 'Safe', 'Malicious', 'o fornecedor negou depois', 'bruno')
		history_rows = reclassification.history_for('27')
		self.assertEqual([row['action'] for row in history_rows], ['reclassify', 'revert'])
		self.assertEqual(history_rows[0]['id'], first['id'])
		latest = reclassification.load_latest()
		self.assertEqual(len(latest), 1)
		self.assertEqual(latest[0]['action'], 'revert')
		self.assertEqual(latest[0]['by'], 'bruno')

	def test_outcomes_are_kept_with_the_decision(self):
		made = reclassification.record('disk:x', '', 'reclassify', 'Suspicious', 'Safe', 'motivo com tamanho', 'ana')
		reclassification.save_outcomes(made['id'], [{'destination': 'Disco', 'ok': True, 'detail': 'ok'}])
		self.assertEqual(reclassification.load_latest()[0]['outcomes'][0]['destination'], 'Disco')


class DiskReclassification(unittest.TestCase):
	"""A decisão escrita na pasta da análise, sem apagar o que a análise disse."""

	def setUp(self):
		self.root = tempfile.mkdtemp()
		self.report = reasoned_report()
		tickets.create_disk({'path': self.root, 'writeEml': 'não', 'writeBody': 'não', 'retentionDays': 0}, self.report)
		self.name = os.listdir(self.root)[0]
		self.folder = os.path.join(self.root, self.name)

	def tearDown(self):
		shutil.rmtree(self.root, ignore_errors = True)

	def test_the_report_keeps_its_verdict_and_gains_the_decision(self):
		tickets.reclassify_disk(self.folder, decision(7, 'disk:' + self.name))
		stored = history.read_report(os.path.join(self.folder, 'report.json'))
		self.assertEqual(stored['verdict'], 'Malicious')
		self.assertEqual(stored['reclassification']['verdict'], 'Safe')
		self.assertEqual(len(stored['reclassificationHistory']), 1)
		self.assertFalse(os.path.exists(os.path.join(self.folder, 'report.json.tmp')))

	def test_the_disk_history_honors_the_decision_on_its_own(self):
		tickets.reclassify_disk(self.folder, decision(7, 'disk:' + self.name))
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(case_insights.case_verdict(cases[0]), 'Safe')
		self.assertEqual(cases[0]['originalVerdict'], 'Malicious')

	def test_the_detail_carries_the_reasoning(self):
		stored = history.read_report(os.path.join(self.folder, 'report.json'))
		detail = history.report_detail(stored, history.DISK, self.name)
		analysis = detail['analysis']
		self.assertEqual(analysis['verdictTrail'], TRAIL)
		self.assertEqual(analysis['llm']['evidence'], ['"sua conta será bloqueada em 24h"', 'link para mau.exemplo/login'])
		self.assertEqual(analysis['llm']['riskLevel'], 'High')
		self.assertEqual(len(analysis['findings']), 2)


if __name__ == '__main__':
	unittest.main()
