"""Um único e-mail não pode gastar sozinho a cota dos fornecedores de reputação.

Medido em 2026-11-23: um e-mail sintético com 40.000 domínios virava 40.000
observáveis e, com os analisadores de domínio ligados, 320.000 consultas. Quem
escolhe esse número é quem escreveu o e-mail.

O teto é por analisador porque a cota é por fornecedor: um teto só para a
mensagem inteira, numa instalação com um fornecedor ligado, seria gasto todo nele.
O que fica de fora é dito no log e na trilha, e a mensagem não fecha como Safe.

Rodar com:  python -m unittest test_job_cap   (a partir de app/)
"""

import collections
import logging
import unittest
from unittest import mock

import analyzers
import run_analysis
import tickets

import test_scoring_pipeline as pipeline

LIMIT = run_analysis.MAX_JOBS_PER_ANALYZER
BODY = ('email', 'email_body')
LLM_BENIGN = {'social_engineering_detected': False, 'risk_level': 'Low', 'tactics': [], 'justification': 'ok'}


def obs(index, obs_type = 'domain', name = None, tags = BODY):
	return {'id': 'obs-{0}'.format(index), 'type': obs_type,
		'name': name or 'd{0}.example'.format(index), 'tags': list(tags),
		'message': '', 'content': None, 'ioc': False}


def domains(count, start = 0):
	return [obs(start + index) for index in range(count)]


def enabled(*analyzer_ids):
	config = analyzers.default_config()
	for analyzer_id in analyzer_ids:
		config[analyzer_id]['enabled'] = True
	return config


def custom(definition_id = 'virustotal'):
	return {'id': definition_id, 'enabled': True, 'name': 'TIP interno', 'observables': ['domain']}


def jobs_by_analyzer(planned):
	return collections.Counter((job['kind'], job['id']) for job in planned)


class RecordingWsl(object):

	def __init__(self):
		self.warnings = []

	def emit_info(self, message):
		pass

	def emit_warning(self, message):
		self.warnings.append(message)

	def emit_error(self, message):
		self.warnings.append(message)


class CountingList(list):
	"""Quantas vezes alguém percorreu a lista: o custo quadrático não falha, demora."""

	def __init__(self, *args):
		super().__init__(*args)
		self.iterations = 0

	def __iter__(self):
		self.iterations += 1
		return super().__iter__()


class UnderTheCapNothingChanges(unittest.TestCase):

	def test_a_normal_email_keeps_exactly_the_same_jobs_in_the_same_order(self):
		observables = [
			obs(0, 'mail', 'quem@exemplo.com', ('email', 'email_header', 'email_header_From')),
			obs(1, 'domain', 'exemplo.com', ('email', 'email_header', 'email_header_Received')),
			obs(2, 'url', 'https://mau.example/a'),
			obs(3, 'domain', 'mau.example'),
			obs(4, 'domain', 'mau.example'),
			obs(5, 'ip', '8.8.8.8'),
			obs(6, 'hash', 'a' * 64, ('email', 'email_attachment_hash')),
			obs(7, 'file', 'fatura.pdf', ('email', 'email_attachment')),
		]
		config = enabled('virustotal', 'urlhaus', 'abuseipdb', 'yara', 'safebrowsing')
		planned, omission = run_analysis.plan_capped_jobs(observables, config, [])
		self.assertEqual(planned, run_analysis.plan_jobs(observables, config, []))
		self.assertIsNone(omission)

	def test_exactly_at_the_limit_is_not_capped(self):
		observables = domains(LIMIT)
		config = enabled('virustotal')
		planned, omission = run_analysis.plan_capped_jobs(observables, config, [])
		self.assertEqual(len(planned), LIMIT)
		self.assertIsNone(omission)

	def test_the_limit_is_above_the_largest_real_email_measured(self):
		# O maior e-mail real medido em 2026-11-23 pede 75 consultas a um analisador.
		# Baixar o teto até aí faria e-mail legítimo perder consulta e virar Suspicious
		self.assertGreaterEqual(LIMIT, 2 * 75)


class OverTheCap(unittest.TestCase):

	def test_40000_domains_stay_within_the_limit_of_every_analyzer(self):
		config = enabled(*[spec['id'] for spec in analyzers.ANALYZERS])
		planned, omission = run_analysis.plan_capped_jobs(domains(40000), config, [])
		counts = jobs_by_analyzer(planned)
		self.assertTrue(counts)
		self.assertLessEqual(max(counts.values()), LIMIT)
		self.assertEqual(omission['observables'], 40000 - LIMIT)
		self.assertEqual(omission['byType'], {'domain': 40000 - LIMIT})

	def test_it_says_how_much_was_planned_and_how_much_runs(self):
		planned, omission = run_analysis.plan_capped_jobs(domains(500),
			enabled('virustotal', 'urlhaus'), [], limit = 100)
		self.assertEqual(omission['limit'], 100)
		self.assertEqual(omission['plannedJobs'], 1000)
		self.assertEqual(omission['runJobs'], len(planned))
		self.assertEqual(len(planned), 200)
		self.assertEqual(sorted(omission['analyzers']), sorted(
			[analyzers.BY_ID['virustotal']['name'], analyzers.BY_ID['urlhaus']['name']]))

	def test_a_flood_for_one_vendor_does_not_starve_another(self):
		# AbuseIPDB só avalia IP: a enxurrada de domínios não é da conta dele
		observables = domains(1000) + [obs(2000 + i, 'ip', '8.8.8.{0}'.format(i)) for i in range(3)]
		planned, _omission = run_analysis.plan_capped_jobs(observables,
			enabled('virustotal', 'abuseipdb'), [], limit = 10)
		self.assertEqual(jobs_by_analyzer(planned)[('native', 'abuseipdb')], 3)

	def test_what_weighs_most_on_the_verdict_runs_first(self):
		received = obs(0, 'domain', 'relay.example', ('email', 'email_header', 'email_header_Received'))
		sender = obs(1, 'domain', 'remetente.example', ('email', 'email_header', 'email_header_From'))
		body_domain = obs(2, 'domain', 'corpo.example')
		body_url = obs(3, 'url', 'https://corpo.example/login')
		unshortened = obs(4, 'url', 'https://destino.example/x', ('email', 'unshortened_url'))
		attachment = obs(5, 'hash', 'b' * 64, ('email', 'email_attachment_hash'))
		observables = [received, sender, body_domain, body_url, unshortened, attachment]
		expected = [attachment, unshortened, body_url, body_domain, sender, received]
		for limit in range(1, len(expected)):
			planned, _omission = run_analysis.plan_capped_jobs(observables, enabled('virustotal'), [], limit = limit)
			self.assertEqual(sorted(job['observable']['id'] for job in planned),
				sorted(item['id'] for item in expected[:limit]), 'limite {0}'.format(limit))

	def test_the_jobs_that_survive_keep_their_original_order(self):
		observables = [obs(0, 'domain', 'relay.example', ('email', 'email_header', 'email_header_Received'))] + domains(5, 1)
		planned, _omission = run_analysis.plan_capped_jobs(observables, enabled('virustotal'), [], limit = 3)
		ids = [job['observable']['id'] for job in planned]
		self.assertEqual(ids, sorted(ids, key = lambda value: int(value.split('-')[1])))

	def test_a_repeated_value_does_not_eat_the_cap(self):
		copies = [obs(index, 'domain', 'repetido.example') for index in range(50)]
		others = domains(3, 100)
		planned, omission = run_analysis.plan_capped_jobs(copies + others, enabled('virustotal'), [], limit = 4)
		names = [job['observable']['name'] for job in planned]
		self.assertEqual(len(names), 4)
		self.assertEqual(len(set(names)), 4)
		self.assertEqual(omission['observables'], 0)
		self.assertFalse(run_analysis.queries_left_out(omission))

	def test_a_value_already_queried_is_not_reported_as_left_out(self):
		copies = [obs(index, 'domain', 'repetido.example') for index in range(50)]
		others = domains(5, 100)
		_planned, omission = run_analysis.plan_capped_jobs(copies + others, enabled('virustotal'), [], limit = 4)
		self.assertEqual(omission['observables'], 2)

	def test_a_custom_analyzer_has_its_own_budget_even_with_a_native_id(self):
		planned, _omission = run_analysis.plan_capped_jobs(domains(20), enabled('virustotal'),
			[custom('virustotal')], limit = 5)
		counts = jobs_by_analyzer(planned)
		self.assertEqual(counts[('native', 'virustotal')], 5)
		self.assertEqual(counts[('custom', 'virustotal')], 5)

	def test_the_examples_are_few_short_and_in_priority_order(self):
		long_name = 'https://mau.example/' + 'a' * 500
		observables = [obs(0, 'domain', 'relay.example', ('email', 'email_header', 'email_header_Received')),
			obs(1, 'url', long_name)] + domains(30, 2)
		_planned, omission = run_analysis.plan_capped_jobs(observables, enabled('virustotal'), [], limit = 1)
		self.assertLessEqual(len(omission['examples']), run_analysis.MAX_OMITTED_EXAMPLES)
		self.assertTrue(all(len(example) <= run_analysis.MAX_OMITTED_EXAMPLE_LENGTH for example in omission['examples']))
		self.assertNotIn('relay.example', omission['examples'])

	def test_an_example_written_by_the_attacker_cannot_break_the_log_line(self):
		observables = [obs(0, 'file', 'a.pdf', ('email', 'email_attachment')),
			obs(1, 'file', 'fatura\r\nFORJADO: linha falsa.pdf', ('email', 'email_attachment'))]
		_planned, omission = run_analysis.plan_capped_jobs(observables, enabled('yara'), [], limit = 1)
		self.assertEqual(omission['examples'], ['fatura FORJADO: linha falsa.pdf'])


class TheAnalysisRespectsTheCap(unittest.TestCase):

	def setUp(self):
		self._log = run_analysis.log
		run_analysis.log = mock.Mock()
		self.addCleanup(setattr, run_analysis, 'log', self._log)
		self.addCleanup(mock.patch.stopall)
		mock.patch.object(run_analysis.custom_analyzers, 'load_all', return_value = []).start()
		self.calls = collections.Counter()

		def fake_run_job(job, native_config, definitions_by_id):
			self.calls[job['id']] += 1
			return {'level': 'safe', 'signal': None, 'detail': '', 'retryable': False}
		mock.patch.object(run_analysis, 'run_job', side_effect = fake_run_job).start()

	def test_40000_domains_reach_each_vendor_at_most_limit_times(self):
		mock.patch.object(run_analysis.analyzers, 'load_config',
			return_value = enabled('virustotal', 'urlhaus', 'otx')).start()
		wsl = RecordingWsl()
		reports, omission = run_analysis.analyze_observables(domains(40000), wsl)
		self.assertEqual(self.calls, {'virustotal': LIMIT, 'urlhaus': LIMIT, 'otx': LIMIT})
		self.assertEqual(len(reports), 3 * LIMIT)
		self.assertEqual(omission['observables'], 40000 - LIMIT)

	def test_the_analysis_log_says_what_was_left_out(self):
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('virustotal')).start()
		wsl = RecordingWsl()
		run_analysis.analyze_observables(domains(LIMIT + 7), wsl)
		said = ' '.join(wsl.warnings)
		self.assertIn('7 observáve', said)
		self.assertIn('d{0}.example'.format(LIMIT), said)
		self.assertTrue(run_analysis.log.warning.called)

	def test_a_normal_email_says_nothing_about_a_cap(self):
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('virustotal')).start()
		wsl = RecordingWsl()
		reports, omission = run_analysis.analyze_observables(domains(10), wsl)
		self.assertEqual(len(reports), 10)
		self.assertIsNone(omission)
		self.assertEqual(wsl.warnings, [])

	def test_shorteners_are_resolved_at_most_limit_times(self):
		# O unshorten faz uma requisição por URL, em sequência, antes do plano:
		# sem o mesmo teto, a enxurrada de URLs nunca chegaria a ele
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('virustotal')).start()
		resolved = []

		def fake_resolve(url):
			resolved.append(url)
			return {'found': False, 'url': url, 'chain': [], 'error': ''}
		mock.patch.object(run_analysis.unshorten, 'resolve', side_effect = fake_resolve).start()
		header_url = obs(0, 'url', 'https://cabecalho.example/x', ('email', 'email_header', 'email_header_Received'))
		body_urls = [obs(index + 1, 'url', 'https://u{0}.example/'.format(index)) for index in range(LIMIT + 50)]
		wsl = RecordingWsl()
		run_analysis.analyze_observables([header_url] + body_urls, wsl)
		self.assertEqual(len(resolved), LIMIT)
		self.assertNotIn(header_url['name'], resolved)
		self.assertTrue(any('encurtad' in message for message in wsl.warnings), wsl.warnings)

	def test_unresolved_shorteners_count_even_with_no_url_analyzer_enabled(self):
		# Sem analisador de URL o plano não corta nada, e o destino escondido atrás
		# do encurtador ficaria de fora sem que o veredito soubesse
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('abuseipdb')).start()
		mock.patch.object(run_analysis.unshorten, 'resolve',
			side_effect = lambda url: {'found': False, 'url': url, 'chain': [], 'error': ''}).start()
		urls = [obs(index, 'url', 'https://u{0}.example/'.format(index)) for index in range(LIMIT + 9)]
		wsl = RecordingWsl()
		_reports, omission = run_analysis.analyze_observables(urls, wsl)
		self.assertTrue(run_analysis.queries_left_out(omission))
		self.assertEqual(omission['byType'], {'url': 9})
		self.assertIn('https://u{0}.example/'.format(LIMIT), omission['examples'])
		self.assertTrue(any('Teto de consultas' in message for message in wsl.warnings), wsl.warnings)

	def test_every_url_of_a_normal_email_is_still_resolved(self):
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('virustotal')).start()
		resolve = mock.patch.object(run_analysis.unshorten, 'resolve',
			side_effect = lambda url: {'found': False, 'url': url, 'chain': [], 'error': ''}).start()
		urls = [obs(index, 'url', 'https://u{0}.example/'.format(index)) for index in range(20)]
		run_analysis.analyze_observables(urls, RecordingWsl())
		self.assertEqual([call.args[0] for call in resolve.call_args_list], [url['name'] for url in urls])


class WhatTheModelIsTold(unittest.TestCase):

	def test_it_learns_a_clean_sheet_is_partial_without_reading_attacker_text(self):
		_planned, omission = run_analysis.plan_capped_jobs(domains(30), enabled('virustotal'), [], limit = 10)
		notice = run_analysis.describe_omission_for_model(omission)
		self.assertIn('20', notice)
		self.assertIn('NOT', notice)
		self.assertNotIn('.example', notice)


class ACappedAnalysisIsNotSafe(unittest.TestCase):

	def setUp(self):
		self.harness = pipeline.TerminateAnalysisComScore('run_it')
		self.harness.setUp()
		run_analysis.config['notificationFlags'] = {'start': True, 'safe': True, 'malicious': True}
		_planned, self.omission = run_analysis.plan_capped_jobs(domains(30), enabled('virustotal'), [], limit = 10)

	def tearDown(self):
		self.harness.tearDown()

	def decide(self, findings, omission = 'default', content_key = ''):
		trail = []
		verdict, _score = run_analysis.terminate_analysis(
			'Acompanhe sua entrega', 'quem@denunciou.com', [pipeline.observable()], findings, LLM_BENIGN,
			self.harness.wsl, auth_results = pipeline.AUTHENTICATED, sent_log = [],
			observables_seen = None, trail = trail, content_key = content_key,
			query_omission = self.omission if omission == 'default' else omission)
		return verdict, trail

	def test_safe_opinions_do_not_vouch_for_what_was_not_queried(self):
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')])
		self.assertEqual(verdict, 'Suspicious')
		reasons = [step['reason'] for step in trail if step['stage'] == 'coverage']
		self.assertEqual(len(reasons), 1)
		self.assertIn('20 observáve', reasons[0])
		self.assertIn('d10.example', reasons[0])

	def test_the_reporter_is_not_told_it_is_safe(self):
		self.decide([pipeline.finding('urlhaus', 'safe')])
		self.assertEqual(self.harness.notified, [])

	def test_it_never_lowers_a_verdict_and_the_trail_still_says_it(self):
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'malicious')])
		self.assertEqual(verdict, 'Malicious')
		self.assertTrue(any(step['stage'] == 'coverage' for step in trail))

	def test_a_whitelisted_sender_does_not_undo_the_floor(self):
		run_analysis.ruleset = _TrustedSender()
		with mock.patch.object(run_analysis.whitelist_state, 'register_downgrade') as downgrade:
			verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')])
		self.assertEqual(verdict, 'Suspicious')
		downgrade.assert_not_called()
		self.assertTrue(any(step['stage'] == 'whitelist' and 'não rebaixado' in step['reason'] for step in trail))

	def test_the_verdict_memory_does_not_undo_the_floor(self):
		with mock.patch.object(run_analysis.verdict_memory, 'apply') as memory:
			verdict, _trail = self.decide([pipeline.finding('urlhaus', 'safe')], content_key = 'conteudo')
		self.assertEqual(verdict, 'Suspicious')
		memory.assert_not_called()

	def test_without_an_omission_nothing_changes(self):
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')], omission = None)
		self.assertEqual(verdict, 'Safe')
		self.assertFalse(any(step['stage'] == 'coverage' for step in trail))

	def test_cutting_only_copies_of_a_queried_value_does_not_raise_the_verdict(self):
		copies = [obs(index, 'domain', 'repetido.example') for index in range(50)]
		_planned, only_copies = run_analysis.plan_capped_jobs(copies, enabled('virustotal'), [], limit = 4)
		verdict, trail = self.decide([pipeline.finding('urlhaus', 'safe')], omission = only_copies)
		self.assertEqual(verdict, 'Safe')
		self.assertFalse(any(step['stage'] == 'coverage' for step in trail))

	def test_the_whitelist_can_still_downgrade_when_nothing_was_left_out(self):
		run_analysis.ruleset = _TrustedSender()
		with mock.patch.object(run_analysis.whitelist_state, 'register_downgrade', return_value = (True, '')) as downgrade:
			verdict, _trail = self.decide([pipeline.finding('urlhaus', 'malicious')], omission = None)
		self.assertEqual(verdict, 'Safe')
		downgrade.assert_called_once()


class _TrustedSender(pipeline.NoWhitelist):

	class Match(pipeline.NoWhitelist.Match):
		rule_id = 'regra-do-remetente'
		def __bool__(self): return True
		__nonzero__ = __bool__


class ManyObservablesStayLinear(unittest.TestCase):
	"""Os observáveis que ficaram de fora continuam na lista, e ela vai até o fim."""

	def test_the_verdict_does_not_walk_the_reports_once_per_observable(self):
		harness = pipeline.TerminateAnalysisComScore('run_it')
		harness.setUp()
		self.addCleanup(harness.tearDown)
		observables = domains(5000)
		reports = CountingList([pipeline.finding('urlhaus', 'safe', obs_id = 'obs-{0}'.format(i)) for i in range(10)])
		run_analysis.terminate_analysis('assunto', 'quem@denunciou.com', observables, reports, LLM_BENIGN,
			harness.wsl, auth_results = pipeline.AUTHENTICATED, sent_log = [], observables_seen = None, trail = [])
		self.assertLess(reports.iterations, 50)

	def test_a_malicious_report_still_marks_its_observable(self):
		harness = pipeline.TerminateAnalysisComScore('run_it')
		harness.setUp()
		self.addCleanup(harness.tearDown)
		observables = domains(3)
		verdict, _score = run_analysis.terminate_analysis('assunto', 'quem@denunciou.com', observables,
			[pipeline.finding('urlhaus', 'malicious', obs_id = 'obs-1')], LLM_BENIGN,
			harness.wsl, auth_results = pipeline.AUTHENTICATED, sent_log = [], observables_seen = None, trail = [])
		self.assertEqual(verdict, 'Malicious')
		self.assertEqual([o['ioc'] for o in observables], [False, True, False])

	def test_the_report_does_not_walk_the_reports_once_per_observable(self):
		reports = CountingList([pipeline.finding('urlhaus', 'malicious', obs_id = 'obs-1'),
			pipeline.finding('otx', 'suspicious', obs_id = 'obs-2')])
		report = tickets.build_report('assunto', 'Malicious', 'quem@denunciou.com', domains(5000), reports)
		self.assertLess(reports.iterations, 10)
		self.assertEqual([o['malicious'] for o in report['observables'][:3]], [False, True, False])
		self.assertEqual([o['suspicious'] for o in report['observables'][:3]], [False, False, True])


class TheWholeAnalysis(unittest.TestCase):
	"""`main` é quem liga o teto ao veredito: sem isto, o piso existe e ninguém o chama."""

	def setUp(self):
		self.addCleanup(mock.patch.stopall)
		self.addCleanup(setattr, run_analysis, 'log', run_analysis.log)
		self.addCleanup(setattr, run_analysis, 'ruleset', run_analysis.ruleset)
		# `main` pega o logger do módulo, e sem a configuração dele o aviso iria para o stderr
		logging.disable(logging.CRITICAL)
		self.addCleanup(logging.disable, logging.NOTSET)
		mock.patch.dict(run_analysis.config, clear = False).start()
		mock.patch.object(run_analysis.logging.config, 'dictConfig').start()
		mock.patch.object(run_analysis.analyzers, 'load_config', return_value = enabled('virustotal')).start()
		mock.patch.object(run_analysis.custom_analyzers, 'load_all', return_value = []).start()
		mock.patch.object(run_analysis.whitelist, 'load', return_value = pipeline.NoWhitelist()).start()
		mock.patch.object(run_analysis.whitelist_state, 'suspended_ids', return_value = set()).start()
		mock.patch.object(run_analysis.whitelist_state, 'record_analysis').start()
		mock.patch.object(run_analysis.scoring, 'load_config', return_value = run_analysis.scoring.default_config()).start()
		mock.patch.object(run_analysis.llm_council, 'main', return_value = dict(LLM_BENIGN)).start()
		mock.patch.object(run_analysis.verdict_memory, 'consult', return_value = []).start()
		mock.patch.object(run_analysis.departments, 'resolve_from_file', return_value = '').start()
		mock.patch.object(run_analysis.connectors, 'load_all', return_value = []).start()
		mock.patch.object(run_analysis.connectors, 'dispatch', return_value = []).start()
		mock.patch.object(run_analysis, 'remember_analysis').start()
		mock.patch.object(run_analysis, 'run_job',
			return_value = {'level': 'safe', 'signal': None, 'detail': '', 'retryable': False}).start()
		self.dispatch = mock.patch.object(run_analysis.tickets, 'dispatch', return_value = []).start()

	def analyze(self, observables):
		verdict, _llm, _score = run_analysis.main(RecordingWsl(), observables, 'quem@denunciou.com',
			'Assunto', 'Corpo', auth_results = pipeline.AUTHENTICATED, notify = False)
		return verdict, self.dispatch.call_args[0][0]

	def test_a_flooded_email_closes_suspicious_with_the_omission_in_the_record(self):
		verdict, report = self.analyze(domains(LIMIT + 25))
		self.assertEqual(verdict, 'Suspicious')
		self.assertEqual(len(report['findings']), LIMIT)
		reasons = [step['reason'] for step in report['verdictTrail'] if step['stage'] == 'coverage']
		self.assertTrue(any('25 observáve' in reason for reason in reasons), reasons)

	def test_a_normal_email_still_closes_safe(self):
		verdict, report = self.analyze(domains(5))
		self.assertEqual(verdict, 'Safe')
		self.assertEqual(len(report['findings']), 5)


if __name__ == '__main__':
	unittest.main()
