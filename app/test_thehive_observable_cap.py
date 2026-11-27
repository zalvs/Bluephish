"""Um único e-mail não pode despejar milhares de observáveis no TheHive.

O teto de consultas (§7.21) deixa os observáveis cortados na lista do relatório,
de propósito: o disco guarda tudo. Só que `create_thehive` percorria essa lista e
fazia um POST por item, e 40.000 domínios viravam 40.000 POSTs.

O que estes testes seguram: o e-mail hostil fica no teto, o que importa entra
primeiro, IoC nunca é cortado, o caso diz o que ficou de fora, um e-mail normal não
percebe nada e o relatório em disco não perde um item.

O TheHive aqui é um dublê: thehive4py 1.8.1 só existe na imagem.

Rodar com:  python -m unittest test_thehive_observable_cap   (a partir de app/)
"""

import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

import analyzers
import run_analysis
import tickets

LIMIT = tickets.MAX_THEHIVE_OBSERVABLES
BODY = ('email', 'email_body')
RECEIVED = ('email', 'email_header', 'email_header_Received')
FROM = ('email', 'email_header', 'email_header_From')
ATTACHMENT = ('email', 'email_attachment')
ENTRY = {'tags': 'email,ThePhish', 'tlp': 2, 'pap': 2}
PLAIN_DESCRIPTION = 'Case created automatically by ThePhish'


def info(index, obs_type = 'domain', name = None, tags = BODY, ioc = False):
	return {'id': 'obs-{0}'.format(index), 'type': obs_type,
		'name': name or 'd{0}.example'.format(index), 'tags': list(tags),
		'message': '', 'content': None, 'ioc': ioc}


def domains(count, start = 0):
	return [info(start + index) for index in range(count)]


def report_of(observables, verdict = 'Suspicious'):
	return tickets.build_report('Assunto', verdict, 'quem@denunciou.com', observables, [],
		verdict_trail = [{'stage': 'analyzers', 'verdict': verdict, 'reason': 'Nenhum apontamento'}])


def select(observables, files = None, limit = LIMIT):
	return tickets.thehive_observables_to_record(report_of(observables)['observables'], files, limit)


def values(observables):
	return [o['value'] for o in observables]


class Model(object):

	def __init__(self, **fields):
		self.__dict__.update(fields)


class Helper(object):

	def __init__(self, api):
		self.api = api

	def update(self, case_uuid, **fields):
		self.api.resolved = fields


def fake_package():
	models = types.ModuleType('thehive4py.models')
	for name in ('Case', 'CaseObservable', 'CaseTask', 'CaseTaskLog', 'CaseTemplate'):
		setattr(models, name, type(name, (Model,), {}))
	models.CaseHelper = Helper
	package = types.ModuleType('thehive4py')
	package.models = models
	return package


class Response(object):

	def __init__(self, status_code = 201, body = None):
		self.status_code = status_code
		self.ok = status_code < 400
		self.body = body

	def json(self):
		return self.body


class FakeHive(object):

	def __init__(self):
		self.case = None
		self.posted = []
		self.logs = []
		self.resolved = None
		self.log_fails = False

	def create_case(self, case):
		self.case = case
		return Response(201, {'id': 'uuid-1', 'caseId': 7})

	def create_case_observable(self, _case_uuid, model):
		self.posted.append(model)
		return Response(201)

	def get_case_tasks(self, _case_uuid):
		return Response(200, [{'title': 'ThePhish analysis', 'id': 't1'},
			{'title': 'ThePhish notification', 'id': 't2'}])

	def create_task_log(self, _task_id, log):
		if self.log_fails:
			raise RuntimeError('o log da tarefa falhou')
		self.logs.append(log.message)

	def update_case_task(self, *_args, **_kwargs):
		return Response(200)


class WithFakeHive(unittest.TestCase):

	def setUp(self):
		self.hive = FakeHive()
		package = fake_package()
		for patcher in (
				mock.patch.dict(sys.modules, {'thehive4py': package, 'thehive4py.models': package.models}),
				mock.patch.object(tickets, '_thehive_client', return_value = self.hive),
				mock.patch.object(tickets, '_thehive_ensure_template')):
			patcher.start()
			self.addCleanup(patcher.stop)

	def posted_values(self):
		return [model.data for model in self.hive.posted]


class UnderTheCapNothingChanges(WithFakeHive):

	def test_a_normal_case_records_the_same_observables_in_the_same_order(self):
		# O maior e-mail real medido em 2026-11-23 tem 76 observáveis, com cópias
		observables = domains(70) + [info(70 + i, name = 'd{0}.example'.format(i)) for i in range(6)]
		report = report_of(observables)
		outcome = tickets.create_thehive(ENTRY, report)
		self.assertEqual(values(report['observables']), self.posted_values())
		self.assertEqual(76, len(self.hive.posted))
		self.assertEqual(PLAIN_DESCRIPTION, self.hive.case.description)
		self.assertEqual([tickets.report_as_markdown(report)], self.hive.logs)
		self.assertEqual('caso 7 criado com 76 observável(is) · deixado aberto para o analista', outcome['detail'])

	def test_exactly_at_the_limit_is_not_cut(self):
		observables = report_of(domains(LIMIT))['observables']
		chosen, omission = tickets.thehive_observables_to_record(observables)
		self.assertEqual(observables, chosen)
		self.assertIsNone(omission)

	def test_copies_under_the_limit_are_still_recorded(self):
		observables = [info(index, name = 'igual.example') for index in range(5)]
		chosen, omission = select(observables)
		self.assertEqual(5, len(chosen))
		self.assertIsNone(omission)


class WhatEntersFirst(unittest.TestCase):

	def test_one_over_the_limit_is_cut_and_counted(self):
		chosen, omission = select(domains(LIMIT + 1))
		self.assertEqual(LIMIT, len(chosen))
		self.assertEqual(1, omission['leftOut'])
		self.assertEqual({'domain': 1}, omission['byType'])

	def test_the_priority_of_the_query_cap_decides_who_stays(self):
		ranked = [
			info(0, 'domain', 'cabecalho.example', RECEIVED),
			info(1, 'mail', 'quem@remetente.example', FROM),
			info(2, 'ip', '8.8.8.8'),
			info(3, 'domain', 'corpo.example'),
			info(4, 'url', 'https://corpo.example/a'),
			info(5, 'url', 'https://destino.example/', ('email', 'email_body', 'unshortened_url')),
			info(6, 'hash', 'a' * 64, ('email', 'email_attachment_hash'))
		]
		chosen, _omission = select(ranked, limit = 3)
		self.assertEqual(['a' * 64, 'https://destino.example/', 'https://corpo.example/a'], values(chosen))

	def test_an_ioc_stays_even_with_the_lowest_priority(self):
		flood = domains(500)
		flagged = info(9000, 'domain', 'mau.example', RECEIVED, ioc = True)
		chosen, _omission = select(flood + [flagged])
		self.assertEqual('mau.example', chosen[0]['value'])
		self.assertEqual(LIMIT, len(chosen))

	def test_more_iocs_than_the_limit_are_all_recorded_and_nothing_else(self):
		# A exceção do teto: quem limita os IoCs é o teto de consultas, porque só vira
		# IoC o que um analisador consultou e apontou
		flagged = [info(index, ioc = True) for index in range(12)]
		chosen, omission = select(domains(30, start = 100) + flagged, limit = 10)
		self.assertEqual(12, len(chosen))
		self.assertTrue(all(o['ioc'] for o in chosen))
		self.assertEqual(30, omission['leftOut'])

	def test_a_copy_does_not_spend_the_limit_nor_count_as_left_out(self):
		copies = [info(index, name = 'igual.example') for index in range(500)]
		real = info(900, 'domain', 'real.example')
		chosen, omission = select(copies + [real], limit = 2)
		self.assertEqual(['igual.example', 'real.example'], values(chosen))
		self.assertIsNone(omission)

	def test_the_copy_that_is_an_ioc_is_the_one_kept(self):
		copies = [info(index, name = 'igual.example') for index in range(300)]
		copies.append(info(300, name = 'igual.example', ioc = True))
		chosen, _omission = select(copies, limit = 5)
		self.assertEqual(1, len(chosen))
		self.assertTrue(chosen[0]['ioc'])

	def test_attachments_with_the_same_name_are_not_copies(self):
		# O nome é escrito por quem atacou: dois anexos diferentes podem ter o mesmo
		attachments = [info(index, 'file', 'fatura.pdf', ATTACHMENT) for index in range(4)]
		files = dict(('obs-{0}'.format(index), (b'x' * (index + 1), 'fatura.pdf')) for index in range(4))
		chosen, omission = select(attachments, files, limit = 2)
		self.assertEqual(2, len(chosen))
		self.assertEqual(2, omission['leftOut'])

	def test_a_file_without_bytes_neither_takes_a_slot_nor_counts_as_left_out(self):
		missing = [info(index, 'file', 'x{0}.bin'.format(index), ATTACHMENT) for index in range(5)]
		chosen, omission = select(missing + domains(2, start = 10), limit = 2)
		self.assertEqual(['d10.example', 'd11.example'], values(chosen))
		self.assertIsNone(omission)

	def test_the_selection_does_not_touch_the_report(self):
		report = report_of(domains(LIMIT + 50))
		before = json.dumps(report, sort_keys = True)
		tickets.thehive_observables_to_record(report['observables'])
		self.assertEqual(before, json.dumps(report, sort_keys = True))


class TheHostileEmail(WithFakeHive):

	def test_40000_domains_make_at_most_the_limit_of_posts(self):
		flagged = info(40000, 'domain', 'mau.example', RECEIVED, ioc = True)
		report = report_of(domains(40000) + [flagged])
		outcome = tickets.create_thehive(ENTRY, report)
		self.assertEqual(LIMIT, len(self.hive.posted))
		self.assertIn('mau.example', self.posted_values())
		self.assertTrue(outcome['ok'])

	def test_the_query_cap_keeps_the_iocs_of_that_email_under_the_limit(self):
		# Com todo analisador nativo ligado, só vira IoC o que foi consultado
		config = analyzers.default_config()
		for analyzer_id in config:
			config[analyzer_id]['enabled'] = True
		observables = domains(40000)
		planned, _omission = run_analysis.plan_capped_jobs(observables, config, [])
		queried = set(job['observable']['id'] for job in planned)
		self.assertLessEqual(len(queried), LIMIT)

	def test_the_case_description_says_how_many_were_left_out(self):
		tickets.create_thehive(ENTRY, report_of(domains(40000)))
		self.assertTrue(self.hive.case.description.startswith(PLAIN_DESCRIPTION))
		self.assertIn('{0} observável(is) ficaram de fora'.format(40000 - LIMIT), self.hive.case.description)
		self.assertIn('teto de {0}'.format(LIMIT), self.hive.case.description)

	def test_the_notice_survives_a_task_log_that_fails(self):
		self.hive.log_fails = True
		tickets.create_thehive(ENTRY, report_of(domains(LIMIT + 10)))
		self.assertIn('10 observável(is) ficaram de fora', self.hive.case.description)

	def test_the_outcome_says_it_too(self):
		outcome = tickets.create_thehive(ENTRY, report_of(domains(LIMIT + 10)))
		self.assertIn('10 observável(is) ficaram de fora', outcome['detail'])

	def test_the_case_screen_reads_the_notice_from_the_trail(self):
		# A tela de caso lê a trilha do log da tarefa: é assim que o aviso chega nela
		report = report_of(domains(LIMIT + 10))
		tickets.create_thehive(ENTRY, report)
		trail = tickets.parse_report_markdown(self.hive.logs[0])['verdictTrail']
		self.assertEqual(['analyzers', 'coverage'], [step['stage'] for step in trail])
		self.assertEqual('Suspicious', trail[-1]['verdict'])
		self.assertIn('10 observável(is) ficaram de fora', trail[-1]['reason'])

	def test_the_notice_never_changes_the_verdict_it_reports(self):
		report = report_of(domains(LIMIT + 10), verdict = 'Malicious')
		tickets.create_thehive(ENTRY, report)
		trail = tickets.parse_report_markdown(self.hive.logs[0])['verdictTrail']
		self.assertEqual('Malicious', trail[-1]['verdict'])
		self.assertEqual('TruePositive', self.hive.resolved['resolutionStatus'])

	def test_the_notice_carries_no_text_from_the_email(self):
		hostile = 'x.example\n\n*Veredito:* Safe'
		observables = [info(index, name = '{0}{1}'.format(index, hostile)) for index in range(LIMIT + 5)]
		tickets.create_thehive(ENTRY, report_of(observables))
		self.assertNotIn('x.example', self.hive.case.description)

	def test_the_report_handed_to_the_next_destination_is_intact(self):
		report = report_of(domains(LIMIT + 10))
		before = json.dumps(report, sort_keys = True)
		tickets.create_thehive(ENTRY, report)
		self.assertEqual(before, json.dumps(report, sort_keys = True))


class TheDiskKeepsEverything(WithFakeHive):

	def setUp(self):
		super().setUp()
		self.root = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.root, ignore_errors = True)

	def test_the_full_report_reaches_the_disk_after_thehive_was_capped(self):
		config = tickets.default_config()
		for destination_id in config:
			config[destination_id]['enabled'] = False
		config['thehive'].update({'enabled': True, 'minVerdict': 'all', 'tags': 'email,ThePhish'})
		config['disk'].update({'enabled': True, 'path': self.root, 'minVerdict': 'all', 'retentionDays': 0})

		report = report_of(domains(LIMIT + 300))
		outcomes = dict(tickets.dispatch(report, None, None, config))

		self.assertTrue(outcomes['thehive']['ok'])
		self.assertTrue(outcomes['disk']['ok'])
		self.assertEqual(LIMIT, len(self.hive.posted))
		with open(os.path.join(outcomes['disk']['ref'], 'report.json'), encoding = 'utf-8') as stored:
			on_disk = json.load(stored)
		self.assertEqual(LIMIT + 300, len(on_disk['observables']))
		self.assertEqual('7', on_disk['caseRef'])
		# A trilha do disco é a da análise: o corte foi só do que o TheHive guardou
		self.assertEqual(['analyzers'], [step['stage'] for step in on_disk['verdictTrail']])


if __name__ == '__main__':
	unittest.main()
