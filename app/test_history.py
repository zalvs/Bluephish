"""Tests for the analysis history read back from the ticket destinations.

The screens used to read TheHive and nothing else, which meant an installation
recording to disk — the destination that exists precisely for a SOC wanting
neither TheHive nor Jira — analyzed all day and saw an empty history, with
nothing failing anywhere. What is pinned down here is that a record survives the
round trip through disk with everything the dashboards count on it, that two
sources holding the same analysis produce one row, and that a source which
cannot answer for something says so instead of answering zero.

history.py has no Flask, eventlet or requests dependency, so this needs no live
anything.

Run with:  python -m unittest test_history   (from the app/ directory)
"""

import io
import json
import os
import shutil
import tempfile
import unittest

import case_insights as ci
import history


def report(subject = 'Fatura em aberto', verdict = 'Malicious', at = '2026-09-09T19:26:39',
	department = '', tactics = None, risk = '', reporter = 'quem@empresa.com',
	observables = None, case_ref = ''):
	"""A report.json as tickets.build_report writes it, reduced to what is read."""
	built = {
		'subject': subject,
		'verdict': verdict,
		'reporter': reporter,
		'department': department,
		'analyzedAt': at,
		'caseRef': case_ref,
		'observables': observables if observables is not None else [],
		'findings': [],
		'llm': None,
		'body': 'corpo do e-mail'
	}
	if tactics or risk:
		built['llm'] = {
			'risk_level': risk or 'High',
			'social_engineering_detected': True,
			'tactics': tactics or [],
			'justification': 'urgência e cobrança'
		}
	return built


def observable(value, obs_type = 'domain', ioc = False, tags = None):
	return {'type': obs_type, 'value': value, 'ioc': ioc, 'tags': tags or [], 'message': ''}


class DiskFolder(unittest.TestCase):
	"""A folder of analyses, written the way tickets.create_disk writes them."""

	def setUp(self):
		self.root = tempfile.mkdtemp(prefix = 'bluephish-history-')

	def tearDown(self):
		shutil.rmtree(self.root, ignore_errors = True)

	def write(self, name, payload):
		folder = os.path.join(self.root, name)
		os.makedirs(folder)
		with io.open(os.path.join(folder, 'report.json'), 'w', encoding = 'utf-8') as handle:
			handle.write(json.dumps(payload, ensure_ascii = False))
		return folder


class RecordsFromDisk(DiskFolder):

	def test_an_analysis_on_disk_becomes_a_row_the_dashboards_can_read(self):
		self.write('2026-09-09T19-26-39-Fatura', report())
		cases, observables, _truncated = history.disk_records(self.root)
		self.assertEqual(len(cases), 1)
		self.assertEqual(cases[0]['title'], 'Fatura em aberto')
		self.assertEqual(ci.case_verdict(cases[0]), 'Malicious')
		self.assertEqual(cases[0]['source'], history.DISK)
		self.assertIn(cases[0]['_id'], observables)

	def test_the_verdict_is_read_rather_than_decoded_from_a_resolution(self):
		# A disk record has no resolutionStatus, and the old mapping turned
		# anything without one into "Suspicious" - the one verdict that means an
		# analyst still has to look. Every Safe email would have grown a task
		self.write('2026-09-09T19-26-39-Boletim', report(verdict = 'Safe'))
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(ci.case_verdict(cases[0]), 'Safe')

	def test_the_department_and_the_tactics_survive_the_round_trip(self):
		# These reach a TheHive case as tags and reach the dashboards as fields.
		# Rebuilt here from the same report through the same function, so a disk
		# installation gets the same executive view rather than a degraded one
		self.write('2026-09-09T19-26-39-Fatura',
			report(department = 'Financeiro', tactics = ['urgency', 'authority'], risk = 'High'))
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(ci.case_department(cases[0]), 'Financeiro')
		self.assertEqual(sorted(ci.case_tactics(cases[0])), ['authority', 'urgency'])
		self.assertEqual(ci.case_risk(cases[0]), 'High')

	def test_the_observables_arrive_in_the_vocabulary_the_readers_use(self):
		# type/value on disk, dataType/data everywhere that reads. Translating in
		# one place is what keeps the IOC ranking and the sender lookup from
		# having to know which destination they are looking at
		self.write('2026-09-09T19-26-39-Fatura', report(observables = [
			observable('golpe@falso.net', 'mail', tags = [ci.SENDER_OBSERVABLE_TAG]),
			observable('falso.net', 'domain', ioc = True)
		]))
		cases, observables, _truncated = history.disk_records(self.root)
		found = observables[cases[0]['_id']]
		row = ci.case_row(cases[0], found)
		self.assertEqual(row['sender'], 'golpe@falso.net')
		self.assertEqual(row['iocCount'], 1)
		self.assertEqual(row['iocs'][0]['value'], 'falso.net')

	def test_records_come_back_newest_first(self):
		self.write('2026-09-07T10-00-00-Antigo', report(at = '2026-09-07T10:00:00'))
		self.write('2026-09-09T19-26-39-Novo', report(at = '2026-09-09T19:26:39'))
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual([case['title'] for case in cases], ['Fatura em aberto', 'Fatura em aberto'])
		self.assertGreater(cases[0]['startDate'], cases[1]['startDate'])

	def test_folders_older_than_the_window_are_not_even_opened(self):
		# The folder name carries the timestamp, so the window is applied before a
		# file is read. On a year of analyses that is the difference between
		# reading the whole history to show a month of it and reading a month
		self.write('2026-01-01T10-00-00-Antigo', report(at = '2026-01-01T10:00:00'))
		self.write('2026-09-09T19-26-39-Novo', report(at = '2026-09-09T19:26:39'))
		since = history._epoch_ms('2026-09-01T00:00:00')
		cases, _observables, _truncated = history.disk_records(self.root, since_ms = since)
		self.assertEqual(len(cases), 1)

	def test_an_unreadable_report_is_skipped_rather_than_failing_the_screen(self):
		folder = os.path.join(self.root, '2026-09-09T19-26-39-Truncado')
		os.makedirs(folder)
		with io.open(os.path.join(folder, 'report.json'), 'w', encoding = 'utf-8') as handle:
			handle.write('{"subject": "cortado no meio"')
		self.write('2026-09-09T19-27-00-Inteiro', report())
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(len(cases), 1)

	def test_a_stray_folder_is_ignored(self):
		os.makedirs(os.path.join(self.root, 'qualquer-coisa'))
		self.write('2026-09-09T19-26-39-Fatura', report())
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(len(cases), 1)

	def test_a_folder_that_does_not_exist_answers_empty_rather_than_raising(self):
		cases, observables, truncated = history.disk_records(os.path.join(self.root, 'nao-existe'))
		self.assertEqual((cases, observables, truncated), ([], {}, False))

	def test_the_folder_name_dates_a_report_whose_timestamp_is_unreadable(self):
		broken = report()
		broken['analyzedAt'] = 'ontem de manhã'
		self.write('2026-09-09T19-26-39-Fatura', broken)
		cases, _observables, _truncated = history.disk_records(self.root)
		self.assertEqual(cases[0]['startDate'], history._epoch_ms('2026-09-09T19:26:39'))

	def test_the_limit_is_reported_rather_than_silently_applied(self):
		for hour in range(10, 15):
			self.write('2026-09-09T{0}-00-00-Fatura'.format(hour), report(at = '2026-09-09T{0}:00:00'.format(hour)))
		cases, _observables, truncated = history.disk_records(self.root, limit = 2)
		self.assertEqual(len(cases), 2)
		self.assertTrue(truncated)


class RecordIdentity(unittest.TestCase):

	def test_a_record_says_which_source_holds_it(self):
		self.assertEqual(history.split_id('disk:2026-09-09T19-26-39-Fatura'),
			(history.DISK, '2026-09-09T19-26-39-Fatura'))
		self.assertEqual(history.split_id('jira:SOC-142'), (history.JIRA, 'SOC-142'))

	def test_a_bare_reference_is_still_a_thehive_case(self):
		# It is what an analyst reads off a case and types into the chat box, and
		# what every link made before there were several sources says
		self.assertEqual(history.split_id('27'), (history.THEHIVE, '27'))
		self.assertEqual(history.split_id('~503816'), (history.THEHIVE, '~503816'))

	def test_the_row_of_a_thehive_case_still_answers_to_its_number(self):
		case = {'_id': '~503816', 'number': 27, 'source': 'thehive'}
		self.assertEqual(ci.record_ref(case), '27')
		self.assertEqual(ci.record_label(case), 'CASE #27')

	def test_a_disk_record_is_named_for_where_it_is(self):
		case = {'_id': 'disk:2026-09-09T19-26-39-Fatura', 'source': 'disk', 'number': None}
		self.assertEqual(ci.record_ref(case), 'disk:2026-09-09T19-26-39-Fatura')
		self.assertEqual(ci.record_label(case), 'DISCO')

	def test_a_jira_record_is_named_by_its_issue_key(self):
		case = {'_id': 'jira:SOC-142', 'source': 'jira', 'ref': 'SOC-142', 'number': None}
		self.assertEqual(ci.record_label(case), 'SOC-142')


class OneAnalysisInTwoPlaces(unittest.TestCase):
	"""TheHive and disk both enabled means one analysis written twice."""

	def hive(self, case_id, number):
		return {'_id': case_id, 'number': number, 'source': history.THEHIVE,
			'title': 'Fatura', 'startDate': 1000}

	def disk(self, name, case_ref = ''):
		return {'_id': history.record_id(history.DISK, name), 'source': history.DISK,
			'ref': name, 'title': 'Fatura', 'startDate': 1000, 'caseRef': case_ref}

	def test_the_disk_copy_of_a_thehive_case_is_dropped(self):
		# Two rows for one analyzed email would also report double the traffic the
		# mailbox actually saw, on a chart somebody plans headcount from
		kept = history.dedupe([self.hive('~503816', 27), self.disk('2026-09-09T19-26-39-Fatura', '27')])
		self.assertEqual([case['source'] for case in kept], [history.THEHIVE])

	def test_the_thehive_row_is_the_one_kept(self):
		# It is the one an analyst can reassign, comment on and close
		kept = history.dedupe([self.disk('2026-09-09T19-26-39-Fatura', '27'), self.hive('~503816', 27)])
		self.assertEqual(len(kept), 1)
		self.assertEqual(kept[0]['source'], history.THEHIVE)

	def test_a_disk_record_with_no_thehive_case_survives(self):
		kept = history.dedupe([self.hive('~503816', 27), self.disk('2026-09-09T19-30-00-Outra')])
		self.assertEqual(len(kept), 2)

	def test_records_are_never_merged_on_a_guess(self):
		# Same subject, same minute, no caseRef: two genuinely separate reports of
		# the same campaign, and collapsing them would hide one
		kept = history.dedupe([self.disk('2026-09-09T19-26-39-Fatura'), self.disk('2026-09-09T19-26-40-Fatura')])
		self.assertEqual(len(kept), 2)


class MergedHistory(unittest.TestCase):

	def record(self, source, ref, started):
		return {'_id': history.record_id(source, ref), 'source': source, 'ref': ref,
			'title': ref, 'startDate': started, 'caseRef': ''}

	def test_every_source_lands_in_one_list_newest_first(self):
		disk = ([self.record(history.DISK, 'a', 300)], {'disk:a': []}, False)
		hive = ([self.record(history.THEHIVE, 'b', 500)], {}, False)
		cases, observables, truncated = history.merge([disk, hive], None, 100)
		self.assertEqual([case['ref'] for case in cases], ['b', 'a'])
		self.assertIn('disk:a', observables)
		self.assertFalse(truncated)

	def test_a_truncated_source_truncates_the_history(self):
		# Half a window presented as the whole one is how a report sits unseen
		disk = ([self.record(history.DISK, 'a', 300)], {}, True)
		cases, _observables, truncated = history.merge([disk], None, 100)
		self.assertTrue(truncated)

	def test_the_window_is_applied_across_the_sources(self):
		disk = ([self.record(history.DISK, 'velho', 100)], {}, False)
		hive = ([self.record(history.THEHIVE, 'novo', 900)], {}, False)
		cases, _observables, _truncated = history.merge([disk, hive], 500, 100)
		self.assertEqual([case['ref'] for case in cases], ['novo'])

	def test_no_source_at_all_is_an_empty_history_not_an_error(self):
		cases, observables, truncated = history.merge([], None, 100)
		self.assertEqual((cases, observables, truncated), ([], {}, False))


class Detail(DiskFolder):

	def test_the_detail_carries_the_body_and_the_llm_assessment(self):
		self.write('2026-09-09T19-26-39-Fatura',
			report(tactics = ['urgency'], risk = 'High', observables = [observable('falso.net')]))
		loaded = history.read_report(
			os.path.join(self.root, '2026-09-09T19-26-39-Fatura', 'report.json'))
		detail = history.report_detail(loaded, history.DISK, '2026-09-09T19-26-39-Fatura')
		self.assertEqual(detail['body'], 'corpo do e-mail')
		self.assertIn('High', detail['llmSummary'])
		self.assertEqual(len(detail['observables']), 1)

	def test_a_report_without_an_llm_assessment_says_nothing_rather_than_guessing(self):
		self.write('2026-09-09T19-26-39-Fatura', report())
		loaded = history.read_report(
			os.path.join(self.root, '2026-09-09T19-26-39-Fatura', 'report.json'))
		detail = history.report_detail(loaded, history.DISK, '2026-09-09T19-26-39-Fatura')
		self.assertEqual(detail['llmSummary'], '')


if __name__ == '__main__':
	unittest.main()
