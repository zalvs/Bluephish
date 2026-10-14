"""A contagem de observáveis marcados e o veredito que sai dela.

É o primeiro passo do veredito em `run_analysis.terminate_analysis`: antes de a
IA, o score ou a whitelist opinarem, os relatórios dos analisadores dizem se o
e-mail tem observável malicioso, suspeito ou nenhum. Um erro aqui muda o veredito
sem levantar exceção nem deixar rastro no log, então o comportamento fica fixado.

Rodar com:  python -m unittest test_flagged_observables   (a partir de app/)
"""

import unittest

import run_analysis


def observable(observable_id):
	return {'id': observable_id, 'ioc': False}


def report(observable_id, result):
	return {'observable_id': observable_id, 'analyzer_result': result}


class CountFlaggedObservables(unittest.TestCase):

	def test_returns_zero_for_both_when_there_is_no_report(self):
		observables = [observable('a'), observable('b')]

		counts = run_analysis._count_flagged_observables(observables, [])

		self.assertEqual(counts, (0, 0))

	def test_counts_each_observable_once_however_many_reports_flag_it(self):
		observables = [observable('a')]
		reports = [report('a', 'malicious'), report('a', 'malicious'), report('a', 'malicious')]

		counts = run_analysis._count_flagged_observables(observables, reports)

		self.assertEqual(counts, (1, 0))

	def test_an_observable_with_both_kinds_of_report_counts_in_both(self):
		observables = [observable('a')]
		reports = [report('a', 'suspicious'), report('a', 'malicious')]

		counts = run_analysis._count_flagged_observables(observables, reports)

		self.assertEqual(counts, (1, 1))

	def test_ignores_reports_that_belong_to_another_observable(self):
		observables = [observable('a')]
		reports = [report('b', 'malicious'), report('c', 'suspicious')]

		counts = run_analysis._count_flagged_observables(observables, reports)

		self.assertEqual(counts, (0, 0))

	def test_info_and_safe_results_do_not_flag_anything(self):
		observables = [observable('a')]
		reports = [report('a', 'info'), report('a', 'safe')]

		counts = run_analysis._count_flagged_observables(observables, reports)

		self.assertEqual(counts, (0, 0))

	def test_marks_only_the_malicious_observables_as_ioc(self):
		malicious, suspicious, clean = observable('a'), observable('b'), observable('c')
		reports = [report('a', 'malicious'), report('b', 'suspicious'), report('c', 'info')]

		run_analysis._count_flagged_observables([malicious, suspicious, clean], reports)

		self.assertTrue(malicious['ioc'])
		self.assertFalse(suspicious['ioc'])
		self.assertFalse(clean['ioc'])

	def test_counts_across_several_observables(self):
		observables = [observable('a'), observable('b'), observable('c'), observable('d')]
		reports = [report('a', 'malicious'), report('b', 'malicious'), report('c', 'suspicious'), report('d', 'info')]

		counts = run_analysis._count_flagged_observables(observables, reports)

		self.assertEqual(counts, (2, 1))


class VerdictFromCounts(unittest.TestCase):

	def test_one_malicious_observable_makes_the_email_malicious(self):
		self.assertEqual(run_analysis._verdict_from_counts(1, 0), 'Malicious')

	def test_malicious_wins_over_suspicious(self):
		self.assertEqual(run_analysis._verdict_from_counts(1, 5), 'Malicious')

	def test_suspicious_without_malicious_makes_the_email_suspicious(self):
		self.assertEqual(run_analysis._verdict_from_counts(0, 1), 'Suspicious')

	def test_nothing_flagged_is_safe(self):
		self.assertEqual(run_analysis._verdict_from_counts(0, 0), 'Safe')


if __name__ == '__main__':
	unittest.main()
