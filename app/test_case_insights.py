"""Tests for the aggregation of the analysis history.

case_insights.py has no Flask, eventlet or requests dependency precisely so it
can be exercised here without a live TheHive. The routes that wrap it are thin
I/O; the arithmetic that ends up on an executive dashboard is what is worth
pinning down.

Run with:  python -m unittest test_case_insights   (from the app/ directory)
"""

import unittest

import case_insights as ci


def case(number, verdict = 'open', started = 1_700_000_000_000, title = 'Assunto',
	tags = None, case_id = None):
	"""A TheHive case as the query API returns it, reduced to what is read.

	`verdict` takes the shape of the real fields: 'open' leaves the case open,
	the others close it with the matching resolutionStatus.
	"""
	built = {
		'_id': case_id or '~{0}'.format(number),
		'number': number,
		'title': title,
		'startDate': started,
		'tags': ['email', 'ThePhish'] if tags is None else tags
	}
	if verdict == 'open':
		built['status'] = 'Open'
	elif verdict == 'malicious':
		built['status'] = 'Resolved'
		built['resolutionStatus'] = 'TruePositive'
	elif verdict == 'safe':
		built['status'] = 'Resolved'
		built['resolutionStatus'] = 'FalsePositive'
	elif verdict == 'other':
		built['status'] = 'Resolved'
		built['resolutionStatus'] = 'Indeterminate'
	return built


def observable(value, data_type = 'mail', ioc = False, tags = None):
	return {'data': value, 'dataType': data_type, 'ioc': ioc, 'tags': tags or []}


def ci_observable_with_tag(value, tag):
	return observable(value, 'mail', tags = ['email', 'email_header', tag])


def sender_observable(address):
	# The casing case_from_email actually writes: it appends the header name, and
	# RFC 5322 spells that one "From"
	return observable(address, 'mail', tags = ['email', 'email_header', 'email_header_From'])


class VerdictMapping(unittest.TestCase):

	def test_resolution_status_decides_a_closed_case(self):
		self.assertEqual(ci.case_verdict(case(1, 'malicious')), 'Malicious')
		self.assertEqual(ci.case_verdict(case(2, 'safe')), 'Safe')

	def test_an_open_case_is_pending_for_the_analyst(self):
		self.assertEqual(ci.case_verdict(case(3, 'open')), 'Suspicious')

	def test_a_case_closed_by_a_human_under_another_resolution_is_not_reinterpreted(self):
		# Folding Indeterminate into Safe or Malicious would misreport an analyst's
		# decision, so it keeps its own bucket
		self.assertEqual(ci.case_verdict(case(4, 'other')), 'Other')

	def test_a_case_with_no_status_at_all_is_treated_as_pending(self):
		self.assertEqual(ci.case_verdict({}), 'Suspicious')


class SubjectNormalization(unittest.TestCase):

	def test_reply_and_forward_prefixes_are_stripped(self):
		self.assertEqual(ci.normalize_subject('Re: Fatura em aberto'), 'Fatura em aberto')
		self.assertEqual(ci.normalize_subject('ENC: Fatura em aberto'), 'Fatura em aberto')
		self.assertEqual(ci.normalize_subject('Re: Fwd: Fatura em aberto'), 'Fatura em aberto')

	def test_per_recipient_numbers_collapse_so_one_campaign_groups_together(self):
		first = ci.normalize_subject('Documento aguardando assinatura (contrato #77120)')
		second = ci.normalize_subject('Documento aguardando assinatura (contrato #88431)')
		self.assertEqual(first, second)

	def test_a_short_number_is_kept_because_it_carries_meaning(self):
		self.assertIn('365', ci.normalize_subject('Alerta Microsoft 365'))

	def test_it_survives_a_missing_title(self):
		self.assertEqual(ci.normalize_subject(None), '')


class CaseSelection(unittest.TestCase):

	def test_cases_without_the_application_tag_are_dropped(self):
		raw = [case(1), case(2, tags = ['email', 'manual'])]
		cases, _ = ci.filter_cases(raw, 'ThePhish', None, 10)
		self.assertEqual([c['number'] for c in cases], [1])

	def test_cases_older_than_the_window_are_dropped(self):
		raw = [case(1, started = 2000), case(2, started = 500)]
		cases, _ = ci.filter_cases(raw, 'ThePhish', 1000, 10)
		self.assertEqual([c['number'] for c in cases], [1])

	def test_results_come_back_newest_first_whatever_the_query_returned(self):
		raw = [case(1, started = 100), case(2, started = 300), case(3, started = 200)]
		cases, _ = ci.filter_cases(raw, 'ThePhish', None, 10)
		self.assertEqual([c['number'] for c in cases], [2, 3, 1])

	def test_exceeding_the_limit_is_reported_rather_than_silently_dropped(self):
		raw = [case(n, started = n) for n in range(1, 6)]
		cases, truncated = ci.filter_cases(raw, 'ThePhish', None, 3)
		self.assertEqual(len(cases), 3)
		self.assertTrue(truncated)

	def test_a_non_dict_entry_does_not_break_the_pass(self):
		cases, _ = ci.filter_cases([case(1), None, 'garbage'], 'ThePhish', None, 10)
		self.assertEqual(len(cases), 1)

	def test_no_tag_configured_keeps_every_case(self):
		raw = [case(1, tags = ['email']), case(2, tags = [])]
		cases, _ = ci.filter_cases(raw, '', None, 10)
		self.assertEqual(len(cases), 2)


class QueryFallbacks(unittest.TestCase):

	def test_the_richest_query_carries_the_window_the_tag_the_sort_and_the_page(self):
		first = ci.build_case_queries(1000, 50, 'ThePhish')[0]
		names = [step['_name'] for step in first]
		self.assertEqual(names, ['listCase', 'filter', 'sort', 'page'])
		filters = first[1]['_and']
		self.assertIn({'_gte': {'_field': 'startDate', '_value': 1000}}, filters)
		# O filtro de etiqueta e um _or sobre os marcadores que este produto ja
		# usou. Sem isso, trocar case.tags nas Configuracoes esvazia o painel: as
		# consultas passam a procurar a etiqueta nova e nenhum caso antigo a tem
		alternativas = [item for item in filters if '_or' in item]
		self.assertTrue(alternativas, 'a etiqueta deve virar um _or de marcadores')
		self.assertIn({'_field': 'tags', '_value': 'ThePhish'}, alternativas[0]['_or'])

	def test_the_candidates_degrade_to_a_bare_list(self):
		candidates = ci.build_case_queries(1000, 50, 'ThePhish')
		self.assertEqual(candidates[-1], [{'_name': 'listCase'}])

	def test_with_no_window_and_no_tag_there_is_nothing_to_filter_on(self):
		candidates = ci.build_case_queries(None, 50, '')
		for query in candidates:
			self.assertNotIn('filter', [step['_name'] for step in query])


class CaseRow(unittest.TestCase):

	def test_the_sender_comes_from_the_from_header_observable(self):
		row = ci.case_row(case(1), [
			observable('empresa.com.br', 'domain'),
			sender_observable('golpe@dominio-falso.net')
		])
		self.assertEqual(row['sender'], 'golpe@dominio-falso.net')

	def test_the_sender_tag_is_matched_however_it_is_cased(self):
		# The tag is written 'email_header_From' and was compared against a
		# lower-case constant, so it matched nothing - for every case, on every
		# screen, for as long as the tag existed. The row said "(remetente nao
		# registrado)" over an analysis that had recorded the sender, and the
		# executive dashboard's senders card stayed empty, which looks exactly
		# like a quiet month
		row = ci.case_row(case(1), [
			ci_observable_with_tag('golpe@falso.net', 'email_header_From'),
		])
		self.assertEqual(row['sender'], 'golpe@falso.net')
		lowered = ci.case_row(case(1), [
			ci_observable_with_tag('golpe@falso.net', 'email_header_from'),
		])
		self.assertEqual(lowered['sender'], 'golpe@falso.net')

	def test_a_case_with_no_observables_still_produces_a_row(self):
		row = ci.case_row(case(1), [])
		self.assertEqual(row['sender'], '')
		self.assertEqual(row['iocCount'], 0)
		self.assertEqual(row['observableCount'], 0)

	def test_a_source_that_cannot_answer_reports_unknown_rather_than_zero(self):
		# None is not an empty list. A Jira issue keeps the report as prose
		# written for a human, so its observables are unknown - and "0 IOCs" on a
		# SOC screen is a claim somebody will act on
		row = ci.case_row(case(1), None)
		self.assertIsNone(row['observableCount'])
		self.assertIsNone(row['iocCount'])
		self.assertEqual(row['iocs'], [])

	def test_only_observables_marked_as_ioc_are_counted(self):
		row = ci.case_row(case(1), [
			observable('1.2.3.4', 'ip', ioc = True),
			observable('5.6.7.8', 'ip', ioc = False)
		])
		self.assertEqual(row['iocCount'], 1)
		self.assertEqual(row['iocs'][0]['value'], '1.2.3.4')

	def test_a_file_observable_falls_back_to_its_attachment_name(self):
		row = ci.case_row(case(1), [
			{'dataType': 'file', 'ioc': True, 'attachment': {'name': 'certificado.html'}}
		])
		self.assertEqual(row['iocs'][0]['value'], 'certificado.html')

	def test_the_generic_email_tag_is_not_shown_as_a_case_label(self):
		row = ci.case_row(case(1, tags = ['email', 'ThePhish']), [])
		self.assertEqual(row['tags'], ['ThePhish'])


class IocDrillThrough(unittest.TestCase):

	def test_a_case_carrying_the_indicator_matches(self):
		self.assertTrue(ci.has_observable([observable('102.89.34.117', 'ip', ioc = True)], '102.89.34.117'))

	def test_a_case_without_it_does_not(self):
		self.assertFalse(ci.has_observable([observable('8.8.8.8', 'ip')], '102.89.34.117'))

	def test_a_domain_also_finds_the_urls_built_on_it(self):
		# Following a campaign indicator across cases is the point, so the match is
		# a substring rather than an equality
		urls = [observable('https://vpn-falso.net/auth/revalidar?id=8f21c', 'url', ioc = True)]
		self.assertTrue(ci.has_observable(urls, 'vpn-falso.net'))

	def test_the_match_ignores_case(self):
		self.assertTrue(ci.has_observable([observable('VPN-Falso.NET', 'domain')], 'vpn-falso.net'))

	def test_an_attachment_name_is_searchable_too(self):
		attachment = [{'dataType': 'file', 'ioc': True, 'attachment': {'name': 'certificado_vpn.html'}}]
		self.assertTrue(ci.has_observable(attachment, 'certificado_vpn'))

	def test_an_empty_needle_never_matches(self):
		# Otherwise an empty ioc= parameter would silently match every case
		self.assertFalse(ci.has_observable([observable('anything', 'ip')], ''))
		self.assertFalse(ci.has_observable([observable('anything', 'ip')], None))

	def test_a_case_with_no_observables_does_not_match(self):
		self.assertFalse(ci.has_observable(None, 'anything'))


class Aggregation(unittest.TestCase):

	def setUp(self):
		# Two days of traffic: 3 malicious, 1 pending, 2 safe
		day_one = 1_700_000_000_000
		day_two = day_one + 86400 * 1000
		self.cases = [
			case(1, 'malicious', day_one, 'Acesso VPN'),
			case(2, 'malicious', day_one, 'Acesso VPN'),
			case(3, 'safe', day_one, 'Newsletter'),
			case(4, 'malicious', day_two, 'Acesso VPN'),
			case(5, 'open', day_two, 'Reembolso pendente'),
			case(6, 'safe', day_two, 'Newsletter')
		]
		# The same IP is reused across the three malicious cases
		self.observables = {
			'~1': [sender_observable('ti@vpn-falso.net'), observable('102.89.34.117', 'ip', ioc = True)],
			'~2': [sender_observable('ti@vpn-falso.net'), observable('102.89.34.117', 'ip', ioc = True)],
			'~4': [sender_observable('ti@vpn-falso.net'), observable('102.89.34.117', 'ip', ioc = True)],
			'~5': [sender_observable('rh@beneficios.info')]
		}

	def aggregate(self):
		return ci.aggregate(self.cases, self.observables, '30d')

	def test_the_kpis_count_what_actually_happened(self):
		kpis = self.aggregate()['kpis']
		self.assertEqual(kpis['analyzed'], 6)
		self.assertEqual(kpis['malicious'], 3)
		self.assertEqual(kpis['pending'], 1)
		self.assertEqual(kpis['safe'], 2)
		self.assertEqual(kpis['maliciousRate'], 50.0)

	def test_the_daily_volume_splits_threats_from_legitimate_traffic(self):
		daily = self.aggregate()['daily']
		self.assertEqual(len(daily), 2)
		self.assertEqual(daily[0]['threat'], 2)   # two malicious on day one
		self.assertEqual(daily[0]['safe'], 1)
		self.assertEqual(daily[1]['threat'], 2)   # one malicious + one pending
		self.assertEqual(daily[1]['safe'], 1)

	def test_the_daily_series_is_chronological(self):
		daily = self.aggregate()['daily']
		self.assertEqual([bucket['date'] for bucket in daily], sorted(bucket['date'] for bucket in daily))

	def test_a_pending_case_counts_as_a_threat_not_as_safe(self):
		# It is exactly the case an analyst still has to judge; putting it on the
		# "legitimate" side of the chart would understate the backlog
		daily = self.aggregate()['daily']
		self.assertEqual(daily[1]['threat'], 2)

	def test_senders_are_ranked_and_carry_their_malicious_share(self):
		senders = self.aggregate()['topSenders']
		self.assertEqual(senders[0]['value'], 'ti@vpn-falso.net')
		self.assertEqual(senders[0]['count'], 3)
		self.assertEqual(senders[0]['malicious'], 3)

	def test_safe_cases_never_contribute_a_sender(self):
		# Only threat cases are fetched, so a legitimate sender must not appear
		values = [s['value'] for s in self.aggregate()['topSenders']]
		self.assertNotIn('newsletter@empresa.com.br', values)

	def test_an_ioc_reused_across_cases_is_reported_as_a_campaign(self):
		recurring = self.aggregate()['recurringIoc']
		self.assertIsNotNone(recurring)
		self.assertEqual(recurring['value'], '102.89.34.117')
		self.assertEqual(recurring['cases'], 3)

	def test_the_ioc_count_is_distinct_cases_not_raw_occurrences(self):
		# The same IOC twice inside one case is one case, not two
		self.observables['~1'].append(observable('102.89.34.117', 'ip', ioc = True))
		self.assertEqual(self.aggregate()['recurringIoc']['cases'], 3)

	def test_an_ioc_below_the_campaign_threshold_is_not_announced(self):
		self.observables = {'~1': [observable('9.9.9.9', 'ip', ioc = True)]}
		self.assertIsNone(self.aggregate()['recurringIoc'])

	def test_subjects_group_after_normalization(self):
		subjects = self.aggregate()['topSubjects']
		self.assertEqual(subjects[0]['label'], 'Acesso VPN')
		self.assertEqual(subjects[0]['count'], 3)

	def test_every_verdict_bucket_is_present_even_at_zero(self):
		verdicts = {entry['key']: entry['count'] for entry in self.aggregate()['verdicts']}
		self.assertEqual(set(verdicts), {'Malicious', 'Suspicious', 'Safe', 'Other'})
		self.assertEqual(verdicts['Other'], 0)

	def test_an_empty_window_produces_zeros_and_not_a_crash(self):
		payload = ci.aggregate([], {}, '30d')
		self.assertEqual(payload['kpis']['analyzed'], 0)
		self.assertEqual(payload['kpis']['maliciousRate'], 0.0)
		self.assertEqual(payload['daily'], [])
		self.assertEqual(payload['topSenders'], [])
		self.assertIsNone(payload['recurringIoc'])

	def test_missing_observables_for_a_case_are_not_an_error(self):
		payload = ci.aggregate(self.cases, {}, '30d')
		self.assertEqual(payload['topSenders'], [])
		self.assertEqual(payload['kpis']['malicious'], 3)


class AnalysisTags(unittest.TestCase):
	"""The department, the tactics and the risk level travel as case tags.

	They are the only reason the executive cards can be built from the case list
	alone, so what counts is that reading them back is exact: a tag that is not
	there must never become a bucket, and a tag meant as a field must never leak
	into the chips an analyst reads.
	"""

	def tagged(self, *tags):
		return case(1, tags = ['email', 'ThePhish'] + list(tags))

	def test_the_fields_are_read_back_out_of_the_tags(self):
		one = self.tagged('dept:Jurídico', 'risk:High', 'se:detected', 'tactic:urgency', 'tactic:authority')
		self.assertEqual(ci.case_department(one), 'Jurídico')
		self.assertEqual(ci.case_risk(one), 'High')
		self.assertEqual(ci.case_tactics(one), ['urgency', 'authority'])

	def test_a_case_without_them_reports_nothing_rather_than_a_default(self):
		one = self.tagged()
		self.assertEqual(ci.case_department(one), '')
		self.assertEqual(ci.case_risk(one), '')
		self.assertEqual(ci.case_tactics(one), [])

	def test_the_field_tags_are_kept_out_of_the_tags_shown_to_the_analyst(self):
		one = self.tagged('dept:RH', 'risk:Low', 'se:detected', 'tactic:fear', 'campanha-x')
		self.assertEqual(ci.display_tags(one), ['ThePhish', 'campanha-x'])

	def test_a_department_name_with_spaces_survives_the_round_trip(self):
		one = self.tagged('dept:Segurança da Informação')
		self.assertEqual(ci.case_department(one), 'Segurança da Informação')


class FixedWindows(unittest.TestCase):

	NOW = 1_700_000_000_000
	HOUR = 3600 * 1000
	DAY = 24 * HOUR

	def windows(self, cases, truncated = False):
		return {w['key']: w for w in ci.count_windows(cases, truncated, self.NOW)['windows']}

	def test_each_window_counts_only_confirmed_phishing_inside_it(self):
		windows = self.windows([
			case(1, 'malicious', self.NOW - 2 * self.HOUR),
			case(2, 'malicious', self.NOW - 3 * self.DAY),
			case(3, 'open', self.NOW - self.HOUR),
			case(4, 'safe', self.NOW - self.HOUR),
			case(5, 'malicious', self.NOW - 40 * self.DAY)
		])
		self.assertEqual([windows[key]['malicious'] for key in ci.WINDOW_KEYS], [1, 2, 2, 2, 3, 3])

	def test_the_comparison_is_against_the_window_right_before(self):
		windows = self.windows([
			case(1, 'malicious', self.NOW - self.HOUR),
			case(2, 'malicious', self.NOW - 30 * self.HOUR),
			case(3, 'malicious', self.NOW - 40 * self.HOUR)
		])
		self.assertEqual(windows['1d']['malicious'], 1)
		self.assertEqual(windows['1d']['previous'], 2)

	def test_a_truncated_history_marks_what_it_did_not_reach(self):
		# The oldest case read is 10 days old: the 7-day window is whole, the
		# 7 days before it and the 15-day window are not
		windows = self.windows([
			case(1, 'malicious', self.NOW - self.HOUR),
			case(2, 'malicious', self.NOW - 10 * self.DAY)
		], truncated = True)
		self.assertTrue(windows['7d']['complete'])
		self.assertIsNone(windows['7d']['previous'])
		self.assertFalse(windows['15d']['complete'])
		self.assertEqual(windows['1d']['previous'], 0)

	def test_an_untruncated_empty_history_is_a_measured_zero(self):
		windows = self.windows([])
		self.assertTrue(all(w['malicious'] == 0 and w['previous'] == 0 and w['complete']
			for w in windows.values()))

	def test_a_case_with_no_date_is_counted_apart(self):
		payload = ci.count_windows([case(1, 'malicious', 0)], False, self.NOW)
		self.assertEqual(payload['undated'], 1)
		self.assertEqual(payload['windows'][-1]['malicious'], 0)

	def test_the_windows_are_selectable_ranges(self):
		for key in ci.WINDOW_KEYS:
			self.assertEqual(ci.normalize_range(key), key)


class SignalFilter(unittest.TestCase):

	def test_the_filter_opens_exactly_what_the_chart_counted(self):
		cases = [
			case(1, tags = ['auth:dmarc=fail']),
			case(2, tags = ['auth:dmarc=softfail']),
			case(3, tags = ['auth:dmarc=pass']),
			case(4, tags = ['auth:dmarc=none']),
			case(5, tags = [])
		]
		dmarc = ci.count_authentication(cases)[2]
		for kind in ci.AUTH_BUCKETS:
			picked = [c for c in cases if ci.matches_signal(c, auth = 'dmarc:' + kind)]
			self.assertEqual(len(picked), dmarc[kind], kind)
		self.assertEqual(dmarc['fail'], 2)

	def test_an_unrecorded_case_is_in_no_slice(self):
		for kind in ci.AUTH_BUCKETS:
			self.assertFalse(ci.matches_signal(case(1, tags = []), auth = 'spf:' + kind))

	def test_the_tier_filter_picks_only_that_band(self):
		self.assertTrue(ci.matches_signal(case(1, tags = ['tier:phishing']), tier = 'phishing'))
		self.assertFalse(ci.matches_signal(case(2, tags = ['tier:spam']), tier = 'phishing'))
		self.assertFalse(ci.matches_signal(case(3, tags = []), tier = 'phishing'))

	def test_a_malformed_filter_matches_nothing(self):
		scored = case(1, tags = ['auth:spf=pass', 'tier:legitimate'])
		self.assertFalse(ci.matches_signal(scored, auth = 'spf'))
		self.assertFalse(ci.matches_signal(scored, auth = 'xyz:pass'))
		self.assertFalse(ci.matches_signal(scored, auth = 'spf:quase'))

	def test_no_filter_keeps_every_case(self):
		self.assertTrue(ci.matches_signal(case(1, tags = [])))


class DepartmentAggregation(unittest.TestCase):

	def cases(self):
		return [
			case(1, 'malicious', tags = ['email', 'dept:Jurídico']),
			case(2, 'safe', tags = ['email', 'dept:Jurídico']),
			case(3, 'malicious', tags = ['email', 'dept:RH']),
			case(4, 'open', tags = ['email'])
		]

	def test_every_report_counts_not_only_the_malicious_ones(self):
		# "Most targeted department" is about which desks the attempts reach; a
		# report that turned out legitimate is still an attempt that reached one
		ranked, _unattributed = ci.count_departments(self.cases())
		self.assertEqual([(d['label'], d['count'], d['malicious']) for d in ranked],
			[('Jurídico', 2, 1), ('RH', 1, 1)])

	def test_a_report_no_rule_claimed_is_counted_apart(self):
		_ranked, unattributed = ci.count_departments(self.cases())
		self.assertEqual(unattributed, 1)

	def test_the_payload_carries_the_ranking_and_the_unattributed_count(self):
		payload = ci.aggregate(self.cases(), {}, '30d')
		self.assertEqual(payload['topDepartments'][0]['label'], 'Jurídico')
		self.assertEqual(payload['departmentsTotal'], 2)
		self.assertEqual(payload['departmentsUnattributed'], 1)


class TacticAggregation(unittest.TestCase):

	def cases(self):
		return [
			case(1, tags = ['email', 'tactic:urgency', 'tactic:credential_harvesting']),
			case(2, tags = ['email', 'tactic:urgency']),
			case(3, tags = ['email'])
		]

	def test_tactics_are_counted_across_the_window(self):
		self.assertEqual(ci.count_tactics(self.cases()),
			[{'key': 'urgency', 'count': 2}, {'key': 'credential_harvesting', 'count': 1}])

	def test_a_window_with_no_tactic_reports_an_empty_ranking(self):
		payload = ci.aggregate([case(1)], {}, '30d')
		self.assertEqual(payload['topTactics'], [])
		self.assertEqual(payload['tacticsTotal'], 0)


class LlmSummary(unittest.TestCase):

	def cases(self):
		return [
			case(1, tags = ['email', 'risk:Critical', 'se:detected']),
			case(2, tags = ['email', 'risk:High', 'se:detected']),
			case(3, tags = ['email', 'risk:Low']),
			case(4, tags = ['email'])
		]

	def test_the_denominator_is_what_the_model_actually_judged(self):
		# An instance whose LLM was off for part of the window must not read as an
		# instance where the model looked and found nothing
		summary = ci.summarize_llm(self.cases())
		self.assertEqual(summary['assessed'], 3)
		self.assertEqual(summary['notAssessed'], 1)

	def test_social_engineering_and_high_risk_are_counted(self):
		summary = ci.summarize_llm(self.cases())
		self.assertEqual(summary['socialEngineering'], 2)
		self.assertEqual(summary['highRisk'], 2)

	def test_every_risk_level_is_present_even_at_zero(self):
		levels = {entry['key']: entry['count'] for entry in ci.summarize_llm(self.cases())['risk']}
		self.assertEqual(levels, {'Critical': 1, 'High': 1, 'Medium': 0, 'Low': 1})

	def test_a_window_the_model_never_saw_reports_zero_assessed(self):
		summary = ci.aggregate([case(1), case(2)], {}, '30d')['llmInsights']
		self.assertEqual(summary['assessed'], 0)
		self.assertEqual(summary['socialEngineering'], 0)


class Ranges(unittest.TestCase):

	def test_all_means_no_lower_bound(self):
		self.assertIsNone(ci.range_to_since_ms('all'))

	def test_a_known_range_is_that_many_days_back_in_milliseconds(self):
		now = 1_700_000_000.0
		self.assertEqual(ci.range_to_since_ms('7d', now = now), int((now - 7 * 86400) * 1000))

	def test_an_unknown_range_falls_back_to_the_default_rather_than_failing(self):
		now = 1_700_000_000.0
		self.assertEqual(ci.range_to_since_ms('bogus', now = now), ci.range_to_since_ms(ci.DEFAULT_RANGE, now = now))
		self.assertEqual(ci.normalize_range('bogus'), ci.DEFAULT_RANGE)

	def test_all_is_a_valid_range(self):
		self.assertEqual(ci.normalize_range('all'), 'all')


class WhyTheHistoryIsEmpty(unittest.TestCase):
	"""An empty screen has several causes and they call for opposite actions.

	All of them looked the same: "Nenhum caso corresponde aos filtros", shown
	under a mailbox that had just finished analyzing an email. That reads as a
	broken pipeline, and it sent an analyst through the log of an analysis that
	had in fact run, scored and been recorded exactly as designed - to a
	destination these screens do not read.
	"""

	def test_a_history_nothing_records_says_so(self):
		notice = ci.empty_reason(recording = False, outside_window = 0, range_key = '30d')
		self.assertIn('Nenhum destino', notice)
		self.assertIn('Destinos', notice)

	def test_not_recording_wins_over_the_window(self):
		# With nothing recording, widening the range finds nothing either: saying
		# so first is what stops the analyst from chasing the wrong control
		notice = ci.empty_reason(recording = False, outside_window = 40, range_key = '7d')
		self.assertIn('Nenhum destino', notice)

	def test_cases_just_outside_the_window_are_named_with_their_count(self):
		notice = ci.empty_reason(recording = True, outside_window = 92, range_key = '30d')
		self.assertIn('92', notice)
		self.assertIn('30', notice)

	def test_the_number_of_days_follows_the_selected_range(self):
		self.assertIn('7', ci.empty_reason(True, 5, '7d'))
		self.assertIn('180', ci.empty_reason(True, 5, '180d'))

	def test_an_empty_whole_history_says_nothing_at_all(self):
		# A fresh install has no cases anywhere. Inviting the analyst to widen a
		# range onto nothing would be worse than the silence
		self.assertEqual(ci.empty_reason(recording = True, outside_window = 0, range_key = '30d'), '')

	def test_the_widest_range_is_never_told_to_widen(self):
		# 'all' already covers everything; the cases counted outside it are the
		# ones past MAX_CASES, and no range change reaches them
		self.assertEqual(ci.empty_reason(recording = True, outside_window = 92, range_key = 'all'), '')


if __name__ == '__main__':
	unittest.main()
