"""The analysis history, read back from whatever destination recorded it.

For a long time these screens read TheHive and nothing else, and the module
docstring of `case_insights.py` said so as if it were a fact about the world.
It was a fact about one configuration. An installation that records to disk —
which is the whole point of the disk destination, "para quem não quer TheHive
nem Jira" — analyzed emails all day and watched "E-mails analisados" stay
empty, with the analysis running perfectly the entire time. That is not a
missing feature, it is the history screen lying about the work that was done.

So the history has **sources**, one per ticket destination, and the enabled
destinations are the ones that get read. Disk lives here because it is files;
Jira is one paged HTTP call in `tickets.read_jira()`, shaped into cases by
`thephish_app.jira_cases()`; TheHive stays in `thephish_app.py` because it
needs a green pool and a query DSL with version fallbacks.

Every source answers in the same shape `case_insights` already consumes — the
TheHive case dict plus its observables — so nothing downstream branches on
where a record came from. Two fields make that shape honest for the others:

  * `verdict`, read directly rather than decoded from a resolution status that
    only TheHive writes (see `case_insights.case_verdict`).
  * `source`, so a row can say where it is stored and the detail route knows
    who to ask for it.

What a source cannot answer, it does not answer. Jira carries the verdict, the
subject and the date as fields, and everything else as prose written for a
human; its records report `observables = None`, which is not the same as an
empty list and must not be rendered as "0 observáveis". Counting IOCs by
parsing a description would produce numbers nobody measured, on a screen a SOC
makes decisions from.
"""

import datetime
import io
import json
import os
import re

import case_insights

# Prefix on the record id, so a row says which source it came from and the
# detail route can ask that source for it again. TheHive ids keep the shape
# TheHive gave them ('~503816') and the number stays the reference an analyst
# types, because that is what is printed on the case they already have open.
DISK = 'disk'
JIRA = 'jira'
THEHIVE = 'thehive'

# Folder name written by tickets.create_disk: an ISO timestamp with the colons
# replaced, then a slug of the subject
DISK_DIR_STAMP = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-')

# A single report.json is bounded by the analysis that wrote it, but the folder
# is on disk and anything could be in it. Past this a file is skipped rather
# than read into the dashboard's memory
MAX_REPORT_BYTES = 8 * 1024 * 1024


def record_id(source, ref):
	"""The id a row carries, and the reference the detail route takes back."""
	return '{0}:{1}'.format(source, ref)


def split_id(record_ref):
	"""(source, ref) of a record id, defaulting to TheHive for a bare reference.

	A bare reference is a TheHive case number or case id. It stays bare because
	it is what an analyst reads off a case and types into the chat box, and
	because it is what every link made before there were several sources says.
	"""
	text = str(record_ref or '').strip()
	for source in (DISK, JIRA, THEHIVE):
		prefix = source + ':'
		if text.startswith(prefix):
			return source, text[len(prefix):]
	return THEHIVE, text


def _epoch_ms(text):
	"""An ISO 8601 local timestamp as epoch milliseconds, 0 when unreadable."""
	if not text:
		return 0
	try:
		parsed = datetime.datetime.strptime(str(text)[:19], '%Y-%m-%dT%H:%M:%S')
	except ValueError:
		return 0
	try:
		return int(parsed.timestamp() * 1000)
	except (OverflowError, OSError, ValueError):
		return 0


def _observables_of(report):
	"""The report's observables in the shape case_insights reads.

	`dataType`/`data` rather than `type`/`value`: that vocabulary is TheHive's,
	and translating here is what keeps every reader downstream — the row, the
	IOC ranking, the sender lookup — from having to know which destination it is
	looking at.
	"""
	observables = []
	for entry in report.get('observables') or []:
		if not isinstance(entry, dict):
			continue
		observables.append({
			'dataType': entry.get('type', ''),
			'data': str(entry.get('value', '')),
			'tags': entry.get('tags') or [],
			'ioc': bool(entry.get('ioc')),
			'message': entry.get('message') or ''
		})
	return observables


def case_from_report(report, source, ref, tags = None):
	"""One recorded analysis as the case dict the dashboards read.

	`tags` are the destination's configured tags; the facts of the analysis are
	appended from the report itself through `case_insights.analysis_tags`, which
	is the same function `tickets.py` used to write them onto a TheHive case. A
	record read back from disk therefore carries its department, its risk level
	and its tactics exactly as a TheHive case does — the executive dashboard
	does not degrade just because the SOC chose a different destination.
	"""
	configured = [tag for tag in (tags or []) if tag]
	case = {
		'_id': record_id(source, ref),
		'source': source,
		'ref': ref,
		'number': None,
		'title': str(report.get('subject') or ''),
		'verdict': str(report.get('verdict') or ''),
		'startDate': _epoch_ms(report.get('analyzedAt')),
		'tags': configured + case_insights.analysis_tags(report),
		'reporter': str(report.get('reporter') or ''),
		# Filled in when TheHive also recorded this analysis, which is what lets
		# the union drop the duplicate rather than show the same email twice
		'caseRef': str(report.get('caseRef') or '')
	}
	# A reclassification written back into the report (tickets.reclassify_disk)
	# holds on its own: an installation that loses its database, or reads this
	# folder from another one, still sees the analyst's decision
	decision = report.get('reclassification')
	if isinstance(decision, dict) and decision.get('verdict') and decision.get('id') is not None:
		case_insights.apply_decision(case, decision)
	return case


def analysis_of(report):
	"""Why this analysis reached its verdict, as fields the detail screen draws.

	Everything here was recorded when the analysis ran; nothing is re-derived.
	`verdictTrail` is None on a report written before the trail existed, and the
	screen says so instead of reconstructing which rule must have fired.
	"""
	llm = report.get('llm') if isinstance(report.get('llm'), dict) else None
	score = report.get('score') if isinstance(report.get('score'), dict) else None
	return {
		'findings': [f for f in (report.get('findings') or []) if isinstance(f, dict)],
		'verdictTrail': report.get('verdictTrail') if isinstance(report.get('verdictTrail'), list) else None,
		'llm': case_insights.llm_view(llm),
		'score': case_insights.score_view(score),
		'authentication': report.get('authentication') if isinstance(report.get('authentication'), dict) else None,
		'injection': ((report.get('promptGuard') or {}).get('injection') or None)
			if isinstance(report.get('promptGuard'), dict) else None
	}


def read_report(path):
	"""One report.json, or None when it is unreadable or not one of ours.

	A dashboard must not fail because somebody dropped a file in the folder, and
	it must not fail because an analysis was interrupted halfway through writing
	one. Either way the record is skipped: a history missing one row is worth
	more than a screen that will not load.
	"""
	try:
		if os.path.getsize(path) > MAX_REPORT_BYTES:
			return None
		with io.open(path, encoding = 'utf-8') as report_file:
			report = json.load(report_file)
	except (OSError, ValueError, UnicodeDecodeError):
		return None
	if not isinstance(report, dict) or not report.get('verdict'):
		return None
	return report


def disk_records(root, tags = None, limit = None, since_ms = None):
	"""Every analysis recorded under `root`, newest first.

	Returns (cases, observables_by_id, truncated).

	The folder name carries the timestamp the analysis was written at, so the
	listing is ordered — and windowed — by **name**, before a single file is
	opened. On a directory holding a year of analyses that is the difference
	between reading the whole history to show thirty days of it and reading
	thirty days of it.
	"""
	cases = []
	observables = {}
	try:
		names = sorted(os.listdir(root), reverse = True)
	except OSError:
		return [], {}, False

	truncated = False
	for name in names:
		# Ordered by name, so once the timestamps fall before the window every
		# remaining folder does too
		if since_ms is not None and _dir_before(name, since_ms):
			break
		if limit is not None and len(cases) >= limit:
			truncated = True
			break
		report = read_report(os.path.join(root, name, 'report.json'))
		if report is None:
			continue
		case = case_from_report(report, DISK, name, tags)
		# The folder name is the timestamp of record: a report.json with an
		# unreadable analyzedAt still lands on the right day of the chart
		if not case['startDate']:
			case['startDate'] = _dir_epoch_ms(name)
		cases.append(case)
		observables[case['_id']] = _observables_of(report)

	cases.sort(key = case_insights.case_started_at, reverse = True)
	return cases, observables, truncated


def _dir_epoch_ms(name):
	"""The timestamp in an analysis folder name, as epoch ms, 0 when absent."""
	match = DISK_DIR_STAMP.match(str(name or ''))
	if not match:
		return 0
	return _epoch_ms('{0}T{1}:{2}:{3}'.format(*match.groups()))


def _dir_before(name, since_ms):
	"""Whether this folder's name places it before the window.

	A folder whose name carries no timestamp is never skipped: it is not proof
	of being old, and dropping a record because its name is unfamiliar is how a
	history silently under-reports.
	"""
	stamp = _dir_epoch_ms(name)
	return bool(stamp) and stamp < since_ms


def report_detail(report, source, ref, tags = None):
	"""The detail payload of one recorded analysis, for the case detail screen."""
	case = case_from_report(report, source, ref, tags)
	llm = report.get('llm') or {}
	summary = ''
	if llm:
		summary = 'Social engineering analysis: risk level {0}, detected {1}. {2}'.format(
			llm.get('risk_level', '?'),
			llm.get('social_engineering_detected'),
			llm.get('justification', '') or '')[:600]
	return {
		'case': case,
		'observables': _observables_of(report),
		'llmSummary': summary,
		'analysis': analysis_of(report),
		'body': str(report.get('body') or '')
	}


def dedupe(cases):
	"""Drop the records that describe an analysis another source already carries.

	With TheHive and disk both enabled, one analyzed email is written to both
	and would be listed twice — the same subject, the same minute, two rows, and
	a verdict count that reports double the traffic the mailbox actually saw.

	The disk report records the TheHive case it was filed alongside (`caseRef`,
	filled by `tickets.dispatch` because TheHive runs first precisely so that the
	later destinations can carry its number). A disk record whose `caseRef`
	matches a TheHive record in this set is that record, and the TheHive one is
	kept: it is the one an analyst can reassign, comment on and close.

	Records with no `caseRef` are never merged on a guess. Two analyses of the
	same subject in the same minute are rare; silently collapsing two genuinely
	separate reports into one is worse than showing both.
	"""
	hive_refs = set()
	for case in cases:
		if case.get('source') in (None, THEHIVE):
			for key in (case.get('_id'), case.get('ref'), case.get('number')):
				if key not in (None, ''):
					hive_refs.add(str(key))

	kept = []
	for case in cases:
		case_ref = str(case.get('caseRef') or '')
		if case_ref and case.get('source') in (DISK, JIRA) and case_ref in hive_refs:
			continue
		kept.append(case)
	return kept


def merge(sources, since_ms, limit):
	"""Every source's records as one history, newest first.

	Returns (cases, observables_by_id, truncated). `sources` is a list of
	(cases, observables, truncated) triples — already fetched, because one of
	them is a network call and this module does no I/O it did not open itself.
	"""
	cases = []
	observables = {}
	truncated = False
	for source_cases, source_observables, source_truncated in sources:
		cases.extend(source_cases or [])
		observables.update(source_observables or {})
		truncated = truncated or bool(source_truncated)

	cases = dedupe(cases)
	if since_ms is not None:
		cases = [case for case in cases
			if not case_insights.case_started_at(case)
			or case_insights.case_started_at(case) >= since_ms]
	cases.sort(key = case_insights.case_started_at, reverse = True)
	if limit is not None and len(cases) > limit:
		cases = cases[:limit]
		truncated = True
	return cases, observables, truncated
