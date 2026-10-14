"""Aggregation of the analysis history, whichever destination recorded it.

The enabled ticket destinations — TheHive, disk, Jira — not this application,
are the system of record for the analysis history. history.py and
thephish_app.py read them back in TheHive's case shape, and this module turns
those cases and observables into the payloads the "E-mails analisados",
"Phishing confirmado" and "Visão Executiva" screens render.

It is deliberately free of Flask, eventlet and requests: it takes plain data
in and returns plain data out. Every I/O concern (connection settings, the
query fallbacks, the green pool that fetches observables) lives in
thephish_app.py. That split is what makes the aggregation testable without a
live TheHive instance, which is the part most likely to be quietly wrong.

Nothing here invents a value. When the window holds no case, the payload is
empty and the interface renders an empty state.
"""

import datetime
import re

# Windows the dashboards offer, in days. 'all' is handled separately.
RANGE_DAYS = {'1d': 1, '7d': 7, '15d': 15, '30d': 30, '60d': 60, '90d': 90, '180d': 180}

# As janelas fixas do indicador "phishing por período", da menor para a maior.
# Cada uma é comparada com a janela de mesmo tamanho logo antes dela, então a
# leitura precisa cobrir o dobro da maior: 90 dias pedem 180.
WINDOW_KEYS = ('1d', '7d', '15d', '30d', '60d', '90d')
WINDOWS_READ_RANGE = '180d'
DEFAULT_RANGE = '30d'

# Hard ceiling on how many cases one dashboard request will consider. A busy
# instance can hold tens of thousands; beyond this the payload reports
# `truncated` rather than silently under-counting.
#
# O teto anterior era de mil casos, e mil casos é o que uma caixa de mil e-mails
# por mês produz — a janela padrão de 30 dias já batia nele, e as de 90 e 180
# dias viviam truncadas. Um KPI truncado não erra por pouco: ele conta os mais
# recentes e diz que aquilo é o mês. Cinco mil cobrem um semestre nesse volume.
MAX_CASES = 5000

# Filtering by IOC has to open every candidate case to read its observables, so
# it is bounded well below MAX_CASES. Beyond this the drill-through reports what
# it found in the most recent cases rather than stalling on a huge window.
#
# Continua bem abaixo de MAX_CASES porque cada caso aqui custa uma requisição a
# mais, mas duzentos casos eram menos de uma semana: seguir um indicador de
# campanha parava antes de chegar ao começo dela.
MAX_CASES_FOR_IOC_SEARCH = 1000

# Observable tag set by case_from_email for the "From" header of the analyzed
# email. It is written as `email_header_From`, because case_from_email builds it
# by appending the header name and RFC 5322 spells that one with a capital F.
#
# Matched case-insensitively, and that is the fix rather than the constant being
# retyped: this was written here in lower case and compared with `in`, so it
# matched nothing — for every case, on every screen, since the tag existed. The
# sender column read "(remetente não registrado)" over analyses whose sender was
# recorded, and the executive dashboard's "most frequent senders" card was
# permanently empty. Nothing failed, nothing logged, no test went red, and an
# empty card is indistinguishable from a quiet month.
SENDER_OBSERVABLE_TAG = 'email_header_from'

# 'email' is on every case this application creates and also on cases opened by
# other tooling, so it is not useful as a per-case label in the interface
GENERIC_TAGS = frozenset(['email'])

# Facts about one analysis that this application records as case tags, so that a
# dashboard over a month of cases can be built from the case list alone.
#
# The alternative was reading every case's task log and parsing the assessment
# back out of prose — one request per case, on text written for a human. A tag is
# a field: it survives, it is queryable, and it costs nothing to count.
#
#   dept:<name>      area the reporter belongs to (departments.py resolved it)
#   tactic:<key>     one per social engineering tactic the LLM reported
#   risk:<Level>     risk level of the LLM assessment
#   se:detected      the LLM concluded there was social engineering
#   ai:injection_attempt  the email tried to manipulate its own analysis
#   score:<0-100>    weighted score of the analysis (scoring.py)
#   tier:<faixa>     band the score fell in: phishing | spam | suspicious | legitimate
#   auth:<result>    SPF/DKIM/DMARC as the receiving server recorded them
DEPARTMENT_TAG_PREFIX = 'dept:'
TACTIC_TAG_PREFIX = 'tactic:'
RISK_TAG_PREFIX = 'risk:'
SOCIAL_ENGINEERING_TAG = 'se:detected'
SCORE_TAG_PREFIX = 'score:'
TIER_TAG_PREFIX = 'tier:'
AUTH_TAG_PREFIX = 'auth:'

# An email carrying prompt-injection markers. Recorded as a tag for the same
# reason the tactics are: it is a fact about the analysis that has to survive the
# task log, and "how many people mailed us something written for our model this
# month" is a question the SOC will eventually ask
PROMPT_INJECTION_TAG = 'ai:injection_attempt'

# Todo prefixo desta tupla precisa estar aqui, e o custo de esquecer um e
# silencioso: `display_tags()` e quem tira estas tags da lista que a analista le,
# entao um prefixo ausente vaza para a interface como se fosse etiqueta escrita
# por gente
ANALYSIS_TAG_PREFIXES = (DEPARTMENT_TAG_PREFIX, TACTIC_TAG_PREFIX, RISK_TAG_PREFIX, 'se:', 'ai:',
	SCORE_TAG_PREFIX, TIER_TAG_PREFIX, AUTH_TAG_PREFIX)

# How many entries the ranked dashboard cards show
TOP_DEPARTMENTS = 6
TOP_TACTICS = 6

# resolutionStatus written by run_analysis when it closes a case. A case left
# open was handed to the analyst, which is exactly the "Suspicious" verdict.
RESOLUTION_TO_VERDICT = {'TruePositive': 'Malicious', 'FalsePositive': 'Safe'}

CLOSED_STATUSES = frozenset(['resolved', 'closed', 'deleted'])

THREAT_VERDICTS = frozenset(['Malicious', 'Suspicious'])

# An IOC seen in at least this many distinct cases is reported as a campaign
# signal — the same infrastructure reused against the organization
CAMPAIGN_MIN_CASES = 3


def range_to_since_ms(range_key, now = None):
	"""Start of the requested window as epoch milliseconds, or None for 'all'."""
	if range_key == 'all':
		return None
	import time
	now = now if now is not None else time.time()
	days = RANGE_DAYS.get(range_key, RANGE_DAYS[DEFAULT_RANGE])
	return int((now - days * 86400) * 1000)


def normalize_range(range_key):
	"""Coerce a caller-supplied range to one this module understands."""
	if range_key == 'all' or range_key in RANGE_DAYS:
		return range_key
	return DEFAULT_RANGE


def analysis_tags(report):
	"""The facts of one analysis that become tags on the record it is written to.

	Written by `tickets.py` onto a TheHive case, and rebuilt by `history.py` from
	the report on disk. One definition, because the alternative — writing the tag
	in one module and re-deriving it in another — is how a verdict read back from
	disk quietly loses its department while every test stays green.
	"""
	tags = []
	if report.get('department'):
		tags.append(DEPARTMENT_TAG_PREFIX + report['department'])
	llm = report.get('llm') or {}
	if llm.get('risk_level'):
		tags.append(RISK_TAG_PREFIX + str(llm['risk_level']))
	if llm.get('social_engineering_detected'):
		tags.append(SOCIAL_ENGINEERING_TAG)
	for tactic in llm.get('tactics') or []:
		tags.append(TACTIC_TAG_PREFIX + str(tactic))
	if (report.get('promptGuard') or {}).get('injection'):
		tags.append(PROMPT_INJECTION_TAG)
	# A nota e a faixa: sem elas, o painel tático não tem como ordenar remetente
	# por risco agregado, e voltaria a ordenar por contagem — que trata quarenta
	# newsletters e quarenta cobranças falsas como o mesmo problema
	score = report.get('score') or {}
	if score.get('score') is not None:
		tags.append(SCORE_TAG_PREFIX + str(score['score']))
	if score.get('label'):
		tags.append(TIER_TAG_PREFIX + str(score['label']))
	# SPF/DKIM/DMARC já eram extraídos por e-mail e só existiam dentro do caso.
	# Como tag eles passam a ser contáveis na janela inteira, que é o que o painel
	# de sinais de autenticação pedia (ROADMAP item 4)
	auth = report.get('authentication') or {}
	for method in ('spf', 'dkim', 'dmarc'):
		result = str(auth.get(method) or '').strip().lower()
		if result:
			tags.append('{0}{1}={2}'.format(AUTH_TAG_PREFIX, method, result))
	return tags


def empty_reason(recording, outside_window, range_key):
	"""Why the history is empty, in the analyst's words, or '' when it is not known.

	An empty history has more than one cause and they call for opposite actions,
	but on screen they looked identical: "Nenhum caso corresponde aos filtros",
	under a mailbox that had just finished analyzing an email. The analyst reads
	that as a broken pipeline and goes looking through the logs of an analysis
	that in fact ran, scored and recorded exactly as it should have.

	Two causes are knowable from here and worth naming:

	  * **nothing is recording.** These screens read the analysis history back
	    from the enabled ticket destinations, so with every one of them off they
	    stay empty however well the analysis itself runs. Nothing is wrong and
	    nothing will appear until one is turned on.
	  * **the window is too narrow.** The cases exist, they are just older than
	    the range selected. `outside_window` is counted, never guessed: it is a
	    real query over the whole history, and 0 produces no message at all
	    rather than an invitation to widen a range onto nothing.

	Anything else - a genuinely fresh install, filters that match no case -
	returns '', and the interface keeps saying what it said before.
	"""
	if not recording:
		return ('Nenhum destino está gravando o histórico: todos estão desligados em '
			'Configurações → Destinos, e estas telas leem deles. As análises continuam '
			'rodando; elas é que não ficam registradas em lugar nenhum.')
	if outside_window:
		if range_key == 'all':
			return ''
		days = RANGE_DAYS.get(range_key, RANGE_DAYS[DEFAULT_RANGE])
		span = 'das últimas 24 horas' if days == 1 else 'dos últimos {0} dias'.format(days)
		return '{0} caso(s) registrado(s) fora {1}. Amplie o período para vê-los.'.format(
			outside_window, span)
	return ''


def case_verdict(case):
	"""The verdict of one analyzed email, whichever destination recorded it.

	A record that carries the verdict says so directly. Only TheHive encodes it
	as a resolution status, because only TheHive has one — the report written to
	disk or to a Jira issue holds the word the analysis decided on. Re-deriving
	it from a resolution TheHive never wrote would turn every disk record into
	"Suspicious", which is the one verdict that means "an analyst still has to
	look at this".
	"""
	if case.get('verdict'):
		return str(case['verdict'])
	resolution = case.get('resolutionStatus') or ''
	if resolution in RESOLUTION_TO_VERDICT:
		return RESOLUTION_TO_VERDICT[resolution]
	status = str(case.get('status') or '').lower()
	# Resolved under any other resolution (Indeterminate, Duplicated, Other) was a
	# human decision this application cannot interpret. Folding it into either
	# "malicious" or "safe" would misreport it, so it gets its own bucket.
	if status in CLOSED_STATUSES:
		return 'Other'
	return 'Suspicious'


def case_started_at(case):
	"""Creation timestamp of a case in epoch milliseconds, 0 when absent."""
	return case.get('startDate') or case.get('_createdAt') or 0


# Marcadores que este produto já usou para etiquetar os casos que ele cria. O
# nome mudou duas vezes — ThePhish -> bluephising -> bluephish — e a etiqueta
# acompanhou, mas os casos abertos antes ficaram com a antiga gravada.
#
# Sem esta lista, trocar `case.tags` nas Configurações faz o painel inteiro
# esvaziar em silêncio: as consultas passam a procurar a etiqueta nova, nenhum
# caso antigo a tem, e a tela mostra "não foi possível consultar os registros"
# como se o TheHive estivesse fora do ar. É exatamente o acoplamento invisível
# que o CLAUDE.md deste repositório manda procurar — a causa fica três camadas
# longe do sintoma, e nada falha, nada loga, nenhum teste fica vermelho.
#
# O frontend já resolve o mesmo problema do mesmo jeito para as preferências
# guardadas no navegador (PREF_BRANDS em bluephish.js).
CASE_TAG_ALIASES = ['bluephish', 'bluephising', 'redphish', 'ThePhish']


def case_tag_markers(configured):
	"""A etiqueta configurada primeiro, e os nomes históricos atrás dela.

	Aceita texto ou lista, e devolve sempre uma lista sem repetição.
	"""
	if isinstance(configured, str):
		configured = [configured] if configured else []
	configured = [tag for tag in (configured or []) if tag]
	# Sem etiqueta configurada o significado é "não filtre por etiqueta", e não
	# "filtre pelos nomes antigos": uma instalação que apagou case.tags marca os
	# casos com nada, e procurar por marcador esconderia todos eles
	if not configured:
		return []
	markers = []
	for tag in configured + CASE_TAG_ALIASES:
		if tag and tag not in markers:
			markers.append(tag)
	return markers


def build_case_queries(since_ms, limit, tag):
	"""Candidate TheHive queries, richest first.

	TheHive's query DSL is not identical across 4.x and 5.x, so the caller tries
	these in order and keeps the first that answers. Every result is filtered
	again by filter_cases, so a fallback that over-fetches still yields correct
	data — only slower.
	"""
	tags = case_tag_markers(tag)
	filters = []
	if since_ms is not None:
		filters.append({'_gte': {'_field': 'startDate', '_value': since_ms}})
	if len(tags) == 1:
		filters.append({'_field': 'tags', '_value': tags[0]})
	elif tags:
		# Um `_or` sobre os marcadores. Se a versão do TheHive recusar esta forma,
		# a lista de candidatos abaixo já cai para consultas sem filtro de
		# etiqueta, e filter_cases estreita do lado de cá — que é para isso que a
		# cadeia de alternativas existe.
		filters.append({'_or': [{'_field': 'tags', '_value': item} for item in tags]})

	sort_and_page = [
		{'_name': 'sort', '_fields': [{'startDate': 'desc'}]},
		{'_name': 'page', 'from': 0, 'to': limit}
	]

	candidates = []
	if filters:
		candidates.append([{'_name': 'listCase'}, {'_name': 'filter', '_and': filters}] + sort_and_page)
		candidates.append([{'_name': 'listCase'}, {'_name': 'filter', '_and': filters}])
	candidates.append([{'_name': 'listCase'}] + sort_and_page)
	candidates.append([{'_name': 'listCase'}])
	return candidates


def filter_cases(raw, tag, since_ms, limit):
	"""Keep the cases of this application inside the window, newest first.

	Returns (cases, truncated). This Python-side pass is what makes the query
	fallbacks in build_case_queries safe: whichever candidate answered, the
	result is narrowed to the same set.
	"""
	tags = case_tag_markers(tag)
	cases = []
	for case in raw or []:
		if not isinstance(case, dict):
			continue
		# Basta UM dos marcadores: o caso aberto sob o nome antigo continua sendo
		# deste produto depois do rebrand
		if tags and not any(item in (case.get('tags') or []) for item in tags):
			continue
		started = case_started_at(case)
		if since_ms is not None and started and started < since_ms:
			continue
		cases.append(case)
	cases.sort(key = case_started_at, reverse = True)
	return cases[:limit], len(cases) > limit


def observable_value(obs):
	"""Readable value of an observable, whether it holds data or a file."""
	data = obs.get('data')
	if data:
		return str(data)
	return str((obs.get('attachment') or {}).get('name', ''))


def sender_of(observables):
	"""The From address recorded as an observable when the analysis ran."""
	for obs in observables or []:
		tags = [str(tag).lower() for tag in (obs.get('tags') or [])]
		if SENDER_OBSERVABLE_TAG in tags:
			value = observable_value(obs)
			if value:
				return value
	return ''


def tag_values(case, prefix):
	"""Every value a case carries under one tag prefix, in the order recorded."""
	values = []
	for tag in case.get('tags') or []:
		tag = str(tag)
		if tag.startswith(prefix):
			value = tag[len(prefix):].strip()
			if value and value not in values:
				values.append(value)
	return values


def first_tag_value(case, prefix):
	"""The single value expected under a prefix, or '' when the tag is absent."""
	values = tag_values(case, prefix)
	return values[0] if values else ''


def case_department(case):
	"""Area the reporter belongs to, or '' when no rule attributed the report."""
	return first_tag_value(case, DEPARTMENT_TAG_PREFIX)


def case_tactics(case):
	"""Social engineering tactics the LLM reported for this email."""
	return tag_values(case, TACTIC_TAG_PREFIX)


def case_risk(case):
	"""Risk level of the LLM assessment, or '' when the LLM did not run."""
	return first_tag_value(case, RISK_TAG_PREFIX)


def case_score(case):
	"""Nota ponderada da análise, ou None quando o caso é anterior ao score.

	None e zero são coisas diferentes aqui, e confundi-los seria o pior tipo de
	erro que este arquivo pode cometer: um caso sem tag `score:` é um caso que
	nunca foi pontuado, e apresentá-lo como zero o colocaria no fundo de um
	ranking como se tivesse sido avaliado e absolvido.
	"""
	raw = first_tag_value(case, SCORE_TAG_PREFIX)
	if not raw:
		return None
	try:
		return float(raw)
	except (TypeError, ValueError):
		return None


def case_tier(case):
	"""Faixa em que o score caiu, ou '' quando o caso não foi pontuado."""
	return first_tag_value(case, TIER_TAG_PREFIX)


def case_auth(case):
	"""Os três resultados de autenticação gravados como tag, como dicionário.

	`{'spf': 'pass', ...}`, e a chave simplesmente falta quando o servidor de
	entrada não registrou aquele mecanismo — o painel conta 'sem registro' como
	uma categoria própria, e não como falha.
	"""
	auth = {}
	for value in tag_values(case, AUTH_TAG_PREFIX):
		if '=' not in value:
			continue
		method, result = value.split('=', 1)
		method = method.strip().lower()
		if method in ('spf', 'dkim', 'dmarc'):
			auth[method] = result.strip().lower()
	return auth


def display_tags(case):
	"""The case tags meant for a human, without the ones that are fields."""
	return [tag for tag in (case.get('tags') or [])
		if tag not in GENERIC_TAGS and not str(tag).startswith(ANALYSIS_TAG_PREFIXES)]


# How a record identifies itself on screen, per source. TheHive is the only one
# with a case number, because it is the only one that is a case management
# system; the others are named by what they actually are, so an analyst reading
# a row knows where to go looking for it.
SOURCE_LABELS = {'thehive': 'CASE', 'disk': 'DISCO', 'jira': 'JIRA'}


def record_ref(case):
	"""What the detail route takes back for this record.

	TheHive records answer to their case number, unprefixed, because that is the
	number printed on the case an analyst already has open and the one they type
	into the chat box. Everything else answers to its `_id`, which carries its
	source.
	"""
	source = case.get('source') or 'thehive'
	if source == 'thehive':
		number = case.get('number')
		return str(number) if number not in (None, '') else str(case.get('_id', ''))
	return str(case.get('_id', ''))


def record_label(case):
	"""The short name of a record, as its pill shows it."""
	source = case.get('source') or 'thehive'
	if source == 'thehive':
		number = case.get('number')
		return 'CASE #{0}'.format(number) if number not in (None, '') else 'CASE'
	if source == 'jira':
		return str(case.get('ref') or 'JIRA')
	return SOURCE_LABELS.get(source, source.upper())


def case_row(case, observables):
	"""Shape one recorded analysis for the analyzed-emails list.

	`observables` is None — not an empty list — when the source that holds this
	record cannot answer for them. Jira keeps the report as prose written for a
	human, so counting IOCs out of it would put a number nobody measured on a
	screen a SOC decides from. `observableCount: null` is what the interface
	renders as "—"; zero would be a claim.
	"""
	known = observables is not None
	observables = observables or []
	iocs = [obs for obs in observables if obs.get('ioc')]
	return {
		'id': case.get('_id', ''),
		'ref': record_ref(case),
		'source': case.get('source') or 'thehive',
		'label': record_label(case),
		'number': case.get('number'),
		'title': case.get('title', ''),
		'verdict': case_verdict(case),
		'startDate': case_started_at(case),
		'department': case_department(case),
		'tactics': case_tactics(case),
		'risk': case_risk(case),
		'score': case_score(case),
		'tier': case_tier(case),
		'tags': display_tags(case),
		'sender': sender_of(observables),
		'observableCount': len(observables) if known else None,
		'iocCount': len(iocs) if known else None,
		'iocs': [
			{'type': obs.get('dataType', ''), 'value': observable_value(obs)[:200]}
			for obs in iocs[:4]
		],
		# Set by reclassification.overlay: the verdict the analysis reached, when
		# an analyst has since decided otherwise. None when nobody did
		'originalVerdict': case.get('originalVerdict') or None,
		'reclassification': case.get('reclassification') or None
	}


def apply_decision(case, decision):
	"""Lay an analyst's reclassification over one history record, in place.

	`verdict` becomes the decision's — it is the field case_verdict reads first,
	so the filters, the counts and the dashboards follow without knowing a human
	intervened. `originalVerdict` keeps what the analysis decided. A reverted
	decision still sets the verdict: the destination may keep saying otherwise (a
	TheHive case reopened after a resolution keeps the old resolution status).

	Pure and here rather than in reclassification.py, so that history.py can
	honor a decision stored inside a report without importing the database.
	"""
	if not decision:
		return case
	if decision.get('action') == 'revert':
		case.pop('originalVerdict', None)
		case['reclassification'] = None
	else:
		case['originalVerdict'] = decision.get('previousVerdict') or ''
		case['reclassification'] = decision
	case['verdict'] = decision.get('verdict') or case.get('verdict')
	return case


# --- the reasoning behind a verdict, for the case detail ----------------------

FLAG_LEVELS = ('malicious', 'suspicious')


def flagged_by(observables, findings):
	"""Each observable with the analyzers that flagged it, IOCs first.

	`observables` is the detail shape ({'type', 'value', 'ioc'}); `findings` is
	the report's list of analyzer answers, or None when the source did not record
	which analyzer said what. Then every observable carries `flaggedBy: None` —
	"this source cannot say" — and never an empty list, which would read as "no
	analyzer flagged it" on an observable marked IOC.

	The order puts what matters on the first screen: malicious, then suspicious,
	then the rest, each group in the order the analysis extracted it.
	"""
	by_value = {}
	for finding in findings or []:
		if finding.get('level') not in FLAG_LEVELS:
			continue
		by_value.setdefault(str(finding.get('observable', '')), []).append({
			'analyzer': finding.get('analyzer', ''),
			'level': finding.get('level'),
			'detail': finding.get('detail', '')
		})

	annotated = []
	for position, obs in enumerate(observables or []):
		entry = dict(obs)
		flags = by_value.get(str(obs.get('value', ''))) if findings is not None else None
		entry['flaggedBy'] = flags or ([] if findings is not None else None)
		levels = [flag['level'] for flag in (flags or [])]
		entry['level'] = 'malicious' if 'malicious' in levels or (obs.get('ioc') and not levels) else (
			'suspicious' if 'suspicious' in levels else None)
		annotated.append((0 if entry['level'] == 'malicious' else 1 if entry['level'] == 'suspicious' else 2,
			position, entry))
	annotated.sort(key = lambda item: (item[0], item[1]))
	return [entry for _rank, _position, entry in annotated]


def llm_view(llm):
	"""The social engineering assessment, whole, or None when the model did not run."""
	if not llm:
		return None
	council = llm.get('council') if isinstance(llm.get('council'), dict) else None
	view = {
		'riskLevel': llm.get('risk_level') or '',
		'detected': bool(llm.get('social_engineering_detected')),
		'tactics': list(llm.get('tactics') or []),
		'justification': str(llm.get('justification') or ''),
		# None when the analysis predates the key, [] when the model named nothing
		'evidence': list(llm['evidence']) if isinstance(llm.get('evidence'), list) else None,
		'council': None
	}
	if council:
		review = council.get('review') if isinstance(council.get('review'), dict) else {}
		view['council'] = {
			'mode': council.get('mode') or '',
			'consensus': bool(council.get('consensus')),
			'divergence': council.get('divergence') or '',
			'holdForHuman': bool(council.get('holdForHuman')),
			'review': {
				'status': review.get('status') or '',
				'action': review.get('action') or '',
				'manipulationDetected': bool(review.get('manipulation_detected')),
				'reason': review.get('reason') or ''
			},
			'agents': [{
				'role': agent.get('role') or '',
				'model': agent.get('model') or '',
				'riskLevel': agent.get('risk_level') or '',
				'detected': bool(agent.get('social_engineering_detected')),
				'justification': agent.get('justification') or '',
				'evidence': list(agent.get('evidence') or []),
				'revised': bool(agent.get('revised'))
			} for agent in (council.get('agents') or []) if isinstance(agent, dict)]
		}
	return view


# How many score factors the detail shows. The memory of the calculation lists
# every analyzer that answered; past the top contributors the rows are zeros
MAX_SCORE_FACTORS = 8


def score_view(score):
	"""The weighted score and its top contributors, or None when it was not computed."""
	if not score or score.get('score') is None:
		return None
	return {
		'score': score.get('score'),
		'tier': score.get('tier') or '',
		'label': score.get('label') or '',
		'capped': bool(score.get('capped')),
		'factors': [{
			'label': factor.get('label') or factor.get('id') or '',
			'contribution': factor.get('contribution') or 0,
			'reason': factor.get('reason') or ''
		} for factor in (score.get('factors') or []) if (factor.get('participation') or 0) > 0][:MAX_SCORE_FACTORS]
	}


def has_observable(observables, needle):
	"""Whether any observable of a case carries `needle`.

	Substring rather than equality, so drilling through from a domain also finds
	the URLs built on it — which is the whole point of following a campaign
	indicator across cases.
	"""
	needle = str(needle or '').strip().lower()
	if not needle:
		return False
	for obs in observables or []:
		if needle in observable_value(obs).lower():
			return True
	return False


def normalize_subject(title):
	"""Collapse the noise that makes two reports of one campaign look distinct.

	Reply/forward prefixes, ticket and invoice numbers and amounts vary per
	recipient while the campaign is the same, so they are stripped before the
	subjects are grouped.
	"""
	subject = str(title or '').strip()
	subject = re.sub(r'^(?:\s*(?:re|res|fw|fwd|enc|encaminhando)\s*:\s*)+', '', subject, flags = re.IGNORECASE)
	subject = re.sub(r'[#nN]?\s*\d[\d.,/-]{3,}\b', '…', subject)
	subject = re.sub(r'\s+', ' ', subject).strip()
	return subject[:80]


def count_tiers(cases):
	"""Quantos casos caíram em cada faixa do score, sempre com todas presentes.

	`unscored` conta os casos anteriores ao score. Ele existe para que a soma das
	faixas nunca precise fechar com o total de casos por acidente — se fechasse,
	um caso não pontuado teria virado silenciosamente 'legítimo'.
	"""
	counts = {'phishing': 0, 'spam': 0, 'suspicious': 0, 'legitimate': 0, 'unscored': 0}
	for case in cases:
		tier = case_tier(case)
		if tier in counts:
			counts[tier] += 1
		else:
			counts['unscored'] += 1
	return counts


def count_verdicts(cases):
	"""Verdict histogram of a list of cases, with every bucket always present."""
	counts = {'Malicious': 0, 'Suspicious': 0, 'Safe': 0, 'Other': 0}
	for case in cases:
		verdict = case_verdict(case)
		counts[verdict] = counts.get(verdict, 0) + 1
	return counts


def count_departments(cases):
	"""How many reports each area sent, and how many of them were malicious.

	Counted over every case, not only the ones with a threat verdict: "most
	targeted department" is a question about who receives the attempts, and a
	report that turned out legitimate is still an attempt that reached that desk.

	A case with no dept: tag is not attributed to anything — it is reported apart,
	so a half-configured mapping cannot pass for a department with few reports.
	"""
	departments = {}
	unattributed = 0
	for case in cases:
		name = case_department(case)
		if not name:
			unattributed += 1
			continue
		entry = departments.setdefault(name, {'label': name, 'count': 0, 'malicious': 0})
		entry['count'] += 1
		if case_verdict(case) == 'Malicious':
			entry['malicious'] += 1
	ranked = sorted(departments.values(), key = lambda d: (d['count'], d['label']), reverse = True)
	return ranked, unattributed


def count_tactics(cases):
	"""How many analyses reported each social engineering tactic."""
	tactics = {}
	for case in cases:
		for key in case_tactics(case):
			tactics[key] = tactics.get(key, 0) + 1
	return sorted([{'key': key, 'count': count} for key, count in tactics.items()],
		key = lambda t: (t['count'], t['key']), reverse = True)


def summarize_llm(cases):
	"""What the LLM concluded across the window, counted from the case tags.

	`assessed` is the denominator that matters: an instance running with the LLM
	disabled, or one whose model was unreachable for half the window, must not
	look like an instance where the model found nothing. Every rate the interface
	shows is over the cases the model actually judged.
	"""
	risk = {level: 0 for level in ['Low', 'Medium', 'High', 'Critical']}
	assessed = 0
	social_engineering = 0
	escalating = 0
	for case in cases:
		level = case_risk(case)
		if level:
			assessed += 1
			risk[level] = risk.get(level, 0) + 1
			if level in ('High', 'Critical'):
				escalating += 1
		if SOCIAL_ENGINEERING_TAG in (case.get('tags') or []):
			social_engineering += 1
	return {
		'assessed': assessed,
		'notAssessed': len(cases) - assessed,
		'socialEngineering': social_engineering,
		'highRisk': escalating,
		'risk': [{'key': level, 'count': risk.get(level, 0)}
			for level in ['Critical', 'High', 'Medium', 'Low']]
	}


# Remediação proposta por tipo de observável. É playbook, não recomendação
# gerada: a ação que se toma sobre um IOC é função do que ele é, e escrever isso
# aqui é o que separa "ação recomendada" de palpite apresentado como conclusão
# (ROADMAP item 5). Quando existe destino de bloqueio habilitado que aceita o
# tipo, a linha vira acionável; quando não existe, ela diz o que falta em vez de
# oferecer um botão que não faz nada.
REMEDIATION_BY_TYPE = {
	'url': {
		'action': 'Bloquear a URL no gateway web e no filtro de e-mail',
		'detail': 'A URL é o que a vítima clica. Bloqueá-la corta a campanha para quem ainda '
			'não abriu, inclusive quem não denunciou.'
	},
	'domain': {
		'action': 'Bloquear o domínio no DNS e no gateway',
		'detail': 'Bloquear o domínio cobre as URLs que ainda não foram vistas nele — uma '
			'campanha troca o caminho e mantém a hospedagem.'
	},
	'ip': {
		'action': 'Bloquear o IP no firewall de borda',
		'detail': 'Vale enquanto a infraestrutura não migrar. Reveja a entrada: IP de nuvem '
			'compartilhada é reatribuído, e um bloqueio permanente vira dano colateral.'
	},
	'mail': {
		'action': 'Bloquear o remetente no gateway de e-mail',
		'detail': 'Se o endereço é de um domínio legítimo, considere que a caixa foi '
			'comprometida antes de bloquear: o bloqueio corta também o tráfego real dela.'
	},
	'hash': {
		'action': 'Bloquear o hash no EDR e varrer a base por execução',
		'detail': 'O hash identifica o anexo exato. Antes do bloqueio, procure execução prévia: '
			'quem já abriu não é resolvido bloqueando o próximo envio.'
	},
	'file': {
		'action': 'Extrair o hash do anexo e bloqueá-lo no EDR',
		'detail': 'O arquivo em si não é indicador transportável; o hash dele é.'
	}
}


def remediation_for(observable_type, blockable_types = None):
	"""Ação proposta para um IOC, e se existe destino habilitado que a execute."""
	base_type = str(observable_type or '').split('_')[0]
	playbook = REMEDIATION_BY_TYPE.get(base_type)
	if playbook is None:
		return None
	blockable = blockable_types if blockable_types is not None else None
	return {
		'action': playbook['action'],
		'detail': playbook['detail'],
		# None = ninguém perguntou aos destinos de bloqueio (a rota não os passou),
		# que é diferente de "perguntei e não há". A tela distingue os dois
		'blockable': None if blockable is None else (base_type in blockable)
	}


def count_authentication(cases):
	"""SPF, DKIM e DMARC somados na janela, a partir das tags do caso.

	Um caso sem tag `auth:` não é um caso que falhou autenticação: é um caso
	anterior à gravação dessas tags, ou um em que o servidor de entrada não
	escreveu o cabeçalho. Ele é contado em `unrecorded` e fica fora dos
	percentuais, porque somá-lo a `fail` inventaria falha que ninguém observou.
	"""
	stats = {}
	for method in ('spf', 'dkim', 'dmarc'):
		stats[method] = {'method': method, 'pass': 0, 'fail': 0, 'other': 0,
			'unrecorded': 0, 'recorded': 0}
	for case in cases:
		auth = case_auth(case)
		for method in ('spf', 'dkim', 'dmarc'):
			bucket = stats[method]
			kind = auth_bucket(auth.get(method))
			if kind is None:
				bucket['unrecorded'] += 1
				continue
			bucket['recorded'] += 1
			bucket[kind] += 1
	return [stats[method] for method in ('spf', 'dkim', 'dmarc')]


AUTH_BUCKETS = ('pass', 'fail', 'other')


def auth_bucket(result):
	"""O balde de um resultado de SPF/DKIM/DMARC, ou None quando não há registro.

	Uma definição só, usada pela pizza e pelo filtro que abre os casos de uma
	fatia. Se os dois classificassem cada um do seu jeito, clicar em "fail 7"
	abriria cinco casos — e a analista deixaria de confiar nos dois números.
	"""
	result = str(result or '').strip().lower()
	if not result or result == 'none':
		return None
	if result == 'pass':
		return 'pass'
	if result in ('fail', 'softfail', 'permerror', 'temperror'):
		return 'fail'
	return 'other'


def matches_signal(case, tier = '', auth = ''):
	"""Se o caso está na fatia pedida: uma faixa do score, ou 'método:balde'.

	Vazio não filtra. Um filtro malformado não casa com nada: devolver a janela
	inteira faria a lista parecer a fatia clicada, com o número errado.
	"""
	if tier and case_tier(case) != tier:
		return False
	if auth:
		method, _, kind = auth.partition(':')
		if method not in ('spf', 'dkim', 'dmarc') or kind not in AUTH_BUCKETS:
			return False
		if auth_bucket(case_auth(case).get(method)) != kind:
			return False
	return True


def threat_cases(cases):
	"""Cases that did not come back clean — the only ones with IOCs to correlate."""
	return [case for case in cases if case_verdict(case) in THREAT_VERDICTS]


def count_windows(cases, truncated, now_ms):
	"""Phishing confirmado em cada janela fixa, e na janela anterior de mesmo tamanho.

	`cases` é o histórico de WINDOWS_READ_RANGE, mais recente primeiro. Duas
	coisas aqui existem para não mentir:

	  * **truncado não é zero.** Quando a leitura bateu no teto, só os casos mais
	    recentes vieram. Uma janela cujo começo é mais antigo que o caso mais velho
	    lido não foi coberta: a contagem dela é um piso (`complete: False`), e a
	    comparação com a janela anterior vira None em vez de um número inventado.
	  * **sem data não entra em janela.** Um caso sem data de criação não pertence
	    a nenhuma; ele é contado à parte em `undated`, não jogado na mais recente.
	"""
	dated = [case_started_at(case) for case in cases if case_started_at(case)]
	oldest = min(dated) if dated else None

	def covered(since_ms):
		return not truncated or (oldest is not None and oldest <= since_ms)

	malicious = [case_started_at(case) for case in cases
		if case_verdict(case) == 'Malicious' and case_started_at(case)]
	windows = []
	for key in WINDOW_KEYS:
		span = RANGE_DAYS[key] * 86400 * 1000
		since = now_ms - span
		before = since - span
		windows.append({
			'key': key,
			'days': RANGE_DAYS[key],
			'malicious': sum(1 for started in malicious if started >= since),
			'complete': covered(since),
			'previous': sum(1 for started in malicious if before <= started < since)
				if covered(before) else None
		})
	return {
		'windows': windows,
		'undated': sum(1 for case in cases
			if case_verdict(case) == 'Malicious' and not case_started_at(case))
	}


def aggregate(cases, observables_by_case, range_key, truncated = False, generated_at = None,
		blockable_types = None):
	"""Build the executive dashboard payload from cases already fetched.

	`observables_by_case` only needs to carry the threat cases (see threat_cases);
	a missing entry is treated as "no observables", never as an error.
	"""
	counts = count_verdicts(cases)
	daily = {}
	subjects = {}

	for case in cases:
		verdict = case_verdict(case)
		started = case_started_at(case)
		if started:
			# Days are bucketed in UTC, matching the epoch timestamps TheHive
			# stores. The interface labels the chart as UTC so a late-evening
			# local report landing on the next bucket is not read as a gap.
			day = datetime.datetime.fromtimestamp(started / 1000, datetime.timezone.utc).strftime('%Y-%m-%d')
			bucket = daily.setdefault(day, {'date': day, 'threat': 0, 'safe': 0})
			# "Threat" groups everything that did not come back clean, which is what
			# the volume chart contrasts against the legitimate traffic
			bucket['threat' if verdict in THREAT_VERDICTS else 'safe'] += 1
		subject = normalize_subject(case.get('title', ''))
		if subject:
			subjects[subject] = subjects.get(subject, 0) + 1

	senders = {}
	ioc_hits = {}
	for case in threat_cases(cases):
		case_observables = observables_by_case.get(case.get('_id')) or []
		sender = sender_of(case_observables)
		score = case_score(case)
		if sender:
			entry = senders.setdefault(sender, {'value': sender, 'count': 0, 'malicious': 0,
				'scored': 0, 'risk': 0.0, 'topScore': 0.0})
			entry['count'] += 1
			if case_verdict(case) == 'Malicious':
				entry['malicious'] += 1
			# Risco agregado é a soma das notas, não a média: um remetente com uma
			# denúncia de 90 e um com dez de 45 não representam o mesmo problema
			# para quem decide o que bloquear primeiro, e a média achataria isso
			if score is not None:
				entry['scored'] += 1
				entry['risk'] += score
				entry['topScore'] = max(entry['topScore'], score)
		for obs in case_observables:
			if not obs.get('ioc'):
				continue
			value = observable_value(obs)
			if not value:
				continue
			key = (obs.get('dataType', ''), value)
			hit = ioc_hits.setdefault(key, {'type': key[0], 'value': value, 'cases': set(),
				'risk': 0.0, 'scored': 0})
			hit['cases'].add(case.get('_id'))
			if score is not None:
				hit['scored'] += 1
				hit['risk'] += score

	# Ranked by how many distinct cases an IOC appears in: a plain count of
	# reuse, not a model's guess at a campaign
	ranked_iocs = sorted(ioc_hits.values(), key = lambda hit: (len(hit['cases']), hit['value']), reverse = True)
	top_iocs = [
		{'type': hit['type'], 'value': hit['value'], 'cases': len(hit['cases']),
		 'risk': round(hit['risk'], 1) if hit['scored'] else None,
		 'scored': hit['scored'],
		 'remediation': remediation_for(hit['type'], blockable_types)}
		for hit in ranked_iocs[:8]
	]
	recurring = None
	if ranked_iocs and len(ranked_iocs[0]['cases']) >= CAMPAIGN_MIN_CASES:
		recurring = {
			'type': ranked_iocs[0]['type'],
			'value': ranked_iocs[0]['value'],
			'cases': len(ranked_iocs[0]['cases'])
		}

	# Departments, tactics and the LLM summary all come from the tags the analysis
	# wrote on the case, so they cost no extra request: the case list already
	# fetched carries them
	ranked_departments, unattributed_departments = count_departments(cases)
	ranked_tactics = count_tactics(cases)

	analyzed = len(cases)
	return {
		'range': range_key,
		'generatedAt': generated_at,
		'truncated': truncated,
		'kpis': {
			'analyzed': analyzed,
			'malicious': counts['Malicious'],
			'pending': counts['Suspicious'],
			'safe': counts['Safe'],
			'maliciousRate': round(counts['Malicious'] * 100.0 / analyzed, 1) if analyzed else 0.0
		},
		'verdicts': [
			{'key': 'Malicious', 'count': counts['Malicious']},
			{'key': 'Suspicious', 'count': counts['Suspicious']},
			{'key': 'Safe', 'count': counts['Safe']},
			{'key': 'Other', 'count': counts['Other']}
		],
		'daily': [daily[day] for day in sorted(daily.keys())],
		# Ordenado por risco agregado quando existe nota, e por contagem quando não
		# existe. `sendersScored` diz qual dos dois a tela está mostrando: um
		# ranking que muda de critério sem avisar é um ranking em que ninguém
		# confia na segunda vez que olha
		'topSenders': [
			dict(sender, risk = round(sender['risk'], 1) if sender['scored'] else None,
				topScore = round(sender['topScore'], 1) if sender['scored'] else None)
			for sender in sorted(senders.values(),
				key = lambda s: (s['risk'], s['count'], s['value']), reverse = True)[:8]
		],
		'sendersScored': sum(1 for sender in senders.values() if sender['scored']),
		'sendersTotal': len(senders),
		'authStats': count_authentication(cases),
		'scored': sum(1 for case in cases if case_score(case) is not None),
		'tiers': count_tiers(cases),
		'topSubjects': sorted(
			[{'label': label, 'count': count} for label, count in subjects.items()],
			key = lambda s: (s['count'], s['label']), reverse = True)[:5],
		'topIocs': top_iocs,
		'recurringIoc': recurring,
		'topDepartments': ranked_departments[:TOP_DEPARTMENTS],
		'departmentsTotal': len(ranked_departments),
		'departmentsUnattributed': unattributed_departments,
		'topTactics': ranked_tactics[:TOP_TACTICS],
		'tacticsTotal': len(ranked_tactics),
		'llmInsights': summarize_llm(cases)
	}
