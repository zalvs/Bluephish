"""A analista discordando do veredito — com nome, data e motivo.

Um e-mail que o pipeline condenou e uma pessoa confirmou ser legítimo precisa
parar de aparecer como phishing: na lista, nas contagens do painel executivo e
no ranking de remetentes. Sem isso, o falso positivo continua inflando o número
que a gestão lê, e a próxima analista abre o mesmo caso sem saber que alguém já
o resolveu.

Três regras sustentam o desenho:

  * **O motivo é obrigatório.** Uma reclassificação sem motivo é indistinguível
    de um clique errado — ou de uma conta comprometida limpando o próprio rastro.
  * **Nada é apagado.** O veredito original fica em `previous_verdict`, a linha
    é só de acréscimo, e desfazer é outra linha. A mais recente de um registro é
    a que vale.
  * **O banco é quem decide o que a tela mostra.** Os destinos (TheHive, Jira,
    disco) recebem a mesma decisão por `tickets.reclassify_*`, mas uma escrita
    que falhou lá fora não pode fazer a tela voltar a dizer "malicioso" sobre um
    e-mail que uma pessoa já liberou.

Sem Flask: a validação e a sobreposição são puras e testadas em
`test_reclassification.py`; só `record` e `load_latest` tocam o banco.
"""

import datetime
import json

import case_insights
import models

# As decisões que uma pessoa pode tomar sobre um veredito, e de onde cada uma
# parte. Duas, e deliberadamente assimétricas:
#
#   * **Legítimo** parte de malicioso ou suspeito. É a correção de um falso
#     positivo — a que dispara a errata ao denunciante e a que pode ensinar a
#     memória de veredito.
#   * **Malicioso** parte de suspeito — o pipeline não conseguiu concluir e uma
#     pessoa concluiu — ou de malicioso, e aí é uma *confirmação*: o veredito não
#     muda, mas o caso deixa de esperar decisão humana e sai da fila. Nunca parte
#     de legítimo: condenar um e-mail que o pipeline liberou é outro fluxo (um
#     incidente), e não deve ser um clique ao lado de "marcar como legítimo".
TARGET_VERDICT = 'Safe'
TRANSITIONS = {
	'Safe': ('Malicious', 'Suspicious'),
	'Malicious': ('Suspicious', 'Malicious')
}
ELIGIBLE_VERDICTS = TRANSITIONS[TARGET_VERDICT]

ACTION_RECLASSIFY = 'reclassify'
ACTION_REVERT = 'revert'

MIN_REASON_CHARS = 15
MAX_REASON_CHARS = 1000


def normalize_reason(text):
	"""(motivo, erro). O motivo é o que alguém vai ler seis semanas depois."""
	reason = ' '.join(str(text or '').split())
	if len(reason) < MIN_REASON_CHARS:
		return '', ('Escreva o motivo da reclassificação (pelo menos {0} caracteres): quem abrir '
			'este caso depois precisa saber por que ele deixou de ser phishing.').format(MIN_REASON_CHARS)
	if len(reason) > MAX_REASON_CHARS:
		return '', 'O motivo passou de {0} caracteres.'.format(MAX_REASON_CHARS)
	return reason, ''


def can_reclassify(verdict, target = TARGET_VERDICT):
	return verdict in TRANSITIONS.get(target, ())


def targets_for(verdict):
	"""As decisões disponíveis para um registro com este veredito, na ordem da tela."""
	return [target for target in ('Safe', 'Malicious') if can_reclassify(verdict, target)]


def is_false_positive(decision):
	"""Se esta decisão corrigiu um falso positivo — o que dispara errata e memória."""
	return bool(decision) and decision.get('action') == ACTION_RECLASSIFY 		and decision.get('verdict') == 'Safe' 		and decision.get('previousVerdict') in TRANSITIONS['Safe']


def is_confirmation(decision):
	"""Uma pessoa confirmou o que o pipeline já dizia. O veredito não muda."""
	return bool(decision) and decision.get('action') == ACTION_RECLASSIFY 		and decision.get('verdict') == decision.get('previousVerdict')


def _iso(moment):
	return moment.replace(microsecond = 0).isoformat() + 'Z' if moment else ''


def decision_of(row):
	"""Uma linha do banco no formato que a tela e os destinos recebem."""
	try:
		outcomes = json.loads(row.outcomes or '[]')
	except ValueError:
		outcomes = []
	return {
		'id': row.id,
		'recordRef': row.record_ref,
		'caseRef': row.case_ref or '',
		'action': row.action,
		'previousVerdict': row.previous_verdict,
		'verdict': row.verdict,
		'reason': row.reason,
		'by': row.created_by,
		'at': _iso(row.created_at),
		'outcomes': outcomes if isinstance(outcomes, list) else []
	}


def record(record_ref, case_ref, action, previous_verdict, verdict, reason, by, outcomes = None, now = None):
	"""Grava uma decisão e a devolve como dicionário."""
	session = models.get_session()
	try:
		row = models.CaseReclassification(
			record_ref = str(record_ref)[:300], case_ref = str(case_ref or '')[:64],
			action = action, previous_verdict = previous_verdict, verdict = verdict,
			reason = reason, created_by = str(by or '')[:64],
			created_at = now or datetime.datetime.utcnow(),
			outcomes = json.dumps(outcomes or [], ensure_ascii = False))
		session.add(row)
		session.commit()
		return decision_of(row)
	finally:
		session.close()


def save_outcomes(decision_id, outcomes):
	"""O que cada destino respondeu, gravado depois de a decisão já valer."""
	session = models.get_session()
	try:
		row = session.query(models.CaseReclassification).filter(
			models.CaseReclassification.id == decision_id).first()
		if row is not None:
			row.outcomes = json.dumps(outcomes or [], ensure_ascii = False)
			session.commit()
	finally:
		session.close()


def load_latest():
	"""A decisão mais recente de cada registro, como lista de dicionários.

	Uma consulta só, sobre uma tabela que cresce com cliques humanos e não com
	tráfego de e-mail — ler tudo e ficar com a última por registro é mais barato
	do que qualquer consulta agrupada que o SQLite do container aceite nas duas
	versões do SQLAlchemy.
	"""
	session = models.get_session()
	try:
		rows = session.query(models.CaseReclassification).order_by(models.CaseReclassification.id).all()
		latest = {}
		for row in rows:
			latest[row.record_ref] = decision_of(row)
		return list(latest.values())
	finally:
		session.close()


def history_for(record_ref):
	"""Toda decisão já tomada sobre um registro, mais antiga primeiro."""
	session = models.get_session()
	try:
		rows = session.query(models.CaseReclassification).filter(
			models.CaseReclassification.record_ref == str(record_ref)).order_by(
			models.CaseReclassification.id).all()
		return [decision_of(row) for row in rows]
	finally:
		session.close()


def case_key(case):
	"""O número do caso no TheHive que este registro representa, ou ''.

	Um caso do TheHive responde pelo próprio número; uma cópia em disco responde
	pelo `caseRef` que tickets.dispatch gravou nela. É o que faz as duas cópias de
	uma mesma análise seguirem uma decisão só.
	"""
	source = case.get('source') or 'thehive'
	if source == 'thehive':
		number = case.get('number')
		return str(number) if number not in (None, '') else ''
	return str(case.get('caseRef') or '')


def lookup(decisions, record_ref, case_ref = ''):
	"""A decisão que vale para um registro: pela referência, ou pelo caso."""
	by_ref = {}
	by_case = {}
	for decision in decisions or []:
		by_ref[decision['recordRef']] = decision
		if decision.get('caseRef'):
			current = by_case.get(decision['caseRef'])
			if current is None or decision['id'] > current['id']:
				by_case[decision['caseRef']] = decision
	candidates = [by_ref.get(str(record_ref))]
	if case_ref:
		candidates.append(by_case.get(str(case_ref)))
	candidates = [c for c in candidates if c]
	return max(candidates, key = lambda c: c['id']) if candidates else None


def overlay(cases, decisions):
	"""Aplica as decisões a uma lista de registros do histórico, no próprio dicionário.

	Quem sobrepõe é case_insights.apply_decision, a mesma função que o leitor de
	disco usa para a decisão gravada dentro do report.json.
	"""
	if not decisions:
		return cases
	for case in cases:
		decision = lookup(decisions, case_insights.record_ref(case), case_key(case))
		if decision:
			case_insights.apply_decision(case, decision)
	return cases
