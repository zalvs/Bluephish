"""O runtime do whitelist: contadores, suspensão automática e histórico curto.

O `whitelist.py` decide se uma regra casa. Este módulo decide o que fazer com o
casamento e guarda a consequência.

O laço que dá nome ao arquivo: uma regra de remetente rebaixa veredito, e cada
rebaixamento de um veredito que não era Safe fica registrado. Quando a mesma
regra esconde vereditos ruins demais numa janela curta, ela é **suspensa
sozinha** e para de rebaixar. É o detector de conta comprometida — um remetente
autenticado cujo conteúdo o pipeline continua achando malicioso é exatamente o
perfil de uma caixa tomada, e é o caso que um bypass puro tornaria invisível.

A suspensão vale a partir do evento que cruza o limiar, inclusive: a análise que
completa a conta **não** é rebaixada. Não faria sentido esconder o veredito que
serviu de prova de que a regra não deve mais valer.
"""

import datetime
import json
import threading

import models
import whitelist


# Limites padrão do laço de suspensão. Contam supressões, não denúncias: usuário
# denunciar newsletter legítima é rotina e não diz nada
DEFAULT_LIMITS = {
	'maliciousLimit': 3,
	'totalLimit': 5,
	'windowDays': 30,
}

# O histórico existe para a simulação de uma regra nova; janela curta, porque o
# conteúdo de verdade mora nos destinos de ticket
DEFAULT_HISTORY_RETENTION_DAYS = 90

# A supressão é o registro de segurança, não um dado operacional: sobrevive ao
# histórico para que a revisão de uma regra antiga ainda tenha o que ler
SUPPRESSION_RETENTION_DAYS = 365

# A limpeza roda no caminho da análise, então roda raro
PRUNE_INTERVAL_SECONDS = 3600
_last_prune = None
_prune_lock = threading.Lock()


def _limits(config = None):
	merged = dict(DEFAULT_LIMITS)
	for key in DEFAULT_LIMITS:
		value = (config or {}).get('whitelist' + key[0].upper() + key[1:])
		if isinstance(value, int) and value > 0:
			merged[key] = value
	return merged


# --- Suspensão e contadores -------------------------------------------------

def suspended_ids():
	"""Os ids das regras suspensas. Falha aberta em erro de banco.

	Aberta, e não fechada, porque um banco indisponível não deve transformar toda
	regra legítima em regra morta: a consequência seria enterrar a caixa de
	entrada em falso positivo. A trava de verdade — remetente precisa estar
	autenticado — não depende deste banco.
	"""
	try:
		session = models.get_session()
	except Exception:
		return set()
	try:
		rows = session.query(models.WhitelistRuleState).filter(
			models.WhitelistRuleState.suspended_at.isnot(None)).all()
		return {row.rule_id for row in rows}
	except Exception:
		return set()
	finally:
		try:
			session.close()
		except Exception:
			pass


def _state_for(session, rule_id):
	state = session.query(models.WhitelistRuleState).filter(
		models.WhitelistRuleState.rule_id == rule_id).first()
	if state is None:
		state = models.WhitelistRuleState(rule_id = rule_id, match_count = 0, suppression_count = 0)
		session.add(state)
	return state


def record_match(rule_id, now = None):
	"""Conta um casamento que não escondeu nada — o caso normal."""
	if not rule_id:
		return
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		state = _state_for(session, rule_id)
		state.match_count = (state.match_count or 0) + 1
		state.last_matched_at = now
		session.commit()
	except Exception:
		session.rollback()
	finally:
		session.close()


def register_downgrade(rule_id, original_verdict, message_from = '', message_subject = '',
		detail = '', config = None, now = None):
	"""Decide se este veredito pode ser rebaixado, e registra a consequência.

	Devolve (rebaixar, motivo). Quando `rebaixar` é falso, a regra acabou de ser
	suspensa: o veredito original vale, e a analista recebe o caso.
	"""
	now = now or datetime.datetime.utcnow()
	limits = _limits(config)
	window_start = now - datetime.timedelta(days = limits['windowDays'])

	session = models.get_session()
	try:
		previous = session.query(models.WhitelistSuppression).filter(
			models.WhitelistSuppression.rule_id == rule_id,
			models.WhitelistSuppression.occurred_at >= window_start).all()
		malicious = sum(1 for row in previous if row.original_verdict == 'Malicious')
		total = len(previous)

		if original_verdict == 'Malicious':
			malicious += 1
		total += 1

		crossed = ''
		if malicious >= limits['maliciousLimit']:
			crossed = 'escondeu {0} vereditos Malicious em {1} dias'.format(malicious, limits['windowDays'])
		elif total >= limits['totalLimit']:
			crossed = 'escondeu {0} vereditos não-Safe em {1} dias'.format(total, limits['windowDays'])

		state = _state_for(session, rule_id)
		state.last_matched_at = now

		if crossed:
			# O evento que cruza o limiar não é escondido: ele é a prova
			state.suspended_at = now
			state.suspended_reason = crossed[:255]
			session.commit()
			return False, crossed

		session.add(models.WhitelistSuppression(
			rule_id = rule_id, occurred_at = now,
			original_verdict = original_verdict or '',
			message_from = (message_from or '')[:320],
			message_subject = (message_subject or '')[:255],
			detail = (detail or '')[:500]))
		state.suppression_count = (state.suppression_count or 0) + 1
		state.match_count = (state.match_count or 0) + 1
		session.commit()
		return True, ''
	except Exception:
		session.rollback()
		# Sem conseguir registrar, não se rebaixa: um rebaixamento que ninguém
		# consegue auditar é o bypass invisível que este desenho existe para não ter
		return False, 'não foi possível registrar o rebaixamento'
	finally:
		session.close()


def clear_suspension(rule_id):
	"""Religa uma regra suspensa. Zera a janela para não suspender de novo na hora."""
	session = models.get_session()
	try:
		state = session.query(models.WhitelistRuleState).filter(
			models.WhitelistRuleState.rule_id == rule_id).first()
		if state is None:
			return False
		state.suspended_at = None
		state.suspended_reason = None
		session.query(models.WhitelistSuppression).filter(
			models.WhitelistSuppression.rule_id == rule_id).delete()
		state.suppression_count = 0
		session.commit()
		return True
	except Exception:
		session.rollback()
		return False
	finally:
		session.close()


def stats_for(rule_ids, window_days = 30, now = None):
	"""Números por regra para a interface: casamentos, supressões e suspensão."""
	now = now or datetime.datetime.utcnow()
	window_start = now - datetime.timedelta(days = window_days)
	stats = {rule_id: {'matchCount': 0, 'suppressionCount': 0, 'suppressionsInWindow': 0,
		'lastMatchedAt': None, 'suspended': False, 'suspendedReason': ''} for rule_id in rule_ids}
	if not rule_ids:
		return stats
	session = models.get_session()
	try:
		for chunk in _chunks(list(rule_ids)):
			_fill_stats(session, stats, chunk, window_start)
		return stats
	except Exception:
		return stats
	finally:
		session.close()


# O SQLite limita quantas variaveis cabem numa consulta (999 na configuracao
# padrao). A migracao do v1 ja produz mais de 460 regras de uma vez, entao a
# lista inteira num unico IN e uma quebra esperando o proximo lote de dominios
IN_CLAUSE_LIMIT = 500


def _chunks(values, size = IN_CLAUSE_LIMIT):
	for start in range(0, len(values), size):
		yield values[start:start + size]


def _fill_stats(session, stats, rule_ids, window_start):
	for state in session.query(models.WhitelistRuleState).filter(
			models.WhitelistRuleState.rule_id.in_(rule_ids)).all():
		stats[state.rule_id].update({
			'matchCount': state.match_count or 0,
			'suppressionCount': state.suppression_count or 0,
			'lastMatchedAt': state.last_matched_at.isoformat() + 'Z' if state.last_matched_at else None,
			'suspended': state.suspended_at is not None,
			'suspendedReason': state.suspended_reason or '',
		})
	for row in session.query(models.WhitelistSuppression).filter(
			models.WhitelistSuppression.rule_id.in_(rule_ids),
			models.WhitelistSuppression.occurred_at >= window_start).all():
		stats[row.rule_id]['suppressionsInWindow'] += 1


def suppressions_for(rule_id, limit = 50):
	"""O que a regra escondeu, do mais recente para o mais antigo."""
	session = models.get_session()
	try:
		rows = session.query(models.WhitelistSuppression).filter(
			models.WhitelistSuppression.rule_id == rule_id).order_by(
			models.WhitelistSuppression.occurred_at.desc()).limit(limit).all()
		return [{
			'occurredAt': row.occurred_at.isoformat() + 'Z' if row.occurred_at else None,
			'originalVerdict': row.original_verdict,
			'from': row.message_from,
			'subject': row.message_subject,
			'detail': row.detail,
		} for row in rows]
	except Exception:
		return []
	finally:
		session.close()


# --- Histórico curto e simulação -------------------------------------------

def record_analysis(from_address = '', from_domain = '', reply_to = '', subject = '',
		authenticated = False, verdict = '', final_verdict = '', downgraded_by = None,
		observables = None, config = None, now = None):
	"""Grava a linha do histórico e, de vez em quando, apara o que envelheceu."""
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		session.add(models.AnalysisHistory(
			analyzed_at = now,
			from_address = (from_address or '')[:320],
			from_domain = (from_domain or '')[:255],
			reply_to = (reply_to or '')[:320],
			subject = (subject or '')[:255],
			authenticated = bool(authenticated),
			verdict = verdict or '',
			final_verdict = final_verdict or verdict or '',
			downgraded_by = downgraded_by,
			observables = json.dumps(_trim_observables(observables), ensure_ascii = False)))
		session.commit()
	except Exception:
		session.rollback()
	finally:
		session.close()
	prune(config, now)


# Teto por tipo: um boletim com trezentas URLs não precisa entrar inteiro para a
# simulação responder o que interessa
MAX_OBSERVABLES_PER_TYPE = 40


def _trim_observables(observables):
	trimmed = {}
	for key in ('domain', 'url', 'hash', 'ip'):
		values = (observables or {}).get(key) or []
		unique = []
		for value in values:
			text = str(value)[:512]
			if text and text not in unique:
				unique.append(text)
			if len(unique) >= MAX_OBSERVABLES_PER_TYPE:
				break
		trimmed[key] = unique
	return trimmed


def prune(config = None, now = None):
	"""Apara histórico e supressões vencidos, no máximo uma vez por hora."""
	global _last_prune
	now = now or datetime.datetime.utcnow()
	with _prune_lock:
		if _last_prune is not None and (now - _last_prune).total_seconds() < PRUNE_INTERVAL_SECONDS:
			return
		_last_prune = now

	retention = (config or {}).get('whitelistHistoryRetentionDays')
	if not isinstance(retention, int) or retention <= 0:
		retention = DEFAULT_HISTORY_RETENTION_DAYS

	session = models.get_session()
	try:
		session.query(models.AnalysisHistory).filter(
			models.AnalysisHistory.analyzed_at < now - datetime.timedelta(days = retention)).delete()
		session.query(models.WhitelistSuppression).filter(
			models.WhitelistSuppression.occurred_at < now - datetime.timedelta(
				days = SUPPRESSION_RETENTION_DAYS)).delete()
		session.commit()
	except Exception:
		session.rollback()
	finally:
		session.close()


def history_count(days = 90, now = None):
	"""Quantas análises o histórico guarda na janela.

	A interface precisa deste número para saber se a simulação tem contra o que
	comparar. Sem ele, o botão Simular só pode responder "não há histórico", que
	na tela se lê como defeito.
	"""
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		return session.query(models.AnalysisHistory).filter(
			models.AnalysisHistory.analyzed_at >= now - datetime.timedelta(days = days)).count()
	except Exception:
		return 0
	finally:
		session.close()


def dry_run(rule, days = 30, now = None):
	"""Roda uma regra contra o histórico e conta o que ela teria pego.

	É a pergunta que evita a entrada catastrófica: "quantos e-mails isso teria
	afetado, e quantos deles não eram Safe?". Uma regra que teria escondido
	quatro vereditos Malicious não deveria chegar a ser salva.
	"""
	now = now or datetime.datetime.utcnow()
	window_start = now - datetime.timedelta(days = days)
	# Um conjunto com a regra sozinha, sempre ativa: a simulação pergunta pelo
	# alcance do padrão, não pelo prazo que ainda nem foi escolhido
	probe = whitelist.Ruleset(rules = [whitelist.normalize_rule(dict(rule, enabled = True,
		expires_at = None, permanent_reason = 'simulação'), now)])
	rule_type = probe.rules[0]['type'] if probe.rules else None
	if not rule_type:
		return {'analyzed': 0, 'matched': 0, 'notSafe': 0, 'samples': []}

	result = {'analyzed': 0, 'matched': 0, 'notSafe': 0, 'samples': []}
	session = models.get_session()
	try:
		rows = session.query(models.AnalysisHistory).filter(
			models.AnalysisHistory.analyzed_at >= window_start).order_by(
			models.AnalysisHistory.analyzed_at.desc()).all()
	except Exception:
		return result
	finally:
		session.close()

	for row in rows:
		result['analyzed'] += 1
		if not _row_matches(probe, rule_type, row, now):
			continue
		result['matched'] += 1
		if row.verdict and row.verdict != 'Safe':
			result['notSafe'] += 1
			if len(result['samples']) < 10:
				result['samples'].append({
					'analyzedAt': row.analyzed_at.isoformat() + 'Z' if row.analyzed_at else None,
					'from': row.from_address, 'subject': row.subject, 'verdict': row.verdict})
	return result


def _row_matches(probe, rule_type, row, now):
	if rule_type == whitelist.TYPE_SENDER:
		return bool(probe.match_sender(row.from_address, {'authenticated': row.authenticated},
			row.reply_to or '', now))
	try:
		observables = json.loads(row.observables or '{}')
	except Exception:
		return False
	if rule_type == whitelist.TYPE_DOMAIN:
		return any(probe.match_domain(value, now) for value in observables.get('domain') or [])
	if rule_type == whitelist.TYPE_URL:
		return any(probe.match_url(value, now) for value in observables.get('url') or [])
	if rule_type == whitelist.TYPE_HASH:
		return any(probe.match_hash(value, now) for value in observables.get('hash') or [])
	if rule_type == whitelist.TYPE_IP:
		return any(probe.match_ip(value, now) for value in observables.get('ip') or [])
	return False
