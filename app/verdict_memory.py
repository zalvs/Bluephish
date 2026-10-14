"""A memória de vereditos: o que uma correção humana ensina às análises seguintes.

Até aqui a plataforma registrava a correção e não aprendia com ela. Uma analista
marcava um falso positivo como legítimo, o histórico passava a dizer "legítimo"
— e a mesma mensagem, denunciada de novo no dia seguinte, recebia o mesmo
veredito errado e caía de novo na mesma fila.

Este módulo fecha o laço, e fecha com as mesmas travas que a whitelist já tem,
porque o poder é o mesmo: rebaixar um veredito.

**Dois escopos, deliberadamente diferentes.**

  * **`content` — a mensagem idêntica.** Casa pela `content_key` de
    `case_scope`: assunto, remetente, corpo e hosts, normalizados. Rebaixa
    sozinho, porque um casamento exato de conteúdo não é uma classe de e-mail, é
    o mesmo e-mail.
  * **`sender` — o remetente.** **Não rebaixa.** Vira uma proposta de regra de
    whitelist, que um admin aprova na tela de whitelist. Rebaixar por remetente
    sem passar por lá seria uma segunda via para o mesmo poder, sem a exigência
    de domínio autenticado nem a simulação — e um remetente liberado mês passado
    cuja caixa for tomada amanhã teria salvo-conduto invisível.

**As travas que valem para `content`:**

  * **Só rebaixa, nunca condena.** Confirmar malicioso não vira memória.
  * **Anexo malicioso nunca é rebaixado** — o mesmo piso da whitelist.
  * **Todo rebaixamento é contado** em `whitelist_state.register_downgrade`, sob
    o id `vm_<id>`. Uma memória que passa a esconder vereditos ruins demais numa
    janela é suspensa sozinha, exatamente como uma regra. É o que pega a mensagem
    "idêntica" cujo host passou a servir malware.
  * **Expira.** 180 dias, o mesmo prazo padrão de uma regra de whitelist.
  * **Desfazer a reclassificação revoga a memória** que ela criou.
  * **Sem conseguir registrar, não se rebaixa.** Um rebaixamento que ninguém
    consegue auditar é o bypass que este desenho existe para não ser.
"""

import datetime
import logging

import models
import whitelist_state

log = logging.getLogger(__name__)

SCOPE_CASE = 'case'
SCOPE_CONTENT = models.VerdictMemory.SCOPE_CONTENT
SCOPE_SENDER = models.VerdictMemory.SCOPE_SENDER
SCOPES = (SCOPE_CASE, SCOPE_CONTENT, SCOPE_SENDER)

DEFAULT_TTL_DAYS = 180

PROPOSAL_PENDING = 'pending'
PROPOSAL_ACCEPTED = 'accepted'
PROPOSAL_DISMISSED = 'dismissed'

# O prefixo sob o qual a memória é contada no laço de suspensão da whitelist.
# `whitelist_rule_state.rule_id` tem 32 caracteres; `vm_` mais um inteiro cabe
RULE_PREFIX = 'vm_'


def rule_id_of(memory_id):
	return '{0}{1}'.format(RULE_PREFIX, memory_id)


def _iso(moment):
	return moment.replace(microsecond = 0).isoformat() + 'Z' if moment else ''


def view(row, now = None):
	now = now or datetime.datetime.utcnow()
	return {
		'id': row.id,
		'scope': row.scope,
		'key': row.key,
		'verdict': row.verdict,
		'reason': row.reason,
		'by': row.created_by,
		'at': _iso(row.created_at),
		'decisionId': row.decision_id,
		'recordRef': row.record_ref,
		'expiresAt': _iso(row.expires_at),
		'revokedAt': _iso(row.revoked_at),
		'revokedBy': row.revoked_by,
		'hits': row.hits or 0,
		'lastHitAt': _iso(row.last_hit_at),
		'proposalStatus': row.proposal_status or '',
		'whitelistRuleId': row.whitelist_rule_id or '',
		'active': is_active(row, now)
	}


def is_active(row, now = None):
	now = now or datetime.datetime.utcnow()
	if row.revoked_at is not None:
		return False
	if row.expires_at is not None and row.expires_at <= now:
		return False
	return True


# --- aprender ---------------------------------------------------------------

def learn(decision, keys, scope, by, now = None, ttl_days = DEFAULT_TTL_DAYS):
	"""Grava o que uma correção de falso positivo ensina. Devolve as memórias criadas.

	`decision` é a reclassificação já gravada; `keys` são as chaves de
	`case_scope.keys_for` do registro. Sem chaves — uma análise anterior à
	impressão digital — não há o que casar, e nada é gravado: uma memória com
	chave vazia casaria com toda mensagem sem chave.

	`sender` grava as duas coisas: a mensagem idêntica (que rebaixa) e a proposta
	de regra de remetente (que espera um admin). Liberar o remetente e continuar
	condenando a mensagem exata que motivou a liberação não faria sentido.
	"""
	if scope not in (SCOPE_CONTENT, SCOPE_SENDER):
		return []
	if not decision or decision.get('verdict') != 'Safe':
		return []
	keys = keys or {}
	now = now or datetime.datetime.utcnow()
	expires = now + datetime.timedelta(days = ttl_days) if ttl_days else None

	wanted = []
	if keys.get('contentKey'):
		wanted.append((SCOPE_CONTENT, keys['contentKey'], ''))
	if scope == SCOPE_SENDER and keys.get('senderKey'):
		wanted.append((SCOPE_SENDER, keys['senderKey'], PROPOSAL_PENDING))
	if not wanted:
		return []

	session = models.get_session()
	try:
		created = []
		for memory_scope, key, status in wanted:
			row = models.VerdictMemory(
				scope = memory_scope, key = str(key)[:320], verdict = 'Safe',
				reason = decision.get('reason') or '', created_by = str(by or '')[:64],
				created_at = now, decision_id = decision.get('id'),
				record_ref = str(decision.get('recordRef') or '')[:300],
				expires_at = expires, proposal_status = status)
			session.add(row)
			created.append(row)
		session.commit()
		return [view(row, now) for row in created]
	finally:
		session.close()


def revoke_for_decision(decision_id, by, record_ref, now = None):
	"""Revoga o que uma decisão ensinou. Devolve quantas memórias foram revogadas.

	Chamado quando a reclassificação é desfeita: a lição não pode sobreviver à
	decisão que a tirou.

	Casado pelo id da decisão **e** pelo registro. O id sozinho não basta: uma
	decisão embutida num report.json em disco (outra instalação, um backup
	restaurado) traz o id do banco que a gravou, e esse número pode ser o de uma
	decisão diferente aqui — revogar por ele apagaria a lição de outro caso.
	"""
	if decision_id is None or not record_ref:
		return 0
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		rows = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.decision_id == decision_id,
			models.VerdictMemory.record_ref == str(record_ref),
			models.VerdictMemory.revoked_at.is_(None)).all()
		for row in rows:
			row.revoked_at = now
			row.revoked_by = str(by or '')[:64]
			if row.proposal_status == PROPOSAL_PENDING:
				row.proposal_status = PROPOSAL_DISMISSED
		session.commit()
		return len(rows)
	finally:
		session.close()


def revoke(memory_id, by, now = None):
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		row = session.query(models.VerdictMemory).filter(models.VerdictMemory.id == memory_id).first()
		if row is None or row.revoked_at is not None:
			return None
		row.revoked_at = now
		row.revoked_by = str(by or '')[:64]
		if row.proposal_status == PROPOSAL_PENDING:
			row.proposal_status = PROPOSAL_DISMISSED
		session.commit()
		return view(row, now)
	finally:
		session.close()


def get(memory_id, now = None):
	"""Uma memória pelo id, ou None."""
	session = models.get_session()
	try:
		row = session.query(models.VerdictMemory).filter(models.VerdictMemory.id == memory_id).first()
		return view(row, now) if row is not None else None
	finally:
		session.close()


def resolve_proposal(memory_id, accepted, by, whitelist_rule_id = '', now = None):
	"""Marca uma proposta de remetente como aceita (virou regra) ou recusada."""
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		row = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.id == memory_id,
			models.VerdictMemory.scope == SCOPE_SENDER).first()
		if row is None or row.proposal_status != PROPOSAL_PENDING:
			return None
		row.proposal_status = PROPOSAL_ACCEPTED if accepted else PROPOSAL_DISMISSED
		row.whitelist_rule_id = str(whitelist_rule_id or '')[:32]
		if not accepted:
			row.revoked_at = now
			row.revoked_by = str(by or '')[:64]
		session.commit()
		return view(row, now)
	finally:
		session.close()


# --- consultar --------------------------------------------------------------

def match_content(content_key, now = None):
	"""A memória de conteúdo em vigor para esta chave, ou None. Falha fechada.

	Fechada, ao contrário de `whitelist_state.suspended_ids`, que falha aberta: lá
	a falha enterraria a caixa em falso positivo desligando regras; aqui a falha
	rebaixaria veredito sem registro. Um banco que não responde não libera nada.
	"""
	if not content_key:
		return None
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return None
	try:
		rows = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.scope == SCOPE_CONTENT,
			models.VerdictMemory.key == content_key,
			models.VerdictMemory.revoked_at.is_(None)).order_by(models.VerdictMemory.id.desc()).all()
		for row in rows:
			if is_active(row, now):
				return view(row, now)
		return None
	except Exception:
		return None
	finally:
		try:
			session.close()
		except Exception:
			pass


def is_suspended(memory_id):
	"""Se o laço da whitelist suspendeu esta memória. Falha fechada: na dúvida, suspensa."""
	try:
		session = models.get_session()
	except Exception:
		return True
	try:
		state = session.query(models.WhitelistRuleState).filter(
			models.WhitelistRuleState.rule_id == rule_id_of(memory_id)).first()
		return state is not None and state.suspended_at is not None
	except Exception:
		return True
	finally:
		try:
			session.close()
		except Exception:
			pass


def register_hit(memory_id, now = None):
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return
	try:
		row = session.query(models.VerdictMemory).filter(models.VerdictMemory.id == memory_id).first()
		if row is not None:
			row.hits = (row.hits or 0) + 1
			row.last_hit_at = now
			session.commit()
	except Exception:
		session.rollback()
	finally:
		session.close()


def apply(verdict, content_key, malicious_attachment, message_from = '', subject = '',
		config = None, now = None):
	"""Decide se a memória rebaixa este veredito. Devolve (veredito, nota ou None, memória ou None).

	Puro na decisão e com efeito só no registro: é chamado de `terminate_analysis`
	depois da whitelist, e só quando ela não rebaixou.
	"""
	if verdict == 'Safe' or not content_key:
		return verdict, None, None
	memory = match_content(content_key, now)
	if memory is None:
		return verdict, None, None

	if malicious_attachment:
		return verdict, ('Esta mensagem foi liberada por {0} em {1}, mas agora entregou anexo malicioso: '
			'o veredito {2} não é rebaixado').format(memory['by'], memory['at'][:10], verdict), memory
	if is_suspended(memory['id']):
		return verdict, ('A liberação desta mensagem por {0} está suspensa: ela escondeu vereditos ruins '
			'demais. O veredito {1} é mantido').format(memory['by'], verdict), memory

	allowed, why = whitelist_state.register_downgrade(
		rule_id_of(memory['id']), verdict, message_from = message_from, message_subject = subject,
		detail = 'memória de veredito: rebaixado de {0} para Safe'.format(verdict),
		config = config, now = now)
	if not allowed:
		return verdict, ('A liberação desta mensagem por {0} foi SUSPENSA agora ({1}). O veredito {2} é '
			'mantido — verifique se a mensagem mudou de natureza').format(memory['by'], why, verdict), memory

	register_hit(memory['id'], now)
	return 'Safe', ('Mensagem idêntica à que {0} reclassificou como legítima em {1}: rebaixado de {2} '
		'para Safe. Motivo registrado: {3}').format(memory['by'], memory['at'][:10], verdict,
		(memory['reason'] or '')[:200]), memory


def list_memories(include_inactive = False, limit = 200, now = None):
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		rows = session.query(models.VerdictMemory).order_by(models.VerdictMemory.id.desc()).limit(limit).all()
		views = [view(row, now) for row in rows]
		return views if include_inactive else [v for v in views
			if v['active'] or v['proposalStatus'] == PROPOSAL_PENDING]
	finally:
		session.close()


def for_decision(decision_id, now = None):
	if decision_id is None:
		return []
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return []
	try:
		rows = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.decision_id == decision_id).all()
		return [view(row, now) for row in rows]
	except Exception:
		return []
	finally:
		session.close()
