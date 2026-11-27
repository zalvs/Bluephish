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

**Um terceiro escopo, `indicator`, que não rebaixa nada.** A mensagem idêntica
não ajuda no falso positivo mais comum: o host de imagens de um provedor de
e-mail (um `dXXXX.cloudfront.net`) que um motor de reputação acusa, e que volta
na newsletter da semana seguinte com outro assunto, outro corpo e outra imagem.
Um falso positivo corrigido grava, para cada host ou IP que um analisador acusou
e que a analista marcou como verificado, um precedente com o motivo que ela
escreveu. Nas análises
seguintes o precedente:

  * **vai para a IA**, junto do resultado do analisador que acusou o mesmo host,
    para que ela pese a acusação com o que a equipe já decidiu — e a IA só eleva
    veredito, nunca baixa (§8);
  * **vai para o passo a passo do veredito**, para quem abrir o caso ver na hora
    que aquele host já foi julgado, por quem e por quê;
  * **vira proposta de regra de whitelist de domínio**, que um admin aceita na
    aba Aprendido. É a regra, com as travas de sufixo público dela, que tira o
    host da análise — nunca o precedente sozinho.

Domínio, URL e IP aparecem no corpo, que quem ataca escreve: é por isso que o
precedente informa e não decide. Anexo nunca vira precedente, pelo mesmo piso
que impede rebaixar anexo malicioso. Falha aberta, ao contrário de `apply`: um
precedente que não pôde ser lido só deixa de informar.
"""

import datetime
import ipaddress
import logging
import urllib.parse

import sqlalchemy

import models
import prompt_guard
import whitelist
import whitelist_state

log = logging.getLogger(__name__)

SCOPE_CASE = 'case'
SCOPE_CONTENT = models.VerdictMemory.SCOPE_CONTENT
SCOPE_SENDER = models.VerdictMemory.SCOPE_SENDER
SCOPE_INDICATOR = models.VerdictMemory.SCOPE_INDICATOR
SCOPES = (SCOPE_CASE, SCOPE_CONTENT, SCOPE_SENDER)
# Os escopos que são proposta de regra de whitelist, e não liberação
PROPOSAL_SCOPES = (SCOPE_SENDER, SCOPE_INDICATOR)

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
			models.VerdictMemory.scope.in_(PROPOSAL_SCOPES)).first()
		if row is None or row.proposal_status != PROPOSAL_PENDING:
			return None
		row.proposal_status = PROPOSAL_ACCEPTED if accepted else PROPOSAL_DISMISSED
		row.whitelist_rule_id = str(whitelist_rule_id or '')[:32]
		rows = [row]
		if not accepted and row.scope == SCOPE_INDICATOR:
			# Recusar um host recusa todas as propostas pendentes dele, como aceitar
			# fecha todas (resolve_indicator_proposals): senão a IA continuaria
			# recebendo o host pelas outras linhas, e a tela diz que não recebe
			rows += session.query(models.VerdictMemory).filter(
				models.VerdictMemory.scope == SCOPE_INDICATOR,
				models.VerdictMemory.key == row.key,
				models.VerdictMemory.id != row.id,
				models.VerdictMemory.proposal_status == PROPOSAL_PENDING).all()
		if not accepted:
			for item in rows:
				item.proposal_status = PROPOSAL_DISMISSED
				item.revoked_at = now
				item.revoked_by = str(by or '')[:64]
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
	"""As memórias para a aba Aprendido, mais recentes primeiro.

	O teto vale por escopo, e o filtro de "em vigor" roda no banco: os precedentes
	de indicador chegam às dezenas por reclassificação, e um teto único sobre a
	tabela inteira empurraria para fora da tela a liberação de conteúdo que um
	admin precisa conseguir revogar.
	"""
	now = now or datetime.datetime.utcnow()
	session = models.get_session()
	try:
		views = []
		for scope in (SCOPE_CONTENT, SCOPE_SENDER, SCOPE_INDICATOR):
			query = session.query(models.VerdictMemory).filter(models.VerdictMemory.scope == scope)
			if not include_inactive:
				query = query.filter(sqlalchemy.or_(models.VerdictMemory.revoked_at.is_(None),
					models.VerdictMemory.proposal_status == PROPOSAL_PENDING))
			rows = query.order_by(models.VerdictMemory.id.desc()).limit(limit).all()
			views.extend(view(row, now) for row in rows)
		views.sort(key = lambda v: v['id'], reverse = True)
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


# --- precedentes de indicador ------------------------------------------------

# Tipos de observável que viram precedente, e o tipo de regra de whitelist que
# os cobre. URL vira o host dela: a regra de domínio cobre toda URL do host, e a
# imagem da semana que vem tem outro caminho
INDICATOR_TYPES = {'url': 'domain', 'domain': 'domain', 'ip': 'ip'}
# Teto por decisão: um e-mail com 300 links acusados não vira 300 propostas
MAX_INDICATORS_PER_DECISION = 20
# Teto do que vai para a IA: o prompt tem orçamento, e o motivo é texto livre
MAX_PRECEDENTS_FOR_MODEL = 10
MAX_REASON_FOR_MODEL = 240
MAX_REASONS_PER_INDICATOR = 3
FLAGGED_LEVELS = ('malicious', 'suspicious')
# Encurtadores e hospedagem de documentos e formulários: o host é de todos
SHARED_HOSTS = {
	'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
	'shorturl.at', 'rb.gy', 't.ly', 'lnkd.in', 'forms.gle', '1drv.ms', 'aka.ms',
	'docs.google.com', 'drive.google.com', 'forms.office.com', 'onedrive.live.com',
	'dropbox.com', 'www.dropbox.com', 'dl.dropboxusercontent.com', 'wetransfer.com', 'we.tl',
	'storage.googleapis.com', 'linktr.ee', 'canva.com', 'www.canva.com', 'notion.so',
	'docsend.com', 'mega.nz', 'mediafire.com', 'www.mediafire.com', 'github.com',
	'raw.githubusercontent.com', 'gist.github.com', 'pastebin.com', 'telegra.ph', 'ipfs.io',
}
# O inquilino destes sufixos compartilha arquivos de qualquer pessoa com quem
# recebe o link: contoso.sharepoint.com é da Contoso, o documento não
SHARED_HOST_SUFFIXES = ('sharepoint.com', 'blob.core.windows.net', 's3.amazonaws.com',
	'r2.dev', 'ipfs.dweb.link')


def indicator_key(kind, value):
	"""'domain:<host>' ou 'ip:<rede>' para um observável, ou '' quando ele não vira precedente."""
	rule_type = INDICATOR_TYPES.get(str(kind or '').split('_')[0])
	text = str(value or '').strip()
	if not rule_type or not text:
		return ''
	if kind == 'url':
		try:
			text = urllib.parse.urlsplit(text).hostname or ''
		except ValueError:
			return ''
	if rule_type == 'domain' and _is_ip_literal(text):
		# http://203.0.113.7/x: uma regra de domínio nunca casaria com isso
		rule_type = 'ip'
	normalized = whitelist.normalize_ip(text) if rule_type == 'ip' else whitelist.normalize_domain(text)
	if not normalized or (rule_type == 'domain' and is_shared_host(normalized)):
		return ''
	return '{0}:{1}'.format(rule_type, normalized)


def _is_ip_literal(text):
	try:
		ipaddress.ip_address(text.strip('[]'))
		return True
	except ValueError:
		return False


def is_shared_host(host):
	"""Se o host serve conteúdo de qualquer pessoa — e por isso não vira precedente.

	Um caso legítimo que passou por bit.ly ou por um formulário do Google não diz
	nada sobre o próximo link ali, que pode ser de quem ataca. Três formas: os
	hosts compartilhados conhecidos, os sufixos públicos da whitelist (onde
	qualquer um registra um nome) e o pai de um deles (google.com cobre
	sites.google.com). O inquilino de um sufixo público — d1a2b3c4.cloudfront.net,
	contoso.sharepoint.com — é de uma conta só; desses, só os que hospedam
	documentos de terceiros entram na lista.
	"""
	if host in SHARED_HOSTS or any(host.endswith('.' + suffix) for suffix in SHARED_HOST_SUFFIXES):
		return True
	if host in whitelist.PUBLIC_SUFFIXES:
		return True
	return any(suffix.endswith('.' + host) for suffix in whitelist.PUBLIC_SUFFIXES)


def split_key(key):
	rule_type, _sep, value = str(key or '').partition(':')
	return rule_type, value


def _collect(entries):
	"""[(tipo, valor, nível, analisador)] -> indicadores acusados, um por chave, em ordem."""
	found = {}
	for kind, value, level, analyzer in entries:
		if level not in FLAGGED_LEVELS:
			continue
		key = indicator_key(kind, value)
		if not key:
			continue
		item = found.setdefault(key, {'key': key, 'type': split_key(key)[0], 'value': split_key(key)[1],
			'level': level, 'analyzers': []})
		if level == 'malicious':
			item['level'] = 'malicious'
		if analyzer and analyzer not in item['analyzers']:
			item['analyzers'].append(analyzer)
	return list(found.values())


def flagged_from_reports(reports_observables):
	"""Os indicadores que os analisadores acusaram, a partir dos resultados crus da análise."""
	return _collect((r.get('observable_type'), r.get('observable_name'), r.get('analyzer_result'),
		r.get('analyzer_name')) for r in reports_observables or [])


def flagged_from_report(report):
	"""Os mesmos indicadores, a partir do report que vai aos destinos (tickets.build_report)."""
	report = report or {}
	entries = [(f.get('observableType'), f.get('observable'), f.get('level'), f.get('analyzer'))
		for f in report.get('findings') or []]
	# Um destino que não guarda os resultados por analisador ainda marca o
	# observável: sem saber quem acusou, o indicador entra sem analisador
	for observable in report.get('observables') or []:
		level = 'malicious' if observable.get('malicious') or observable.get('ioc') else (
			'suspicious' if observable.get('suspicious') else '')
		entries.append((observable.get('type'), observable.get('value'), level, ''))
	return _collect(entries)


def parse_chosen_keys(raw):
	"""As chaves que a analista marcou, do campo do formulário (vírgula ou linha)."""
	keys = []
	for part in str(raw or '').replace('\n', ',').split(','):
		part = part.strip()
		if part and part not in keys:
			keys.append(part)
	return keys


def select_indicators(flagged, chosen_keys):
	"""Os indicadores acusados que a analista marcou como verificados.

	A interseção, e não a lista que chegou: o formulário vem do navegador, e uma
	chave que os analisadores não acusaram neste caso não vira precedente.
	"""
	chosen = set(chosen_keys or [])
	return [item for item in flagged or [] if item.get('key') in chosen]


def learn_indicators(decision, flagged, by, now = None, ttl_days = DEFAULT_TTL_DAYS):
	"""Grava um precedente por indicador acusado num falso positivo corrigido.

	Não exige admin, ao contrário de `learn`: o precedente não rebaixa nada. Ele
	informa a IA — que só eleva — e propõe uma regra que só um admin cria.
	"""
	if not decision or decision.get('verdict') != 'Safe':
		return []
	wanted = []
	for item in flagged or []:
		key = item.get('key') or indicator_key(item.get('type'), item.get('value'))
		if key and key not in wanted:
			wanted.append(key)
	wanted = wanted[:MAX_INDICATORS_PER_DECISION]
	if not wanted:
		return []
	now = now or datetime.datetime.utcnow()
	expires = now + datetime.timedelta(days = ttl_days) if ttl_days else None
	session = models.get_session()
	try:
		created = []
		for key in wanted:
			row = models.VerdictMemory(
				scope = SCOPE_INDICATOR, key = key[:320], verdict = 'Safe',
				reason = decision.get('reason') or '', created_by = str(by or '')[:64],
				created_at = now, decision_id = decision.get('id'),
				record_ref = str(decision.get('recordRef') or '')[:300],
				expires_at = expires, proposal_status = PROPOSAL_PENDING)
			session.add(row)
			created.append(row)
		session.commit()
		return [view(row, now) for row in created]
	finally:
		session.close()


def _consultable(row, now):
	# Recusada é revogada; aceita continua valendo, porque a regra tirou o host
	# da análise e o precedente segue explicando por quê
	return is_active(row, now) and row.proposal_status != PROPOSAL_DISMISSED


def precedents_for(keys, now = None):
	"""{chave: resumo} dos precedentes em vigor para estas chaves. Falha aberta: {}."""
	keys = [key for key in keys or [] if key]
	if not keys:
		return {}
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return {}
	try:
		rows = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.scope == SCOPE_INDICATOR,
			models.VerdictMemory.key.in_(keys),
			models.VerdictMemory.revoked_at.is_(None)).order_by(models.VerdictMemory.id.desc()).all()
		found = {}
		for row in rows:
			if not _consultable(row, now):
				continue
			item = found.setdefault(row.key, {'count': 0, 'ids': [], 'latest': view(row, now), 'reasons': []})
			item['count'] += 1
			item['ids'].append(row.id)
			reason = (row.reason or '').strip()
			if reason and prompt_guard.inspect(reason)['injection']:
				# O motivo citou o ataque: mandá-lo à IA faria toda análise futura com
				# este host parecer tentativa de injeção. A decisão vale, o texto não vai
				reason = '(motivo retido: cita texto com forma de instrução)'
			if reason and reason not in item['reasons'] and len(item['reasons']) < MAX_REASONS_PER_INDICATOR:
				item['reasons'].append(reason)
		return found
	except Exception:
		log.warning('Não foi possível ler os precedentes de indicador', exc_info = True)
		return {}
	finally:
		try:
			session.close()
		except Exception:
			pass


def consult(reports_observables, now = None):
	"""Os precedentes que valem para os indicadores acusados nesta análise. Conta a consulta.

	Uma lista, na ordem em que os analisadores acusaram, com o que a IA e o passo
	a passo precisam: o indicador, quem o acusou agora, e o que a equipe decidiu.
	"""
	now = now or datetime.datetime.utcnow()
	try:
		flagged = flagged_from_reports(reports_observables)
		found = precedents_for([item['key'] for item in flagged], now)
	except Exception:
		log.warning('Não foi possível consultar os precedentes de indicador', exc_info = True)
		return []
	result = []
	for item in flagged:
		precedent = found.get(item['key'])
		if not precedent:
			continue
		latest = precedent['latest']
		result.append({'key': item['key'], 'type': item['type'], 'value': item['value'],
			'level': item['level'], 'analyzers': item['analyzers'], 'count': precedent['count'],
			'by': latest['by'], 'at': latest['at'], 'recordRef': latest['recordRef'],
			'reasons': precedent['reasons'], 'ids': precedent['ids']})
	register_hits([memory_id for item in result for memory_id in item['ids']], now)
	return result


def register_hits(memory_ids, now = None):
	"""Conta uma consulta em cada memória, num UPDATE só. Nunca levanta."""
	if not memory_ids:
		return
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return
	try:
		session.query(models.VerdictMemory).filter(models.VerdictMemory.id.in_(memory_ids)).update(
			{models.VerdictMemory.hits: models.VerdictMemory.hits + 1, models.VerdictMemory.last_hit_at: now},
			synchronize_session = False)
		session.commit()
	except Exception:
		session.rollback()
	finally:
		session.close()


def describe_for_model(precedents):
	"""O bloco que vai para a IA junto dos resultados dos analisadores, ou ''."""
	if not precedents:
		return ''
	lines = ['Analyst precedents recorded by this SOC (decisions about reputation flags, not about this email):']
	for item in precedents[:MAX_PRECEDENTS_FOR_MODEL]:
		reasons = '; '.join(reason[:MAX_REASON_FOR_MODEL] for reason in item['reasons']) or '(no reason recorded)'
		lines.append('- {0} {1}, flagged now by {2}: analysts reclassified {3} earlier email(s) flagged on this '
			'same {0} as legitimate (latest {4}). Analyst reason: {5}'.format(
			'host' if item['type'] == 'domain' else item['type'], item['value'],
			', '.join(item['analyzers']) or 'a reputation service', item['count'], item['at'][:10], reasons))
	if len(precedents) > MAX_PRECEDENTS_FOR_MODEL:
		lines.append('- … and {0} more'.format(len(precedents) - MAX_PRECEDENTS_FOR_MODEL))
	lines.append('A precedent only lowers the weight of the reputation flag on that exact host or IP. It says '
		'nothing about the sender, the text, the other links or where the call-to-action leads: judge those '
		'on their own.')
	return '\n'.join(lines)


def describe_for_trail(precedents):
	"""A linha do passo a passo do veredito, em português, ou ''."""
	if not precedents:
		return ''
	parts = []
	for item in precedents[:MAX_PRECEDENTS_FOR_MODEL]:
		parts.append('{0} (acusado agora por {1}) já foi julgado falso positivo em {2} caso(s), o último por '
			'{3} em {4}: "{5}"'.format(item['value'], ', '.join(item['analyzers']) or 'um analisador',
			item['count'], item['by'], item['at'][:10], (item['reasons'][0] if item['reasons'] else '—')[:200]))
	return ('Precedente da equipe: {0}. A IA recebeu este histórico; o veredito dos analisadores não muda por '
		'ele — para tirar o host da análise, um admin aceita a proposta em Configurações › Whitelist › '
		'Aprendido').format('; '.join(parts))


def rule_matches_indicator(rule, key):
	"""Se a regra de whitelist salva é exatamente o indicador proposto."""
	rule_type, value = split_key(key)
	if not rule or rule.get('type') != rule_type or not value:
		return False
	if rule_type == 'ip':
		return whitelist.normalize_ip(rule.get('value')) == value
	return rule.get('value') == value


def resolve_indicator_proposals(key, whitelist_rule_id, by, now = None):
	"""Fecha como aceitas todas as propostas pendentes deste indicador. Devolve quantas."""
	if not key:
		return 0
	session = models.get_session()
	try:
		rows = session.query(models.VerdictMemory).filter(
			models.VerdictMemory.scope == SCOPE_INDICATOR,
			models.VerdictMemory.key == key,
			models.VerdictMemory.proposal_status == PROPOSAL_PENDING).all()
		for row in rows:
			row.proposal_status = PROPOSAL_ACCEPTED
			row.whitelist_rule_id = str(whitelist_rule_id or '')[:32]
		session.commit()
		return len(rows)
	finally:
		session.close()
