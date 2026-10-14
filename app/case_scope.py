"""Quantas pessoas denunciaram este mesmo e-mail — e o que "mesmo" quer dizer.

Uma campanha de phishing não chega como um caso. Chega como quarenta denúncias
em vinte minutos, cada uma virando a sua própria análise e o seu próprio registro
num destino de ticket. Até aqui nada ligava as quarenta: a analista abria a
primeira sem saber que era a primeira de quarenta, e a quadragésima sem saber que
alguém já tinha decidido a primeira.

Este módulo grava, a cada análise, três resumos da mensagem, e é isso que liga:

  * **`content_key`** — assunto normalizado + remetente + corpo + os hosts das
    URLs. É "a mesma mensagem", no sentido estrito. É a chave que a memória de
    veredito casa, justamente porque é estrita.
  * **`body_key`** — só o corpo. Pega o caso em que o assunto mudou no
    encaminhamento (`ENC:`, um número de protocolo diferente por destinatário) e
    o conteúdo é o mesmo.
  * **`sender_key`** — o `From` normalizado pelo mesmo `whitelist.normalize_address`
    que as regras usam, para que uma lição de remetente e uma regra de whitelist
    falem do mesmo endereço.

Três decisões que parecem detalhe e não são:

  * **O resumo é de texto normalizado, não do `.eml`.** Dois destinatários da
    mesma campanha recebem bytes diferentes — cabeçalhos de entrega, pixel de
    rastreio com id por pessoa, `Received:` distintos. Resumir os bytes brutos
    diria que são quarenta mensagens diferentes, que é exatamente a resposta
    errada.
  * **Nenhuma contagem é inventada.** Um registro sem impressão digital gravada
    (uma análise anterior a este módulo) responde `None`, nunca zero: "ainda não
    medimos" e "só você denunciou" são afirmações diferentes, e a segunda é uma
    afirmação.
  * **Denunciante distinto, não denúncia distinta.** A mesma pessoa reencaminhando
    o mesmo e-mail três vezes é uma pessoa. O que a tela diz é quantas *pessoas*,
    e é esse número que pesa numa decisão.

Sem Flask e sem eventlet: puro exceto `record` e as consultas, testado em
`test_case_scope.py`.
"""

import datetime
import hashlib
import re

import case_insights
import models
import whitelist

# Quanto do corpo entra no resumo. Um corpo enorme não torna o casamento melhor,
# e cabeçalho de lista e rodapé de assinatura ficam no fim justamente onde
# variam mais entre destinatários
BODY_DIGEST_CHARS = 4000

# Teto de hosts no resumo de conteúdo. Ordenados e sem repetição, então o teto só
# corta cauda de rastreadores
MAX_HOSTS = 40

_HOST = re.compile(r'^[a-z0-9.+-]+://([^/?#\s]+)', re.IGNORECASE)


def normalize_body(text):
	"""O corpo reduzido ao que não varia entre destinatários da mesma campanha.

	Espaços colapsados, minúsculas, e os números longos trocados por um marcador
	— um boleto, um protocolo ou um id de rastreio mudam por pessoa enquanto a
	mensagem é a mesma. É a mesma troca que `case_insights.normalize_subject`
	faz no assunto, pelo mesmo motivo.
	"""
	body = str(text or '')
	body = re.sub(r'\d[\d.,/-]{3,}', '…', body)
	body = re.sub(r'\s+', ' ', body).strip().lower()
	return body[:BODY_DIGEST_CHARS]


def host_of(value):
	match = _HOST.match(str(value or '').strip())
	return match.group(1).lower() if match else ''


def hosts_of(observables):
	"""Os hosts distintos das URLs de uma análise, ordenados.

	Ordenados porque a ordem em que os observáveis foram extraídos não é um fato
	sobre a mensagem: duas cópias da mesma campanha não podem ter resumos
	diferentes porque um extrator visitou as âncoras noutra ordem.
	"""
	found = set()
	for observable in observables or []:
		kind = str(observable.get('type') or observable.get('dataType') or '')
		if kind.split('_')[0] not in ('url', 'domain'):
			continue
		value = observable.get('value') or observable.get('data') or observable.get('name') or ''
		host = host_of(value) or str(value or '').strip().lower()
		if host:
			found.add(host)
	return sorted(found)[:MAX_HOSTS]


def _digest(*parts):
	joined = '\x1f'.join(str(part or '') for part in parts)
	return hashlib.sha256(joined.encode('utf-8')).hexdigest()


def sender_key(address):
	return whitelist.normalize_address(address) or ''


def body_key(body):
	normalized = normalize_body(body)
	return _digest('body', normalized) if normalized else ''


def content_key(subject, sender, body, observables = None):
	"""O resumo de "esta mensagem exatamente".

	Vazio quando não há nem corpo nem assunto: um registro sem nenhum dos dois
	casaria com todo outro registro sem nenhum dos dois, o que é um casamento
	falso e o pior tipo de erro para uma chave que rebaixa veredito.
	"""
	normalized_subject = case_insights.normalize_subject(subject)
	normalized_body = normalize_body(body)
	if not normalized_subject and not normalized_body:
		return ''
	return _digest('content', normalized_subject, sender_key(sender),
		normalized_body, '|'.join(hosts_of(observables)))


def fingerprint(subject, sender, body, observables = None):
	"""As três chaves de uma análise, como dicionário."""
	return {
		'contentKey': content_key(subject, sender, body, observables),
		'bodyKey': body_key(body),
		'senderKey': sender_key(sender)
	}


# --- gravação ---------------------------------------------------------------

def record(record_refs, case_ref, subject, sender, reporter, body, observables,
		verdict, now = None, keys = None):
	"""Grava a impressão digital desta análise sob cada referência produzida.

	Devolve as chaves gravadas. Uma análise gravada no TheHive e no disco produz
	duas referências e duas linhas: é por referência que a tela de detalhe
	pergunta, e uma linha só deixaria metade das telas sem resposta.

	Nunca levanta: medir o escopo é o que enriquece a decisão, não o que a
	produz.
	"""
	# `keys` já calculadas pela análise têm precedência: são as mesmas que a
	# memória de veredito consultou, e é essa igualdade que faz a memória casar
	keys = keys if keys else fingerprint(subject, sender, body, observables)
	if not record_refs:
		return keys
	now = now or datetime.datetime.utcnow()
	try:
		session = models.get_session()
	except Exception:
		return keys
	try:
		for record_ref in record_refs:
			if not record_ref:
				continue
			session.add(models.AnalysisFingerprint(
				record_ref = str(record_ref)[:300], case_ref = str(case_ref or '')[:64],
				content_key = keys['contentKey'], body_key = keys['bodyKey'],
				sender_key = keys['senderKey'][:320], subject = str(subject or '')[:255],
				reporter = str(reporter or '')[:320], verdict = str(verdict or '')[:16],
				analyzed_at = now))
		session.commit()
	except Exception:
		try:
			session.rollback()
		except Exception:
			pass
	finally:
		try:
			session.close()
		except Exception:
			pass
	return keys


# --- consulta ---------------------------------------------------------------

def _iso(moment):
	return moment.replace(microsecond = 0).isoformat() + 'Z' if moment else ''


def _row_view(row):
	return {
		'recordRef': row.record_ref,
		'caseRef': row.case_ref or '',
		'reporter': row.reporter or '',
		'subject': row.subject or '',
		'verdict': row.verdict or '',
		'at': _iso(row.analyzed_at)
	}


def scope_for(record_ref):
	"""Quantas pessoas denunciaram a mesma mensagem que este registro.

	Devolve um dicionário com `reporters` em `None` quando não dá para dizer —
	registro sem impressão digital gravada, ou banco que não respondeu. `None`
	vira "—" na tela; um zero ali seria uma contagem que ninguém fez, e sobre
	esta pergunta um número errado muda uma decisão.

	`match` diz por onde os irmãos foram encontrados: `content` quando a mensagem
	é idêntica, `body` quando só o corpo bate — um assunto reescrito no
	encaminhamento não deve esconder que são a mesma campanha.
	"""
	unknown = {'known': False, 'reporters': None, 'reports': None, 'match': '',
		'firstSeen': '', 'lastSeen': '', 'records': []}
	try:
		session = models.get_session()
	except Exception:
		return unknown
	try:
		mine = session.query(models.AnalysisFingerprint).filter(
			models.AnalysisFingerprint.record_ref == str(record_ref)).order_by(
			models.AnalysisFingerprint.id.desc()).first()
		if mine is None:
			return unknown

		siblings, match = [], ''
		if mine.content_key:
			siblings = session.query(models.AnalysisFingerprint).filter(
				models.AnalysisFingerprint.content_key == mine.content_key).all()
			match = 'content'
		# O corpo é consultado sempre, e não só quando o conteúdo achou pouco:
		# numa campanha de quarenta denúncias em que três reescreveram o assunto,
		# o conteúdo acha trinta e sete e a tela diria trinta e sete
		if mine.body_key:
			by_body = session.query(models.AnalysisFingerprint).filter(
				models.AnalysisFingerprint.body_key == mine.body_key).all()
			if len(by_body) > len(siblings):
				siblings, match = by_body, 'body'
		if not siblings:
			siblings, match = [mine], 'content'

		# Uma análise gravada em dois destinos produziu duas linhas para a mesma
		# denúncia. O que se conta é denúncia, não linha: o caso é a unidade
		by_case = {}
		for row in siblings:
			key = row.case_ref or row.record_ref
			current = by_case.get(key)
			if current is None or row.id < current.id:
				by_case[key] = row
		reports = list(by_case.values())
		reports.sort(key = lambda row: row.analyzed_at or datetime.datetime.min)

		reporters = {(row.reporter or '').strip().lower() for row in reports}
		reporters.discard('')
		return {
			'known': True,
			# Denunciantes distintos. Quando nenhum registro guardou o
			# denunciante — instalação sem esse campo — a contagem não existe, e
			# `reports` continua valendo
			'reporters': len(reporters) if reporters else None,
			'reports': len(reports),
			'match': match,
			'firstSeen': _iso(reports[0].analyzed_at) if reports else '',
			'lastSeen': _iso(reports[-1].analyzed_at) if reports else '',
			'records': [_row_view(row) for row in reports[:50]]
		}
	except Exception:
		return unknown
	finally:
		try:
			session.close()
		except Exception:
			pass


def keys_for(record_ref):
	"""As chaves gravadas para um registro, ou None. É o que a memória consulta."""
	try:
		session = models.get_session()
	except Exception:
		return None
	try:
		row = session.query(models.AnalysisFingerprint).filter(
			models.AnalysisFingerprint.record_ref == str(record_ref)).order_by(
			models.AnalysisFingerprint.id.desc()).first()
		if row is None:
			return None
		return {'contentKey': row.content_key, 'bodyKey': row.body_key,
			'senderKey': row.sender_key, 'subject': row.subject, 'reporter': row.reporter,
			# A chave pela qual scope_for agrupa linhas numa denúncia só. É o que
			# uma reanálise grava como `case_ref` para não virar denúncia nova —
			# e precisa ser esta, e não a referência que a tela abriu: um caso
			# gravado no TheHive e no disco é aberto por qualquer das duas
			'reportKey': row.case_ref or row.record_ref}
	except Exception:
		return None
	finally:
		try:
			session.close()
		except Exception:
			pass
