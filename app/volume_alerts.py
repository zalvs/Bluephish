"""Alerta de volume — a equipe de SI sabendo da campanha antes da análise.

Uma campanha de phishing chega como uma rajada: dezenas de denúncias do mesmo
e-mail em poucos minutos. A análise automática trata uma de cada vez, e o
veredito da primeira pode demorar. Este módulo olha a fila ainda não analisada
e avisa a equipe quando um mesmo padrão — o assunto ou o remetente do e-mail
denunciado — passa de um limiar dentro de uma janela de tempo.

Três decisões que valem explicar
--------------------------------
1. **Nada é baixado para isto.** A detecção usa só o que a leitura da caixa já
   tem em memória (`inbox_poll_state['emails']`). Um e-mail que ainda é envelope
   — corpo não carregado — não entra na contagem, porque sem o corpo não se sabe
   o assunto nem o remetente do e-mail *denunciado*: no modo de denúncia por
   anexo, o `from` do envelope é o colega que encaminhou, não o atacante. Baixar
   corpo por ciclo para contar mais cedo gastaria o orçamento diário de download
   do provedor (THEPHISH_ARCHITECTURE.md §7.7.1), que falha fingindo ser rede.

2. **Cooldown por padrão, persistido.** Sem ele, uma campanha que continua na
   fila dispararia o mesmo alerta a cada ciclo de leitura. Fica em
   `data/volume_alerts.json`, ao lado do log de auditoria, e não em
   `configuration.json`: aquele arquivo carrega segredo e não deve ser regravado
   por um laço.

3. **O webhook é o conector genérico.** O destino, a autenticação, o template
   JSON, a trava SSRF revalidada no disparo e a recusa de redirect são os de
   `connectors.py`; só o contexto das variáveis muda. O assunto e o remetente
   são escritos por quem atacou — entram no corpo por `json.dumps`, nunca por
   concatenação.

`evaluate()` decide e marca; `fire()` envia e nunca levanta. Quem chama roda
`fire()` fora do semáforo da caixa: um webhook lento não pode segurar a leitura.
"""

import datetime
import email.utils
import json
import logging
import os
import traceback

import case_insights
import connectors
import mailer

log = logging.getLogger('volume_alerts')

CONFIG_FILE = connectors.CONFIG_FILE
CONFIG_SECTION = 'volumeAlerts'
CONNECTORS_SECTION = 'alertConnectors'

MAX_CONNECTORS = 10
MAX_RECIPIENTS = 20

STATE_FILE = os.environ.get('THEPHISH_VOLUME_ALERT_STATE', os.path.join(
	os.path.dirname(os.path.abspath(__file__)), 'data', 'volume_alerts.json'))

# Quantos disparos a tela mostra. É histórico de conferência, não auditoria —
# o que foi enviado para onde também vai para o log
RECENT_MAX = 30

# Faixas aceitas. O cooldown não desce de 5 minutos: abaixo disso ele deixa de
# segurar a repetição a cada ciclo de leitura, que é o motivo de existir
LIMITS = {
	'threshold': (2, 1000),
	'windowMinutes': (1, 7 * 24 * 60),
	'cooldownMinutes': (5, 30 * 24 * 60)
}

DEFAULTS = {
	'enabled': False,
	'bySubject': True,
	'bySender': True,
	'threshold': 5,
	'windowMinutes': 60,
	'cooldownMinutes': 240,
	'recipients': []
}

# Um Date no futuro é relógio errado ou cabeçalho forjado. Uma folga pequena
# cobre o primeiro; sem teto, o segundo manteria um e-mail na janela para sempre
FUTURE_TOLERANCE_MS = 10 * 60 * 1000

PATTERN_LABEL = {'subject': 'assunto', 'sender': 'remetente'}

VARIABLES = [
	{'name': 'patternType', 'type': 'texto', 'help': '"subject" ou "sender".'},
	{'name': 'patternLabel', 'type': 'texto', 'help': '"assunto" ou "remetente", para a mensagem.'},
	{'name': 'pattern', 'type': 'texto', 'help': 'O assunto normalizado ou o endereço do remetente.'},
	{'name': 'count', 'type': 'número', 'help': 'Quantos e-mails da fila repetem o padrão na janela.'},
	{'name': 'threshold', 'type': 'número', 'help': 'O limiar configurado.'},
	{'name': 'windowMinutes', 'type': 'número', 'help': 'O tamanho da janela, em minutos.'},
	{'name': 'firstSeen', 'type': 'texto', 'help': 'Chegada do mais antigo da rajada, ISO-8601.'},
	{'name': 'lastSeen', 'type': 'texto', 'help': 'Chegada do mais recente da rajada, ISO-8601.'},
	{'name': 'samples_csv', 'type': 'texto', 'help': 'Até três assuntos (alerta por remetente) ou remetentes (por assunto).'},
	{'name': 'samples', 'type': 'lista', 'help': 'Os mesmos exemplos como lista.'},
	{'name': 'message', 'type': 'texto', 'help': 'O alerta pronto em uma frase, para Teams, Slack e afins.'},
	{'name': 'detectedAt', 'type': 'texto', 'help': 'Quando o alerta foi detectado, ISO-8601.'}
]


# --------------------------------------------------------------------------- #
# Configuração                                                                 #
# --------------------------------------------------------------------------- #

def default_config():
	config = dict(DEFAULTS)
	config['recipients'] = []
	return config


def load_config(path = None):
	"""A configuração gravada sobre os padrões. Seção ausente é alerta desligado."""
	config = default_config()
	try:
		with open(path or CONFIG_FILE) as conf_file:
			stored = json.load(conf_file).get(CONFIG_SECTION, {}) or {}
	except Exception:
		return config
	if not isinstance(stored, dict):
		return config
	for key in DEFAULTS:
		if key in stored:
			config[key] = stored[key]
	return config


def save_config(entry, path = None):
	path = path or CONFIG_FILE
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[CONFIG_SECTION] = entry
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def _bounded_int(submitted, key, label):
	low, high = LIMITS[key]
	try:
		value = int(submitted.get(key))
	except (TypeError, ValueError):
		return None, '{0} precisa ser um número.'.format(label)
	if value < low or value > high:
		return None, '{0} precisa estar entre {1} e {2}.'.format(label, low, high)
	return value, None


def validate_config(submitted):
	"""(entrada, erro) para o que veio do formulário. As faixas estão em LIMITS."""
	submitted = submitted or {}
	entry = {
		'enabled': bool(submitted.get('enabled', False)),
		'bySubject': bool(submitted.get('bySubject', False)),
		'bySender': bool(submitted.get('bySender', False))
	}
	for key, label in (('threshold', 'A quantidade de e-mails'),
			('windowMinutes', 'A janela (em minutos)'),
			('cooldownMinutes', 'O cooldown (em minutos)')):
		value, error = _bounded_int(submitted, key, label)
		if error:
			return None, error
		entry[key] = value

	if entry['enabled'] and not (entry['bySubject'] or entry['bySender']):
		return None, 'Escolha ao menos um padrão: assunto ou remetente.'

	raw = submitted.get('recipients') or []
	if isinstance(raw, str):
		raw = raw.replace(';', ',').replace('\n', ',').split(',')
	recipients = []
	for value in raw:
		address = str(value or '').strip()
		if not address:
			continue
		if not mailer.looks_like_address(address):
			return None, '{0} não parece um endereço de e-mail.'.format(address)
		if address.lower() not in [r.lower() for r in recipients]:
			recipients.append(address)
	if len(recipients) > MAX_RECIPIENTS:
		return None, 'No máximo {0} destinatários.'.format(MAX_RECIPIENTS)
	entry['recipients'] = recipients
	return entry, None


def load_connectors(path = None):
	return connectors.load_all(path, CONNECTORS_SECTION)


# --------------------------------------------------------------------------- #
# Detecção — pura, e é a parte que os testes fixam                             #
# --------------------------------------------------------------------------- #

def sender_address(value):
	"""O endereço de um cabeçalho From, minúsculo. `Nome <a@b>` e `a@b` são o mesmo."""
	address = email.utils.parseaddr(str(value or ''))[1].strip().lower()
	return address if '@' in address else ''


def is_loaded(mail):
	# Envelope sem corpo não diz o assunto nem o remetente do e-mail denunciado
	return mail.get('bodyLoaded') is not False


def pending_count(emails):
	return sum(1 for mail in emails or [] if not is_loaded(mail))


def _iso(ms):
	return datetime.datetime.fromtimestamp(ms / 1000.0).replace(microsecond = 0).isoformat()


def pattern_key(pattern_type, pattern):
	return '{0}:{1}'.format(pattern_type, pattern)


def detect(emails, config, now_ms, cooldowns = None):
	"""Os alertas que esta fila justifica agora, já descontado o cooldown.

	Conta e-mails distintos (por UID) cuja chegada cai na janela e cujo padrão
	se repete ao menos `threshold` vezes. Não marca nada: isso é de `evaluate`.
	"""
	if not config.get('enabled'):
		return []
	cooldowns = cooldowns or {}
	window_start = now_ms - int(config['windowMinutes']) * 60 * 1000
	latest_accepted = now_ms + FUTURE_TOLERANCE_MS
	cooldown_ms = int(config['cooldownMinutes']) * 60 * 1000

	groups = {}
	for mail in emails or []:
		if not is_loaded(mail):
			continue
		received = mail.get('receivedAt')
		if not isinstance(received, (int, float)) or received < window_start or received > latest_accepted:
			continue
		subject = case_insights.normalize_subject(mail.get('attachedMail'))
		sender = sender_address(mail.get('attachedFrom'))
		candidates = []
		if config.get('bySubject') and subject:
			candidates.append(('subject', subject, sender))
		if config.get('bySender') and sender:
			candidates.append(('sender', sender, subject))
		for pattern_type, pattern, sample in candidates:
			group = groups.setdefault(pattern_key(pattern_type, pattern), {
				'patternType': pattern_type, 'pattern': pattern,
				'uids': set(), 'first': received, 'last': received, 'samples': []})
			group['uids'].add(mail.get('mailUID'))
			group['first'] = min(group['first'], received)
			group['last'] = max(group['last'], received)
			if sample and sample not in group['samples'] and len(group['samples']) < 3:
				group['samples'].append(sample)

	alerts = []
	for key, group in groups.items():
		count = len(group['uids'])
		if count < int(config['threshold']):
			continue
		last_fired = cooldowns.get(key)
		if isinstance(last_fired, (int, float)) and now_ms - last_fired < cooldown_ms:
			continue
		alerts.append({
			'key': key,
			'patternType': group['patternType'],
			'patternLabel': PATTERN_LABEL[group['patternType']],
			'pattern': group['pattern'],
			'count': count,
			'threshold': int(config['threshold']),
			'windowMinutes': int(config['windowMinutes']),
			'firstSeen': _iso(group['first']),
			'lastSeen': _iso(group['last']),
			'samples': group['samples'],
			'detectedAt': _iso(now_ms)
		})
	alerts.sort(key = lambda a: (-a['count'], a['key']))
	return alerts


def alert_message(alert):
	"""O alerta numa frase. Texto puro — quem monta JSON é o conector."""
	return '{0} e-mails na fila com o mesmo {1} "{2}" em {3} min, ainda não analisados.'.format(
		alert['count'], alert['patternLabel'], alert['pattern'], alert['windowMinutes'])


def alert_context(alert, secrets = None):
	"""O que os placeholders de um webhook de alerta podem ver."""
	context = dict(alert or {})
	context.pop('key', None)
	context['samples'] = list((alert or {}).get('samples') or [])
	context['samples_csv'] = ', '.join(context['samples'])
	context['message'] = alert_message(alert) if alert else ''
	context['_secrets'] = dict(secrets or {})
	return context


def sample_alert():
	"""Um alerta visivelmente de exemplo, para pré-visualizar e testar o webhook."""
	now = datetime.datetime.now().replace(microsecond = 0)
	return {
		'key': 'subject:[EXEMPLO] Sua conta será suspensa',
		'patternType': 'subject',
		'patternLabel': 'assunto',
		'pattern': '[EXEMPLO] Sua conta será suspensa',
		'count': 7,
		'threshold': 5,
		'windowMinutes': 60,
		'firstSeen': (now - datetime.timedelta(minutes = 40)).isoformat(),
		'lastSeen': now.isoformat(),
		'samples': ['exemplo@exemplo.invalid'],
		'detectedAt': now.isoformat()
	}


def email_text(alert):
	subject = 'Alerta de volume: {0} e-mails com o mesmo {1}'.format(alert['count'], alert['patternLabel'])
	lines = [
		alert_message(alert),
		'',
		'Padrão ({0}): {1}'.format(alert['patternLabel'], alert['pattern']),
		'E-mails na janela: {0} (limiar {1})'.format(alert['count'], alert['threshold']),
		'Primeiro: {0}'.format(alert['firstSeen']),
		'Último: {0}'.format(alert['lastSeen'])
	]
	if alert.get('samples'):
		lines.append('Exemplos de {0}: {1}'.format(
			'remetente' if alert['patternType'] == 'subject' else 'assunto', ', '.join(alert['samples'])))
	lines += ['', 'Os e-mails ainda aguardam análise na Caixa de e-mail do BluePhish.']
	return subject, '\n'.join(lines)


# --------------------------------------------------------------------------- #
# Estado — cooldown e últimos disparos                                         #
# --------------------------------------------------------------------------- #

def load_state(path = None):
	try:
		with open(path or STATE_FILE) as handle:
			state = json.load(handle)
	except Exception:
		state = {}
	if not isinstance(state, dict):
		state = {}
	cooldowns = state.get('cooldowns')
	recent = state.get('recent')
	return {
		'cooldowns': cooldowns if isinstance(cooldowns, dict) else {},
		'recent': recent if isinstance(recent, list) else []
	}


def save_state(state, path = None):
	path = path or STATE_FILE
	directory = os.path.dirname(path)
	if directory:
		os.makedirs(directory, exist_ok = True)
	temporary = path + '.tmp'
	with open(temporary, 'w') as handle:
		json.dump(state, handle, indent = '\t')
	os.replace(temporary, path)


def mark(state, alerts, now_ms):
	"""Registra o disparo no cooldown e esquece o que já passou do teto de cooldown."""
	oldest = now_ms - LIMITS['cooldownMinutes'][1] * 60 * 1000
	state['cooldowns'] = dict((key, value) for key, value in state['cooldowns'].items()
		if isinstance(value, (int, float)) and value >= oldest)
	for alert in alerts:
		state['cooldowns'][alert['key']] = now_ms
	return state


# --------------------------------------------------------------------------- #
# Execução                                                                     #
# --------------------------------------------------------------------------- #

def evaluate(emails, now_ms = None, config = None, state_path = None):
	"""Detecta e marca o cooldown na hora — antes do envio, para que duas
	avaliações seguidas (fim do ciclo e lote do carregador) não mandem o mesmo
	alerta duas vezes enquanto a primeira ainda está enviando."""
	config = load_config() if config is None else config
	if not config.get('enabled'):
		return []
	now_ms = int(now_ms if now_ms is not None else datetime.datetime.now().timestamp() * 1000)
	state = load_state(state_path)
	alerts = detect(emails, config, now_ms, state['cooldowns'])
	if alerts:
		save_state(mark(state, alerts, now_ms), state_path)
	return alerts


def deliver(alert, config, definitions):
	"""Envia um alerta por todo canal configurado. Devolve um resultado por canal."""
	results = []
	if config.get('recipients'):
		subject, body = email_text(alert)
		for address in config['recipients']:
			outcome = mailer.send(address, subject, body)
			results.append({'channel': 'email', 'target': address,
				'ok': bool(outcome.get('ok')), 'error': outcome.get('error', '')})
	for definition in definitions or []:
		if not definition.get('enabled'):
			continue
		outcome = connectors.deliver(definition, alert, context_builder = alert_context)
		results.append({'channel': 'webhook', 'target': definition.get('name', definition.get('id', '')),
			'ok': bool(outcome.get('ok')), 'error': outcome.get('error', '')})
	return results


def fire(alerts, config = None, definitions = None, state_path = None):
	"""Envia os alertas e guarda o que aconteceu. Nunca levanta."""
	try:
		config = load_config() if config is None else config
		definitions = load_connectors() if definitions is None else definitions
		entries = []
		for alert in alerts:
			results = deliver(alert, config, definitions)
			if not results:
				log.warning('Volume alert without any channel: {0}'.format(alert_message(alert)))
			for result in results:
				if result['ok']:
					log.info('Volume alert sent by {0} to {1}'.format(result['channel'], result['target']))
				else:
					log.warning('Volume alert not sent by {0} to {1}: {2}'.format(
						result['channel'], result['target'], result['error']))
			entries.append({
				'detectedAt': alert['detectedAt'],
				'patternType': alert['patternType'],
				'pattern': alert['pattern'],
				'count': alert['count'],
				'windowMinutes': alert['windowMinutes'],
				'results': results
			})
		state = load_state(state_path)
		state['recent'] = (entries + state['recent'])[:RECENT_MAX]
		save_state(state, state_path)
		return entries
	except Exception:
		log.error('Volume alert delivery failed: {0}'.format(traceback.format_exc()))
		return []
