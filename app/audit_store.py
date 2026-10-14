"""Onde a trilha de auditoria é escrita, por quanto tempo fica, e para onde é copiada.

`auth.audit()` compõe o registro; este módulo decide o destino. `audit_trail.py`
lê de volta. A configuração mora em `configuration.json`, na chave `auditLog`, e
só global_admin a altera (§4.6.2) — encurtar a retenção apaga histórico, e é o
jeito mais curto de alguém sumir com o próprio rastro.

Quatro decisões que não são óbvias lendo o código:

1. **Tempo e teto valem juntos.** Um arquivo por dia (ou antes, quando ele passa
   de um décimo do teto), e dois cortes depois de cada virada: sai o que é mais
   velho que a retenção, e sai o mais antigo enquanto o total passar do teto. O
   teto vence o prazo — é o que impede a trilha de encher o disco —, e quando
   ele vence a tela diz isso, porque uma retenção prometida que não está sendo
   cumprida é exatamente o que uma auditoria precisa saber.

2. **Há um piso.** Nem prazo nem teto descem abaixo de MIN_RETENTION_DAYS e
   MIN_MEGABYTES, e isso é conferido no servidor. Um global_admin comprometido
   não zera a trilha pela tela.

3. **A pasta fica dentro do volume de dados.** "Aonde" é uma subpasta de
   `data/` — o único lugar do container que sobrevive a um rebuild. Um caminho
   livre deixaria a tela escrever em qualquer lugar do sistema de arquivos, e
   uma pasta de outro recurso (os originais, os renders) teria seus arquivos
   apagados pela poda dele. Trocar a pasta leva os arquivos junto: a tela de
   Auditoria continua enxergando o histórico inteiro.

4. **O syslog é mais um consumidor da trava de SSRF** — o sétimo. É um endereço
   que alguém digitou, e o que vai para lá são os IPs e as ações de todo mundo.
   Rede interna liberada (um SIEM mora nela), metadados da nuvem nunca. O nome é
   resolvido e validado ao aplicar a configuração, e o handler recebe o IP já
   validado: ele nunca resolve o nome de novo, então não há DNS rebinding entre
   a checagem e o envio.
"""

import datetime
import json
import logging
import logging.handlers
import os
import re
import socket
import threading


CONFIG_FILE = 'configuration.json'
CONFIG_KEY = 'auditLog'
LOG_NAME = 'auth.log'

MIN_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 3650
MIN_MEGABYTES = 10
MAX_MEGABYTES = 10240

DEFAULTS = {
	'folder': '',
	'retentionDays': 365,
	# 30 MB: o mesmo espaço que o RotatingFileHandler de 5 MB × 6 arquivos ocupava
	'maxMegabytes': 30,
	'syslog': {'enabled': False, 'host': '', 'port': 514, 'protocol': 'udp'},
}

# Pastas de outros recursos dentro de data/. A poda de cada um apaga o que acha
# lá dentro, e a trilha não pode morar onde outra coisa faz limpeza
RESERVED_FOLDERS = frozenset(['originals', 'rendered', 'analises', 'yara', 'cache', 'tmp'])

FOLDER_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')

# Um arquivo girado: auth.log.20260925-000000 (ou -1, -2 se virou duas vezes no
# mesmo segundo). Os antigos, do RotatingFileHandler, são auth.log.1 … auth.log.5
STAMP_FORMAT = '%Y%m%d-%H%M%S'
_STAMPED = re.compile(r'^\.(\d{8}-\d{6})(?:-(\d+))?$')
_LEGACY = re.compile(r'^\.(\d+)$')

SYSLOG_TIMEOUT = 3


# --- Arquivos ----------------------------------------------------------------

def rotated_files(path):
	"""As cópias giradas da trilha, da mais antiga para a mais nova, sem o arquivo atual.

	Primeiro as do formato antigo (auth.log.5 é a mais velha), depois as datadas,
	na ordem do nome — que é a ordem em que foram escritas.
	"""
	folder = os.path.dirname(path) or '.'
	base = os.path.basename(path)
	try:
		names = os.listdir(folder)
	except OSError:
		return []
	legacy, stamped = [], []
	for name in names:
		if not name.startswith(base + '.'):
			continue
		suffix = name[len(base):]
		match = _STAMPED.match(suffix)
		if match:
			stamped.append((match.group(1), int(match.group(2) or 0), name))
			continue
		match = _LEGACY.match(suffix)
		if match:
			legacy.append((int(match.group(1)), name))
	ordered = [name for _, name in sorted(legacy, reverse = True)]
	ordered += [name for _, _, name in sorted(stamped)]
	return [os.path.join(folder, name) for name in ordered]


def trail_files(path):
	"""Todos os arquivos da trilha, do mais antigo ao atual."""
	files = rotated_files(path)
	if os.path.isfile(path):
		files.append(path)
	return files


def _size(name):
	try:
		return os.path.getsize(name)
	except OSError:
		return 0


def _mtime(name):
	try:
		return datetime.datetime.fromtimestamp(os.path.getmtime(name))
	except OSError:
		return None


def prune(path, retention_days, max_bytes, now = None):
	"""Apaga o que passou do prazo e, depois, o mais antigo enquanto passar do teto.

	O arquivo atual nunca é apagado aqui — ele é o que está sendo escrito.
	Devolve {'expired': n, 'overCap': n}; `overCap` > 0 é o teto cortando antes
	do prazo, e a tela avisa.
	"""
	now = now or datetime.datetime.now()
	limit = now - datetime.timedelta(days = retention_days)
	removed = {'expired': 0, 'overCap': 0}
	kept = []
	for name in rotated_files(path):
		# A última escrita de uma cópia girada é o registro mais novo dela: se até
		# ele passou do prazo, o arquivo inteiro passou
		written = _mtime(name)
		if written is not None and written < limit and _remove(name):
			removed['expired'] += 1
			continue
		kept.append(name)
	total = sum(_size(name) for name in kept) + _size(path)
	while kept and total > max_bytes:
		oldest = kept.pop(0)
		size = _size(oldest)
		if _remove(oldest):
			removed['overCap'] += 1
			total -= size
	return removed


def _remove(name):
	try:
		os.remove(name)
		return True
	except OSError as error:
		print("[ERROR]_[audit_store]: não foi possível apagar {0}: {1}".format(name, error))
		return False


_RECORD_AT = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')


def _first_record_at(name):
	try:
		with open(name, encoding = 'utf-8', errors = 'replace') as handle:
			for line in handle:
				match = _RECORD_AT.match(line)
				if match:
					return datetime.datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
	except OSError:
		pass
	return None


def usage(path):
	"""O que a trilha ocupa agora — a linha de uso da tela de configuração."""
	files = trail_files(path)
	oldest = None
	for name in files:
		oldest = _first_record_at(name)
		if oldest is not None:
			break
	return {
		'files': len(files),
		'bytes': sum(_size(name) for name in files),
		'oldest': oldest.strftime('%Y-%m-%d %H:%M:%S') if oldest else None,
	}


def _stamped_name(path, when = None):
	stamp = (when or datetime.datetime.now()).strftime(STAMP_FORMAT)
	candidate = '{0}.{1}'.format(path, stamp)
	suffix = 1
	while os.path.exists(candidate):
		candidate = '{0}.{1}-{2}'.format(path, stamp, suffix)
		suffix += 1
	return candidate


# --- O handler do arquivo ------------------------------------------------------

class AuditFileHandler(logging.handlers.BaseRotatingHandler):
	"""Um arquivo por dia, girado antes se passar de um décimo do teto, e podado a cada virada."""

	def __init__(self, filename, retention_days, max_bytes):
		self.retention_days = retention_days
		self.max_bytes = max_bytes
		# Um décimo do teto por arquivo, entre 1 MB e 100 MB: com isso o corte pelo
		# teto tira no máximo ~10% da trilha de uma vez, nunca metade dela
		self.segment_bytes = min(max(max_bytes // 10, 1024 * 1024), 100 * 1024 * 1024)
		self.last_prune = {'expired': 0, 'overCap': 0}
		logging.handlers.BaseRotatingHandler.__init__(self, filename, 'a', encoding = 'utf-8', delay = False)
		written = _mtime(self.baseFilename)
		self.opened_day = (written or datetime.datetime.now()).date()

	def shouldRollover(self, record):
		if self.stream is None:
			self.stream = self._open()
		self.stream.seek(0, 2)
		if datetime.datetime.now().date() != self.opened_day and self.stream.tell() > 0:
			return True
		return self.stream.tell() >= self.segment_bytes

	def doRollover(self):
		if self.stream:
			self.stream.close()
			self.stream = None
		if os.path.exists(self.baseFilename) and _size(self.baseFilename) > 0:
			os.rename(self.baseFilename, _stamped_name(self.baseFilename))
		self.stream = self._open()
		self.opened_day = datetime.datetime.now().date()
		self.last_prune = prune(self.baseFilename, self.retention_days, self.max_bytes)
		if self.last_prune['expired'] or self.last_prune['overCap']:
			print("[INFO]_[audit_store]: trilha podada: {0} arquivo(s) fora do prazo, {1} pelo teto".format(
				self.last_prune['expired'], self.last_prune['overCap']))


# --- O handler do syslog -------------------------------------------------------

class AuditSyslogHandler(logging.handlers.SysLogHandler):
	"""SysLogHandler que não despeja traceback a cada falha e guarda a última."""

	def __init__(self, address, socktype):
		self.last_error = None
		self.sent = 0
		logging.handlers.SysLogHandler.__init__(self, address = address,
			facility = logging.handlers.SysLogHandler.LOG_AUTH, socktype = socktype)
		if getattr(self, 'socket', None) is not None:
			# Um SIEM que parou de ler não pode travar o login de ninguém
			self.socket.settimeout(SYSLOG_TIMEOUT)

	def emit(self, record):
		# O estado é o do último envio: um SIEM que voltou deixa de aparecer como fora
		self.last_error = None
		logging.handlers.SysLogHandler.emit(self, record)
		if self.last_error is None:
			self.sent += 1

	def handleError(self, record):
		# A classe-mãe chama isto em vez de levantar; sem esta troca, cada registro
		# com o SIEM fora do ar despejaria um traceback no console
		import sys
		error = sys.exc_info()[1]
		self.last_error = 'falha ao enviar: {0}'.format(error)[:200] if error else 'falha ao enviar'


def resolve_syslog(host, port, protocol):
	"""(ip, erro): o endereço que o handler vai usar, já passado pela trava de SSRF.

	A validação é a mesma dos outros consumidores (custom_analyzers.validate_destination),
	com rede interna liberada — um SIEM mora nela — e metadados da nuvem recusados.
	Todos os endereços do nome são checados; o handler recebe um deles, fixo.
	"""
	# Importado aqui: auth importa este módulo na subida, e custom_analyzers puxa o
	# registro de analisadores inteiro — que nada tem a ver com escrever a trilha
	import custom_analyzers
	host = str(host or '').strip().strip('[]')
	literal = '[{0}]'.format(host) if ':' in host else host
	ok, error = custom_analyzers.validate_destination('http://{0}:{1}'.format(literal, port),
		allow_internal = True, require_https = False)
	if not ok:
		return None, error
	socktype = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
	try:
		infos = socket.getaddrinfo(host, port, 0, socktype)
	except socket.gaierror:
		infos = []
	if not infos:
		return None, 'Não consegui resolver o nome {0}.'.format(host)
	return infos[0][4][0], None


# --- Configuração --------------------------------------------------------------

def valid_folder(folder):
	folder = str(folder or '')
	if folder == '':
		return True
	return bool(FOLDER_RE.match(folder)) and folder.lower() not in RESERVED_FOLDERS and folder not in ('.', '..')


def _clamp(value, low, high, default):
	try:
		return min(max(int(value), low), high)
	except (TypeError, ValueError):
		return default


def load_config(path = CONFIG_FILE):
	try:
		with open(path) as handle:
			stored = json.load(handle).get(CONFIG_KEY) or {}
	except Exception:
		stored = {}
	syslog = dict(DEFAULTS['syslog'])
	syslog.update({key: value for key, value in (stored.get('syslog') or {}).items() if key in syslog})
	folder = stored.get('folder', DEFAULTS['folder'])
	# Uma configuração gravada à mão abaixo do piso não é obedecida
	return {
		'folder': folder if valid_folder(folder) else '',
		'retentionDays': _clamp(stored.get('retentionDays', DEFAULTS['retentionDays']),
			MIN_RETENTION_DAYS, MAX_RETENTION_DAYS, DEFAULTS['retentionDays']),
		'maxMegabytes': _clamp(stored.get('maxMegabytes', DEFAULTS['maxMegabytes']),
			MIN_MEGABYTES, MAX_MEGABYTES, DEFAULTS['maxMegabytes']),
		'syslog': syslog,
	}


def save_config(config, path = CONFIG_FILE):
	with open(path) as handle:
		conf_dict = json.load(handle)
	conf_dict[CONFIG_KEY] = config
	with open(path, 'w') as handle:
		json.dump(conf_dict, handle, indent = '\t')


def validate(form):
	"""(config, erro) a partir do formulário. O piso é conferido aqui, não só na tela."""
	folder = str(form.get('folder') or '').strip().strip('/\\')
	if not valid_folder(folder):
		return None, ('A pasta precisa ser um nome simples dentro do volume de dados (letras, números, '
			'ponto, hífen, sublinhado), e não pode ser a pasta de outro recurso ({0}).'.format(
				', '.join(sorted(RESERVED_FOLDERS))))
	try:
		days = int(str(form.get('retentionDays') or '').strip())
		megabytes = int(str(form.get('maxMegabytes') or '').strip())
	except ValueError:
		return None, 'Retenção e teto precisam ser números inteiros.'
	if days < MIN_RETENTION_DAYS or days > MAX_RETENTION_DAYS:
		return None, 'A retenção vai de {0} a {1} dias.'.format(MIN_RETENTION_DAYS, MAX_RETENTION_DAYS)
	if megabytes < MIN_MEGABYTES or megabytes > MAX_MEGABYTES:
		return None, 'O teto vai de {0} a {1} MB.'.format(MIN_MEGABYTES, MAX_MEGABYTES)

	enabled = str(form.get('syslogEnabled') or '') == 'true'
	host = str(form.get('syslogHost') or '').strip()
	protocol = str(form.get('syslogProtocol') or 'udp').strip().lower()
	if protocol not in ('udp', 'tcp'):
		return None, 'O protocolo do syslog é UDP ou TCP.'
	try:
		port = int(str(form.get('syslogPort') or '514').strip())
	except ValueError:
		return None, 'A porta do syslog precisa ser um número.'
	if port < 1 or port > 65535:
		return None, 'A porta do syslog vai de 1 a 65535.'
	if len(host) > 253:
		return None, 'Endereço do syslog longo demais.'
	if enabled:
		if not host:
			return None, 'Informe o servidor syslog, ou desligue o envio.'
		_, error = resolve_syslog(host, port, protocol)
		if error:
			return None, error
	return {
		'folder': folder,
		'retentionDays': days,
		'maxMegabytes': megabytes,
		'syslog': {'enabled': enabled, 'host': host, 'port': port, 'protocol': protocol},
	}, None


# --- Aplicar -------------------------------------------------------------------

# O que está aplicado agora, para a tela e para a leitura (audit_trail)
_state = {'path': None, 'base': None, 'syslog': None, 'syslogError': None, 'config': None}
_lock = threading.RLock()


def log_path(base_path, config):
	"""O arquivo da trilha: data/<pasta>/auth.log, sendo data/ a pasta de AUDIT_LOG_PATH."""
	root = os.path.dirname(base_path)
	name = os.path.basename(base_path) or LOG_NAME
	return os.path.join(root, config['folder'], name) if config['folder'] else os.path.join(root, name)


def current_path(base_path):
	"""Onde a trilha está sendo escrita agora; o padrão enquanto nada foi aplicado.

	O estado só vale para a mesma base: um teste que troca AUDIT_LOG_PATH não
	pode ler a trilha que outro teste deixou aplicada.
	"""
	if _state['path'] and _state['base'] == base_path:
		return _state['path']
	return log_path(base_path, load_config())


def _move_trail(old_path, new_path):
	"""Leva a trilha para a pasta nova, sem sobrescrever nada que já esteja lá."""
	os.makedirs(os.path.dirname(new_path), exist_ok = True)
	# Uma trilha que já estava no destino (a pasta foi trocada e destrocada) é
	# girada antes, para o arquivo atual da origem não cair em cima dela
	if os.path.isfile(new_path) and _size(new_path) > 0:
		os.rename(new_path, _stamped_name(new_path))
	for name in trail_files(old_path):
		target = new_path + os.path.basename(name)[len(os.path.basename(old_path)):]
		if os.path.exists(target):
			target = _stamped_name(new_path)
		os.replace(name, target)


def apply(logger, base_path, config = None, formatter = None):
	"""Troca os handlers do logger de auditoria pelos que a configuração pede.

	Chamado na subida e a cada POST da configuração. Devolve o estado aplicado.
	"""
	config = config or load_config()
	formatter = formatter or logging.Formatter('%(asctime)s %(message)s')
	with _lock:
		new_path = log_path(base_path, config)
		previous = _state['path'] if _state['base'] == base_path else None
		for handler in list(logger.handlers):
			logger.removeHandler(handler)
			try:
				handler.close()
			except Exception:
				pass
		os.makedirs(os.path.dirname(new_path) or '.', exist_ok = True)
		if previous and os.path.abspath(previous) != os.path.abspath(new_path):
			try:
				_move_trail(previous, new_path)
			except OSError as error:
				print("[ERROR]_[audit_store]: não foi possível mover a trilha para {0}: {1}".format(new_path, error))

		max_bytes = config['maxMegabytes'] * 1024 * 1024
		file_handler = AuditFileHandler(new_path, config['retentionDays'], max_bytes)
		file_handler.setFormatter(formatter)
		# Um prazo ou um teto que encolheu vale agora, não na próxima virada do dia
		file_handler.last_prune = prune(new_path, config['retentionDays'], max_bytes)
		logger.addHandler(file_handler)

		syslog_handler, syslog_error = None, None
		syslog = config['syslog']
		if syslog.get('enabled') and syslog.get('host'):
			ip, syslog_error = resolve_syslog(syslog['host'], syslog['port'], syslog['protocol'])
			if ip:
				try:
					socktype = socket.SOCK_STREAM if syslog['protocol'] == 'tcp' else socket.SOCK_DGRAM
					syslog_handler = AuditSyslogHandler((ip, int(syslog['port'])), socktype)
					syslog_handler.setFormatter(logging.Formatter('bluephish-audit: %(asctime)s %(message)s'))
					logger.addHandler(syslog_handler)
				except OSError as error:
					syslog_error = 'Não consegui conectar a {0}:{1} ({2}).'.format(syslog['host'], syslog['port'], error)
			if syslog_error:
				print("[ERROR]_[audit_store]: syslog da auditoria desligado: {0}".format(syslog_error))

		logger.setLevel(logging.INFO)
		logger.propagate = False
		_state.update({'path': new_path, 'base': base_path, 'syslog': syslog_handler,
			'syslogError': syslog_error, 'config': config})
		return status(logger)


def status(logger = None):
	"""O que a tela de configuração mostra: o que vale, onde está, e se o teto cortou."""
	config = _state['config'] or load_config()
	path = _state['path']
	file_handler = None
	for handler in (logger.handlers if logger else []):
		if isinstance(handler, AuditFileHandler):
			file_handler = handler
	syslog_handler = _state['syslog']
	result = dict(config)
	result.update({
		'path': path,
		'limits': {
			'minRetentionDays': MIN_RETENTION_DAYS, 'maxRetentionDays': MAX_RETENTION_DAYS,
			'minMegabytes': MIN_MEGABYTES, 'maxMegabytes': MAX_MEGABYTES,
		},
		'reservedFolders': sorted(RESERVED_FOLDERS),
		'usage': usage(path) if path else None,
		'capCut': bool(file_handler and file_handler.last_prune.get('overCap')),
		'syslogActive': syslog_handler is not None,
		'syslogError': _state['syslogError'] or (syslog_handler.last_error if syslog_handler else None),
		'syslogSent': syslog_handler.sent if syslog_handler else 0,
	})
	return result
