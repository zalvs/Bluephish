"""A coleta do panorama externo: baixar, acumular e dizer o estado de cada fonte.

A parte pura (catálogo, leitura do XML, classificação) está em threat_intel.py.
Aqui fica o que toca rede e disco, no mesmo desenho de feeds.py:

  * o endereço vem do catálogo, nunca da requisição;
  * redirect é recusado, o tamanho é cortado enquanto chega, a requisição é
    condicional (ETag / Last-Modified);
  * refresh() nunca levanta: uma fonte que falha guarda o motivo e mantém o que
    já foi coletado;
  * o arquivo de itens é trocado inteiro (os.replace), nunca editado no lugar.

Onde fica (`data/threat_intel/`, ao lado de `data/feeds/`):

  items.json   {"collectingSince": <epoch s>, "items": [{"id", "source", "title",
               "link", "published", "seenAt", "excerpt", "categories"?}]}
  state.json   {<id da fonte>: {"fetchedAt", "checkedAt", "lastAttempt",
               "lastError", "etag", "lastModified", "count"}}

Configuração (`configuration.json`, seção `threat_intel`, gravada pela tela):

  {"sources": {<id>: true|false}, "summary": {"enabled", "model"}}

Nada é baixado até um admin ligar uma fonte.
"""

import json
import config_file
import logging
import os
import threading
import time

import requests

import config_store
import threat_intel

log = logging.getLogger('threat_intel_sync')

DATA_DIR = os.path.join('data', 'threat_intel')
CONFIG_SECTION = 'threat_intel'

HTTP_TIMEOUT = (10, 30)
USER_AGENT = 'BluePhish-threat-intel (+https://github.com/zalvs/Bluephish)'

# Feed de notícia muda algumas vezes por dia. Duas horas pega tudo antes de sair
# da janela de 10 a 50 itens dos feeds mais curtos (a BleepingComputer cobre dois
# dias) sem martelar quem publica
INTERVAL_MINUTES = 120
RETRY_AFTER_FAILURE_MINUTES = 20
# Fonte sem coleta bem-sucedida há este tanto de intervalos aparece como parada
STALE_AFTER_INTERVALS = 6

_store_lock = threading.Lock()
_running = set()
_running_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Configuração                                                                 #
# --------------------------------------------------------------------------- #

SUMMARY_MODES = ('manual', 'auto')
SUMMARY_LENGTHS = ('short', 'medium')


def default_config():
	return {'sources': dict((source['id'], False) for source in threat_intel.SOURCES),
		'summary': {'enabled': False, 'model': '', 'mode': 'manual', 'length': 'short'}}


def normalize_config(raw):
	"""A seção como a aplicação a entende. Fonte que não está no catálogo é descartada."""
	config = default_config()
	raw = raw if isinstance(raw, dict) else {}
	sources = raw.get('sources') if isinstance(raw.get('sources'), dict) else {}
	# Só o booleano verdadeiro liga: bool("false") é True, e um corpo mal formado
	# não pode ligar fonte nem gastar token por acidente
	for source_id in config['sources']:
		config['sources'][source_id] = sources.get(source_id) is True
	summary = raw.get('summary') if isinstance(raw.get('summary'), dict) else {}
	config['summary']['enabled'] = summary.get('enabled') is True
	config['summary']['model'] = str(summary.get('model') or '').strip()[:200]
	if summary.get('mode') in SUMMARY_MODES:
		config['summary']['mode'] = summary['mode']
	if summary.get('length') in SUMMARY_LENGTHS:
		config['summary']['length'] = summary['length']
	return config


def load_config(path = 'configuration.json'):
	try:
		return normalize_config(config_file.read(path).get(CONFIG_SECTION))
	except (OSError, ValueError):
		return default_config()


def save_config(config, path = 'configuration.json'):
	"""Grava só a seção `threat_intel`, preservando o resto do arquivo.

	Pelo config_store, que grava no lugar: o configuration.json é bind mount de
	arquivo único, e um os.replace sobre o ponto de montagem falha no contêiner.
	"""
	section = normalize_config(config)
	config_store.write_section(path, CONFIG_SECTION, section)
	return section


def enabled_sources(config):
	return [source for source in threat_intel.SOURCES if config['sources'].get(source['id'])]


# --------------------------------------------------------------------------- #
# Armazenamento                                                                #
# --------------------------------------------------------------------------- #

def _read_json(path, fallback):
	try:
		with open(path, encoding = 'utf-8') as source_file:
			value = json.load(source_file)
		return value if isinstance(value, type(fallback)) else fallback
	except (OSError, ValueError):
		return fallback


def _write_json(path, value):
	os.makedirs(os.path.dirname(path), exist_ok = True)
	temp = path + '.tmp'
	with open(temp, 'w', encoding = 'utf-8') as target:
		json.dump(value, target, ensure_ascii = False)
	os.replace(temp, path)


def read_store(base_dir = None):
	store = _read_json(os.path.join(base_dir or DATA_DIR, 'items.json'), {})
	items = store.get('items') if isinstance(store.get('items'), list) else []
	since = store.get('collectingSince')
	return {'collectingSince': since if isinstance(since, (int, float)) else None,
		'items': [item for item in items if threat_intel.valid_stored(item)]}


def read_state(base_dir = None):
	return _read_json(os.path.join(base_dir or DATA_DIR, 'state.json'), {})


def _update_state(base_dir, source_id, changes):
	# Sob o mesmo lock dos itens: a atualização manual e o laço de fundo podem
	# terminar ao mesmo tempo, e ler-alterar-gravar sem lock perde a de um deles
	with _store_lock:
		state = read_state(base_dir)
		entry = dict(state.get(source_id) or {})
		entry.update(changes)
		state[source_id] = entry
		_write_json(os.path.join(base_dir, 'state.json'), state)
	return entry


def source_status(source, state, now):
	"""O que a tela diz de uma fonte. Fonte nunca baixada não tem contagem, nem zero."""
	entry = state.get(source['id']) or {}
	fetched = entry.get('fetchedAt')
	if not fetched:
		status = 'failed' if entry.get('lastError') else 'never'
	elif now - fetched > STALE_AFTER_INTERVALS * INTERVAL_MINUTES * 60:
		status = 'stale'
	elif entry.get('lastError'):
		status = 'failing'
	else:
		status = 'fresh'
	return {
		'status': status,
		'fetchedAt': fetched,
		'checkedAt': entry.get('checkedAt'),
		'count': entry.get('count'),
		'error': entry.get('lastError') or '',
		'refreshing': is_refreshing(source)
	}


def is_due(entry, now):
	entry = entry or {}
	if entry.get('lastError') and entry.get('lastAttempt'):
		if now - entry['lastAttempt'] < RETRY_AFTER_FAILURE_MINUTES * 60:
			return False
	checked = entry.get('checkedAt') or entry.get('fetchedAt')
	return not checked or now - checked >= INTERVAL_MINUTES * 60


def is_refreshing(source):
	with _running_lock:
		return source['id'] in _running


# --------------------------------------------------------------------------- #
# Coleta                                                                       #
# --------------------------------------------------------------------------- #

def _download(source, entry, http):
	"""(documento, etag, last-modified); documento None quando a fonte respondeu 304. Levanta em erro."""
	headers = {'User-Agent': USER_AGENT,
		'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml'}
	if entry.get('etag'):
		headers['If-None-Match'] = entry['etag']
	elif entry.get('lastModified'):
		headers['If-Modified-Since'] = entry['lastModified']
	# Nunca seguir redirect: o destino não veio do catálogo
	response = http.get(source['url'], headers = headers, stream = True, allow_redirects = False,
		timeout = HTTP_TIMEOUT)
	try:
		if response.status_code == 304:
			return None, entry.get('etag', ''), entry.get('lastModified', '')
		if 300 <= response.status_code < 400:
			raise threat_intel.FeedError('a fonte respondeu com redirecionamento (HTTP {0}), que é recusado'.format(
				response.status_code))
		if response.status_code != 200:
			raise threat_intel.FeedError('a fonte respondeu HTTP {0}'.format(response.status_code))
		declared = response.headers.get('Content-Length')
		if declared and declared.isdigit() and int(declared) > threat_intel.MAX_FEED_BYTES:
			raise threat_intel.FeedError('o documento declara {0} bytes, acima do limite'.format(declared))
		chunks = []
		received = 0
		for chunk in response.iter_content(chunk_size = 64 * 1024):
			received += len(chunk)
			# Contado depois da descompressão, então uma bomba pequena também é cortada
			if received > threat_intel.MAX_FEED_BYTES:
				raise threat_intel.FeedError('o documento passou do limite de tamanho e foi interrompido')
			chunks.append(chunk)
		return b''.join(chunks), response.headers.get('ETag') or '', response.headers.get('Last-Modified') or ''
	finally:
		response.close()


def refresh(source, base_dir = None, now = None, session = None, offload = None):
	"""Baixa uma fonte e acumula os itens. Nunca levanta. -> {'ok', 'busy', 'error', 'added'}

	`offload` roda a leitura do XML fora do hub do eventlet
	(`analyzers.run_off_hub`); sem ele roda direto, que é o que um teste quer.
	"""
	base_dir = base_dir or DATA_DIR
	with _running_lock:
		if source['id'] in _running:
			return {'ok': False, 'busy': True, 'error': '', 'added': 0}
		_running.add(source['id'])
	started = time.time() if now is None else now
	try:
		return _refresh(source, base_dir, started, session or requests, offload)
	finally:
		with _running_lock:
			_running.discard(source['id'])


def _refresh(source, base_dir, started, http, offload):
	entry = read_state(base_dir).get(source['id']) or {}
	try:
		raw, etag, last_modified = _download(source, entry, http)
		if raw is None:
			_update_state(base_dir, source['id'], {'checkedAt': started, 'lastAttempt': started, 'lastError': ''})
			return {'ok': True, 'busy': False, 'error': '', 'added': 0}
		parse = offload or (lambda function, *args: function(*args))
		fetched = parse(threat_intel.parse_feed, raw, started)
	except threat_intel.FeedError as error:
		return _fail(base_dir, source, started, str(error))
	except requests.exceptions.Timeout:
		return _fail(base_dir, source, started, 'a fonte não respondeu dentro do tempo limite')
	except requests.exceptions.RequestException as error:
		return _fail(base_dir, source, started, 'falha de rede: {0}'.format(type(error).__name__))
	except Exception:
		log.exception('source %s: unexpected failure', source['id'])
		return _fail(base_dir, source, started, 'erro inesperado; veja o log do servidor')

	try:
		with _store_lock:
			store = read_store(base_dir)
			known = set(item['id'] for item in store['items'])
			items = threat_intel.merge(store['items'], source['id'], fetched, started)
			_write_json(os.path.join(base_dir, 'items.json'), {
				'collectingSince': store['collectingSince'] or started,
				'items': items
			})
	except Exception:
		# refresh() nunca levanta: um disco cheio vira o motivo da fonte, não uma
		# exceção solta numa tarefa de fundo
		log.exception('source %s: could not store the items', source['id'])
		return _fail(base_dir, source, started, 'não foi possível gravar as publicações; veja o log do servidor')
	added = sum(1 for item in fetched if item['id'] not in known)
	_update_state(base_dir, source['id'], {
		'fetchedAt': started, 'checkedAt': started, 'lastAttempt': started, 'lastError': '',
		'etag': etag, 'lastModified': last_modified, 'count': len(fetched)
	})
	log.info('source %s: %s item(s), %s new', source['id'], len(fetched), added)
	return {'ok': True, 'busy': False, 'error': '', 'added': added}


def _fail(base_dir, source, started, message):
	log.warning('source %s: %s', source['id'], message)
	try:
		_update_state(base_dir, source['id'], {'lastAttempt': started, 'lastError': message})
	except OSError:
		log.exception('source %s: could not record the failure', source['id'])
	return {'ok': False, 'busy': False, 'error': message, 'added': 0}


def refresh_due(config, base_dir = None, now = None, session = None, offload = None):
	"""Atualiza cada fonte ligada cuja vez chegou, uma por vez. -> {id: resultado}"""
	base_dir = base_dir or DATA_DIR
	results = {}
	for source in enabled_sources(config):
		moment = time.time() if now is None else now
		if not is_due(read_state(base_dir).get(source['id']), moment):
			continue
		results[source['id']] = refresh(source, base_dir, moment, session, offload)
	return results
