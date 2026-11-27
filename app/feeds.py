"""Public threat-intelligence feeds, downloaded once and queried offline.

A feed here is a flat list somebody publishes for free (a file of domains, a file
of URLs). Asking a vendor about each observable would send the victim's
indicators out of the network and make every analysis depend on the vendor being
up. Instead the list is downloaded in the background, indexed in a local SQLite
file, and the analysis only ever reads that file.

Shape of the module, in the same split `analyzers.py` uses:

  FEEDS            declarative registry — where to download, what the list holds,
                   how often, how big it may be, under which licence. The URL is
                   fixed in this file on purpose: there is no field to type one,
                   so the downloader is not a new way to make the server call an
                   address somebody chose (the SSRF chain in CLAUDE.md).

  normalize(),     pure. The same normalization runs when the index is built and
  parse_lines(),   when it is queried; if the two ever differ, a listed indicator
  accept_swap(),   silently stops matching.
  freshness(),
  is_due()

  refresh(),       impure. refresh() never raises: a failed download keeps the
  lookup()         previous index and records why.

What "not listed" means is decided by the caller, not here. See
`analyzers.level_for`: a feed that does not list an indicator says nothing about
it, so that is `info`, never `safe`.
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.parse

import requests

import whitelist

log = logging.getLogger('feeds')

FEEDS_DIR = os.path.join('data', 'feeds')

# Connect fast, wait longer for the body: the lists are tens of megabytes
HTTP_TIMEOUT = (10, 60)
USER_AGENT = 'BluePhish-feed-sync (+https://github.com/zalvs/Bluephish)'

# A list that has not been confirmed current for this many intervals no longer
# vouches for an indicator it does not list. A hit stays valid: an old list
# naming a phishing domain is still naming a phishing domain
STALE_AFTER_INTERVALS = 3

# After a failed attempt, wait this long before trying again. Without it a feed
# whose host is down would be hammered every pass of the background loop
RETRY_AFTER_FAILURE_MINUTES = 10

# A new list that shrinks by more than this against the one it would replace is
# refused. It is how a truncated or emptied download (or a poisoned one) is kept
# from erasing the detection it is meant to feed
MAX_SHRINK_RATIO = 0.5

# Hosts that serve content for thousands of unrelated people. A domain list that
# names one of them (the Phishing.Database lists sites.google.com and bit.ly as
# of 2026-10-23, because phishing pages were published there) would convict every
# legitimate email that links to a Google Site or a short link. A domain feed
# says nothing about these; a URL feed still can, since the full path tells one
# page from another. Checked at lookup time so a change needs no re-download
SHARED_HOSTS = frozenset([
	'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'forms.office.com',
	'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'lnkd.in', 'is.gd', 'rebrand.ly',
	'github.com', 'github.io', 'githubusercontent.com', 'pages.dev', 'workers.dev', 'netlify.app',
	'vercel.app', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'blogspot.com', 'wixsite.com',
	'weebly.com', 'notion.site', 'typeform.com', 'sharepoint.com', 'onedrive.live.com',
	'dropbox.com', 'amazonaws.com', 'cloudfront.net'
])

MAX_LINE_LENGTH = 2048
INSERT_BATCH = 20000

MIB = 1024 * 1024

FEEDS = [
	{
		'id': 'certpl_domains',
		'name': 'CERT Polska — domínios maliciosos',
		'kind': 'feed público · domínios · consulta offline',
		'description': 'Lista de domínios de phishing e malware mantida pelo CERT Polska, com '
			'remoção automática depois de 6 meses. O arquivo é baixado e consultado localmente: '
			'nenhum domínio do e-mail sai da rede. Constar na lista é sinal forte; não constar '
			'não diz nada, e o resultado é "sem opinião", nunca "seguro".',
		'docs': 'https://cert.pl/en/warning-list/',
		'url': 'https://hole.cert.pl/domains/v2/domains.txt',
		'type': 'domain',
		'listedLevel': 'malicious',
		'intervalMinutes': 60,
		'maxBytes': 64 * MIB,
		'minCount': 1000,
		'recommended': True,
		'license': {
			'class': 'free',
			'note': 'Uso livre para qualquer fim, inclusive comercial, sem garantia. Atribuição '
				'não é obrigatória.',
			'url': 'https://cert.pl/en/warning-list/'
		},
		'testPlaceholder': 'um domínio, como exemplo.com'
	},
	{
		'id': 'phishingdb_domains',
		'name': 'Phishing.Database — domínios ativos',
		'kind': 'feed público · domínios · consulta offline',
		'description': 'Domínios de phishing ativos, compilados e retestados continuamente pelo '
			'projeto Phishing.Database a partir de várias fontes. Lista automática: pode '
			'conter falso positivo, por isso uma ocorrência vale "suspeito" e não "malicioso". '
			'Plataformas compartilhadas (Google Sites, encurtadores, hospedagens) são ignoradas '
			'nesta lista. Consulta local, sem enviar nada para fora.',
		'docs': 'https://github.com/mitchellkrogza/Phishing.Database',
		'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/'
			'phishing-domains-ACTIVE.txt',
		'type': 'domain',
		'listedLevel': 'suspicious',
		'intervalMinutes': 360,
		'maxBytes': 96 * MIB,
		'minCount': 1000,
		'recommended': False,
		'license': {
			'class': 'confirm',
			'note': 'Licença MIT sobre a compilação. O projeto não informa de quais fontes vêm as '
				'entradas, então não dá para afirmar que o uso numa empresa é livre: confirme '
				'antes de ligar.',
			'url': 'https://github.com/mitchellkrogza/Phishing.Database/blob/master/LICENSE.md'
		},
		'testPlaceholder': 'um domínio, como exemplo.com'
	},
	{
		'id': 'phishingdb_links',
		'name': 'Phishing.Database — URLs ativas',
		'kind': 'feed público · URLs · consulta offline',
		'description': 'URLs de phishing ativas do projeto Phishing.Database. O arquivo é grande '
			'(dezenas de megabytes) e por isso não vem no pacote recomendado. A URL inteira '
			'precisa coincidir, então uma ocorrência é sinal forte.',
		'docs': 'https://github.com/mitchellkrogza/Phishing.Database',
		'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/'
			'phishing-links-ACTIVE.txt',
		'type': 'url',
		'listedLevel': 'malicious',
		'intervalMinutes': 360,
		'maxBytes': 256 * MIB,
		'minCount': 1000,
		'recommended': False,
		'license': {
			'class': 'confirm',
			'note': 'Licença MIT sobre a compilação. O projeto não informa de quais fontes vêm as '
				'entradas, então não dá para afirmar que o uso numa empresa é livre: confirme '
				'antes de ligar.',
			'url': 'https://github.com/mitchellkrogza/Phishing.Database/blob/master/LICENSE.md'
		},
		'testPlaceholder': 'uma URL de phishing conhecida'
	}
]

BY_ID = dict((feed['id'], feed) for feed in FEEDS)


def analyzer_spec(feed):
	"""The feed as an entry of the analyzer registry, so the screen, `run()` and the
	scoring table treat it like any other analyzer."""
	return {
		'id': feed['id'],
		'family': 'feed',
		'name': feed['name'],
		'kind': feed['kind'],
		'description': feed['description'],
		'docs': feed['docs'],
		'observables': [feed['type']],
		'credentials': [],
		'thresholds': [],
		'testPlaceholder': feed['testPlaceholder'],
		'listedLevel': feed['listedLevel'],
		'license': feed['license'],
		'feed': {
			'intervalMinutes': feed['intervalMinutes'],
			'recommended': feed['recommended'],
			'type': feed['type'],
			'host': urllib.parse.urlsplit(feed['url']).hostname
		}
	}


# --------------------------------------------------------------------------- #
# Pure                                                                         #
# --------------------------------------------------------------------------- #

def normalize(kind, value):
	"""The form an indicator is stored and looked up in, or '' when it is not one.

	Domain: lowercase ASCII (punycode), no trailing dot. URL: host and path as a
	browser would visit them, without scheme, userinfo, fragment or trailing
	slash — so `http://` and `https://` of the same address are the same entry.
	"""
	if kind == 'domain':
		return whitelist.normalize_domain(value)
	if kind == 'url':
		host, target = whitelist.normalize_url(value)
		if not host:
			return ''
		path, separator, query = (target or '/').partition('?')
		return host + path.rstrip('/') + (separator + query if query else '')
	return ''


def parse_lines(kind, lines):
	"""Yield the normalized indicators of a text list, skipping comments, blanks
	and anything that is not an indicator of this kind."""
	for line in lines:
		line = line.strip()
		if not line or line.startswith('#') or len(line) > MAX_LINE_LENGTH:
			continue
		key = normalize(kind, line)
		if key:
			yield key


def accept_swap(new_count, old_count, min_count):
	"""Whether a freshly built index may replace the current one. -> (ok, reason)."""
	if new_count < min_count:
		return False, 'a lista nova tem {0} entrada(s), abaixo do mínimo de {1}'.format(
			new_count, min_count)
	if old_count and new_count < old_count * (1 - MAX_SHRINK_RATIO):
		return False, ('a lista nova encolheu de {0} para {1} entradas; a anterior foi mantida '
			'até alguém conferir').format(old_count, new_count)
	return True, ''


def freshness(meta, now, interval_minutes):
	"""'missing' (never downloaded), 'fresh' or 'stale'."""
	if not meta or not meta.get('checkedAt'):
		return 'missing'
	if now - meta['checkedAt'] > STALE_AFTER_INTERVALS * interval_minutes * 60:
		return 'stale'
	return 'fresh'


def is_due(meta, now, interval_minutes):
	"""Whether the background loop should try this feed now."""
	meta = meta or {}
	if meta.get('lastError') and now - (meta.get('lastAttempt') or 0) < RETRY_AFTER_FAILURE_MINUTES * 60:
		return False
	checked = meta.get('checkedAt')
	return checked is None or now - checked >= interval_minutes * 60


# --------------------------------------------------------------------------- #
# Storage                                                                      #
# --------------------------------------------------------------------------- #

def data_dir():
	return FEEDS_DIR


def _feed_dir(base_dir, feed):
	return os.path.join(base_dir, feed['id'])


def _db_path(base_dir, feed):
	return os.path.join(_feed_dir(base_dir, feed), 'current.sqlite')


def _meta_path(base_dir, feed):
	return os.path.join(_feed_dir(base_dir, feed), 'meta.json')


def read_meta(base_dir, feed):
	try:
		with open(_meta_path(base_dir, feed)) as meta_file:
			meta = json.load(meta_file)
		return meta if isinstance(meta, dict) else None
	except (OSError, ValueError):
		return None


def _write_meta(base_dir, feed, meta):
	path = _meta_path(base_dir, feed)
	temp = path + '.tmp'
	with open(temp, 'w') as meta_file:
		json.dump(meta, meta_file, indent = '\t')
	os.replace(temp, path)


def status(feed, base_dir = None, now = None):
	"""What the screen shows about one feed. Never invents a number: a feed that was
	never downloaded has no count, not a zero."""
	base_dir = base_dir or data_dir()
	now = time.time() if now is None else now
	meta = read_meta(base_dir, feed) or {}
	return {
		'status': freshness(meta, now, feed['intervalMinutes']),
		'count': meta.get('count'),
		'checkedAt': meta.get('checkedAt'),
		'fetchedAt': meta.get('fetchedAt'),
		'error': meta.get('lastError') or '',
		'refreshing': is_refreshing(feed)
	}


def lookup(feed, kind, value, base_dir = None, now = None):
	"""Look one indicator up in the local index. No network.

	-> {'status': 'missing'|'fresh'|'stale', 'listed': bool, 'count': int|None}
	"""
	base_dir = base_dir or data_dir()
	now = time.time() if now is None else now
	meta = read_meta(base_dir, feed)
	state = freshness(meta, now, feed['intervalMinutes'])
	result = {'status': state, 'listed': False, 'count': (meta or {}).get('count'),
		'checkedAt': (meta or {}).get('checkedAt'), 'shared': False}
	path = _db_path(base_dir, feed)
	key = normalize(kind, value)
	if kind == 'domain' and key in SHARED_HOSTS:
		result['shared'] = True
		return result
	if state == 'missing' or not key or not os.path.exists(path):
		return result
	# Opened per call and read-only: the file is replaced whole on refresh, and a
	# connection kept open would keep reading the old one
	connection = sqlite3.connect('file:{0}?mode=ro'.format(urllib.parse.quote(path)), uri = True)
	try:
		row = connection.execute('SELECT 1 FROM ind WHERE v = ?', (key,)).fetchone()
	finally:
		connection.close()
	result['listed'] = row is not None
	return result


# --------------------------------------------------------------------------- #
# Download                                                                     #
# --------------------------------------------------------------------------- #

_locks = {}
_locks_guard = threading.Lock()


def _lock_for(feed):
	with _locks_guard:
		return _locks.setdefault(feed['id'], threading.Lock())


def is_refreshing(feed):
	return _lock_for(feed).locked()


def _build_index(kind, source_path, db_path):
	"""Parse the downloaded text into a fresh SQLite file. Blocking and CPU-bound:
	the caller runs it off the eventlet hub. -> number of indicators."""
	if os.path.exists(db_path):
		os.remove(db_path)
	connection = sqlite3.connect(db_path)
	try:
		connection.execute('CREATE TABLE ind (v TEXT PRIMARY KEY) WITHOUT ROWID')
		with open(source_path, encoding = 'utf-8', errors = 'replace') as source:
			batch = []
			for key in parse_lines(kind, source):
				batch.append((key,))
				if len(batch) >= INSERT_BATCH:
					connection.executemany('INSERT OR IGNORE INTO ind VALUES (?)', batch)
					batch = []
			if batch:
				connection.executemany('INSERT OR IGNORE INTO ind VALUES (?)', batch)
		connection.commit()
		return connection.execute('SELECT COUNT(*) FROM ind').fetchone()[0]
	finally:
		connection.close()


def _remove(path):
	try:
		os.remove(path)
	except OSError:
		pass


def refresh(feed, base_dir = None, now = None, offload = None, session = None):
	"""Download the feed and swap it in. Never raises.

	`offload` runs the blocking index build somewhere that does not stop the
	eventlet hub (`analyzers.run_off_hub`); without one it runs inline, which is
	what a test wants. -> {'ok', 'changed', 'busy', 'error', 'count'}
	"""
	base_dir = base_dir or data_dir()
	lock = _lock_for(feed)
	if not lock.acquire(False):
		return {'ok': False, 'changed': False, 'busy': True, 'error': '', 'count': None}
	started = time.time() if now is None else now
	try:
		return _refresh_locked(feed, base_dir, started, offload, session or requests)
	finally:
		lock.release()


def _fail(base_dir, feed, meta, started, message):
	log.warning('feed %s: %s', feed['id'], message)
	meta = dict(meta or {})
	meta['lastError'] = message
	meta['lastAttempt'] = started
	try:
		_write_meta(base_dir, feed, meta)
	except OSError:
		log.exception('feed %s: could not record the failure', feed['id'])
	return {'ok': False, 'changed': False, 'busy': False, 'error': message,
		'count': meta.get('count')}


def _refresh_locked(feed, base_dir, started, offload, http):
	directory = _feed_dir(base_dir, feed)
	download_path = os.path.join(directory, 'download.tmp')
	temp_db = os.path.join(directory, 'current.sqlite.tmp')
	meta = None
	try:
		os.makedirs(directory, exist_ok = True)
		meta = read_meta(base_dir, feed)
		headers = {'User-Agent': USER_AGENT}
		# A conditional request only when there is an index it would leave in place
		if meta and os.path.exists(_db_path(base_dir, feed)):
			if meta.get('etag'):
				headers['If-None-Match'] = meta['etag']
			elif meta.get('lastModified'):
				headers['If-Modified-Since'] = meta['lastModified']

		# Never follow a redirect: the target did not come from this file
		response = http.get(feed['url'], headers = headers, stream = True,
			allow_redirects = False, timeout = HTTP_TIMEOUT)
		try:
			if response.status_code == 304:
				meta = dict(meta or {})
				meta.update({'checkedAt': started, 'lastAttempt': started, 'lastError': ''})
				_write_meta(base_dir, feed, meta)
				return {'ok': True, 'changed': False, 'busy': False, 'error': '',
					'count': meta.get('count')}
			if response.status_code != 200:
				return _fail(base_dir, feed, meta, started,
					'o servidor respondeu HTTP {0}'.format(response.status_code))
			declared = response.headers.get('Content-Length')
			if declared and declared.isdigit() and int(declared) > feed['maxBytes']:
				return _fail(base_dir, feed, meta, started,
					'o arquivo declara {0} bytes, acima do limite de {1}'.format(declared, feed['maxBytes']))

			digest = hashlib.sha256()
			received = 0
			with open(download_path, 'wb') as target:
				for chunk in response.iter_content(chunk_size = 256 * 1024):
					received += len(chunk)
					# Counted after decompression, so a small compressed bomb is cut too
					if received > feed['maxBytes']:
						return _fail(base_dir, feed, meta, started,
							'o download passou do limite de {0} bytes e foi interrompido'.format(
								feed['maxBytes']))
					digest.update(chunk)
					target.write(chunk)
			etag = response.headers.get('ETag') or ''
			last_modified = response.headers.get('Last-Modified') or ''
		finally:
			response.close()

		build = offload or (lambda function, *args: function(*args))
		count = build(_build_index, feed['type'], download_path, temp_db)
		ok, reason = accept_swap(count, (meta or {}).get('count'), feed['minCount'])
		if not ok:
			return _fail(base_dir, feed, meta, started, reason)

		os.replace(temp_db, _db_path(base_dir, feed))
		_write_meta(base_dir, feed, {
			'fetchedAt': started, 'checkedAt': started, 'lastAttempt': started,
			'count': count, 'sha256': digest.hexdigest(), 'etag': etag,
			'lastModified': last_modified, 'lastError': ''
		})
		log.info('feed %s: %s indicator(s) indexed', feed['id'], count)
		return {'ok': True, 'changed': True, 'busy': False, 'error': '', 'count': count}
	except requests.exceptions.Timeout:
		return _fail(base_dir, feed, meta, started, 'o servidor não respondeu dentro do tempo limite')
	except requests.exceptions.RequestException as error:
		return _fail(base_dir, feed, meta, started,
			'falha de rede ao baixar: {0}'.format(type(error).__name__))
	except Exception:
		log.exception('feed %s: unexpected failure', feed['id'])
		return _fail(base_dir, feed, meta, started, 'erro inesperado ao atualizar; veja o log do servidor')
	finally:
		_remove(download_path)
		_remove(temp_db)


def refresh_due(config, base_dir = None, now = None, offload = None):
	"""Refresh every enabled feed whose turn has come. -> {feed_id: result}."""
	base_dir = base_dir or data_dir()
	now = time.time() if now is None else now
	results = {}
	for feed in FEEDS:
		if not (config.get(feed['id']) or {}).get('enabled'):
			continue
		if not is_due(read_meta(base_dir, feed), now, feed['intervalMinutes']):
			continue
		results[feed['id']] = refresh(feed, base_dir, now, offload)
	return results
