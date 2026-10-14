"""O acervo das mensagens originais, do ponto de vista de quem o usa.

`eml_store.py` é a mecânica — arquivos, índice, orçamento. Este módulo é a porta:
uma instância só por processo, a configuração lida de `configuration.json`, e as
duas operações que o resto do código faz.

Por que uma instância só: o índice do acervo vive em memória, e dois objetos
apontando para o mesmo diretório se desencontrariam — um despejaria o arquivo que
o outro acabou de registrar. A análise (`run_analysis`) guarda; a interface
(`thephish_app`) lê. Os dois passam por aqui.

**Nada aqui levanta.** Guardar o original é o que permite rever e reanalisar um
caso depois; não é o que decide o veredito. Um disco cheio, um diretório sem
permissão ou uma configuração quebrada fazem `keep()` devolver False e `fetch()`
devolver None — e a tela diz que o original não está guardado, em vez de a
análise parar por causa do arquivo que serve para revê-la.
"""

import json
import os
import threading

import eml_store

# Onde o acervo mora. Sob `data/`, que é o bind mount: um rebuild de imagem não
# leva junto o que foi analisado
DIRECTORY = os.environ.get('BLUEPHISH_ORIGINALS_PATH',
	os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'originals'))

CONFIG_FILE = 'configuration.json'

DEFAULTS = {
	'storeOriginal': True,
	'retentionDays': eml_store.RETENTION_DAYS,
	'maxGigabytes': eml_store.MAX_BYTES / (1024.0 * 1024 * 1024)
}

_store = None
_store_signature = None
_lock = threading.Lock()


def load_config(path = CONFIG_FILE):
	"""A seção `caseEvidence`, com os padrões do módulo no lugar do que falta.

	Lida do disco a cada chamada, como as demais seções: quem muda a retenção na
	tela espera que a próxima análise já obedeça, sem reiniciar o container.
	"""
	entry = {}
	try:
		with open(path) as conf_file:
			entry = json.load(conf_file).get('caseEvidence') or {}
	except Exception:
		entry = {}
	if not isinstance(entry, dict):
		entry = {}
	retention = entry.get('retentionDays')
	gigabytes = entry.get('maxGigabytes')
	return {
		'storeOriginal': bool(entry.get('storeOriginal', DEFAULTS['storeOriginal'])),
		'retentionDays': retention if isinstance(retention, int) and retention >= 0 else DEFAULTS['retentionDays'],
		'maxGigabytes': gigabytes if isinstance(gigabytes, (int, float)) and gigabytes > 0 else DEFAULTS['maxGigabytes']
	}


def enabled():
	return load_config()['storeOriginal']


def store():
	"""A instância do acervo, ou None quando ela não pôde ser aberta.

	Reconstruída quando a retenção ou o teto mudam na tela — e só então: abrir o
	acervo relê o diretório inteiro, e fazer isso a cada análise seria pagar o
	índice de novo por nada.
	"""
	global _store, _store_signature
	entry = load_config()
	signature = (entry['retentionDays'], entry['maxGigabytes'])
	with _lock:
		if _store is not None and _store_signature == signature:
			return _store
		try:
			_store = eml_store.EmlStore(DIRECTORY,
				max_bytes = int(entry['maxGigabytes'] * 1024 * 1024 * 1024),
				retention_days = entry['retentionDays'])
			_store_signature = signature
		except Exception:
			_store = None
			_store_signature = None
		return _store


def keep(record_refs, message_bytes):
	"""Guarda o original sob cada referência que a análise produziu.

	Devolve quantas referências ficaram guardadas. Zero não é erro: pode ser o
	acervo desligado, a mensagem grande demais, ou um destino que não respondeu
	com referência nenhuma.

	Várias referências para uma análise é o caso normal de quem tem TheHive e
	disco ligados; o `eml_store` faz as duas dividirem um arquivo só.
	"""
	if not message_bytes or not record_refs:
		return 0
	if not enabled():
		return 0
	archive = store()
	if archive is None:
		return 0
	kept = 0
	for record_ref in record_refs:
		if not record_ref:
			continue
		try:
			if archive.put(record_ref, message_bytes):
				kept += 1
		except Exception:
			continue
	# A poda roda aqui, no caminho de quem guarda, e não num laço próprio: a
	# frequência que importa é a de chegada de análise
	try:
		archive.prune()
	except Exception:
		pass
	return kept


def fetch(record_ref):
	"""Os bytes do original deste registro, ou None."""
	archive = store()
	if archive is None:
		return None
	try:
		return archive.get(record_ref)
	except Exception:
		return None


def held(record_ref):
	"""Se o original deste registro está guardado. Sem tocar o disco."""
	archive = store()
	if archive is None:
		return False
	try:
		return archive.has(record_ref)
	except Exception:
		return False


def discard(record_ref):
	archive = store()
	if archive is None:
		return
	try:
		archive.discard(record_ref)
	except Exception:
		pass


def reset():
	"""Esquece a instância. Existe para os testes, e para a tela de configuração."""
	global _store, _store_signature
	with _lock:
		_store = None
		_store_signature = None
