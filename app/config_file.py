"""A única porta de leitura e gravação do configuration.json.

Antes, cada módulo abria o arquivo e fazia `json.load`/`json.dump` por conta
própria — uns setenta pontos. Com os segredos no cofre (secret_vault.py), o
arquivo guarda referências (`vault:v1:<id>`) no lugar dos valores, e um módulo
que ainda lesse o arquivo direto receberia a referência como senha, sem erro
nenhum: a integração simplesmente pararia de autenticar. Por isso ninguém mais
abre o arquivo — test_config_file varre o código e falha se alguém voltar a
abrir.

* `read(path)` — o documento com os segredos abertos. É o que todo módulo usa.
* `write(document, path)` — cifra os segredos em texto, grava, e só então apaga
  do cofre as linhas que ficaram sem uso. Recusa (VaultError) quando gravar
  agora perderia um segredo (secret_vault.assert_writable).
* `read_raw(path)` — o arquivo como está no disco, com as referências. Só para
  o estado do cofre e para a migração.

A gravação continua no lugar, não por troca de arquivo (ver config_store): o
arquivo é montado no contêiner como bind mount de arquivo, e renomear por cima
de um ponto de montagem falha.
"""

import contextlib
import fcntl
import json
import logging
import os
import threading

import secret_vault

log = logging.getLogger('config_file')

CONFIG_FILE = 'configuration.json'


def read_raw(path = None):
	with open(path or CONFIG_FILE) as handle:
		return json.load(handle)


def read(path = None):
	return secret_vault.unseal(read_raw(path))


_thread_lock = threading.RLock()


@contextlib.contextmanager
def _exclusive(path):
	"""Uma gravação por vez, entre threads e entre processos (manage.py vault-seal
	roda fora da aplicação). Sem isso, duas gravações intercaladas fazem o
	`collect` de uma apagar as linhas que a outra acabou de selar, e o arquivo
	dela aponta para segredos que viram '' em silêncio. A trava fica no próprio
	arquivo (um bind mount: não dá para criar um arquivo-irmão em todo lugar).
	"""
	with _thread_lock:
		with open(path, 'a') as handle:
			fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
			try:
				yield
			finally:
				fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write(document, path = None):
	path = path or CONFIG_FILE
	with _exclusive(path):
		return _write_locked(document, path)


def _write_locked(document, path):
	current = None
	if os.path.getsize(path) > 0:
		try:
			current = read_raw(path)
		except ValueError:
			# O arquivo está ilegível agora (outra gravação no meio); a trava de
			# perda de segredo não tem o que conferir nele
			current = None
	secret_vault.assert_writable(current)
	known = None if current is None else secret_vault.reference_places(current)
	sealed = secret_vault.seal(document, known)
	with open(path, 'w') as handle:
		json.dump(sealed, handle, indent = '\t')
		handle.flush()
		os.fsync(handle.fileno())
	secret_vault.collect(sealed)
	return sealed


def migrate(path = None):
	"""Cifra os segredos que ainda estão em texto no arquivo. Devolve quantos.

	Roda na subida da aplicação e pelo `manage.py vault-seal`. Sem chave mestra
	não faz nada — o arquivo segue como está (secret_vault, decisão 2).
	"""
	path = path or CONFIG_FILE
	if secret_vault.master_key() is None or not os.path.exists(path):
		return 0
	raw = read_raw(path)
	pending = secret_vault.status(raw)['plaintext']
	if pending:
		write(secret_vault.unseal(raw), path)
		log.info('%s segredo(s) de %s passaram para o cofre cifrado', pending, path)
	return pending
