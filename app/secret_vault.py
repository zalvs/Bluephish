"""Cofre dos segredos da configuração: AES-256-GCM, com um salt por segredo.

O que é segredo no configuration.json — senha da caixa, client secret, chave de
API, token do Jira, senha do SMTP, o `authValue` de um analisador definido pelo
analista, o parâmetro marcado `isSecret` de um conector — sai do arquivo. No
lugar fica uma referência (`vault:v1:<id>`), e o valor vai, cifrado, para a
tabela `vault_secret` do SQLite (models.VaultSecret). Quem lê e grava o arquivo
é config_file.py, que chama `seal` e `unseal`; nenhum outro módulo abre o
configuration.json (test_config_file segura isso).

A cifra: para cada segredo, um salt aleatório de 16 bytes; a chave da linha é
HKDF-SHA256(chave mestra, salt); o valor é cifrado com AES-256-GCM, nonce de 12
bytes, e o id da linha entra como dado autenticado — trocar o conteúdo de duas
linhas faz as duas falharem, em vez de pôr a senha do SMTP no lugar da do IMAP.

Seis decisões que não são óbvias lendo o código:

1. **A chave mestra mora fora do banco e fora do volume dele.** Um arquivo
   (BLUEPHISH_MASTER_KEY_FILE, padrão /run/secrets/bluephish/master.key), numa
   pasta montada somente leitura só no contêiner da aplicação. Copiar o volume
   de dados — o backup, o disco esquecido — não entrega segredo nenhum. É isso
   que responde à objeção do models.User.mfa_secret ("cifrar só muda o problema
   de lugar"): o problema muda de lugar *de propósito*, para fora do volume.

2. **Sem chave mestra, nada é cifrado e nada se perde.** Uma instalação que
   ainda não tem o arquivo segue lendo e gravando os segredos em texto, como
   antes, e o log e a aba Segurança dizem isso. O contrário — recusar subir —
   trancaria a instalação de fora numa atualização.

3. **Referência que não abre vira vazio, e grita.** Chave mestra trocada, linha
   apagada, banco restaurado de outro lugar: o valor sai como '' (a integração
   se comporta como "sem credencial", que ela já sabe dizer), e o log diz qual
   referência falhou. Devolver a própria referência mandaria `vault:v1:...`
   como senha para o servidor de e-mail.

4. **Enquanto uma referência não abre por falta da chave certa, nada se grava.**
   A tela que salvasse nesse estado gravaria vazio onde havia a referência, e o
   segredo se perderia — inclusive para quando a chave certa voltasse.
   `assert_writable` recusa a gravação, e a coleta nunca apaga uma linha
   cifrada com outra chave.

5. **A referência é um id aleatório, não o caminho no JSON.** Um conector
   removido do meio da lista desloca as posições; um id preso à posição daria o
   segredo de um conector ao vizinho. Linhas que nenhuma referência usa mais são
   apagadas logo depois da gravação do arquivo (`collect`).

6. **O que a aplicação gera para si mora aqui também**, com id fixo e fora da
   coleta: a chave que assina o cookie de sessão (antes THEPHISH_SECRET_KEY no
   .env). Ver `app_secret`.
"""

import base64
import binascii
import copy
import datetime
import hashlib
import logging
import os
import re
import secrets
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import models

log = logging.getLogger('secret_vault')

KEY_FILE_ENV = 'BLUEPHISH_MASTER_KEY_FILE'
DEFAULT_KEY_FILE = '/run/secrets/bluephish/master.key'
REF_PREFIX = 'vault:v1:'
APP_PREFIX = 'app:'
_INFO = b'bluephish-vault-v1'
_REF = re.compile(r'vault:v1:[0-9a-f]{32}')

# O nome da chave diz que o valor é segredo. Casa no fim do nome, sem distinguir
# maiúsculas: password, appPassword, clientSecret, apiKey, api_key, apikey,
# apiToken, token, secret, authValue. Um nome que é uma pergunta (isSecret,
# hasClientSecret) é um marcador, não o segredo
# O (?-i:...) mantém o marcador sensível a maiúsculas: isSecret é marcador,
# issuerToken e hashSecret são segredos
_SECRET_NAME = re.compile(r'^(?!(?-i:is|has)[A-Z_]).*(?i:password|secret|token|api_?key|authvalue)$')

_lock = threading.RLock()
_key_cache = {'key': None, 'value': None}
_plain_cache = {}
_reported = set()


class VaultError(Exception):
	pass


def key_file():
	return os.environ.get(KEY_FILE_ENV) or DEFAULT_KEY_FILE


def _decode_key(raw):
	text = raw.strip()
	for decode in (lambda value: base64.b64decode(value, validate = True), binascii.unhexlify):
		try:
			key = decode(text)
		except (binascii.Error, ValueError):
			continue
		if len(key) == 32:
			return key
	raise VaultError('a chave mestra em {0} precisa ter 32 bytes, em base64 ou hexadecimal'.format(key_file()))


def master_key():
	"""Os 32 bytes da chave mestra, ou None quando o arquivo não existe.

	Levanta VaultError quando o arquivo existe e não é uma chave: um arquivo
	estragado não pode ser lido como "não há cofre" e fazer a aplicação voltar a
	gravar segredo em texto.
	"""
	path = key_file()
	try:
		stamp = (path, os.stat(path).st_mtime_ns)
	except OSError:
		return None
	if _key_cache['key'] == stamp:
		return _key_cache['value']
	with open(path, 'rb') as handle:
		key = _decode_key(handle.read().decode('ascii', 'replace'))
	_key_cache.update({'key': stamp, 'value': key})
	return key


def key_id(key):
	"""Uma impressão curta da chave mestra — mostrável, e não revela a chave."""
	return hashlib.sha256(_INFO + b':id:' + key).hexdigest()[:16]


def generate_key():
	"""Uma chave mestra nova, em base64, para gravar no arquivo."""
	return base64.b64encode(os.urandom(32)).decode('ascii')


def _aad(secret_id):
	return _INFO + b':' + secret_id.encode('ascii')


def _derive(key, salt):
	return HKDF(algorithm = hashes.SHA256(), length = 32, salt = salt, info = _INFO).derive(key)


def is_secret_name(name):
	return isinstance(name, str) and bool(_SECRET_NAME.search(name))


def is_reference(value):
	return isinstance(value, str) and bool(_REF.fullmatch(value))


def _secret_slots(node):
	"""(contêiner, chave) de cada valor de segredo, em texto ou referência, em profundidade."""
	if isinstance(node, dict):
		marked = node.get('isSecret') is True
		for name, value in node.items():
			if isinstance(value, (dict, list)):
				for slot in _secret_slots(value):
					yield slot
			elif isinstance(value, str) and (is_secret_name(name) or (marked and name == 'value')):
				yield node, name
	elif isinstance(node, list):
		for item in node:
			for slot in _secret_slots(item):
				yield slot


def _secret_slot_paths(node, path = ()):
	"""(caminho, contêiner, chave) de cada segredo. O caminho troca índice de lista
	por '[]': remover um item do meio de uma lista não muda o caminho dos outros."""
	if isinstance(node, dict):
		marked = node.get('isSecret') is True
		for name, value in node.items():
			if isinstance(value, (dict, list)):
				for slot in _secret_slot_paths(value, path + (name,)):
					yield slot
			elif isinstance(value, str) and (is_secret_name(name) or (marked and name == 'value')):
				yield path + (name,), node, name
	elif isinstance(node, list):
		for item in node:
			for slot in _secret_slot_paths(item, path + ('[]',)):
				yield slot


def reference_places(document):
	"""{id da referência: os caminhos onde ela aparece} — o que `seal` confere."""
	places = {}
	for path, node, name in _secret_slot_paths(document):
		if is_reference(node[name]):
			places.setdefault(node[name][len(REF_PREFIX):], set()).add(path)
	return places


def _references(document):
	return [node[name][len(REF_PREFIX):] for node, name in _secret_slots(document) if is_reference(node[name])]


def _store(session, key, secret_id, plaintext):
	salt = os.urandom(16)
	nonce = os.urandom(12)
	ciphertext = AESGCM(_derive(key, salt)).encrypt(nonce, plaintext.encode('utf-8'), _aad(secret_id))
	row = session.query(models.VaultSecret).get(secret_id)
	if row is None:
		row = models.VaultSecret(id = secret_id)
		session.add(row)
	row.key_id = key_id(key)
	row.salt = salt
	row.nonce = nonce
	row.ciphertext = ciphertext
	row.updated_at = datetime.datetime.utcnow()
	_plain_cache[secret_id] = plaintext


def _open(row, key):
	if row.key_id != key_id(key):
		raise VaultError('cifrado com outra chave mestra ({0})'.format(row.key_id))
	try:
		plaintext = AESGCM(_derive(key, row.salt)).decrypt(row.nonce, row.ciphertext, _aad(row.id))
	except InvalidTag:
		raise VaultError('o conteúdo não confere (alterado, ou de outra linha)')
	return plaintext.decode('utf-8')


def _report(secret_id, reason):
	if (secret_id, reason) in _reported:
		return
	_reported.add((secret_id, reason))
	log.error('o segredo %s não pôde ser lido do cofre: %s; vale vazio', secret_id, reason)


def _read(session, key, secret_id):
	if secret_id in _plain_cache:
		return _plain_cache[secret_id]
	if key is None:
		_report(secret_id, 'não há chave mestra em {0}'.format(key_file()))
		return ''
	row = session.query(models.VaultSecret).get(secret_id)
	if row is None:
		_report(secret_id, 'a linha não existe no banco')
		return ''
	try:
		plaintext = _open(row, key)
	except VaultError as error:
		_report(secret_id, str(error))
		return ''
	_plain_cache[secret_id] = plaintext
	return plaintext


def _key_or_none():
	try:
		return master_key()
	except VaultError as error:
		log.error('%s', error)
		return None


def unseal(document):
	"""Uma cópia do documento com cada referência trocada pelo valor."""
	result = copy.deepcopy(document)
	slots = [(node, name) for node, name in _secret_slots(result) if is_reference(node[name])]
	if not slots:
		return result
	with _lock:
		# Do cache quando dá: config_file.read roda a cada leitura da
		# configuração, e abrir o banco em cada uma custaria à toa
		missing = []
		for node, name in slots:
			secret_id = node[name][len(REF_PREFIX):]
			if secret_id in _plain_cache:
				node[name] = _plain_cache[secret_id]
			else:
				missing.append((node, name))
		if not missing:
			return result
		key = _key_or_none()
		session = models.get_session()
		try:
			for node, name in missing:
				node[name] = _read(session, key, node[name][len(REF_PREFIX):])
		finally:
			session.close()
	return result


def assert_writable(current_raw):
	"""Levanta VaultError se gravar agora perderia um segredo (decisão 4).

	`current_raw` é o arquivo como está no disco, com as referências. Perde-se
	um segredo quando há referência e não há chave, ou quando a linha dela foi
	cifrada com outra chave. Linha que não existe mais já se perdeu: recusar por
	ela travaria a gravação para sempre.
	"""
	references = _references(current_raw or {})
	if not references:
		return
	key = master_key()
	if key is None:
		raise VaultError('o arquivo tem {0} segredo(s) cifrado(s) e não há chave mestra em {1}: '
			'gravar agora apagaria esses segredos'.format(len(references), key_file()))
	current = key_id(key)
	session = models.get_session()
	try:
		for secret_id in references:
			row = session.query(models.VaultSecret).get(secret_id)
			if row is not None and row.key_id != current:
				raise VaultError('há segredo cifrado com outra chave mestra ({0}); a chave atual é {1}: '
					'gravar agora apagaria esse segredo'.format(row.key_id, current))
	finally:
		session.close()


class ForeignReference(ValueError):
	"""Uma referência que o arquivo gravado não tinha: alguém colou o id de outro segredo."""


def seal(document, known_references = None):
	"""Uma cópia do documento com cada segredo em texto trocado por uma referência.

	`known_references` é o `reference_places` do arquivo gravado. Uma referência
	que ele não tinha naquele campo é recusada: o AAD amarra o texto cifrado ao
	id, não ao campo, então colar a referência do IMAP no campo do SMTP faria o
	SMTP usar a senha do IMAP. None (arquivo novo ou ilegível) não confere.

	Sem chave mestra, devolve o documento como veio: nada é cifrado (decisão 2).
	Grava as linhas novas; quem apaga as que ficaram sem uso é `collect`, chamado
	depois que o arquivo foi gravado — antes, uma gravação que falhasse deixaria o
	arquivo antigo apontando para linhas já apagadas.
	"""
	result = copy.deepcopy(document)
	with _lock:
		key = master_key()
		if key is None:
			return result
		session = models.get_session()
		try:
			for path, node, name in _secret_slot_paths(result):
				value = node[name]
				if not value:
					continue
				if is_reference(value):
					if known_references is not None and path not in known_references.get(value[len(REF_PREFIX):], ()):
						raise ForeignReference('referência de cofre fora do campo dela: {0}'.format('.'.join(path)))
					continue
				secret_id = secrets.token_hex(16)
				_store(session, key, secret_id, value)
				node[name] = REF_PREFIX + secret_id
			session.commit()
		finally:
			session.close()
	return result


def collect(sealed_document):
	"""Apaga as linhas que nenhuma referência do documento gravado usa mais."""
	with _lock:
		key = _key_or_none()
		if key is None:
			return 0
		used = set(_references(sealed_document))
		current = key_id(key)
		session = models.get_session()
		removed = 0
		try:
			for row in session.query(models.VaultSecret).all():
				if row.id.startswith(APP_PREFIX) or row.id in used or row.key_id != current:
					continue
				session.delete(row)
				_plain_cache.pop(row.id, None)
				removed += 1
			session.commit()
		finally:
			session.close()
		return removed


def app_secret(name, generate):
	"""Um segredo que a própria aplicação gera e guarda (id fixo, fora da coleta).

	Sem chave mestra, devolve None: quem chama decide o que vale (hoje, o valor
	do ambiente ou um aleatório por processo, como antes).
	"""
	secret_id = APP_PREFIX + name
	with _lock:
		key = _key_or_none()
		if key is None:
			return None
		session = models.get_session()
		try:
			row = session.query(models.VaultSecret).get(secret_id)
			if row is not None:
				try:
					return _open(row, key)
				except VaultError as error:
					# Não regenera em silêncio: trocar a chave do cookie derruba todas
					# as sessões, e quem trocou a chave mestra precisa saber
					log.error('o segredo %s não abriu (%s); gerando outro', secret_id, error)
			value = generate()
			_store(session, key, secret_id, value)
			session.commit()
			return value
		finally:
			session.close()


def status(raw_document):
	"""O estado do cofre para a aba Segurança. Nunca devolve valor de segredo."""
	try:
		key = master_key()
		key_error = None
	except (VaultError, OSError) as error:
		key, key_error = None, str(error)
	slots = list(_secret_slots(raw_document or {}))
	references = _references(raw_document or {})
	plaintext = len([1 for node, name in slots if node[name] and not is_reference(node[name])])
	unreadable = 0
	if references:
		session = models.get_session()
		try:
			for secret_id in references:
				row = session.query(models.VaultSecret).get(secret_id)
				if row is None or key is None or row.key_id != key_id(key):
					unreadable += 1
		finally:
			session.close()
	return {
		'keyFile': key_file(),
		'keyPresent': key is not None,
		'keyError': key_error,
		'keyId': key_id(key) if key is not None else None,
		'sealed': len(references),
		'plaintext': plaintext,
		'unreadable': unreadable
	}


def forget_cache():
	"""Para os testes, e para quem troca a chave mestra com o processo de pé."""
	with _lock:
		_plain_cache.clear()
		_reported.clear()
		_key_cache.update({'key': None, 'value': None})
