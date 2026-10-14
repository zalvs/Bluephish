"""A mensagem original de cada análise, guardada pela própria aplicação.

Existe por duas funções da mesa de trabalho que não têm como funcionar sem ela:
reanalisar um caso e mostrar o e-mail como ele chegou à caixa da pessoa. As duas
precisam do `.eml` bruto — cabeçalhos, partes, anexos — e até aqui ele só
sobrevivia quando alguém tinha ligado o destino Disco (`writeEml`) ou o Jira
(`attachEml`). Numa instalação que só grava no TheHive, ele não sobrevivia a
lugar nenhum, e as duas funções simplesmente não existiriam.

O que isso significa, dito por extenso porque é uma decisão e não um detalhe:
**a aplicação passa a armazenar e-mail de phishing bruto**, com anexo e tudo.
Três limites cercam essa decisão, e nenhum é opcional:

  * **Retenção em dias.** Uma análise velha o bastante perde o `.eml` mesmo que
    haja espaço de sobra. O padrão é 90 dias; zero significa "só o orçamento de
    bytes manda", e é uma escolha que quem administra faz sabendo.
  * **Orçamento de bytes.** O que passa dele é descartado do mais antigo para o
    mais novo. O teto é por bytes e não por contagem, pelo mesmo motivo do
    `render_store`: um e-mail de texto puro e um com um PDF de 8 MB diferem em
    duas ordens de grandeza em tamanho, não em número.
  * **Nada fora do volume de dados.** O diretório é criado sob `data/`, que é o
    bind mount — um rebuild de imagem não leva o acervo junto.

E três regras de escrita, cada uma porque quebrá-la mostra a mensagem errada em
vez de falhar:

  * **Uma entrada é o seu metadado.** O `.meta.json` é o que faz a entrada
    existir. Ele é removido antes de o payload ser trocado e escrito depois, os
    dois por temporário e rename, de modo que um processo morto no meio deixa um
    órfão que o próximo start apaga — nunca um metadado velho sobre um `.eml`
    novo.
  * **A chave é a referência do registro**, a mesma que a rota de detalhe
    aceita (`4021`, `disk:2026-09-15T...`, `jira:SOC-12`). É o que liga o `.eml`
    ao caso sem depender do `mailUID`, que some da caixa assim que a análise
    termina. Uma análise gravada em dois destinos produz duas referências para a
    mesma mensagem, e as duas apontam para **um** arquivo: o payload é nomeado
    pelo resumo do conteúdo, não pela referência, e só sai do disco quando a
    última referência que o citava sai. Sem isso, quem tem TheHive e disco
    ligados gasta o dobro do orçamento guardando o mesmo e-mail duas vezes.
  * **Ler nunca levanta.** Um acervo corrompido, um disco cheio ou um diretório
    sem permissão devolvem None e a tela diz que não tem a mensagem original.
    Derrubar a análise por causa do arquivo que serve para revê-la depois seria
    trocar o essencial pelo acessório.

Sem eventlet e sem libmagic: isto é importável, e testado, fora da imagem.
"""

import hashlib
import io
import json
import os
import time

# Teto do acervo inteiro, em bytes. O padrão é deliberadamente modesto perto do
# `render_store` (1 GB de layouts): ali cada entrada é uma página HTML, aqui cada
# entrada pode ser um e-mail com anexo
MAX_BYTES = 2 * 1024 * 1024 * 1024

# Por quantos dias um `.eml` continua guardado. 0 desliga a retenção por tempo e
# deixa só o orçamento de bytes decidindo
RETENTION_DAYS = 90

# Teto de uma mensagem. Acima disto ela não entra: um anexo gigante encheria o
# acervo sozinho, e reanalisar algo que o pipeline mal conseguiu baixar não é o
# caso que esta função existe para servir
MAX_MESSAGE_BYTES = 40 * 1024 * 1024

PAYLOAD_SUFFIX = '.eml'
META_SUFFIX = '.meta.json'
TEMP_SUFFIX = '.tmp'

SECONDS_PER_DAY = 86400


class EmlStore:

	def __init__(self, directory, max_bytes = MAX_BYTES, retention_days = RETENTION_DAYS):
		self.directory = directory
		self.max_bytes = max_bytes
		self.retention_days = retention_days
		# record_ref -> metadado. Em memória para que responder "tem o original
		# deste caso?" em toda linha de uma lista nunca toque o disco
		self.index = {}
		self._sequence = 0
		os.makedirs(directory, exist_ok = True)
		self._load_index()

	# ---- leitura -------------------------------------------------------------

	def has(self, record_ref):
		"""Se existe original guardado para este registro. Só o índice, sem disco."""
		return str(record_ref) in self.index

	def stored_at(self, record_ref):
		"""Quando o original foi guardado, em epoch, ou None."""
		meta = self.index.get(str(record_ref))
		return meta.get('stored') if meta else None

	def size_of(self, record_ref):
		meta = self.index.get(str(record_ref))
		return meta.get('bytes') if meta else None

	def get(self, record_ref):
		"""Os bytes do `.eml`, ou None quando não há entrada válida."""
		record_ref = str(record_ref)
		meta = self.index.get(record_ref)
		if meta is None:
			return None
		try:
			with io.open(self._payload_path(meta['contentKey']), 'rb') as handle:
				return handle.read()
		except OSError:
			# O metadado existe e o payload não: a entrada não é mais uma entrada
			self.discard(record_ref)
			return None

	def total_bytes(self):
		"""Os bytes que o acervo ocupa. Um payload compartilhado conta uma vez."""
		by_content = {}
		for meta in self.index.values():
			by_content[meta.get('contentKey')] = meta.get('bytes', 0)
		return sum(by_content.values())

	def count(self):
		"""Quantas referências o acervo responde. Duas podem citar o mesmo arquivo."""
		return len(self.index)

	# ---- escrita -------------------------------------------------------------

	def put(self, record_ref, message_bytes, now = None):
		"""Guarda o original de uma análise. Devolve True quando guardou.

		Recusa em silêncio o que não vale guardar — vazio, ou grande demais — e
		devolve False: quem chama está no caminho da análise, e um acervo cheio
		nunca é motivo para o veredito não sair.
		"""
		record_ref = str(record_ref)
		if not record_ref or not message_bytes:
			return False
		if len(message_bytes) > MAX_MESSAGE_BYTES:
			return False

		meta_key = self._meta_key(record_ref)
		content_key = self._content_key(message_bytes)
		now = now if now is not None else time.time()

		# Despublica primeiro: até o metadado novo pousar não existe entrada
		# nenhuma, em vez de um metadado antigo descrevendo outro conteúdo
		previous = self.index.pop(record_ref, None)
		self._remove(self._meta_path(meta_key))
		# Trocar o conteúdo de uma referência pode deixar o payload anterior sem
		# ninguém citando; ele sai aqui, e não na próxima poda
		if previous is not None and previous.get('contentKey') != content_key:
			self._collect(previous.get('contentKey'))

		payload_path = self._payload_path(content_key)
		if not os.path.isfile(payload_path):
			try:
				self._write(payload_path, message_bytes)
			except OSError:
				self._remove(payload_path + TEMP_SUFFIX)
				return False

		self._sequence += 1
		meta = {
			'recordRef': record_ref,
			'key': meta_key,
			'contentKey': content_key,
			'bytes': len(message_bytes),
			'stored': now,
			'sequence': self._sequence
		}
		try:
			self._write(self._meta_path(meta_key), json.dumps(meta).encode('utf-8'))
		except OSError:
			self._collect(content_key)
			return False
		self.index[record_ref] = meta
		self._evict(keep = record_ref)
		return True

	def discard(self, record_ref):
		record_ref = str(record_ref)
		meta = self.index.pop(record_ref, None)
		self._remove(self._meta_path(meta['key'] if meta else self._meta_key(record_ref)))
		if meta is not None:
			self._collect(meta.get('contentKey'))

	def prune(self, now = None):
		"""Aplica a retenção por tempo e o orçamento de bytes. Devolve quantas saíram.

		Roda no caminho de quem guarda, e não num laço próprio: a frequência que
		importa é a de chegada de análise, e um acervo parado não precisa de poda.
		"""
		now = now if now is not None else time.time()
		removed = 0
		if self.retention_days and self.retention_days > 0:
			horizon = now - self.retention_days * SECONDS_PER_DAY
			for record_ref, meta in list(self.index.items()):
				if meta.get('stored', 0) < horizon:
					self.discard(record_ref)
					removed += 1
		removed += self._evict(keep = None)
		return removed

	# ---- internos ------------------------------------------------------------

	def _collect(self, content_key):
		"""Apaga o payload quando a última referência que o citava saiu."""
		if not content_key:
			return
		for meta in self.index.values():
			if meta.get('contentKey') == content_key:
				return
		self._remove(self._payload_path(content_key))

	def _evict(self, keep):
		"""Descarta do mais antigo para o mais novo até caber no orçamento.

		Nunca a entrada recém-escrita: despejar o que alguém acabou de pedir para
		abrir espaço para ela não é acervo, é perda de tempo com E/S. Descartar
		uma referência que divide o arquivo com outra libera zero bytes — o laço
		continua porque cada volta remove uma referência, e acaba.
		"""
		removed = 0
		while self.total_bytes() > self.max_bytes:
			candidates = [meta for ref, meta in self.index.items() if ref != keep]
			if not candidates:
				return removed
			oldest = min(candidates, key = lambda meta: meta.get('sequence', 0))
			self.discard(oldest['recordRef'])
			removed += 1
		return removed

	def _load_index(self):
		try:
			names = os.listdir(self.directory)
		except OSError:
			return
		referenced = set()
		for name in names:
			path = os.path.join(self.directory, name)
			if name.endswith(TEMP_SUFFIX):
				# Uma escrita que nunca chegou ao rename
				self._remove(path)
				continue
			if not name.endswith(META_SUFFIX):
				continue
			key = name[:-len(META_SUFFIX)]
			try:
				with io.open(path, encoding = 'utf-8') as handle:
					meta = json.load(handle)
			except (OSError, ValueError):
				self._remove(path)
				continue
			if (not isinstance(meta, dict) or meta.get('key') != key or not meta.get('recordRef')
					or not meta.get('contentKey')
					or not os.path.isfile(self._payload_path(meta['contentKey']))):
				self._remove(path)
				continue
			referenced.add(meta['contentKey'])
			self.index[meta['recordRef']] = meta
			self._sequence = max(self._sequence, int(meta.get('sequence') or 0))
		# Um payload que nenhum metadado cita nunca foi — ou deixou de ser — uma entrada
		for name in names:
			if name.endswith(PAYLOAD_SUFFIX) and name[:-len(PAYLOAD_SUFFIX)] not in referenced:
				self._remove(os.path.join(self.directory, name))

	def _meta_key(self, record_ref):
		# Resumido porque uma referência de registro carrega ':' e barras, que um
		# nome de arquivo não deve carregar, e porque nada no nome precisa ser
		# legível — o que liga a entrada ao caso é o metadado, não o nome
		return hashlib.sha256(record_ref.encode('utf-8')).hexdigest()[:40]

	def _content_key(self, message_bytes):
		# O payload é endereçado pelo conteúdo: é o que faz duas referências da
		# mesma análise dividirem um arquivo só
		return hashlib.sha256(message_bytes).hexdigest()[:40]

	def _payload_path(self, content_key):
		return os.path.join(self.directory, content_key + PAYLOAD_SUFFIX)

	def _meta_path(self, meta_key):
		return os.path.join(self.directory, meta_key + META_SUFFIX)

	def _write(self, path, data):
		temporary = path + TEMP_SUFFIX
		with io.open(temporary, 'wb') as handle:
			handle.write(data)
		os.replace(temporary, path)

	def _remove(self, path):
		try:
			os.remove(path)
		except OSError:
			pass
