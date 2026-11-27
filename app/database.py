"""Onde o banco mora: PostgreSQL em contêiner próprio, ou SQLite como antes.

O compose sobe o PostgreSQL num contêiner só dele (`db`), numa rede interna
(`data`) em que só a API entra. A aplicação escolhe o banco assim:

* **BLUEPHISH_DB_HOST definido** → PostgreSQL. A senha vem de um arquivo
  (BLUEPHISH_DB_PASSWORD_FILE, padrão /run/secrets/bluephish/db.password), o mesmo
  que o contêiner do banco lê em POSTGRES_PASSWORD_FILE. Nunca do ambiente: uma
  variável aparece em `docker inspect`, em /proc/<pid>/environ e em todo
  processo filho.
* **Sem BLUEPHISH_DB_HOST** → SQLite em models.DB_PATH, exatamente como antes. É
  o que os testes e quem roda fora do compose usam.

Quatro decisões que não são óbvias lendo o código:

1. **Postgres pedido e senha ausente é erro, não SQLite.** Cair em silêncio para
   o SQLite subiria a aplicação com um banco vazio: sem usuários, ninguém entra,
   e o banco de verdade parece ter sumido. Melhor não subir e dizer por quê.

2. **Migração do SQLite, uma vez, sozinha.** Uma instalação que vem do SQLite
   sobe com o Postgres vazio. Se o arquivo antigo existe, o banco novo não tem
   nenhum usuário e a migração ainda não foi feita, tudo é copiado numa
   transação só, e as sequências dos ids avançam para depois do maior copiado.
   Antes, o arquivo antigo é copiado para `<arquivo>.pre-postgres-<data>.bak`, e
   ele mesmo não é tocado; um marcador (`<arquivo>.migrated`) impede uma segunda
   cópia. Se a cópia falha, nada é gravado no Postgres e a aplicação não sobe:
   subir vazia seria o mesmo problema da decisão 1.

3. **Texto maior que a coluna é cortado na cópia, e contado.** O SQLite não
   impõe o tamanho de VARCHAR; o Postgres impõe. Recusar a migração inteira por
   um assunto de e-mail comprido deixaria a instalação parada; cortar no tamanho
   que o modelo sempre declarou, e dizer no log quantos foram, não perde nada
   que o resto da aplicação já não cortasse.

4. **psycopg2 verde.** O psycopg2 é C e bloqueia o processo inteiro enquanto
   espera o banco; com eventlet, isso para todas as análises e websockets ao
   mesmo tempo. Com o socket do eventlet já trocado (thephish_app faz o
   monkey_patch primeiro), um wait callback entrega a espera ao hub do eventlet
   — é o que o psycogreen faz, em quinze linhas que não pedem dependência nova.
"""

import datetime
import logging
import os
import shutil
import sys
import tempfile

import sqlalchemy

log = logging.getLogger('database')

DEFAULT_PASSWORD_FILE = '/run/secrets/bluephish/db.password'  # nosec B105 — o caminho do arquivo, não a senha
DEFAULT_PORT = 5432
DEFAULT_NAME = 'bluephish'
DEFAULT_USER = 'bluephish'

MIGRATED_SUFFIX = '.migrated'


class DatabaseConfigError(RuntimeError):
	"""O Postgres foi pedido e não dá para montar a conexão."""


def postgres_requested():
	return bool(os.environ.get('BLUEPHISH_DB_HOST', '').strip())


def _read_password():
	path = os.environ.get('BLUEPHISH_DB_PASSWORD_FILE', '').strip() or DEFAULT_PASSWORD_FILE
	try:
		with open(path) as handle:
			password = handle.read().strip()
	except OSError as error:
		raise DatabaseConfigError('BLUEPHISH_DB_HOST está definido, mas a senha do banco não abriu ({0}: {1}). '
			'Rode ../setup.sh para gerar docker/secrets/db.password'.format(path, error.strerror or error))
	if not password:
		raise DatabaseConfigError('O arquivo de senha do banco ({0}) está vazio.'.format(path))
	return password


def postgres_url():
	"""A URL do Postgres montada do ambiente, ou DatabaseConfigError."""
	host = os.environ.get('BLUEPHISH_DB_HOST', '').strip()
	port_text = os.environ.get('BLUEPHISH_DB_PORT', '').strip()
	try:
		port = int(port_text) if port_text else DEFAULT_PORT
	except ValueError:
		raise DatabaseConfigError('BLUEPHISH_DB_PORT não é um número: {0!r}'.format(port_text))
	return sqlalchemy.engine.URL.create('postgresql+psycopg2',
		username = os.environ.get('BLUEPHISH_DB_USER', '').strip() or DEFAULT_USER,
		password = _read_password(),
		host = host, port = port,
		database = os.environ.get('BLUEPHISH_DB_NAME', '').strip() or DEFAULT_NAME)


def _green_psycopg2():
	"""Faz a espera do psycopg2 ceder ao hub do eventlet (decisão 4)."""
	eventlet = sys.modules.get('eventlet')
	if eventlet is None:
		return
	try:
		if not eventlet.patcher.is_monkey_patched('socket'):
			return
	except AttributeError:
		return
	import psycopg2
	import psycopg2.extensions
	from eventlet.hubs import trampoline

	def wait(connection, timeout = None):
		while True:
			state = connection.poll()
			if state == psycopg2.extensions.POLL_OK:
				return
			if state == psycopg2.extensions.POLL_READ:
				trampoline(connection.fileno(), read = True)
			elif state == psycopg2.extensions.POLL_WRITE:
				trampoline(connection.fileno(), write = True)
			else:
				raise psycopg2.OperationalError('estado inesperado do poll do psycopg2: {0!r}'.format(state))

	psycopg2.extensions.set_wait_callback(wait)


def create_engine(sqlite_path):
	"""O engine do banco escolhido (ver o cabeçalho)."""
	if postgres_requested():
		url = postgres_url()
		_green_psycopg2()
		engine = sqlalchemy.create_engine(url, pool_pre_ping = True, pool_size = 5, max_overflow = 10,
			connect_args = {'connect_timeout': 10, 'application_name': 'bluephish'})
		log.info('banco: PostgreSQL em %s:%s/%s', url.host, url.port, url.database)
		return engine
	db_dir = os.path.dirname(sqlite_path)
	if db_dir and not os.path.isdir(db_dir):
		os.makedirs(db_dir, exist_ok = True)
	return sqlalchemy.create_engine('sqlite:///{0}'.format(sqlite_path), connect_args = {'check_same_thread': False})


def column_type(engine, definition):
	"""A definição de coluna do ALTER no dialeto do engine.

	As definições de models.NEW_COLUMNS foram escritas para o SQLite; só DATETIME
	não existe no Postgres, que chama o tipo de TIMESTAMP.
	"""
	if engine.dialect.name == 'postgresql':
		return definition.replace('DATETIME', 'TIMESTAMP')
	return definition


def existing_columns(engine, table):
	"""Os nomes das colunas da tabela, ou set() quando ela ainda não existe."""
	inspector = sqlalchemy.inspect(engine)
	if not inspector.has_table(table):
		return set()
	return {column['name'] for column in inspector.get_columns(table)}


def _truncate(row, table, counter):
	fixed = dict(row)
	for column in table.columns:
		length = getattr(column.type, 'length', None)
		value = fixed.get(column.name)
		if length and isinstance(value, str) and len(value) > length:
			fixed[column.name] = value[:length]
			counter[0] += 1
	return fixed


def _reset_sequences(connection, metadata):
	for table in metadata.sorted_tables:
		primary = list(table.primary_key.columns)
		if len(primary) != 1 or not isinstance(primary[0].type, sqlalchemy.Integer):
			continue
		column = primary[0].name
		sequence = connection.execute(sqlalchemy.text('SELECT pg_get_serial_sequence(:t, :c)'),
			{'t': table.name, 'c': column}).scalar()
		if not sequence:
			continue
		# Tabela e coluna vêm do metadata do modelo, nunca de fora; identificador não
		# vai como parâmetro, então entra quotado pelo próprio dialeto
		preparer = connection.dialect.identifier_preparer
		template = 'SELECT setval(:s, COALESCE((SELECT MAX({0}) FROM {1}), 1), (SELECT MAX({0}) FROM {1}) IS NOT NULL)'
		query = template.format(preparer.quote(column), preparer.quote(table.name))  # nosec B608 — identificadores do modelo, quotados
		connection.execute(sqlalchemy.text(query), {'s': sequence})


def migrate_from_sqlite(engine, sqlite_path, metadata, prepare):
	"""Copia o SQLite antigo para o Postgres, uma vez (decisão 2).

	`prepare(engine)` é o passo de colunas novas de models, aplicado à cópia de
	trabalho do arquivo antigo para que todo campo do modelo exista nela.
	Devolve o número de linhas copiadas, ou None quando não havia o que migrar.
	"""
	if engine.dialect.name != 'postgresql' or not os.path.isfile(sqlite_path):
		return None
	marker = sqlite_path + MIGRATED_SUFFIX
	if os.path.exists(marker):
		return None
	with engine.connect() as connection:
		if connection.execute(sqlalchemy.text('SELECT COUNT(*) FROM users')).scalar():
			log.warning('o Postgres já tem usuários e %s existe sem marcador de migração: nada foi copiado. '
				'Se o SQLite é o banco certo, esvazie o Postgres e reinicie', sqlite_path)
			return None

	stamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
	backup = '{0}.pre-postgres-{1}.bak'.format(sqlite_path, stamp)
	shutil.copy2(sqlite_path, backup)
	work_dir = tempfile.mkdtemp(prefix = 'bluephish-migrate-')
	work = os.path.join(work_dir, 'legacy.db')
	shutil.copy2(sqlite_path, work)
	legacy = sqlalchemy.create_engine('sqlite:///{0}'.format(work))
	try:
		metadata.create_all(legacy)
		prepare(legacy)
		copied, truncated = 0, [0]
		with legacy.connect() as source, engine.begin() as target:
			for table in metadata.sorted_tables:
				rows = [_truncate(row._mapping, table, truncated) for row in source.execute(table.select())]
				if rows:
					target.execute(table.insert(), rows)
					copied += len(rows)
				log.info('migração: %s, %d linha(s)', table.name, len(rows))
			_reset_sequences(target, metadata)
	except Exception:
		log.exception('a migração do SQLite (%s) para o Postgres falhou; nada foi gravado no Postgres. '
			'O arquivo original está intacto e a cópia em %s', sqlite_path, backup)
		raise
	finally:
		legacy.dispose()
		shutil.rmtree(work_dir, ignore_errors = True)

	with open(marker, 'w') as handle:
		handle.write('{0} {1} linhas copiadas para o PostgreSQL; cópia do original em {2}\n'.format(
			stamp, copied, os.path.basename(backup)))
	if truncated[0]:
		log.warning('migração: %d texto(s) maiores que a coluna foram cortados no tamanho do modelo', truncated[0])
	log.warning('migração do SQLite para o PostgreSQL concluída: %d linha(s). O arquivo antigo (%s) não é mais usado; '
		'a cópia de segurança é %s', copied, sqlite_path, backup)
	return copied
