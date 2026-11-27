"""Testes de database.py: a escolha do banco e a migração do SQLite para o Postgres.

A primeira parte roda sempre. A segunda precisa de um PostgreSQL de verdade e só
roda quando BLUEPHISH_TEST_PG_HOST está definido (o CI sobe um, em
.github/workflows/python-app.yml); sem ele, é pulada, e diz isso.

O que se prende aqui:

  * sem BLUEPHISH_DB_HOST, o banco é o SQLite de sempre;
  * com ele, a senha vem do arquivo, e arquivo ausente ou vazio é erro — nunca
    um SQLite vazio no lugar (database.py, decisão 1);
  * o ALTER das colunas novas fala o dialeto do Postgres;
  * a migração copia tudo, uma vez só, deixa backup e marcador, avança as
    sequências e corta texto maior que a coluna;
  * com usuários já no Postgres, nada é copiado por cima.

Roda com:  python -m unittest test_database   (a partir do diretório app/)
"""

import datetime
import os
import shutil
import tempfile
import unittest

import sqlalchemy

import database
import models


ENV_KEYS = ('BLUEPHISH_DB_HOST', 'BLUEPHISH_DB_PORT', 'BLUEPHISH_DB_USER', 'BLUEPHISH_DB_NAME',
	'BLUEPHISH_DB_PASSWORD_FILE')


class EnvMixin(object):

	def setUp(self):
		self.saved_env = {key: os.environ.get(key) for key in ENV_KEYS}
		for key in ENV_KEYS:
			os.environ.pop(key, None)
		self.directory = tempfile.mkdtemp()

	def tearDown(self):
		for key, value in self.saved_env.items():
			if value is None:
				os.environ.pop(key, None)
			else:
				os.environ[key] = value
		shutil.rmtree(self.directory, ignore_errors = True)

	def password_file(self, content):
		path = os.path.join(self.directory, 'db.password')
		with open(path, 'w') as handle:
			handle.write(content)
		return path


class EscolhaDoBanco(EnvMixin, unittest.TestCase):

	def test_sem_host_e_o_sqlite_de_sempre(self):
		engine = database.create_engine(os.path.join(self.directory, 'x.db'))
		self.assertEqual('sqlite', engine.dialect.name)

	def test_a_senha_vem_do_arquivo_e_nunca_do_ambiente(self):
		os.environ['BLUEPHISH_DB_HOST'] = 'db'
		os.environ['BLUEPHISH_DB_PASSWORD_FILE'] = self.password_file('segredo-do-banco\n')
		url = database.postgres_url()
		self.assertEqual('postgresql+psycopg2', url.drivername)
		self.assertEqual('segredo-do-banco', url.password)
		self.assertEqual(('db', 5432, 'bluephish', 'bluephish'), (url.host, url.port, url.database, url.username))

	def test_senha_ausente_e_erro_e_nao_sqlite(self):
		os.environ['BLUEPHISH_DB_HOST'] = 'db'
		os.environ['BLUEPHISH_DB_PASSWORD_FILE'] = os.path.join(self.directory, 'nao-existe')
		with self.assertRaises(database.DatabaseConfigError):
			database.create_engine(os.path.join(self.directory, 'x.db'))
		self.assertFalse(os.path.exists(os.path.join(self.directory, 'x.db')))

	def test_senha_vazia_e_erro(self):
		os.environ['BLUEPHISH_DB_HOST'] = 'db'
		os.environ['BLUEPHISH_DB_PASSWORD_FILE'] = self.password_file('  \n')
		with self.assertRaises(database.DatabaseConfigError):
			database.postgres_url()

	def test_porta_que_nao_e_numero_e_erro(self):
		os.environ['BLUEPHISH_DB_HOST'] = 'db'
		os.environ['BLUEPHISH_DB_PORT'] = 'cinco'
		os.environ['BLUEPHISH_DB_PASSWORD_FILE'] = self.password_file('x')
		with self.assertRaises(database.DatabaseConfigError):
			database.postgres_url()

	def test_datetime_vira_timestamp_no_postgres(self):
		pg = sqlalchemy.create_engine('postgresql+psycopg2://u:p@h/d')
		lite = sqlalchemy.create_engine('sqlite://')
		self.assertEqual('TIMESTAMP', database.column_type(pg, 'DATETIME'))
		self.assertEqual('DATETIME', database.column_type(lite, 'DATETIME'))

	def test_sem_postgres_a_migracao_nao_faz_nada(self):
		lite = sqlalchemy.create_engine('sqlite://')
		self.assertIsNone(database.migrate_from_sqlite(lite, os.path.join(self.directory, 'x.db'),
			models.Base.metadata, models._add_missing_columns))

	def test_o_logger_esta_configurado(self):
		import json
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logging_conf.json')) as conf:
			self.assertIn('database', json.load(conf)['loggers'])


@unittest.skipUnless(os.environ.get('BLUEPHISH_TEST_PG_HOST'), 'sem PostgreSQL de teste (BLUEPHISH_TEST_PG_HOST)')
class MigracaoParaPostgres(EnvMixin, unittest.TestCase):

	def setUp(self):
		super(MigracaoParaPostgres, self).setUp()
		os.environ['BLUEPHISH_DB_HOST'] = os.environ['BLUEPHISH_TEST_PG_HOST']
		os.environ['BLUEPHISH_DB_PORT'] = os.environ.get('BLUEPHISH_TEST_PG_PORT', '5432')
		os.environ['BLUEPHISH_DB_USER'] = os.environ.get('BLUEPHISH_TEST_PG_USER', 'bluephish')
		os.environ['BLUEPHISH_DB_NAME'] = os.environ.get('BLUEPHISH_TEST_PG_DB', 'bluephish')
		os.environ['BLUEPHISH_DB_PASSWORD_FILE'] = self.password_file(os.environ.get('BLUEPHISH_TEST_PG_PASSWORD', ''))
		self.previous_db = models.DB_PATH
		models.DB_PATH = os.path.join(self.directory, 'thephish.db')
		self.reset_engine()
		self.wipe_postgres()

	def tearDown(self):
		self.wipe_postgres()
		self.reset_engine()
		models.DB_PATH = self.previous_db
		super(MigracaoParaPostgres, self).tearDown()

	def reset_engine(self):
		if models._engine is not None:
			models._engine.dispose()
		models._engine = None
		models._SessionFactory = None

	def wipe_postgres(self):
		engine = database.create_engine(models.DB_PATH)
		models.Base.metadata.drop_all(engine)
		engine.dispose()

	def legacy_sqlite(self, users = ('ana', 'bia'), subject = 'Assunto'):
		"""Um SQLite como o de uma instalação anterior, com dados."""
		engine = sqlalchemy.create_engine('sqlite:///{0}'.format(models.DB_PATH))
		models.Base.metadata.create_all(engine)
		Session = sqlalchemy.orm.sessionmaker(bind = engine)
		session = Session()
		for name in users:
			user = models.User(username = name, role = models.ROLE_GLOBAL_ADMIN)
			user.set_password('senha-bem-comprida-1')
			session.add(user)
		session.add(models.AnalysisHistory(analyzed_at = datetime.datetime(2026, 11, 1, 12, 0),
			subject = subject))
		session.commit()
		session.close()
		engine.dispose()

	def users(self):
		session = models.get_session()
		try:
			return sorted(user.username for user in session.query(models.User).all())
		finally:
			session.close()

	def test_o_engine_e_postgres(self):
		self.assertEqual('postgresql', models.init_db().dialect.name)

	def test_copia_tudo_uma_vez_com_backup_e_marcador(self):
		self.legacy_sqlite()
		models.init_db()
		self.assertEqual(['ana', 'bia'], self.users())
		files = os.listdir(self.directory)
		self.assertIn('thephish.db' + database.MIGRATED_SUFFIX, files)
		self.assertTrue(any(name.startswith('thephish.db.pre-postgres-') for name in files))
		# O original fica intacto
		self.assertIn('thephish.db', files)

	def test_a_senha_copiada_continua_valendo(self):
		self.legacy_sqlite()
		models.init_db()
		session = models.get_session()
		try:
			user = session.query(models.User).filter(models.User.username == 'ana').first()
			self.assertTrue(user.check_password('senha-bem-comprida-1'))
		finally:
			session.close()

	def test_a_sequencia_continua_depois_do_maior_id(self):
		self.legacy_sqlite()
		models.init_db()
		new_id = models.create_user('caio', 'senha-bem-comprida-2', models.ROLE_ANALYST)
		self.assertEqual(3, new_id)

	def test_nao_copia_de_novo_depois_do_marcador(self):
		self.legacy_sqlite()
		models.init_db()
		models.create_user('caio', 'senha-bem-comprida-2', models.ROLE_ANALYST)
		self.reset_engine()
		models.init_db()
		self.assertEqual(['ana', 'bia', 'caio'], self.users())

	def test_postgres_com_usuarios_nao_recebe_copia(self):
		models.init_db()
		models.create_user('dono', 'senha-bem-comprida-3', models.ROLE_GLOBAL_ADMIN)
		self.reset_engine()
		self.legacy_sqlite()
		models.init_db()
		self.assertEqual(['dono'], self.users())
		self.assertNotIn('thephish.db' + database.MIGRATED_SUFFIX, os.listdir(self.directory))

	def test_texto_maior_que_a_coluna_e_cortado(self):
		self.legacy_sqlite(subject = 'x' * 400)
		models.init_db()
		session = models.get_session()
		try:
			subject = session.query(models.AnalysisHistory).first().subject
		finally:
			session.close()
		self.assertEqual(255, len(subject))

	def test_coluna_nova_entra_numa_tabela_postgres_antiga(self):
		engine = models.init_db()
		with engine.begin() as connection:
			connection.execute(sqlalchemy.text('ALTER TABLE users DROP COLUMN mfa_confirmed_at'))
		self.reset_engine()
		models.init_db()
		self.assertIn('mfa_confirmed_at', database.existing_columns(models._engine, 'users'))


if __name__ == '__main__':
	unittest.main()
