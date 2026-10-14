"""Testes da conta provisionada por SSO e da sessão que morre com a aba.

Três coisas que só se percebe que quebraram quando já é tarde:

  1. A coluna `auth_source` não existia antes do SSO. Uma instalação em uso tem
     o banco sem ela, e `create_all()` não acrescenta coluna a tabela que já
     existe — sem o ALTER, o primeiro login depois do deploy morre em SQL.

  2. O grupo no Entra ID manda no cargo, mas não a ponto de trancar a porta: o
     último global_admin não pode ser rebaixado por uma mudança de grupo.

  3. A sessão presa à aba tem de expirar sozinha quando os sinais de vida param,
     e um registro vazio (processo reiniciado) tem de valer como "morta".

Roda com:  python -m unittest test_session_tab   (a partir do diretório app/)
"""

import datetime
import os
import shutil
import tempfile
import unittest

import sqlalchemy

import models


# SQLAlchemy 1.4 (a da imagem) e 2.x (a de quem roda os testes) discordam sobre
# `engine.execute` e sobre commit explícito. Estes dois auxiliares falam as duas
def run(engine, *statements):
	with engine.connect() as connection:
		for statement in statements:
			connection.execute(sqlalchemy.text(statement))
		commit = getattr(connection, 'commit', None)
		if commit is not None:
			commit()


def columns_of(engine, table):
	with engine.connect() as connection:
		rows = connection.execute(sqlalchemy.text('PRAGMA table_info({0})'.format(table))).fetchall()
	return {row[1] for row in rows}


class BancoTemporario(unittest.TestCase):
	"""Cada teste com o seu banco em disco, jogado fora no fim."""

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-test-')
		self.db_path = os.path.join(self.directory, 'bluephish.db')
		self.previous_path = models.DB_PATH
		models.DB_PATH = self.db_path
		models._engine = None
		models._SessionFactory = None

	def tearDown(self):
		models.DB_PATH = self.previous_path
		models._engine = None
		models._SessionFactory = None
		shutil.rmtree(self.directory, ignore_errors = True)


class Migracao(BancoTemporario):

	def test_a_coluna_e_acrescentada_a_um_banco_que_nao_a_tem(self):
		# Um banco como o de antes do SSO: a tabela users sem auth_source
		engine = sqlalchemy.create_engine('sqlite:///{0}'.format(self.db_path))
		run(engine,
			'CREATE TABLE users ('
			' id INTEGER NOT NULL PRIMARY KEY,'
			' username VARCHAR(64) NOT NULL,'
			' password_hash VARCHAR(255) NOT NULL,'
			' role VARCHAR(32) NOT NULL,'
			' failed_logins INTEGER NOT NULL DEFAULT 0,'
			' locked_until DATETIME,'
			' last_login DATETIME,'
			' password_changed_at DATETIME NOT NULL)',
			"INSERT INTO users (username, password_hash, role, password_changed_at)"
			" VALUES ('ana', 'x', 'global_admin', '2020-01-01 00:00:00')")
		engine.dispose()

		models.init_db()

		columns = columns_of(models._engine, 'users')
		self.assertIn('auth_source', columns)
		# E quem já existia continua sendo conta local, com senha valendo
		session = models.get_session()
		try:
			self.assertEqual(models.AUTH_LOCAL, session.query(models.User).filter(models.User.username == 'ana').first().auth_source)
		finally:
			session.close()

	def test_rodar_duas_vezes_nao_quebra(self):
		models.init_db()
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		columns = columns_of(models._engine, 'users')
		self.assertIn('auth_source', columns)


class ProvisionamentoPorSSO(BancoTemporario):

	def setUp(self):
		super().setUp()
		models.init_db()

	def user(self, username):
		session = models.get_session()
		try:
			return session.query(models.User).filter(models.User.username == username).first()
		finally:
			session.close()

	def test_a_primeira_entrada_cria_a_conta_com_o_cargo_do_grupo(self):
		user_id, action = models.sso_sign_in('ana@acme.com', models.ROLE_ADMIN)
		self.assertEqual('created', action)
		created = self.user('ana@acme.com')
		self.assertEqual(models.ROLE_ADMIN, created.role)
		self.assertEqual(models.AUTH_SSO, created.auth_source)
		self.assertTrue(created.is_sso())
		self.assertEqual(user_id, created.id)

	def test_a_conta_criada_nao_tem_senha_utilizavel(self):
		models.sso_sign_in('ana@acme.com', models.ROLE_ANALYST)
		created = self.user('ana@acme.com')
		for attempt in ('', 'senha', 'x' * 32, created.password_hash):
			self.assertFalse(created.check_password(attempt))

	def test_mudar_de_grupo_muda_o_cargo_na_entrada_seguinte(self):
		models.sso_sign_in('ana@acme.com', models.ROLE_ANALYST)
		_id, action = models.sso_sign_in('ana@acme.com', models.ROLE_ADMIN)
		self.assertEqual('role_changed', action)
		self.assertEqual(models.ROLE_ADMIN, self.user('ana@acme.com').role)

	def test_o_nome_de_usuario_e_normalizado(self):
		models.sso_sign_in('  Ana@ACME.com  ', models.ROLE_ANALYST)
		self.assertIsNotNone(self.user('ana@acme.com'))

	def test_o_ultimo_global_admin_nao_e_rebaixado_por_mudanca_de_grupo(self):
		"""Senão uma edição de grupo tranca a instalação inteira para fora."""
		models.sso_sign_in('dono@acme.com', models.ROLE_GLOBAL_ADMIN)
		_id, action = models.sso_sign_in('dono@acme.com', models.ROLE_ANALYST)
		self.assertEqual('signed_in', action)
		self.assertEqual(models.ROLE_GLOBAL_ADMIN, self.user('dono@acme.com').role)

	def test_havendo_outro_global_admin_o_rebaixamento_vale(self):
		models.create_user('outro@acme.com', 'senha-bem-comprida', models.ROLE_GLOBAL_ADMIN)
		models.sso_sign_in('dono@acme.com', models.ROLE_GLOBAL_ADMIN)
		models.sso_sign_in('dono@acme.com', models.ROLE_ANALYST)
		self.assertEqual(models.ROLE_ANALYST, self.user('dono@acme.com').role)

	def test_uma_conta_local_que_entra_por_sso_continua_local(self):
		"""A senha dela segue valendo se o provedor de identidade cair."""
		models.create_user('ana@acme.com', 'senha-bem-comprida', models.ROLE_ANALYST)
		models.sso_sign_in('ana@acme.com', models.ROLE_ADMIN)
		local = self.user('ana@acme.com')
		self.assertEqual(models.AUTH_LOCAL, local.auth_source)
		self.assertEqual(models.ROLE_ADMIN, local.role)
		self.assertTrue(local.check_password('senha-bem-comprida'))

	def test_um_cargo_desconhecido_e_recusado(self):
		with self.assertRaises(ValueError):
			models.sso_sign_in('ana@acme.com', 'inventado')

	def test_um_token_sem_usuario_e_recusado(self):
		with self.assertRaises(ValueError):
			models.sso_sign_in('   ', models.ROLE_ANALYST)


class VidaDaAba(unittest.TestCase):
	"""Enquanto a aba existe ela bate ponto; quando para, a sessão morre."""

	def setUp(self):
		import auth
		self.auth = auth
		self.auth._live_sessions.clear()

	def tearDown(self):
		self.auth._live_sessions.clear()

	def test_uma_sessao_que_acabou_de_dar_sinal_esta_viva(self):
		self.auth._live_sessions['abc'] = datetime.datetime.utcnow()
		self.assertTrue(self.auth._session_is_live('abc'))

	def test_dentro_da_carencia_ainda_esta_viva(self):
		"""Navegador estrangula timer de aba em segundo plano — daí a folga."""
		self.auth._live_sessions['abc'] = datetime.datetime.utcnow() - self.auth.TAB_GRACE + datetime.timedelta(seconds = 5)
		self.assertTrue(self.auth._session_is_live('abc'))

	def test_passada_a_carencia_sem_sinal_a_sessao_morreu(self):
		self.auth._live_sessions['abc'] = datetime.datetime.utcnow() - self.auth.TAB_GRACE - datetime.timedelta(seconds = 1)
		self.assertFalse(self.auth._session_is_live('abc'))

	def test_sessao_desconhecida_esta_morta(self):
		"""Falha fechado: é o estado de todas depois de um reinício do processo."""
		self.assertFalse(self.auth._session_is_live('nunca-vista'))

	def test_a_carencia_nunca_e_curta_demais_para_uma_aba_em_segundo_plano(self):
		# Um disparo por minuto é o que o navegador garante numa aba escondida
		self.assertGreaterEqual(self.auth.TAB_GRACE, datetime.timedelta(seconds = 60))
		self.assertGreater(self.auth.TAB_GRACE.total_seconds(), self.auth.TAB_HEARTBEAT_SECONDS * 2)


if __name__ == '__main__':
	unittest.main()
