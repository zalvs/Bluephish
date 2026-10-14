"""Testes do segundo fator obrigatório.

O que estes testes prendem não é o algoritmo — o TOTP vem de pyotp e não é
nosso. É a *política* em volta dele, que é onde mora o jeito de errar caro:

  1. Um código já usado não pode valer de novo enquanto a janela não fecha. Sem
     o contador guardado, um código lido por cima do ombro (ou colhido numa
     página de phishing) vale por até 90 segundos em outro navegador.

  2. A janela de tolerância tem de ser ±1 passo e não mais. Cada passo a mais é
     um código a mais válido por tentativa de adivinhação.

  3. Um segredo *proposto* não é um fator. A conta que abriu a tela de
     configuração e desistiu tem de continuar sendo cobrada no login seguinte,
     não entrar por ter um segredo no banco.

  4. As três colunas do MFA não existiam antes: um banco em uso precisa ganhá-las
     no lugar, e toda conta que já existia tem de acordar como "ainda não
     configurou" — que é o que faz o requisito valer para quem já estava dentro.

  5. Nenhum caminho de código digitado pode ser aceito fora de forma (vazio,
     letras, cinco dígitos), porque um `normalize_code` frouxo vira comparação
     contra um segredo com entrada que o atacante escolhe.

Roda com:  python -m unittest test_mfa   (a partir do diretório app/)
"""

import os
import shutil
import tempfile
import unittest

import pyotp
import sqlalchemy

import mfa
import models


def code_at(secret, moment):
	return pyotp.TOTP(secret, digits = mfa.DIGITS, interval = mfa.PERIOD_SECONDS).at(int(moment))


# Um instante fixo, longe de qualquer borda de passo, para que o teste não
# dependa de quando ele roda
NOW = 1770000015.0


class Codigo(unittest.TestCase):
	"""mfa.normalize_code: o que é um código e o que não é."""

	def test_seis_digitos_passam(self):
		self.assertEqual('012345', mfa.normalize_code('012345'))

	def test_espaco_e_hifen_saem(self):
		# Vários aplicativos mostram "123 456"; quem copia leva o espaço junto
		self.assertEqual('123456', mfa.normalize_code('123 456'))
		self.assertEqual('123456', mfa.normalize_code('123-456'))
		self.assertEqual('123456', mfa.normalize_code('  123456\n'))

	def test_o_que_nao_e_codigo_vira_None(self):
		for entrada in (None, '', '12345', '1234567', 'abcdef', '12345a', '½23456', 123456):
			# 123456 como inteiro também passa, virando texto — é o único caso
			# da lista que não é recusa
			resultado = mfa.normalize_code(entrada)
			if entrada == 123456:
				self.assertEqual('123456', resultado)
			else:
				self.assertIsNone(resultado, 'aceitou {0!r}'.format(entrada))


class Conferencia(unittest.TestCase):

	def setUp(self):
		self.secret = mfa.new_secret()

	def test_o_segredo_tem_o_tamanho_do_RFC(self):
		# 32 caracteres base32 = 160 bits
		self.assertEqual(32, len(self.secret))

	def test_dois_segredos_nunca_saem_iguais(self):
		self.assertNotEqual(mfa.new_secret(), mfa.new_secret())

	def test_o_codigo_do_momento_vale(self):
		ok, counter = mfa.verify(self.secret, code_at(self.secret, NOW), now = NOW)
		self.assertTrue(ok)
		self.assertEqual(int(NOW // mfa.PERIOD_SECONDS), counter)

	def test_um_passo_para_cada_lado_vale(self):
		# Relógio de celular erra; 30 segundos para cada lado cobre isso
		for delta in (-mfa.PERIOD_SECONDS, mfa.PERIOD_SECONDS):
			ok, _ = mfa.verify(self.secret, code_at(self.secret, NOW + delta), now = NOW)
			self.assertTrue(ok, 'recusou um desvio de {0}s'.format(delta))

	def test_dois_passos_ja_nao_valem(self):
		# A janela para em um passo de propósito: cada passo a mais é um código
		# a mais válido por tentativa de adivinhação
		for delta in (-2 * mfa.PERIOD_SECONDS, 2 * mfa.PERIOD_SECONDS):
			ok, _ = mfa.verify(self.secret, code_at(self.secret, NOW + delta), now = NOW)
			self.assertFalse(ok, 'aceitou um desvio de {0}s'.format(delta))

	def test_o_codigo_de_outro_segredo_nao_vale(self):
		outro = mfa.new_secret()
		ok, _ = mfa.verify(self.secret, code_at(outro, NOW), now = NOW)
		self.assertFalse(ok)

	def test_sem_segredo_nada_vale(self):
		self.assertEqual((False, None), mfa.verify(None, '123456', now = NOW))
		self.assertEqual((False, None), mfa.verify('', '123456', now = NOW))

	def test_um_codigo_usado_nao_volta_a_valer(self):
		"""O centro do bloco: sem isto, um código interceptado vale 90 segundos."""
		code = code_at(self.secret, NOW)
		ok, counter = mfa.verify(self.secret, code, now = NOW)
		self.assertTrue(ok)
		# Mesmo código, mesmo instante, agora com o contador guardado
		repeated, _ = mfa.verify(self.secret, code, last_counter = counter, now = NOW)
		self.assertFalse(repeated)

	def test_o_contador_guardado_tambem_barra_o_passo_anterior(self):
		# Quem já usou o código do passo N não pode voltar e usar o de N-1, que
		# a janela de tolerância ainda aceitaria
		counter = int(NOW // mfa.PERIOD_SECONDS)
		anterior = code_at(self.secret, NOW - mfa.PERIOD_SECONDS)
		ok, _ = mfa.verify(self.secret, anterior, last_counter = counter, now = NOW)
		self.assertFalse(ok)

	def test_o_proximo_codigo_continua_valendo_depois_de_um_uso(self):
		# A trava é contra repetição, não contra o login seguinte
		counter = int(NOW // mfa.PERIOD_SECONDS)
		seguinte = NOW + mfa.PERIOD_SECONDS
		ok, novo = mfa.verify(self.secret, code_at(self.secret, seguinte), last_counter = counter, now = seguinte)
		self.assertTrue(ok)
		self.assertEqual(counter + 1, novo)


class Provisionamento(unittest.TestCase):

	def test_a_uri_traz_o_que_o_aplicativo_precisa(self):
		secret = mfa.new_secret()
		uri = mfa.provisioning_uri('ana.silva', secret)
		self.assertTrue(uri.startswith('otpauth://totp/'))
		self.assertIn(secret, uri)
		self.assertIn('issuer=' + mfa.ISSUER, uri)

	def test_o_qr_sai_como_data_uri_de_svg(self):
		uri = mfa.provisioning_uri('ana.silva', mfa.new_secret())
		data = mfa.qr_data_uri(uri)
		# `data:` e não um endereço próprio: o segredo não pode passar por uma
		# URL (histórico, log de acesso, Referer)
		self.assertTrue(data.startswith('data:image/svg+xml;base64,'))
		self.assertGreater(len(data), 1000)

	def test_o_qr_tem_fundo_branco(self):
		# Sobre o tema escuro do painel, um QR sem fundo é um quadrado que
		# nenhuma câmera lê
		import base64
		data = mfa.qr_data_uri(mfa.provisioning_uri('x', mfa.new_secret()))
		svg = base64.b64decode(data.split(',', 1)[1]).decode('utf-8')
		self.assertIn('fill="white"', svg)


class BancoTemporario(unittest.TestCase):
	"""Cada teste com o seu banco em disco, jogado fora no fim."""

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-mfa-')
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

	def user(self, username = 'analista'):
		models.create_user(username, 'uma senha bem longa', models.ROLE_ANALYST)
		return models.get_session()


class EstadoDaConta(BancoTemporario):

	def test_uma_conta_nova_nasce_sem_segundo_fator(self):
		session = self.user()
		try:
			user = session.query(models.User).first()
			self.assertFalse(user.mfa_is_enrolled())
			self.assertIsNone(user.mfa_secret)
			self.assertFalse(user.to_dict()['mfaEnrolled'])
		finally:
			session.close()

	def test_um_segredo_proposto_ainda_nao_e_um_fator(self):
		"""Abriu a tela de configuração e desistiu: continua sendo cobrada."""
		session = self.user()
		try:
			user = session.query(models.User).first()
			user.start_mfa_enrollment()
			session.commit()
			self.assertTrue(user.mfa_secret)
			self.assertIsNone(user.mfa_confirmed_at)
			self.assertFalse(user.mfa_is_enrolled())
		finally:
			session.close()

	def test_a_confirmacao_e_o_que_torna_o_segredo_um_fator(self):
		session = self.user()
		try:
			user = session.query(models.User).first()
			secret = user.start_mfa_enrollment()
			ok, counter = mfa.verify(secret, code_at(secret, NOW), now = NOW)
			self.assertTrue(ok)
			user.confirm_mfa(counter)
			session.commit()
			self.assertTrue(user.mfa_is_enrolled())
			self.assertEqual(counter, user.mfa_last_counter)
			self.assertTrue(user.to_dict()['mfaEnrolled'])
		finally:
			session.close()

	def test_reabrir_a_configuracao_propoe_um_segredo_novo(self):
		# O segredo pendente pode ter sido lido por um telefone que a pessoa não
		# tem mais; reaproveitá-lo entregaria o fator a esse telefone
		session = self.user()
		try:
			user = session.query(models.User).first()
			primeiro = user.start_mfa_enrollment()
			segundo = user.start_mfa_enrollment()
			self.assertNotEqual(primeiro, segundo)
		finally:
			session.close()

	def test_zerar_devolve_a_conta_ao_estado_de_quem_nunca_configurou(self):
		session = self.user()
		try:
			user = session.query(models.User).first()
			secret = user.start_mfa_enrollment()
			_, counter = mfa.verify(secret, code_at(secret, NOW), now = NOW)
			user.confirm_mfa(counter)
			session.commit()
			user.reset_mfa()
			session.commit()
			self.assertFalse(user.mfa_is_enrolled())
			self.assertIsNone(user.mfa_secret)
			self.assertIsNone(user.mfa_last_counter)
		finally:
			session.close()


class Migracao(BancoTemporario):
	"""Um banco anterior ao MFA precisa ganhar as colunas no lugar.

	`create_all()` cria a tabela que falta, mas nunca acrescenta coluna a uma
	tabela que já existe: sem o ALTER, o primeiro login depois do deploy morre
	em SQL — e um login que morre em SQL é a plataforma inteira fora do ar.
	"""

	def test_as_colunas_sao_acrescentadas_a_um_banco_que_nao_as_tem(self):
		engine = sqlalchemy.create_engine('sqlite:///{0}'.format(self.db_path))
		with engine.connect() as connection:
			connection.execute(sqlalchemy.text(
				'CREATE TABLE users ('
				' id INTEGER NOT NULL PRIMARY KEY,'
				' username VARCHAR(64) NOT NULL,'
				' password_hash VARCHAR(255) NOT NULL,'
				' role VARCHAR(32) NOT NULL,'
				' failed_logins INTEGER NOT NULL DEFAULT 0,'
				' locked_until DATETIME,'
				' last_login DATETIME,'
				" password_changed_at DATETIME NOT NULL DEFAULT '2024-01-01 00:00:00',"
				" auth_source VARCHAR(16) NOT NULL DEFAULT 'local')"))
			connection.execute(sqlalchemy.text(
				"INSERT INTO users (username, password_hash, role) VALUES ('antigo', 'x', 'admin')"))
			commit = getattr(connection, 'commit', None)
			if commit is not None:
				commit()
		engine.dispose()

		models.init_db()
		session = models.get_session()
		try:
			with models._engine.connect() as connection:
				rows = connection.execute(sqlalchemy.text('PRAGMA table_info(users)')).fetchall()
			existing = {row[1] for row in rows}
			for column in ('mfa_secret', 'mfa_confirmed_at', 'mfa_last_counter'):
				self.assertIn(column, existing)
			# E a conta que já existia acorda devendo o segundo fator, que é o
			# que faz o requisito alcançar quem já estava dentro
			antigo = session.query(models.User).filter(models.User.username == 'antigo').first()
			self.assertIsNotNone(antigo)
			self.assertFalse(antigo.mfa_is_enrolled())
		finally:
			session.close()

	def test_rodar_a_migracao_duas_vezes_nao_quebra(self):
		models.init_db()
		models._engine = None
		models._SessionFactory = None
		models.init_db()
		session = models.get_session()
		try:
			self.assertEqual(0, session.query(models.User).count())
		finally:
			session.close()


if __name__ == '__main__':
	unittest.main()
