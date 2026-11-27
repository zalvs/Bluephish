"""Testes da trava contra se trancar para fora (autolock).

Quem exclui a própria conta, ou rebaixa o próprio cargo, perde no mesmo clique o
acesso à tela que desfaria o erro. A trava do último global_admin não cobre o
caso de haver dois: um se rebaixava, e o outro podia estar de férias.

O que se prende aqui:

  * ninguém exclui a própria conta — nem um global_admin com outro ao lado;
  * ninguém muda o próprio cargo, nem para cima nem para baixo;
  * um global_admin continua excluindo e mudando o cargo de outra pessoa;
  * a recusa do próprio cargo fica na trilha de auditoria.

Roda com:  python -m unittest test_self_lockout   (a partir do diretório app/)
"""

import unittest

import models
import test_mfa_gate


class Base(test_mfa_gate.Base):

	def user(self, username):
		session = models.get_session()
		try:
			return session.query(models.User).filter(models.User.username == username).first()
		finally:
			session.close()

	def two_global_admins(self):
		"""O caso que a trava do último global_admin não cobre."""
		self.create('outro', models.ROLE_GLOBAL_ADMIN)
		self.enrolled_user('chefe', models.ROLE_GLOBAL_ADMIN)
		return self.user('chefe')


class PropriaConta(Base):

	def test_global_admin_nao_exclui_a_propria_conta(self):
		me = self.two_global_admins()
		response = self.client.delete('/api/users/{0}'.format(me.id))
		self.assertEqual(400, response.status_code)
		self.assertIsNotNone(self.user('chefe'))

	def test_global_admin_nao_rebaixa_o_proprio_cargo(self):
		me = self.two_global_admins()
		response = self.client.post('/api/users/{0}/role'.format(me.id), json = {'role': models.ROLE_ANALYST})
		self.assertEqual(400, response.status_code)
		self.assertEqual(models.ROLE_GLOBAL_ADMIN, self.user('chefe').role)

	def test_a_recusa_do_proprio_cargo_vai_para_a_auditoria(self):
		me = self.two_global_admins()
		self.client.post('/api/users/{0}/role'.format(me.id), json = {'role': models.ROLE_ADMIN})
		with open(test_mfa_gate.auth.AUDIT_LOG_PATH) as handle:
			trail = handle.read()
		self.assertIn('user_role_change', trail)
		self.assertIn('reason=self', trail)

	def test_reafirmar_o_proprio_cargo_tambem_e_recusado(self):
		# A regra é "não mexe no próprio cargo", não "não rebaixa": uma exceção
		# para o mesmo cargo seria um caminho a mais para manter certo
		me = self.two_global_admins()
		response = self.client.post('/api/users/{0}/role'.format(me.id), json = {'role': models.ROLE_GLOBAL_ADMIN})
		self.assertEqual(400, response.status_code)


class ContaDeOutraPessoa(Base):

	def test_global_admin_exclui_outra_conta(self):
		self.create('alvo')
		self.enrolled_user('chefe', models.ROLE_GLOBAL_ADMIN)
		target = self.user('alvo')
		self.assertEqual(200, self.client.delete('/api/users/{0}'.format(target.id)).status_code)
		self.assertIsNone(self.user('alvo'))

	def test_global_admin_muda_o_cargo_de_outra_conta(self):
		self.create('alvo')
		self.enrolled_user('chefe', models.ROLE_GLOBAL_ADMIN)
		target = self.user('alvo')
		response = self.client.post('/api/users/{0}/role'.format(target.id), json = {'role': models.ROLE_ADMIN})
		self.assertEqual(200, response.status_code)
		self.assertEqual(models.ROLE_ADMIN, self.user('alvo').role)

	def test_global_admin_rebaixa_outro_global_admin(self):
		self.two_global_admins()
		other = self.user('outro')
		response = self.client.post('/api/users/{0}/role'.format(other.id), json = {'role': models.ROLE_ANALYST})
		self.assertEqual(200, response.status_code)



class UltimoGlobalAdminLocal(Base):
	"""Com um global_admin de SSO ao lado, o último local ainda não sai.

	Se ele sai e o provedor de identidade cai, ninguém entra para consertar.
	"""

	def sso_global_admin_and_local_target(self):
		# O operador é de SSO, e o alvo é o único global_admin com senha
		models.create_user('local', 'senha-bem-comprida-1', models.ROLE_GLOBAL_ADMIN)
		self.enrolled_user('chefe', models.ROLE_GLOBAL_ADMIN)
		session = models.get_session()
		try:
			me = session.query(models.User).filter(models.User.username == 'chefe').first()
			me.auth_source = models.AUTH_SSO
			session.commit()
		finally:
			session.close()
		return self.user('local')

	def test_nao_exclui_o_ultimo_global_admin_local(self):
		target = self.sso_global_admin_and_local_target()
		response = self.client.delete('/api/users/{0}'.format(target.id))
		self.assertEqual(400, response.status_code)
		self.assertIsNotNone(self.user('local'))

	def test_nao_rebaixa_o_ultimo_global_admin_local(self):
		target = self.sso_global_admin_and_local_target()
		response = self.client.post('/api/users/{0}/role'.format(target.id), json = {'role': models.ROLE_ADMIN})
		self.assertEqual(400, response.status_code)
		self.assertEqual(models.ROLE_GLOBAL_ADMIN, self.user('local').role)

	def test_a_recusa_vai_para_a_auditoria(self):
		target = self.sso_global_admin_and_local_target()
		self.client.delete('/api/users/{0}'.format(target.id))
		with open(test_mfa_gate.auth.AUDIT_LOG_PATH) as handle:
			self.assertIn('reason=last_local_global_admin', handle.read())

	def test_havendo_outro_local_a_exclusao_vale(self):
		target = self.sso_global_admin_and_local_target()
		models.create_user('reserva', 'senha-bem-comprida-2', models.ROLE_GLOBAL_ADMIN)
		self.assertEqual(200, self.client.delete('/api/users/{0}'.format(target.id)).status_code)

	def test_o_sso_nao_rebaixa_o_ultimo_global_admin_local(self):
		models.create_user('dono@acme.com', 'senha-bem-comprida-3', models.ROLE_GLOBAL_ADMIN)
		models.sso_sign_in('outro@acme.com', models.ROLE_GLOBAL_ADMIN)
		_id, action = models.sso_sign_in('dono@acme.com', models.ROLE_ANALYST)
		self.assertEqual('signed_in', action)
		self.assertEqual(models.ROLE_GLOBAL_ADMIN, self.user('dono@acme.com').role)


if __name__ == '__main__':
	unittest.main()
