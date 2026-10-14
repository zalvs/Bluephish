"""Testes da troca da própria senha contra adivinhação (BP-SEC-06).

A troca da própria senha pede a senha atual, e é isso que a protege de quem
pegou uma sessão aberta — uma estação destravada, um XSS futuro. Mas errar a
senha atual não contava para nada: nem para o bloqueio da conta, nem para um
limite por minuto. Quem tinha a sessão testava senhas até acertar e saía com a
senha em texto, reaproveitável em qualquer outro serviço.

O que se prende aqui, um teste cada:

  * errar a senha atual conta na mesma régua do login (MAX_FAILED_LOGINS);
  * na última tentativa a conta trava e a sessão acaba — quem estava
    adivinhando não fica com uma sessão aberta numa conta travada;
  * a conta travada recusa até a senha certa, como no login;
  * a rota tem limite por minuto, como o login e o segundo fator;
  * acertar a senha atual continua trocando a senha normalmente;
  * o reset que um global_admin faz na senha de outra pessoa não é afetado.

Roda com:  python -m unittest test_password_change   (a partir do diretório app/)
"""

import unittest

import models
import test_mfa_gate
from test_mfa_gate import SENHA

NOVA = 'outra senha bem longa'
ERRADA = 'nao e a senha atual'


class Base(test_mfa_gate.Base):

	def change(self, current, new = NOVA):
		return self.client.post('/api/users/change_password',
			json = {'currentPassword': current, 'newPassword': new})

	def user(self, username = 'analista'):
		session = models.get_session()
		try:
			return session.query(models.User).filter(models.User.username == username).first()
		finally:
			session.close()


class Adivinhacao(Base):

	def test_errar_a_senha_atual_conta_como_tentativa(self):
		self.enrolled_user()
		self.assertEqual(400, self.change(ERRADA).status_code)
		self.assertEqual(1, self.user().failed_logins)

	def test_abaixo_do_limite_a_sessao_continua(self):
		self.enrolled_user()
		for _ in range(models.MAX_FAILED_LOGINS - 1):
			self.assertEqual(400, self.change(ERRADA).status_code)
		self.assertOpen()
		self.assertFalse(self.user().is_locked())

	def test_no_limite_a_conta_trava_e_a_sessao_acaba(self):
		self.enrolled_user()
		for _ in range(models.MAX_FAILED_LOGINS - 1):
			self.change(ERRADA)
		last = self.change(ERRADA)
		self.assertEqual(401, last.status_code)
		self.assertTrue(last.get_json().get('reauthenticate'))
		self.assertTrue(self.user().is_locked())
		self.assertBlocked()

	def test_conta_travada_recusa_ate_a_senha_certa(self):
		self.enrolled_user()
		for _ in range(models.MAX_FAILED_LOGINS):
			self.change(ERRADA)
		response = self.login()
		self.assertEqual(401, response.status_code)
		self.assertNotIn('mfaRequired', response.get_json())

	def test_a_senha_nao_muda_enquanto_se_adivinha(self):
		self.enrolled_user()
		for _ in range(models.MAX_FAILED_LOGINS):
			self.change(ERRADA)
		self.assertTrue(self.user().check_password(SENHA))


class TrocaLegitima(Base):

	def test_acertar_a_senha_atual_troca_a_senha(self):
		self.enrolled_user()
		self.change(ERRADA)
		response = self.change(SENHA)
		self.assertEqual(200, response.status_code)
		self.assertTrue(response.get_json()['reauthenticate'])
		self.assertTrue(self.user().check_password(NOVA))

	def test_reset_do_global_admin_nao_pede_nem_conta_senha_atual(self):
		self.create('alvo')
		self.enrolled_user('chefe', models.ROLE_GLOBAL_ADMIN)
		target = self.user('alvo')
		response = self.client.post('/api/users/change_password',
			json = {'userId': target.id, 'newPassword': NOVA})
		self.assertEqual(200, response.status_code)
		self.assertEqual(0, self.user('chefe').failed_logins or 0)
		self.assertTrue(self.user('alvo').check_password(NOVA))


class LimitePorMinuto(Base):
	"""Com o limitador ligado — build_app o desliga para os outros testes."""

	def setUp(self):
		super().setUp()
		limiters = self.app.extensions.get('limiter')
		limiters = limiters if isinstance(limiters, (set, list, tuple)) else [limiters]
		for limiter in limiters:
			limiter.enabled = True
			self.addCleanup(setattr, limiter, 'enabled', False)

	def test_a_rota_tem_limite_por_minuto(self):
		self.enrolled_user()
		# Uma senha nova que falha na política não chega a conferir a atual: são
		# tentativas que não travam a conta, e mesmo assim têm de parar no limite
		statuses = [self.client.post('/api/users/change_password',
			json = {'currentPassword': ERRADA, 'newPassword': 'curta'}).status_code for _ in range(8)]
		self.assertIn(429, statuses)


if __name__ == '__main__':
	unittest.main()
