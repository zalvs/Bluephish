"""A inatividade da sessão conta gesto de uma pessoa, não requisição automática.

O painel faz requisições sozinho: o sinal de vida da aba a cada 30 s, a leitura da
configuração, o painel tático ao vivo. Se cada uma renovasse `last_seen`, a sessão
jamais ficaria inativa enquanto houvesse uma aba aberta — o limite de 30 minutos
estaria no código e não valeria para ninguém, e uma tela esquecida aberta numa
segunda aba manteria a sessão viva para sempre. O cookie é um só para todas as
abas, então a inatividade também é uma só: vencida, cai em todas.

Roda com:  python -m unittest test_session_activity   (a partir do diretório app/)
"""

import datetime
import unittest

import auth
import test_mfa_gate as gate

AUTOMATIC = {'X-Requested-With': 'XMLHttpRequest'}
HUMAN = {'X-Requested-With': 'XMLHttpRequest', 'X-User-Activity': '1'}


class Activity(gate.Base):

	def setUp(self):
		super().setUp()
		self.enrolled_user()
		self.minutes_ago(20)

	def minutes_ago(self, minutes):
		with self.client.session_transaction() as session:
			past = auth._utcnow() - datetime.timedelta(minutes = minutes)
			session['last_seen'] = past.strftime('%Y-%m-%d %H:%M:%S')
			self.before = session['last_seen']

	def last_seen(self):
		with self.client.session_transaction() as session:
			return session['last_seen']

	def test_an_automatic_request_does_not_renew_the_idle_clock(self):
		self.assertEqual(200, self.client.get('/api/list', headers = AUTOMATIC).status_code)
		self.assertEqual(self.before, self.last_seen())

	def test_an_automatic_request_still_keeps_the_tab_alive(self):
		sid = self.client.get('/api/list', headers = AUTOMATIC) and None
		with self.client.session_transaction() as session:
			sid = session['sid']
		auth._live_sessions[sid] = auth._utcnow() - datetime.timedelta(minutes = 4)
		self.client.get('/api/list', headers = AUTOMATIC)
		self.assertLess(auth._utcnow() - auth._live_sessions[sid], datetime.timedelta(seconds = 30))

	def test_a_request_flagged_as_human_renews_it(self):
		self.assertEqual(200, self.client.get('/api/list', headers = HUMAN).status_code)
		self.assertNotEqual(self.before, self.last_seen())

	def test_a_page_navigation_renews_it(self):
		# Navegação não passa por JavaScript: é sempre uma pessoa
		self.assertEqual(200, self.client.get('/list').status_code)
		self.assertNotEqual(self.before, self.last_seen())

	def test_only_automatic_requests_past_the_limit_end_the_session_everywhere(self):
		self.minutes_ago(31)
		self.assertEqual(401, self.client.get('/api/list', headers = AUTOMATIC).status_code)
		# O cookie é o mesmo em toda aba: o que uma viu, a outra vê
		self.assertEqual(401, self.client.get('/api/list', headers = HUMAN).status_code)

	def test_the_header_cannot_revive_a_session_already_past_the_limit(self):
		self.minutes_ago(31)
		self.assertEqual(401, self.client.get('/api/list', headers = HUMAN).status_code)


if __name__ == '__main__':
	unittest.main()
