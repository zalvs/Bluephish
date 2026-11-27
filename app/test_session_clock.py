"""O cookie de sessão não cai quando o relógio recua alguns segundos.

Reproduz o que acontecia no Docker Desktop: o relógio da VM voltou 4,3 s, o cookie
assinado antes do salto ficou "no futuro" e o Flask passou a tratá-lo como
inválido — sessão vazia, 401, login de novo, nada na auditoria.

O relógio é controlado trocando `get_timestamp` do signer, que é de onde o
itsdangerous tira a hora tanto para assinar quanto para conferir.

Run with:  python -m unittest test_session_clock   (from the app/ directory)
"""

import unittest
from unittest import mock

import flask
import itsdangerous
from flask.sessions import SecureCookieSessionInterface

import session_clock

T0 = 1793370000


def make_app(interface):
	app = flask.Flask(__name__)
	app.config['SECRET_KEY'] = 'test-only-key'
	app.config['PERMANENT_SESSION_LIFETIME'] = 12 * 3600
	app.session_interface = interface

	@app.route('/set')
	def set_value():
		flask.session['user'] = 'analista'
		return 'ok'

	@app.route('/get')
	def get_value():
		return flask.session.get('user', 'ANONIMO')

	return app


def cookie_value(client, name):
	return client.get_cookie(name).value


def put_cookie(client, name, value):
	client.set_cookie(name, value)


class ClockTestCase(unittest.TestCase):
	def at(self, seconds):
		# Trocado no TimestampSigner, que o signer tolerante herda: vale para os dois
		return mock.patch.object(itsdangerous.TimestampSigner, 'get_timestamp', return_value = seconds)

	def signed_then_read(self, interface, read_at):
		app = make_app(interface)
		client = app.test_client()
		with self.at(T0):
			client.get('/set')
		with self.at(read_at):
			return client.get('/get').get_data(as_text = True)


class DefaultFlaskTest(ClockTestCase):
	def test_the_default_cookie_drops_the_session_when_the_clock_goes_back(self):
		# O defeito, documentado: é isto que mandava a pessoa para o login
		self.assertEqual(self.signed_then_read(SecureCookieSessionInterface(), T0 - 4), 'ANONIMO')


class SkewTolerantTest(ClockTestCase):
	def interface(self):
		return session_clock.SkewTolerantSessionInterface()

	def test_a_few_seconds_back_keeps_the_session(self):
		self.assertEqual(self.signed_then_read(self.interface(), T0 - 4), 'analista')

	def test_the_limit_of_tolerance_still_holds(self):
		limit = session_clock.MAX_BACKWARD_SECONDS
		self.assertEqual(self.signed_then_read(self.interface(), T0 - limit), 'analista')
		self.assertEqual(self.signed_then_read(self.interface(), T0 - limit - 1), 'ANONIMO')

	def test_max_age_still_expires_the_session(self):
		self.assertEqual(self.signed_then_read(self.interface(), T0 + 12 * 3600 - 1), 'analista')
		self.assertEqual(self.signed_then_read(self.interface(), T0 + 12 * 3600 + 1), 'ANONIMO')

	def test_a_tampered_cookie_is_still_refused(self):
		app = make_app(self.interface())
		client = app.test_client()
		with self.at(T0):
			client.get('/set')
			value = cookie_value(client, 'session')
			forged = value[:-2] + ('AA' if not value.endswith('AA') else 'BB')
			put_cookie(client, 'session', forged)
			self.assertEqual(client.get('/get').get_data(as_text = True), 'ANONIMO')

	def test_a_cookie_from_another_key_is_refused(self):
		other = make_app(self.interface())
		other.config['SECRET_KEY'] = 'another-key'
		other_client = other.test_client()
		with self.at(T0):
			other_client.get('/set')
			value = cookie_value(other_client, 'session')
		app = make_app(self.interface())
		client = app.test_client()
		put_cookie(client, 'session', value)
		with self.at(T0):
			self.assertEqual(client.get('/get').get_data(as_text = True), 'ANONIMO')

	def test_the_jump_is_logged_once_per_minute(self):
		session_clock._last_warning[0] = 0.0
		with self.assertLogs('session_clock', level = 'WARNING') as logs:
			self.signed_then_read(self.interface(), T0 - 4)
			self.signed_then_read(self.interface(), T0 - 4)
		self.assertEqual(len(logs.records), 1)


if __name__ == '__main__':
	unittest.main()
