"""Testes de quem entra no websocket, e de quanto tempo fica (BP-SEC-01, 02, 04).

O `before_request` que aplica a política de sessão não roda no handshake do
Socket.IO. Sem socket_guard, o handler de `connect` só perguntava se o cookie
dizia "autenticado" — e um cookie de sessão é assinado, não revogável: a cópia
de uma sessão já encerrada continua dizendo isso. O HTTP recusava essa cópia; o
websocket a deixava entrar na sala da caixa de denúncias.

O que se prende aqui, um teste cada:

  * socket anônimo é recusado no handshake, e não aceito para ouvir broadcast;
  * sessão encerrada (logout, aba fechada, processo reiniciado, inatividade)
    não abre socket, e um socket já aberto sai da sala quando ela morre;
  * conectar o socket não conta como sinal de vida da sessão;
  * o `sid` que as rotas de análise recebem só vale se for de um socket da
    mesma sessão — vazio ou alheio vira None, nunca broadcast;
  * WebSocketLogger sem destino não emite nada.

Como test_mfa_gate, a aplicação é mínima: importar thephish_app faz o monkey
patch do eventlet e arrasta módulos que só existem na imagem. Os handlers de
socket abaixo repetem, linha por linha, o que thephish_app registra.

Roda com:  python -m unittest test_socket_guard   (a partir do diretório app/)
"""

import datetime
import unittest

import flask
import flask_socketio

import auth
import socket_guard
import test_mfa_gate
from ws_logger import WebSocketLogger

ROOM = 'inbox-subscribers'

# Um navegador só: o cliente HTTP e o socket se apresentam com o mesmo
# User-Agent e o mesmo endereço, para que a proteção 'strong' do Flask-Login
# reconheça a mesma sessão nos dois — como acontece com um navegador de verdade
SAME_BROWSER = {'User-Agent': 'bluephish-teste', 'X-Forwarded-For': '127.0.0.1'}


def build_socket_app():
	application = test_mfa_gate.build_app()
	# Como em thephish_app: a sessão fica presa a IP e User-Agent. É por isso que
	# o socket de teste abaixo se apresenta como o cliente HTTP — um navegador
	# de verdade manda os mesmos dois no handshake
	application.login_manager.session_protection = 'strong'
	socketio = flask_socketio.SocketIO(application)

	@socketio.on('connect')
	def on_client_connected():
		if not socket_guard.admit(flask.request.sid):
			return False
		flask_socketio.join_room(ROOM)

	@socketio.on('disconnect')
	def on_client_disconnected():
		socket_guard.forget(flask.request.sid)

	@application.route('/api/log-target', methods = ['POST'])
	@auth.requires_analyst
	def log_target():
		return flask.jsonify({'target': socket_guard.log_target(flask.request.form.get('sid'))})

	return application, socketio


class Base(test_mfa_gate.Base):

	def setUp(self):
		super().setUp()
		socket_guard.owners.clear()
		self.app, self.socketio = build_socket_app()
		self.client = self.app.test_client()
		self.client.environ_base.update({
			'HTTP_USER_AGENT': SAME_BROWSER['User-Agent'],
			'HTTP_X_FORWARDED_FOR': SAME_BROWSER['X-Forwarded-For']
		})

	def tearDown(self):
		socket_guard.owners.clear()
		super().tearDown()

	def socket(self):
		return self.socketio.test_client(self.app, flask_test_client = self.client, headers = SAME_BROWSER)

	def signed_in(self):
		self.enrolled_user()
		self.assertOpen()


class Handshake(Base):

	def test_socket_anonimo_e_recusado(self):
		socket = self.socket()
		self.assertFalse(socket.is_connected())
		self.assertEqual({}, socket_guard.owners)

	def test_senha_certa_sem_segundo_fator_nao_abre_socket(self):
		self.create()
		self.login()
		self.assertFalse(self.socket().is_connected())

	def test_sessao_completa_abre_socket_e_registra_o_dono(self):
		self.signed_in()
		socket = self.socket()
		self.assertTrue(socket.is_connected())
		self.assertEqual(1, len(socket_guard.owners))

	def test_cookie_de_sessao_encerrada_nao_abre_socket(self):
		# O cenário do achado: o cookie foi copiado antes do logout. O HTTP o
		# recusa depois do logout; o websocket tem de recusar também
		self.signed_in()
		with self.client.session_transaction() as session:
			copied = dict(session)
		self.client.post('/api/auth/logout')
		with self.client.session_transaction() as session:
			session.update(copied)
		self.assertBlocked()
		with self.client.session_transaction() as session:
			session.update(copied)
		self.assertFalse(self.socket().is_connected())

	def test_processo_reiniciado_nao_abre_socket(self):
		self.signed_in()
		auth._live_sessions.clear()
		self.assertFalse(self.socket().is_connected())

	def test_sessao_inativa_alem_do_limite_nao_abre_socket(self):
		self.signed_in()
		stale = auth._utcnow() - auth.IDLE_TIMEOUT - datetime.timedelta(minutes = 1)
		with self.client.session_transaction() as session:
			session['last_seen'] = stale.strftime('%Y-%m-%d %H:%M:%S')
		self.assertFalse(self.socket().is_connected())

	def test_conectar_o_socket_nao_conta_como_sinal_de_vida(self):
		# Só o HTTP prova que a aba existe. Se o handshake renovasse o registro,
		# reconectar o socket de tempos em tempos manteria viva uma sessão cuja
		# aba já foi fechada
		self.signed_in()
		with self.client.session_transaction() as session:
			sid = session['sid']
		before = auth._utcnow() - datetime.timedelta(minutes = 2)
		auth._live_sessions[sid] = before
		self.assertTrue(self.socket().is_connected())
		self.assertEqual(before, auth._live_sessions[sid])


class Poda(Base):

	def test_socket_aberto_sai_quando_a_sessao_morre(self):
		self.signed_in()
		socket = self.socket()
		self.assertTrue(socket.is_connected())
		self.client.post('/api/auth/logout')
		pruned = socket_guard.prune(self.socketio.server, ROOM)
		self.assertEqual(1, len(pruned))
		self.assertEqual({}, socket_guard.owners)
		self.assertNotIn(pruned[0], self.socketio.server.manager.rooms.get('/', {}).get(ROOM, {}))

	def test_sessao_viva_nao_e_podada(self):
		self.signed_in()
		self.socket()
		self.assertEqual([], socket_guard.prune(self.socketio.server, ROOM))
		self.assertEqual(1, len(socket_guard.owners))

	def test_inatividade_derruba_o_registro_na_hora(self):
		# enforce_session_policy esquece a sessão em toda recusa, não só na da
		# aba fechada: é o que faz a poda seguinte pegar o socket sem esperar a
		# carência de TAB_GRACE
		self.signed_in()
		with self.client.session_transaction() as session:
			sid = session['sid']
			stale = auth._utcnow() - auth.IDLE_TIMEOUT - datetime.timedelta(minutes = 1)
			session['last_seen'] = stale.strftime('%Y-%m-%d %H:%M:%S')
		self.assertBlocked()
		self.assertNotIn(sid, auth._live_sessions)


class DestinoDoLog(Base):

	def target(self, sid):
		return self.client.post('/api/log-target', data = {'sid': sid}).get_json()['target']

	def test_sid_vazio_vira_none_e_nao_broadcast(self):
		self.signed_in()
		self.assertIsNone(self.target(''))

	def test_sid_desconhecido_vira_none(self):
		self.signed_in()
		self.assertIsNone(self.target('um-sid-inventado'))

	def test_sid_de_outra_sessao_vira_none(self):
		self.signed_in()
		socket_guard.owners['socket-alheio'] = 'sessao-alheia'
		self.assertIsNone(self.target('socket-alheio'))

	def test_sid_do_proprio_socket_vale(self):
		self.signed_in()
		self.socket()
		own = next(iter(socket_guard.owners))
		self.assertEqual(own, self.target(own))


class FakeSocketIO(object):

	def __init__(self):
		self.sent = []

	def emit(self, event, message, to = None, room = None):
		self.sent.append((event, message, to))


class Logger(unittest.TestCase):

	def test_sem_destino_nao_emite(self):
		for missing in (None, ''):
			socketio = FakeSocketIO()
			wsl = WebSocketLogger(socketio, missing)
			wsl.emit_info('assunto: fatura')
			wsl.emit_warning('aviso')
			wsl.emit_error('erro')
			self.assertEqual([], socketio.sent)

	def test_emite_para_o_socket_de_quem_pediu(self):
		socketio = FakeSocketIO()
		WebSocketLogger(socketio, 'abc').emit_info('oi')
		self.assertEqual([('logInfo', 'oi', 'abc')], socketio.sent)

	def test_sem_socket_cai_na_sala(self):
		socketio = FakeSocketIO()
		WebSocketLogger(socketio, None, room = ROOM).emit_error('falhou')
		self.assertEqual([('logError', 'falhou', ROOM)], socketio.sent)


if __name__ == '__main__':
	unittest.main()
