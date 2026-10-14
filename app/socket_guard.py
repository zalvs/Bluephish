"""Quem entra no websocket, e por quanto tempo fica.

O `before_request` que aplica a política de sessão (auth.enforce_session_policy)
não roda no handshake do Socket.IO. E o cookie de sessão é assinado, não
revogável: a cópia de uma sessão já encerrada continua dizendo "autenticado".
O HTTP recusa essa cópia porque confere o registro de vida no servidor; um
handler de `connect` que só olhasse o cookie a deixaria entrar na sala da caixa
de denúncias — assuntos, remetentes e trechos de corpo a cada ciclo, sem prazo.

Então o websocket responde à mesma regra, em três pontos:

  * admit()      — o handshake passa pela política inteira da sessão (sem
                   renová-la) e pelo carimbo do segundo fator;
  * prune()      — cada socket guarda a sessão HTTP que o abriu, e quem teve a
                   sessão encerrada depois de conectar sai da sala;
  * log_target() — o `sid` que uma rota de análise recebe só vale se for de um
                   socket desta mesma sessão. Vazio ou alheio vira None, e o
                   WebSocketLogger descarta em vez de fazer broadcast.
"""

import logging

import flask
import flask_login

import auth

log = logging.getLogger('socket_guard')

# {sid do socket: sid da sessão HTTP que o abriu}. Em memória como o registro de
# vida em auth: o processo é um só, e um reinício derruba os dois juntos
owners = {}


def admit(socket_sid):
	"""True quando a sessão pode abrir este socket; registra o dono.

	Recusa anônimo, sessão que falha a política (inatividade, prazo absoluto,
	senha trocada, aba fechada, processo reiniciado) e sessão sem o segundo
	fator — exatamente o que o HTTP recusa.
	"""
	user = flask_login.current_user
	if not user or not user.is_authenticated:
		return False
	if not auth.session_policy_holds():
		return False
	if flask.session.get(auth.MFA_DONE) is not True:
		return False
	session_sid = flask.session.get('sid')
	if not session_sid:
		return False
	owners[socket_sid] = session_sid
	return True


def forget(socket_sid):
	owners.pop(socket_sid, None)


def prune(server, room, namespace = '/'):
	"""Tira da sala e desconecta todo socket cuja sessão HTTP morreu.

	Roda antes de cada envio para a sala, então um socket nunca recebe o que
	a sessão dele já não poderia pedir pelo HTTP. Devolve os sids podados.
	"""
	dead = [socket_sid for socket_sid, session_sid in list(owners.items())
		if not auth.session_is_live(session_sid)]
	for socket_sid in dead:
		owners.pop(socket_sid, None)
		# A saída da sala vem antes e à parte: é ela que garante que nada mais
		# chega, mesmo que o desconectar falhe
		try:
			server.leave_room(socket_sid, room, namespace = namespace)
		except Exception:
			log.warning('Could not remove socket {0} from {1}'.format(socket_sid, room), exc_info = True)
		try:
			server.disconnect(socket_sid, namespace = namespace)
		except Exception:
			log.warning('Could not disconnect socket {0}'.format(socket_sid), exc_info = True)
	if dead:
		log.info('Removed {0} socket(s) whose session had ended'.format(len(dead)))
	return dead


def log_target(requested_sid):
	"""O socket de quem fez a requisição, ou None.

	Só vale um sid que este processo conhece e que pertence à mesma sessão HTTP
	da requisição. None faz o WebSocketLogger descartar o log: a análise segue,
	só sem o acompanhamento ao vivo — nunca em broadcast, nunca na tela de outra
	pessoa.
	"""
	sid = str(requested_sid or '').strip()
	if sid and owners.get(sid) is not None and owners.get(sid) == flask.session.get('sid'):
		return sid
	return None
