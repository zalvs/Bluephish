import os
import logging
import logging.handlers
import datetime
import json
import functools
import secrets
import time
import flask
import flask_login

import abuse_guard
import access_profiles
import captcha
import models
import mfa
import audit_store
import client_addr
import page_routes
import security_headers
import security_policy
import sso
from models import User, ROLE_ANALYST, ROLE_ADMIN, ROLE_GLOBAL_ADMIN, ROLES

# The login answer is deliberately identical for "unknown user", "wrong
# password" and "locked account": telling them apart would let an attacker
# enumerate valid usernames and discover which accounts they already locked
GENERIC_LOGIN_ERROR = 'Invalid username or password'

# Dedicated audit log, separate from the application log
AUDIT_LOG_PATH = os.environ.get('THEPHISH_AUDIT_LOG', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'auth.log'))

audit_log = logging.getLogger('thephish.audit')


# Configure the audit logger. Where it writes, for how long the files stay and
# whether a copy goes to a syslog server is audit_store's job and the global
# admin's decision (Configurações → Auditoria). It does not propagate to the
# root logger, so the audit trail stays in one place
def init_audit_log():
	if audit_log.handlers:
		return
	audit_store.apply(audit_log, AUDIT_LOG_PATH)


# Onde a trilha está sendo escrita agora — a pasta é configurável, então quem lê
# pergunta aqui em vez de montar o caminho a partir de AUDIT_LOG_PATH
def audit_log_path():
	return audit_store.current_path(AUDIT_LOG_PATH)


# O endereço de quem fez a requisição. X-Forwarded-For só é honrado quando o par
# é um proxy confiável (BLUEPHISH_TRUSTED_PROXIES) e, nesse caso, vale a entrada
# mais à direita que não é proxy — a primeira é a que o cliente escreveu. Segue
# sendo uma dica para a trilha e para o limitador, nunca base de autorização.
# A regra mora em client_addr.py, que não depende do Flask e tem teste próprio
def _resolve_client():
	return client_addr.resolve(
		flask.request.remote_addr,
		# Todas as linhas do cabeçalho: um proxy que acrescenta uma segunda linha em
		# vez de anexar à primeira não pode deixar a do cliente valendo sozinha
		','.join(flask.request.headers.getlist('X-Forwarded-For')),
		client_addr.configured_trusted())


def client_ip():
	return _resolve_client().ip


# --- Limite por IP e banimento (abuse_guard) ---------------------------------
# A regra mora em abuse_guard.py; aqui só se decide *qual* endereço contar. Não
# se conta o endereço que não é uma pessoa (gateway do Docker, proxy sem
# X-Forwarded-For) nem o que está na lista de liberados — ver abuse_guard.

_allowlist_cache = {'key': None, 'networks': []}

UNCOUNTED_ENDPOINTS = ('static', 'api_heartbeat')

# A CSP de toda resposta (thephish_app._security_headers). Mora aqui porque a
# tela de login é a única que a estende — com as origens do reCAPTCHA, e só
# quando ele está ligado (captcha.login_csp). Sem 'unsafe-inline' no script-src:
# ver BLUEPHISH_ARCHITECTURE.md §7.4
# A política mora em security_headers (um lugar só); o login a estende com o reCAPTCHA
BASE_CSP = security_headers.CONTENT_SECURITY_POLICY


def _allowlist_networks(entries):
	key = tuple(entries)
	if _allowlist_cache['key'] != key:
		_allowlist_cache['networks'] = abuse_guard.parse_allowlist(entries)
		_allowlist_cache['key'] = key
	return _allowlist_cache['networks']


def abuse_subject():
	"""(o IP a contar, a política). O IP é None quando o endereço não é contado."""
	resolved = _resolve_client()
	policy = security_policy.protection_policy()
	if not abuse_guard.countable(resolved, client_addr.configured_trusted()):
		return None, policy
	if abuse_guard.is_allowed(resolved.ip, _allowlist_networks(policy['allowlist'])):
		return None, policy
	return resolved.ip, policy


def address_allowed():
	"""Se o endereço desta requisição está na lista de liberados do abuse_guard."""
	policy = security_policy.protection_policy()
	return abuse_guard.is_allowed(_resolve_client().ip, _allowlist_networks(policy['allowlist']))


def captcha_required():
	"""A configuração do captcha quando este login precisa passar por ele; None quando não."""
	config = security_policy.captcha_policy()
	if not captcha.is_active(config) or address_allowed():
		return None
	return config


def address_status():
	"""O que a tela de Segurança mostra sobre o endereço de quem está olhando."""
	resolved = _resolve_client()
	policy = security_policy.protection_policy()
	return {
		'ip': resolved.ip,
		'countable': abuse_guard.countable(resolved, client_addr.configured_trusted()),
		'allowed': abuse_guard.is_allowed(resolved.ip, _allowlist_networks(policy['allowlist'])),
		# X-Forwarded-For chegou de um par que não está em BLUEPHISH_TRUSTED_PROXIES:
		# se esse par é o proxy da instalação, todo mundo tem o IP dele, e o
		# primeiro banimento tranca todos. Isentar quem manda o cabeçalho não é a
		# saída — o atacante o mandaria. A saída é a tela avisar
		'forwardedIgnored': bool(flask.request.headers.get('X-Forwarded-For')) and resolved.source == 'peer'
	}


def count_failure(kind):
	"""Uma falha de autenticação deste endereço, na conta do banimento."""
	ip, policy = abuse_subject()
	if ip is None:
		return
	if abuse_guard.record_failure(ip, kind, policy, time.time()):
		_audit_ban(ip, kind, policy)


def _audit_ban(ip, kind, policy):
	audit('ip_ban', '-', 'success', 'ip={0} motivo={1} minutos={2}'.format(ip, kind, policy['ban']['banMinutes']))


def address_refused():
	"""Se o endereço desta requisição está banido. Para o websocket, que não passa por before_request."""
	ip, policy = abuse_subject()
	if ip is None:
		return False
	return abuse_guard.check(ip, policy, time.time(), count_request = False).refused


def _abuse_refusal(verdict):
	if verdict.reason == 'limited':
		message = 'Requisições demais vindas deste endereço. Tente de novo em instantes.'
		status = 429
	else:
		message = ('Este endereço foi bloqueado temporariamente depois de falhas repetidas. '
			'Tente de novo em {0} minuto(s) ou peça a um global_admin para liberá-lo.').format(-(-verdict.retry_after // 60))
		status = 403
	if _wants_json():
		response = flask.jsonify({'error': message, 'banned': status == 403, 'retryAfter': verdict.retry_after})
	else:
		response = flask.Response(message, mimetype = 'text/plain')
	response.status_code = status
	response.headers['Retry-After'] = str(verdict.retry_after)
	return response


# Quando o par é o gateway da bridge do Docker e nenhum proxy confiável
# informou o cliente, 172.x.0.1 não é uma pessoa: o IP real se perdeu entre a
# porta publicada e este processo. A trilha diz isso em vez de exibir o gateway
# como se fosse o autor (ver BLUEPHISH_ARCHITECTURE.md, trilha de auditoria)
DOCKER_GATEWAY_NOTE = 'ip_origem=gateway-docker (IP real indisponivel)'


# Uma linha por registro, e só uma. O nome digitado num login que falhou vai
# para `target` como veio, e um "\n" dentro dele abria uma segunda linha no
# arquivo — um registro forjado, com data, evento e ator escolhidos por quem
# nem conta tem. A trilha agora é lida de volta pela tela de Auditoria
# (audit_trail.py), então o caractere de controle vira texto visível em vez de
# sumir: uma tentativa de forjar a trilha é coisa que ela mesma precisa mostrar
_CONTROL_CHARS = {code: '\\x{0:02x}'.format(code) for code in list(range(0, 32)) + [127]}
_CONTROL_CHARS.update({ord('\n'): '\\n', ord('\r'): '\\r', ord('\t'): '\\t'})


def _one_line(value):
	return str(value).translate(_CONTROL_CHARS)


# Write one audit record. Never raises: a broken audit sink must not take the
# application down, but the failure is surfaced on stdout
def audit(event, username = '-', status = '-', detail = ''):
	try:
		actor = '-'
		if flask_login.current_user and flask_login.current_user.is_authenticated:
			actor = '{0}({1})'.format(flask_login.current_user.username, flask_login.current_user.role)
		client = _resolve_client()
		if client.docker_gateway:
			detail = '{0} {1}'.format(detail, DOCKER_GATEWAY_NOTE).strip()
		audit_log.info('event=%s status=%s ip=%s actor=%s target=%s detail=%s',
			*(_one_line(value) for value in (event, status, client.ip, actor, username, detail)))
	except Exception as e:
		print("[ERROR]_[auth]: unable to write the audit log: {}".format(e))


# --- RBAC ------------------------------------------------------------------
# Every decorator answers with 401 when the caller is not authenticated and 403
# when it is authenticated but lacks the privilege level. Browser navigations
# are redirected to the login page instead of receiving a bare 401

def _wants_json():
	# XHR/fetch calls and the /api namespace get JSON, page loads get a redirect
	if flask.request.path.startswith('/api/'):
		return True
	if flask.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		return True
	accept = flask.request.headers.get('Accept', '')
	return 'application/json' in accept and 'text/html' not in accept


# O motivo de um fim de sessão, como a tela de login o entende (o `reason` de
# /login). Conjunto fechado: é o servidor quem sabe por que a sessão caiu, e a
# tela não adivinha — um palpite do relógio do painel diria "inatividade" a quem
# teve a sessão revogada por uma troca de senha
LOGIN_REASONS = {
	'idle': 'idle',
	'absolute': 'expired',
	'password_changed': 'password',
	'tab_closed': 'tab'
}


def _deny(status_code, message, reason = None):
	login_reason = LOGIN_REASONS.get(reason)
	if status_code == 401 and not _wants_json():
		return flask.redirect(flask.url_for('login_page', next = flask.request.path, reason = login_reason))
	body = {'error': message}
	if login_reason:
		body['reason'] = login_reason
	return flask.jsonify(body), status_code


def requires_role(minimum_role):
	def decorator(view):
		@functools.wraps(view)
		def wrapper(*args, **kwargs):
			user = flask_login.current_user
			if not user or not user.is_authenticated:
				return _deny(401, 'Authentication required.')
			# O perfil de acesso decide antes do cargo (access_profiles): a rota
			# que pertence a uma tela abre para quem tem a tela, com o cargo que
			# for; a que não pertence a nenhuma segue o cargo
			if not access_profiles.allows(user, flask.request.endpoint, minimum_role):
				audit('authorization_denied', user.username, 'denied', 'path={0} required={1}'.format(flask.request.path, minimum_role))
				return _deny(403, 'Insufficient privileges.')
			return view(*args, **kwargs)
		# Para test_access_profiles achar toda rota protegida
		wrapper.required_role = minimum_role
		return wrapper
	return decorator


# Any authenticated user (analyst and above): list emails, analyze, AI chat
requires_analyst = requires_role(ROLE_ANALYST)
# Configuration changes (email sync, LLM, integrations, whitelist, scheduler)
requires_admin = requires_role(ROLE_ADMIN)
# User management and global settings
requires_global_admin = requires_role(ROLE_GLOBAL_ADMIN)


# --- Session freshness ------------------------------------------------------
# Idle timeout, absolute timeout and password-change revocation are enforced on
# every request. The three markers live in the session cookie, which is signed,
# so a client cannot extend its own session by editing them
#
# Os dois prazos são configuráveis (Configurações → Segurança, global_admin) e
# lidos de security_policy. Não há constante com o valor deles: uma constante
# seria o padrão, não o que vale, e quem a lesse cobraria o prazo errado.


def session_limits():
	"""(inatividade, duração máxima, aviso em segundos) que valem agora.

	Lidos uma vez por requisição: a política de sessão, o sinal de vida e o
	cálculo do prazo perguntam na mesma requisição, e cada pergunta seria mais
	uma consulta ao arquivo.
	"""
	if flask.has_request_context() and '_session_limits' in flask.g:
		return flask.g._session_limits
	idle_minutes, absolute_hours, warn_seconds = security_policy.session_limits()
	limits = (datetime.timedelta(minutes = idle_minutes), datetime.timedelta(hours = absolute_hours), warn_seconds)
	if flask.has_request_context():
		flask.g._session_limits = limits
	return limits


def idle_timeout():
	return session_limits()[0]


def absolute_timeout():
	return session_limits()[1]


def session_deadline(now = None):
	"""(segundos que faltam, qual prazo vence primeiro: 'idle' ou 'absolute').

	A inatividade é uma só para todas as abas (o cookie é um só), então quem
	pergunta é o painel, ao servidor, a cada sinal de vida: um relógio próprio
	de cada aba avisaria na hora errada para quem está trabalhando em outra.

	Dizer *qual* prazo vence importa tanto quanto quanto falta: perto do fim da
	duração máxima, quem está trabalhando não está inativo, e "continuar
	conectado" não adia nada. O painel avisa diferente nos dois casos.
	"""
	now = now or _utcnow()
	last_seen = _parse(flask.session.get('last_seen'))
	started_at = _parse(flask.session.get('started_at'))
	if last_seen is None or started_at is None:
		return 0, 'idle'
	idle, absolute, _ = session_limits()
	idle_end = last_seen + idle
	absolute_end = started_at + absolute
	ends_by = 'absolute' if absolute_end <= idle_end else 'idle'
	left = min(idle_end, absolute_end) - now
	return int(max(0, left.total_seconds())), ends_by


# --- Sessão presa à aba ------------------------------------------------------
# Fechar a aba tem de encerrar a sessão. O cookie sozinho não sabe disso: ele é
# de sessão de *navegador*, sobrevive ao fechamento de uma aba e, com a restaura-
# ção de sessão que Chrome e Firefox fazem, sobrevive até ao fechamento do
# navegador. E o navegador não avisa ninguém quando a aba morre — `pagehide`
# dispara igual num F5, então tratá-lo como logout deslogaria a cada recarga.
#
# Então a prova de vida é ativa e tem dois lados, um servidor e um cliente:
#
#  1. Enquanto a aba existe ela bate ponto (`POST /api/auth/heartbeat`, e
#     qualquer outra requisição vale igual). O servidor guarda o instante do
#     último sinal por sessão; passado TAB_GRACE sem nenhum, a sessão está morta
#     e é revogada na requisição seguinte. Aba fechada para de bater ponto — e
#     processo reiniciado esvazia o registro, o que também revoga tudo. As duas
#     coisas falham fechado, que é o lado certo para falhar.
#
#  2. O token da aba vive no `sessionStorage`, que o navegador destrói junto com
#     a aba (o F5 preserva, e é o que separa recarga de fechamento). Ao abrir, o
#     painel devolve esse token; sem token nenhum a sessão é revogada na hora,
#     sem esperar a carência. É isto que faz "fechei e abri de novo" pedir
#     autenticação imediatamente em vez de daqui a alguns minutos.
#
# A carência é generosa de propósito: navegador estrangula timer de aba em
# segundo plano para um disparo por minuto, e uma carência curta deslogaria quem
# só deixou o painel atrás de outra janela. Quem fecha a aba é pego pelo item 2
# na hora, então o item 1 não precisa ser agressivo.
TAB_HEARTBEAT_SECONDS = 30
try:
	TAB_GRACE = datetime.timedelta(seconds = max(60, int(os.environ.get('BLUEPHISH_TAB_GRACE_SECONDS', '300'))))
except ValueError:
	TAB_GRACE = datetime.timedelta(seconds = 300)

# {session_id: último sinal de vida}. Em memória de propósito: o processo é um
# só (eventlet), e um registro que sobrevivesse ao reinício manteria viva uma
# sessão cuja aba pode ter sido fechada enquanto o servidor estava fora
_live_sessions = {}

# Cookie legível pelo JavaScript, com o token da aba, entregue uma única vez no
# login. O script o move para o sessionStorage e o apaga em seguida. Não é
# credencial: sem o cookie de sessão (esse sim HttpOnly) ele não abre nada
TAB_COOKIE_NAME = 'bluephish_tab'


def touch_session():
	sid = flask.session.get('sid')
	if sid:
		_live_sessions[sid] = _utcnow()


def _forget_session():
	sid = flask.session.get('sid')
	if sid:
		_live_sessions.pop(sid, None)


def _session_is_live(sid):
	last_seen = _live_sessions.get(sid)
	if last_seen is None:
		return False
	return (_utcnow() - last_seen) <= TAB_GRACE


def _utcnow():
	return datetime.datetime.utcnow()


def _parse(value):
	try:
		return datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
	except (TypeError, ValueError):
		return None


def session_is_live(sid):
	"""Se a sessão HTTP `sid` ainda dá sinal de vida. Para quem vive fora do
	ciclo de requisição — socket_guard poda por aqui os sockets de sessões mortas."""
	return _session_is_live(sid)


# Evento de auditoria e mensagem de cada motivo por que uma sessão deixa de valer
SESSION_VIOLATIONS = {
	'absolute': ('session_expired', 'Session expired, please sign in again.'),
	'idle': ('session_expired', 'Session expired, please sign in again.'),
	'password_changed': ('session_revoked', 'Session expired, please sign in again.'),
	'tab_closed': ('session_revoked', 'Session ended, please sign in again.')
}


def _session_violation(user, now):
	"""O motivo por que a sessão atual não vale mais, ou None. Só lê.

	É a regra inteira da sessão, num lugar só, para que o HTTP e o websocket
	(socket_guard) não tenham cada um a sua versão dela.
	"""
	started_at = _parse(flask.session.get('started_at'))
	last_seen = _parse(flask.session.get('last_seen'))
	idle, absolute, _ = session_limits()
	# Absolute lifetime: a session cannot live longer than the configured maximum
	# even if the user is continuously active
	if started_at is None or (now - started_at) > absolute:
		return 'absolute'
	# Idle timeout
	if last_seen is None or (now - last_seen) > idle:
		return 'idle'
	# Password-change revocation: the session records when the password was last
	# changed; a newer value in the database means the password changed after
	# this session was opened, so the session is no longer valid
	session_marker = flask.session.get('pwd_marker')
	current_marker = user.password_changed_at.strftime('%Y-%m-%d %H:%M:%S') if user.password_changed_at else ''
	if session_marker != current_marker:
		return 'password_changed'
	# Aba fechada: ninguém mais dá sinal de vida por esta sessão (ver o bloco
	# "Sessão presa à aba"). Vale também para sessão aberta antes de um reinício
	# do processo, cujo registro de vida se foi junto
	sid = flask.session.get('sid')
	if not sid or not _session_is_live(sid):
		return 'tab_closed'
	return None


def session_policy_holds():
	"""A sessão atual passa na política, sem renová-la nem encerrá-la.

	É a pergunta do handshake do websocket. Ele não renova a sessão de
	propósito: só o HTTP prova que a aba existe, e um handshake que contasse
	como sinal de vida deixaria um socket reconectando manter viva a sessão de
	uma aba já fechada.
	"""
	user = flask_login.current_user
	if not user or not user.is_authenticated:
		return False
	return _session_violation(user, _utcnow()) is None


def enforce_session_policy():
	user = flask_login.current_user
	if not user or not user.is_authenticated:
		return None
	now = _utcnow()
	reason = _session_violation(user, now)
	if reason is not None:
		event, message = SESSION_VIOLATIONS[reason]
		audit(event, user.username, reason)
		# Esquecida em toda recusa, não só na da aba fechada: o registro de vida
		# é o que socket_guard consulta, e uma sessão vencida que ficasse nele
		# manteria o websocket dela na sala até o fim da carência
		_forget_session()
		flask_login.logout_user()
		flask.session.clear()
		return _deny(401, message, reason)
	sid = flask.session.get('sid')
	_live_sessions[sid] = now
	if _counts_as_activity():
		flask.session['last_seen'] = now.strftime('%Y-%m-%d %H:%M:%S')
	return None


# Cabeçalho que o painel manda quando uma pessoa mexeu em *alguma* aba nos últimos
# instantes (ver "Atividade" em bluephish.js)
ACTIVITY_HEADER = 'X-User-Activity'


def _counts_as_activity():
	"""Se esta requisição prova que há uma pessoa do outro lado, e renova a inatividade.

	O limite de inatividade existe para a pessoa que saiu da mesa. O painel, porém,
	faz requisições sozinho — o sinal de vida da aba a cada 30 s, a leitura da
	configuração, o painel tático ao vivo — e se cada uma renovasse `last_seen`, a
	sessão nunca ficaria inativa enquanto houvesse uma aba aberta: o limite de 30
	minutos existiria no código e não valeria para ninguém. Então a requisição
	automática renova só o sinal de vida da aba (que decide se a aba foi fechada), e
	`last_seen` só anda quando o painel diz que houve gesto humano em alguma aba, ou
	quando é uma navegação de página — que não passa por JavaScript e é sempre uma
	pessoa. O cookie de sessão é um só para todas as abas, então a inatividade
	também é uma só: vencida, cai em todas.
	"""
	if flask.request.headers.get('X-Requested-With') != 'XMLHttpRequest':
		return True
	return flask.request.headers.get(ACTIVITY_HEADER) == '1'


def start_session(user):
	now = _utcnow()
	flask.session['started_at'] = now.strftime('%Y-%m-%d %H:%M:%S')
	flask.session['last_seen'] = now.strftime('%Y-%m-%d %H:%M:%S')
	flask.session['pwd_marker'] = user.password_changed_at.strftime('%Y-%m-%d %H:%M:%S') if user.password_changed_at else ''
	# Identidade desta sessão no registro de vida, e o token que a aba guarda no
	# sessionStorage e devolve a cada sinal
	sid = secrets.token_urlsafe(24)
	tab_token = secrets.token_urlsafe(24)
	flask.session['sid'] = sid
	flask.session['tab_token'] = tab_token
	_live_sessions[sid] = now
	# O cookie é entregue uma vez e apagado pelo script assim que ele o copia
	# para o sessionStorage. Curto porque só precisa sobreviver ao redirecionamento
	@flask.after_this_request
	def _hand_over_tab_token(response):
		response.set_cookie(TAB_COOKIE_NAME, tab_token, max_age = 120, secure = True,
			httponly = False, samesite = 'Strict')
		return response


# --- Segundo fator obrigatório ----------------------------------------------
# Ninguém entra só com usuário e senha. Nem quem acabou de ser criado, nem quem
# já tinha conta desde antes disto existir, nem quem entra pelo SSO corporativo.
#
# A forma como isso é imposto importa mais do que parece. O caminho óbvio seria
# deixar a sessão nascer no acerto da senha e barrar as telas depois, com um
# `before_request` — só que aí existe, por alguns instantes, uma sessão
# autenticada que ainda não provou o segundo fator, e ela vale exatamente o que
# a lista de exceções desse `before_request` deixar valer. Todo endpoint novo
# que alguém acrescentar passa a depender de lembrar dessa lista.
#
# Então a sessão não nasce. O acerto da senha (ou o retorno do provedor de
# identidade) abre um *desafio*: um registro na sessão assinada do navegador
# dizendo "esta pessoa provou o primeiro fator, e tem MFA_CHALLENGE_TTL para
# provar o segundo". Nada mais. `flask_login.login_user` só é chamado depois do
# código conferido, em _complete_login. Antes disso `current_user` é anônimo, e
# todo o resto da aplicação — as rotas com @requires_analyst, o `before_request`
# de sessão, até o handler de conexão do websocket — já recusa o anônimo sem
# precisar saber que MFA existe.
#
# O `before_request` continua existindo (enforce_mfa_policy, mais abaixo), mas
# como rede de proteção e não como a defesa: ele derruba qualquer sessão
# autenticada que não carimbe MFA_DONE. Hoje isso nunca acontece; se um dia
# alguém acrescentar um caminho de login que esqueça o segundo fator, a rede é o
# que transforma esse esquecimento numa porta fechada em vez de uma aberta.
#
# O desafio tem prazo e tem um número de tentativas, e os dois são cobrados
# por desafio — além, e não no lugar, do bloqueio da conta (MAX_FAILED_LOGINS,
# que segue contando cada código errado através de quantos desafios forem):
#
#   * **45 segundos para digitar o código** de quem já tem o aplicativo. Um
#     código TOTP vive 30 s; quem tem o telefone na mão digita em bem menos que
#     isso, e quem está adivinhando ganha só o que couber no prazo.
#   * **2 minutos para parear** o aplicativo pela primeira vez: ler o QR, abrir
#     o aplicativo, cadastrar a conta. Em 45 segundos isso não cabe, e quem não
#     termina recebe um segredo novo a cada recomeço.
#   * **3 códigos errados encerram o desafio** e mandam a pessoa de volta à
#     senha.
#
# O contador e o prazo moram no servidor (_mfa_challenges), não no cookie. A
# sessão do Flask é um cookie assinado que o próprio navegador guarda: um
# contador gravado nela seria rebobinado por quem reenviasse o cookie de antes
# do erro, e cada reenvio daria três tentativas novas. O cookie carrega só o
# identificador do desafio. Desafio que o servidor não conhece (já encerrado,
# vencido, ou o processo reiniciou) não vale: falha fechada, como o registro
# de abas (_live_sessions).
MFA_CODE_TTL = datetime.timedelta(seconds = 45)
MFA_ENROLL_TTL = datetime.timedelta(minutes = 2)
MFA_MAX_ATTEMPTS = 3

# Carimbo da sessão que já passou pelo segundo fator
MFA_DONE = 'mfa_ok'
# O desafio em andamento
MFA_PENDING = 'mfa_pending'

# Por que um desafio terminou sem sessão. Códigos fechados: é o que volta na
# resposta e na URL do /login, e a tela escolhe a frase pelo código, nunca o
# contrário
MFA_END_EXPIRED = 'mfa_expired'
MFA_END_ATTEMPTS = 'mfa_attempts'
MFA_END_CANCELLED = 'mfa_cancel'

# id do desafio -> {'user_id', 'started_at', 'attempts'}. Um desafio por conta:
# um login novo substitui o anterior, de modo que abrir vários desafios em
# paralelo não multiplica as tentativas
_mfa_challenges = {}


def _challenge_ttl(user):
	return MFA_CODE_TTL if user.mfa_is_enrolled() else MFA_ENROLL_TTL


def _prune_challenges(now):
	# O maior prazo vale para todos: um desafio de pareamento vencido também sai
	for challenge_id in [cid for cid, entry in _mfa_challenges.items()
			if now - entry['started_at'] > MFA_ENROLL_TTL]:
		_mfa_challenges.pop(challenge_id, None)


def _start_mfa_challenge(user, source, next_path = None):
	"""Troca o primeiro fator provado por um desafio de segundo fator.

	A sessão é esvaziada antes: o que houvesse nela vinha de antes desta pessoa
	se identificar, e um desafio montado por cima de estado alheio é o começo de
	uma fixação de sessão.

	`next_path` é a tela que a pessoa queria abrir quando o login a interrompeu.
	Ele mora dentro do desafio, e não solto na sessão, justamente porque o
	desafio é o que sobrevive à limpeza acima e ao retorno do provedor de
	identidade — e porque, vencido o desafio, o destino vai junto. Só chega aqui
	o que `page_routes.safe_next` já aceitou.
	"""
	now = _utcnow()
	_prune_challenges(now)
	for challenge_id in [cid for cid, entry in _mfa_challenges.items() if entry['user_id'] == user.id]:
		_mfa_challenges.pop(challenge_id, None)
	challenge_id = secrets.token_urlsafe(24)
	_mfa_challenges[challenge_id] = {'user_id': user.id, 'started_at': now, 'attempts': 0}
	flask.session.clear()
	flask.session[MFA_PENDING] = {
		'id': challenge_id,
		'user_id': user.id,
		'at': now.strftime('%Y-%m-%d %H:%M:%S'),
		'source': source,
		'next': next_path
	}


def _pending_challenge():
	"""O registro do servidor para o desafio deste navegador, ou None."""
	pending = flask.session.get(MFA_PENDING)
	if not isinstance(pending, dict):
		return None
	entry = _mfa_challenges.get(str(pending.get('id') or ''))
	if entry is None or entry['user_id'] != pending.get('user_id'):
		return None
	return entry


def _end_challenge():
	pending = flask.session.pop(MFA_PENDING, None)
	if isinstance(pending, dict):
		_mfa_challenges.pop(str(pending.get('id') or ''), None)


def _challenge_user(db_session):
	"""O usuário do desafio em andamento, ou None.

	None cobre tudo que dá errado — sem desafio, desafio que o servidor não
	conhece, prazo vencido, tentativas esgotadas, conta apagada ou bloqueada
	entre o primeiro e o segundo fator — porque a resposta é a mesma em todos
	os casos: começar de novo pela senha.
	"""
	entry = _pending_challenge()
	if entry is None:
		flask.session.pop(MFA_PENDING, None)
		return None
	try:
		user = db_session.query(User).get(int(entry['user_id']))
	except (TypeError, ValueError):
		user = None
	if (user is None or user.is_locked()
			or entry['attempts'] >= MFA_MAX_ATTEMPTS
			or _utcnow() - entry['started_at'] > _challenge_ttl(user)):
		_end_challenge()
		return None
	return user


def challenge_status(user):
	"""Quanto resta do desafio em andamento: o que a tela mostra na contagem.

	Só informa — quem decide é _challenge_user, no servidor, a cada código.
	"""
	entry = _pending_challenge()
	if entry is None:
		return {'expiresIn': 0, 'attemptsLeft': 0}
	elapsed = _utcnow() - entry['started_at']
	remaining = int(max(0, (_challenge_ttl(user) - elapsed).total_seconds()))
	return {'expiresIn': remaining, 'attemptsLeft': max(0, MFA_MAX_ATTEMPTS - entry['attempts'])}


def _wrong_code(db_session, user, step):
	"""Conta um código errado no desafio e na conta, e responde quando ele acaba.

	Na terceira tentativa do desafio, ou quando a conta acaba de bloquear, o
	desafio termina e a resposta manda a tela de volta à senha. A frase é a
	mesma nos dois casos: dizer "a conta bloqueou" contaria a quem está
	adivinhando que o bloqueio existe e quando ele começou. Devolve None quando
	ainda restam tentativas.
	"""
	locked_now = user.register_failed_login()
	db_session.commit()
	entry = _pending_challenge()
	if entry is not None:
		entry['attempts'] += 1
	attempts_left = max(0, MFA_MAX_ATTEMPTS - entry['attempts']) if entry is not None else 0
	audit(step, user.username, 'failure', 'locked={0} attempts_left={1}'.format(locked_now, attempts_left))
	count_failure(abuse_guard.KIND_MFA)
	if locked_now or attempts_left == 0:
		_end_challenge()
		return flask.jsonify({'error': 'Tentativas esgotadas. Entre de novo.',
			'restart': True, 'reason': MFA_END_ATTEMPTS}), 401
	return None


def _complete_login(db_session, user):
	"""Segundo fator conferido: agora, e só agora, a sessão existe.

	Devolve a página para onde a pessoa vai: a que ela pediu antes do login, ou a
	inicial. Validada de novo aqui, mesmo tendo sido na entrada — o que decide se
	um caminho é página é o mapa de rotas, e ele é o de agora, não o de dez
	minutos atrás.
	"""
	pending = flask.session.get(MFA_PENDING)
	next_path = page_routes.safe_next((pending or {}).get('next')) or '/'
	user.register_successful_login()
	db_session.commit()
	# Desafio usado não vale de novo: um cookie copiado antes do acerto não
	# reabre o segundo passo
	_end_challenge()
	flask_login.login_user(user, remember = False)
	start_session(user)
	flask.session[MFA_DONE] = True
	return next_path


def _challenge_expired():
	return flask.jsonify({'error': 'A verificação expirou. Entre de novo.', 'restart': True,
		'reason': MFA_END_EXPIRED}), 401


def enforce_mfa_policy():
	"""Rede de proteção: sessão autenticada sem segundo fator não existe.

	Roda depois de enforce_session_policy, em todo request. Ver o cabeçalho
	deste bloco para por que ela é a segunda linha de defesa e não a primeira.
	"""
	user = flask_login.current_user
	if not user or not user.is_authenticated:
		return None
	if flask.session.get(MFA_DONE) is True:
		return None
	# Uma sessão aberta antes deste deploy cai aqui: o cookie é válido e
	# assinado, mas nasceu num mundo sem segundo fator e não traz o carimbo.
	# Derrubá-la é o que faz o requisito valer para quem já estava dentro
	audit('mfa_gate', user.username, 'denied', 'path={0}'.format(flask.request.path))
	_forget_session()
	flask_login.logout_user()
	flask.session.clear()
	return _deny(401, 'Multi-factor authentication is required.')


# --- SSO --------------------------------------------------------------------

def base_url():
	"""A origem pública desta instalação, sem barra no fim.

	`request.url_root` é o que o próprio processo vê. Atrás de um proxy que
	termina o TLS isso vira `http://` numa porta interna, e o URI de
	redirecionamento precisa bater byte a byte com o que está registrado no
	Entra ID — daí o override por ambiente.
	"""
	configured = os.environ.get('BLUEPHISH_BASE_URL', '').strip()
	if configured:
		return configured.rstrip('/')
	return flask.request.url_root.rstrip('/')


def redirect_uri():
	return base_url() + sso.REDIRECT_PATH


# Motivos de recusa do SSO. A tela de login recebe o *código* e escolhe a frase
# a partir desta lista; o texto nunca viaja na URL. Duas razões: o que volta do
# provedor é conteúdo externo e não escreve na nossa tela, e um parâmetro que
# vira mensagem deixa qualquer um montar um /login?erro=... dizendo o que quiser
# numa página que pede senha
SSO_ERRORS = (
	'not_configured',   # ninguém configurou o provedor
	'provider',         # o Entra ID recusou, ou não deu para falar com ele
	'expired',          # o pedido guardado na sessão não existe mais
	'no_username',      # token sem UPN nem e-mail
	'group_overage',    # grupos demais: o token não trouxe a lista
	'no_group',         # a pessoa não está em nenhum grupo mapeado
	'provisioning'      # a conta não pôde ser criada ou atualizada
)


def _sso_failure(code):
	return flask.redirect(flask.url_for('login_page', sso_error = code if code in SSO_ERRORS else 'provider'))


# --- Blueprint --------------------------------------------------------------
auth_bp = flask.Blueprint('auth', __name__)


def register(app, login_manager, limiter):
	init_audit_log()
	models.init_db()

	# Antes de tudo, inclusive da política de sessão e das rotas de login: um
	# endereço banido não chega nem a tentar a senha. Registrado aqui, e não em
	# thephish_app, para valer também na aplicação que os testes montam
	@app.before_request
	def _abuse_guard():
		ip, policy = abuse_subject()
		if ip is None:
			return None
		# Não contam no limite: os arquivos estáticos (abrir o painel são uns
		# quinze de uma vez, e o navegador os guarda em cache) e o sinal de vida
		# da aba — recusado por um minuto, ele deixaria a sessão morrer como "aba
		# fechada" quando a carência é curta. O banimento vale para os dois igual
		verdict = abuse_guard.check(ip, policy, time.time(),
			count_request = flask.request.endpoint not in UNCOUNTED_ENDPOINTS)
		if not verdict.refused:
			return None
		if verdict.reason == 'banned_now':
			_audit_ban(ip, abuse_guard.KIND_RATE, policy)
		return _abuse_refusal(verdict)

	@login_manager.user_loader
	def load_user(user_id):
		session = models.get_session()
		try:
			return session.query(User).get(int(user_id))
		except (TypeError, ValueError):
			return None
		finally:
			session.close()

	@login_manager.unauthorized_handler
	def unauthorized():
		return _deny(401, 'Authentication required.')

	# The login view itself must stay reachable without authentication
	@app.route('/login', methods = ['GET'])
	def login_page():
		# `next` é a tela que a pessoa queria abrir quando caiu aqui (o `_deny`
		# o preenche com o caminho pedido). Só passa o que é página deste painel:
		# o que sai desta linha vai para um redirect e para um atributo do HTML, e
		# nenhum dos dois pode carregar um endereço escolhido por quem montou o link
		next_path = page_routes.safe_next(flask.request.args.get('next'))
		if flask_login.current_user.is_authenticated:
			return flask.redirect(next_path or flask.url_for('homepage'))
		# O botão de SSO é renderizado pelo servidor, não revelado pelo script:
		# uma instalação sem provedor configurado não chega a ter o botão no HTML
		requested_error = flask.request.args.get('sso_error', '')
		# Um desafio de segundo fator em andamento faz a tela abrir já no passo
		# dele. É por aqui que o retorno do SSO chega: o provedor redireciona
		# para cá, e não para o painel, porque ainda falta um fator. O estágio
		# sai da conta, nunca da URL — um /login?stage=... deixaria qualquer um
		# escolher em que passo a tela abre
		#
		# A tela que volta do segundo passo com um motivo (prazo, tentativas,
		# cancelar) encerra o desafio antes: sem isso, o desafio que ainda
		# tivesse meio segundo de vida reabriria o formulário do código, e o
		# "Cancelar" levaria de volta para o mesmo lugar de onde saiu
		reason = flask.request.args.get('reason', '')
		if reason in (MFA_END_EXPIRED, MFA_END_ATTEMPTS, MFA_END_CANCELLED):
			_end_challenge()
		stage = ''
		status = {'expiresIn': 0, 'attemptsLeft': 0}
		db_session = models.get_session()
		try:
			challenged = _challenge_user(db_session)
			if challenged is not None:
				stage = 'verify' if challenged.mfa_is_enrolled() else 'enroll'
				status = challenge_status(challenged)
		finally:
			db_session.close()
		captcha_config = captcha_required()
		page = flask.make_response(flask.render_template('login.html',
			captcha_site_key = captcha_config['siteKey'] if captcha_config else '',
			captcha_script = captcha.SCRIPT_URL,
			sso_available = sso.is_available(sso.load_config()),
			sso_error = requested_error if requested_error in SSO_ERRORS else '',
			next_path = next_path or '',
			mfa_stage = stage,
			mfa_expires_in = status['expiresIn'],
			mfa_attempts_left = status['attemptsLeft'],
			# Mesma regra do sso_error: um código fechado, nunca texto da URL
			session_ended = reason == 'tab',
			session_idle = reason == 'idle',
			session_expired = reason == 'expired',
			password_changed = reason == 'password',
			mfa_ended = reason if reason in (MFA_END_EXPIRED, MFA_END_ATTEMPTS) else ''))
		# Só esta resposta, e só com o captcha ligado: o painel segue com a CSP
		# de sempre (o after_request usa setdefault e não sobrescreve esta)
		if captcha_config:
			page.headers['Content-Security-Policy'] = captcha.login_csp(BASE_CSP)
		return page

	# Rate limited per IP to slow down online brute force. The account lockout
	# below is the per-account counterpart (an attacker rotating IPs still gets
	# locked out on the targeted account)
	@app.route('/api/auth/login', methods = ['POST'])
	@limiter.limit('5 per minute')
	def api_login():
		payload = flask.request.get_json(silent = True) or flask.request.form
		username = (payload.get('username') or '').strip()
		password = payload.get('password') or ''
		# Antes de olhar a senha: um robô não chega a saber se ela estava certa
		captcha_config = captcha_required()
		if captcha_config:
			passed, outcome, score = captcha.verify(captcha_config, payload.get('captchaToken'))
			if not passed:
				audit('login', username, 'failure', 'reason=captcha outcome={0} score={1}'.format(outcome, score))
				count_failure(abuse_guard.KIND_CAPTCHA)
				return flask.jsonify({'error': 'A verificação anti-robô não passou. Recarregue a página e tente de novo.',
					'captcha': True}), 401
			if outcome in (captcha.OUTCOME_UNAVAILABLE, captcha.OUTCOME_MISCONFIGURED):
				# Passou sem a verificação (captcha.py, decisão 2): fica dito na trilha
				audit('captcha', username, outcome)
		session = models.get_session()
		try:
			user = session.query(User).filter(User.username == username).first()
			# Conta que só existe por SSO não tem senha utilizável. A recusa é a
			# mesma mensagem genérica: dizer "esta conta entra por SSO" contaria
			# a quem estiver de fora quem é do tenant
			if user is not None and user.is_sso():
				audit('login', username, 'failure', 'reason=sso_account')
				count_failure(abuse_guard.KIND_LOGIN)
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			# Locked account: same generic answer, no hint that it is locked
			if user is not None and user.is_locked():
				audit('login', username, 'failure', 'reason=locked')
				count_failure(abuse_guard.KIND_LOGIN)
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			if user is None or not user.check_password(password):
				if user is not None:
					locked_now = user.register_failed_login()
					session.commit()
					audit('login', username, 'failure', 'reason=bad_password locked={0}'.format(locked_now))
				else:
					# Unknown user: nothing to update, but still audited
					audit('login', username, 'failure', 'reason=unknown_user')
				count_failure(abuse_guard.KIND_LOGIN)
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			# Senha certa não é entrada: é metade dela. A contagem de falhas
			# *não* é zerada aqui de propósito — ela segue valendo através do
			# segundo fator, de modo que acertar a senha não dá a quem está
			# tentando um orçamento novo de tentativas para adivinhar o código.
			# Quem zera é _complete_login, depois dos dois fatores
			_start_mfa_challenge(user, 'local', page_routes.safe_next(payload.get('next')))
			enrolled = user.mfa_is_enrolled()
			audit('login', username, 'mfa_required', 'role={0} enrolled={1}'.format(user.role, enrolled))
			body = {'mfaRequired': True, 'mfaEnrolled': enrolled}
			body.update(challenge_status(user))
			return flask.jsonify(body)
		finally:
			session.close()

	@app.route('/api/auth/logout', methods = ['POST'])
	def api_logout():
		username = flask_login.current_user.username if flask_login.current_user.is_authenticated else '-'
		audit('logout', username, 'success')
		_forget_session()
		flask_login.logout_user()
		flask.session.clear()
		return flask.jsonify({'status': 'ok'})

	# Sinal de vida da aba. Chega do painel a cada TAB_HEARTBEAT_SECONDS e carrega,
	# no cabeçalho, o token que a aba guarda no sessionStorage. Token ausente ou
	# diferente significa aba diferente da que abriu a sessão — normalmente porque
	# a original foi fechada e o navegador reabriu o endereço com o cookie ainda
	# no lugar. A sessão morre aqui, sem esperar a carência
	@app.route('/api/auth/heartbeat', methods = ['POST'])
	def api_heartbeat():
		user = flask_login.current_user
		if not user or not user.is_authenticated:
			return flask.jsonify({'error': 'Authentication required.'}), 401
		presented = flask.request.headers.get('X-Session-Tab', '')
		expected = flask.session.get('tab_token', '')
		if not presented or not expected or not secrets.compare_digest(str(presented), str(expected)):
			audit('session_revoked', user.username, 'tab_closed', 'reason=tab_token_mismatch')
			_forget_session()
			flask_login.logout_user()
			flask.session.clear()
			return flask.jsonify({'error': 'Session ended, please sign in again.', 'reason': LOGIN_REASONS['tab_closed']}), 401
		touch_session()
		# O sinal de vida só renova a inatividade quando carrega o gesto de uma
		# pessoa (enforce_session_policy já decidiu isso antes de chegar aqui).
		# A resposta diz quanto falta, e é por ela que o painel avisa antes de
		# desligar
		_, _, warn_seconds = session_limits()
		seconds_left, ends_by = session_deadline()
		# secondsLeft é o prazo que vence primeiro — a inatividade ou a duração
		# máxima, dito em endsBy. Só o primeiro se adia com um gesto
		return flask.jsonify({'status': 'ok', 'intervalSeconds': TAB_HEARTBEAT_SECONDS,
			'secondsLeft': seconds_left, 'endsBy': ends_by, 'warnSeconds': warn_seconds})

	# --- Segundo fator: os dois passos do desafio ---
	# As três rotas abaixo são as únicas que respondem a quem só provou a senha.
	# Todas partem de _challenge_user, ou seja: sem desafio válido na sessão,
	# nenhuma delas conta nada nem muda nada

	# Desenha o QR. O segredo é gravado como *proposta* (mfa_confirmed_at nulo):
	# ele ainda não vale como fator, e não vale até um código gerado por ele
	# voltar em /activate. Quem já configurou não passa por aqui — trocar um
	# segredo confirmado é reposição de credencial, e isso é ato de global_admin
	# (POST /api/users/<id>/mfa/reset)
	@app.route('/api/auth/mfa/setup', methods = ['POST'])
	@limiter.limit('10 per minute')
	def api_mfa_setup():
		session = models.get_session()
		try:
			user = _challenge_user(session)
			if user is None:
				return _challenge_expired()
			if user.mfa_is_enrolled():
				audit('mfa_setup', user.username, 'denied', 'reason=already_enrolled')
				return flask.jsonify({'error': 'Esta conta já tem o segundo fator configurado.'}), 409
			secret = user.start_mfa_enrollment()
			session.commit()
			audit('mfa_setup', user.username, 'success', 'source={0}'.format((flask.session.get(MFA_PENDING) or {}).get('source', '-')))
			uri = mfa.provisioning_uri(user.username, secret)
			# O segredo viaja porque a pessoa precisa dele para digitar à mão
			# quando a câmera não lê o QR. Vai no corpo de um POST, sobre a
			# sessão que provou a senha, e nunca numa URL
			return flask.jsonify({
				'secret': secret,
				'issuer': mfa.ISSUER,
				'account': user.username,
				'digits': mfa.DIGITS,
				'periodSeconds': mfa.PERIOD_SECONDS,
				'qr': mfa.qr_data_uri(uri)
			})
		finally:
			session.close()

	# Primeiro código do segredo proposto: é ele que transforma a proposta em
	# fator e, no mesmo movimento, abre a sessão. Provar que o aplicativo já
	# gera códigos certos *antes* de liberar o acesso é o que impede alguém de
	# terminar o cadastro com um segredo que nenhum telefone guardou
	@app.route('/api/auth/mfa/activate', methods = ['POST'])
	@limiter.limit('10 per minute')
	def api_mfa_activate():
		payload = flask.request.get_json(silent = True) or flask.request.form
		session = models.get_session()
		try:
			user = _challenge_user(session)
			if user is None:
				return _challenge_expired()
			if user.mfa_is_enrolled() or not user.mfa_secret:
				return flask.jsonify({'error': 'Não há uma configuração em andamento. Comece de novo.', 'restart': True}), 409
			ok, counter = mfa.verify(user.mfa_secret, payload.get('code'))
			if not ok:
				ended = _wrong_code(session, user, 'mfa_activate')
				if ended is not None:
					return ended
				body = {'error': 'Código inválido. Confira o relógio do telefone e tente o próximo código.'}
				body.update(challenge_status(user))
				return flask.jsonify(body), 401
			user.confirm_mfa(counter)
			username = user.username
			role = user.role
			next_path = _complete_login(session, user)
			audit('mfa_activate', username, 'success')
			audit('login', username, 'success', 'role={0} mfa=activated'.format(role))
			return flask.jsonify({'username': username, 'role': role, 'next': next_path})
		finally:
			session.close()

	# Código de quem já tem o segundo fator configurado
	@app.route('/api/auth/mfa/verify', methods = ['POST'])
	@limiter.limit('10 per minute')
	def api_mfa_verify():
		payload = flask.request.get_json(silent = True) or flask.request.form
		session = models.get_session()
		try:
			user = _challenge_user(session)
			if user is None:
				return _challenge_expired()
			if not user.mfa_is_enrolled():
				return flask.jsonify({'error': 'Esta conta ainda precisa configurar o segundo fator.', 'restart': True}), 409
			ok, counter = mfa.verify(user.mfa_secret, payload.get('code'), user.mfa_last_counter)
			if not ok:
				ended = _wrong_code(session, user, 'mfa_verify')
				if ended is not None:
					return ended
				body = {'error': 'Código inválido.'}
				body.update(challenge_status(user))
				return flask.jsonify(body), 401
			# Guardar o passo aceito é o que impede que o mesmo código volte a
			# valer enquanto a janela não fecha (ver mfa.verify)
			user.mfa_last_counter = counter
			username = user.username
			role = user.role
			next_path = _complete_login(session, user)
			audit('mfa_verify', username, 'success')
			audit('login', username, 'success', 'role={0} mfa=totp'.format(role))
			return flask.jsonify({'username': username, 'role': role, 'next': next_path})
		finally:
			session.close()

	# Identity of the caller, used by the interface to render the RBAC controls
	@app.route('/api/auth/me', methods = ['GET'])
	def api_me():
		user = flask_login.current_user
		if not user or not user.is_authenticated:
			return flask.jsonify({'authenticated': False}), 401
		return flask.jsonify({
			'authenticated': True,
			'id': user.id,
			'username': user.username,
			'role': user.role,
			'canManageUsers': user.has_role_at_least(ROLE_GLOBAL_ADMIN),
			'canChangeSettings': user.has_role_at_least(ROLE_ADMIN),
			# As telas, abas e ações que o perfil (ou o cargo) libera. O menu se
			# monta com isto; quem recusa o resto é o servidor
			'pages': access_profiles.visible(user),
			'profileId': user.profile_id,
			'mfaEnrolled': user.mfa_is_enrolled(),
			'mfaConfirmedAt': user.mfa_confirmed_at.strftime('%Y-%m-%d %H:%M:%S') if user.mfa_confirmed_at else None
		})

	# --- SSO corporativo (OpenID Connect / Microsoft Entra ID) ---
	# Início do fluxo. O `flow` (com state e code_verifier do PKCE) fica na sessão
	# assinada do navegador: é o que amarra o retorno a este pedido, e sem ele o
	# código que voltar do provedor não é aceito
	@app.route('/auth/sso/start', methods = ['GET'])
	@limiter.limit('10 per minute')
	def sso_start():
		config = sso.load_config()
		if not sso.is_available(config):
			audit('sso_login', status = 'failure', detail = 'reason=not_configured')
			return _sso_failure('not_configured')
		try:
			auth_uri, flow = sso.begin(config, redirect_uri())
		except Exception as e:
			audit('sso_login', status = 'failure', detail = 'reason=begin_failed')
			print('[ERROR]_[auth]: não foi possível iniciar o fluxo de SSO: {0}'.format(e))
			return _sso_failure('provider')
		flask.session['sso_flow'] = flow
		# Para onde a pessoa queria ir quando caiu na tela de login. Guardado na
		# sessão porque o provedor de identidade é uma viagem de ida e volta que
		# não devolve nada que não tenhamos mandado, e o retorno limpa a sessão
		# (_start_mfa_challenge) — o destino é recolhido no callback antes disso
		next_path = page_routes.safe_next(flask.request.args.get('next'))
		if next_path:
			flask.session['sso_next'] = next_path
		else:
			flask.session.pop('sso_next', None)
		return flask.redirect(auth_uri)

	# Retorno do provedor. Tudo aqui é recusa por padrão: sem flow guardado, com
	# state divergente, sem grupo mapeado ou sem nome de usuário, ninguém entra
	@app.route(sso.REDIRECT_PATH, methods = ['GET'])
	@limiter.limit('10 per minute')
	def sso_callback():
		config = sso.load_config()
		flow = flask.session.pop('sso_flow', None)
		# Recolhido já: qualquer recusa daqui para baixo não deixa um destino
		# esquecido na sessão, e o desafio abaixo o leva consigo
		next_path = flask.session.pop('sso_next', None)
		if not sso.is_available(config) or not flow:
			audit('sso_login', status = 'failure', detail = 'reason=no_flow')
			return _sso_failure('expired')
		claims, error = sso.complete(config, flow, flask.request.args.to_dict())
		if error:
			audit('sso_login', status = 'failure', detail = 'reason=token {0}'.format(error)[:200])
			return _sso_failure('provider')
		username = sso.username_from_claims(claims)
		if not username:
			audit('sso_login', status = 'failure', detail = 'reason=no_username')
			return _sso_failure('no_username')
		# Mais de ~200 grupos: o Entra ID manda um ponteiro em vez da lista, e
		# decidir cargo pelo que sobrou daria o cargo errado
		if sso.has_group_overage(claims):
			audit('sso_login', username, 'failure', 'reason=group_overage')
			return _sso_failure('group_overage')
		role = sso.role_for_claims(config, claims)
		if not role:
			audit('sso_login', username, 'denied', 'reason=no_mapped_group')
			return _sso_failure('no_group')
		try:
			user_id, action = models.sso_sign_in(username, role)
		except ValueError as e:
			audit('sso_login', username, 'failure', 'reason=provisioning {0}'.format(e)[:200])
			return _sso_failure('provisioning')
		session = models.get_session()
		try:
			user = session.query(User).get(user_id)
			# O provedor de identidade provou *um* fator, e é só isso que ele
			# prova aqui. O requisito não abre exceção por origem da conta, e
			# uma exceção para o SSO seria justamente a porta que a plataforma
			# não pode ter: quem tivesse o token do tenant entraria sem mais
			# nada. Então o retorno do Entra ID não leva ao painel — leva ao
			# mesmo desafio de segundo fator que o login por senha
			_start_mfa_challenge(user, 'sso', page_routes.safe_next(next_path))
			audit('sso_login', username, 'mfa_required', 'role={0} action={1} enrolled={2}'.format(
				user.role, action, user.mfa_is_enrolled()))
		finally:
			session.close()
		return flask.redirect(flask.url_for('login_page'))

	# --- User management (global_admin only) ---
	@app.route('/api/users', methods = ['GET'])
	@requires_global_admin
	def api_list_users():
		session = models.get_session()
		try:
			users = session.query(User).order_by(User.username).all()
			return flask.jsonify([u.to_dict() for u in users])
		finally:
			session.close()

	@app.route('/api/users', methods = ['POST'])
	@requires_global_admin
	def api_create_user():
		payload = flask.request.get_json(silent = True) or flask.request.form
		username = (payload.get('username') or '').strip()
		password = payload.get('password') or ''
		role = (payload.get('role') or ROLE_ANALYST).strip()
		try:
			user_id = models.create_user(username, password, role)
		except ValueError as e:
			audit('user_create', username, 'failure', str(e))
			return flask.jsonify({'error': str(e)}), 400
		audit('user_create', username, 'success', 'role={0} id={1}'.format(role, user_id))
		return flask.jsonify({'id': user_id, 'username': username, 'role': role})

	@app.route('/api/users/<int:user_id>', methods = ['DELETE'])
	@requires_global_admin
	def api_delete_user(user_id):
		if user_id == flask_login.current_user.id:
			return flask.jsonify({'error': 'You cannot delete your own account.'}), 400
		session = models.get_session()
		try:
			user = session.query(User).get(user_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			# Never leave the installation without a global admin
			if user.role == ROLE_GLOBAL_ADMIN and session.query(User).filter(User.role == ROLE_GLOBAL_ADMIN).count() <= 1:
				return flask.jsonify({'error': 'The last global_admin cannot be deleted.'}), 400
			# Nem a última que entra por senha: sem ela, o SSO fora do ar tranca todos
			if models.is_last_local_global_admin(session, user):
				audit('user_delete', user.username, 'denied', 'reason=last_local_global_admin')
				return flask.jsonify({'error': 'The last global_admin with a local password cannot be deleted: if SSO fails, nobody could sign in.'}), 400
			username = user.username
			session.delete(user)
			session.commit()
			audit('user_delete', username, 'success', 'id={0}'.format(user_id))
			return flask.jsonify({'status': 'ok'})
		finally:
			session.close()

	@app.route('/api/users/<int:user_id>/role', methods = ['POST'])
	@requires_global_admin
	def api_set_role(user_id):
		# Mesma regra da exclusão: quem rebaixa o próprio cargo perde, no mesmo
		# clique, o acesso a esta tela que desfaria o erro. A trava do último
		# global_admin não cobre o caso — havendo dois, um podia se rebaixar e
		# o outro estar de férias. Quem precisa mudar o próprio cargo pede a
		# outro global_admin
		if user_id == flask_login.current_user.id:
			audit('user_role_change', flask_login.current_user.username, 'denied', 'reason=self')
			return flask.jsonify({'error': 'You cannot change your own role.'}), 400
		payload = flask.request.get_json(silent = True) or flask.request.form
		role = (payload.get('role') or '').strip()
		if role not in ROLES:
			return flask.jsonify({'error': 'Unknown role.'}), 400
		session = models.get_session()
		try:
			user = session.query(User).get(user_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			# Do not allow demoting the last global admin
			if user.role == ROLE_GLOBAL_ADMIN and role != ROLE_GLOBAL_ADMIN and session.query(User).filter(User.role == ROLE_GLOBAL_ADMIN).count() <= 1:
				return flask.jsonify({'error': 'The last global_admin cannot be demoted.'}), 400
			if role != ROLE_GLOBAL_ADMIN and models.is_last_local_global_admin(session, user):
				audit('user_role_change', user.username, 'denied', 'reason=last_local_global_admin')
				return flask.jsonify({'error': 'The last global_admin with a local password cannot be demoted: if SSO fails, nobody could sign in.'}), 400
			user.role = role
			session.commit()
			audit('user_role_change', user.username, 'success', 'role={0}'.format(role))
			return flask.jsonify(user.to_dict())
		finally:
			session.close()

	# --- Perfis de acesso (global_admin only, access_profiles.py) ---
	# Quem distribui acesso precisa ter todo o acesso: estas rotas ficam no cargo
	# (access_profiles.ROLE_ONLY), e nenhum perfil as abre
	def _profiles_payload(db_session):
		counts = {}
		for user in db_session.query(User).all():
			if user.profile_id is not None:
				counts[user.profile_id] = counts.get(user.profile_id, 0) + 1
		profiles = db_session.query(models.AccessProfile).order_by(models.AccessProfile.name).all()
		return {
			'catalogue': list(access_profiles.CATALOGUE),
			'roleDefaults': {role: sorted(access_profiles.role_items(role)) for role in ROLES},
			'profiles': [access_profiles.profile_dict(profile, counts.get(profile.id, 0)) for profile in profiles]
		}

	def _profile_summary(items):
		return ','.join(items)[:400] or '-'

	@app.route('/api/profiles', methods = ['GET'])
	@requires_global_admin
	def api_list_profiles():
		db_session = models.get_session()
		try:
			return flask.jsonify(_profiles_payload(db_session))
		finally:
			db_session.close()

	def _save_profile(profile_id):
		payload = flask.request.get_json(silent = True) or flask.request.form
		name, description, items, error = access_profiles.validate(payload)
		if error:
			audit('profile_save', '-', 'refused', error[:200])
			return flask.jsonify({'error': error}), 400
		db_session = models.get_session()
		try:
			clash = db_session.query(models.AccessProfile).filter(models.AccessProfile.name == name).first()
			if clash is not None and clash.id != profile_id:
				return flask.jsonify({'error': 'Já existe um perfil com esse nome.'}), 400
			if profile_id is None:
				profile = models.AccessProfile(name = name)
				db_session.add(profile)
				before = '-'
			else:
				profile = db_session.query(models.AccessProfile).get(profile_id)
				if profile is None:
					return flask.jsonify({'error': 'Perfil não encontrado.'}), 404
				before = _profile_summary(sorted(access_profiles.parse_items(profile.items)))
			profile.name = name
			profile.description = description
			profile.items = json.dumps(items)
			profile.updated_at = datetime.datetime.utcnow()
			db_session.commit()
			audit('profile_save', name, 'success', 'id={0} antes: {1} | depois: {2}'.format(
				profile.id, before, _profile_summary(items)))
			return flask.jsonify(_profiles_payload(db_session))
		finally:
			db_session.close()

	@app.route('/api/profiles', methods = ['POST'])
	@requires_global_admin
	def api_create_profile():
		return _save_profile(None)

	@app.route('/api/profiles/<int:profile_id>', methods = ['POST'])
	@requires_global_admin
	def api_update_profile(profile_id):
		return _save_profile(profile_id)

	@app.route('/api/profiles/<int:profile_id>', methods = ['DELETE'])
	@requires_global_admin
	def api_delete_profile(profile_id):
		db_session = models.get_session()
		try:
			profile = db_session.query(models.AccessProfile).get(profile_id)
			if profile is None:
				return flask.jsonify({'error': 'Perfil não encontrado.'}), 404
			# Apagar um perfil em uso deixaria as contas dele sem tela nenhuma (o
			# perfil apagado não cai no cargo: access_profiles._profile_items)
			in_use = db_session.query(User).filter(User.profile_id == profile_id).count()
			if in_use:
				return flask.jsonify({'error': 'O perfil está em {0} conta(s). Troque o perfil delas antes de apagar.'.format(in_use)}), 400
			name = profile.name
			db_session.delete(profile)
			db_session.commit()
			audit('profile_delete', name, 'success', 'id={0}'.format(profile_id))
			return flask.jsonify(_profiles_payload(db_session))
		finally:
			db_session.close()

	@app.route('/api/users/<int:user_id>/profile', methods = ['POST'])
	@requires_global_admin
	def api_set_profile(user_id):
		payload = flask.request.get_json(silent = True) or flask.request.form
		raw = payload.get('profileId')
		db_session = models.get_session()
		try:
			user = db_session.query(User).get(user_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			profile = None
			if raw not in (None, '', 'null'):
				try:
					profile = db_session.query(models.AccessProfile).get(int(raw))
				except (TypeError, ValueError):
					profile = None
				if profile is None:
					return flask.jsonify({'error': 'Perfil não encontrado.'}), 400
			user.profile_id = profile.id if profile else None
			db_session.commit()
			audit('user_profile_change', user.username, 'success', 'perfil={0}'.format(profile.name if profile else 'cargo'))
			return flask.jsonify(user.to_dict())
		finally:
			db_session.close()

	# Telefone perdido, trocado, ou aplicativo apagado sem querer: o segredo some
	# junto e não há como recuperá-lo — é essa a natureza de um segredo que só
	# existe nos dois lados. Zerar o segundo fator devolve a conta ao estado de
	# quem nunca configurou, e o próximo login cobra a configuração de novo.
	#
	# É o mesmo caminho que a plataforma já usa para senha esquecida (um
	# global_admin repõe), e por isso a mesma régua de privilégio. Não existe
	# atalho por e-mail para cá de propósito: um "recupere seu MFA por e-mail"
	# devolve o segundo fator a quem tomou a caixa postal, e reduz os dois
	# fatores de volta a um — o mesmo motivo pelo qual e-mail e SMS não são
	# métodos aceitos aqui
	@app.route('/api/users/<int:user_id>/mfa/reset', methods = ['POST'])
	@requires_global_admin
	def api_reset_mfa(user_id):
		session = models.get_session()
		try:
			user = session.query(User).get(user_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			if not user.mfa_secret:
				return flask.jsonify({'error': 'Esta conta ainda não configurou o segundo fator.'}), 400
			user.reset_mfa()
			session.commit()
			audit('mfa_reset', user.username, 'success', 'id={0} by_admin=True'.format(user_id))
			return flask.jsonify(user.to_dict())
		finally:
			session.close()

	# Unlock an account locked by the failed-login policy
	@app.route('/api/users/<int:user_id>/unlock', methods = ['POST'])
	@requires_global_admin
	def api_unlock_user(user_id):
		session = models.get_session()
		try:
			user = session.query(User).get(user_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			user.failed_logins = 0
			user.locked_until = None
			session.commit()
			audit('user_unlock', user.username, 'success')
			return flask.jsonify(user.to_dict())
		finally:
			session.close()

	# Password change.
	# - a global_admin may reset any account without knowing the current password
	# - everybody else may only change their own password, and must prove it by
	#   supplying the current one
	# Limitada por minuto como o login e o segundo fator: é a única outra rota
	# que confere uma senha, e quem a chama já tem uma sessão — talvez alheia
	@app.route('/api/users/change_password', methods = ['POST'])
	@limiter.limit('5 per minute')
	@requires_analyst
	def api_change_password():
		payload = flask.request.get_json(silent = True) or flask.request.form
		actor = flask_login.current_user
		try:
			target_id = int(payload.get('userId') or actor.id)
		except (TypeError, ValueError):
			return flask.jsonify({'error': 'Invalid user id.'}), 400
		new_password = payload.get('newPassword') or ''
		current_password = payload.get('currentPassword') or ''
		is_global_admin = actor.has_role_at_least(ROLE_GLOBAL_ADMIN)
		if not is_global_admin and target_id != actor.id:
			audit('password_change', str(target_id), 'denied', 'reason=not_own_account')
			return flask.jsonify({'error': 'You can only change your own password.'}), 403
		policy_error = models.validate_password(new_password)
		if policy_error:
			return flask.jsonify({'error': policy_error}), 400
		session = models.get_session()
		try:
			user = session.query(User).get(target_id)
			if user is None:
				return flask.jsonify({'error': 'User not found.'}), 404
			# Conta que entra pelo Entra ID não tem senha: gravar uma aqui criaria
			# uma credencial que nada consome e que ninguém pensaria em revogar
			if user.is_sso():
				audit('password_change', user.username, 'denied', 'reason=sso_account')
				return flask.jsonify({'error': 'Esta conta entra pelo SSO corporativo e não tem senha. A troca é feita no provedor de identidade.'}), 400
			# The current password is always required unless a global_admin is
			# resetting somebody else's password
			if not (is_global_admin and target_id != actor.id):
				if not user.check_password(current_password):
					# Conta na mesma régua do login. Sem isto, quem pegou uma sessão
					# aberta testava a senha atual sem limite até acertar — e saía
					# com a senha em texto, reaproveitável fora daqui
					locked_now = user.register_failed_login()
					session.commit()
					audit('password_change', user.username, 'failure',
						'reason=bad_current_password locked={0}'.format(locked_now))
					count_failure(abuse_guard.KIND_PASSWORD)
					if locked_now:
						# Quem estava adivinhando não fica com uma sessão aberta
						# numa conta que acabou de travar
						_forget_session()
						flask_login.logout_user()
						flask.session.clear()
						return flask.jsonify({'error': 'Senha atual incorreta repetidas vezes: a conta foi '
							'bloqueada por {0} minutos e a sessão foi encerrada.'.format(models.LOCKOUT_MINUTES),
							'reauthenticate': True}), 401
					return flask.jsonify({'error': 'The current password is not correct.'}), 400
			user.set_password(new_password)
			session.commit()
			audit('password_change', user.username, 'success', 'by_admin={0}'.format(is_global_admin and target_id != actor.id))
			# Changing your own password revokes every session, including this
			# one: the client is told to sign in again
			if target_id == actor.id:
				_forget_session()
				flask_login.logout_user()
				flask.session.clear()
				return flask.jsonify({'status': 'ok', 'reauthenticate': True})
			return flask.jsonify({'status': 'ok', 'reauthenticate': False})
		finally:
			session.close()
