import os
import logging
import logging.handlers
import datetime
import functools
import secrets
import flask
import flask_login

import models
import mfa
import audit_store
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


# Client IP, honouring X-Forwarded-For only for its first entry (the value is
# attacker-controllable, so it is recorded as a hint, never used for decisions)
def client_ip():
	forwarded = flask.request.headers.get('X-Forwarded-For', '')
	if forwarded:
		return forwarded.split(',')[0].strip()[:45]
	return flask.request.remote_addr or '-'


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
		audit_log.info('event=%s status=%s ip=%s actor=%s target=%s detail=%s',
			*(_one_line(value) for value in (event, status, client_ip(), actor, username, detail)))
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


def _deny(status_code, message):
	if status_code == 401 and not _wants_json():
		return flask.redirect(flask.url_for('login_page', next = flask.request.path))
	return flask.jsonify({'error': message}), status_code


def requires_role(minimum_role):
	def decorator(view):
		@functools.wraps(view)
		def wrapper(*args, **kwargs):
			user = flask_login.current_user
			if not user or not user.is_authenticated:
				return _deny(401, 'Authentication required.')
			if not user.has_role_at_least(minimum_role):
				audit('authorization_denied', user.username, 'denied', 'path={0} required={1}'.format(flask.request.path, minimum_role))
				return _deny(403, 'Insufficient privileges.')
			return view(*args, **kwargs)
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
IDLE_TIMEOUT = datetime.timedelta(minutes = 30)
ABSOLUTE_TIMEOUT = datetime.timedelta(hours = 12)


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
	# Absolute lifetime: a session cannot live longer than ABSOLUTE_TIMEOUT even
	# if the user is continuously active
	if started_at is None or (now - started_at) > ABSOLUTE_TIMEOUT:
		return 'absolute'
	# Idle timeout
	if last_seen is None or (now - last_seen) > IDLE_TIMEOUT:
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
		return _deny(401, message)
	sid = flask.session.get('sid')
	_live_sessions[sid] = now
	flask.session['last_seen'] = now.strftime('%Y-%m-%d %H:%M:%S')
	return None


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
MFA_CHALLENGE_TTL = datetime.timedelta(minutes = 10)

# Carimbo da sessão que já passou pelo segundo fator
MFA_DONE = 'mfa_ok'
# O desafio em andamento
MFA_PENDING = 'mfa_pending'


def _start_mfa_challenge(user, source):
	"""Troca o primeiro fator provado por um desafio de segundo fator.

	A sessão é esvaziada antes: o que houvesse nela vinha de antes desta pessoa
	se identificar, e um desafio montado por cima de estado alheio é o começo de
	uma fixação de sessão.
	"""
	flask.session.clear()
	flask.session[MFA_PENDING] = {
		'user_id': user.id,
		'at': _utcnow().strftime('%Y-%m-%d %H:%M:%S'),
		'source': source
	}


def _challenge_user(db_session):
	"""O usuário do desafio em andamento, ou None.

	None cobre tudo que dá errado — sem desafio, desafio vencido, conta apagada
	entre o primeiro e o segundo fator — porque a resposta é a mesma nos três
	casos: começar de novo pela senha.
	"""
	pending = flask.session.get(MFA_PENDING)
	if not isinstance(pending, dict):
		return None
	started_at = _parse(pending.get('at'))
	if started_at is None or (_utcnow() - started_at) > MFA_CHALLENGE_TTL:
		flask.session.pop(MFA_PENDING, None)
		return None
	try:
		user = db_session.query(User).get(int(pending.get('user_id')))
	except (TypeError, ValueError):
		return None
	if user is None or user.is_locked():
		flask.session.pop(MFA_PENDING, None)
		return None
	return user


def _complete_login(db_session, user):
	"""Segundo fator conferido: agora, e só agora, a sessão existe."""
	user.register_successful_login()
	db_session.commit()
	flask.session.pop(MFA_PENDING, None)
	flask_login.login_user(user, remember = False)
	start_session(user)
	flask.session[MFA_DONE] = True


def _challenge_expired():
	return flask.jsonify({'error': 'A verificação expirou. Entre de novo.', 'restart': True}), 401


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
		if flask_login.current_user.is_authenticated:
			return flask.redirect(flask.url_for('homepage'))
		# O botão de SSO é renderizado pelo servidor, não revelado pelo script:
		# uma instalação sem provedor configurado não chega a ter o botão no HTML
		requested_error = flask.request.args.get('sso_error', '')
		# Um desafio de segundo fator em andamento faz a tela abrir já no passo
		# dele. É por aqui que o retorno do SSO chega: o provedor redireciona
		# para cá, e não para o painel, porque ainda falta um fator. O estágio
		# sai da conta, nunca da URL — um /login?stage=... deixaria qualquer um
		# escolher em que passo a tela abre
		stage = ''
		db_session = models.get_session()
		try:
			challenged = _challenge_user(db_session)
			if challenged is not None:
				stage = 'verify' if challenged.mfa_is_enrolled() else 'enroll'
		finally:
			db_session.close()
		return flask.render_template('login.html',
			sso_available = sso.is_available(sso.load_config()),
			sso_error = requested_error if requested_error in SSO_ERRORS else '',
			mfa_stage = stage,
			# Mesma regra do sso_error: um código fechado, nunca texto da URL
			session_ended = flask.request.args.get('reason', '') == 'tab')

	# Rate limited per IP to slow down online brute force. The account lockout
	# below is the per-account counterpart (an attacker rotating IPs still gets
	# locked out on the targeted account)
	@app.route('/api/auth/login', methods = ['POST'])
	@limiter.limit('5 per minute')
	def api_login():
		payload = flask.request.get_json(silent = True) or flask.request.form
		username = (payload.get('username') or '').strip()
		password = payload.get('password') or ''
		session = models.get_session()
		try:
			user = session.query(User).filter(User.username == username).first()
			# Conta que só existe por SSO não tem senha utilizável. A recusa é a
			# mesma mensagem genérica: dizer "esta conta entra por SSO" contaria
			# a quem estiver de fora quem é do tenant
			if user is not None and user.is_sso():
				audit('login', username, 'failure', 'reason=sso_account')
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			# Locked account: same generic answer, no hint that it is locked
			if user is not None and user.is_locked():
				audit('login', username, 'failure', 'reason=locked')
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			if user is None or not user.check_password(password):
				if user is not None:
					locked_now = user.register_failed_login()
					session.commit()
					audit('login', username, 'failure', 'reason=bad_password locked={0}'.format(locked_now))
				else:
					# Unknown user: nothing to update, but still audited
					audit('login', username, 'failure', 'reason=unknown_user')
				return flask.jsonify({'error': GENERIC_LOGIN_ERROR}), 401
			# Senha certa não é entrada: é metade dela. A contagem de falhas
			# *não* é zerada aqui de propósito — ela segue valendo através do
			# segundo fator, de modo que acertar a senha não dá a quem está
			# tentando um orçamento novo de tentativas para adivinhar o código.
			# Quem zera é _complete_login, depois dos dois fatores
			_start_mfa_challenge(user, 'local')
			enrolled = user.mfa_is_enrolled()
			audit('login', username, 'mfa_required', 'role={0} enrolled={1}'.format(user.role, enrolled))
			return flask.jsonify({'mfaRequired': True, 'mfaEnrolled': enrolled})
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
			return flask.jsonify({'error': 'Session ended, please sign in again.'}), 401
		touch_session()
		return flask.jsonify({'status': 'ok', 'intervalSeconds': TAB_HEARTBEAT_SECONDS})

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
				locked_now = user.register_failed_login()
				session.commit()
				audit('mfa_activate', user.username, 'failure', 'locked={0}'.format(locked_now))
				return flask.jsonify({'error': 'Código inválido. Confira o relógio do telefone e tente o próximo código.'}), 401
			user.confirm_mfa(counter)
			username = user.username
			role = user.role
			_complete_login(session, user)
			audit('mfa_activate', username, 'success')
			audit('login', username, 'success', 'role={0} mfa=activated'.format(role))
			return flask.jsonify({'username': username, 'role': role})
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
				locked_now = user.register_failed_login()
				session.commit()
				audit('mfa_verify', user.username, 'failure', 'locked={0}'.format(locked_now))
				return flask.jsonify({'error': 'Código inválido.'}), 401
			# Guardar o passo aceito é o que impede que o mesmo código volte a
			# valer enquanto a janela não fecha (ver mfa.verify)
			user.mfa_last_counter = counter
			username = user.username
			role = user.role
			_complete_login(session, user)
			audit('mfa_verify', username, 'success')
			audit('login', username, 'success', 'role={0} mfa=totp'.format(role))
			return flask.jsonify({'username': username, 'role': role})
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
		return flask.redirect(auth_uri)

	# Retorno do provedor. Tudo aqui é recusa por padrão: sem flow guardado, com
	# state divergente, sem grupo mapeado ou sem nome de usuário, ninguém entra
	@app.route(sso.REDIRECT_PATH, methods = ['GET'])
	@limiter.limit('10 per minute')
	def sso_callback():
		config = sso.load_config()
		flow = flask.session.pop('sso_flow', None)
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
			_start_mfa_challenge(user, 'sso')
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
			user.role = role
			session.commit()
			audit('user_role_change', user.username, 'success', 'role={0}'.format(role))
			return flask.jsonify(user.to_dict())
		finally:
			session.close()

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
