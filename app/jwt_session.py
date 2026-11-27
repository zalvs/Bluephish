"""A sessão do painel num JWT estrito, com revogação no servidor.

O cookie de sessão (`thephish_session`) deixa de ser o formato do itsdangerous e
passa a ser um JWT assinado com HS256 pela chave da aplicação (a do cofre,
secret_vault.app_secret). O conteúdo da sessão — o usuário do flask_login, o
token de CSRF, o desafio do segundo fator em andamento — vai dentro, numa claim
`sess`, serializado como o Flask sempre serializou (TaggedJSONSerializer), de
modo que nada do resto da aplicação muda.

"Estrito" quer dizer, e cada item tem teste (test_jwt_session):

* **Um algoritmo só.** HS256 e nada mais: `none`, HS512, RS256 — tudo recusado. É o
  ataque clássico a JWT, e o PyJWT só o evita com a lista de algoritmos explícita.
* **Emissor e público fixos** (`iss`, `aud`) e as claims `exp`, `iat`, `nbf`,
  `jti` e `sess` obrigatórias. Faltando uma, o token não vale.
* **Revogação no servidor pelo `jti`.** Numa sessão autenticada o `jti` é o
  `sid` que auth.start_session gera, e o `sid` é a chave do registro de vida
  (auth._live_sessions): sair, trocar a senha, fechar a aba, passar da
  inatividade ou reiniciar o processo tira o `sid` de lá, e a política de sessão
  recusa o token na requisição seguinte — o HTTP e o websocket, que passam pela
  mesma regra. Um token cujo `jti` não bate com o `sid` de dentro dele é recusado
  aqui mesmo: não dá para pôr a sessão de outro sob um `jti` ainda vivo.
* **O login gira o `jti`.** start_session gera um `sid` novo; o token anterior ao
  login (o da tela de senha) não vira o da sessão — fixação de sessão fechada.
* **O cookie continua HttpOnly, Secure e SameSite=Strict.** O JWT nunca vai para o
  JavaScript nem para um cabeçalho Authorization: guardado no navegador fora de
  cookie HttpOnly, um XSS levaria a sessão.

O relógio (§7.19): o Docker Desktop corrige a hora aos saltos para trás, e um
`iat` "do futuro" derrubaria a sessão em silêncio. As datas são conferidas aqui,
não pelo PyJWT, com a mesma tolerância de session_clock (MAX_BACKWARD_SECONDS
para trás, logado no máximo uma vez por minuto); o `exp` não tem folga.

O `exp` cobre a duração máxima da sessão que a aba Segurança configura (até 24 h),
ou as 12 h do Flask se forem maiores: quem decide o fim da sessão continua sendo
auth.enforce_session_policy, com os horários de dentro dela, e o token não pode
vencer antes.

O conteúdo do JWT é assinado, não cifrado — como era o cookie do Flask. Nada ali
é segredo de terceiros; o token de CSRF e o da aba só valem junto com o cookie.
"""

import logging
import secrets
import time

import jwt
from flask.json.tag import TaggedJSONSerializer
from flask.sessions import SessionInterface, SessionMixin
from werkzeug.datastructures import CallbackDict

import session_clock

log = logging.getLogger('jwt_session')

ALGORITHM = 'HS256'
ISSUER = 'bluephish'
AUDIENCE = 'bluephish-panel'
REQUIRED = ('exp', 'iat', 'nbf', 'jti', 'iss', 'aud', 'sess')
# Um cookie passa de 4 KB e o navegador o descarta sem avisar: melhor recusar
# aqui, com log, do que ver a sessão sumir no navegador. O limite de 4096 do
# navegador conta nome, valor e atributos; 3800 deixa folga para o resto
MAX_TOKEN_CHARS = 3800

ALLOWED_HEADER = frozenset(('alg', 'typ'))

_serializer = TaggedJSONSerializer()
_last_warning = [0.0]


def _now():
	return time.time()


class JwtSession(CallbackDict, SessionMixin):

	def __init__(self, initial = None, jti = None):
		def on_update(_self):
			_self.modified = True
		CallbackDict.__init__(self, initial, on_update)
		self.jti = jti
		self.modified = False


def _warn_skew(seconds):
	now = _now()
	if now - _last_warning[0] < session_clock.WARN_EVERY_SECONDS:
		return
	_last_warning[0] = now
	log.warning('token de sessão emitido %.1f s no futuro: o relógio recuou; aceito (tolerância de %s s)',
		seconds, session_clock.MAX_BACKWARD_SECONDS)


def decode(token, key):
	"""O conteúdo da sessão e o jti, ou (None, None) quando o token não vale."""
	if not token or not key or len(token) > MAX_TOKEN_CHARS:
		return None, None
	# Esta aplicação só emite {alg, typ}. Qualquer outro campo no cabeçalho (crit,
	# kid, jku, jwk, x5u) é token que não saiu daqui; recusar antes de verificar
	# fecha a classe de falhas do PyJWT 2.9 em torno deles (CVE-2026-32597 e afins),
	# cuja correção exige Python >= 3.9
	try:
		header = jwt.get_unverified_header(token)
	except jwt.InvalidTokenError:
		return None, None
	if not set(header) <= ALLOWED_HEADER:
		return None, None
	try:
		claims = jwt.decode(token, key, algorithms = [ALGORITHM], audience = AUDIENCE, issuer = ISSUER,
			options = {'require': list(REQUIRED), 'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
	except jwt.InvalidTokenError:
		return None, None
	now = _now()
	try:
		issued, not_before, expires = float(claims['iat']), float(claims['nbf']), float(claims['exp'])
	except (TypeError, ValueError):
		return None, None
	if expires <= now:
		return None, None
	ahead = max(issued, not_before) - now
	if ahead > session_clock.MAX_BACKWARD_SECONDS:
		return None, None
	if ahead > 0:
		_warn_skew(ahead)
	try:
		data = _serializer.loads(claims['sess'])
	except Exception:
		return None, None
	if not isinstance(data, dict):
		return None, None
	jti = claims['jti']
	# Sessão autenticada: o jti é o sid. Um token com o sid de uma sessão sob o
	# jti de outra é montagem, não emissão desta aplicação
	if data.get('sid') and data['sid'] != jti:
		return None, None
	return data, jti


def encode(data, key, lifetime_seconds, jti):
	now = int(_now())
	claims = {
		'iss': ISSUER,
		'aud': AUDIENCE,
		'iat': now,
		'nbf': now,
		'exp': now + int(lifetime_seconds),
		'jti': jti,
		'sess': _serializer.dumps(dict(data))
	}
	return jwt.encode(claims, key, algorithm = ALGORITHM)


def lifetime_seconds(app):
	# Pelo acessor de auth, que lê a política uma vez por requisição (flask.g):
	# esta é a mesma requisição que a política de sessão acabou de conferir
	import auth
	absolute = auth.session_limits()[1]
	return max(app.permanent_session_lifetime.total_seconds(), absolute.total_seconds())


class JwtSessionInterface(SessionInterface):

	def open_session(self, app, request):
		data, jti = decode(request.cookies.get(self.get_cookie_name(app)), app.secret_key)
		if data is None:
			return JwtSession()
		return JwtSession(data, jti)

	def save_session(self, app, session, response):
		name = self.get_cookie_name(app)
		domain = self.get_cookie_domain(app)
		path = self.get_cookie_path(app)
		if not session:
			if session.modified:
				response.delete_cookie(name, domain = domain, path = path,
					secure = self.get_cookie_secure(app), samesite = self.get_cookie_samesite(app))
			return
		if not self.should_set_cookie(app, session):
			return
		# O jti de uma sessão autenticada é o sid (revogável no servidor); antes do
		# login, um aleatório que não vale nada sozinho
		jti = session.get('sid') or session.jti or secrets.token_urlsafe(24)
		session.jti = jti
		token = encode(session, app.secret_key, lifetime_seconds(app), jti)
		if len(token) > MAX_TOKEN_CHARS:
			log.error('o token de sessão passou de %s caracteres (%s); a sessão não foi gravada', MAX_TOKEN_CHARS, len(token))
			return
		response.set_cookie(name, token, httponly = self.get_cookie_httponly(app), secure = self.get_cookie_secure(app),
			samesite = self.get_cookie_samesite(app), domain = domain, path = path)
		response.vary.add('Cookie')
