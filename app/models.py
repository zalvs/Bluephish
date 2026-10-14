import os
import datetime
import secrets
import bcrypt
import sqlalchemy
from sqlalchemy import Boolean, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

import mfa

# The three roles, ordered from the least to the most privileged. The index in
# this list is the privilege level used by the RBAC decorators in auth.py
ROLE_ANALYST = 'analyst'
ROLE_ADMIN = 'admin'
ROLE_GLOBAL_ADMIN = 'global_admin'
ROLES = [ROLE_ANALYST, ROLE_ADMIN, ROLE_GLOBAL_ADMIN]

# De onde a conta se autentica. Uma conta 'sso' não tem senha utilizável: o
# hash guardado é de um valor aleatório que ninguém conhece, e o login por
# senha a recusa antes mesmo de conferir o hash (ver auth.api_login)
AUTH_LOCAL = 'local'
AUTH_SSO = 'sso'

# Account lockout policy
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

# Password policy: the minimum length is the only hard requirement, so that a
# long passphrase is accepted (NIST SP 800-63B discourages composition rules)
MIN_PASSWORD_LENGTH = 12

# The database lives next to the application. The directory is bind-mounted in
# the compose file so that users survive a container rebuild
DB_PATH = os.environ.get('THEPHISH_DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'thephish.db'))

Base = declarative_base()
_engine = None
_SessionFactory = None


class User(Base):
	__tablename__ = 'users'

	id = Column(Integer, primary_key = True)
	username = Column(String(64), unique = True, nullable = False, index = True)
	# bcrypt hash: the plaintext password is never stored, and bcrypt is
	# deliberately slow, so a leaked database cannot be cracked cheaply
	password_hash = Column(String(255), nullable = False)
	role = Column(String(32), nullable = False, default = ROLE_ANALYST)
	failed_logins = Column(Integer, nullable = False, default = 0)
	locked_until = Column(DateTime, nullable = True)
	last_login = Column(DateTime, nullable = True)
	# Bumped on every password change: the value is stored in the session, so
	# changing the password invalidates every session opened before it
	password_changed_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow)
	# 'local' (usuário e senha daqui) ou 'sso' (Entra ID). Uma instalação que já
	# existia não tem esta coluna, e init_db a acrescenta com 'local' — ver
	# _add_missing_columns
	auth_source = Column(String(16), nullable = False, default = AUTH_LOCAL, server_default = AUTH_LOCAL)

	# --- Segundo fator (TOTP) ---
	# O segredo compartilhado com o aplicativo autenticador, em base32. Diferente
	# da senha, ele *não* é um hash: TOTP é simétrico, e conferir um código exige
	# ter o mesmo segredo que gerou. Quem tem o arquivo do banco tem o segundo
	# fator de todo mundo, então o banco é o que precisa ser protegido — ele fica
	# no volume da aplicação, com o log de auditoria e a chave TLS.
	#
	# Cifrá-lo aqui só mudaria o problema de lugar: a chave teria de estar ao
	# alcance do mesmo processo que lê o banco, e a única chave que a instalação
	# já tem (THEPHISH_SECRET_KEY) é aleatória por processo quando não vem do
	# ambiente — o que apagaria o segundo fator de todo mundo a cada reinício.
	mfa_secret = Column(String(64), nullable = True)
	# Quando o primeiro código válido foi apresentado. Enquanto for nulo o
	# segredo é só uma proposta: existe no banco porque o QR precisou ser
	# desenhado, mas não vale como fator e não libera nada. É essa separação que
	# faz "abriu a tela de configuração e desistiu" não virar uma conta com MFA
	# que ninguém consegue usar
	mfa_confirmed_at = Column(DateTime, nullable = True)
	# O último passo de tempo aceito, contra repetição do mesmo código dentro da
	# janela de validade (ver mfa.verify)
	mfa_last_counter = Column(Integer, nullable = True)

	# --- Flask-Login interface ---
	@property
	def is_authenticated(self):
		return True

	@property
	def is_active(self):
		return True

	@property
	def is_anonymous(self):
		return False

	def get_id(self):
		return str(self.id)

	# --- Password handling ---
	def set_password(self, password):
		self.password_hash = hash_password(password)
		self.password_changed_at = datetime.datetime.utcnow()

	def check_password(self, password):
		return verify_password(password, self.password_hash)

	# --- Lockout handling ---
	def is_locked(self):
		return self.locked_until is not None and self.locked_until > datetime.datetime.utcnow()

	def register_failed_login(self):
		self.failed_logins = (self.failed_logins or 0) + 1
		if self.failed_logins >= MAX_FAILED_LOGINS:
			self.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes = LOCKOUT_MINUTES)
			self.failed_logins = 0
			return True
		return False

	def register_successful_login(self):
		self.failed_logins = 0
		self.locked_until = None
		self.last_login = datetime.datetime.utcnow()

	def is_sso(self):
		return self.auth_source == AUTH_SSO

	# --- Segundo fator ---
	# Configurado *e* provado. Um segredo sem confirmação não conta: ver o
	# comentário de mfa_confirmed_at
	def mfa_is_enrolled(self):
		return bool(self.mfa_secret) and self.mfa_confirmed_at is not None

	# Propõe um segredo novo e devolve. Sempre um segredo novo, mesmo quando já
	# havia um pendente: reabrir a tela de configuração tem de dar um QR que
	# funciona, e um segredo pendente pode ter sido lido por um telefone que a
	# pessoa não tem mais
	def start_mfa_enrollment(self):
		self.mfa_secret = mfa.new_secret()
		self.mfa_confirmed_at = None
		self.mfa_last_counter = None
		return self.mfa_secret

	def confirm_mfa(self, counter):
		self.mfa_confirmed_at = datetime.datetime.utcnow()
		self.mfa_last_counter = counter

	# Volta a conta ao estado de quem nunca configurou: o próximo login cobra a
	# configuração de novo. É o caminho de recuperação para telefone perdido ou
	# trocado, e por isso é privilégio de global_admin (ver auth.api_reset_mfa)
	def reset_mfa(self):
		self.mfa_secret = None
		self.mfa_confirmed_at = None
		self.mfa_last_counter = None

	# --- Role helpers ---
	def privilege_level(self):
		try:
			return ROLES.index(self.role)
		except ValueError:
			# An unknown role is treated as the least privileged one
			return 0

	def has_role_at_least(self, role):
		return self.privilege_level() >= ROLES.index(role)

	def to_dict(self):
		return {
			'id': self.id,
			'username': self.username,
			'role': self.role,
			'authSource': self.auth_source or AUTH_LOCAL,
			'mfaEnrolled': self.mfa_is_enrolled(),
			'mfaConfirmedAt': self.mfa_confirmed_at.strftime('%Y-%m-%d %H:%M:%S') if self.mfa_confirmed_at else None,
			'locked': self.is_locked(),
			'lockedUntil': self.locked_until.strftime('%Y-%m-%d %H:%M:%S') if self.locked_until else None,
			'lastLogin': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
		}


# Hash a password with bcrypt (never a plain SHA/MD5 digest, which is far too
# fast to resist offline cracking)
def hash_password(password):
	return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# Verify a password against its bcrypt hash. Returns False instead of raising
# when the stored hash is malformed
def verify_password(password, password_hash):
	try:
		return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
	except (ValueError, TypeError):
		return False


# Validate a password against the policy
# Returns None when the password is acceptable, or the reason why it is not
def validate_password(password):
	if password is None or len(password) < MIN_PASSWORD_LENGTH:
		return 'The password must be at least {0} characters long.'.format(MIN_PASSWORD_LENGTH)
	if len(password) > 200:
		return 'The password must be at most 200 characters long.'
	return None


# --- Whitelist: o que é runtime, e por que não mora no whitelist.json --------
#
# O arquivo guarda a declaração — o que quem administra escreveu. Estas três
# tabelas guardam o que acontece depois, e ficam aqui porque o caminho da
# análise escreve a cada e-mail: reescrever o JSON a cada análise atropelaria a
# edição que a interface acabou de salvar, e o v1 já perdia entrada por isso
# (load → mutate → save sem lock, thephish_app.py:1596)


class WhitelistRuleState(Base):
	"""Contadores e suspensão automática de uma regra."""

	__tablename__ = 'whitelist_rule_state'

	rule_id = Column(String(32), primary_key = True)
	match_count = Column(Integer, nullable = False, default = 0)
	# Quantas vezes a regra rebaixou um veredito que não era Safe. É o número que
	# importa: casar com e-mail limpo é o esperado, esconder veredito ruim não
	suppression_count = Column(Integer, nullable = False, default = 0)
	last_matched_at = Column(DateTime, nullable = True)
	suspended_at = Column(DateTime, nullable = True)
	suspended_reason = Column(String(255), nullable = True)


class WhitelistSuppression(Base):
	"""Um veredito que a regra escondeu — a linha do tempo que revela a conta comprometida.

	Um remetente confiável cujo conteúdo o pipeline continua achando malicioso é
	o perfil de conta tomada. Sem esta tabela o rebaixamento seria invisível, que
	é exatamente o que o bypass puro faria.
	"""

	__tablename__ = 'whitelist_suppression'

	id = Column(Integer, primary_key = True)
	rule_id = Column(String(32), nullable = False, index = True)
	occurred_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow, index = True)
	original_verdict = Column(String(16), nullable = False, default = '')
	message_from = Column(String(320), nullable = False, default = '')
	message_subject = Column(String(255), nullable = False, default = '')
	detail = Column(String(500), nullable = False, default = '')


class AnalysisHistory(Base):
	"""Registro enxuto de cada análise, mantido por uma janela curta.

	Existe para uma pergunta só: "esta regra que estou prestes a salvar teria
	afetado quantos e-mails?". Sem isso a simulação não tem contra o que rodar, e
	a entrada catastrófica só aparece depois de já estar valendo.

	Guarda o mínimo para reexecutar as regras: quem mandou, se o domínio estava
	autenticado, o veredito, e os observables distintos em JSON. Não guarda corpo,
	anexo nem o .eml — a retenção é curta e o conteúdo fica nos destinos de
	ticket, que é onde ele deve estar.
	"""

	__tablename__ = 'analysis_history'

	id = Column(Integer, primary_key = True)
	analyzed_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow, index = True)
	from_address = Column(String(320), nullable = False, default = '')
	from_domain = Column(String(255), nullable = False, default = '')
	reply_to = Column(String(320), nullable = False, default = '')
	subject = Column(String(255), nullable = False, default = '')
	authenticated = Column(Boolean, nullable = False, default = False)
	# O veredito que a análise produziu e o que saiu depois do whitelist. Iguais
	# quando nenhuma regra rebaixou
	verdict = Column(String(16), nullable = False, default = '')
	final_verdict = Column(String(16), nullable = False, default = '')
	downgraded_by = Column(String(32), nullable = True)
	# {"domain": [...], "url": [...], "hash": [...]}
	observables = Column(Text, nullable = False, default = '{}')


class CaseReclassification(Base):
	"""Uma decisão humana sobre o veredito de um e-mail já analisado.

	Só acrescenta, nunca edita: desfazer é uma linha nova com o veredito de volta,
	e a linha mais recente de um registro é a que vale. A linha do tempo inteira é
	o que responde "quem disse que isto era legítimo, quando e por quê" seis
	semanas depois, quando a mesma campanha voltar.

	O veredito original não é apagado em lugar nenhum: fica aqui em
	`previous_verdict` e nos destinos, ao lado da reclassificação.
	"""

	__tablename__ = 'case_reclassification'

	id = Column(Integer, primary_key = True)
	# A referência que a rota de detalhe aceita (número do caso no TheHive,
	# disk:pasta, jira:CHAVE)
	record_ref = Column(String(300), nullable = False, index = True)
	# O número do caso no TheHive que o registro carrega, quando carrega. É o que
	# faz a cópia em disco de um caso do TheHive seguir a reclassificação dele
	case_ref = Column(String(64), nullable = False, default = '', index = True)
	action = Column(String(16), nullable = False, default = 'reclassify')
	previous_verdict = Column(String(16), nullable = False, default = '')
	verdict = Column(String(16), nullable = False, default = '')
	reason = Column(Text, nullable = False, default = '')
	created_by = Column(String(64), nullable = False, default = '')
	created_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow, index = True)
	# [{"destination": "...", "ok": true, "detail": "..."}] — o que cada destino
	# respondeu quando a decisão foi escrita nele
	outcomes = Column(Text, nullable = False, default = '[]')


class AnalysisFingerprint(Base):
	"""A impressão digital de uma análise, para responder duas perguntas.

	A primeira é o **escopo**: quantas pessoas denunciaram este mesmo e-mail. Uma
	campanha chega como N denúncias separadas, cada uma virando o seu próprio
	registro num destino de ticket, e nada até aqui ligava as N. `content_key`
	liga. `body_key` liga o caso em que o assunto foi editado no encaminhamento e
	o corpo é o mesmo.

	A segunda é a **memória do veredito**: quando alguém reclassifica um e-mail
	como legítimo e escolhe valer para a mensagem idêntica, é `content_key` que a
	análise seguinte consulta.

	Não guarda corpo, anexo nem .eml — só os resumos. O conteúdo fica no
	`eml_store` e nos destinos, que é onde ele deve estar.
	"""

	__tablename__ = 'analysis_fingerprint'

	id = Column(Integer, primary_key = True)
	# A referência que a rota de detalhe aceita, igual à de CaseReclassification
	record_ref = Column(String(300), nullable = False, default = '', index = True)
	case_ref = Column(String(64), nullable = False, default = '', index = True)
	# sha256 de (assunto + remetente + corpo + hosts das URLs) normalizados
	content_key = Column(String(64), nullable = False, default = '', index = True)
	# sha256 só do corpo normalizado: o mesmo e-mail reencaminhado por várias
	# pessoas costuma chegar com o assunto prefixado de "ENC:"
	body_key = Column(String(64), nullable = False, default = '', index = True)
	# O From normalizado pelo mesmo normalize_address da whitelist
	sender_key = Column(String(320), nullable = False, default = '', index = True)
	subject = Column(String(255), nullable = False, default = '')
	# Quem denunciou. É o que a contagem de escopo conta como pessoa distinta, e
	# o destinatário da errata quando o veredito muda
	reporter = Column(String(320), nullable = False, default = '')
	verdict = Column(String(16), nullable = False, default = '')
	analyzed_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow, index = True)


class VerdictMemory(Base):
	"""A lição que uma reclassificação deixou para as análises seguintes.

	Duas regras, e as duas existem porque a assimetria é o ponto:

	  * **Só rebaixa, nunca condena.** `verdict` é sempre o alvo da
	    reclassificação, e hoje ele é sempre 'Safe'. Confirmar que algo é
	    malicioso não vira memória: daria a uma conta comprometida o poder de
	    negar correio legítimo em massa a partir de um clique.
	  * **O escopo 'sender' não rebaixa sozinho.** Ele vira proposta de regra de
	    whitelist, que passa pela exigência de domínio autenticado e pela
	    auto-suspensão que já existem. Rebaixar por remetente sem essas duas
	    travas é exatamente o buraco que elas fecham — e falharia em silêncio.

	Nada é apagado: revogar é preencher `revoked_at`, e a linha continua contando
	a história. `hits` e `last_hit_at` são o que permite a uma tela dizer quantas
	análises esta lição já poupou — e a uma auditoria ver uma memória que anda
	rebaixando demais.
	"""

	__tablename__ = 'verdict_memory'

	# 'content': casamento exato da mensagem, rebaixa sozinho.
	# 'sender': vira proposta de regra de whitelist, nunca rebaixa por si
	SCOPE_CONTENT = 'content'
	SCOPE_SENDER = 'sender'

	id = Column(Integer, primary_key = True)
	scope = Column(String(16), nullable = False, default = SCOPE_CONTENT, index = True)
	# content_key quando o escopo é 'content'; sender_key quando é 'sender'
	key = Column(String(320), nullable = False, default = '', index = True)
	verdict = Column(String(16), nullable = False, default = 'Safe')
	reason = Column(Text, nullable = False, default = '')
	created_by = Column(String(64), nullable = False, default = '')
	created_at = Column(DateTime, nullable = False, default = datetime.datetime.utcnow, index = True)
	# A reclassificação que gerou esta memória. Desfazer aquela decisão revoga
	# esta linha, e é por este campo que uma encontra a outra
	decision_id = Column(Integer, nullable = True, index = True)
	# O registro de onde a lição saiu, para a tela poder linkar de volta
	record_ref = Column(String(300), nullable = False, default = '')
	expires_at = Column(DateTime, nullable = True)
	revoked_at = Column(DateTime, nullable = True)
	revoked_by = Column(String(64), nullable = False, default = '')
	hits = Column(Integer, nullable = False, default = 0)
	last_hit_at = Column(DateTime, nullable = True)
	# Só para o escopo 'sender': 'pending' até um admin decidir, 'accepted' quando
	# virou regra de whitelist (e `whitelist_rule_id` diz qual), 'dismissed' quando
	# foi recusada. Vazio no escopo 'content', que não é proposta de nada
	proposal_status = Column(String(16), nullable = False, default = '')
	whitelist_rule_id = Column(String(32), nullable = False, default = '')


# create_all() cria a tabela que falta, mas nunca acrescenta coluna a uma tabela
# que já existe: numa instalação anterior ao SSO o banco tem `users` sem
# `auth_source`, e toda consulta passaria a citar uma coluna inexistente. Este é
# o passo de migração — declarativo, idempotente, e o lugar para o próximo
# ALTER quando houver um
NEW_COLUMNS = {
	'users': [
		('auth_source', "VARCHAR(16) NOT NULL DEFAULT '{0}'".format(AUTH_LOCAL)),
		# As três do segundo fator. Todas anuláveis, e é o que faz a migração ser
		# só um ALTER: toda conta que já existia acorda com mfa_secret nulo, ou
		# seja, "não configurou ainda" — que é exatamente o estado que o login
		# intercepta para exigir a configuração
		('mfa_secret', 'VARCHAR(64)'),
		('mfa_confirmed_at', 'DATETIME'),
		('mfa_last_counter', 'INTEGER')
	]
}


# A conexão é aberta explicitamente, e o commit só é chamado quando existe:
# `engine.execute()` some no SQLAlchemy 2, e o commit explícito não existe no 1.4
# não-future (que é o da imagem, onde o DDL já se auto-confirma). Assim o mesmo
# arquivo roda nas duas versões
def _add_missing_columns(engine):
	with engine.connect() as connection:
		for table, columns in NEW_COLUMNS.items():
			try:
				rows = connection.execute(sqlalchemy.text('PRAGMA table_info({0})'.format(table))).fetchall()
			except Exception:
				continue
			existing = {row[1] for row in rows}
			if not existing:
				# Tabela ainda não criada: create_all já a fez com tudo
				continue
			for name, definition in columns:
				if name in existing:
					continue
				connection.execute(sqlalchemy.text('ALTER TABLE {0} ADD COLUMN {1} {2}'.format(table, name, definition)))
				print('[INFO]_[models]: coluna {0}.{1} acrescentada ao banco existente'.format(table, name))
		commit = getattr(connection, 'commit', None)
		if commit is not None:
			commit()


def init_db():
	global _engine, _SessionFactory
	if _engine is None:
		db_dir = os.path.dirname(DB_PATH)
		if db_dir and not os.path.isdir(db_dir):
			os.makedirs(db_dir, exist_ok = True)
		_engine = sqlalchemy.create_engine('sqlite:///{0}'.format(DB_PATH), connect_args = {'check_same_thread': False})
		Base.metadata.create_all(_engine)
		_add_missing_columns(_engine)
		_SessionFactory = sessionmaker(bind = _engine)
	return _engine


def get_session():
	if _SessionFactory is None:
		init_db()
	return _SessionFactory()


# Create a user. Raises ValueError when the policy is not met or the username
# is already taken, so the caller (CLI or API) can report the reason
def create_user(username, password, role):
	username = (username or '').strip()
	if not username:
		raise ValueError('The username cannot be empty.')
	if len(username) > 64:
		raise ValueError('The username must be at most 64 characters long.')
	if role not in ROLES:
		raise ValueError('Unknown role: {0}. Valid roles: {1}'.format(role, ', '.join(ROLES)))
	policy_error = validate_password(password)
	if policy_error:
		raise ValueError(policy_error)
	session = get_session()
	try:
		if session.query(User).filter(User.username == username).first():
			raise ValueError('The user {0} already exists.'.format(username))
		user = User(username = username, role = role)
		user.set_password(password)
		session.add(user)
		session.commit()
		return user.id
	finally:
		session.close()


# Uma conta que só entra pelo provedor de identidade não tem senha. O campo é
# obrigatório no banco, então guarda o hash de um valor aleatório que ninguém —
# nem quem administra — jamais viu: qualquer senha tentada contra ela falha
def unusable_password_hash():
	return hash_password(secrets.token_urlsafe(32))


def sso_sign_in(username, role):
	"""Entra pelo provedor de identidade e devolve o id do usuário.

	O grupo no Entra ID é a fonte da verdade do cargo, então uma conta que já
	existe tem o cargo atualizado a cada entrada — é isso que faz a remoção de
	alguém de um grupo valer aqui sem ninguém precisar lembrar.

	Duas exceções, ambas para não transformar uma mudança de grupo em porta
	trancada: o último `global_admin` nunca é rebaixado (mesma regra da API de
	usuários), e uma conta local que entre por SSO continua local, de modo que a
	senha dela segue valendo se o provedor cair.
	"""
	username = (username or '').strip().lower()
	if not username:
		raise ValueError('O provedor de identidade não informou um nome de usuário.')
	if role not in ROLES:
		raise ValueError('Cargo desconhecido: {0}'.format(role))
	session = get_session()
	try:
		user = session.query(User).filter(User.username == username).first()
		if user is None:
			user = User(username = username, role = role, auth_source = AUTH_SSO,
				password_hash = unusable_password_hash())
			session.add(user)
			user.register_successful_login()
			session.commit()
			return user.id, 'created'
		demoting_last_global_admin = (
			user.role == ROLE_GLOBAL_ADMIN and role != ROLE_GLOBAL_ADMIN
			and session.query(User).filter(User.role == ROLE_GLOBAL_ADMIN).count() <= 1
		)
		changed = user.role != role and not demoting_last_global_admin
		if changed:
			user.role = role
		user.register_successful_login()
		session.commit()
		return user.id, 'role_changed' if changed else 'signed_in'
	finally:
		session.close()


def count_users():
	session = get_session()
	try:
		return session.query(User).count()
	finally:
		session.close()
