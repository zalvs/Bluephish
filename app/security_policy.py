"""Política de segurança configurável pela tela (Configurações → Segurança).

Hoje: o tempo de inatividade que desliga a sessão (auto logoff), o tempo máximo
de uma sessão, e com quanta antecedência o painel avisa que vai desligar. A
regra que usa esses números continua em `auth._session_violation`, num lugar só
para o HTTP e o websocket — este módulo só guarda e confere os números.

E a proteção contra abuso (`protection`): o limite de requisições por minuto
por IP, o banimento de IP depois de N falhas e a lista de IPs liberados dos
dois. Quem aplica é abuse_guard, chamado de auth._abuse_guard.

E o reCAPTCHA v3 do login (`captcha`): as duas chaves e a nota mínima. Quem
aplica é captcha.py, chamado de auth.api_login. O segredo nunca sai daqui para
o navegador — `captcha_view` é o que a tela recebe.

A configuração mora em `configuration.json`, na chave `security`, e só
global_admin a altera: alongar a sessão é afrouxar o controle que existe para
a pessoa que saiu da mesa, a mesma régua de SSO e da trilha de auditoria.

Quatro decisões que não são óbvias lendo o código:

1. **Há piso e teto, conferidos no servidor.** Inatividade de 5 a 240 minutos,
   sessão de 1 a 24 horas. Um número gravado à mão fora disso não é obedecido —
   vale o limite mais próximo —, e um global_admin comprometido não desliga o
   auto logoff pela tela.

2. **A sessão não pode ser mais curta que a inatividade.** Seria um limite de
   inatividade que nunca chega a valer; a validação recusa.

3. **Um arquivo ilegível não afrouxa nada.** JSON quebrado (uma vírgula a mais
   numa edição à mão, ou a leitura pegando o arquivo no meio de uma gravação —
   ver config_store) ou a seção com o formato errado (`"session": "x"`): vale a
   última configuração boa que este processo leu, e o erro vai para o log. Só
   sem nenhuma leitura boa antes vale o padrão. Cair no padrão em silêncio
   transformaria uma inatividade de 5 minutos em 30 sem ninguém saber.

4. **Lido do arquivo só quando ele muda.** `_session_violation` roda em toda
   requisição; reabrir o JSON em cada uma custaria caro, e guardar o valor só
   na memória deixaria uma edição à mão sem efeito até o próximo reinício. O
   mtime do arquivo decide quando reler.
"""

import ipaddress
import logging
import os
import re

import config_store

log = logging.getLogger('security_policy')

CONFIG_FILE = 'configuration.json'
CONFIG_KEY = 'security'

MIN_IDLE_MINUTES = 5
MAX_IDLE_MINUTES = 240
MIN_ABSOLUTE_HOURS = 1
MAX_ABSOLUTE_HOURS = 24
MIN_WARN_SECONDS = 30
MAX_WARN_SECONDS = 300

# Proteção contra abuso. O piso do limite por minuto é o que um painel aberto
# precisa para abrir sem tropeçar; o teto do banimento é uma semana
MIN_PER_MINUTE = 60
MAX_PER_MINUTE = 10000
MIN_MAX_FAILURES = 3
MAX_MAX_FAILURES = 100
MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1440
MIN_BAN_MINUTES = 1
MAX_BAN_MINUTES = 10080
MAX_ALLOWLIST = 100
# Uma rede maior que isto na lista de liberados é "desligar o banimento" com
# outro nome: 0.0.0.0/0 liberaria todo mundo
MIN_PREFIX = {4: 8, 6: 32}

# reCAPTCHA v3: a nota vai de 0 a 1. Abaixo de 0,1 o captcha não recusa ninguém;
# acima de 0,9 recusa gente
MIN_SCORE = 0.1
MAX_SCORE = 0.9
# As chaves do Google são 40 caracteres de [A-Za-z0-9_-]; a folga é para não
# recusar um formato novo que só mude o tamanho
_CAPTCHA_KEY = re.compile(r'[A-Za-z0-9_-]{20,100}')

DEFAULTS = {
	'session': {
		'idleMinutes': 30,
		'absoluteHours': 12,
		'warnSeconds': 60
	},
	'protection': {
		'rateLimit': {'enabled': True, 'perMinute': 1200},
		'ban': {'enabled': True, 'maxFailures': 10, 'windowMinutes': 10, 'banMinutes': 30},
		'allowlist': []
	},
	'captcha': {'enabled': False, 'siteKey': '', 'secret': '', 'minScore': 0.5}
}

# key: (caminho, mtime) da última leitura; config: o que vale para essa chave;
# good: a última configuração lida sem erro, que é o que vale enquanto o arquivo
# estiver ilegível
_cache = {'key': None, 'config': None, 'good': None}


class _BadShape(Exception):
	pass


def _section(value, name):
	if value is None:
		return {}
	if not isinstance(value, dict):
		raise _BadShape('{0} não é um objeto'.format(name))
	return value


def allowlist_entry(text):
	"""(entrada normalizada, erro) para uma linha da lista de liberados."""
	text = str(text or '').strip()
	try:
		network = ipaddress.ip_network(text, strict = False)
	except ValueError:
		return None, '"{0}" não é um endereço IP nem uma rede (CIDR).'.format(text[:60])
	if network.prefixlen < MIN_PREFIX[network.version]:
		return None, '"{0}" é uma rede grande demais: o mínimo é /{1}.'.format(text[:60], MIN_PREFIX[network.version])
	# Um endereço sozinho fica escrito como endereço, não como /32
	if network.num_addresses == 1:
		return str(network.network_address), None
	return str(network), None


def _normalize_allowlist(stored):
	if stored is None:
		return []
	if not isinstance(stored, list):
		raise _BadShape(CONFIG_KEY + '.protection.allowlist não é uma lista')
	entries = []
	for item in stored:
		entry, error = allowlist_entry(item)
		if error:
			# Uma linha estragada não derruba a lista inteira: as outras continuam
			# liberadas, e quem editou à mão fica sabendo pelo log
			log.error('lista de liberados: %s', error)
			continue
		if entry not in entries:
			entries.append(entry)
	return entries[:MAX_ALLOWLIST]


def _strict_bool(value, default):
	return value if isinstance(value, bool) else default


def _normalize_protection(stored):
	protection = _section(stored, CONFIG_KEY + '.protection')
	rate = _section(protection.get('rateLimit'), CONFIG_KEY + '.protection.rateLimit')
	ban = _section(protection.get('ban'), CONFIG_KEY + '.protection.ban')
	rate_defaults = DEFAULTS['protection']['rateLimit']
	ban_defaults = DEFAULTS['protection']['ban']
	return {
		'rateLimit': {
			'enabled': _strict_bool(rate.get('enabled'), rate_defaults['enabled']),
			'perMinute': config_store.clamp(rate.get('perMinute', rate_defaults['perMinute']),
				MIN_PER_MINUTE, MAX_PER_MINUTE, rate_defaults['perMinute'])
		},
		'ban': {
			'enabled': _strict_bool(ban.get('enabled'), ban_defaults['enabled']),
			'maxFailures': config_store.clamp(ban.get('maxFailures', ban_defaults['maxFailures']),
				MIN_MAX_FAILURES, MAX_MAX_FAILURES, ban_defaults['maxFailures']),
			'windowMinutes': config_store.clamp(ban.get('windowMinutes', ban_defaults['windowMinutes']),
				MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES, ban_defaults['windowMinutes']),
			'banMinutes': config_store.clamp(ban.get('banMinutes', ban_defaults['banMinutes']),
				MIN_BAN_MINUTES, MAX_BAN_MINUTES, ban_defaults['banMinutes'])
		},
		'allowlist': _normalize_allowlist(protection.get('allowlist'))
	}


def _score(value, default):
	try:
		number = float(value)
	except (TypeError, ValueError):
		return default
	if number != number:
		return default
	return round(min(max(number, MIN_SCORE), MAX_SCORE), 2)


def _key(value):
	value = str(value or '').strip() if isinstance(value, str) else ''
	return value if _CAPTCHA_KEY.fullmatch(value) else ''


def _normalize_captcha(stored):
	captcha = _section(stored, CONFIG_KEY + '.captcha')
	defaults = DEFAULTS['captcha']
	return {
		'enabled': _strict_bool(captcha.get('enabled'), defaults['enabled']),
		'siteKey': _key(captcha.get('siteKey')),
		'secret': _key(captcha.get('secret')),
		'minScore': _score(captcha.get('minScore', defaults['minScore']), defaults['minScore'])
	}


def _normalize(stored):
	"""A configuração dentro dos limites. Levanta _BadShape se o formato não é o esperado."""
	section = _section(stored, CONFIG_KEY)
	return {
		'session': _normalize_session(section),
		'protection': _normalize_protection(section.get('protection')),
		'captcha': _normalize_captcha(section.get('captcha'))
	}


def _normalize_session(section):
	session = _section(section.get('session'), CONFIG_KEY + '.session')
	defaults = DEFAULTS['session']
	idle = config_store.clamp(session.get('idleMinutes', defaults['idleMinutes']),
		MIN_IDLE_MINUTES, MAX_IDLE_MINUTES, defaults['idleMinutes'])
	absolute = config_store.clamp(session.get('absoluteHours', defaults['absoluteHours']),
		MIN_ABSOLUTE_HOURS, MAX_ABSOLUTE_HOURS, defaults['absoluteHours'])
	# Gravado à mão com a sessão mais curta que a inatividade: a sessão sobe até
	# cobrir a inatividade
	if absolute * 60 < idle:
		absolute = min(MAX_ABSOLUTE_HOURS, -(-idle // 60))
	warn = config_store.clamp(session.get('warnSeconds', defaults['warnSeconds']),
		MIN_WARN_SECONDS, MAX_WARN_SECONDS, defaults['warnSeconds'])
	warn = min(warn, idle * 60 // 2)
	return {'idleMinutes': idle, 'absoluteHours': absolute, 'warnSeconds': warn}


def _fallback():
	return _cache['good'] if _cache['good'] is not None else _normalize(None)


def load_config(path = None):
	path = path or CONFIG_FILE
	try:
		key = (path, os.stat(path).st_mtime_ns)
	except OSError:
		key = (path, None)
	if _cache['key'] == key:
		return _cache['config']
	try:
		if key[1] is None:
			raise config_store.ConfigUnreadable('o arquivo não existe')
		config = _normalize(config_store.read_section(path, CONFIG_KEY))
		_cache['good'] = config
	except (config_store.ConfigUnreadable, _BadShape, OSError) as error:
		config = _fallback()
		# Uma vez por versão do arquivo: o cache abaixo impede que cada requisição
		# repita a leitura e o aviso
		log.error('configuração de segurança ilegível em %s (%s); valendo %s', path, error,
			'a última lida' if _cache['good'] is not None else 'o padrão')
	_cache['key'] = key
	_cache['config'] = config
	return config


def session_limits(path = None):
	"""(inatividade em minutos, sessão em horas, aviso em segundos)."""
	session = load_config(path)['session']
	return session['idleMinutes'], session['absoluteHours'], session['warnSeconds']


def save_config(config, path = None):
	config_store.write_section(path or CONFIG_FILE, CONFIG_KEY, config)
	_cache['key'] = None


def _integer(form, name):
	try:
		return int(str(form.get(name) or '').strip())
	except ValueError:
		return None


def protection_policy(path = None):
	return load_config(path)['protection']


def validate(form):
	"""(seção session, erro) a partir do formulário. Os limites são conferidos aqui, não só na tela.

	Devolve só `{'session': ...}`: quem grava junta com o resto da configuração
	(`merged`), para salvar a sessão não apagar a proteção, e vice-versa.
	"""
	idle = _integer(form, 'idleMinutes')
	absolute = _integer(form, 'absoluteHours')
	warn = _integer(form, 'warnSeconds')
	if idle is None or absolute is None or warn is None:
		return None, 'Os três tempos precisam ser números inteiros.'
	if not MIN_IDLE_MINUTES <= idle <= MAX_IDLE_MINUTES:
		return None, 'A inatividade vai de {0} a {1} minutos.'.format(MIN_IDLE_MINUTES, MAX_IDLE_MINUTES)
	if not MIN_ABSOLUTE_HOURS <= absolute <= MAX_ABSOLUTE_HOURS:
		return None, 'A sessão vai de {0} a {1} horas.'.format(MIN_ABSOLUTE_HOURS, MAX_ABSOLUTE_HOURS)
	if absolute * 60 < idle:
		return None, 'A sessão não pode ser mais curta que o tempo de inatividade.'
	if not MIN_WARN_SECONDS <= warn <= MAX_WARN_SECONDS:
		return None, 'O aviso vai de {0} a {1} segundos.'.format(MIN_WARN_SECONDS, MAX_WARN_SECONDS)
	if warn > idle * 60 // 2:
		return None, 'O aviso não pode passar da metade do tempo de inatividade.'
	return {'session': {'idleMinutes': idle, 'absoluteHours': absolute, 'warnSeconds': warn}}, None


def _checkbox(form, name):
	return str(form.get(name) or '').strip().lower() in ('1', 'true', 'on')


def validate_protection(form):
	"""(seção protection, erro) a partir do formulário da tela."""
	per_minute = _integer(form, 'perMinute')
	max_failures = _integer(form, 'maxFailures')
	window = _integer(form, 'windowMinutes')
	ban_minutes = _integer(form, 'banMinutes')
	if None in (per_minute, max_failures, window, ban_minutes):
		return None, 'O limite por minuto e os números do banimento precisam ser inteiros.'
	if not MIN_PER_MINUTE <= per_minute <= MAX_PER_MINUTE:
		return None, 'O limite vai de {0} a {1} requisições por minuto.'.format(MIN_PER_MINUTE, MAX_PER_MINUTE)
	if not MIN_MAX_FAILURES <= max_failures <= MAX_MAX_FAILURES:
		return None, 'O banimento pede de {0} a {1} falhas.'.format(MIN_MAX_FAILURES, MAX_MAX_FAILURES)
	if not MIN_WINDOW_MINUTES <= window <= MAX_WINDOW_MINUTES:
		return None, 'A janela das falhas vai de {0} a {1} minutos.'.format(MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES)
	if not MIN_BAN_MINUTES <= ban_minutes <= MAX_BAN_MINUTES:
		return None, 'O banimento dura de {0} a {1} minutos.'.format(MIN_BAN_MINUTES, MAX_BAN_MINUTES)
	entries = []
	for line in str(form.get('allowlist') or '').replace(',', '\n').splitlines():
		if not line.strip():
			continue
		entry, error = allowlist_entry(line)
		if error:
			return None, error
		if entry not in entries:
			entries.append(entry)
	if len(entries) > MAX_ALLOWLIST:
		return None, 'A lista de liberados aceita até {0} entradas.'.format(MAX_ALLOWLIST)
	return {'protection': {
		'rateLimit': {'enabled': _checkbox(form, 'rateLimitEnabled'), 'perMinute': per_minute},
		'ban': {'enabled': _checkbox(form, 'banEnabled'), 'maxFailures': max_failures,
			'windowMinutes': window, 'banMinutes': ban_minutes},
		'allowlist': entries
	}}, None


def captcha_policy(path = None):
	return load_config(path)['captcha']


def captcha_view(config):
	"""O que a tela recebe do captcha: tudo menos o segredo."""
	captcha = config['captcha']
	return {'enabled': captcha['enabled'], 'siteKey': captcha['siteKey'], 'minScore': captcha['minScore'],
		'hasSecret': bool(captcha['secret'])}


def validate_captcha(form, stored):
	"""(seção captcha, erro). Segredo em branco mantém o gravado, como nas outras telas."""
	enabled = _checkbox(form, 'captchaEnabled')
	site_key = str(form.get('siteKey') or '').strip()
	secret = str(form.get('secret') or '').strip() or stored['secret']
	if site_key and not _CAPTCHA_KEY.fullmatch(site_key):
		return None, 'A chave do site não tem o formato de uma chave do reCAPTCHA.'
	if secret and not _CAPTCHA_KEY.fullmatch(secret):
		return None, 'A chave secreta não tem o formato de uma chave do reCAPTCHA.'
	try:
		score = float(str(form.get('minScore') or '').replace(',', '.'))
	except ValueError:
		return None, 'A nota mínima precisa ser um número.'
	if not MIN_SCORE <= score <= MAX_SCORE:
		return None, 'A nota mínima vai de {0} a {1}.'.format(MIN_SCORE, MAX_SCORE)
	if enabled and not (site_key and secret):
		return None, 'Para ligar o captcha, informe a chave do site e a chave secreta.'
	return {'captcha': {'enabled': enabled, 'siteKey': site_key, 'secret': secret, 'minScore': round(score, 2)}}, None


def captcha_summary(config):
	captcha = config['captcha']
	return 'captcha={0} nota_minima={1} chave_site={2} segredo={3}'.format(
		'ligado' if captcha['enabled'] else 'desligado', captcha['minScore'],
		captcha['siteKey'][:8] + '…' if captcha['siteKey'] else '-',
		'definido' if captcha['secret'] else 'ausente')


def merged(part, path = None):
	"""A configuração inteira, com `part` (uma ou mais seções validadas) por cima da atual."""
	config = dict(load_config(path))
	config.update(part)
	return config


def summary(config):
	session = config['session']
	return 'inatividade={0}min sessao={1}h aviso={2}s'.format(
		session['idleMinutes'], session['absoluteHours'], session['warnSeconds'])


def protection_summary(config):
	protection = config['protection']
	rate, ban = protection['rateLimit'], protection['ban']
	return 'limite={0} {1}/min banimento={2} {3} falhas em {4}min por {5}min liberados={6}'.format(
		'ligado' if rate['enabled'] else 'desligado', rate['perMinute'],
		'ligado' if ban['enabled'] else 'desligado', ban['maxFailures'], ban['windowMinutes'],
		ban['banMinutes'], len(protection['allowlist']))
