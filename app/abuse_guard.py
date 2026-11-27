"""Limite de requisições por IP e banimento temporário de IP (o "fail2ban" da aplicação).

Plain Python, sem Flask: a decisão é testada onde é escrita (test_abuse_guard.py).
Quem liga isto às requisições é auth.py (`_abuse_guard`, um `before_request`
registrado antes da política de sessão) e o handshake do websocket (socket_guard).
Os números vêm de security_policy (Configurações → Segurança).

Duas peças:

* **Limite por minuto, por IP, somando todas as rotas.** O Flask-Limiter já põe
  limites mais apertados no login, no segundo fator e na troca de senha; aqueles
  continuam valendo e não são afrouxados por nada daqui. Este é o teto geral de
  quem dispara requisições em massa contra a API. Ele não usa o `default_limits`
  do Flask-Limiter de propósito: aquele limite é por rota, e quem espalha as
  requisições por cinquenta rotas teria cinquenta vezes o teto.

* **Banimento depois de N falhas numa janela.** Conta senha errada, código do
  segundo fator errado, senha atual errada na troca de senha, login recusado pelo
  reCAPTCHA e cada minuto em que o IP estourou o limite acima. É o fail2ban, mas dentro da aplicação: ele vê a
  falha com o IP que client_addr resolveu, e não o IP do proxy que um fail2ban
  no host leria no log. O bloqueio por conta (models.MAX_FAILED_LOGINS) segue
  existindo — este é o complemento por endereço, contra quem testa senhas de
  muitas contas a partir do mesmo lugar.

Quatro decisões que não são óbvias lendo o código:

1. **Um endereço que não é uma pessoa nunca é contado nem banido.** O gateway da
   bridge do Docker (172.x.0.1, quando o IP real se perdeu na porta publicada) e
   um proxy confiável que não informou o cliente são *todo mundo* ao mesmo
   tempo. Banir esse endereço trancaria a instalação inteira de fora na primeira
   rajada de senhas erradas — e o contrário, o processo não tem como separar as
   pessoas atrás dele. A tela diz quando é esse o caso (`you.countable`).

2. **A lista de liberados vem antes de tudo.** Um IP liberado não é contado, não é
   limitado e não é banido; liberar um IP já banido o solta na hora. O limite
   do login (5 por minuto) e o bloqueio da conta valem para ele igual: a lista
   é para não trancar o SOC fora, não para dar a alguém tentativas ilimitadas.

3. **O estado é da memória do processo.** O processo é um só (o mesmo motivo do
   registro de vida em auth), e reiniciar o contêiner solta todos os banidos —
   que é também a saída de emergência de quem se trancou fora sem estar na lista.

4. **A memória tem teto.** Quem troca de IP a cada requisição não pode encher o
   dicionário: passou de MAX_TRACKED endereços, saem os mais antigos.
"""

import collections
import ipaddress
import logging
import threading

log = logging.getLogger('abuse_guard')

MAX_TRACKED = 10000

# Por que uma falha conta: fica no registro do banimento e na trilha
KIND_LOGIN = 'login'
KIND_MFA = 'mfa'
KIND_PASSWORD = 'password'
KIND_RATE = 'rate'
KIND_CAPTCHA = 'captcha'
KINDS = (KIND_LOGIN, KIND_MFA, KIND_PASSWORD, KIND_RATE, KIND_CAPTCHA)

Verdict = collections.namedtuple('Verdict', ['refused', 'reason', 'retry_after'])
ALLOWED = Verdict(False, None, 0)

_lock = threading.Lock()
# ip -> [instantes das falhas dentro da janela, em segundos]
_failures = collections.OrderedDict()
# ip -> {'until': segundos, 'since': segundos, 'kind': o tipo da última falha, 'failures': n}
_bans = collections.OrderedDict()
# ip -> [início da janela de um minuto, requisições nela, se a estourada já contou como falha]
_windows = collections.OrderedDict()


def reset():
	"""Esquece tudo. Para os testes, e para nada mais."""
	with _lock:
		_failures.clear()
		_bans.clear()
		_windows.clear()


def parse_allowlist(entries):
	"""As redes da lista de liberados. Entrada que não é endereço nem rede é ignorada."""
	networks = []
	for entry in entries or ():
		try:
			networks.append(ipaddress.ip_network(str(entry).strip(), strict = False))
		except ValueError:
			continue
	return networks


def _address(ip):
	try:
		parsed = ipaddress.ip_address(str(ip))
	except ValueError:
		return None
	mapped = getattr(parsed, 'ipv4_mapped', None)
	return mapped if mapped is not None else parsed


def _in_any(parsed, networks):
	return any(parsed in network for network in networks if network.version == parsed.version)


def is_allowed(ip, networks):
	parsed = _address(ip)
	return parsed is not None and _in_any(parsed, networks)


def countable(resolved, trusted):
	"""Se o endereço resolvido é de uma pessoa — e portanto pode ser contado e banido.

	`resolved` é um client_addr.Resolved. Não é uma pessoa: o gateway do Docker,
	um par confiável que chegou sem X-Forwarded-For (o próprio proxy, ou alguém
	no host falando com o loopback) e um endereço que não deu para ler.
	"""
	parsed = _address(resolved.ip)
	if resolved.docker_gateway or parsed is None:
		return False
	if resolved.source == 'peer' and _in_any(parsed, trusted):
		return False
	return True


def _trim(table):
	while len(table) > MAX_TRACKED:
		table.popitem(last = False)


def _ban_left(ip, now):
	ban = _bans.get(ip)
	if ban is None:
		return 0
	if ban['until'] <= now:
		del _bans[ip]
		return 0
	return int(ban['until'] - now + 0.999)


def check(ip, policy, now, count_request = True):
	"""Se esta requisição passa. Conta a requisição na janela do minuto.

	`policy` é security_policy.load_config()['protection']. Quem chama já decidiu
	que o endereço é contável e não está na lista de liberados.
	"""
	with _lock:
		left = _ban_left(ip, now)
		if left:
			return Verdict(True, 'banned', left)
		limit = policy['rateLimit']
		if not limit['enabled'] or not count_request:
			return ALLOWED
		window = _windows.get(ip)
		if window is None or now - window[0] >= 60:
			window = [now, 0, False]
		window[1] += 1
		_windows[ip] = window
		_windows.move_to_end(ip)
		_trim(_windows)
		if window[1] <= limit['perMinute']:
			return ALLOWED
		retry = max(1, int(window[0] + 60 - now + 0.999))
		# O minuto estourado conta uma vez como falha, não uma por requisição: uma
		# rajada de mil requisições não pode virar mil falhas e um banimento na hora
		first_breach = not window[2]
		window[2] = True
	if first_breach and record_failure(ip, KIND_RATE, policy, now):
		# 'banned_now': foi esta requisição que baniu — quem chama registra na trilha
		return Verdict(True, 'banned_now', policy['ban']['banMinutes'] * 60)
	return Verdict(True, 'limited', retry)


def record_failure(ip, kind, policy, now):
	"""Conta uma falha deste endereço. True quando foi ela que baniu o endereço."""
	ban = policy['ban']
	if not ban['enabled']:
		return False
	window = ban['windowMinutes'] * 60
	with _lock:
		if _ban_left(ip, now):
			return False
		moments = [moment for moment in _failures.get(ip, ()) if now - moment < window]
		moments.append(now)
		if len(moments) < ban['maxFailures']:
			_failures[ip] = moments
			_failures.move_to_end(ip)
			_trim(_failures)
			return False
		_failures.pop(ip, None)
		_bans[ip] = {'until': now + ban['banMinutes'] * 60, 'since': now, 'kind': kind, 'failures': len(moments)}
		_trim(_bans)
	log.warning('endereço %s banido por %s min depois de %s falhas (última: %s)',
		ip, ban['banMinutes'], len(moments), kind)
	return True


def unban(ip):
	"""Solta um endereço. True se ele estava banido."""
	with _lock:
		_failures.pop(ip, None)
		_windows.pop(ip, None)
		return _bans.pop(ip, None) is not None


def release_allowed(networks):
	"""Solta os banidos que passaram a estar na lista de liberados. Devolve quais."""
	with _lock:
		released = [ip for ip in _bans if is_allowed(ip, networks)]
		for ip in released:
			del _bans[ip]
			_failures.pop(ip, None)
	return released


def bans(now):
	"""Os banimentos em vigor, do mais recente para o mais antigo."""
	with _lock:
		for ip in [ip for ip, ban in _bans.items() if ban['until'] <= now]:
			del _bans[ip]
		rows = [{
			'ip': ip,
			'secondsLeft': int(ban['until'] - now + 0.999),
			'sinceSeconds': int(now - ban['since']),
			'kind': ban['kind'],
			'failures': ban['failures']
		} for ip, ban in _bans.items()]
	rows.reverse()
	return rows
