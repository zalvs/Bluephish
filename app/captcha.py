"""reCAPTCHA v3 no login por senha.

Configurado em Configurações → Segurança (global_admin); os números e as chaves
moram em security_policy, na seção `security.captcha` do configuration.json. O
segredo nunca volta para o navegador: a tela recebe só se ele existe
(`hasSecret`), como o segredo do SSO. No configuration.json ele vira uma
referência ao cofre cifrado (secret_vault.py), como todo segredo.

O v3 não mostra desafio: o script do Google dá uma nota de 0 a 1 para a
interação, e o servidor recusa abaixo da nota mínima configurada. Ele é a
terceira camada contra força bruta, junto do limite de 5 por minuto do login e
do banimento de IP (abuse_guard) — não a única.

Quatro decisões que não são óbvias lendo o código:

1. **Só o login por senha.** O SSO tem o provedor de identidade na frente, e o
   segundo fator já tem prazo e tentativas contadas; pôr o captcha neles não
   protegeria nada que não esteja protegido.

2. **O Google fora do ar não tranca ninguém fora.** Se a chamada de verificação
   falha (rede, tempo esgotado, resposta que não é JSON), o login segue e o
   caso vai para o log e para a trilha (`captcha`, `unavailable`). Fechar aqui
   seria entregar a disponibilidade do login a um terceiro — e a quem
   conseguisse derrubar a saída do servidor para a internet. O token ausente,
   inválido, de outra ação ou com nota baixa é recusado: isso o cliente
   controla, o Google fora do ar não. Pelo mesmo motivo, a chave secreta que o
   Google diz ser inválida (`misconfigured`) deixa passar e grita no log: é um
   erro desta instalação, e recusar por ele trancaria todos de fora.

3. **Há saída de emergência fora da tela.** Uma chave errada, ou um proxy
   corporativo que bloqueia o script do Google no navegador, deixaria todo mundo
   sem login — inclusive quem desligaria o captcha pela tela. Por isso
   `BLUEPHISH_CAPTCHA_DISABLED=1` no ambiente desliga sem tocar no arquivo, e
   `manage.py captcha-off` grava o desligamento. Um IP da lista de liberados do
   abuse_guard não recebe o captcha.

4. **A CSP do painel não muda.** As origens do Google entram só na resposta da
   tela de login, e só com o captcha ligado (`login_csp`). Ali também, e só ali,
   `style-src` ganha 'unsafe-inline': o script do Google injeta estilo inline no
   selo e no iframe, e sem isso o widget se desmonta. `script-src` nunca ganha.
"""

import json
import logging
import os

import requests

log = logging.getLogger('captcha')

VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'
SCRIPT_URL = 'https://www.google.com/recaptcha/api.js'
DISABLE_ENV = 'BLUEPHISH_CAPTCHA_DISABLED'
ACTION = 'login'
TIMEOUT_SECONDS = 5
MAX_TOKEN_CHARS = 4096

OUTCOME_OK = 'ok'
OUTCOME_MISSING = 'missing'
OUTCOME_INVALID = 'invalid'
OUTCOME_WRONG_ACTION = 'wrong_action'
OUTCOME_LOW_SCORE = 'low_score'
OUTCOME_UNAVAILABLE = 'unavailable'
OUTCOME_MISCONFIGURED = 'misconfigured'

# O que o Google responde quando o erro é da chave secreta desta instalação, não
# do cliente. Recusar aqui recusaria todo mundo por um erro de digitação
SECRET_ERRORS = ('invalid-input-secret', 'missing-input-secret')

# Origens que o script do reCAPTCHA precisa, segundo a documentação do Google:
# o script e o iframe invisível que ele cria
SCRIPT_SOURCES = 'https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/'
FRAME_SOURCES = 'https://www.google.com/recaptcha/'


def disabled_by_environment():
	return str(os.environ.get(DISABLE_ENV, '')).strip().lower() in ('1', 'true', 'yes', 'on')


def is_active(config):
	"""Se o login cobra o captcha: ligado, com as duas chaves, e sem a saída de emergência."""
	return bool(config['enabled'] and config['siteKey'] and config['secret']) and not disabled_by_environment()


def login_csp(base):
	"""A CSP da tela de login com as origens do reCAPTCHA acrescentadas."""
	directives = [part.strip() for part in base.split(';') if part.strip()]
	result = []
	for directive in directives:
		if directive.startswith('script-src '):
			directive = directive + ' ' + SCRIPT_SOURCES
		elif directive.startswith('style-src ') and "'unsafe-inline'" not in directive:
			# O api.js do Google monta o selo e o iframe com estilo inline. Só aqui, só
			# com o captcha ligado, e só em style-src: script-src continua sem ele
			directive = directive + " 'unsafe-inline'"
		result.append(directive)
	result.append('frame-src ' + FRAME_SOURCES)
	return '; '.join(result)


def verify(config, token, post = None):
	"""(passou, desfecho, nota). A nota é None quando não houve uma."""
	token = str(token or '').strip()
	if not token:
		return False, OUTCOME_MISSING, None
	if len(token) > MAX_TOKEN_CHARS:
		return False, OUTCOME_INVALID, None
	post = post or requests.post
	try:
		# Host fixo, sem redirect (o mesmo cuidado das outras chamadas que levam
		# um segredo), e o IP de quem tenta entrar não vai junto: o Google não
		# precisa dele para dar a nota, e não há por que entregá-lo
		response = post(VERIFY_URL, data = {'secret': config['secret'], 'response': token},
			timeout = TIMEOUT_SECONDS, allow_redirects = False)
		if response.status_code != 200:
			raise ValueError('HTTP {0}'.format(response.status_code))
		answer = response.json()
		if not isinstance(answer, dict):
			raise ValueError('resposta que não é um objeto')
	except (requests.RequestException, ValueError, json.JSONDecodeError) as error:
		log.error('verificação do reCAPTCHA indisponível (%s); o login segue sem ela', error)
		return True, OUTCOME_UNAVAILABLE, None
	if answer.get('success') is not True:
		errors = answer.get('error-codes') if isinstance(answer.get('error-codes'), list) else []
		if any(code in SECRET_ERRORS for code in errors):
			log.error('o Google recusou a chave secreta do reCAPTCHA (%s); o login segue sem ele até a chave ser corrigida',
				','.join(str(code) for code in errors)[:200])
			return True, OUTCOME_MISCONFIGURED, None
		return False, OUTCOME_INVALID, None
	if answer.get('action') != ACTION:
		return False, OUTCOME_WRONG_ACTION, None
	score = answer.get('score')
	if not isinstance(score, (int, float)) or isinstance(score, bool):
		return False, OUTCOME_INVALID, None
	if score < config['minScore']:
		return False, OUTCOME_LOW_SCORE, score
	return True, OUTCOME_OK, score
