"""Envio das notificações de veredito — o caminho que não passa mais pelo Cortex.

Até aqui o aviso ao denunciante era escrito na descrição de uma task do TheHive
no formato `mailto:<endereço>\\n<corpo>` e um responder do Cortex (`Mailer_1_0`)
lia aquilo e mandava o e-mail. Eram três saltos — ThePhish grava, TheHive
dispara, Cortex envia — para uma mensagem de duas linhas, e o Cortex ficava de pé
só por causa disso depois que os analisadores passaram a ser nativos.

Este módulo fala SMTP direto. A forma é a mesma de `analyzers.py` e
`responders.py` de propósito: registro declarativo de campos, `validate_entry()`
para o formulário, `public_config()` que nunca devolve a senha, `probe()` que
prova a credencial sem mandar mensagem nenhuma e `send()` que nunca levanta.

Duas decisões que valem explicar:

  * **`probe()` não envia e-mail.** Ele abre a sessão, faz STARTTLS quando é o
    caso, autentica e encerra. Um botão "Testar" que mandasse uma mensagem de
    verdade acabaria entregando teste na caixa de alguém.

  * **`send()` nunca levanta.** Um servidor SMTP fora do ar não pode derrubar a
    análise: o veredito já foi decidido, o caso já foi fechado, e a notificação
    é a última coisa que acontece. A falha vira log e segue.
"""

import json
import re
import smtplib
import ssl
import traceback

from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid

CONFIG_FILE = 'configuration.json'
CONFIG_SECTION = 'notification'
SMTP_KEY = 'smtp'

# Um servidor SMTP que não responde rápido no connect está inalcançável; o envio
# em si pode demorar um pouco mais
SMTP_TIMEOUT = 20

# Como a sessão é cifrada. 'starttls' na 587 é o padrão de fato; 'ssl' na 465 é o
# TLS implícito; 'none' existe para um relay interno sem TLS e é dito na tela.
SECURITY_MODES = ('starttls', 'ssl', 'none')

# Portas usuais de cada modo, usadas só para sugerir na interface
DEFAULT_PORTS = {'starttls': 587, 'ssl': 465, 'none': 25}

# Os avisos ao denunciante, cada um com o seu interruptor. `errata` é o único que
# não sai de uma análise: sai de uma pessoa corrigindo um falso positivo, e ainda
# assim só quando ela confirma no formulário (errata.py)
NOTIFICATION_EVENTS = ('start', 'safe', 'malicious', 'errata')


# Avisos que não existiam no tempo do interruptor único, e por isso não o herdam
EVENTS_WITHOUT_LEGACY = ('errata',)


def notification_flags(notif_conf):
	"""Qual aviso ao denunciante está ligado, evento por evento.

	Havia um interruptor só (`enabled`). Quem ainda não gravou as chaves por
	evento herda o valor dele nos avisos que ele já controlava: ninguém passa a
	receber — ou deixa de receber — um aviso que não pediu só porque a tela mudou.

	A errata não herda, pela mesma regra lida do outro lado: ela é um tipo novo
	de e-mail, e herdar o `enabled` faria toda instalação com os avisos ligados
	começar a mandá-la sem que ninguém a tivesse ligado. Nasce desligada.
	"""
	notif_conf = notif_conf if isinstance(notif_conf, dict) else {}
	legacy = bool(notif_conf.get('enabled', True))
	return dict((event, bool(notif_conf.get(event + 'Enabled',
		False if event in EVENTS_WITHOUT_LEGACY else legacy))) for event in NOTIFICATION_EVENTS)


# --------------------------------------------------------------------------- #
# Registro dos campos — a tela monta o formulário a partir daqui               #
# --------------------------------------------------------------------------- #

FIELDS = [
	{'key': 'host', 'label': 'SERVIDOR SMTP', 'secret': False, 'required': True,
	 'placeholder': 'smtp.office365.com',
	 'help': 'Só o nome do host, sem porta e sem esquema.'},
	{'key': 'port', 'label': 'PORTA', 'secret': False, 'required': True,
	 'default': 587,
	 'help': '587 com STARTTLS, 465 com TLS implícito, 25 num relay interno sem autenticação.'},
	{'key': 'security', 'label': 'SEGURANÇA', 'secret': False, 'required': True,
	 'default': 'starttls', 'options': list(SECURITY_MODES),
	 'help': 'STARTTLS começa em claro e sobe para TLS; SSL abre já cifrado. "Nenhuma" só faz '
		'sentido para um relay na sua própria rede — a mensagem trafega legível.'},
	{'key': 'user', 'label': 'USUÁRIO', 'secret': False, 'required': False,
	 'placeholder': 'notificacoes@suaempresa.com',
	 'help': 'Em branco, a sessão é aberta sem autenticação. Um relay interno costuma aceitar; '
		'qualquer provedor de nuvem, não.'},
	{'key': 'password', 'label': 'SENHA', 'secret': True, 'required': False,
	 'help': 'Em provedor com MFA, use uma senha de aplicativo — a senha da conta é recusada.'},
	{'key': 'sender', 'label': 'REMETENTE', 'secret': False, 'required': True,
	 'placeholder': 'notificacoes@suaempresa.com',
	 'help': 'O endereço que aparece no De:. Precisa ser um endereço que o servidor autoriza '
		'este usuário a usar, ou o envio é recusado.'},
	{'key': 'senderName', 'label': 'NOME DO REMETENTE', 'secret': False, 'required': False,
	 'default': 'BluePhish', 'help': 'O nome exibido ao lado do endereço.'},
	{'key': 'subjectPrefix', 'label': 'PREFIXO DO ASSUNTO', 'secret': False, 'required': False,
	 'default': '[BluePhish]',
	 'help': 'Prefixo aplicado ao assunto de toda notificação, para o denunciante reconhecer '
		'a resposta.'}
]

BY_KEY = dict((f['key'], f) for f in FIELDS)


# --------------------------------------------------------------------------- #
# Configuração                                                                 #
# --------------------------------------------------------------------------- #

def default_config():
	"""Os padrões documentados, sem credencial nenhuma."""
	entry = {'enabled': False}
	for field in FIELDS:
		entry[field['key']] = field.get('default', '')
	return entry


def load_config(path = CONFIG_FILE):
	"""A configuração gravada mesclada sobre os padrões.

	Mesclar em vez de substituir faz uma configuration.json escrita antes deste
	módulo existir continuar produzindo uma entrada completa e utilizável.
	"""
	config = default_config()
	try:
		with open(path) as conf_file:
			stored = (json.load(conf_file).get(CONFIG_SECTION, {}) or {}).get(SMTP_KEY, {})
	except Exception:
		return config
	if not isinstance(stored, dict):
		return config
	for key, value in stored.items():
		if key in config:
			config[key] = value
	return config


def save_config(entry, path = CONFIG_FILE):
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	notification = conf_dict.get(CONFIG_SECTION, {})
	notification[SMTP_KEY] = entry
	conf_dict[CONFIG_SECTION] = notification
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def public_config(entry):
	"""A configuração como o navegador pode vê-la: a senha nunca volta."""
	public = {'enabled': bool(entry.get('enabled', False))}
	for field in FIELDS:
		key = field['key']
		if field.get('secret'):
			public['has' + key[0].upper() + key[1:]] = bool(entry.get(key))
		else:
			public[key] = entry.get(key, field.get('default', ''))
	return public


def looks_like_address(value):
	"""Suficiente para pegar o erro de digitação; o servidor é quem valida de verdade."""
	return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', str(value or '').strip()))


def validate_entry(submitted, stored):
	"""(entrada, erro) para o que veio do formulário.

	Senha em branco mantém a gravada, como em todo outro formulário desta
	aplicação. Os campos obrigatórios só são cobrados quando o envio está ligado:
	preencher o formulário em etapas com o aviso desligado é permitido.
	"""
	stored = stored or {}
	entry = {'enabled': bool(submitted.get('enabled', False))}

	for field in FIELDS:
		key = field['key']
		if key == 'port':
			continue
		value = submitted.get(key, '')
		value = '' if value is None else str(value).strip()
		if field.get('secret') and value == '':
			value = stored.get(key, '')
		elif not field.get('secret') and value == '':
			value = stored.get(key, '') or field.get('default', '')
		options = field.get('options')
		if options and value not in options:
			return None, 'Valor inválido para {0}.'.format(field['label'].lower())
		if entry['enabled'] and field.get('required') and value == '':
			return None, '{0} é obrigatório para enviar as notificações.'.format(field['label'].lower())
		entry[key] = value

	raw_port = submitted.get('port', stored.get('port', DEFAULT_PORTS.get(entry.get('security'), 587)))
	try:
		port = int(raw_port)
	except (TypeError, ValueError):
		return None, 'A porta precisa ser um número.'
	if port < 1 or port > 65535:
		return None, 'A porta precisa estar entre 1 e 65535.'
	entry['port'] = port

	# Um remetente inválido é recusado aqui em vez de virar uma falha silenciosa
	# no fim de cada análise, que é onde ele apareceria
	if entry.get('sender') and not looks_like_address(entry['sender']):
		return None, '{0} não parece um endereço de e-mail.'.format(entry['sender'])

	# Senha sem usuário é um engano comum: a sessão seria aberta sem autenticar e
	# o servidor recusaria o envio sem dizer por quê
	if entry['enabled'] and entry.get('password') and not entry.get('user'):
		return None, 'Informe o usuário — uma senha sem usuário não autentica nada.'

	return entry, None


# --------------------------------------------------------------------------- #
# Sessão SMTP                                                                  #
# --------------------------------------------------------------------------- #

class MailerError(Exception):
	"""Uma falha de envio que vale mostrar ao analista tal como é."""


def _connect(entry):
	"""Abre a sessão já cifrada e autenticada. Quem chama é dono do close()."""
	host = str(entry.get('host', '') or '').strip()
	if not host:
		raise MailerError('Servidor SMTP não configurado.')
	try:
		port = int(entry.get('port') or DEFAULT_PORTS.get(entry.get('security'), 587))
	except (TypeError, ValueError):
		port = 587
	security = str(entry.get('security', 'starttls') or 'starttls')

	try:
		if security == 'ssl':
			session = smtplib.SMTP_SSL(host, port, timeout = SMTP_TIMEOUT,
				context = ssl.create_default_context())
		else:
			session = smtplib.SMTP(host, port, timeout = SMTP_TIMEOUT)
	except smtplib.SMTPException as error:
		raise MailerError('O servidor SMTP recusou a conexão: {0}'.format(error))
	except ssl.SSLError as error:
		raise MailerError('Falha no TLS com {0}:{1} — {2}'.format(host, port, error))
	except OSError as error:
		raise MailerError('Não foi possível alcançar {0}:{1} — {2}'.format(host, port, error))

	try:
		session.ehlo()
		if security == 'starttls':
			try:
				session.starttls(context = ssl.create_default_context())
			except smtplib.SMTPNotSupportedError:
				raise MailerError('O servidor não oferece STARTTLS nesta porta. Use 465 com SSL, '
					'ou 25 sem cifra se for um relay da sua rede.')
			except ssl.SSLError as error:
				raise MailerError('Falha na negociação do STARTTLS: {0}'.format(error))
			session.ehlo()

		user = str(entry.get('user', '') or '').strip()
		if user:
			try:
				session.login(user, entry.get('password', ''))
			except smtplib.SMTPAuthenticationError as error:
				raise MailerError('O servidor recusou as credenciais de {0}. Em provedor com MFA, '
					'é preciso uma senha de aplicativo. ({1})'.format(user, error.smtp_code))
			except smtplib.SMTPNotSupportedError:
				raise MailerError('O servidor não aceita autenticação nesta sessão. Sem cifra, '
					'quase nenhum servidor aceita — confira o modo de segurança.')
	except Exception:
		try:
			session.quit()
		except Exception:
			pass
		raise

	return session


def probe(entry):
	"""Verifica servidor, cifra e credencial sem mandar mensagem. {ok, detail, error}."""
	try:
		session = _connect(entry)
	except MailerError as error:
		return {'ok': False, 'detail': '', 'error': str(error)}
	except Exception:
		print("[ERROR]_[mailer]: probe failed: {0}".format(traceback.format_exc()))
		return {'ok': False, 'detail': '', 'error': 'O servidor SMTP devolveu uma resposta inesperada.'}

	try:
		security = str(entry.get('security', 'starttls'))
		how = {'starttls': 'STARTTLS', 'ssl': 'TLS implícito', 'none': 'sem cifra'}.get(security, security)
		user = str(entry.get('user', '') or '').strip()
		detail = 'sessão aberta em {0}:{1} · {2} · {3}'.format(
			entry.get('host', ''), entry.get('port', ''), how,
			'autenticado como ' + user if user else 'sem autenticação')
		return {'ok': True, 'detail': detail, 'error': ''}
	finally:
		try:
			session.quit()
		except Exception:
			# Uma sessão não encerrada expira sozinha; falhar aqui mascararia o
			# resultado real do teste
			pass


def build_message(entry, to_address, subject, body):
	"""A mensagem pronta. Pura: nenhuma rede, e é a parte que os testes fixam."""
	prefix = str(entry.get('subjectPrefix', '') or '').strip()
	full_subject = '{0} {1}'.format(prefix, subject).strip() if prefix else str(subject or '')

	message = MIMEText(body or '', 'plain', 'utf-8')
	message['Subject'] = Header(full_subject, 'utf-8')
	sender = str(entry.get('sender', '') or '').strip()
	sender_name = str(entry.get('senderName', '') or '').strip()
	message['From'] = formataddr((str(Header(sender_name, 'utf-8')), sender)) if sender_name else sender
	message['To'] = to_address
	message['Date'] = formatdate(localtime = True)
	# Sem Message-ID muitos servidores marcam a mensagem como suspeita, e é
	# justamente uma notificação de segurança que não pode cair em spam
	message['Message-ID'] = make_msgid(domain = sender.split('@')[-1] if '@' in sender else None)
	message['Auto-Submitted'] = 'auto-generated'
	return message


def send(to_address, subject, body, config = None):
	"""Manda uma notificação. Devolve {ok, detail, error} e nunca levanta.

	O veredito já foi decidido e o caso já foi fechado quando isto roda: um
	servidor SMTP fora do ar precisa virar um aviso no log, nunca uma exceção que
	derruba a análise inteira.
	"""
	entry = config if config is not None else load_config()

	if not entry.get('enabled'):
		return {'ok': False, 'detail': '', 'error': 'Envio de notificações desabilitado.'}
	to_address = str(to_address or '').strip()
	if not looks_like_address(to_address):
		return {'ok': False, 'detail': '',
			'error': '{0} não é um endereço de destino válido.'.format(to_address or '(vazio)')}
	if not entry.get('sender'):
		return {'ok': False, 'detail': '', 'error': 'Remetente não configurado.'}

	try:
		session = _connect(entry)
	except MailerError as error:
		return {'ok': False, 'detail': '', 'error': str(error)}
	except Exception:
		print("[ERROR]_[mailer]: could not open the SMTP session: {0}".format(traceback.format_exc()))
		return {'ok': False, 'detail': '', 'error': 'O servidor SMTP devolveu uma resposta inesperada.'}

	try:
		message = build_message(entry, to_address, subject, body)
		session.sendmail(entry['sender'], [to_address], message.as_string())
		return {'ok': True, 'detail': 'notificação enviada para {0}'.format(to_address), 'error': ''}
	except smtplib.SMTPRecipientsRefused:
		return {'ok': False, 'detail': '',
			'error': 'O servidor recusou o destinatário {0}.'.format(to_address)}
	except smtplib.SMTPSenderRefused:
		return {'ok': False, 'detail': '',
			'error': 'O servidor recusou o remetente {0}. Confira se o usuário autenticado tem '
				'permissão de enviar como esse endereço.'.format(entry.get('sender', ''))}
	except smtplib.SMTPException as error:
		return {'ok': False, 'detail': '', 'error': 'O servidor SMTP recusou o envio: {0}'.format(error)}
	except Exception:
		print("[ERROR]_[mailer]: send failed: {0}".format(traceback.format_exc()))
		return {'ok': False, 'detail': '', 'error': 'Falha inesperada ao enviar a notificação.'}
	finally:
		try:
			session.quit()
		except Exception:
			pass
