"""Bloqueio de indicadores — a primeira ação desta aplicação com efeito fora dela.

Tudo o que existia até aqui era leitura. `analyzers.py` consulta fornecedor e
devolve um nível; `custom_analyzers.py` faz o mesmo apontando para um endereço
que o analista escolheu; a whitelist grava num arquivo local. Nada disso muda o
estado de nenhum sistema de terceiro.

Este módulo muda. Ele escreve na lista de bloqueio do tenant do Microsoft 365 e
nos objetos de um firewall de perímetro. Um erro aqui não devolve um veredito
errado: derruba tráfego legítimo ou deixa passar o que deveria ter barrado. Daí
as diferenças em relação ao módulo de analisadores, todas deliberadas:

  * **`probe()` é separado de `run()`.** O botão "Testar" de um analisador faz a
    mesma consulta que o pipeline faria — testar é inofensivo. Aqui não: um botão
    Testar que bloqueasse de verdade seria uma armadilha. `probe()` faz uma
    chamada estritamente de leitura contra o mesmo endpoint e com a mesma
    credencial, e prova o caminho sem escrever nada.

  * **Não existe "bloqueio automático".** Nenhuma rota deste módulo é chamada
    pelo pipeline. Bloquear é sempre um ato explícito de um admin sobre um
    indicador que ele escolheu, e cada um vai para o log de auditoria com o valor
    e o destino.

  * **O objeto não é a regra.** Registrar um IP num grupo dinâmico do PAN-OS,
    num address group do FortiGate ou num network group do Check Point só barra
    tráfego se existir uma regra de negação referenciando aquele grupo. Isso é
    dito no guia porque é o erro que faz alguém achar que bloqueou e não ter
    bloqueado nada.

Forma do módulo, espelhando `analyzers.py` de propósito — quem entendeu um
entende o outro:

  RESPONDERS      registro declarativo — identidade, quais tipos de indicador o
                  destino aceita, os campos de credencial e os ajustes. A tela
                  monta card e formulário a partir daqui, então um destino novo é
                  uma entrada no registro mais um cliente, nunca marcação nova.

  run()           bloqueia um indicador. Nunca levanta: falha vira
                  `{'ok': False, ...}` com o motivo, porque um firewall
                  inalcançável não pode impedir que os outros sejam acionados.

  probe()         verifica credencial e alcance sem escrever nada.
"""

import datetime
import json
import re
import traceback
import xml.etree.ElementTree as ElementTree

import requests

import pinned_http
import urllib3

import analyzers
import custom_analyzers


# Mesmo par de timeouts dos analisadores. Um firewall costuma estar na rede
# interna e responder rápido; a nuvem da Microsoft, nem sempre.
HTTP_TIMEOUT = analyzers.HTTP_TIMEOUT

CONFIG_FILE = analyzers.CONFIG_FILE
CONFIG_SECTION = 'responders'

# Os tipos de indicador que faz sentido bloquear. 'filename' e 'filetype' ficam
# de fora: nenhum dos destinos aqui bloqueia por nome de arquivo, e oferecer o
# que não funciona é pior do que não oferecer.
TARGET_TYPES = ('mail', 'domain', 'url', 'ip', 'hash')

# Rótulos usados nas mensagens; a tela tem os seus
TARGET_LABEL = {
	'mail': 'remetente',
	'domain': 'domínio',
	'url': 'URL',
	'ip': 'endereço IP',
	'hash': 'hash de arquivo'
}


# --------------------------------------------------------------------------- #
# Registro                                                                     #
# --------------------------------------------------------------------------- #

RESPONDERS = [
	{
		'id': 'eop',
		'family': 'email_gateway',
		'name': 'Microsoft 365 · Exchange Online Protection',
		'kind': 'lista de bloqueio do tenant',
		'description': 'Grava o indicador na Tenant Allow/Block List do Microsoft 365 — a mesma lista '
			'que o Centro de Segurança mostra em Políticas → Listas de permissão/bloqueio do locatário. '
			'Remetente, domínio e URL param de entregar; o hash SHA-256 barra o anexo.',
		'docs': 'https://learn.microsoft.com/defender-office-365/tenant-allow-block-list-about',
		'targets': ['mail', 'domain', 'url', 'hash'],
		'credentials': [
			{'key': 'tenantId', 'label': 'TENANT ID', 'secret': False, 'required': True,
			 'placeholder': '00000000-0000-0000-0000-000000000000'},
			{'key': 'clientId', 'label': 'CLIENT ID', 'secret': False, 'required': True,
			 'placeholder': '00000000-0000-0000-0000-000000000000'},
			{'key': 'clientSecret', 'label': 'CLIENT SECRET', 'secret': True, 'required': True,
			 'help': 'O registro de aplicativo precisa da permissão de aplicação Exchange.ManageAsApp '
				'(Office 365 Exchange Online) com consentimento do administrador, E do papel de '
				'diretório Administrador do Exchange ou Administrador de Segurança atribuído ao '
				'próprio aplicativo. Só a permissão de API não basta.'},
			{'key': 'organization', 'label': 'ORGANIZAÇÃO', 'secret': False, 'required': True,
			 'placeholder': 'contoso.onmicrosoft.com',
			 'help': 'O domínio inicial do tenant. É o que entra no caminho do endpoint de '
				'administração do Exchange Online.'}
		],
		'settings': [
			{'key': 'expirationDays', 'label': 'EXPIRAÇÃO DO BLOQUEIO', 'unit': 'dias',
			 'min': 0, 'max': 90, 'default': 30,
			 'help': 'A Microsoft aceita no máximo 90 dias. Zero grava sem expiração — use com '
				'critério: uma entrada permanente sobrevive à campanha que a motivou.'}
		],
		'testHint': 'lê a lista de bloqueio de remetentes do tenant; não grava nada'
	},
	{
		'id': 'panos',
		'family': 'firewall',
		'name': 'Palo Alto Networks · PAN-OS',
		'kind': 'grupo dinâmico e categoria de URL',
		'description': 'Registra o IP numa tag de Dynamic Address Group pela API de User-ID, que vale '
			'na hora e não pede commit, e acrescenta domínio e URL a uma categoria de URL '
			'personalizada. A regra de negação que usa a tag e a categoria é sua — este destino '
			'preenche os objetos, não escreve política.',
		'docs': 'https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api',
		'targets': ['ip', 'domain', 'url'],
		'credentials': [
			{'key': 'url', 'label': 'ENDEREÇO DE GERÊNCIA', 'secret': False, 'required': True,
			 'placeholder': 'https://192.0.2.10',
			 'help': 'Só o host, sem /api. Endereço na rede interna é esperado aqui.'},
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'help': 'Gerada em /api/?type=keygen com um usuário administrativo. O perfil de acesso '
				'precisa de XML API com User-ID e Configuration habilitados.'},
			{'key': 'tag', 'label': 'TAG DO GRUPO DINÂMICO', 'secret': False, 'required': True,
			 'default': 'bluephish-block',
			 'help': 'A tag registrada para cada IP. Crie um Dynamic Address Group que case com ela '
				'e uma regra negando o tráfego desse grupo.'},
			{'key': 'urlCategory', 'label': 'CATEGORIA DE URL PERSONALIZADA', 'secret': False,
			 'required': True, 'default': 'bluephish-block',
			 'help': 'Precisa existir antes. Domínios e URLs são acrescentados à lista dela.'},
			{'key': 'vsys', 'label': 'VSYS', 'secret': False, 'required': True, 'default': 'vsys1'},
			{'key': 'commit', 'label': 'EFETUAR COMMIT', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'O registro de IP vale imediatamente e nunca precisa de commit. Domínio e URL '
				'só passam a valer depois dele. Desligue se a sua operação exige commit revisado.'},
			{'key': 'verifyTls', 'label': 'VALIDAR CERTIFICADO TLS', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Interface de gerência costuma usar certificado próprio. Desligar aceita o '
				'certificado sem validar — só faça isso numa rede em que você confia no caminho.'}
		],
		'settings': [],
		'testHint': 'lê a versão do sistema pela API operacional; não altera configuração'
	},
	{
		'id': 'fortigate',
		'family': 'firewall',
		'name': 'Fortinet · FortiGate',
		'kind': 'address group e filtro de URL',
		'description': 'Cria o objeto de endereço (subnet para IP, FQDN para domínio) e o acrescenta a '
			'um address group, e grava a URL como entrada de bloqueio num perfil de filtro web. A '
			'política que nega o grupo é sua.',
		'docs': 'https://fndn.fortinet.net/index.php?/fortiapi/1-fortios/',
		'targets': ['ip', 'domain', 'url'],
		'credentials': [
			{'key': 'url', 'label': 'ENDEREÇO DE GERÊNCIA', 'secret': False, 'required': True,
			 'placeholder': 'https://192.0.2.20',
			 'help': 'Só o host, sem /api/v2. Endereço na rede interna é esperado aqui.'},
			{'key': 'apiToken', 'label': 'TOKEN DE API', 'secret': True, 'required': True,
			 'help': 'Gerado em System → Administrators → REST API Admin. O perfil precisa de escrita '
				'em Firewall Objects; o filtro de URL exige também escrita em Security Profiles. '
				'Confira o trusted host do token, ou a chamada volta 403 mesmo correta.'},
			{'key': 'addressGroup', 'label': 'ADDRESS GROUP', 'secret': False, 'required': True,
			 'default': 'BLUEPHISH_BLOCK',
			 'help': 'Precisa existir antes e estar referenciado por uma política de negação.'},
			{'key': 'urlFilter', 'label': 'ID DO FILTRO DE URL', 'secret': False, 'required': False,
			 'placeholder': '1',
			 'help': 'O id numérico da tabela webfilter urlfilter que recebe as URLs. Em branco, '
				'este destino recusa URLs e continua aceitando IP e domínio.'},
			{'key': 'vdom', 'label': 'VDOM', 'secret': False, 'required': True, 'default': 'root'},
			{'key': 'verifyTls', 'label': 'VALIDAR CERTIFICADO TLS', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Interface de gerência costuma usar certificado próprio. Desligar aceita o '
				'certificado sem validar — só faça isso numa rede em que você confia no caminho.'}
		],
		'settings': [],
		'testHint': 'lê o status do sistema pela API de monitoração; não altera configuração'
	},
	{
		'id': 'checkpoint',
		'family': 'firewall',
		'name': 'Check Point · Management API',
		'kind': 'network group e application site',
		'description': 'Abre sessão na Management API, cria o host e o coloca num network group, ou '
			'acrescenta a URL à lista de um Application/Site personalizado, e publica. A instalação '
			'de política é opcional e desligada por padrão.',
		'docs': 'https://sc1.checkpoint.com/documents/latest/APIs/',
		'targets': ['ip', 'domain', 'url'],
		'credentials': [
			{'key': 'url', 'label': 'ENDEREÇO DO SERVIDOR DE GERÊNCIA', 'secret': False, 'required': True,
			 'placeholder': 'https://192.0.2.30',
			 'help': 'Só o host, sem /web_api. Endereço na rede interna é esperado aqui.'},
			{'key': 'user', 'label': 'USUÁRIO', 'secret': False, 'required': True,
			 'help': 'Precisa de permissão de leitura/escrita na Management API, que também tem de '
				'estar aceitando conexões de fora do servidor (api fwm set-accessibility).'},
			{'key': 'password', 'label': 'SENHA', 'secret': True, 'required': True},
			{'key': 'domain', 'label': 'DOMÍNIO (MDS)', 'secret': False, 'required': False,
			 'help': 'Só em Multi-Domain Security Management. Em branco num servidor único.'},
			{'key': 'networkGroup', 'label': 'NETWORK GROUP', 'secret': False, 'required': True,
			 'default': 'BluePhish-Block',
			 'help': 'Precisa existir antes e estar referenciado por uma regra de drop.'},
			{'key': 'applicationSite', 'label': 'APPLICATION/SITE', 'secret': False, 'required': False,
			 'placeholder': 'BluePhish-Block-URLs',
			 'help': 'Objeto Application/Site personalizado com lista de URLs. Em branco, este destino '
				'recusa domínio e URL e continua aceitando IP.'},
			{'key': 'policyPackage', 'label': 'PACOTE DE POLÍTICA', 'secret': False, 'required': False,
			 'placeholder': 'Standard',
			 'help': 'Preenchido, a política é instalada depois de publicar. Em branco, apenas '
				'publica — o objeto fica gravado e passa a valer na próxima instalação.'},
			{'key': 'verifyTls', 'label': 'VALIDAR CERTIFICADO TLS', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Servidor de gerência costuma usar certificado próprio. Desligar aceita o '
				'certificado sem validar — só faça isso numa rede em que você confia no caminho.'}
		],
		'settings': [],
		'testHint': 'abre e fecha uma sessão de API; nenhum objeto é criado ou publicado'
	}
]

BY_ID = dict((r['id'], r) for r in RESPONDERS)


def field_defs(responder_id):
	"""Definições de credencial e de ajuste de um destino."""
	spec = BY_ID.get(responder_id)
	if spec is None:
		return [], []
	return spec.get('credentials', []), spec.get('settings', [])


def supports(responder_id, target_type):
	"""Se este destino bloqueia indicadores deste tipo."""
	spec = BY_ID.get(responder_id)
	if spec is None:
		return False
	base_type = str(target_type or '').split('_')[0]
	return base_type in spec['targets']


# --------------------------------------------------------------------------- #
# Configuração — mesmo contrato dos analisadores                               #
# --------------------------------------------------------------------------- #

def default_config():
	"""Todo destino desligado, ajustes nos padrões documentados."""
	config = {}
	for spec in RESPONDERS:
		entry = {'enabled': False}
		for field in spec.get('credentials', []):
			entry[field['key']] = field.get('default', '')
		for field in spec.get('settings', []):
			entry[field['key']] = field['default']
		config[spec['id']] = entry
	return config


def load_config(path = CONFIG_FILE):
	"""A configuração gravada, mesclada sobre os padrões."""
	config = default_config()
	try:
		with open(path) as conf_file:
			stored = json.load(conf_file).get(CONFIG_SECTION, {})
	except Exception:
		return config
	for responder_id, entry in (stored or {}).items():
		if responder_id not in config or not isinstance(entry, dict):
			continue
		for key, value in entry.items():
			if key in config[responder_id]:
				config[responder_id][key] = value
	return config


def save_config(config, path = CONFIG_FILE):
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[CONFIG_SECTION] = config
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def public_config(config):
	"""A configuração como o navegador pode vê-la: segredo nunca volta."""
	public = {}
	for spec in RESPONDERS:
		entry = config.get(spec['id'], {})
		out = {'enabled': bool(entry.get('enabled', False))}
		for field in spec.get('credentials', []):
			key = field['key']
			if field.get('secret'):
				out['has' + key[0].upper() + key[1:]] = bool(entry.get(key))
			else:
				out[key] = entry.get(key, field.get('default', ''))
		for field in spec.get('settings', []):
			out[field['key']] = entry.get(field['key'], field['default'])
		public[spec['id']] = out
	return public


def validate_entry(responder_id, submitted, stored):
	"""(entrada, erro) para o que veio do formulário.

	Segredo em branco mantém o gravado, como em todo outro formulário desta
	aplicação. O endereço de gerência passa pela mesma trava de destino dos
	analisadores customizados, com a rede interna liberada — um firewall de
	perímetro nunca tem endereço público, e exigir um tornaria a tela inútil.
	"""
	spec = BY_ID.get(responder_id)
	if spec is None:
		return None, 'Destino de bloqueio desconhecido: {0}.'.format(responder_id)

	stored = stored or {}
	entry = {'enabled': bool(submitted.get('enabled', False))}

	for field in spec.get('credentials', []):
		key = field['key']
		value = submitted.get(key, '')
		value = '' if value is None else str(value).strip()
		if field.get('secret') and value == '':
			value = stored.get(key, '')
		elif not field.get('secret') and value == '':
			value = stored.get(key, '') or field.get('default', '')
		options = field.get('options')
		if options and value not in options:
			return None, '{0}: valor inválido para {1}.'.format(spec['name'], field['label'].lower())
		if entry['enabled'] and field.get('required') and value == '':
			return None, '{0}: {1} é obrigatório para habilitar o destino.'.format(
				spec['name'], field['label'].lower())
		entry[key] = value

	for field in spec.get('settings', []):
		key = field['key']
		raw = submitted.get(key, field['default'])
		try:
			value = int(raw)
		except (TypeError, ValueError):
			return None, '{0}: {1} precisa ser um número.'.format(spec['name'], field['label'].lower())
		if value < field['min'] or value > field['max']:
			return None, '{0}: {1} precisa estar entre {2} e {3}.'.format(
				spec['name'], field['label'].lower(), field['min'], field['max'])
		entry[key] = value

	# O endereço de gerência é digitado, não está no código: a mesma trava dos
	# analisadores customizados vale aqui, e pelo mesmo motivo. A diferença é que
	# a rede interna é liberada por construção, porque é onde o firewall está.
	if 'url' in entry:
		if entry['enabled'] or entry['url']:
			ok, error = custom_analyzers.validate_destination(entry['url'], allow_internal = True)
			if not ok:
				return None, '{0}: {1}'.format(spec['name'], error)

	# Um FortiGate sem id de filtro de URL, ou um Check Point sem Application/Site,
	# continua válido — só deixa de aceitar URL. Recusar o salvamento obrigaria
	# quem só quer bloquear IP a inventar um objeto que não usa.
	return entry, None


def available_targets(responder_id, entry):
	"""Os tipos que este destino aceita *com a configuração atual*.

	Diferente de `supports()`, que só olha o registro: um FortiGate sem id de
	filtro de URL declara suporte a URL e não tem para onde mandá-la.
	"""
	spec = BY_ID.get(responder_id)
	if spec is None:
		return []
	targets = list(spec['targets'])
	entry = entry or {}
	if responder_id == 'fortigate' and not str(entry.get('urlFilter', '') or '').strip():
		targets = [t for t in targets if t != 'url']
	if responder_id == 'checkpoint' and not str(entry.get('applicationSite', '') or '').strip():
		targets = [t for t in targets if t not in ('url', 'domain')]
	return targets


# --------------------------------------------------------------------------- #
# Normalização do indicador                                                    #
# --------------------------------------------------------------------------- #

class ResponderError(Exception):
	"""Uma chamada ao destino falhou de um jeito que vale mostrar ao analista."""


def host_of(value):
	"""O host de uma URL, ou o próprio valor quando já é um host."""
	text = str(value or '').strip()
	if not text:
		return ''
	if '://' in text:
		try:
			from urllib.parse import urlparse
			return urlparse(text).hostname or text
		except Exception:
			return text
	return text.split('/')[0]


def strip_scheme(value):
	"""A URL sem esquema e sem barra final — a forma que quase todo destino quer."""
	text = str(value or '').strip()
	text = re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', '', text)
	return text.rstrip('/')


def normalize_target(target_type, value):
	"""(tipo, valor) validados, ou levanta ResponderError.

	Puro: nenhuma rede, nenhum arquivo. É a parte que os testes fixam.
	"""
	target_type = str(target_type or '').split('_')[0].strip().lower()
	value = str(value or '').strip()

	if target_type not in TARGET_TYPES:
		raise ResponderError('Não é possível bloquear um observável do tipo {0}.'.format(
			target_type or '(vazio)'))
	if not value:
		raise ResponderError('Indicador vazio.')
	if '\n' in value or '\r' in value or ' ' in value:
		raise ResponderError('O indicador precisa ser um valor único, sem espaço nem quebra de linha.')

	if target_type == 'mail':
		if '@' not in value:
			raise ResponderError('{0} não parece um endereço de e-mail.'.format(value))
	elif target_type == 'hash':
		if not re.match(r'^[0-9a-fA-F]{64}$', value):
			# EOP só aceita SHA-256; MD5 e SHA-1 são recusados aqui em vez de
			# serem enviados para tomar erro do outro lado
			raise ResponderError('Só hash SHA-256 pode ser bloqueado; {0} tem {1} caracteres.'.format(
				value, len(value)))
		value = value.lower()
	elif target_type == 'ip':
		import ipaddress
		try:
			ipaddress.ip_address(value)
		except ValueError:
			raise ResponderError('{0} não é um endereço IP válido.'.format(value))
	elif target_type == 'domain':
		if not re.match(r'^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$', value):
			raise ResponderError('{0} não parece um nome de domínio.'.format(value))
		value = value.lower()
	elif target_type == 'url':
		if '.' not in value:
			raise ResponderError('{0} não parece uma URL.'.format(value))

	return target_type, value


def _verify(entry):
	"""O que passar em `verify=` para o requests, conforme o campo do formulário."""
	return str(entry.get('verifyTls', 'sim')).lower() != 'não'


def _tls_note(entry):
	return '' if _verify(entry) else ' (certificado TLS não validado)'


def _guard(entry):
	"""Revalida o endereço de gerência imediatamente antes de chamá-lo.

	Pelo mesmo motivo de custom_analyzers.query(): um nome que resolvia para o
	firewall na hora de salvar pode passar a resolver para outro lugar depois, e é
	a resolução do momento da chamada que decide para onde o pacote vai.
	"""
	url = str(entry.get('url', '') or '').strip().rstrip('/')
	ok, error = custom_analyzers.validate_destination(url, allow_internal = True)
	if not ok:
		raise ResponderError('Destino recusado: {0}'.format(error))
	return url


def _suppress_tls_warning(entry):
	if not _verify(entry):
		urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------- #
# Microsoft 365 · Exchange Online Protection                                   #
# --------------------------------------------------------------------------- #

# O escopo do Exchange Online. Não é o do Graph: a Tenant Allow/Block List não é
# exposta pelo Graph, só pelo endpoint de administração do Exchange.
EXO_SCOPE = 'https://outlook.office365.com/.default'

# A lista aceita três tipos, e o mapeamento não é óbvio: domínio entra como
# remetente (bloqueia o domínio inteiro), não como URL.
EOP_LIST_TYPES = {
	'mail': 'Sender',
	'domain': 'Sender',
	'url': 'Url',
	'hash': 'FileHash'
}


def eop_list_type(target_type):
	"""O ListType da Tenant Allow/Block List para um tipo de indicador."""
	list_type = EOP_LIST_TYPES.get(str(target_type or '').split('_')[0])
	if list_type is None:
		raise ResponderError('A lista de bloqueio do tenant não aceita indicadores do tipo {0}.'.format(
			target_type))
	return list_type


def eop_entry_value(target_type, value):
	"""O valor na forma que a lista de bloqueio espera."""
	if target_type == 'url':
		# A lista casa por padrão de URL, sem esquema
		return strip_scheme(value)
	return value


def _entra_token(entry, scope):
	"""Token de aplicação pelo fluxo client credentials.

	Escrito aqui em vez de reusar m365_auth.get_access_token de propósito: aquele
	módulo guarda uma instância MSAL única por processo, e alternar entre as
	credenciais da caixa monitorada e as do bloqueio jogaria fora o cache das duas
	a cada chamada.
	"""
	response = requests.post(
		'https://login.microsoftonline.com/{0}/oauth2/v2.0/token'.format(entry.get('tenantId', '')),
		data = {
			'client_id': entry.get('clientId', ''),
			'client_secret': entry.get('clientSecret', ''),
			'scope': scope,
			'grant_type': 'client_credentials'
		},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (400, 401):
		raise ResponderError('O Entra ID recusou as credenciais. Confira tenant id, client id e secret.')
	response.raise_for_status()
	token = response.json().get('access_token')
	if not token:
		raise ResponderError('O Entra ID não devolveu um token de acesso.')
	return token


def _eop_invoke(entry, cmdlet, parameters):
	"""Executa um cmdlet do Exchange Online pelo endpoint REST de administração.

	É o mesmo caminho que o módulo Exchange Online PowerShell v3 usa por baixo.
	Não existe API REST pública para a Tenant Allow/Block List fora dele.
	"""
	for field in ('tenantId', 'clientId', 'clientSecret', 'organization'):
		if not entry.get(field):
			raise ResponderError('Credenciais do Exchange Online incompletas.')

	token = _entra_token(entry, EXO_SCOPE)
	response = requests.post(
		'https://outlook.office365.com/adminapi/beta/{0}/InvokeCommand'.format(
			str(entry['organization']).strip()),
		headers = {
			'Authorization': 'Bearer ' + token,
			'Content-Type': 'application/json',
			'Accept': 'application/json',
			'X-ResponseFormat': 'json'
		},
		json = {'CmdletInput': {'CmdletName': cmdlet, 'Parameters': parameters}},
		timeout = HTTP_TIMEOUT)

	if response.status_code in (401, 403):
		raise ResponderError('O Exchange Online recusou o acesso (HTTP {0}). A permissão '
			'Exchange.ManageAsApp não basta sozinha: o aplicativo também precisa do papel de '
			'diretório Administrador do Exchange ou Administrador de Segurança.'.format(
				response.status_code))
	if response.status_code == 404:
		raise ResponderError('O Exchange Online não reconheceu a organização "{0}". Use o domínio '
			'inicial do tenant, como contoso.onmicrosoft.com.'.format(entry.get('organization', '')))

	try:
		body = response.json()
	except ValueError:
		body = {}

	if response.status_code >= 400:
		message = ''
		if isinstance(body, dict):
			message = str(body.get('error', {}).get('message', '') or body.get('Message', '') or '')
		raise ResponderError('O Exchange Online recusou o comando (HTTP {0}){1}'.format(
			response.status_code, ': ' + message if message else '.'))

	return body if isinstance(body, dict) else {}


def block_eop(entry, target_type, value):
	list_type = eop_list_type(target_type)
	item = eop_entry_value(target_type, value)

	parameters = {'ListType': list_type, 'Block': True, 'Entries': [item]}
	try:
		days = int(entry.get('expirationDays', 30))
	except (TypeError, ValueError):
		days = 30
	if days <= 0:
		parameters['NoExpiration'] = True
		horizon = 'sem expiração'
	else:
		expires = datetime.datetime.utcnow() + datetime.timedelta(days = days)
		parameters['ExpirationDate'] = expires.strftime('%Y-%m-%dT%H:%M:%SZ')
		horizon = 'expira em {0} dia(s), {1}'.format(days, expires.strftime('%d/%m/%Y'))

	try:
		_eop_invoke(entry, 'New-TenantAllowBlockListItems', parameters)
	except ResponderError as error:
		# A Microsoft recusa a duplicata com erro, e uma entrada que já existe é o
		# resultado desejado — não uma falha que valha alarme na tela
		if 'already exist' in str(error).lower() or 'já exist' in str(error).lower():
			return {'status': 'already',
				'detail': 'já constava na lista de bloqueio do tenant como {0}'.format(list_type)}
		raise

	return {'status': 'blocked',
		'detail': 'gravado na lista de bloqueio do tenant como {0} · {1}'.format(list_type, horizon)}


def probe_eop(entry):
	body = _eop_invoke(entry, 'Get-TenantAllowBlockListItems', {'ListType': 'Sender', 'Block': True})
	items = body.get('value')
	count = len(items) if isinstance(items, list) else 0
	return 'sessão aberta na organização {0} · {1} bloqueio(s) de remetente já na lista'.format(
		entry.get('organization', ''), count)


# --------------------------------------------------------------------------- #
# Palo Alto Networks · PAN-OS                                                  #
# --------------------------------------------------------------------------- #

def _panos_call(entry, data):
	"""Uma chamada à XML API. Devolve o elemento <response> já validado."""
	base = _guard(entry)
	_suppress_tls_warning(entry)
	payload = dict(data)
	payload['key'] = entry.get('apiKey', '')
	try:
		response = pinned_http.post(base + '/api/', True, data = payload, timeout = HTTP_TIMEOUT,
			verify = _verify(entry), allow_redirects = False)
	except pinned_http.DestinationRefused as refused:
		raise ResponderError('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		raise ResponderError('Falha na validação do certificado TLS da interface de gerência. '
			'Se ela usa certificado próprio, desligue a validação neste destino.')

	if response.status_code in (401, 403):
		raise ResponderError('O PAN-OS recusou a chave de API (HTTP {0}).'.format(response.status_code))
	response.raise_for_status()

	try:
		root = ElementTree.fromstring(response.text)
	except ElementTree.ParseError:
		raise ResponderError('A interface de gerência não devolveu XML — confira se o endereço '
			'aponta para o PAN-OS e não para um portal intermediário.')

	if root.get('status') != 'success':
		message = ' '.join(text.strip() for text in root.itertext() if text and text.strip())
		raise ResponderError('O PAN-OS recusou a operação: {0}'.format(message or 'sem detalhe'))
	return root


def panos_url_entry(value):
	"""Um domínio ou URL na forma que a categoria de URL personalizada aceita.

	O PAN-OS casa por padrão de URL: `exemplo.com/` cobre o site inteiro,
	`exemplo.com/pagina` cobre só aquele caminho.
	"""
	text = strip_scheme(value)
	if '/' not in text:
		return text + '/'
	return text


def _panos_commit(entry):
	root = _panos_call(entry, {'type': 'commit', 'cmd': '<commit></commit>'})
	job = root.find('.//job')
	return job.text if job is not None and job.text else ''


def block_panos(entry, target_type, value):
	if target_type == 'ip':
		# Registro de User-ID: vale na hora, não entra na configuração candidata e
		# portanto não precisa de commit. É por isso que ele é o caminho para IP.
		tag = entry.get('tag', '')
		command = ('<uid-message><version>2.0</version><type>update</type><payload><register>'
			'<entry ip="{0}"><tag><member>{1}</member></tag></entry>'
			'</register></payload></uid-message>').format(value, tag)
		_panos_call(entry, {'type': 'user-id', 'vsys': entry.get('vsys', 'vsys1'), 'cmd': command})
		return {'status': 'blocked',
			'detail': 'registrado na tag {0} do grupo dinâmico, válido imediatamente{1}'.format(
				tag, _tls_note(entry))}

	category = entry.get('urlCategory', '')
	member = panos_url_entry(value)
	xpath = ("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{0}']"
		"/profiles/custom-url-category/entry[@name='{1}']/list").format(
			entry.get('vsys', 'vsys1'), category)
	_panos_call(entry, {
		'type': 'config',
		'action': 'set',
		'xpath': xpath,
		'element': '<member>{0}</member>'.format(member)
	})

	if str(entry.get('commit', 'sim')).lower() == 'sim':
		job = _panos_commit(entry)
		return {'status': 'blocked',
			'detail': 'acrescentado à categoria {0} como {1} · commit enfileirado{2}{3}'.format(
				category, member, ' (job ' + job + ')' if job else '', _tls_note(entry))}

	return {'status': 'pending',
		'detail': 'acrescentado à categoria {0} como {1} · aguardando commit para valer{2}'.format(
			category, member, _tls_note(entry))}


def probe_panos(entry):
	root = _panos_call(entry, {'type': 'op', 'cmd': '<show><system><info/></system></show>'})
	model = root.find('.//model')
	version = root.find('.//sw-version')
	hostname = root.find('.//hostname')
	return 'conectado a {0} · {1} · PAN-OS {2}{3}'.format(
		hostname.text if hostname is not None else 'firewall',
		model.text if model is not None else 'modelo desconhecido',
		version.text if version is not None else '?', _tls_note(entry))


# --------------------------------------------------------------------------- #
# Fortinet · FortiGate                                                         #
# --------------------------------------------------------------------------- #

# O FortiOS limita o nome de um objeto a 79 caracteres, e não aceita qualquer
# caractere num nome. O prefixo torna óbvio de onde o objeto veio.
FORTIGATE_NAME_PREFIX = 'bp-'


def fortigate_object_name(value):
	"""Nome estável e válido para o objeto de endereço criado a partir do valor."""
	slug = re.sub(r'[^A-Za-z0-9._-]+', '-', str(value or '')).strip('-')
	return (FORTIGATE_NAME_PREFIX + slug)[:63] or FORTIGATE_NAME_PREFIX + 'indicador'


def _fortigate_call(entry, method, path, payload = None):
	base = _guard(entry)
	_suppress_tls_warning(entry)
	try:
		response = pinned_http.request(
			method,
			base + path,
			True,
			headers = {'Authorization': 'Bearer ' + entry.get('apiToken', ''),
				'Content-Type': 'application/json'},
			params = {'vdom': entry.get('vdom', 'root')},
			json = payload,
			timeout = HTTP_TIMEOUT,
			verify = _verify(entry),
			allow_redirects = False)
	except pinned_http.DestinationRefused as refused:
		raise ResponderError('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		raise ResponderError('Falha na validação do certificado TLS da interface de gerência. '
			'Se ela usa certificado próprio, desligue a validação neste destino.')

	if response.status_code in (401, 403):
		raise ResponderError('O FortiGate recusou o token (HTTP {0}). Confira o perfil de acesso e o '
			'trusted host do REST API Admin.'.format(response.status_code))

	try:
		body = response.json()
	except ValueError:
		body = {}

	# O FortiOS sinaliza a duplicata com -5 e HTTP 500, o que não é uma falha:
	# o objeto que se queria criar já está lá
	if isinstance(body, dict) and body.get('error') == -5:
		return body, True
	if response.status_code == 404:
		raise ResponderError('O FortiGate não encontrou o objeto referenciado no caminho {0}. '
			'Confira se o address group e o filtro de URL existem.'.format(path))
	if response.status_code >= 400:
		message = ''
		if isinstance(body, dict):
			message = str(body.get('cli_error') or body.get('status') or '')
		raise ResponderError('O FortiGate recusou a operação (HTTP {0}){1}'.format(
			response.status_code, ': ' + message.strip() if message.strip() else '.'))
	return body, False


def block_fortigate(entry, target_type, value):
	group = entry.get('addressGroup', '')

	if target_type == 'url':
		url_filter = str(entry.get('urlFilter', '') or '').strip()
		if not url_filter:
			raise ResponderError('Este FortiGate não tem id de filtro de URL configurado, então só '
				'aceita IP e domínio.')
		_body, duplicate = _fortigate_call(entry, 'POST',
			'/api/v2/cmdb/webfilter/urlfilter/{0}/entries'.format(url_filter),
			{'url': strip_scheme(value), 'type': 'simple', 'action': 'block', 'status': 'enable'})
		if duplicate:
			return {'status': 'already',
				'detail': 'já constava no filtro de URL {0}'.format(url_filter)}
		return {'status': 'blocked',
			'detail': 'entrada de bloqueio criada no filtro de URL {0}{1}'.format(
				url_filter, _tls_note(entry))}

	name = fortigate_object_name(value)
	if target_type == 'ip':
		address = {'name': name, 'subnet': '{0} 255.255.255.255'.format(value)}
	else:
		address = {'name': name, 'type': 'fqdn', 'fqdn': value}

	_body, existed = _fortigate_call(entry, 'POST', '/api/v2/cmdb/firewall/address', address)
	_body, in_group = _fortigate_call(entry, 'POST',
		'/api/v2/cmdb/firewall/addrgrp/{0}/member'.format(group), {'name': name})

	if existed and in_group:
		return {'status': 'already', 'detail': '{0} já estava no address group {1}'.format(name, group)}
	return {'status': 'blocked',
		'detail': 'objeto {0} {1} e acrescentado ao address group {2}{3}'.format(
			name, 'reaproveitado' if existed else 'criado', group, _tls_note(entry))}


def probe_fortigate(entry):
	body, _duplicate = _fortigate_call(entry, 'GET', '/api/v2/monitor/system/status')
	results = body.get('results', {}) if isinstance(body, dict) else {}
	return 'conectado a {0} · FortiOS {1} · vdom {2}{3}'.format(
		results.get('hostname') or body.get('serial') or 'firewall',
		results.get('version') or body.get('version') or '?',
		entry.get('vdom', 'root'), _tls_note(entry))


# --------------------------------------------------------------------------- #
# Check Point · Management API                                                 #
# --------------------------------------------------------------------------- #

CHECKPOINT_NAME_PREFIX = 'bp-'


def checkpoint_object_name(value):
	slug = re.sub(r'[^A-Za-z0-9._-]+', '-', str(value or '')).strip('-')
	return (CHECKPOINT_NAME_PREFIX + slug)[:63] or CHECKPOINT_NAME_PREFIX + 'indicador'


def _checkpoint_call(entry, command, payload, sid = None):
	base = _guard(entry)
	_suppress_tls_warning(entry)
	headers = {'Content-Type': 'application/json'}
	if sid:
		headers['X-chkp-sid'] = sid
	try:
		response = pinned_http.post(base + '/web_api/' + command, True, headers = headers, json = payload,
			timeout = HTTP_TIMEOUT, verify = _verify(entry), allow_redirects = False)
	except pinned_http.DestinationRefused as refused:
		raise ResponderError('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		raise ResponderError('Falha na validação do certificado TLS do servidor de gerência. '
			'Se ele usa certificado próprio, desligue a validação neste destino.')

	try:
		body = response.json()
	except ValueError:
		body = {}

	if response.status_code >= 400:
		message = str(body.get('message', '')) if isinstance(body, dict) else ''
		if response.status_code in (401, 403):
			raise ResponderError('O Check Point recusou a autenticação (HTTP {0}){1}'.format(
				response.status_code, ': ' + message if message else '.'))
		raise ResponderError('O Check Point recusou "{0}" (HTTP {1}){2}'.format(
			command, response.status_code, ': ' + message if message else '.'))
	return body if isinstance(body, dict) else {}


def _checkpoint_login(entry):
	payload = {'user': entry.get('user', ''), 'password': entry.get('password', '')}
	if entry.get('domain'):
		payload['domain'] = entry['domain']
	body = _checkpoint_call(entry, 'login', payload)
	sid = body.get('sid')
	if not sid:
		raise ResponderError('O Check Point não devolveu um identificador de sessão.')
	return sid


def _checkpoint_logout(entry, sid):
	try:
		_checkpoint_call(entry, 'logout', {}, sid)
	except Exception:
		# Uma sessão não encerrada expira sozinha; falhar aqui não desfaz o que já
		# foi publicado, e mascararia o resultado real da operação
		pass


def block_checkpoint(entry, target_type, value):
	sid = _checkpoint_login(entry)
	try:
		if target_type == 'ip':
			group = entry.get('networkGroup', '')
			name = checkpoint_object_name(value)
			try:
				_checkpoint_call(entry, 'add-host', {'name': name, 'ip-address': value}, sid)
				created = True
			except ResponderError as error:
				if 'more than one object' in str(error).lower() or 'already exists' in str(error).lower():
					created = False
				else:
					raise
			_checkpoint_call(entry, 'set-group', {'name': group, 'members': {'add': name}}, sid)
			what = 'host {0} {1} e acrescentado ao network group {2}'.format(
				name, 'criado' if created else 'reaproveitado', group)
		else:
			site = str(entry.get('applicationSite', '') or '').strip()
			if not site:
				raise ResponderError('Este Check Point não tem Application/Site configurado, então só '
					'aceita IP.')
			member = strip_scheme(value)
			_checkpoint_call(entry, 'set-application-site',
				{'name': site, 'url-list': {'add': member}}, sid)
			what = 'acrescentado à lista de URLs do Application/Site {0} como {1}'.format(site, member)

		_checkpoint_call(entry, 'publish', {}, sid)

		package = str(entry.get('policyPackage', '') or '').strip()
		if package:
			_checkpoint_call(entry, 'install-policy',
				{'policy-package': package, 'access': True}, sid)
			return {'status': 'blocked',
				'detail': '{0} · publicado e política {1} instalada{2}'.format(
					what, package, _tls_note(entry))}

		return {'status': 'pending',
			'detail': '{0} · publicado, valendo na próxima instalação de política{1}'.format(
				what, _tls_note(entry))}
	finally:
		_checkpoint_logout(entry, sid)


def probe_checkpoint(entry):
	sid = _checkpoint_login(entry)
	try:
		body = _checkpoint_call(entry, 'show-session', {}, sid)
		return 'sessão aberta como {0}{1}{2}'.format(
			body.get('user-name') or entry.get('user', ''),
			' no domínio ' + entry['domain'] if entry.get('domain') else '',
			_tls_note(entry))
	finally:
		_checkpoint_logout(entry, sid)


# --------------------------------------------------------------------------- #
# Ponto de entrada                                                             #
# --------------------------------------------------------------------------- #

BLOCKERS = {
	'eop': block_eop,
	'panos': block_panos,
	'fortigate': block_fortigate,
	'checkpoint': block_checkpoint
}

PROBES = {
	'eop': probe_eop,
	'panos': probe_panos,
	'fortigate': probe_fortigate,
	'checkpoint': probe_checkpoint
}


def _failure(message):
	return {'ok': False, 'status': 'error', 'detail': '', 'error': message}


def run(responder_id, target_type, value, config = None):
	"""Bloqueia um indicador num destino. Devolve {ok, status, detail, error}.

	Nunca levanta: um firewall inalcançável não pode impedir que os outros
	destinos sejam acionados, e o analista precisa ver o que funcionou e o que
	não funcionou na mesma tela.

	`status` é 'blocked' quando a regra já vale, 'already' quando o indicador já
	estava lá, 'pending' quando o objeto foi gravado mas depende de um commit ou
	de uma instalação de política, e 'error' quando falhou.
	"""
	config = config if config is not None else load_config()
	entry = config.get(responder_id, {})
	spec = BY_ID.get(responder_id)

	if spec is None:
		return _failure('Destino de bloqueio desconhecido.')
	if not entry.get('enabled'):
		return _failure('Destino desabilitado.')

	try:
		target_type, value = normalize_target(target_type, value)
	except ResponderError as error:
		return _failure(str(error))

	if target_type not in available_targets(responder_id, entry):
		return _failure('{0} não bloqueia {1}.'.format(
			spec['name'], TARGET_LABEL.get(target_type, target_type)))

	try:
		outcome = BLOCKERS[responder_id](entry, target_type, value)
	except ResponderError as error:
		return _failure(str(error))
	except requests.exceptions.Timeout:
		return _failure('{0} não respondeu dentro do tempo limite.'.format(spec['name']))
	except requests.exceptions.ConnectionError:
		return _failure('Não foi possível alcançar {0} em {1}.'.format(
			spec['name'], entry.get('url', '') or 'seu endereço'))
	except Exception:
		print("[ERROR]_[responders]: {0} failed to block {1} {2}: {3}".format(
			responder_id, target_type, value, traceback.format_exc()))
		return _failure('{0} devolveu uma resposta inesperada.'.format(spec['name']))

	return {
		'ok': True,
		'status': outcome.get('status', 'blocked'),
		'detail': outcome.get('detail', ''),
		'error': ''
	}


def probe(responder_id, entry):
	"""Verifica credencial e alcance sem escrever nada. {ok, detail, error}.

	Recebe a entrada já validada, e não o id da configuração gravada, para que a
	credencial digitada e ainda não salva seja a que vale — como no botão Testar
	dos analisadores.
	"""
	spec = BY_ID.get(responder_id)
	if spec is None:
		return {'ok': False, 'detail': '', 'error': 'Destino de bloqueio desconhecido.'}

	try:
		detail = PROBES[responder_id](entry)
	except ResponderError as error:
		return {'ok': False, 'detail': '', 'error': str(error)}
	except requests.exceptions.Timeout:
		return {'ok': False, 'detail': '',
			'error': '{0} não respondeu dentro do tempo limite.'.format(spec['name'])}
	except requests.exceptions.ConnectionError:
		return {'ok': False, 'detail': '',
			'error': 'Não foi possível alcançar {0} em {1}.'.format(
				spec['name'], entry.get('url', '') or 'seu endereço')}
	except Exception:
		print("[ERROR]_[responders]: probe of {0} failed: {1}".format(
			responder_id, traceback.format_exc()))
		return {'ok': False, 'detail': '',
			'error': '{0} devolveu uma resposta inesperada.'.format(spec['name'])}

	return {'ok': True, 'detail': detail, 'error': ''}


def responders_for(target_type, config = None):
	"""Ids dos destinos habilitados que bloqueiam este tipo de indicador."""
	config = config if config is not None else load_config()
	found = []
	base_type = str(target_type or '').split('_')[0]
	for spec in RESPONDERS:
		entry = config.get(spec['id'], {})
		if not entry.get('enabled'):
			continue
		if base_type in available_targets(spec['id'], entry):
			found.append(spec['id'])
	return found
