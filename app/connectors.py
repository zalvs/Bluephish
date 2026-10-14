"""Conector genérico — o destino que a gente não previu.

`tickets.py` cobre três destinos escritos à mão. Quem usa Splunk, ServiceNow,
PagerDuty ou qualquer outra das dezenas de ferramentas do mercado não tem como
registrar a análise sem esperar que alguém escreva o cliente. Este módulo fecha
essa lacuna pelo mesmo caminho que `custom_analyzers.py` abriu do lado da
consulta: uma definição gravada em configuração vira um destino de primeira
classe.

A ideia é curta. O analista abre a documentação da ferramenta de destino, copia
o JSON que ela exige, cola aqui e marca onde entram os dados da análise. A gente
só dispara.

O que este módulo NÃO é
-----------------------
Não é um motor de template. A gramática tem exatamente uma construção,
`{{caminho.pontilhado}}`, e nada mais: sem condicional, sem laço, sem filtro,
sem chamada de função. A tentação de usar Jinja é forte e a resposta é não — um
template editável na tela e avaliado como expressão é execução remota de código
neste servidor, e "só admin edita" não cobre uma conta comprometida.

As três coisas que precisam estar certas
----------------------------------------
1. **Preservação de tipo.** `"severity": "{{severity_number}}"` precisa sair
   como `3`, não como `"3"`. O TheHive recusa o texto com 400, e ele não é
   exceção: metade das APIs de mercado exige inteiro em algum campo. Por isso
   um placeholder *sozinho* devolve o valor no tipo nativo, e só um placeholder
   embutido em texto vira texto.

2. **Escape.** O assunto do e-mail é escrito por quem atacou a vítima. Ele entra
   no corpo da requisição, então uma aspa dele não pode virar estrutura. Aqui
   isso sai de graça e de propósito: a substituição produz um objeto Python e
   quem serializa é `json.dumps`. Nunca se concatena JSON como string.

3. **Destino.** É a mesma trava de `custom_analyzers`, pelo mesmo motivo e com o
   mesmo cuidado de revalidar na hora do disparo — mas aqui pesa mais: o que sai
   no corpo não é um observável solto, é o relatório inteiro, com o corpo do
   e-mail dentro. Um conector mal apontado é exfiltração com nome de integração.

Forma do módulo
---------------
  render()      resolve os placeholders. Puro, sem rede — é a parte que os
                testes fixam.

  build_request() monta URL, cabeçalhos, query e corpo a partir da definição.
                Também puro: é o que a pré-visualização mostra na tela.

  deliver()     dispara. Nunca levanta, como `tickets.create()`: o veredito já
                foi decidido quando isto roda.

  dispatch()    roda todo conector habilitado que aceita este veredito.
"""

import base64
import datetime
import json
import re
import traceback

import requests

import pinned_http

import analyzers
import custom_analyzers
import tickets

# Os nativos usam um par (conexão, leitura): um destino firewalled falha rápido,
# um lento mas vivo é esperado. Aqui a leitura é do usuário — um Jira grande
# demora a criar issue — e a conexão continua sendo a dos nativos.
CONNECT_TIMEOUT = analyzers.HTTP_TIMEOUT[0]

DEFAULT_TIMEOUT = analyzers.HTTP_TIMEOUT[1]

CONFIG_FILE = analyzers.CONFIG_FILE
CONFIG_SECTION = 'connectors'

# Um teto para que a tela continue navegável e para que um erro de automação não
# encha a configuração
MAX_CONNECTORS = 20

# GET e DELETE ficam de fora: um conector existe para *registrar* a análise em
# algum lugar, e nenhum dos dois carrega corpo
METHODS = ('POST', 'PUT', 'PATCH')

AUTH_TYPES = ('none', 'basic', 'bearer', 'header', 'query')

LOCATIONS = ('header', 'query', 'body')

VALUE_TYPES = ('string', 'number', 'boolean', 'json')

# O id é gerado a partir do nome e não pode colidir com um destino nativo
ID_PREFIX = 'connector_'

# Um relatório grande não pode virar um POST de dezenas de megabytes: o destino
# recusaria de qualquer forma, e o custo de descobrir isso é uma conexão aberta
# segurando um worker
MAX_BODY_BYTES = 512 * 1024

# A resposta do destino vai para o histórico, então precisa caber nele
MAX_RESPONSE_CHARS = 4096

DEFAULT_SUCCESS_STATUS = (200, 201, 202, 204)

# O veredito como número, para as APIs que só aceitam inteiro em severidade
SEVERITY_NUMBER = {'Safe': 1, 'Suspicious': 2, 'Malicious': 3}

# O tipo do observável como o TheHive o nomeia. Fora dele a lista é a mesma dos
# analisadores, então a tradução é identidade na maioria dos casos
THEHIVE_DATATYPE = {'ip': 'ip', 'domain': 'domain', 'url': 'url', 'mail': 'mail',
	'hash': 'hash', 'file': 'file', 'filename': 'filename', 'other': 'other'}


class ConnectorError(Exception):
	"""Falha que já tem uma mensagem pronta para o analista ler."""


# --------------------------------------------------------------------------- #
# Contexto                                                                     #
# --------------------------------------------------------------------------- #

def _observable_datatype(observable_type):
	base = str(observable_type or 'other').split('_')[0]
	return THEHIVE_DATATYPE.get(base, 'other')


def context_from_report(report, secrets = None):
	"""O que os placeholders podem ver.

	Começa pelo report de `tickets.build_report()` — que já é dado puro, sem nada
	do TheHive dentro — e acrescenta as formas derivadas. As derivadas existem
	porque a alternativa seria pedir laço na linguagem de template, e laço em
	template editável é o começo de um interpretador.
	"""
	context = dict(report or {})

	observables = report.get('observables') or [] if report else []
	context['observables_csv'] = ', '.join(str(o.get('value', '')) for o in observables)
	context['ioc_count'] = sum(1 for o in observables if o.get('ioc'))
	context['observable_count'] = len(observables)
	context['severity_number'] = SEVERITY_NUMBER.get(report.get('verdict') if report else '', 1)

	# Já na forma que o TheHive espera. É o único atalho por fornecedor deste
	# módulo, e ele existe porque montar essa lista à mão exigiria justamente o
	# laço que a gramática não tem.
	context['thehive_observables'] = [{
		'dataType': _observable_datatype(o.get('type')),
		'data': str(o.get('value', '')),
		'ioc': bool(o.get('ioc')),
		'message': str(o.get('message', '') or '')
	} for o in observables]

	try:
		context['report_markdown'] = tickets.report_as_markdown(report)
	except Exception:
		# Um relatório que não vira prosa não pode impedir o disparo: o resto do
		# contexto continua válido
		context['report_markdown'] = ''
	context['report_text'] = re.sub(r'[*_`]', '', context['report_markdown'])

	# As protecoes de prompt em forma escalar: a gramatica nao tem laco, entao a
	# lista de regras so e util aqui se ja vier achatada. Um SOC que quer ser
	# avisado quando um e-mail ataca o proprio analisador dispara por este campo
	injection = ((report or {}).get('promptGuard') or {}).get('injection') or []
	context['injection_detected'] = bool(injection)
	context['injection_rules_csv'] = ', '.join(str(f.get('rule', '')) for f in injection)

	context['_secrets'] = dict(secrets or {})
	return context


# As variáveis que a tela oferece no painel lateral. A lista é documentação
# executável: se um nome sair daqui sem sair de `context_from_report`, a tela
# passa a oferecer um placeholder que resolve para vazio.
VARIABLES = [
	{'name': 'subject', 'type': 'texto', 'help': 'Assunto do e-mail analisado.'},
	{'name': 'verdict', 'type': 'texto', 'help': 'Safe, Suspicious ou Malicious.'},
	{'name': 'severity_number', 'type': 'número', 'help': '1, 2 ou 3 — para APIs que exigem inteiro.'},
	{'name': 'reporter', 'type': 'texto', 'help': 'Quem reportou o e-mail.'},
	{'name': 'department', 'type': 'texto', 'help': 'Área de quem reportou, vazio quando nenhuma regra a resolveu.'},
	{'name': 'analyzedAt', 'type': 'texto', 'help': 'Data e hora ISO-8601.'},
	{'name': 'caseRef', 'type': 'texto', 'help': 'Número do caso registrado, quando houver.'},
	{'name': 'report_markdown', 'type': 'texto', 'help': 'Relatório completo, formatado.'},
	{'name': 'report_text', 'type': 'texto', 'help': 'O mesmo relatório sem marcação.'},
	{'name': 'observables', 'type': 'lista', 'help': 'Observáveis com tipo, valor e se são IOC.'},
	{'name': 'thehive_observables', 'type': 'lista', 'help': 'Os observáveis já na forma dataType/data/ioc.'},
	{'name': 'observables_csv', 'type': 'texto', 'help': 'Os valores separados por vírgula.'},
	{'name': 'ioc_count', 'type': 'número', 'help': 'Quantidade de observáveis marcados como IOC.'},
	{'name': 'observable_count', 'type': 'número', 'help': 'Quantidade total de observáveis.'},
	{'name': 'findings', 'type': 'lista', 'help': 'Veredito de cada analisador sobre cada observável.'},
	{'name': 'llm.summary', 'type': 'texto', 'help': 'Resumo da avaliação de engenharia social.'},
	{'name': 'injection_detected', 'type': 'booleano', 'help': 'O e-mail tentou manipular a própria análise.'},
	{'name': 'injection_rules_csv', 'type': 'texto', 'help': 'Regras de prompt injection acionadas, separadas por vírgula.'},
	{'name': 'body', 'type': 'texto', 'help': 'Corpo do e-mail analisado.'}
]


# --------------------------------------------------------------------------- #
# Renderização                                                                 #
# --------------------------------------------------------------------------- #

PLACEHOLDER = re.compile(r'\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}')


def resolve(path, context):
	"""O valor de um placeholder. Devolve None quando o caminho não existe."""
	path = str(path or '')
	if path.startswith('secrets.'):
		return (context.get('_secrets') or {}).get(path[len('secrets.'):])
	return custom_analyzers.read_path(context, path)


def render(node, context, missing = None):
	"""Resolve os placeholders de uma estrutura JSON. Puro: sem rede, sem eval.

	Percorre o template como dado, nunca como código. Uma string que é *só* um
	placeholder devolve o valor no tipo nativo — é o que faz `"severity":
	"{{severity_number}}"` sair como número. Uma string com texto em volta devolve
	string, e o escape fica por conta do `json.dumps` de quem serializa.

	As chaves também passam pela substituição: há API que nomeia campo por
	variável, e descobrir isso depois custaria uma segunda passada.

	`missing` recebe os nomes que não resolveram, para a pré-visualização poder
	dizer quais. Um placeholder inexistente vira vazio em vez de erro: o disparo
	ainda é útil sem um campo opcional, e a tela avisa.
	"""
	if isinstance(node, dict):
		return dict((render(key, context, missing), render(value, context, missing))
			for key, value in node.items())
	if isinstance(node, list):
		return [render(item, context, missing) for item in node]
	if not isinstance(node, str):
		return node

	whole = PLACEHOLDER.fullmatch(node.strip())
	if whole:
		value = resolve(whole.group(1), context)
		if value is None and missing is not None:
			missing.append(whole.group(1))
		return value

	def substitute(match):
		value = resolve(match.group(1), context)
		if value is None:
			if missing is not None:
				missing.append(match.group(1))
			return ''
		if isinstance(value, (dict, list)):
			# Uma estrutura no meio de um texto só pode virar a sua serialização;
			# é o que o usuário quer ao escrever "IOCs: {{observables}}"
			return json.dumps(value, ensure_ascii = False)
		if isinstance(value, bool):
			return 'true' if value else 'false'
		return str(value)

	return PLACEHOLDER.sub(substitute, node)


def coerce(value, value_type):
	"""O valor de um parâmetro no tipo que o usuário declarou.

	Um tipo que não casa com o valor devolve o valor como veio: o destino é quem
	sabe o que aceita, e recusar aqui trocaria um 400 legível dele por um erro
	nosso sem contexto.
	"""
	if value_type == 'number':
		try:
			text = str(value).strip()
			return int(text) if re.fullmatch(r'-?\d+', text) else float(text)
		except (TypeError, ValueError):
			return value
	if value_type == 'boolean':
		return str(value).strip().lower() in ('true', '1', 'yes', 'sim', 'on')
	if value_type == 'json':
		try:
			return json.loads(value) if isinstance(value, str) else value
		except ValueError:
			return value
	if isinstance(value, (dict, list)) or value is None:
		return value
	return str(value)


def set_path(body, path, value):
	"""Grava um valor num caminho pontilhado, criando o que faltar pelo caminho.

	É o que permite colar o JSON da documentação intacto e ajustar
	`fields.customfield_10010` por fora, na aba de parâmetros. Um segmento
	numérico indexa lista, porque `components.0.name` é forma corrente no Jira.
	"""
	parts = [p for p in str(path or '').split('.') if p != '']
	if not parts:
		return body

	current = body
	for index, part in enumerate(parts[:-1]):
		nxt = parts[index + 1]
		want_list = re.fullmatch(r'\d+', nxt) is not None
		if re.fullmatch(r'\d+', part):
			position = int(part)
			if not isinstance(current, list):
				return body
			while len(current) <= position:
				current.append([] if want_list else {})
			if not isinstance(current[position], (dict, list)):
				current[position] = [] if want_list else {}
			current = current[position]
			continue
		if not isinstance(current, dict):
			return body
		if not isinstance(current.get(part), (dict, list)):
			current[part] = [] if want_list else {}
		current = current[part]

	last = parts[-1]
	if re.fullmatch(r'\d+', last) and isinstance(current, list):
		position = int(last)
		while len(current) <= position:
			current.append(None)
		current[position] = value
	elif isinstance(current, dict):
		current[last] = value
	return body


# --------------------------------------------------------------------------- #
# Definição                                                                    #
# --------------------------------------------------------------------------- #

def make_id(name, taken):
	"""Um id estável a partir do nome, sem colidir com destino nativo nem com outro."""
	slug = re.sub(r'[^a-z0-9]+', '_', str(name or '').lower()).strip('_')
	slug = slug or 'conector'
	base = ID_PREFIX + slug[:40]
	candidate = base
	suffix = 2
	while candidate in taken or candidate in tickets.BY_ID:
		candidate = '{0}_{1}'.format(base, suffix)
		suffix += 1
	return candidate


def _validate_params(submitted, stored):
	"""(parâmetros, erro). Segredo em branco mantém o gravado, casado por local+chave."""
	previous = {}
	for param in (stored or {}).get('params') or []:
		previous[(param.get('location'), param.get('key'))] = param.get('value', '')

	params = []
	seen = set()
	for raw in (submitted.get('params') or []):
		key = str(raw.get('key', '') or '').strip()
		if not key:
			continue
		location = str(raw.get('location', 'body') or 'body')
		if location not in LOCATIONS:
			return None, 'Local inválido em "{0}": use header, query ou body.'.format(key)
		if (location, key) in seen:
			return None, 'O parâmetro "{0}" está repetido em {1}.'.format(key, location)
		seen.add((location, key))

		value_type = str(raw.get('valueType', 'string') or 'string')
		if value_type not in VALUE_TYPES:
			return None, 'Tipo inválido em "{0}": use string, number, boolean ou json.'.format(key)

		is_secret = bool(raw.get('isSecret', False))
		value = raw.get('value', '')
		if is_secret and not str(value or '').strip():
			value = previous.get((location, key), '')
			if not value:
				return None, 'O parâmetro "{0}" está marcado como secreto e está vazio.'.format(key)

		params.append({'location': location, 'key': key, 'value': value,
			'valueType': value_type, 'isSecret': is_secret})
	return params, None


def validate_definition(submitted, stored = None, taken = None):
	"""(definição, erro) para o que veio do formulário.

	Um segredo em branco significa "mantenha o que está gravado", como em todo
	outro formulário desta aplicação.
	"""
	stored = stored or {}
	taken = taken or []

	name = str(submitted.get('name', '') or '').strip()
	if not name:
		return None, 'Dê um nome ao conector.'
	if len(name) > 60:
		return None, 'O nome precisa ter no máximo 60 caracteres.'

	description = str(submitted.get('description', '') or '').strip()
	if len(description) > 400:
		return None, 'A descrição precisa ter no máximo 400 caracteres.'

	allow_internal = bool(submitted.get('allowInternal', False))

	url = str(submitted.get('url', '') or '').strip()
	# O endereço pode conter placeholder; a trava precisa julgar o host, então
	# validamos a forma sem eles. O disparo revalida o endereço já renderizado.
	ok, error = custom_analyzers.validate_destination(
		PLACEHOLDER.sub('x', url), allow_internal)
	if not ok:
		return None, error

	method = str(submitted.get('method', 'POST') or 'POST').upper()
	if method not in METHODS:
		return None, 'Método precisa ser POST, PUT ou PATCH.'

	auth_type = str(submitted.get('authType', 'none') or 'none')
	if auth_type not in AUTH_TYPES:
		return None, 'Tipo de autenticação desconhecido.'

	auth_name = str(submitted.get('authName', '') or '').strip()
	if auth_type in ('header', 'query') and not auth_name:
		return None, 'Informe o nome do cabeçalho ou do parâmetro de autenticação.'

	auth_user = str(submitted.get('authUser', '') or '').strip()
	if auth_type == 'basic' and not auth_user:
		return None, 'Informe o usuário ou e-mail da conta para autenticação basic.'

	auth_value = str(submitted.get('authValue', '') or '').strip()
	if not auth_value:
		auth_value = stored.get('authValue', '')
	if auth_type != 'none' and not auth_value:
		return None, 'Informe a credencial, ou escolha autenticação "nenhuma".'

	template = submitted.get('payloadTemplate', {})
	if isinstance(template, str):
		try:
			template = json.loads(template) if template.strip() else {}
		except ValueError:
			return None, 'O payload não é um JSON válido.'
	if not isinstance(template, (dict, list)):
		return None, 'O payload precisa ser um objeto ou uma lista JSON.'

	params, error = _validate_params(submitted, stored)
	if error:
		return None, error

	if not template and not any(p['location'] == 'body' for p in params):
		return None, ('O corpo da requisição está vazio. Cole o JSON que a ferramenta de '
			'destino exige, ou monte-o pela aba de parâmetros.')

	min_verdict = str(submitted.get('minVerdict', 'all') or 'all')
	if min_verdict not in ('all',) + tickets.VERDICTS:
		return None, 'Veredito mínimo inválido.'

	# `or` não serve aqui: 0 é um timeout inválido que precisa ser recusado, e não
	# um campo vazio que cai no padrão
	raw_timeout = submitted.get('timeout')
	if raw_timeout in (None, ''):
		raw_timeout = DEFAULT_TIMEOUT
	try:
		timeout = int(raw_timeout)
	except (TypeError, ValueError):
		return None, 'O timeout precisa ser um número de segundos.'
	if not 1 <= timeout <= 60:
		return None, 'O timeout precisa estar entre 1 e 60 segundos.'

	success = []
	for status in (submitted.get('successStatus') or DEFAULT_SUCCESS_STATUS):
		try:
			success.append(int(status))
		except (TypeError, ValueError):
			return None, 'Status de sucesso inválido: {0}.'.format(status)
	if not success:
		return None, 'Informe ao menos um status HTTP de sucesso.'

	definition = {
		'id': stored.get('id') or make_id(name, taken),
		'enabled': bool(submitted.get('enabled', False)),
		'name': name,
		'description': description,
		'method': method,
		'url': url,
		'allowInternal': allow_internal,
		'verifyTls': bool(submitted.get('verifyTls', True)),
		'timeout': timeout,
		'contentType': str(submitted.get('contentType', 'application/json') or 'application/json'),
		'authType': auth_type,
		'authName': auth_name,
		'authUser': auth_user,
		'authValue': auth_value,
		'params': params,
		'payloadTemplate': template,
		'minVerdict': min_verdict,
		'resultRefPath': str(submitted.get('resultRefPath', '') or '').strip(),
		'successStatus': success
	}
	return definition, None


def public_definition(definition):
	"""A definição como o navegador pode vê-la: nunca com credencial nem segredo."""
	public = dict(definition)
	public.pop('authValue', None)
	public['hasAuthValue'] = bool(definition.get('authValue'))
	public['params'] = [
		dict(param, value = '' if param.get('isSecret') else param.get('value', ''),
			hasValue = bool(param.get('value')))
		for param in definition.get('params') or []]
	return public


def basic_header(definition):
	"""O valor do cabeçalho Authorization para autenticação basic."""
	pair = '{0}:{1}'.format(definition.get('authUser', ''), definition.get('authValue', ''))
	return 'Basic ' + base64.b64encode(pair.encode('utf-8')).decode('ascii')


def secret_values(definition):
	"""Todo segredo desta definição. É por estes valores que a redação procura.

	O basic entra aqui **duas vezes**: o token cru e a sua forma base64. Procurar
	só pelo cru deixaria a credencial passar inteira para a tela — base64 não é
	cifra, é codificação, e `usuario:senha` volta com uma linha de Python. O
	bearer não precisa disso porque o token aparece literal dentro do cabeçalho.
	"""
	values = []
	if definition.get('authValue'):
		values.append(str(definition['authValue']))
		if definition.get('authType') == 'basic':
			values.append(basic_header(definition)[len('Basic '):])
	for param in definition.get('params') or []:
		if param.get('isSecret') and param.get('value'):
			values.append(str(param['value']))
	return values


def secret_map(definition):
	"""Os segredos por chave, para `{{secrets.<chave>}}` dentro de um texto maior."""
	return dict((param['key'], param.get('value', ''))
		for param in definition.get('params') or [] if param.get('isSecret'))


# --------------------------------------------------------------------------- #
# Persistência                                                                 #
# --------------------------------------------------------------------------- #

def load_all(path = None, section = None):
	"""As definições gravadas. Uma configuração sem a seção devolve lista vazia.

	`section` existe para os webhooks do alerta de volume (volume_alerts.py), que
	são conectores com a mesma forma gravados em outra seção: um conector de
	análise não recebe alerta, e um de alerta não recebe relatório.
	"""
	path = path or CONFIG_FILE
	try:
		with open(path) as conf_file:
			stored = json.load(conf_file).get(section or CONFIG_SECTION, [])
	except Exception:
		return []
	if not isinstance(stored, list):
		return []
	return [d for d in stored if isinstance(d, dict) and d.get('id')]


def save_all(definitions, path = None, section = None):
	path = path or CONFIG_FILE
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[section or CONFIG_SECTION] = definitions
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def find(definitions, connector_id):
	for definition in definitions:
		if definition.get('id') == connector_id:
			return definition
	return None


# --------------------------------------------------------------------------- #
# Montagem da requisição                                                       #
# --------------------------------------------------------------------------- #

def redact(value, secrets):
	"""O mesmo valor sem nenhum segredo dentro, para o histórico e o log.

	A redação é pelo *valor*, não pelo nome do campo: um token colado no meio de
	uma string de texto livre não seria pego por uma lista de nomes. Segredos
	curtos demais são deixados de lado de propósito — trocar toda ocorrência de
	uma sequência de três caracteres deixaria o registro ilegível sem proteger
	nada que já não estivesse exposto.
	"""
	text = json.dumps(value, ensure_ascii = False)
	for secret in sorted([str(s) for s in secrets if s], key = len, reverse = True):
		if len(secret) >= 6:
			text = text.replace(secret, '***')
	return json.loads(text)


def apply_auth(definition, headers, params):
	"""A credencial no lugar que a ferramenta de destino espera."""
	auth_type = definition.get('authType', 'none')
	secret = definition.get('authValue', '')
	if auth_type == 'bearer':
		headers['Authorization'] = 'Bearer ' + secret
	elif auth_type == 'basic':
		headers['Authorization'] = basic_header(definition)
	elif auth_type == 'header':
		headers[definition.get('authName', '')] = secret
	elif auth_type == 'query':
		params[definition.get('authName', '')] = secret


def build_request(definition, context):
	"""(url, headers, params, body, faltando). Puro — é o que a tela pré-visualiza."""
	missing = []
	url = render(definition.get('url', ''), context, missing)
	url = str(url or '')

	body = render(definition.get('payloadTemplate', {}), context, missing)
	headers = {'Content-Type': definition.get('contentType', 'application/json')}
	params = {}

	for param in definition.get('params') or []:
		value = render(param.get('value', ''), context, missing)
		location = param.get('location', 'body')
		if location == 'header':
			headers[str(param['key'])] = '' if value is None else str(value)
		elif location == 'query':
			params[str(param['key'])] = '' if value is None else str(value)
		else:
			if not isinstance(body, dict):
				# Um template que é lista não tem onde receber um caminho
				# pontilhado; dizer isso é melhor do que descartar em silêncio
				raise ConnectorError('O parâmetro "{0}" grava no corpo, mas o payload não é um '
					'objeto JSON.'.format(param['key']))
			set_path(body, param['key'], coerce(value, param.get('valueType', 'string')))

	apply_auth(definition, headers, params)
	return url, headers, params, body, missing


def sample_report(verdict = 'Malicious'):
	"""Um relatório de exemplo, para a pré-visualização e o botão Testar.

	Os valores são visivelmente de exemplo — `exemplo.invalid` é um domínio que
	não pode existir. Um conector testado contra dado de mentira que *parece*
	verdadeiro acaba abrindo chamado que o SOC trata como real.
	"""
	return {
		'subject': '[EXEMPLO] Sua conta será suspensa em 24h',
		'verdict': verdict,
		'reporter': 'exemplo@exemplo.invalid',
		'department': 'Exemplo',
		'analyzedAt': datetime.datetime.now().replace(microsecond = 0).isoformat(),
		'caseRef': '',
		'observables': [
			{'id': '1', 'type': 'url', 'value': 'http://exemplo.invalid/login', 'tags': [],
			 'message': 'exemplo de resposta de analisador', 'ioc': True,
			 'malicious': True, 'suspicious': False},
			{'id': '2', 'type': 'domain', 'value': 'exemplo.invalid', 'tags': [],
			 'message': '', 'ioc': True, 'malicious': True, 'suspicious': False}
		],
		'findings': [{'observableType': 'url', 'observable': 'http://exemplo.invalid/login',
			'analyzer': 'Exemplo', 'level': 'malicious', 'detail': 'exemplo', 'error': ''}],
		'llm': {'summary': 'Exemplo de avaliação de engenharia social.'},
		'authentication': None,
		'body': 'Corpo de exemplo do e-mail analisado.'
	}


def preview(definition, report, context_builder = None):
	"""O que sairia, sem sair. Segredos mascarados — isto volta para o navegador."""
	context = (context_builder or context_from_report)(report, secret_map(definition))
	url, headers, params, body, missing = build_request(definition, context)
	secrets = secret_values(definition)
	return {
		'method': definition.get('method', 'POST'),
		'url': url,
		'headers': redact(headers, secrets),
		'params': redact(params, secrets),
		'body': redact(body, secrets),
		'missing': sorted(set(missing)),
		'bytes': len(json.dumps(body, ensure_ascii = False).encode('utf-8'))
	}


# --------------------------------------------------------------------------- #
# Execução                                                                     #
# --------------------------------------------------------------------------- #

def _read_timeout(definition):
	"""O timeout de leitura gravado, ou o padrão. `deliver` recebe a definição do
	disco, e uma seção de configuração editada à mão pode trazer qualquer coisa —
	`requests` levantaria ValueError antes mesmo de abrir a conexão."""
	try:
		value = int(definition.get('timeout', DEFAULT_TIMEOUT))
	except (TypeError, ValueError):
		return DEFAULT_TIMEOUT
	return value if 1 <= value <= 60 else DEFAULT_TIMEOUT


def _failure(message, retryable = False):
	return {'ok': False, 'ref': '', 'detail': '', 'error': message, 'retryable': retryable,
		'status': 0, 'latencyMs': 0}


def classify(definition, status_code, payload, text):
	"""O resultado a partir da resposta. "2xx" não basta, e cada caso tem conduta."""
	success = definition.get('successStatus') or list(DEFAULT_SUCCESS_STATUS)
	if status_code in success:
		ref = ''
		path = definition.get('resultRefPath', '')
		if path and payload is not None:
			found = custom_analyzers.read_path(payload, path)
			ref = '' if found is None else str(found)
		detail = 'registrado ({0})'.format(status_code)
		if ref:
			detail = 'registrado como {0}'.format(ref)
		return {'ok': True, 'ref': ref, 'detail': detail, 'error': '', 'retryable': False}

	if status_code in (401, 403):
		return _failure('O destino recusou a credencial (HTTP {0}).'.format(status_code))
	if status_code in (400, 422):
		# O corpo da resposta é a única coisa que diz *qual* campo faltou, e essa
		# frase é o que o analista precisa ler para corrigir o payload
		return _failure('O destino recusou o payload (HTTP {0}): {1}'.format(
			status_code, (text or '')[:400]))
	if status_code == 404:
		return _failure('O destino respondeu 404 — confira a URL e a versão da API.')
	if status_code == 429:
		return _failure('Limite de requisições do destino atingido (429).', retryable = True)
	if status_code in (301, 302, 303, 307, 308):
		return _failure('O destino respondeu com um redirecionamento, que não é seguido — '
			'o endereço de destino não passaria pela validação.')
	if status_code >= 500:
		return _failure('O destino respondeu HTTP {0}.'.format(status_code), retryable = True)
	return _failure('O destino respondeu HTTP {0}, que não está entre os status de sucesso '
		'configurados.'.format(status_code))


def deliver(definition, report, context_builder = None):
	"""Dispara um conector. Nunca levanta.

	Mesmo contrato de `tickets.create()`: quando isto roda o veredito já foi
	decidido e a análise já terminou. Um destino fora do ar vira aviso no log,
	nunca uma exceção que desfaz o trabalho.

	`context_builder` troca o que as variáveis enxergam — o alerta de volume
	passa o dele — sem trocar nada do caminho de disparo: a trava de destino, o
	teto de corpo e a recusa de redirect valem para os dois.
	"""
	name = definition.get('name', 'Conector')
	secrets = secret_values(definition)

	try:
		context = (context_builder or context_from_report)(report, secret_map(definition))
		url, headers, params, body, missing = build_request(definition, context)
	except ConnectorError as error:
		return _failure(str(error))
	except Exception:
		print("[ERROR]_[connectors]: rendering {0} failed: {1}".format(
			definition.get('id'), traceback.format_exc()))
		return _failure('Não foi possível montar a requisição de {0}.'.format(name))

	# Revalidação do destino NO DISPARO, não só ao salvar. Um nome que resolvia
	# para um endereço público quando o conector foi gravado pode passar a
	# resolver para dentro da rede — e é a resolução deste instante que decide
	# para onde o pacote vai. A liberação da rede interna é lida da definição
	# gravada: quem decidiu isso decidiu uma vez, com auditoria.
	ok, error = custom_analyzers.validate_destination(url, definition.get('allowInternal', False))
	if not ok:
		return _failure('Destino recusado: {0}'.format(error))

	try:
		encoded = json.dumps(body, ensure_ascii = False).encode('utf-8')
	except (TypeError, ValueError):
		return _failure('O corpo renderizado não é serializável como JSON.')
	if len(encoded) > MAX_BODY_BYTES:
		return _failure('O corpo renderizado tem {0} KB e o limite é {1} KB.'.format(
			len(encoded) // 1024, MAX_BODY_BYTES // 1024))

	started = datetime.datetime.now()
	try:
		# Fixado no endereço que a trava aprovou: um nome que responde diferente
		# à validação e à conexão não leva o disparo para dentro da rede
		response = pinned_http.request(
			definition.get('method', 'POST'), url, definition.get('allowInternal', False),
			headers = headers, params = params, data = encoded,
			timeout = (CONNECT_TIMEOUT, _read_timeout(definition)),
			# Seguir um redirecionamento levaria a um destino que nunca passou
			# pela trava acima
			allow_redirects = False,
			verify = definition.get('verifyTls', True))
	except pinned_http.DestinationRefused as refused:
		return _failure('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		return _failure('Falha na validação do certificado TLS do destino.')
	except requests.exceptions.Timeout:
		return _failure('{0} não respondeu dentro do tempo limite.'.format(name), retryable = True)
	except requests.exceptions.ConnectionError:
		return _failure('Não foi possível alcançar {0}.'.format(url), retryable = True)
	except Exception:
		print("[ERROR]_[connectors]: {0} failed: {1}".format(
			definition.get('id'), traceback.format_exc()))
		return _failure('{0} devolveu uma resposta inesperada.'.format(name))

	latency = int((datetime.datetime.now() - started).total_seconds() * 1000)
	text = (response.text or '')[:MAX_RESPONSE_CHARS]
	try:
		payload = response.json()
	except ValueError:
		payload = None

	outcome = classify(definition, response.status_code, payload, text)
	outcome['status'] = response.status_code
	outcome['latencyMs'] = latency
	outcome['missing'] = sorted(set(missing))
	# O request fica no resultado já redigido, porque quem o registra a seguir
	# não deveria precisar lembrar de redigir
	outcome['request'] = redact({'url': url, 'headers': headers, 'body': body}, secrets)
	outcome['response'] = text
	return outcome


def accepts_verdict(definition, verdict):
	return tickets.accepts_verdict(definition.get('minVerdict', 'all'), verdict)


def enabled_for(verdict, definitions = None):
	"""As definições habilitadas que agem sobre este veredito."""
	definitions = load_all() if definitions is None else definitions
	return [d for d in definitions if d.get('enabled') and accepts_verdict(d, verdict)]


def dispatch(report, definitions = None):
	"""Entrega o report a todo conector habilitado. Devolve [(id, resultado)].

	Um conector que falha não impede os outros: quem tem Splunk e Slack ligados
	precisa que o Slack avise mesmo com o Splunk fora do ar.
	"""
	results = []
	for definition in enabled_for(report.get('verdict'), definitions):
		results.append((definition['id'], deliver(definition, report)))
	return results
