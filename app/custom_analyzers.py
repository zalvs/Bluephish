"""Analisadores definidos pelo analista — o fornecedor que a gente não previu.

O registro de `analyzers.py` cobre doze fornecedores escolhidos a dedo. Quem já
paga um serviço de reputação que não está lá não tem como usá-lo sem esperar que
alguém escreva o cliente. Este módulo fecha essa lacuna: uma definição gravada em
configuração vira um analisador de primeira classe, com card, formulário, botão
Testar e o mesmo contrato de nível dos nativos.

O que muda em relação a um nativo, e por que importa
----------------------------------------------------
Um analisador nativo chama um endereço que está no código-fonte. Um customizado
chama um endereço que alguém digitou na tela. Isso é SSRF por construção: sem
trava, o servidor viraria um proxy para a rede interna, e como o que se manda no
lugar de `{value}` são os observáveis do e-mail da vítima, viraria também um
caminho de exfiltração.

Daí as três travas, nesta ordem:

  1. só admin cria (as rotas já são @requires_admin);
  2. `validate_destination()` recusa qualquer destino que não seja HTTPS público;
  3. a validação roda de novo na hora de chamar, não só na hora de salvar.

O passo 3 é o que costuma faltar. Validar só ao salvar deixa passar o caso em que
o nome resolvia para um IP público naquele instante e passa a resolver para
169.254.169.254 depois — o servidor de metadados da nuvem, onde moram as
credenciais da instância.

Contrato de veredito
--------------------
O analista aponta um caminho na resposta JSON e mapeia valores para níveis:
`"malicious" -> malicioso`, `"clean" -> safe`. O que não casar com nenhuma regra
cai no nível de reserva, que por padrão é `info` — porque um valor que a gente não
sabe ler não é um atestado de limpeza.
"""

import ipaddress
import socket
import re

import requests

import analyzers


# Mesmo par de timeouts dos nativos: um destino firewalled falha rápido, um lento
# mas vivo é esperado
HTTP_TIMEOUT = analyzers.HTTP_TIMEOUT

CONFIG_SECTION = 'custom_analyzers'

# Um teto existe para que a tela continue navegável e para que um erro de
# automação não encha a configuração
MAX_CUSTOM = 20

OBSERVABLE_TYPES = ('ip', 'domain', 'url', 'hash', 'mail', 'file')

# 'file' fica de fora de propósito: mandar um arquivo para um endereço arbitrário
# é exatamente a exfiltração que este módulo existe para evitar
ALLOWED_OBSERVABLES = ('ip', 'domain', 'url', 'hash', 'mail')

AUTH_TYPES = ('none', 'header', 'query', 'bearer')

METHODS = ('GET', 'POST')

# O id é gerado a partir do nome, e precisa não colidir com um analisador nativo
ID_PREFIX = 'custom_'


# --------------------------------------------------------------------------- #
# Trava de destino                                                             #
# --------------------------------------------------------------------------- #

# O serviço de metadados da nuvem. Nunca é um analisador, e é o alvo de maior
# valor de um SSRF: é ali que moram as credenciais da instância. Continua barrado
# mesmo com a rede interna liberada.
# 100.100.100.200 é o da Alibaba Cloud, e fica na faixa CGNAT — que um MISP
# interno numa rede Tailscale também usa, então é recusado pelo endereço exato.
METADATA_ADDRESSES = ('169.254.169.254', 'fd00:ec2::254', '100.100.100.200')

# IPv6 que carrega um IPv4 dentro: o pacote vai para o IPv4, então é ele que se julga
NAT64 = ipaddress.ip_network('64:ff9b::/96')


def _embedded_ipv4(address):
	"""O IPv4 que um IPv6 carrega (mapeado, NAT64, 6to4), ou o próprio endereço."""
	if address.version != 6:
		return address
	if address.ipv4_mapped is not None:
		return address.ipv4_mapped
	if address.sixtofour is not None:
		return address.sixtofour
	if address in NAT64:
		return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
	return address


def _canonical(ip_text):
	"""O endereço como o pacote o vê — IPv4 embutido desembrulhado —, ou None."""
	try:
		# O sufixo de zona (fe80::1%eth0) não muda para onde o pacote vai
		return _embedded_ipv4(ipaddress.ip_address(str(ip_text).split('%')[0]))
	except ValueError:
		return None


def is_metadata_address(ip_text):
	address = _canonical(ip_text)
	# str() de um ipaddress é a forma canônica, a mesma da lista
	return address is not None and str(address) in METADATA_ADDRESSES


def _is_forbidden_address(ip_text, allow_internal = False):
	"""Endereço que o analisador não pode alcançar.

	Com `allow_internal`, a rede privada e o loopback passam a ser permitidos —
	é o que faz um MISP on-prem ou um TIP interno serem alcançáveis. O serviço de
	metadados não passa em hipótese alguma.

	Sem ela, a regra é `is_global`: o que não é internet pública fica de fora. A
	soma anterior (is_private, is_loopback, ...) esquecia 100.64.0.0/10 no
	Python 3.8 da imagem, e comparava o endereço de metadados como texto — uma
	grafia não canônica, ou o mesmo IPv4 dentro de um IPv6, passava.
	"""
	address = _canonical(ip_text)
	if address is None:
		return True

	if is_metadata_address(ip_text):
		return True

	if allow_internal:
		# Multicast e "não especificado" seguem barrados: nenhum dos dois é um
		# endpoint ao qual se faça uma consulta
		return address.is_multicast or address.is_unspecified

	return ((not address.is_global) or address.is_multicast
		or getattr(address, 'is_site_local', False))


def validate_destination(url, allow_internal = False, require_https = True):
	"""(ok, erro) para o endereço que o analisador vai chamar.

	Roda ao salvar E antes de cada chamada. A segunda vez não é zelo excessivo: um
	nome que resolvia para um IP público na hora de salvar pode passar a resolver
	para a rede interna depois, e é a resolução do momento da chamada que decide
	para onde o pacote vai.

	São duas travas, e elas protegem coisas diferentes:

	  * **o esquema** protege o que *sai* na requisição. Um analisador manda a
	    credencial e o observável, e em http os dois vão em claro. Quem não manda
	    nem um nem outro — o unshortener, que só faz um HEAD numa URL que já
	    estava no e-mail — passa `require_https = False`: exigir https ali não
	    protegeria nada e deixaria de resolver todo encurtador em http, que é
	    justamente o caso comum.

	  * **o endereço** protege para *onde* a requisição vai, e essa nunca é
	    dispensada: rede interna só com `allow_internal`, e o serviço de metadados
	    da nuvem em hipótese nenhuma.
	"""
	url = str(url or '').strip()
	if not url:
		return False, 'Informe o endereço que o analisador deve consultar.'

	lowered = url.lower()
	if allow_internal or not require_https:
		# Um serviço interno costuma não ter TLS, ou ter certificado próprio. Exigir
		# https aqui tornaria a liberação da rede interna inútil na prática.
		if not lowered.startswith(('https://', 'http://')):
			return False, 'O endereço precisa começar com https:// ou http://.'
	elif not lowered.startswith('https://'):
		return False, ('O endereço precisa começar com https:// — em http o observável e a '
			'credencial trafegam em claro. Para um serviço interno sem TLS, marque '
			'"permitir rede interna".')

	try:
		from urllib.parse import urlparse
		parsed = urlparse(url)
	except Exception:
		return False, 'Endereço inválido.'

	host = parsed.hostname or ''
	if not host:
		return False, 'Endereço sem host.'

	def refusal(host, candidate = None):
		where = '{0} resolve para {1}, que'.format(host, candidate) if candidate else '{0}'.format(host)
		if candidate is None:
			where = '{0}'.format(host)
		if is_metadata_address(candidate or host):
			return ('{0} é o serviço de metadados da nuvem, onde ficam as credenciais da '
				'instância. Esse destino é recusado mesmo com a rede interna liberada.'.format(
					candidate or host))
		if allow_internal:
			return '{0} não é um destino ao qual se possa fazer uma consulta.'.format(candidate or host)
		return ('{0} não é um endereço público. Marque "permitir rede interna" se este '
			'analisador aponta mesmo para dentro da sua rede.'.format(where))

	# Um IP digitado direto dispensa resolução, mas não dispensa a checagem
	try:
		ipaddress.ip_address(host)
		if _is_forbidden_address(host, allow_internal):
			return False, refusal(host)
		return True, None
	except ValueError:
		pass

	try:
		resolved = socket.getaddrinfo(host, None)
	except socket.gaierror:
		return False, 'Não consegui resolver o nome {0}.'.format(host)

	# Um nome pode resolver para vários endereços; basta um proibido para recusar,
	# porque não se controla qual deles a chamada vai usar
	for info in resolved:
		candidate = info[4][0]
		if _is_forbidden_address(candidate, allow_internal):
			return False, refusal(host, candidate)
	return True, None


# --------------------------------------------------------------------------- #
# Definição                                                                    #
# --------------------------------------------------------------------------- #

def make_id(name, taken):
	"""Um id estável a partir do nome, sem colidir com nativo nem com outro custom."""
	slug = re.sub(r'[^a-z0-9]+', '_', str(name or '').lower()).strip('_')
	slug = slug or 'analisador'
	base = ID_PREFIX + slug[:40]
	candidate = base
	suffix = 2
	while candidate in taken or candidate in analyzers.BY_ID:
		candidate = '{0}_{1}'.format(base, suffix)
		suffix += 1
	return candidate


def validate_definition(submitted, stored = None, taken = None):
	"""(definição, erro) para o que veio do formulário.

	Um segredo em branco significa "mantenha o que está gravado", como em todo
	outro formulário desta aplicação.
	"""
	stored = stored or {}
	taken = taken or []

	name = str(submitted.get('name', '') or '').strip()
	if not name:
		return None, 'Dê um nome ao analisador.'
	if len(name) > 60:
		return None, 'O nome precisa ter no máximo 60 caracteres.'

	description = str(submitted.get('description', '') or '').strip()
	if len(description) > 400:
		return None, 'A descrição precisa ter no máximo 400 caracteres.'

	allow_internal = bool(submitted.get('allowInternal', False))

	url = str(submitted.get('url', '') or '').strip()
	ok, error = validate_destination(url, allow_internal)
	if not ok:
		return None, error
	if '{value}' not in url:
		return None, ('O endereço precisa conter {value} — é onde o observável entra na '
			'consulta. Exemplo: https://api.exemplo.com/v1/lookup?indicator={value}')

	method = str(submitted.get('method', 'GET') or 'GET').upper()
	if method not in METHODS:
		return None, 'Método precisa ser GET ou POST.'

	auth_type = str(submitted.get('authType', 'none') or 'none')
	if auth_type not in AUTH_TYPES:
		return None, 'Tipo de autenticação desconhecido.'

	auth_name = str(submitted.get('authName', '') or '').strip()
	if auth_type in ('header', 'query') and not auth_name:
		return None, 'Informe o nome do cabeçalho ou do parâmetro de autenticação.'

	# Segredo em branco mantém o gravado
	auth_value = str(submitted.get('authValue', '') or '').strip()
	if not auth_value:
		auth_value = stored.get('authValue', '')
	if auth_type != 'none' and not auth_value:
		return None, 'Informe a credencial, ou escolha autenticação "nenhuma".'

	observables = [o for o in (submitted.get('observables') or []) if o in ALLOWED_OBSERVABLES]
	if not observables:
		return None, ('Escolha ao menos um tipo de observável. Arquivos não estão disponíveis '
			'para analisador customizado: enviar o anexo a um endereço arbitrário é justamente '
			'o que esta tela não faz.')

	value_path = str(submitted.get('valuePath', '') or '').strip()
	if not value_path:
		return None, ('Informe o caminho do valor na resposta. Exemplo: data.attributes.classification')

	rules = []
	for rule in (submitted.get('levelMap') or []):
		when = str(rule.get('value', '') or '').strip()
		level = str(rule.get('level', '') or '').strip()
		if not when:
			continue
		if level not in analyzers.LEVELS:
			return None, 'Nível inválido em "{0}": use info, safe, suspicious ou malicious.'.format(when)
		rules.append({'value': when, 'level': level})
	if not rules:
		return None, ('Mapeie ao menos um valor para um nível — é isso que transforma a resposta '
			'do fornecedor em veredito.')

	fallback = str(submitted.get('fallbackLevel', 'info') or 'info')
	if fallback not in analyzers.LEVELS:
		return None, 'Nível de reserva inválido.'

	definition = {
		'id': stored.get('id') or make_id(name, taken),
		'enabled': bool(submitted.get('enabled', False)),
		'name': name,
		'description': description,
		'allowInternal': allow_internal,
		'url': url,
		'method': method,
		'authType': auth_type,
		'authName': auth_name,
		'authValue': auth_value,
		'observables': observables,
		'valuePath': value_path,
		'levelMap': rules,
		'fallbackLevel': fallback
	}
	return definition, None


def to_spec(definition):
	"""A definição na forma do registro, para a tela renderizar sem saber a diferença."""
	return {
		'id': definition['id'],
		'family': 'custom',
		'name': definition['name'],
		'kind': 'rede interna' if definition.get('allowInternal') else 'definido por você',
		# A descrição do analista ganha da gerada: ela diz por que o analisador
		# existe, e a gerada só sabe repetir para onde ele aponta
		'description': definition.get('description') or (
			'Analisador customizado apontando para {0}. O veredito sai do mapa de valores '
			'que você definiu.'.format(_host_of(definition.get('url', '')))),
		'docs': '',
		'observables': definition.get('observables', []),
		'credentials': [],
		'thresholds': [],
		'custom': True,
		'testPlaceholder': 'um observável dos tipos que este analisador aceita'
	}


def _host_of(url):
	try:
		from urllib.parse import urlparse
		return urlparse(url).hostname or url
	except Exception:
		return url


def public_definition(definition):
	"""A definição como o navegador pode vê-la: nunca com a credencial."""
	public = dict(definition)
	public.pop('authValue', None)
	public['hasAuthValue'] = bool(definition.get('authValue'))
	return public


# --------------------------------------------------------------------------- #
# Persistência                                                                 #
# --------------------------------------------------------------------------- #

def load_all(path = None):
	"""As definições gravadas. Uma configuração sem a seção devolve lista vazia."""
	import json
	path = path or analyzers.CONFIG_FILE
	try:
		with open(path) as conf_file:
			stored = json.load(conf_file).get(CONFIG_SECTION, [])
	except Exception:
		return []
	if not isinstance(stored, list):
		return []
	return [d for d in stored if isinstance(d, dict) and d.get('id')]


def save_all(definitions, path = None):
	import json
	path = path or analyzers.CONFIG_FILE
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[CONFIG_SECTION] = definitions
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def find(definitions, analyzer_id):
	for definition in definitions:
		if definition.get('id') == analyzer_id:
			return definition
	return None


# --------------------------------------------------------------------------- #
# Execução                                                                     #
# --------------------------------------------------------------------------- #

def read_path(payload, path):
	"""Segue um caminho pontilhado dentro da resposta. Índice de lista também vale."""
	current = payload
	for part in str(path or '').split('.'):
		if part == '':
			continue
		if isinstance(current, list):
			try:
				current = current[int(part)]
				continue
			except (ValueError, IndexError):
				return None
		if isinstance(current, dict):
			if part not in current:
				return None
			current = current[part]
			continue
		return None
	return current


def level_from_map(definition, signal):
	"""Nível a partir do mapa de valores. Puro, e é a parte que os testes fixam."""
	if signal is None:
		return 'info'
	value = signal.get('value')
	if value is None:
		return definition.get('fallbackLevel', 'info')
	text = str(value).strip().lower()
	for rule in definition.get('levelMap', []):
		if str(rule['value']).strip().lower() == text:
			return rule['level']
	return definition.get('fallbackLevel', 'info')


def query(definition, observable_type, value):
	"""Chama o endereço definido e extrai o valor. Levanta AnalyzerError ao falhar."""
	url = definition.get('url', '')

	# Revalidação na hora da chamada — ver o docstring do módulo. A liberação da
	# rede interna é lida da definição gravada, não do que veio na requisição:
	# quem decide isso é quem salvou o analisador, uma vez, com auditoria.
	ok, error = validate_destination(url, definition.get('allowInternal', False))
	if not ok:
		raise analyzers.AnalyzerError('Destino recusado: {0}'.format(error))

	from urllib.parse import quote
	target = url.replace('{value}', quote(str(value), safe = ''))

	headers = {'Accept': 'application/json'}
	params = {}
	auth_type = definition.get('authType', 'none')
	secret = definition.get('authValue', '')
	if auth_type == 'header':
		headers[definition.get('authName', '')] = secret
	elif auth_type == 'bearer':
		headers['Authorization'] = 'Bearer ' + secret
	elif auth_type == 'query':
		params[definition.get('authName', '')] = secret

	# Importado aqui porque pinned_http importa este módulo (a regra de endereço
	# é uma só, e mora acima)
	import pinned_http
	allow_internal = definition.get('allowInternal', False)
	try:
		if definition.get('method', 'GET') == 'POST':
			response = pinned_http.post(target, allow_internal, headers = headers, params = params,
				json = {'value': value, 'type': observable_type},
				timeout = HTTP_TIMEOUT, allow_redirects = False)
		else:
			response = pinned_http.get(target, allow_internal, headers = headers, params = params,
				timeout = HTTP_TIMEOUT, allow_redirects = False)
	except pinned_http.DestinationRefused as refused:
		# A trava acima aprovou o nome; a conexão ouviu outra resposta do DNS
		raise analyzers.AnalyzerError('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		raise analyzers.AnalyzerError('Falha na validação do certificado TLS do destino.')

	# Redirecionamento é recusado em vez de seguido: seguir levaria a um destino
	# que nunca passou pela trava
	if response.status_code in (301, 302, 303, 307, 308):
		raise analyzers.AnalyzerError('O destino respondeu com um redirecionamento, que não é '
			'seguido — o endereço de destino não passaria pela validação.')
	if response.status_code in (401, 403):
		raise analyzers.AnalyzerError('O fornecedor recusou a credencial (HTTP {0}).'.format(
			response.status_code))
	if response.status_code == 429:
		raise analyzers.AnalyzerError('Limite de consultas do fornecedor atingido (429).')
	response.raise_for_status()

	try:
		payload = response.json()
	except ValueError:
		raise analyzers.AnalyzerError('A resposta do fornecedor não é JSON.')

	extracted = read_path(payload, definition.get('valuePath', ''))
	return {'value': extracted, 'path': definition.get('valuePath', '')}


def describe(definition, signal):
	"""Uma linha sobre o que o analisador viu."""
	if signal is None:
		return 'sem resposta'
	if signal.get('value') is None:
		return 'o caminho {0} não existe na resposta'.format(signal.get('path', ''))
	return '{0} = {1}'.format(signal.get('path', ''), signal.get('value'))


def run(definition, observable_type, value):
	"""Julga um observável. Nunca levanta: falha vira 'info' com o motivo junto."""
	if not definition.get('enabled'):
		return {'level': 'info', 'signal': None, 'detail': '', 'error': 'Analisador desabilitado.'}
	if observable_type.split('_')[0] not in definition.get('observables', []):
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} não avalia observáveis do tipo {1}.'.format(
				definition.get('name', ''), observable_type)}
	try:
		signal = query(definition, observable_type.split('_')[0], value)
	except analyzers.AnalyzerError as error:
		return {'level': 'info', 'signal': None, 'detail': '', 'error': str(error)}
	except requests.exceptions.Timeout:
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} não respondeu dentro do tempo limite.'.format(definition.get('name', ''))}
	except Exception:
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} devolveu uma resposta inesperada.'.format(definition.get('name', ''))}

	return {
		'level': level_from_map(definition, signal),
		'signal': signal,
		'detail': describe(definition, signal),
		'error': ''
	}
