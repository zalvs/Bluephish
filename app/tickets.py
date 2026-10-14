"""Para onde vai o resultado de uma análise.

O TheHive já foi a espinha disto: o caso nascia antes da análise, os observáveis
eram gravados nele e lidos de volta, e cada job de analisador era chaveado pelo
id que ele atribuía. Não é mais. Os observáveis vivem em memória do parse ao
veredito (`run_analysis`), e este módulo é o único ponto do processo que fala com
qualquer sistema externo de registro.

Com isso o TheHive vira um destino como os outros, e a pergunta "onde isto fica
registrado" passa a ter três respostas combináveis: TheHive, Jira, disco, os três
ou nenhum.

E "como os outros" vale para a leitura também. As telas de Casos, Phishing e
Executivo liam do TheHive e de mais nada, o que fazia de uma instalação que grava
em disco — que é exatamente para quem o destino Disco existe — uma instalação que
analisava o dia inteiro e via a tela vazia. Elas leem dos destinos **habilitados**
agora, via `history.py`. Cada destino responde pelo que de fato guarda: o disco
guarda o report inteiro em JSON, o TheHive guarda caso e observáveis, e a issue
do Jira guarda veredito, assunto e data como campo e o resto como prosa — então
quem lê dela reporta observável como desconhecido, nunca como zero.

Forma do módulo, espelhando `analyzers.py` e `responders.py` de propósito:

  DESTINATIONS   registro declarativo — identidade, campos de credencial e
                 ajustes. A tela monta card e formulário daqui.

  build_report() normaliza o resultado da análise em dado puro. É a fronteira:
                 nada aqui é objeto do TheHive, e é por isso que um destino novo
                 não precisa saber que ele existe.

  create()       entrega um report a um destino. Nunca levanta: o veredito já
                 foi decidido, e um Jira fora do ar não pode desfazer a análise.

  probe()        verifica credencial e alcance sem criar ticket nenhum. Um botão
                 Testar que abrisse chamado de verdade seria armadilha — a mesma
                 razão que separa probe de run em `responders.py`.

  dispatch()     roda todos os destinos habilitados que aceitam este veredito.
"""

import datetime
import io
import json
import os
import re
import traceback

import requests

import pinned_http

import analyzers
import case_insights
import custom_analyzers

HTTP_TIMEOUT = analyzers.HTTP_TIMEOUT

CONFIG_FILE = analyzers.CONFIG_FILE
CONFIG_SECTION = 'ticketing'

# Os vereditos, do mais fraco ao mais forte. Um destino declara o mínimo que o
# faz agir, e a ordem é o que torna "a partir de suspeito" comparável.
VERDICTS = ('Safe', 'Suspicious', 'Malicious')

VERDICT_LABEL = {
	'all': 'todo e-mail analisado',
	'Suspicious': 'suspeito ou malicioso',
	'Malicious': 'somente malicioso'
}


# --------------------------------------------------------------------------- #
# Registro                                                                     #
# --------------------------------------------------------------------------- #

DESTINATIONS = [
	{
		'id': 'thehive',
		'name': 'TheHive',
		'kind': 'gestão de casos',
		'description': 'Cria o caso com os observáveis já marcados, o relatório dos analisadores '
			'na task de análise e o veredito aplicado. Deixa aberto o que ficou suspeito e resolve '
			'o resto. As telas de Casos, Phishing e Executivo leem daqui — e de todo outro destino '
			'habilitado; se este for o único ligado, desligá-lo esvazia as três.',
		'docs': 'https://docs.strangebee.com/thehive/api-docs/',
		# O endereço e a chave ficam aqui, como em todo outro destino. Já estiveram
		# de fora, quando existia um segundo card do TheHive escrito à mão só para
		# eles — dois formulários gravando o mesmo campo. O card foi removido, e a
		# assimetria com ele: `save_config` continua gravando os dois na seção
		# `thehive`, que é de onde o resto da aplicação os lê.
		'credentials': [
			{'key': 'url', 'label': 'ENDEREÇO DO THEHIVE', 'secret': False, 'required': True,
			 'placeholder': 'http://thehive:9000',
			 'help': 'Dentro do Docker é o nome do serviço, não localhost — de dentro do '
				'contêiner, localhost é o próprio contêiner.'},
			{'key': 'apikey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'help': 'Gerada no TheHive em Organisation → Users → Create API key. A conta '
				'precisa do perfil analyst na organização de destino.'},
			{'key': 'tags', 'label': 'TAGS DO CASO', 'secret': False, 'required': False,
			 'default': 'email,ThePhish', 'help': 'Separadas por vírgula, aplicadas a todo caso criado.'},
			{'key': 'mispId', 'label': 'NOME DA EXPORTAÇÃO MISP', 'secret': False, 'required': False,
			 'placeholder': 'MISP THP',
			 'help': 'Nome do servidor MISP como configurado no TheHive. Em branco, um caso malicioso '
				'não é exportado. O conector MISP precisa estar habilitado no application.conf do '
				'TheHive, ou a exportação falha.'}
		],
		'settings': [
			{'key': 'tlp', 'label': 'TLP', 'type': 'number', 'min': 0, 'max': 3, 'default': 2,
			 'help': '0 White, 1 Green, 2 Amber, 3 Red.'},
			{'key': 'pap', 'label': 'PAP', 'type': 'number', 'min': 0, 'max': 3, 'default': 2},
			{'key': 'minVerdict', 'label': 'CRIAR CASO PARA', 'type': 'choice',
			 'default': 'all', 'options': ['all', 'Suspicious', 'Malicious'],
			 'help': 'O padrão cria para tudo, que é o comportamento histórico. Restringir aqui '
				'também esvazia as telas de histórico na mesma medida, porque elas leem do TheHive.'}
		],
		'testHint': 'lê a quem pertence a chave de API; não cria caso nenhum'
	},
	{
		'id': 'jira',
		'name': 'Jira',
		'kind': 'chamado por e-mail analisado',
		'description': 'Abre uma issue por análise, com o veredito no título e o relatório '
			'completo na descrição: observáveis encontrados, o que cada analisador respondeu e a '
			'avaliação de engenharia social. Serve tanto o Jira Cloud quanto o Data Center.',
		'docs': 'https://developer.atlassian.com/cloud/jira/platform/rest/v2/',
		'credentials': [
			{'key': 'url', 'label': 'ENDEREÇO DO JIRA', 'secret': False, 'required': True,
			 'placeholder': 'https://suaempresa.atlassian.net',
			 'help': 'Só o host, sem /rest. Um Data Center na rede interna é aceito aqui.'},
			{'key': 'authType', 'label': 'AUTENTICAÇÃO', 'secret': False, 'required': True,
			 'default': 'basic', 'options': ['basic', 'bearer'],
			 'help': 'No Cloud é "basic": e-mail da conta mais um API token. Num Data Center é '
				'"bearer": um Personal Access Token, e o campo de e-mail fica vazio.'},
			{'key': 'user', 'label': 'E-MAIL DA CONTA', 'secret': False, 'required': False,
			 'placeholder': 'voce@suaempresa.com',
			 'help': 'Só para autenticação "basic". Em branco no modo bearer.'},
			{'key': 'token', 'label': 'API TOKEN', 'secret': True, 'required': True,
			 'help': 'No Cloud, gerado em id.atlassian.com → Security → API tokens. A conta '
				'precisa da permissão de criar issues no projeto.'},
			{'key': 'project', 'label': 'CHAVE DO PROJETO', 'secret': False, 'required': True,
			 'placeholder': 'SOC',
			 'help': 'A parte antes do hífen na chave da issue: em SOC-142, é SOC.'},
			{'key': 'issueType', 'label': 'TIPO DE ISSUE', 'secret': False, 'required': True,
			 'default': 'Task',
			 'help': 'Precisa existir no projeto e valer para o tipo dele. Um nome que não existe '
				'é recusado pelo Jira na criação, e o Testar mostra isso antes.'},
			{'key': 'labels', 'label': 'RÓTULOS', 'secret': False, 'required': False,
			 'default': 'bluephish',
			 'help': 'Separados por vírgula, aplicados a toda issue criada. O Jira não aceita '
				'espaço dentro de um rótulo.'},
			{'key': 'attachEml', 'label': 'ANEXAR O .EML', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Anexa o e-mail original à issue. Ele contém o conteúdo do phishing — mantenha '
				'desligado se o projeto for visível para além do time de segurança.'},
			{'key': 'verifyTls', 'label': 'VALIDAR CERTIFICADO TLS', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Desligue apenas para um Data Center com certificado próprio, e só numa rede '
				'em que você confia no caminho.'}
		],
		'settings': [
			{'key': 'minVerdict', 'label': 'ABRIR CHAMADO PARA', 'type': 'choice',
			 'default': 'Suspicious', 'options': ['all', 'Suspicious', 'Malicious'],
			 'help': 'Abrir para todo e-mail analisado enche a fila com os seguros, que são a '
				'maioria. "Suspeito ou malicioso" é o padrão porque é o que pede alguém olhando.'}
		],
		'testHint': 'lê o projeto e os tipos de issue dele; não cria chamado nenhum'
	},
	{
		'id': 'disk',
		'name': 'Disco',
		'kind': 'arquivo local, sem centralizador',
		'description': 'Grava cada análise numa pasta datada: o relatório em JSON para consumo '
			'por script, o mesmo em Markdown para leitura, e opcionalmente o e-mail original. É a '
			'opção para quem não quer TheHive nem Jira — nada sai da máquina. As telas de Casos, '
			'Phishing e Executivo leem estas pastas: o JSON guarda observáveis, IOCs, departamento '
			'e avaliação do LLM, então o histórico aqui é tão completo quanto o do TheHive.',
		'docs': '',
		'credentials': [
			{'key': 'path', 'label': 'DIRETÓRIO', 'secret': False, 'required': True,
			 'default': '/root/thephish/data/analises',
			 'help': 'Caminho dentro do container. Use um diretório sob data/, que é bind-mount do '
				'host e sobrevive ao rebuild da imagem — fora dele, o resultado some no próximo build.'},
			{'key': 'writeEml', 'label': 'GRAVAR O .EML', 'secret': False, 'required': True,
			 'default': 'sim', 'options': ['sim', 'não'],
			 'help': 'Grava o e-mail original ao lado do relatório. É o que permite reanalisar '
				'depois; também é o que põe conteúdo de phishing no disco.'},
			{'key': 'writeBody', 'label': 'GRAVAR O CORPO EM TEXTO', 'secret': False, 'required': True,
			 'default': 'não', 'options': ['sim', 'não'],
			 'help': 'O texto limpo do e-mail, separado, para grep. Redundante se você já grava o .eml.'}
		],
		'settings': [
			{'key': 'minVerdict', 'label': 'GRAVAR', 'type': 'choice',
			 'default': 'all', 'options': ['all', 'Suspicious', 'Malicious'],
			 'help': 'O padrão grava tudo: em disco não há fila para poluir, e o histórico completo '
				'é justamente o que serve para auditoria depois.'},
			{'key': 'retentionDays', 'label': 'APAGAR APÓS', 'type': 'number', 'unit': 'dias',
			 'min': 0, 'max': 3650, 'default': 0,
			 'help': 'Zero nunca apaga. Com um valor, as pastas mais antigas que isso são removidas '
				'a cada gravação — o e-mail de phishing guardado é dado pessoal de quem denunciou.'}
		],
		'testHint': 'cria e apaga um arquivo de teste no diretório; nenhuma análise é gravada'
	}
]

BY_ID = dict((d['id'], d) for d in DESTINATIONS)


def field_defs(destination_id):
	spec = BY_ID.get(destination_id)
	if spec is None:
		return [], []
	return spec.get('credentials', []), spec.get('settings', [])


def accepts_verdict(min_verdict, verdict):
	"""Se este destino age sobre este veredito. Puro, e é o que os testes fixam."""
	if min_verdict == 'all':
		return True
	if verdict not in VERDICTS or min_verdict not in VERDICTS:
		return False
	return VERDICTS.index(verdict) >= VERDICTS.index(min_verdict)


# --------------------------------------------------------------------------- #
# Configuração — mesmo contrato dos analisadores e dos destinos de bloqueio    #
# --------------------------------------------------------------------------- #

# A fresh installation runs on Bluephish alone, with no TheHive and no Jira, so
# the destination that ships on is the one that needs no service: the disk. The
# history screens then have somewhere to read from since the first analysis, and
# no analysis tries to reach a TheHive that is not there.
DEFAULT_ENABLED = ('disk',)

# An installation that already used TheHive keeps it on: before this refactor
# every analysis created a case there unconditionally, and an upgrade that
# silently stopped doing that would look like the application had lost the cases.
# load_config() tells the two apart (a saved TheHive key, or destinations already
# saved).
UPGRADE_ENABLED = ('thehive',)


def default_config(upgrade = False):
	enabled_by_default = UPGRADE_ENABLED if upgrade else DEFAULT_ENABLED
	config = {}
	for spec in DESTINATIONS:
		entry = {'enabled': spec['id'] in enabled_by_default}
		for field in spec.get('credentials', []):
			entry[field['key']] = field.get('default', '')
		for field in spec.get('settings', []):
			entry[field['key']] = field['default']
		config[spec['id']] = entry
	return config


def load_config(path = CONFIG_FILE):
	try:
		with open(path) as conf_file:
			conf_dict = json.load(conf_file)
		stored = conf_dict.get(CONFIG_SECTION, {})
	except Exception:
		return default_config()

	# The TheHive URL and API key have lived under `thehive` since long before
	# this section existed, and `save_config` below still writes them there —
	# thephish_app and the history screens read that section directly. Read them
	# from their old home unless this section overrides them, so an upgrade needs
	# no migration and nobody retypes a key.
	legacy = conf_dict.get('thehive', {}) or {}
	config = default_config(upgrade = bool(stored) or bool(legacy.get('apikey')))
	if legacy.get('url'):
		config['thehive']['url'] = legacy['url']
	if legacy.get('apikey'):
		config['thehive']['apikey'] = legacy['apikey']
	misp = conf_dict.get('misp', {}) or {}
	if misp.get('id'):
		config['thehive']['mispId'] = misp['id']
	case = conf_dict.get('case', {}) or {}
	if case.get('tags'):
		config['thehive']['tags'] = ','.join(case['tags'])
	for key in ('tlp', 'pap'):
		if case.get(key) not in (None, ''):
			try:
				config['thehive'][key] = int(case[key])
			except (TypeError, ValueError):
				pass
	for destination_id, entry in (stored or {}).items():
		if destination_id not in config or not isinstance(entry, dict):
			continue
		for key, value in entry.items():
			# A seção `thehive` é a fonte do endereço e da chave, e o que estiver
			# gravado aqui não pode sobrepô-los. Não é zelo: uma versão anterior
			# gravava `apikey: ""` nesta seção, e essa string vazia apagava a chave
			# real na leitura. O destino então recusava criar caso dizendo que a
			# chave não estava configurada — com a chave ali, no arquivo, visível.
			if destination_id == 'thehive' and key in ('url', 'apikey'):
				continue
			if key in config[destination_id]:
				config[destination_id][key] = value
	return config


def save_config(config, path = CONFIG_FILE):
	"""Grava a configuração dos destinos.

	O endereço e a chave do TheHive saem daqui e vão para a seção `thehive`, que é
	de onde o resto da aplicação os lê — `thephish_app` e as telas de histórico vão
	direto lá. Gravá-los nos dois lugares criaria duas cópias da mesma chave, e a
	que ficasse para trás seria justamente a que alguém depuraria por engano.
	"""
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)

	stored = {}
	for destination_id, entry in (config or {}).items():
		entry = dict(entry or {})
		if destination_id == 'thehive':
			legacy = conf_dict.get('thehive', {}) or {}
			if entry.get('url'):
				legacy['url'] = entry['url']
			if entry.get('apikey'):
				legacy['apikey'] = entry['apikey']
			conf_dict['thehive'] = legacy
			entry.pop('url', None)
			entry.pop('apikey', None)
		stored[destination_id] = entry

	conf_dict[CONFIG_SECTION] = stored
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def public_config(config):
	"""A configuração como o navegador pode vê-la: o token nunca volta."""
	public = {}
	for spec in DESTINATIONS:
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


def validate_entry(destination_id, submitted, stored):
	"""(entrada, erro) para o que veio do formulário.

	Segredo em branco mantém o gravado. Campo obrigatório só é cobrado com o
	destino habilitado, para o formulário poder ser preenchido em etapas.
	"""
	spec = BY_ID.get(destination_id)
	if spec is None:
		return None, 'Destino de ticket desconhecido: {0}.'.format(destination_id)

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
		if field.get('type') == 'choice':
			value = str(raw or field['default'])
			if value not in field['options']:
				return None, '{0}: valor inválido para {1}.'.format(spec['name'], field['label'].lower())
		else:
			try:
				value = int(raw)
			except (TypeError, ValueError):
				return None, '{0}: {1} precisa ser um número.'.format(spec['name'], field['label'].lower())
			if value < field['min'] or value > field['max']:
				return None, '{0}: {1} precisa estar entre {2} e {3}.'.format(
					spec['name'], field['label'].lower(), field['min'], field['max'])
		entry[key] = value

	if destination_id == 'thehive':
		# Mesma trava dos outros destinos digitados, com a rede interna liberada:
		# dentro do Docker o TheHive é alcançado pelo nome do serviço, que resolve
		# para um endereço privado da rede do compose
		if entry['enabled'] or entry.get('url'):
			ok, error = custom_analyzers.validate_destination(
				entry.get('url', ''), allow_internal = True, require_https = False)
			if not ok:
				return None, 'TheHive: {0}'.format(error)

	if destination_id == 'jira':
		# Autenticação basic no Cloud exige o e-mail junto do token; sem ele o Jira
		# responde 401 sem dizer o que faltou
		if entry['enabled'] and entry.get('authType') == 'basic' and not entry.get('user'):
			return None, ('Jira: a autenticação "basic" precisa do e-mail da conta junto do API '
				'token. Para um Personal Access Token, escolha "bearer".')
		# O endereço é digitado, não está no código: mesma trava dos analisadores
		# customizados, com a rede interna liberada porque um Data Center vive nela
		if entry['enabled'] or entry.get('url'):
			ok, error = custom_analyzers.validate_destination(entry.get('url', ''), allow_internal = True)
			if not ok:
				return None, 'Jira: {0}'.format(error)
		project = entry.get('project', '')
		if project and not re.match(r'^[A-Za-z][A-Za-z0-9_]*$', project):
			return None, ('Jira: "{0}" não parece uma chave de projeto. É a parte antes do hífen '
				'na chave da issue, como SOC em SOC-142.').format(project)

	if destination_id == 'disk':
		path = entry.get('path', '')
		if entry['enabled'] and not os.path.isabs(path):
			return None, 'Disco: informe um caminho absoluto, começando com /.'

	return entry, None


# --------------------------------------------------------------------------- #
# O report — o que todo destino recebe                                         #
# --------------------------------------------------------------------------- #

def build_report(subject, verdict, reporter, observables_info, reports_observables,
		llm_result = None, auth_results = None, email_body = '', case_ref = '',
		department = '', injection_findings = None, verdict_trail = None):
	"""Normaliza o resultado da análise.

	É a fronteira que torna um destino independente do TheHive: nada aqui é um
	objeto do TheHive, só dados. Um destino novo consome isto e pronto.
	"""
	observables = []
	for observable_info in observables_info or []:
		levels = [r.get('analyzer_result') for r in (reports_observables or [])
			if r.get('observable_id') == observable_info.get('id')]
		observables.append({
			'id': observable_info.get('id', ''),
			'type': observable_info.get('type', ''),
			'value': str(observable_info.get('name', '')),
			'tags': observable_info.get('tags') or [],
			'message': observable_info.get('message') or '',
			# The analyzers decided this during terminate_analysis; a destination
			# that creates observables carries the flag over rather than guessing
			'ioc': bool(observable_info.get('ioc')),
			'malicious': 'malicious' in levels,
			'suspicious': 'suspicious' in levels
		})

	findings = []
	for report_obs in reports_observables or []:
		findings.append({
			'observableType': report_obs.get('observable_type', ''),
			'observable': str(report_obs.get('observable_name', '')),
			'analyzer': report_obs.get('analyzer_name', ''),
			'level': report_obs.get('analyzer_result', 'info'),
			'detail': report_obs.get('analyzer_detail', ''),
			'error': report_obs.get('analyzer_error', '')
		})

	return {
		'subject': str(subject or '(sem assunto)'),
		'verdict': verdict,
		'reporter': reporter or '',
		# Area the reporter belongs to, resolved by departments.py from the rules
		# the SOC declared. '' when no rule claimed them, which is not an error:
		# the dashboards report unattributed reports as such
		'department': department or '',
		'analyzedAt': datetime.datetime.now().replace(microsecond = 0).isoformat(),
		'caseRef': case_ref or '',
		'observables': observables,
		'findings': findings,
		# Como o veredito foi decidido, etapa por etapa (run_analysis.terminate_analysis).
		# None numa análise anterior a este campo, e não [] — "não foi registrado" e
		# "nenhuma etapa" são afirmações diferentes
		'verdictTrail': list(verdict_trail) if verdict_trail is not None else None,
		'llm': llm_result or None,
		# O que as protecoes de prompt viram neste e-mail. Fica fora de 'llm'
		# de proposito: e um fato sobre a mensagem, medido sem o modelo, e
		# continua valendo numa instancia com o LLM desligado
		'promptGuard': {'injection': injection_findings or []} if injection_findings else None,
		'authentication': auth_results or None,
		# Preenchido por run_analysis logo depois desta chamada: o score só existe
		# quando o veredito já está decidido, e é ele quem o calcula
		'score': None,
		'bulk': None,
		'body': email_body or ''
	}


def report_as_markdown(report):
	"""O mesmo report em prosa. Vai para a descrição da issue e para o .md em disco."""
	lines = []
	lines.append('*Veredito:* {0}'.format(report['verdict']))
	lines.append('*Analisado em:* {0}'.format(report['analyzedAt']))
	if report.get('reporter'):
		lines.append('*Denunciado por:* {0}{1}'.format(report['reporter'],
			' ({0})'.format(report['department']) if report.get('department') else ''))
	if report.get('caseRef'):
		lines.append('*Caso no TheHive:* {0}'.format(report['caseRef']))

	auth = report.get('authentication')
	if auth:
		lines.append('')
		lines.append('*Autenticação do remetente:* SPF={0}, DKIM={1}, DMARC={2}{3}'.format(
			auth.get('spf', '?'), auth.get('dkim', '?'), auth.get('dmarc', '?'),
			'' if auth.get('authenticated') else ' — o domínio NÃO está autenticado'))

	llm = report.get('llm')
	if llm:
		lines.append('')
		lines.append('*Engenharia social (LLM):* risco {0}, detectada: {1}'.format(
			llm.get('risk_level', '?'), llm.get('social_engineering_detected')))
		if llm.get('tactics'):
			lines.append('*Táticas:* {0}'.format(', '.join(llm['tactics'])))
		if llm.get('justification'):
			# Uma linha só: `parse_report_markdown` lê este bloco de volta do log do
			# TheHive, e uma quebra de linha no meio da justificativa a partiria
			lines.append(_one_line(llm['justification']))
		if llm.get('evidence'):
			lines.append('')
			lines.append(MD_EVIDENCE)
			for item in llm['evidence']:
				lines.append('- {0}'.format(_one_line(item)))

	trail = report.get('verdictTrail')
	if trail:
		lines.append('')
		lines.append(MD_TRAIL)
		for step in trail:
			lines.append('- [{0}] {1} → {2}'.format(
				step.get('stage', '?'), _one_line(step.get('reason', '')), step.get('verdict', '?')))

	# Por que o caso chegou como Suspicious sem nenhum analisador ter apontado
	# nada: sem esta linha a analista abre o caso e nao encontra o motivo
	injection = (report.get('promptGuard') or {}).get('injection')
	if injection:
		lines.append('')
		lines.append('*Prompt injection:* a mensagem tentou manipular a propria analise.')
		for finding in injection:
			lines.append('- {0}: {1}'.format(finding.get('rule', '?'), finding.get('description', '')))

	flagged = [f for f in report['findings'] if f['level'] in ('malicious', 'suspicious')]
	lines.append('')
	if flagged:
		lines.append(MD_FLAGGED)
		for finding in flagged:
			lines.append('- {0} {1} — {2}: {3}{4}'.format(
				finding['observableType'], _one_line(finding['observable']), _one_line(finding['analyzer']),
				finding['level'], ' · ' + _one_line(finding['detail']) if finding['detail'] else ''))
	else:
		# Dizer a limitação por extenso: os serviços de reputação não conhecem
		# domínio registrado ontem, então lista limpa não é atestado de inocência
		lines.append(MD_NOTHING_FLAGGED + ' Isso não prova que o '
			'e-mail é seguro: os serviços de reputação não conhecem domínios registrados há pouco.')

	if report['observables']:
		lines.append('')
		lines.append('*Observáveis ({0}):*'.format(len(report['observables'])))
		for observable in report['observables'][:60]:
			mark = ' [malicioso]' if observable['malicious'] else (
				' [suspeito]' if observable['suspicious'] else '')
			lines.append('- {0}: {1}{2}'.format(observable['type'], observable['value'][:200], mark))
		if len(report['observables']) > 60:
			lines.append('- … e mais {0}'.format(len(report['observables']) - 60))

	return '\n'.join(lines)


# Os cabeçalhos que `parse_report_markdown` procura. Constantes, e não texto
# repetido, porque escrever num lugar e ler noutro com uma vírgula de diferença
# é como o detalhe do caso no TheHive perderia os analisadores em silêncio
MD_EVIDENCE = '*Indícios apontados pela IA:*'
MD_TRAIL = '*Como o veredito foi decidido:*'
MD_FLAGGED = '*Apontado pelos analisadores:*'
MD_NOTHING_FLAGGED = '*Nenhum observável foi apontado pelos analisadores.*'

_MD_VERDICT = re.compile(r'^\*Veredito:\* (\w+)')
_MD_LLM = re.compile(r'^\*Engenharia social \(LLM\):\* risco (\w+), detectada: (True|False)')
_MD_TACTICS = re.compile(r'^\*Táticas:\* (.*)$')
_MD_TRAIL_STEP = re.compile(r'^- \[(\w+)\] (.*) → (\w+)$')
_MD_FINDING = re.compile(r'^- (\S+) (.+) — (.+): (malicious|suspicious)(?: · (.*))?$')


def _one_line(text):
	return re.sub(r'\s+', ' ', str(text or '')).strip()


def parse_report_markdown(text):
	"""O que `report_as_markdown` escreveu, lido de volta como dado.

	Existe por causa do TheHive: ele guarda o relatório da análise como log de
	tarefa, em prosa, e não há outro lugar de onde tirar qual analisador apontou
	cada observável ou o que a IA concluiu. Só este formato é lido — o que esta
	mesma aplicação escreve, travado por um teste de ida e volta. Uma seção que
	não está no texto volta None, nunca vazia: um caso anterior ao passo a passo
	não "não teve etapas", ele não as registrou.
	"""
	parsed = {'verdict': None, 'llm': None, 'findings': None, 'verdictTrail': None}
	section = None
	for raw_line in str(text or '').splitlines():
		line = raw_line.strip()
		if not line:
			section = None
			continue

		match = _MD_VERDICT.match(line)
		if match and parsed['verdict'] is None:
			parsed['verdict'] = match.group(1)
			continue
		match = _MD_LLM.match(line)
		if match:
			parsed['llm'] = {'risk_level': match.group(1),
				'social_engineering_detected': match.group(2) == 'True',
				'tactics': [], 'justification': '', 'evidence': None}
			section = 'llm'
			continue
		if line == MD_EVIDENCE:
			section = 'evidence'
			if parsed['llm'] is not None:
				parsed['llm']['evidence'] = []
			continue
		if line == MD_TRAIL:
			section = 'trail'
			parsed['verdictTrail'] = []
			continue
		if line == MD_FLAGGED:
			section = 'findings'
			parsed['findings'] = []
			continue
		if line.startswith(MD_NOTHING_FLAGGED):
			section = None
			parsed['findings'] = []
			continue

		if section == 'llm':
			match = _MD_TACTICS.match(line)
			if match:
				parsed['llm']['tactics'] = [t.strip() for t in match.group(1).split(',') if t.strip()]
			elif not line.startswith(('*', '- ')) and not parsed['llm']['justification']:
				parsed['llm']['justification'] = line
		elif section == 'evidence' and line.startswith('- ') and parsed['llm'] is not None:
			parsed['llm']['evidence'].append(line[2:])
		elif section == 'trail':
			match = _MD_TRAIL_STEP.match(line)
			if match:
				parsed['verdictTrail'].append(
					{'stage': match.group(1), 'reason': match.group(2), 'verdict': match.group(3)})
		elif section == 'findings':
			match = _MD_FINDING.match(line)
			if match:
				parsed['findings'].append({
					'observableType': match.group(1), 'observable': match.group(2),
					'analyzer': match.group(3), 'level': match.group(4),
					'detail': match.group(5) or '', 'error': ''})

	# O writer omite a seção de indícios quando a lista é vazia. Num relatório que
	# já traz o passo a passo, a ausência dela é "a IA não apontou nenhum", e não
	# "não foi registrado" — a mesma versão do código escreveu as duas seções
	if parsed['llm'] is not None and parsed['llm']['evidence'] is None and parsed['verdictTrail'] is not None:
		parsed['llm']['evidence'] = []
	return parsed


# --------------------------------------------------------------------------- #
# Reclassificação — a decisão da analista escrita de volta no destino          #
# --------------------------------------------------------------------------- #
#
# A reclassificação vale no BluePhish pelo banco (reclassification.py). Estes
# escritores levam a mesma decisão ao sistema de registro, para que quem abre o
# caso no TheHive, a issue no Jira ou a pasta em disco não leia um "Malicious"
# que uma pessoa já desmentiu. O veredito original nunca é apagado: a decisão
# fica ao lado dele, com autor, data e motivo.

def reclassification_markdown(decision):
	"""A decisão em prosa, para o log do TheHive, o comentário do Jira e o report.md."""
	title = ('*Reclassificação manual:* {0} → {1}' if decision.get('action') != 'revert'
		else '*Reclassificação desfeita:* {0} → {1}').format(
		decision.get('previousVerdict', '?'), decision.get('verdict', '?'))
	return '\n'.join([
		title,
		'*Por:* {0} em {1}'.format(decision.get('by', '?'), decision.get('at', '?')),
		'*Motivo:* {0}'.format(_one_line(decision.get('reason', '')))
	])


def reclassify_disk(folder, decision):
	"""Grava a decisão no report.json da análise, sem tocar no veredito original.

	Escreve num arquivo temporário e troca de uma vez: um report.json cortado ao
	meio por uma falha de disco some do histórico (history.read_report o pula), e
	uma reclassificação não pode custar a análise que ela corrige.
	"""
	path = os.path.join(folder, 'report.json')
	try:
		with io.open(path, encoding = 'utf-8') as report_file:
			report = json.load(report_file)
	except (OSError, ValueError) as error:
		raise TicketError('Não foi possível ler {0}: {1}'.format(path, error))
	if not isinstance(report, dict):
		raise TicketError('{0} não é um relatório de análise.'.format(path))

	report['reclassification'] = decision
	report['reclassificationHistory'] = list(report.get('reclassificationHistory') or []) + [decision]
	temporary = path + '.tmp'
	try:
		with io.open(temporary, 'w', encoding = 'utf-8') as out:
			out.write(json.dumps(report, indent = '\t', ensure_ascii = False))
		os.replace(temporary, path)
		with io.open(os.path.join(folder, 'report.md'), 'a', encoding = 'utf-8') as md_file:
			md_file.write('\n' + reclassification_markdown(decision) + '\n')
	except OSError as error:
		raise TicketError('Falha ao gravar em {0}: {1}'.format(folder, error))
	return 'report.json atualizado'


def reclassify_thehive(entry, case_uuid, decision):
	"""Resolve (ou reabre) o caso conforme o novo veredito, e registra o motivo no log."""
	import thehive4py.models
	api = _thehive_client(entry)
	verdict = decision.get('verdict')
	summary = _one_line('{0} por {1}: {2}'.format(
		'Reclassificado manualmente para ' + str(verdict) if decision.get('action') != 'revert'
		else 'Reclassificação desfeita, de volta a ' + str(verdict),
		decision.get('by', '?'), decision.get('reason', '')))[:1000]

	resolution = THEHIVE_RESOLUTION.get(verdict)
	try:
		if resolution:
			thehive4py.models.CaseHelper(api).update(case_uuid, status = 'Resolved',
				resolutionStatus = resolution[0], impactStatus = resolution[1], summary = summary)
			detail = 'caso resolvido como {0}'.format(resolution[0])
		else:
			# Suspicious é o caso aberto esperando uma pessoa — é o que ele era
			thehive4py.models.CaseHelper(api).update(case_uuid, status = 'Open')
			detail = 'caso reaberto'
	except Exception as error:
		raise TicketError('O TheHive recusou a atualização do caso: {0}'.format(error))

	try:
		tasks = dict((task['title'], task['id']) for task in api.get_case_tasks(case_uuid).json())
		task_id = tasks.get('ThePhish result') or tasks.get('ThePhish analysis')
		if task_id:
			api.create_task_log(task_id, thehive4py.models.CaseTaskLog(
				message = reclassification_markdown(decision)))
			detail += ' · motivo registrado no log'
	except Exception:
		# O caso já foi resolvido; perder só o log não desfaz isso
		detail += ' · o motivo não pôde ser registrado no log'
	return detail


def jira_issue(entry, key):
	"""Os campos que a reclassificação precisa de uma issue: título e rótulos."""
	body = _jira_call(entry, 'GET', '/rest/api/2/issue/{0}'.format(key),
		params = {'fields': 'summary,labels,created'})
	return (body.get('fields') or {}) if isinstance(body, dict) else {}


def reclassify_jira(entry, key, decision, title):
	"""Troca o prefixo de veredito do título e comenta o motivo na issue.

	O título é por onde o histórico lê o veredito de volta (JIRA_SUMMARY_VERDICT),
	então é ele que muda; o comentário é o que diz a quem abre a issue por quê.
	"""
	_jira_call(entry, 'PUT', '/rest/api/2/issue/{0}'.format(key),
		headers = {'Content-Type': 'application/json'},
		json = {'fields': {'summary': '[{0}] {1}'.format(decision.get('verdict'), title)[:250]}})
	_jira_call(entry, 'POST', '/rest/api/2/issue/{0}/comment'.format(key),
		headers = {'Content-Type': 'application/json'},
		json = {'body': reclassification_markdown(decision)})
	return 'título atualizado e motivo comentado'


# --------------------------------------------------------------------------- #
# Jira                                                                         #
# --------------------------------------------------------------------------- #

class TicketError(Exception):
	"""Uma falha de entrega que vale mostrar ao analista tal como é."""


def _verify(entry):
	return str(entry.get('verifyTls', 'sim')).lower() != 'não'


def _jira_auth(entry):
	"""(auth, headers) conforme o modo escolhido."""
	headers = {'Accept': 'application/json'}
	if entry.get('authType') == 'bearer':
		headers['Authorization'] = 'Bearer ' + entry.get('token', '')
		return None, headers
	return (entry.get('user', ''), entry.get('token', '')), headers


def _jira_call(entry, method, path, **kwargs):
	"""Uma chamada à REST API v2 — a que serve Cloud e Data Center igualmente."""
	base = str(entry.get('url', '') or '').strip().rstrip('/')
	# Revalidação na hora da chamada, como em custom_analyzers.query(): o nome pode
	# ter passado a resolver para outro lugar depois que alguém salvou
	ok, error = custom_analyzers.validate_destination(base, allow_internal = True)
	if not ok:
		raise TicketError('Destino recusado: {0}'.format(error))

	auth, headers = _jira_auth(entry)
	headers.update(kwargs.pop('headers', {}))
	try:
		response = pinned_http.request(method, base + path, True, auth = auth, headers = headers,
			timeout = HTTP_TIMEOUT, verify = _verify(entry), allow_redirects = False, **kwargs)
	except pinned_http.DestinationRefused as refused:
		raise TicketError('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		raise TicketError('Falha na validação do certificado TLS do Jira. Se ele usa certificado '
			'próprio, desligue a validação neste destino.')

	if response.status_code in (401, 403):
		raise TicketError('O Jira recusou as credenciais (HTTP {0}). No Cloud, "basic" quer o '
			'e-mail da conta e um API token — não a senha.'.format(response.status_code))
	if response.status_code == 404:
		raise TicketError('O Jira não encontrou {0}. Confira o endereço e a chave do projeto.'.format(path))

	try:
		body = response.json()
	except ValueError:
		body = {}

	if response.status_code >= 400:
		messages = []
		if isinstance(body, dict):
			messages = list(body.get('errorMessages') or [])
			for field, text in (body.get('errors') or {}).items():
				messages.append('{0}: {1}'.format(field, text))
		raise TicketError('O Jira recusou a operação (HTTP {0}){1}'.format(
			response.status_code, ': ' + '; '.join(messages) if messages else '.'))

	return body if isinstance(body, (dict, list)) else {}


def jira_summary(report):
	"""O título da issue. O Jira corta em 255; cortar aqui evita a recusa."""
	summary = '[{0}] {1}'.format(report['verdict'], report['subject'])
	return summary[:250]


def create_jira(entry, report, eml = None, files = None):
	fields = {
		'project': {'key': entry.get('project', '')},
		'summary': jira_summary(report),
		'description': report_as_markdown(report),
		'issuetype': {'name': entry.get('issueType', 'Task')}
	}
	labels = [l.strip().replace(' ', '-') for l in str(entry.get('labels', '') or '').split(',')]
	labels = [l for l in labels if l]
	if labels:
		fields['labels'] = labels

	created = _jira_call(entry, 'POST', '/rest/api/2/issue',
		headers = {'Content-Type': 'application/json'}, json = {'fields': fields})
	key = created.get('key', '') if isinstance(created, dict) else ''
	detail = 'issue {0} criada'.format(key or 'sem chave')

	if eml and str(entry.get('attachEml', 'sim')).lower() == 'sim' and key:
		try:
			_jira_call(entry, 'POST', '/rest/api/2/issue/{0}/attachments'.format(key),
				headers = {'X-Atlassian-Token': 'no-check'},
				files = {'file': ('email.eml', io.BytesIO(eml), 'message/rfc822')})
			detail += ' com o .eml anexado'
		except TicketError as error:
			# A issue já existe; falhar o anexo não pode desfazê-la nem virar um erro
			# que sugira que nada foi criado
			detail += ' (o anexo falhou: {0})'.format(error)

	return {'ok': True, 'ref': key, 'detail': detail, 'error': ''}


# O prefixo que `jira_summary` põe no título: "[Malicious] assunto do e-mail".
# É por onde o veredito volta como campo em vez de prosa
JIRA_SUMMARY_VERDICT = re.compile(r'^\[(Malicious|Suspicious|Safe|Other)\]\s*(.*)$', re.S)

# Quantas issues uma leitura de histórico traz por página. O Jira Cloud recusa
# `maxResults` acima de 100 em silêncio — devolve 100 e segue — então pedir mais
# não é otimização, é uma contagem errada esperando acontecer
JIRA_PAGE = 100


def read_jira(entry, since_ms = None, limit = 200):
	"""As issues que este destino abriu, mais novas primeiro, como (chave, campos).

	Só o que a issue guarda **como campo** volta daqui: a chave, o título (de onde
	sai o veredito e o assunto), a data de criação e os rótulos. O relatório da
	análise está na descrição, em prosa escrita para uma pessoa ler — observáveis
	cortados em sessenta, o resto em frases. Reconstituir contagem de IOC daquilo
	poria na tela de um SOC um número que ninguém mediu, e é justamente o que o
	CLAUDE.md deste repositório manda não fazer. Quem lê daqui reporta observáveis
	como desconhecidos, não como zero.
	"""
	project = str(entry.get('project', '') or '').strip()
	if not project:
		return []
	jql = 'project = "{0}"'.format(project.replace('"', ''))
	labels = [l.strip().replace(' ', '-') for l in str(entry.get('labels', '') or '').split(',')]
	labels = [l for l in labels if l]
	if labels:
		# Sem isto o histórico mostraria toda issue do projeto, inclusive as que
		# nada têm a ver com e-mail analisado
		jql += ' AND labels in ({0})'.format(', '.join('"{0}"'.format(l) for l in labels))
	if since_ms:
		day = datetime.datetime.utcfromtimestamp(since_ms / 1000).strftime('%Y-%m-%d')
		jql += ' AND created >= "{0}"'.format(day)
	jql += ' ORDER BY created DESC'

	issues = []
	start = 0
	while len(issues) < limit:
		page = _jira_call(entry, 'GET', '/rest/api/2/search', params = {
			'jql': jql,
			'startAt': start,
			'maxResults': min(JIRA_PAGE, limit - len(issues)),
			'fields': 'summary,created,labels'
		})
		found = page.get('issues') or [] if isinstance(page, dict) else []
		if not found:
			break
		issues.extend(found)
		start += len(found)
		if start >= int(page.get('total') or 0):
			break
	return issues[:limit]


def probe_jira(entry):
	"""Lê o projeto e os tipos de issue dele. Não cria nada."""
	project = entry.get('project', '')
	body = _jira_call(entry, 'GET', '/rest/api/2/project/{0}'.format(project))
	name = body.get('name', project) if isinstance(body, dict) else project
	types = [t.get('name', '') for t in (body.get('issuetypes') or [])] if isinstance(body, dict) else []
	wanted = entry.get('issueType', 'Task')
	detail = 'projeto {0} ({1}) alcançado'.format(project, name)
	if types:
		if wanted in types:
			detail += ' · tipo "{0}" existe'.format(wanted)
		else:
			# É a causa mais comum de a criação falhar depois de um teste verde
			detail += ' · ATENÇÃO: o tipo "{0}" não existe neste projeto. Disponíveis: {1}'.format(
				wanted, ', '.join(t for t in types if t))
	return detail


# --------------------------------------------------------------------------- #
# Disco                                                                        #
# --------------------------------------------------------------------------- #

def slugify(text, limit = 60):
	"""Um nome de pasta previsível a partir do assunto, que veio de um atacante."""
	slug = re.sub(r'[^A-Za-z0-9._-]+', '-', str(text or '')).strip('-.')
	return slug[:limit] or 'sem-assunto'


# Toda pasta de análise começa com o carimbo de tempo. O padrão existe para a
# retenção saber o que é dela: sem ele, apagar "o que está velho" apagaria
# qualquer diretório que estivesse na raiz.
ANALYSIS_DIR_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-')


def analysis_dirname(report):
	"""AAAA-MM-DDTHH-MM-SS-assunto — ordenável por nome, legível por humano."""
	stamp = str(report.get('analyzedAt', '')).replace(':', '-') or 'sem-data'
	return '{0}-{1}'.format(stamp, slugify(report.get('subject', '')))


def is_analysis_dir(name):
	"""Se este diretório foi criado por uma análise, e portanto é nosso para apagar."""
	return bool(ANALYSIS_DIR_PATTERN.match(name))


def prune_old_analyses(root, retention_days, now = None):
	"""Apaga as pastas de análise mais antigas que a retenção. Devolve quantas foram.

	O e-mail guardado é dado pessoal de quem denunciou, então guardar para sempre
	é uma decisão, não um padrão. Zero desliga.

	Só apaga o que casa com `ANALYSIS_DIR_PATTERN`, e isso não é zelo: o caminho
	natural para apontar este destino é o próprio data/, que é o bind mount, e lá
	moram as regras do YARA e o banco de usuários. Apagar "o que está velho" sem
	olhar o nome levaria as regras junto na primeira limpeza.
	"""
	try:
		retention_days = int(retention_days)
	except (TypeError, ValueError):
		return 0
	if retention_days <= 0 or not os.path.isdir(root):
		return 0

	import shutil
	now = now or datetime.datetime.now()
	cutoff = now - datetime.timedelta(days = retention_days)
	removed = 0
	for name in os.listdir(root):
		path = os.path.join(root, name)
		if not os.path.isdir(path) or not is_analysis_dir(name):
			continue
		try:
			modified = datetime.datetime.fromtimestamp(os.path.getmtime(path))
		except OSError:
			continue
		if modified < cutoff:
			shutil.rmtree(path, ignore_errors = True)
			removed += 1
	return removed


def create_disk(entry, report, eml = None, files = None):
	root = entry.get('path', '')
	try:
		os.makedirs(root, exist_ok = True)
	except OSError as error:
		raise TicketError('Não foi possível criar {0}: {1}'.format(root, error))

	folder = os.path.join(root, analysis_dirname(report))
	try:
		os.makedirs(folder, exist_ok = True)
		with io.open(os.path.join(folder, 'report.json'), 'w', encoding = 'utf-8') as json_file:
			json_file.write(json.dumps(report, indent = '\t', ensure_ascii = False))
		with io.open(os.path.join(folder, 'report.md'), 'w', encoding = 'utf-8') as md_file:
			md_file.write('# {0}\n\n'.format(report['subject']))
			md_file.write(report_as_markdown(report))
			md_file.write('\n')
		written = ['report.json', 'report.md']

		if eml and str(entry.get('writeEml', 'sim')).lower() == 'sim':
			with open(os.path.join(folder, 'email.eml'), 'wb') as eml_file:
				eml_file.write(eml)
			written.append('email.eml')

		if str(entry.get('writeBody', 'não')).lower() == 'sim' and report.get('body'):
			with io.open(os.path.join(folder, 'body.txt'), 'w', encoding = 'utf-8') as body_file:
				body_file.write(report['body'])
			written.append('body.txt')
	except OSError as error:
		raise TicketError('Falha ao gravar em {0}: {1}'.format(folder, error))

	detail = 'gravado em {0} ({1})'.format(folder, ', '.join(written))
	removed = prune_old_analyses(root, entry.get('retentionDays', 0))
	if removed:
		detail += ' · {0} análise(s) antiga(s) removida(s)'.format(removed)
	return {'ok': True, 'ref': folder, 'detail': detail, 'error': ''}


def probe_disk(entry):
	"""Prova que dá para escrever, e desfaz o que escreveu."""
	root = entry.get('path', '')
	if not root:
		raise TicketError('Informe o diretório.')
	try:
		os.makedirs(root, exist_ok = True)
		probe_path = os.path.join(root, '.bluephish-write-test')
		with open(probe_path, 'w') as probe_file:
			probe_file.write('ok')
		os.remove(probe_path)
	except OSError as error:
		raise TicketError('Não é possível escrever em {0}: {1}'.format(root, error))

	existing = 0
	try:
		existing = len([n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n))])
	except OSError:
		pass
	warning = ''
	if '/data/' not in root.replace('\\', '/') and not root.rstrip('/').endswith('/data'):
		# Fora de data/ o diretório vive só na camada de escrita do container
		warning = ' · ATENÇÃO: fora de data/, o conteúdo some no próximo rebuild da imagem'
	return 'diretório gravável · {0} análise(s) já armazenada(s){1}'.format(existing, warning)


# --------------------------------------------------------------------------- #
# TheHive                                                                      #
# --------------------------------------------------------------------------- #

# TheHive used to be the pipeline itself: the case was created before the
# analysis, the observables were stored in it and read back, and every analyzer
# job was keyed to the id it handed out. That is over — the observables live in
# `run_analysis` now — and what is left is what TheHive was always good at:
# being the case management system where an analyst picks the work up.
#
# So it is a destination like the others: the Cases, Phishing and Executive
# screens read it alongside every other enabled destination (history.py), and
# turning it off empties them only when nothing else records the analyses.

THEHIVE_TEMPLATE = 'ThePhish'

# The three tasks the template carries. They are created completed, with the
# analysis already in them: the case arrives finished, not in progress.
THEHIVE_TASKS = ('ThePhish notification', 'ThePhish analysis', 'ThePhish result')

# How a final verdict closes the case
THEHIVE_RESOLUTION = {
	'Malicious': ('TruePositive', 'NoImpact'),
	'Safe': ('FalsePositive', 'NotApplicable')
}


def _thehive_client(entry):
	"""A client built from this destination's own settings.

	Every destination owns its client, which is what lets `case_from_email` and
	`run_analysis` import nothing from thehive4py at all.
	"""
	import thehive4py.api
	# O endereço e a chave são gravados na seção `thehive` (save_config), não
	# nesta — então a entrada recebida pode não trazê-los, e a configuração
	# gravada é a fonte
	url = str(entry.get('url', '') or '').strip().rstrip('/')
	apikey = entry.get('apikey', '')
	if not url or not apikey:
		stored = load_config().get('thehive', {})
		url = url or str(stored.get('url', '') or '').strip().rstrip('/')
		apikey = apikey or stored.get('apikey', '')
	if not url:
		raise TicketError('Endereço do TheHive não configurado. Preencha o card do TheHive.')
	if not apikey:
		raise TicketError('Chave de API do TheHive não configurada. Preencha o card do TheHive.')
	return thehive4py.api.TheHiveApi(url, apikey)


def _thehive_ensure_template(api):
	"""Create the case template once, if this TheHive has never seen it."""
	import thehive4py.models, thehive4py.query
	found = api.find_case_templates(query = thehive4py.query.Eq('name', THEHIVE_TEMPLATE))
	if found.status_code == 200 and len(found.json()) > 0:
		return
	template = thehive4py.models.CaseTemplate(
		name = THEHIVE_TEMPLATE,
		titlePrefix = '[ThePhish] ',
		tasks = [thehive4py.models.CaseTask(title = title) for title in THEHIVE_TASKS])
	response = api.create_case_template(template)
	if response.status_code != 201:
		raise TicketError('Não foi possível criar o template {0}: HTTP {1}'.format(
			THEHIVE_TEMPLATE, response.status_code))


def _thehive_observable(observable, files):
	"""One CaseObservable from one in-memory observable."""
	import thehive4py.models
	base_type = str(observable.get('type', '')).split('_')[0]
	common = {
		'ioc': bool(observable.get('ioc')),
		'tags': observable.get('tags') or ['email'],
		'message': observable.get('message') or ''
	}
	if base_type == 'file':
		content = (files or {}).get(observable['id'])
		if not content:
			return None
		# thehive4py takes a (file-like, filename) tuple for a file observable
		return thehive4py.models.CaseObservable(
			dataType = 'file', data = (io.BytesIO(content[0]), content[1]), **common)
	return thehive4py.models.CaseObservable(
		dataType = observable.get('type'), data = observable.get('value') or observable.get('name'),
		**common)


# Os fatos da análise que viram tag no caso, além das tags configuradas.
#
# O TheHive guarda o histórico das análises e as telas de Casos e Visão Executiva
# leem esse histórico de volta. Sem isto, o departamento que denunciou e a tática
# que o LLM reconheceu só existiriam na prosa do log da tarefa — visível para
# quem abre o caso, incontável para quem olha o mês inteiro.
#
# A regra mora em case_insights.py, que é quem lê de volta, e o leitor de disco
# (history.py) reconstrói as mesmas tags a partir do mesmo report. Uma definição
# só: escrever a tag num lugar e derivá-la noutro é como um veredito de disco
# perderia o departamento sem nada ficar vermelho.
analysis_tags = case_insights.analysis_tags


def create_thehive(entry, report, eml = None, files = None):
	import thehive4py.models

	api = _thehive_client(entry)
	_thehive_ensure_template(api)

	tags = [t.strip() for t in str(entry.get('tags', '') or '').split(',') if t.strip()]
	tags = (tags or ['email', 'ThePhish']) + analysis_tags(report)
	# Emojis are stripped from the title: MISP chokes on them when the case is exported
	try:
		import emoji
		title = emoji.replace_emoji(report['subject'], '')
	except Exception:
		title = report['subject']

	case = thehive4py.models.Case(
		title = title,
		tlp = int(entry.get('tlp', 2)),
		pap = int(entry.get('pap', 2)),
		flag = False,
		tags = tags,
		description = 'Case created automatically by ThePhish',
		template = THEHIVE_TEMPLATE)
	response = api.create_case(case)
	if response.status_code != 201:
		raise TicketError('O TheHive recusou a criação do caso (HTTP {0}).'.format(
			response.status_code))

	created = response.json()
	case_uuid = created['id']
	case_ref = str(created.get('caseId', ''))
	added = 0
	for observable in report.get('observables', []):
		model = _thehive_observable(observable, files)
		if model is None:
			continue
		if api.create_case_observable(case_uuid, model).status_code == 201:
			added += 1

	# The analyzer evidence and the LLM assessment go in as task logs, which is
	# where an analyst opening the case looks for them
	tasks = {}
	try:
		for task in api.get_case_tasks(case_uuid).json():
			tasks[task['title']] = task['id']
	except Exception:
		tasks = {}

	analysis_task = tasks.get('ThePhish analysis')
	if analysis_task:
		try:
			api.create_task_log(analysis_task, thehive4py.models.CaseTaskLog(
				message = report_as_markdown(report)))
		except Exception:
			# The case exists and carries the observables; a missing log is not
			# worth failing the whole destination over
			pass

	# What was emailed to the reporter, kept where it always was: the description
	# of the notification task
	for note in report.get('notifications', []):
		task_id = tasks.get('ThePhish notification')
		if not task_id:
			break
		try:
			api.update_case_task(thehive4py.models.CaseTask(
				id = task_id, description = 'mailto:' + note.get('to', '') + '\n' + note.get('body', ''),
				status = 'Completed'), fields = ['description', 'status'])
		except Exception:
			pass

	detail = 'caso {0} criado com {1} observável(is)'.format(case_ref or case_uuid, added)

	# A Suspicious verdict deliberately leaves the case open: it is the one that
	# needs a human, and closing it would bury exactly the work worth doing
	resolution = THEHIVE_RESOLUTION.get(report['verdict'])
	if resolution:
		if report['verdict'] == 'Malicious' and entry.get('mispId'):
			export = api.export_to_misp(entry['mispId'], case_uuid)
			detail += ' · exportado para o MISP' if export.ok else ' · a exportação para o MISP falhou'
		for title in THEHIVE_TASKS:
			task_id = tasks.get(title)
			if task_id:
				try:
					api.update_case_task(thehive4py.models.CaseTask(id = task_id, status = 'Completed'),
						fields = ['status'])
				except Exception:
					pass
		try:
			thehive4py.models.CaseHelper(api).update(case_uuid, status = 'Resolved',
				resolutionStatus = resolution[0], impactStatus = resolution[1],
				summary = 'Automated analysis')
			detail += ' · resolvido como {0}'.format(resolution[0])
		except Exception:
			detail += ' · não foi possível resolver o caso'
	else:
		detail += ' · deixado aberto para o analista'

	return {'ok': True, 'ref': case_ref or case_uuid, 'detail': detail, 'error': ''}


def probe_thehive(entry):
	"""Reads who the API key belongs to. Creates no case."""
	api = _thehive_client(entry)
	response = api.get_current_user()
	if response.status_code in (401, 403):
		raise TicketError('O TheHive recusou a chave de API (HTTP {0}).'.format(response.status_code))
	if not response.ok:
		raise TicketError('O TheHive respondeu HTTP {0}.'.format(response.status_code))
	body = response.json() if response.content else {}
	who = body.get('login') or body.get('name') or 'usuário desconhecido'
	organisation = body.get('organisation') or ''
	# A wrong organisation is the quiet failure: the key works and the cases land
	# somewhere nobody is looking
	return 'autenticado como {0}{1}'.format(who,
		' na organização ' + organisation if organisation else '')

# --------------------------------------------------------------------------- #
# Ponto de entrada                                                             #
# --------------------------------------------------------------------------- #

CREATORS = {'thehive': create_thehive, 'jira': create_jira, 'disk': create_disk}
PROBES = {'thehive': probe_thehive, 'jira': probe_jira, 'disk': probe_disk}


def _failure(message):
	return {'ok': False, 'ref': '', 'detail': '', 'error': message}


def create(destination_id, report, eml = None, files = None, config = None):
	"""Entrega um report a um destino. Nunca levanta.

	O veredito já foi decidido e o caso já foi fechado quando isto roda: um Jira
	fora do ar precisa virar aviso no log, nunca uma exceção que derruba a
	análise inteira.
	"""
	config = config if config is not None else load_config()
	entry = config.get(destination_id, {})
	spec = BY_ID.get(destination_id)

	if spec is None:
		return _failure('Destino de ticket desconhecido.')
	if not entry.get('enabled'):
		return _failure('Destino desabilitado.')
	if not accepts_verdict(entry.get('minVerdict', 'all'), report.get('verdict')):
		return _failure('Veredito {0} está abaixo do mínimo configurado.'.format(report.get('verdict')))

	try:
		return CREATORS[destination_id](entry, report, eml, files)
	except TicketError as error:
		return _failure(str(error))
	except requests.exceptions.Timeout:
		return _failure('{0} não respondeu dentro do tempo limite.'.format(spec['name']))
	except requests.exceptions.ConnectionError:
		return _failure('Não foi possível alcançar {0} em {1}.'.format(
			spec['name'], entry.get('url', '') or 'seu endereço'))
	except Exception:
		print("[ERROR]_[tickets]: {0} failed for verdict {1}: {2}".format(
			destination_id, report.get('verdict'), traceback.format_exc()))
		return _failure('{0} devolveu uma resposta inesperada.'.format(spec['name']))


def probe(destination_id, entry):
	"""Verifica credencial e alcance sem criar ticket. {ok, detail, error}."""
	spec = BY_ID.get(destination_id)
	if spec is None:
		return {'ok': False, 'detail': '', 'error': 'Destino de ticket desconhecido.'}
	try:
		detail = PROBES[destination_id](entry)
	except TicketError as error:
		return {'ok': False, 'detail': '', 'error': str(error)}
	except requests.exceptions.Timeout:
		return {'ok': False, 'detail': '',
			'error': '{0} não respondeu dentro do tempo limite.'.format(spec['name'])}
	except requests.exceptions.ConnectionError:
		return {'ok': False, 'detail': '',
			'error': 'Não foi possível alcançar {0} em {1}.'.format(
				spec['name'], entry.get('url', '') or 'seu endereço')}
	except Exception:
		print("[ERROR]_[tickets]: probe of {0} failed: {1}".format(
			destination_id, traceback.format_exc()))
		return {'ok': False, 'detail': '',
			'error': '{0} devolveu uma resposta inesperada.'.format(spec['name'])}
	return {'ok': True, 'detail': detail, 'error': ''}


def enabled_for(verdict, config = None):
	"""Ids dos destinos habilitados que agem sobre este veredito."""
	config = config if config is not None else load_config()
	found = []
	for spec in DESTINATIONS:
		entry = config.get(spec['id'], {})
		if entry.get('enabled') and accepts_verdict(entry.get('minVerdict', 'all'), verdict):
			found.append(spec['id'])
	return found


def dispatch(report, eml = None, files = None, config = None):
	"""Entrega o report a todo destino habilitado. Devolve [(id, resultado)].

	O TheHive vai primeiro quando está ligado, e não por precedência histórica: é
	ele que produz o número do caso, e um chamado no Jira que aponte para esse
	número vale mais do que um que não aponte para nada. Os destinos seguintes
	recebem o report já com o `caseRef` preenchido.

	Um destino que falha não impede os outros: quem tem TheHive e disco ligados
	precisa que o disco grave mesmo com o TheHive fora do ar.
	"""
	config = config if config is not None else load_config()
	ordered = enabled_for(report.get('verdict'), config)
	ordered.sort(key = lambda d: 0 if d == 'thehive' else 1)

	results = []
	for destination_id in ordered:
		outcome = create(destination_id, report, eml, files, config)
		if destination_id == 'thehive' and outcome['ok'] and outcome.get('ref'):
			report['caseRef'] = outcome['ref']
		results.append((destination_id, outcome))
	return results
