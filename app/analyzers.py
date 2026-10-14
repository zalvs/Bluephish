"""Native observable analyzers — what replaced the Cortex dependency.

The old pipeline submitted every observable to Cortex and read back a taxonomy
*level*: one of 'info', 'safe', 'suspicious' or 'malicious'. The verdict logic
downstream only ever counted those levels. That made the level the real
contract, and it is the contract this module reproduces by calling each vendor
directly.

Shape of the module:

  ANALYZERS      declarative registry — identity, which observable types an
                 analyzer can judge, the credential fields the interface must
                 collect, and the tunable thresholds. The interface renders its
                 forms from this, so adding an analyzer is a registry entry plus
                 a client function, never new markup.

  level_for()    pure: (thresholds, signal) -> level. No network, no config
                 file. This is where "malicious from 5 engines up, suspicious
                 from 1" actually lives, and it is what the tests pin down.

  run()          impure: resolves credentials, calls the vendor API, normalizes
                 the answer into a `signal`, then defers to level_for().

Every client returns the same normalized signal so that the threshold logic
never has to know a vendor's response shape.

run_analysis.analyze_observables calls run() for every observable of a case. The
same registry also drives the Integrações screen, where an analyst saves
credentials and runs a real query to see the level a given threshold produces
before enabling the analyzer.
"""

import base64
import json
import os
import re
import time
import traceback

import requests

# Vendor calls are given a short connect timeout and a longer read timeout: a
# firewalled endpoint should fail fast, a slow-but-alive one should be waited for
HTTP_TIMEOUT = (10, 30)

# The four levels the pipeline understands, weakest first. 'info' means the
# analyzer had nothing to say, which is different from 'safe' (it looked and
# found the observable clean).
LEVELS = ('info', 'safe', 'suspicious', 'malicious')

CONFIG_FILE = 'configuration.json'
CONFIG_SECTION = 'native_analyzers'

# Texto que a tela mostra acima da escolha de tipos, igual para todo analisador.
# A escolha existe porque "o que este fornecedor sabe avaliar" e "o que vale a
# pena mandar para ele" são perguntas diferentes: a segunda depende da cota
# contratada e do volume da caixa, e só quem administra a instalação sabe
# responder.
OBSERVABLE_CHOICE_HINT = (
	'Marque o que deve ser enviado a este fornecedor. Desmarcar um tipo não o remove da '
	'análise — outros analisadores habilitados continuam avaliando aquele observável.'
)


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #

ANALYZERS = [
	{
		'id': 'virustotal',
		'family': 'reputation',
		'name': 'VirusTotal',
		'kind': 'reputação multi-motor',
		'description': 'Consulta a reputação de IPs, domínios, URLs e hashes contra ~90 motores '
			'antivírus e serviços de blocklist. O veredito sai da contagem de motores que apontaram '
			'o indicador, e não de um único motor.',
		'docs': 'https://docs.virustotal.com/reference/overview',
		'observables': ['ip', 'domain', 'url', 'hash'],
		'observablesHelp': 'As URLs são o que consome a cota: um e-mail de marketing traz dezenas '
			'delas, e a chave gratuita permite 4 consultas por minuto e cerca de 500 por dia. '
			'Numa caixa movimentada, deixar só os hashes de anexo mantém o sinal mais forte do '
			'VirusTotal (multimotor sobre arquivo) sem estourar o limite.',
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'placeholder': 'chave da conta VirusTotal',
			 'help': 'A chave gratuita permite 4 consultas por minuto — suficiente para triagem, '
				'apertada para um lote grande.'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'motores',
			 'min': 1, 'max': 40, 'default': 5,
			 'help': 'Quantos motores precisam apontar o indicador para o veredito ser malicioso.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'motores',
			 'min': 1, 'max': 40, 'default': 1,
			 'help': 'Abaixo do limiar de malicioso, quantos motores bastam para marcar como suspeito.'}
		],
		'testPlaceholder': '8.8.8.8, exemplo.com ou uma URL'
	},
	{
		'id': 'abuseipdb',
		'family': 'reputation',
		'name': 'AbuseIPDB',
		'kind': 'reputação de IP por denúncias',
		'description': 'Pontua um IP de 0 a 100 conforme as denúncias de abuso recebidas na janela '
			'consultada. Vale só para IPs — domínios, URLs e hashes passam batido.',
		'docs': 'https://docs.abuseipdb.com/',
		'observables': ['ip'],
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'placeholder': 'chave da conta AbuseIPDB'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'de confiança',
			 'min': 1, 'max': 100, 'default': 80,
			 'help': 'Pontuação de confiança de abuso (0–100) a partir da qual o IP é malicioso.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'de confiança',
			 'min': 1, 'max': 100, 'default': 25},
			{'key': 'maxAgeInDays', 'label': 'JANELA DE DENÚNCIAS', 'unit': 'dias',
			 'min': 1, 'max': 365, 'default': 90,
			 'help': 'Denúncias mais antigas que isso são ignoradas na pontuação.'}
		],
		'testPlaceholder': '118.25.6.39'
	},
	{
		'id': 'yara',
		'family': 'local',
		'name': 'YARA',
		'kind': 'regras locais sobre arquivos',
		'description': 'Casa regras YARA contra os anexos do e-mail. Roda inteiramente local: '
			'nenhum conteúdo sai da rede, e não há chave de API nem limite de consultas.',
		'docs': 'https://yara.readthedocs.io/',
		'observables': ['file'],
		'credentials': [
			{'key': 'rulesPath', 'label': 'DIRETÓRIO DE REGRAS', 'secret': False, 'required': True,
			 'placeholder': '/root/thephish/data/yara',
			 'default': '/root/thephish/data/yara',
			 'help': 'Caminho dentro do container. Use um diretório sob data/, que é bind-mount '
				'do host e sobrevive ao rebuild da imagem.'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'regras casadas',
			 'min': 1, 'max': 20, 'default': 1},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'regras casadas',
			 'min': 1, 'max': 20, 'default': 1}
		],
		'testPlaceholder': 'caminho de um arquivo para testar as regras'
	},
	{
		'id': 'safebrowsing',
		'family': 'blocklist',
		'name': 'Google Safe Browsing',
		'kind': 'blocklist de navegação',
		'description': 'A mesma lista que o Chrome consulta antes de abrir uma página. Cobre malware, '
			'engenharia social (phishing) e software indesejado. Resposta binária: a URL está na lista '
			'ou não está.',
		'docs': 'https://developers.google.com/safe-browsing/v4',
		'observables': ['url', 'domain'],
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'placeholder': 'chave do Google Cloud com a Safe Browsing API habilitada'}
		],
		'thresholds': [],
		'testPlaceholder': 'https://testsafebrowsing.appspot.com/s/phishing.html'
	},
	{
		'id': 'phishtank',
		'family': 'blocklist',
		'name': 'PhishTank',
		'kind': 'base comunitária de phishing',
		'description': 'Base colaborativa de URLs de phishing denunciadas e confirmadas por revisores. '
			'Só marca como malicioso o que está na base E foi verificado — uma denúncia ainda em '
			'revisão vira suspeito.',
		'docs': 'https://www.phishtank.com/api_info.php',
		'observables': ['url'],
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE APLICAÇÃO', 'secret': True, 'required': False,
			 'placeholder': 'opcional — sem chave o limite de consultas é menor'}
		],
		'thresholds': [],
		'testPlaceholder': 'uma URL de phishing conhecida'
	},
	{
		'id': 'openphish',
		'family': 'blocklist',
		'name': 'OpenPhish',
		'kind': 'feed comunitário de phishing',
		'description': 'Lista pública de URLs de phishing ativas. Ao contrário dos outros, não é uma '
			'consulta por indicador: o feed inteiro é baixado e a URL é procurada nele. O feed fica '
			'em cache por alguns minutos para não ser rebaixado a cada observável.',
		'docs': 'https://openphish.com/faq.html',
		'observables': ['url'],
		'credentials': [
			{'key': 'feedUrl', 'label': 'URL DO FEED', 'secret': False, 'required': True,
			 'default': 'https://openphish.com/feed.txt',
			 'help': 'O feed comunitário é gratuito e atualizado a cada 12h. Assinantes do feed '
				'premium podem apontar para a URL deles aqui.'}
		],
		'thresholds': [],
		'testPlaceholder': 'uma URL para procurar no feed'
	},
	{
		'id': 'urlhaus',
		'family': 'blocklist',
		'name': 'URLhaus (abuse.ch)',
		'kind': 'URLs de distribuição de malware',
		'description': 'Base da abuse.ch com URLs usadas para distribuir malware. Estar nela é sinal '
			'forte: são URLs confirmadas, não suspeitas. Aceita URL, host e hash de payload.',
		'docs': 'https://urlhaus-api.abuse.ch/',
		'observables': ['url', 'domain', 'ip', 'hash'],
		'credentials': [
			{'key': 'apiKey', 'label': 'AUTH-KEY', 'secret': True, 'required': False,
			 'placeholder': 'opcional — a abuse.ch passou a exigir chave em 2025'}
		],
		'thresholds': [],
		'testPlaceholder': 'uma URL, host ou sha256'
	},
	{
		'id': 'otx',
		'family': 'reputation',
		'name': 'AlienVault OTX',
		'kind': 'inteligência colaborativa',
		'description': 'Conta em quantos "pulses" — coleções de IOCs publicadas por pesquisadores — o '
			'indicador aparece. Um pulse isolado pode ser ruído; vários pulses independentes é '
			'corroboração.',
		'docs': 'https://otx.alienvault.com/api',
		'observables': ['ip', 'domain', 'url', 'hash'],
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'placeholder': 'chave da conta OTX'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'pulses',
			 'min': 1, 'max': 50, 'default': 3,
			 'help': 'Em quantos pulses o indicador precisa aparecer para o veredito ser malicioso.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'pulses',
			 'min': 1, 'max': 50, 'default': 1}
		],
		'testPlaceholder': '8.8.8.8, um domínio ou um hash'
	},
	{
		'id': 'hybridanalysis',
		'family': 'sandbox',
		'name': 'Hybrid Analysis',
		'kind': 'sandbox — relatórios existentes',
		'description': 'Procura relatórios de detonação já existentes para o hash do anexo. Não submete '
			'nada: só lê o que a sandbox já analisou, o que mantém a consulta rápida e não expõe o '
			'anexo a terceiros.',
		'docs': 'https://www.hybrid-analysis.com/docs/api/v2',
		'observables': ['hash'],
		'credentials': [
			{'key': 'apiKey', 'label': 'CHAVE DE API', 'secret': True, 'required': True,
			 'placeholder': 'chave da conta Hybrid Analysis'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'de threat score',
			 'min': 1, 'max': 100, 'default': 70,
			 'help': 'Threat score (0–100) do relatório. Um veredito explícito de "malicious" na '
				'sandbox marca como malicioso independentemente da pontuação.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'de threat score',
			 'min': 1, 'max': 100, 'default': 30}
		],
		'testPlaceholder': 'um sha256 de amostra conhecida'
	},
	{
		'id': 'mdti',
		'family': 'reputation',
		'name': 'Microsoft Defender Threat Intelligence',
		'kind': 'reputação de host',
		'description': 'Reputação de domínios e IPs pela base da Microsoft, com a classificação e a '
			'pontuação que ela atribui e as regras que motivaram cada uma. Autentica por OAuth 2.0 '
			'no Microsoft Graph.',
		'docs': 'https://learn.microsoft.com/graph/api/resources/security-hostreputation',
		'observables': ['ip', 'domain'],
		'credentials': [
			{'key': 'tenantId', 'label': 'TENANT ID', 'secret': False, 'required': True,
			 'placeholder': '00000000-0000-0000-0000-000000000000'},
			{'key': 'clientId', 'label': 'CLIENT ID', 'secret': False, 'required': True,
			 'placeholder': '00000000-0000-0000-0000-000000000000'},
			{'key': 'clientSecret', 'label': 'CLIENT SECRET', 'secret': True, 'required': True,
			 'help': 'O registro de aplicativo precisa da permissão de aplicação '
				'ThreatIntelligence.Read.All com consentimento do administrador.'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'de pontuação',
			 'min': 1, 'max': 100, 'default': 75,
			 'help': 'A classificação da própria Microsoft prevalece: um host que ela chama de '
				'malicioso é marcado como tal, qualquer que seja a pontuação.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'de pontuação',
			 'min': 1, 'max': 100, 'default': 25}
		],
		'testPlaceholder': 'um domínio ou IP'
	},
	{
		'id': 'crowdstrike',
		'family': 'reputation',
		'name': 'CrowdStrike Falcon Intel',
		'kind': 'inteligência de ameaças',
		'description': 'Procura o indicador na base de inteligência da CrowdStrike e usa o nível de '
			'malícia atribuído por ela. Autentica por OAuth 2.0 client credentials.',
		'docs': 'https://falcon.crowdstrike.com/documentation',
		'observables': ['ip', 'domain', 'url', 'hash'],
		'credentials': [
			{'key': 'clientId', 'label': 'CLIENT ID', 'secret': False, 'required': True,
			 'placeholder': 'client id da API do Falcon'},
			{'key': 'clientSecret', 'label': 'CLIENT SECRET', 'secret': True, 'required': True},
			{'key': 'cloud', 'label': 'REGIÃO', 'secret': False, 'required': True,
			 'default': 'us-1', 'options': ['us-1', 'us-2', 'eu-1', 'us-gov-1'],
			 'help': 'Região do seu tenant Falcon; a errada devolve 401 mesmo com credenciais válidas.'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'indicadores',
			 'min': 1, 'max': 20, 'default': 1,
			 'help': 'Quantos indicadores de alta malícia bastam para o veredito ser malicioso.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'indicadores',
			 'min': 1, 'max': 20, 'default': 1}
		],
		'testPlaceholder': 'um IP, domínio ou hash conhecido'
	},
	{
		'id': 'crowdstrike_sandbox',
		'family': 'sandbox',
		'name': 'CrowdStrike Falcon Sandbox',
		'kind': 'sandbox — relatórios existentes',
		'description': 'Procura relatórios de detonação que a Falcon Intelligence Sandbox já produziu, '
			'por hash do anexo ou pela URL detonada. Não submete nada: o anexo e a URL não saem da '
			'rede, e a consulta responde no mesmo instante em vez de esperar minutos por uma '
			'detonação.',
		'docs': 'https://falcon.crowdstrike.com/documentation/page/f0d4b95d/falcon-sandbox',
		'observables': ['hash', 'url'],
		'credentials': [
			{'key': 'clientId', 'label': 'CLIENT ID', 'secret': False, 'required': True,
			 'placeholder': 'client id da API do Falcon'},
			{'key': 'clientSecret', 'label': 'CLIENT SECRET', 'secret': True, 'required': True,
			 'help': 'As credenciais precisam do escopo Sandbox (Falcon Intelligence) — o mesmo par '
				'usado no Falcon Intel só serve aqui se tiver esse escopo também.'},
			{'key': 'cloud', 'label': 'REGIÃO', 'secret': False, 'required': True,
			 'default': 'us-1', 'options': ['us-1', 'us-2', 'eu-1', 'us-gov-1'],
			 'help': 'Região do seu tenant Falcon; a errada devolve 401 mesmo com credenciais válidas.'}
		],
		'thresholds': [
			{'key': 'maliciousMin', 'label': 'MALICIOSO A PARTIR DE', 'unit': 'de threat score',
			 'min': 1, 'max': 100, 'default': 70,
			 'help': 'Threat score (0–100) do relatório. Um veredito explícito de "malicious" na '
				'sandbox marca como malicioso independentemente da pontuação.'},
			{'key': 'suspiciousMin', 'label': 'SUSPEITO A PARTIR DE', 'unit': 'de threat score',
			 'min': 1, 'max': 100, 'default': 30}
		],
		'testPlaceholder': 'um sha256 de amostra conhecida ou uma URL já detonada'
	}
]

BY_ID = dict((a['id'], a) for a in ANALYZERS)

# Falcon has one API host per region
CROWDSTRIKE_HOSTS = {
	'us-1': 'https://api.crowdstrike.com',
	'us-2': 'https://api.us-2.crowdstrike.com',
	'eu-1': 'https://api.eu-1.crowdstrike.com',
	'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com'
}


def field_defs(analyzer_id):
	"""Credential and threshold definitions of one analyzer."""
	spec = BY_ID.get(analyzer_id)
	if spec is None:
		return [], []
	return spec.get('credentials', []), spec.get('thresholds', [])


# --------------------------------------------------------------------------- #
# Configuration                                                                #
# --------------------------------------------------------------------------- #

def normalize_observables(analyzer_id, raw):
	"""Quais tipos este analisador vai receber, a partir do que está gravado.

	Mantém a ordem do registro (e não a que veio do disco ou do formulário), de
	modo que a tela liste sempre igual. Um valor ausente, vazio ou que não seja
	lista significa "todos os que ele sabe avaliar": é o comportamento anterior à
	existência desta escolha, e é o que uma instalação que nunca a tocou espera.
	"""
	spec = BY_ID.get(analyzer_id)
	if spec is None:
		return []
	supported = spec['observables']
	if not isinstance(raw, (list, tuple, set)):
		return list(supported)
	chosen = [t for t in supported if t in raw]
	return chosen if chosen else list(supported)


def default_config():
	"""Every analyzer disabled, thresholds at their documented defaults."""
	config = {}
	for spec in ANALYZERS:
		entry = {'enabled': False}
		for field in spec.get('credentials', []):
			entry[field['key']] = field.get('default', '')
		for field in spec.get('thresholds', []):
			entry[field['key']] = field['default']
		# Todo tipo que o fornecedor sabe avaliar, até que alguém restrinja
		entry['observables'] = list(spec['observables'])
		config[spec['id']] = entry
	return config


def load_config(path = CONFIG_FILE):
	"""Stored configuration merged over the defaults.

	Merging rather than replacing means a configuration.json written before an
	analyzer (or a threshold) existed still yields a complete, usable entry.
	"""
	config = default_config()
	try:
		with open(path) as conf_file:
			stored = json.load(conf_file).get(CONFIG_SECTION, {})
	except Exception:
		return config
	for analyzer_id, entry in (stored or {}).items():
		if analyzer_id not in config or not isinstance(entry, dict):
			continue
		for key, value in entry.items():
			if key in config[analyzer_id]:
				config[analyzer_id][key] = value
	# A lista de tipos vem do disco e pode ter sido escrita à mão, ter um tipo que
	# o fornecedor nunca soube avaliar, ou ter ficado vazia. Normalizar aqui é o
	# que garante que o resto do módulo trate `observables` como um dado válido
	for analyzer_id in config:
		config[analyzer_id]['observables'] = normalize_observables(
			analyzer_id, config[analyzer_id].get('observables'))
	return config


def save_config(config, path = CONFIG_FILE):
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[CONFIG_SECTION] = config
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def public_config(config):
	"""The configuration as the browser may see it.

	A stored secret is never echoed back — only whether one exists — so an API
	key cannot be read out of the interface by anyone who reaches the endpoint.
	"""
	public = {}
	for spec in ANALYZERS:
		entry = config.get(spec['id'], {})
		out = {'enabled': bool(entry.get('enabled', False))}
		for field in spec.get('credentials', []):
			key = field['key']
			if field.get('secret'):
				out['has' + key[0].upper() + key[1:]] = bool(entry.get(key))
			else:
				out[key] = entry.get(key, field.get('default', ''))
		for field in spec.get('thresholds', []):
			out[field['key']] = entry.get(field['key'], field['default'])
		out['observables'] = normalize_observables(spec['id'], entry.get('observables'))
		public[spec['id']] = out
	return public


def validate_entry(analyzer_id, submitted, stored):
	"""Validate one analyzer's submitted settings against its registry entry.

	Returns (entry, error). An empty secret means "keep the stored one", which is
	how every other settings form in this application behaves.
	"""
	spec = BY_ID.get(analyzer_id)
	if spec is None:
		return None, 'Analisador desconhecido: {0}.'.format(analyzer_id)

	stored = stored or {}
	entry = {'enabled': bool(submitted.get('enabled', False))}

	for field in spec.get('credentials', []):
		key = field['key']
		value = submitted.get(key, '')
		value = '' if value is None else str(value).strip()
		if field.get('secret') and value == '':
			# Blank means unchanged, not cleared
			value = stored.get(key, '')
		elif not field.get('secret') and value == '':
			value = stored.get(key, '') or field.get('default', '')
		options = field.get('options')
		if options and value not in options:
			return None, '{0}: valor inválido para {1}.'.format(spec['name'], field['label'].lower())
		# A credential is only required to actually run; saving a disabled
		# analyzer half-filled is allowed so the form can be filled in stages
		if entry['enabled'] and field.get('required') and value == '':
			return None, '{0}: {1} é obrigatório para habilitar o analisador.'.format(
				spec['name'], field['label'].lower())
		entry[key] = value

	for field in spec.get('thresholds', []):
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

	# Quais tipos de observável vão para este fornecedor. Chave ausente significa
	# "não mexeu nisso" — é o que a rota de teste manda, e o que uma integração
	# antiga continuaria mandando — então cai no que está gravado.
	if 'observables' in submitted:
		submitted_types = submitted.get('observables')
		if not isinstance(submitted_types, (list, tuple)):
			return None, '{0}: a lista de tipos de observável é inválida.'.format(spec['name'])
		unknown = [str(t) for t in submitted_types if str(t) not in spec['observables']]
		if unknown:
			return None, '{0}: não avalia observáveis do tipo {1}.'.format(
				spec['name'], ', '.join(sorted(set(unknown))))
		chosen = [t for t in spec['observables'] if t in submitted_types]
		# Habilitado sem nenhum tipo é um analisador que nunca roda: parece ligado
		# na tela e não aparece em análise nenhuma. Recusar é mais honesto do que
		# deixar o analista descobrir isso pelo silêncio
		if entry['enabled'] and not chosen:
			return None, ('{0}: escolha ao menos um tipo de observável para enviar, ou desabilite '
				'o analisador.').format(spec['name'])
		entry['observables'] = chosen or list(spec['observables'])
	else:
		entry['observables'] = normalize_observables(analyzer_id, stored.get('observables'))

	# A suspicious threshold above the malicious one would make the suspicious
	# band unreachable — every hit strong enough to be suspicious would already
	# have been malicious. Catch it here rather than let it silently mislabel.
	if 'maliciousMin' in entry and 'suspiciousMin' in entry:
		if entry['suspiciousMin'] > entry['maliciousMin']:
			return None, ('{0}: o limiar de suspeito ({1}) não pode ser maior que o de malicioso ({2}) '
				'— a faixa de suspeito ficaria inalcançável.').format(
					spec['name'], entry['suspiciousMin'], entry['maliciousMin'])

	return entry, None


# --------------------------------------------------------------------------- #
# Verdict thresholds — pure, and the part worth testing                        #
# --------------------------------------------------------------------------- #

def level_for(analyzer_id, thresholds, signal):
	"""Map a normalized analyzer signal onto a pipeline level.

	`signal` is whatever the corresponding client produced; `None` means the
	analyzer could not judge this observable, which is 'info' rather than 'safe'
	— it never looked, so it cannot vouch for it.
	"""
	if signal is None:
		return 'info'

	if analyzer_id == 'virustotal':
		malicious = int(signal.get('malicious', 0))
		suspicious = int(signal.get('suspicious', 0))
		total = int(signal.get('total', 0))
		if malicious >= thresholds['maliciousMin']:
			return 'malicious'
		if malicious + suspicious >= thresholds['suspiciousMin']:
			return 'suspicious'
		# No engine flagged it, but engines did look
		return 'safe' if total > 0 else 'info'

	if analyzer_id == 'abuseipdb':
		score = int(signal.get('score', 0))
		if score >= thresholds['maliciousMin']:
			return 'malicious'
		if score >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'yara':
		matches = int(signal.get('matches', 0))
		if matches >= thresholds['maliciousMin']:
			return 'malicious'
		if matches >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'crowdstrike':
		high = int(signal.get('highConfidence', 0))
		total = int(signal.get('indicators', 0))
		if high >= thresholds['maliciousMin']:
			return 'malicious'
		if total >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'crowdstrike_sandbox':
		if not signal.get('reports'):
			# The sandbox never detonated this sample or URL, which says nothing
			# about it — absence of a report is not a clean bill of health
			return 'info'
		# The sandbox's own verdict outranks the numeric score, as with any other
		# vendor that states one
		verdict = str(signal.get('verdict', '')).lower()
		if verdict == 'malicious':
			return 'malicious'
		score = int(signal.get('threatScore', 0))
		if score >= thresholds['maliciousMin']:
			return 'malicious'
		if verdict == 'suspicious' or score >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'safebrowsing':
		# A blocklist is binary: Google either has it flagged or it does not.
		# Absence is not a clean bill of health, so it is 'safe', never stronger.
		return 'malicious' if signal.get('matches') else 'safe'

	if analyzer_id == 'phishtank':
		if not signal.get('inDatabase'):
			return 'info'
		if signal.get('verified') and signal.get('valid'):
			return 'malicious'
		# Reported but still awaiting a reviewer, or reviewed and rejected
		return 'suspicious' if signal.get('valid') else 'safe'

	if analyzer_id == 'openphish':
		return 'malicious' if signal.get('listed') else 'safe'

	if analyzer_id == 'urlhaus':
		# URLhaus only holds confirmed malware-distribution URLs, so presence is
		# a conviction on its own — there is no "somewhat listed"
		if not signal.get('listed'):
			return 'safe'
		# ...for the URL or the payload it names. A HOST lookup answers "some URL
		# on this host was once listed", and hosts are shared: a Braze image CDN
		# (dXXXX.cloudfront.net) with one old malware_download entry convicted a
		# Strava newsletter whose own URLs were not listed at all (2026-09-09).
		# Offline everywhere on a host is history about a neighbour: suspicious,
		# for a human to weigh. A URL still online there is a live conviction
		if signal.get('scope') == 'host' and not signal.get('online'):
			return 'suspicious'
		return 'malicious'

	if analyzer_id == 'otx':
		pulses = int(signal.get('pulses', 0))
		if pulses >= thresholds['maliciousMin']:
			return 'malicious'
		if pulses >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'hybridanalysis':
		if not signal.get('reports'):
			# Nothing detonated this sample yet, which says nothing about it
			return 'info'
		# The sandbox's own verdict outranks the numeric score
		verdict = str(signal.get('verdict', '')).lower()
		if verdict == 'malicious':
			return 'malicious'
		score = int(signal.get('threatScore', 0))
		if score >= thresholds['maliciousMin']:
			return 'malicious'
		if verdict == 'suspicious' or score >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe'

	if analyzer_id == 'mdti':
		# Microsoft's own classification is authoritative; the score only decides
		# the cases it left as neutral or unknown
		classification = str(signal.get('classification', '')).lower()
		if classification == 'malicious':
			return 'malicious'
		score = int(signal.get('score', 0))
		if score >= thresholds['maliciousMin']:
			return 'malicious'
		if classification == 'suspicious' or score >= thresholds['suspiciousMin']:
			return 'suspicious'
		return 'safe' if classification else 'info'

	return 'info'


def guess_observable_type(value):
	"""Best-effort type of a value typed into the test box.

	Only used by the "Testar" button, where the analyst supplies a loose string.
	The pipeline never guesses — TheHive already knows each observable's type.
	"""
	value = str(value or '').strip()
	if not value:
		return ''
	if value.startswith(('http://', 'https://')):
		return 'url'
	if os.path.sep in value or value.startswith('/'):
		return 'file'
	if re.match(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$', value):
		return 'hash'
	if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
		octets = [int(part) for part in value.split('.')]
		if all(octet <= 255 for octet in octets):
			return 'ip'
	if ':' in value and re.match(r'^[0-9a-fA-F:]+$', value):
		return 'ip'
	if '@' in value:
		return 'mail'
	if '.' in value:
		return 'domain'
	return ''


def supports(analyzer_id, observable_type):
	"""Whether an analyzer can judge this observable type at all."""
	spec = BY_ID.get(analyzer_id)
	if spec is None:
		return False
	# The pipeline tags forwarded .eml attachments as 'file_message/rfc822'
	base_type = str(observable_type or '').split('_')[0]
	return base_type in spec['observables']


def sends(analyzer_id, observable_type, config):
	"""Se este observável vai ser mandado a este analisador nesta instalação.

	`supports` responde o que o fornecedor sabe avaliar; esta responde o que quem
	administra escolheu mandar. As duas são separadas de propósito: o botão
	Testar consulta a primeira, porque ali o analista está pedindo a consulta
	explicitamente e não faria sentido a tela recusar o que ela mesma ofereceu.
	"""
	if not supports(analyzer_id, observable_type):
		return False
	entry = (config or {}).get(analyzer_id, {})
	base_type = str(observable_type or '').split('_')[0]
	return base_type in normalize_observables(analyzer_id, entry.get('observables'))


# --------------------------------------------------------------------------- #
# Vendor clients — each returns a normalized signal or raises                   #
# --------------------------------------------------------------------------- #

class AnalyzerError(Exception):
	"""A vendor call failed in a way worth showing the analyst verbatim."""


class RateLimited(AnalyzerError):
	"""The vendor refused this call *for now*, and the same call may work later.

	Kept apart from the other failures because the pipeline treats it differently:
	a 429 from a free VirusTotal key (4 queries a minute) is not a verdict, it is
	a "come back in a minute". run() marks these results as retryable so that
	run_analysis can requeue them instead of recording a false 'info'.
	"""


def _virustotal_path(observable_type, value):
	"""VirusTotal addresses each observable class under its own collection."""
	if observable_type == 'ip':
		return 'ip_addresses/' + value
	if observable_type == 'domain':
		return 'domains/' + value
	if observable_type == 'hash':
		return 'files/' + value
	# A URL is addressed by its unpadded base64url form
	encoded = base64.urlsafe_b64encode(value.encode('utf-8')).decode('ascii').strip('=')
	return 'urls/' + encoded


def query_virustotal(entry, observable_type, value):
	api_key = entry.get('apiKey', '')
	if not api_key:
		raise AnalyzerError('Chave de API do VirusTotal não configurada.')
	url = 'https://www.virustotal.com/api/v3/' + _virustotal_path(observable_type, value)
	response = requests.get(url, headers = {'x-apikey': api_key}, timeout = HTTP_TIMEOUT)
	if response.status_code == 401:
		raise AnalyzerError('O VirusTotal recusou a chave de API (401).')
	if response.status_code == 429:
		raise RateLimited('Limite de consultas do VirusTotal atingido (429). A chave gratuita '
			'permite 4 por minuto.')
	if response.status_code == 404:
		# Unknown to VirusTotal is a real answer, not a failure
		return {'malicious': 0, 'suspicious': 0, 'total': 0, 'unknown': True}
	response.raise_for_status()
	stats = (response.json().get('data', {}).get('attributes', {}) or {}).get('last_analysis_stats', {}) or {}
	malicious = int(stats.get('malicious', 0))
	suspicious = int(stats.get('suspicious', 0))
	total = sum(int(v) for v in stats.values() if isinstance(v, int))
	return {'malicious': malicious, 'suspicious': suspicious, 'total': total, 'unknown': False}


def query_abuseipdb(entry, observable_type, value):
	api_key = entry.get('apiKey', '')
	if not api_key:
		raise AnalyzerError('Chave de API do AbuseIPDB não configurada.')
	response = requests.get(
		'https://api.abuseipdb.com/api/v2/check',
		headers = {'Key': api_key, 'Accept': 'application/json'},
		params = {'ipAddress': value, 'maxAgeInDays': entry.get('maxAgeInDays', 90)},
		timeout = HTTP_TIMEOUT)
	if response.status_code == 401:
		raise AnalyzerError('O AbuseIPDB recusou a chave de API (401).')
	if response.status_code == 429:
		raise RateLimited('Limite diário de consultas do AbuseIPDB atingido (429).')
	if response.status_code == 422:
		raise AnalyzerError('O AbuseIPDB só aceita endereços IP.')
	response.raise_for_status()
	data = response.json().get('data', {}) or {}
	return {
		'score': int(data.get('abuseConfidenceScore', 0)),
		'reports': int(data.get('totalReports', 0)),
		'country': data.get('countryCode') or ''
	}


def run_off_hub(function, *args):
	"""Roda uma função bloqueante sem parar o resto do processo.

	Todo I/O daqui passa por greenlets do eventlet, que só trocam de contexto
	quando alguém cede o controle. Uma extensão em C não cede: enquanto o YARA
	compila regras e varre um anexo grande, o processo inteiro fica parado — o
	log da análise não anda, a caixa não é lida e a interface parece travada.
	`tpool` empurra a chamada para uma thread de sistema de verdade, que é o
	único jeito de o hub continuar girando enquanto ela roda.

	Sem eventlet (num teste que importe só este módulo) a chamada acontece
	direto, que é o comportamento correto quando não há hub para proteger.
	"""
	try:
		from eventlet import tpool
	except ImportError:
		return function(*args)
	return tpool.execute(function, *args)


def _compile_and_match_yara(rule_files, path):
	"""A parte que bloqueia: compilar as regras e varrer o arquivo."""
	import yara
	compiled = yara.compile(filepaths = rule_files)
	return [str(match) for match in compiled.match(path)]


def query_yara(entry, observable_type, value):
	"""Match the local rule set against a file path.

	yara-python is an optional dependency: when it is absent the analyzer says so
	instead of pretending the file is clean.
	"""
	try:
		import yara  # noqa: F401 — só para reportar a ausência antes de qualquer trabalho
	except ImportError:
		raise AnalyzerError('O módulo yara-python não está instalado nesta imagem. '
			'Adicione-o ao Dockerfile para usar este analisador.')
	rules_path = entry.get('rulesPath', '')
	if not rules_path or not os.path.isdir(rules_path):
		raise AnalyzerError('Diretório de regras não encontrado: {0}'.format(rules_path or '(vazio)'))
	rule_files = {}
	for root, _dirs, files in os.walk(rules_path):
		for name in files:
			if name.lower().endswith(('.yar', '.yara')):
				rule_files['r{0}'.format(len(rule_files))] = os.path.join(root, name)
	if not rule_files:
		raise AnalyzerError('Nenhuma regra .yar/.yara em {0}.'.format(rules_path))
	if not os.path.isfile(value):
		raise AnalyzerError('Arquivo não encontrado: {0}'.format(value))
	try:
		matched = run_off_hub(_compile_and_match_yara, rule_files, value)
	except Exception as error:
		raise AnalyzerError('Falha ao compilar as regras ou varrer o arquivo: {0}'.format(error))
	return {
		'matches': len(matched),
		'rules': matched[:10],
		'ruleFiles': len(rule_files)
	}


def _crowdstrike_token(entry):
	host = CROWDSTRIKE_HOSTS.get(entry.get('cloud', 'us-1'), CROWDSTRIKE_HOSTS['us-1'])
	response = requests.post(
		host + '/oauth2/token',
		data = {'client_id': entry.get('clientId', ''), 'client_secret': entry.get('clientSecret', '')},
		headers = {'Content-Type': 'application/x-www-form-urlencoded'},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (401, 403):
		raise AnalyzerError('A CrowdStrike recusou as credenciais (HTTP {0}). Confira o client id, '
			'o secret e a região.'.format(response.status_code))
	response.raise_for_status()
	token = response.json().get('access_token')
	if not token:
		raise AnalyzerError('A CrowdStrike não devolveu um token de acesso.')
	return host, token


def query_crowdstrike(entry, observable_type, value):
	if not entry.get('clientId') or not entry.get('clientSecret'):
		raise AnalyzerError('Client id e client secret da CrowdStrike não configurados.')
	host, token = _crowdstrike_token(entry)
	response = requests.get(
		host + '/intel/combined/indicators/v1',
		headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'},
		params = {'filter': "indicator:'{0}'".format(value), 'limit': 50},
		timeout = HTTP_TIMEOUT)
	if response.status_code == 403:
		raise AnalyzerError('As credenciais não têm o escopo de leitura de inteligência (403).')
	response.raise_for_status()
	resources = response.json().get('resources', []) or []
	high = 0
	families = []
	actors = []
	for indicator in resources:
		if str(indicator.get('malicious_confidence', '')).lower() == 'high':
			high += 1
		# Falcon attributes an indicator to malware families and to the adversaries
		# that use it. Both are far more useful in a case than a bare count, and
		# both already come back in this response — they were simply discarded.
		for family in indicator.get('malware_families', []) or []:
			if family and family not in families:
				families.append(family)
		for actor in indicator.get('actors', []) or []:
			if actor and actor not in actors:
				actors.append(actor)
	return {
		'indicators': len(resources),
		'highConfidence': high,
		'families': families[:5],
		'actors': actors[:5]
	}


def _crowdstrike_sandbox_summaries(host, token, report_ids):
	"""Fetch the summary of each report id, tolerating both response shapes."""
	response = requests.get(
		host + '/falconx/entities/report-summaries/v1',
		headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'},
		params = [('ids', report_id) for report_id in report_ids],
		timeout = HTTP_TIMEOUT)
	response.raise_for_status()
	summaries = []
	for report in response.json().get('resources', []) or []:
		# `sandbox` comes back as a list of runs (one per environment), but a
		# single object has been observed on some report shapes
		runs = report.get('sandbox') or []
		if isinstance(runs, dict):
			runs = [runs]
		summaries.append((report, runs))
	return summaries


# The sandbox verdicts, weakest first — a hash detonated in several environments
# is judged by its worst run, not by whichever one came back first
SANDBOX_VERDICTS = ('no specific threat', 'informational', 'unknown', 'suspicious', 'malicious')


def query_crowdstrike_sandbox(entry, observable_type, value):
	"""Read existing Falcon Sandbox reports. Never submits anything.

	Detonation itself is asynchronous and takes minutes, so it cannot produce a
	level within this seam — the same reason ANY.RUN was left out. Looking up a
	report CrowdStrike already produced is synchronous, and it keeps the
	attachment and the URL inside the network.
	"""
	if not entry.get('clientId') or not entry.get('clientSecret'):
		raise AnalyzerError('Client id e client secret da CrowdStrike não configurados.')
	host, token = _crowdstrike_token(entry)

	# The sandbox indexes a file report by the sample hash and a URL report by the
	# URL that was submitted for detonation
	if observable_type == 'url':
		query_filter = "sandbox.submit_url:'{0}'".format(value)
	else:
		query_filter = "sandbox.sha256:'{0}'".format(value)

	response = requests.get(
		host + '/falconx/queries/reports/v1',
		headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'},
		params = {'filter': query_filter, 'limit': 10},
		timeout = HTTP_TIMEOUT)
	if response.status_code == 403:
		raise AnalyzerError('As credenciais não têm o escopo de leitura da Falcon Sandbox (403). '
			'O escopo do Falcon Intel não cobre a sandbox.')
	response.raise_for_status()
	report_ids = response.json().get('resources', []) or []
	if not report_ids:
		# Nobody detonated this sample or URL yet
		return {'reports': 0, 'verdict': '', 'threatScore': 0, 'family': '', 'environment': ''}

	worst = ''
	threat_score = 0
	family = ''
	environment = ''
	for report, runs in _crowdstrike_sandbox_summaries(host, token, report_ids):
		verdict = str(report.get('verdict', '')).lower()
		if verdict in SANDBOX_VERDICTS:
			if not worst or SANDBOX_VERDICTS.index(verdict) > SANDBOX_VERDICTS.index(worst):
				worst = verdict
		for run in runs:
			try:
				score = int(run.get('threat_score', 0) or 0)
			except (TypeError, ValueError):
				score = 0
			if score > threat_score:
				threat_score = score
			family = family or (run.get('malware_family') or '')
			environment = environment or (run.get('environment_description') or '')

	return {
		'reports': len(report_ids),
		'verdict': worst,
		'threatScore': threat_score,
		'family': family,
		'environment': environment
	}


def query_safebrowsing(entry, observable_type, value):
	api_key = entry.get('apiKey', '')
	if not api_key:
		raise AnalyzerError('Chave de API do Google Safe Browsing não configurada.')
	# The API only takes URLs, so a bare domain is promoted to one
	target = value if observable_type == 'url' else 'http://' + value
	response = requests.post(
		'https://safebrowsing.googleapis.com/v4/threatMatches:find',
		params = {'key': api_key},
		json = {
			'client': {'clientId': 'redphish', 'clientVersion': '1.0'},
			'threatInfo': {
				'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
					'POTENTIALLY_HARMFUL_APPLICATION'],
				'platformTypes': ['ANY_PLATFORM'],
				'threatEntryTypes': ['URL'],
				'threatEntries': [{'url': target}]
			}
		},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (400, 403):
		raise AnalyzerError('O Google recusou a chave de API (HTTP {0}). Confirme que a Safe '
			'Browsing API está habilitada no projeto.'.format(response.status_code))
	response.raise_for_status()
	matches = response.json().get('matches', []) or []
	return {
		'matches': len(matches),
		'threats': sorted(set(m.get('threatType', '') for m in matches))
	}


def query_phishtank(entry, observable_type, value):
	data = {'url': base64.b64encode(value.encode('utf-8')).decode('ascii'), 'format': 'json'}
	if entry.get('apiKey'):
		data['app_key'] = entry['apiKey']
	# PhishTank rejects requests without an identifying User-Agent
	response = requests.post(
		'https://checkurl.phishtank.com/checkurl/',
		data = data,
		headers = {'User-Agent': 'phishtank/redphish'},
		timeout = HTTP_TIMEOUT)
	if response.status_code == 403:
		raise AnalyzerError('O PhishTank recusou a consulta (403). O cadastro da API deles está '
			'fechado por períodos; sem chave o limite é bem baixo.')
	if response.status_code == 429:
		raise RateLimited('Limite de consultas do PhishTank atingido (429).')
	response.raise_for_status()
	results = (response.json().get('results') or {})
	return {
		'inDatabase': bool(results.get('in_database')),
		'valid': bool(results.get('valid')),
		'verified': bool(results.get('verified')),
		'page': results.get('phish_detail_page') or ''
	}


# The OpenPhish feed is a flat list, so it is fetched whole and kept briefly in
# memory: re-downloading it per observable would be wasteful and rude to a free
# service. {feed_url: (expires_at, set_of_urls)}
_openphish_cache = {}
OPENPHISH_CACHE_TTL_SECONDS = 900


def query_openphish(entry, observable_type, value):
	feed_url = entry.get('feedUrl') or 'https://openphish.com/feed.txt'
	cached = _openphish_cache.get(feed_url)
	if cached is None or cached[0] < time.time():
		response = requests.get(feed_url, timeout = HTTP_TIMEOUT)
		if response.status_code in (401, 403):
			raise AnalyzerError('O OpenPhish recusou o acesso ao feed (HTTP {0}).'.format(response.status_code))
		response.raise_for_status()
		urls = set(line.strip() for line in response.text.splitlines() if line.strip())
		cached = (time.time() + OPENPHISH_CACHE_TTL_SECONDS, urls)
		_openphish_cache[feed_url] = cached
	feed = cached[1]
	# The feed lists exact URLs; compare without the trailing slash so a cosmetic
	# difference does not hide a match
	needle = value.rstrip('/')
	listed = value in feed or needle in feed or (needle + '/') in feed
	return {'listed': listed, 'feedSize': len(feed)}


def query_urlhaus(entry, observable_type, value):
	if observable_type == 'url':
		endpoint, data = 'url', {'url': value}
	elif observable_type == 'hash':
		key = 'sha256_hash' if len(value) == 64 else 'md5_hash'
		endpoint, data = 'payload', {key: value}
	else:
		endpoint, data = 'host', {'host': value}
	headers = {}
	# abuse.ch moved URLhaus behind an Auth-Key during 2025
	if entry.get('apiKey'):
		headers['Auth-Key'] = entry['apiKey']
	response = requests.post('https://urlhaus-api.abuse.ch/v1/{0}/'.format(endpoint),
		data = data, headers = headers, timeout = HTTP_TIMEOUT)
	if response.status_code in (401, 403):
		raise AnalyzerError('O URLhaus exige uma Auth-Key (HTTP {0}). Gere uma conta na abuse.ch '
			'e informe a chave.'.format(response.status_code))
	response.raise_for_status()
	body = response.json()
	status = body.get('query_status', '')
	if status not in ('ok', 'no_results'):
		raise AnalyzerError('O URLhaus respondeu "{0}".'.format(status))
	scope = {'url': 'url', 'payload': 'payload', 'host': 'host'}[endpoint]
	if status == 'no_results':
		return {'listed': False, 'threat': '', 'online': False, 'scope': scope}
	# A host lookup answers with a list of URLs rather than a single record, and
	# the host is online when ANY of them still is — the first entry is only the
	# newest, and a host with one live URL behind an offline one is live
	urls = body.get('urls') or []
	threat = body.get('threat') or (urls[0].get('threat') if urls else '')
	if urls:
		online = any(str(item.get('url_status') or '') == 'online' for item in urls)
	else:
		online = str(body.get('url_status') or '') == 'online'
	return {'listed': True, 'threat': threat or 'malware_download', 'online': online,
		'count': len(urls) or 1, 'scope': scope}


OTX_SECTIONS = {'ip': 'IPv4', 'domain': 'domain', 'url': 'url', 'hash': 'file'}


def query_otx(entry, observable_type, value):
	api_key = entry.get('apiKey', '')
	if not api_key:
		raise AnalyzerError('Chave de API do AlienVault OTX não configurada.')
	section = OTX_SECTIONS.get(observable_type, 'domain')
	response = requests.get(
		'https://otx.alienvault.com/api/v1/indicators/{0}/{1}/general'.format(section, value),
		headers = {'X-OTX-API-KEY': api_key},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (401, 403):
		raise AnalyzerError('O OTX recusou a chave de API ({0}).'.format(response.status_code))
	if response.status_code == 404:
		return {'pulses': 0, 'names': [], 'unknown': True}
	response.raise_for_status()
	pulse_info = response.json().get('pulse_info', {}) or {}
	pulses = pulse_info.get('pulses', []) or []
	return {
		'pulses': int(pulse_info.get('count', len(pulses))),
		'names': [p.get('name', '') for p in pulses[:3]],
		'unknown': False
	}


def query_hybridanalysis(entry, observable_type, value):
	api_key = entry.get('apiKey', '')
	if not api_key:
		raise AnalyzerError('Chave de API do Hybrid Analysis não configurada.')
	response = requests.post(
		'https://www.hybrid-analysis.com/api/v2/search/hash',
		data = {'hash': value},
		headers = {'api-key': api_key, 'User-Agent': 'Falcon Sandbox', 'accept': 'application/json'},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (401, 403):
		raise AnalyzerError('O Hybrid Analysis recusou a chave de API ({0}).'.format(response.status_code))
	if response.status_code == 429:
		raise RateLimited('Limite de consultas do Hybrid Analysis atingido (429).')
	response.raise_for_status()
	reports = response.json() or []
	if not isinstance(reports, list) or not reports:
		return {'reports': 0, 'verdict': '', 'threatScore': 0, 'family': ''}
	# Several sandboxes may have run the sample; take the harshest verdict
	order = {'malicious': 3, 'suspicious': 2, 'no specific threat': 1, 'whitelisted': 0}
	worst = max(reports, key = lambda r: order.get(str(r.get('verdict') or '').lower(), 0))
	scores = [int(r.get('threat_score') or 0) for r in reports]
	return {
		'reports': len(reports),
		'verdict': worst.get('verdict') or '',
		'threatScore': max(scores) if scores else 0,
		'family': worst.get('vx_family') or ''
	}


def _mdti_token(entry):
	response = requests.post(
		'https://login.microsoftonline.com/{0}/oauth2/v2.0/token'.format(entry.get('tenantId', '')),
		data = {
			'client_id': entry.get('clientId', ''),
			'client_secret': entry.get('clientSecret', ''),
			'scope': 'https://graph.microsoft.com/.default',
			'grant_type': 'client_credentials'
		},
		timeout = HTTP_TIMEOUT)
	if response.status_code in (400, 401):
		raise AnalyzerError('O Entra ID recusou as credenciais. Confira tenant id, client id e secret.')
	response.raise_for_status()
	token = response.json().get('access_token')
	if not token:
		raise AnalyzerError('O Entra ID não devolveu um token de acesso.')
	return token


def query_mdti(entry, observable_type, value):
	for field in ('tenantId', 'clientId', 'clientSecret'):
		if not entry.get(field):
			raise AnalyzerError('Credenciais do Defender TI incompletas.')
	token = _mdti_token(entry)
	response = requests.get(
		'https://graph.microsoft.com/beta/security/threatIntelligence/hosts/{0}/reputation'.format(value),
		headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'},
		timeout = HTTP_TIMEOUT)
	if response.status_code == 403:
		raise AnalyzerError('O aplicativo não tem a permissão ThreatIntelligence.Read.All com '
			'consentimento do administrador (403).')
	if response.status_code == 404:
		return {'classification': '', 'score': 0, 'rules': [], 'unknown': True}
	response.raise_for_status()
	body = response.json()
	return {
		'classification': body.get('classification') or '',
		'score': int(body.get('score') or 0),
		'rules': [r.get('name', '') for r in (body.get('rules') or [])[:3]],
		'unknown': False
	}


CLIENTS = {
	'virustotal': query_virustotal,
	'abuseipdb': query_abuseipdb,
	'yara': query_yara,
	'crowdstrike': query_crowdstrike,
	'crowdstrike_sandbox': query_crowdstrike_sandbox,
	'safebrowsing': query_safebrowsing,
	'phishtank': query_phishtank,
	'openphish': query_openphish,
	'urlhaus': query_urlhaus,
	'otx': query_otx,
	'hybridanalysis': query_hybridanalysis,
	'mdti': query_mdti
}


# --------------------------------------------------------------------------- #
# Entry point                                                                  #
# --------------------------------------------------------------------------- #

def describe(analyzer_id, signal):
	"""One human-readable line about what the analyzer actually saw."""
	if signal is None:
		return 'sem resposta'
	if analyzer_id == 'virustotal':
		if signal.get('unknown'):
			return 'indicador desconhecido do VirusTotal (nunca submetido)'
		return '{0} de {1} motores apontaram como malicioso, {2} como suspeito'.format(
			signal.get('malicious', 0), signal.get('total', 0), signal.get('suspicious', 0))
	if analyzer_id == 'abuseipdb':
		return 'confiança de abuso {0}/100 a partir de {1} denúncia(s){2}'.format(
			signal.get('score', 0), signal.get('reports', 0),
			' · ' + signal['country'] if signal.get('country') else '')
	if analyzer_id == 'yara':
		rules = ', '.join(signal.get('rules', []))
		return '{0} regra(s) casaram de {1} arquivo(s) de regra{2}'.format(
			signal.get('matches', 0), signal.get('ruleFiles', 0), ': ' + rules if rules else '')
	if analyzer_id == 'crowdstrike':
		text = '{0} indicador(es) na base, {1} de alta malícia'.format(
			signal.get('indicators', 0), signal.get('highConfidence', 0))
		families = ', '.join(f for f in signal.get('families', []) if f)
		actors = ', '.join(a for a in signal.get('actors', []) if a)
		if families:
			text += ' · família ' + families
		if actors:
			text += ' · atribuído a ' + actors
		return text
	if analyzer_id == 'crowdstrike_sandbox':
		if not signal.get('reports'):
			return 'nenhum relatório de detonação da Falcon Sandbox para este indicador'
		return '{0} relatório(s), pior veredito "{1}", threat score {2}{3}{4}'.format(
			signal.get('reports', 0), signal.get('verdict') or 'sem veredito',
			signal.get('threatScore', 0),
			' · família ' + signal['family'] if signal.get('family') else '',
			' · ' + signal['environment'] if signal.get('environment') else '')
	if analyzer_id == 'safebrowsing':
		if not signal.get('matches'):
			return 'não consta nas listas do Safe Browsing'
		return 'consta como {0}'.format(', '.join(signal.get('threats', [])) or 'ameaça')
	if analyzer_id == 'phishtank':
		if not signal.get('inDatabase'):
			return 'não consta na base do PhishTank'
		if signal.get('verified'):
			return 'consta e foi verificado como phishing' if signal.get('valid') \
				else 'consta, mas os revisores rejeitaram a denúncia'
		return 'consta como denúncia, ainda aguardando verificação'
	if analyzer_id == 'openphish':
		return '{0} no feed do OpenPhish ({1} URLs ativas)'.format(
			'encontrada' if signal.get('listed') else 'não encontrada', signal.get('feedSize', 0))
	if analyzer_id == 'urlhaus':
		if not signal.get('listed'):
			return 'não consta no URLhaus'
		if signal.get('scope') == 'host':
			return 'o host tem {0} URL(s) listada(s) como {1}, {2}'.format(
				signal.get('count', 1), signal.get('threat', 'malware'),
				'alguma ainda online' if signal.get('online') else 'todas já offline')
		return 'consta como {0}, {1}'.format(
			signal.get('threat', 'malware'), 'ainda online' if signal.get('online') else 'já offline')
	if analyzer_id == 'otx':
		if signal.get('unknown'):
			return 'indicador desconhecido do OTX'
		names = ', '.join(n for n in signal.get('names', []) if n)
		return 'aparece em {0} pulse(s){1}'.format(
			signal.get('pulses', 0), ': ' + names if names else '')
	if analyzer_id == 'hybridanalysis':
		if not signal.get('reports'):
			return 'nenhum relatório de detonação para este hash'
		return '{0} relatório(s), pior veredito "{1}", threat score {2}{3}'.format(
			signal.get('reports', 0), signal.get('verdict') or 'sem veredito',
			signal.get('threatScore', 0),
			' · família ' + signal['family'] if signal.get('family') else '')
	if analyzer_id == 'mdti':
		if signal.get('unknown'):
			return 'host desconhecido do Defender TI'
		rules = ', '.join(r for r in signal.get('rules', []) if r)
		return 'classificado como {0}, pontuação {1}{2}'.format(
			signal.get('classification') or 'desconhecido', signal.get('score', 0),
			' · ' + rules if rules else '')
	return ''


def run(analyzer_id, observable_type, value, config = None):
	"""Judge one observable. Returns {level, signal, detail, error}.

	Never raises: a vendor failure comes back as an 'info' level with the reason
	attached, because one unreachable analyzer must not sink a whole analysis.
	"""
	config = config if config is not None else load_config()
	entry = config.get(analyzer_id, {})
	spec = BY_ID.get(analyzer_id)

	if spec is None:
		return {'level': 'info', 'signal': None, 'detail': '', 'error': 'Analisador desconhecido.'}
	if not entry.get('enabled'):
		return {'level': 'info', 'signal': None, 'detail': '', 'error': 'Analisador desabilitado.'}
	if not supports(analyzer_id, observable_type):
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} não avalia observáveis do tipo {1}.'.format(spec['name'], observable_type)}

	try:
		signal = CLIENTS[analyzer_id](entry, str(observable_type).split('_')[0], value)
	except AnalyzerError as error:
		return {'level': 'info', 'signal': None, 'detail': '', 'error': str(error)}
	except requests.exceptions.Timeout:
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} não respondeu dentro do tempo limite.'.format(spec['name'])}
	except Exception:
		print("[ERROR]_[analyzers]: {0} failed for {1} {2}: {3}".format(
			analyzer_id, observable_type, value, traceback.format_exc()))
		return {'level': 'info', 'signal': None, 'detail': '',
			'error': '{0} devolveu uma resposta inesperada.'.format(spec['name'])}

	thresholds = {}
	for field in spec.get('thresholds', []):
		thresholds[field['key']] = entry.get(field['key'], field['default'])

	return {
		'level': level_for(analyzer_id, thresholds, signal),
		'signal': signal,
		'detail': describe(analyzer_id, signal),
		'error': ''
	}
