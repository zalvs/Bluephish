"""Metodologia de score: `score = 100 × Σ (peso × fator)`, fatores em [0,1].

Por que existe
--------------
O veredito que o pipeline produz é categórico — Malicious, Suspicious, Safe — e
foi assim desde o Cortex (`THEPHISH_ARCHITECTURE.md` §1.2). Categoria responde
"o que é" e não responde "o que eu abro primeiro": quarenta casos suspeitos numa
segunda-feira são quarenta linhas indistinguíveis. O score ordena essa fila.

O contrato com o veredito
-------------------------
**O veredito é piso do score, nunca teto.** Um observável malicioso já convicta a
mensagem hoje; se a média ponderada saísse abaixo disso, o score estaria
rebaixando em silêncio o que o pipeline condenou — exatamente o tipo de falha
que este repositório não pode ter. Então:

    score = max( 100 × Σ(peso·fator)/Σ(peso) , piso(veredito) )

e como o piso já é o do veredito corrente, a classificação por faixa só pode
*subir* o veredito, nunca baixá-lo. É a mesma regra que governa a escalada do
LLM, pelo mesmo motivo, e não é coincidência: quem só sabe somar evidência não
tem autoridade para retirá-la.

Não existe modo "autoritativo" em que o score derruba um veredito. A ausência é
deliberada: um único analisador de reputação em desacordo com onze blocklists
limpas produziria média baixa e fecharia como legítimo um e-mail que o
VirusTotal apontou. Rebaixamento neste sistema tem um lugar só, e é a whitelist
de remetente — que é auditada, contada e suspensa automaticamente.

Normalização
------------
Cada fator vive em [0,1] e **nenhum fator subtrai**. Autenticação, por exemplo,
não é "passou = -0,3": é "falhou = +0,7, passou = 0". Um fator que subtraísse
transformaria configurar mais analisadores em baixar o score, e a operação
aprenderia a desligá-los.

O denominador soma só o peso de quem **participou**. `info` — o nível que um
analisador devolve quando não conseguiu olhar (§7.6) — não participa: nem soma
no numerador nem no denominador. Diluir o score porque o VirusTotal estourou a
cota seria transformar uma falha de infraestrutura em um veredito mais brando,
que é precisamente o que `info` existe para impedir.

**Evidência de inocência participa com peso reduzido** (`CLEAN_PARTICIPATION`).
Vale para qualquer fator que valha zero: a blocklist limpa, o modelo que rodou e
não viu engenharia social, o domínio que passou no DMARC. A razão está no §4.9:
"não está na lista" é evidência fraca. Numa média normalizada, um fator zerado
com peso inteiro *arrasta* como se fosse subtração — e foi exatamente o que
fazia uma newsletter perfeitamente autenticada pontuar menos do que a mesma
newsletter sem cabeçalho de autenticação nenhum. Peso inteiro só para quem
encontrou alguma coisa.

Teto de contexto
----------------
Cabeçalho de massa e falha de autenticação são *contexto*: descrevem a forma da
mensagem, não o que ela carrega. Sozinhos eles nunca alcançam a faixa de
phishing.

A condição do teto é **evidência**, não participação: algum analisador ou o LLM
precisa ter *encontrado alguma coisa* (fator > 0). Um analisador que rodou e
devolveu `safe` participa da média, mas não é evidência de nada — e deixá-lo
levantar o teto criava um falso positivo com nome e sobrenome: DMARC fail mais
um `List-Unsubscribe` forjado, com toda a reputação limpa e o LLM desligado,
fechava como malicioso. DMARC quebra em encaminhamento e em lista de discussão
o tempo todo; esse e-mail pertence à fila da analista, não ao arquivo de
maliciosos.

Sem teto nenhum, o caso extremo é pior: uma newsletter num domínio recém
registrado, numa instalação sem analisador habilitado, normalizaria para 100 e
viraria phishing confirmado.

Faixas
------
phishing ≥ 50 · suspeito/spam ≥ 40 · legítimo ≥ 20. Ajustáveis, com a mesma
validação em par que os limiares de analisador têm: uma faixa acima da seguinte
tornaria a de baixo inalcançável.
"""

import json


CONFIG_FILE = 'configuration.json'
CONFIG_SECTION = 'scoring'

# Modo de operação. `escalate` deixa a faixa elevar o veredito (o padrão, e o que
# torna a metodologia operante); `advisory` calcula e mostra o score sem tocar no
# veredito, para quem quer calibrar os pesos antes de confiar neles; `off` não
# calcula nada. Não há modo que rebaixe — ver o cabeçalho deste módulo.
MODES = ('off', 'advisory', 'escalate')
DEFAULT_MODE = 'escalate'

# Fator de cada nível. `info` é ausência, e por isso é None e não 0.0: zero é uma
# opinião ("olhei e está limpo"), None é a falta dela ("não olhei")
LEVEL_FACTOR = {'malicious': 1.0, 'suspicious': 0.5, 'safe': 0.0, 'info': None}

# Quanto do peso um fator zerado carrega no denominador. Ver §4.9 e o cabeçalho
# deste módulo: sem essa redução, configurar mais analisadores limpos baixaria o
# score, e a operação aprenderia a desligá-los
CLEAN_PARTICIPATION = 0.35

# Nome anterior, mantido porque a rota /api/scoring o publica para a tela
SAFE_PARTICIPATION = CLEAN_PARTICIPATION

# Risco do LLM mapeado em [0,1]. Medium já contribui porque é o limiar em que a
# escalada para Suspicious hoje acontece
RISK_FACTOR = {'Low': 0.0, 'Medium': 0.4, 'High': 0.75, 'Critical': 1.0}


# --------------------------------------------------------------------------- #
# Fatores que não são analisador                                               #
# --------------------------------------------------------------------------- #
#
# Entram no mesmo ranking, com o mesmo formato de linha, porque para quem ajusta
# a priorização a pergunta é uma só: quanto este sinal vale no total. Separá-los
# em duas telas obrigaria a somar de cabeça pesos que competem entre si.

SIGNAL_FACTORS = [
	{
		'id': 'signal:llm_risk',
		'name': 'Engenharia social (LLM)',
		'source': 'assunto, corpo e imagens do e-mail',
		'description': 'Nível de risco da avaliação de engenharia social. Só participa quando o '
			'modelo rodou e reconheceu engenharia social — uma avaliação que não detectou nada '
			'contribui zero, nunca desconto.',
		'conviction': True,
		'weight': 0.70
	},
	{
		'id': 'signal:sender_auth',
		'name': 'Autenticação do remetente',
		'source': 'Authentication-Results (SPF/DKIM/DMARC)',
		'description': 'Falha de autenticação do domínio que assina o From. Só pontua quando '
			'falha: um domínio autenticado contribui zero, e nunca abate o que os analisadores '
			'encontraram.',
		'conviction': False,
		'weight': 0.55
	},
	{
		'id': 'signal:bulk_headers',
		'name': 'Cabeçalhos de massa',
		'source': 'List-Unsubscribe, Precedence, SCL (RFC 2369/8058/3098)',
		'description': 'Gramática de correspondência em massa nos cabeçalhos. É o sinal que separa '
			'newsletter de phishing na faixa intermediária; sozinho nunca convicta.',
		'conviction': False,
		'weight': 0.30
	}
]

SIGNAL_BY_ID = dict((factor['id'], factor) for factor in SIGNAL_FACTORS)

# Fatores que podem levar o score à faixa de phishing. Os demais descrevem a
# forma da mensagem, não o que ela carrega
CONVICTION_SIGNALS = frozenset(f['id'] for f in SIGNAL_FACTORS if f['conviction'])


# Peso inicial de cada analisador nativo. Não é uma opinião sobre o fornecedor: é
# quanta evidência independente o veredito dele carrega. Multimotor e sandbox no
# topo (dezenas de opiniões, ou uma detonação real); blocklist de indicador
# isolado abaixo, porque a presença convicta mas a ausência quase não informa
DEFAULT_ANALYZER_WEIGHTS = {
	'virustotal': 0.90,
	'safebrowsing': 0.85,
	'mdti': 0.85,
	'crowdstrike': 0.85,
	'crowdstrike_sandbox': 0.80,
	'hybridanalysis': 0.80,
	'yara': 0.80,
	'urlhaus': 0.75,
	'phishtank': 0.75,
	'openphish': 0.70,
	'abuseipdb': 0.65,
	'otx': 0.60
}

# Um analisador que o registro ganhar depois deste arquivo entra com peso médio em
# vez de sumir do ranking. Peso zero seria pior do que ausência: ele rodaria, a
# tela o mostraria habilitado, e ele não afetaria score nenhum
DEFAULT_WEIGHT = 0.50

# Um analisador definido pela analista aponta para um serviço que ninguém deste
# lado auditou. Entra abaixo dos nativos, e quem confia mais sobe o peso à mão
DEFAULT_CUSTOM_WEIGHT = 0.50

WEIGHT_MIN = 0.0
WEIGHT_MAX = 1.0

DEFAULT_TIERS = {'phishing': 50, 'suspicious': 40, 'legitimate': 20}
TIER_KEYS = ('phishing', 'suspicious', 'legitimate')
TIER_LABEL = {'phishing': 'phishing', 'spam': 'spam', 'suspicious': 'suspeito',
	'legitimate': 'legítimo'}

# Piso que cada veredito impõe ao score. Malicious não pode aparecer abaixo da
# faixa de phishing, e Suspicious não pode aparecer abaixo da de suspeito: a tela
# mostra os dois lado a lado, e "Malicious · 23" é um sistema se contradizendo
VERDICT_FLOOR_TIER = {'Malicious': 'phishing', 'Suspicious': 'suspicious'}


# --------------------------------------------------------------------------- #
# Configuração                                                                 #
# --------------------------------------------------------------------------- #

def default_config():
	"""Pesos padrão de tudo que o registro conhece hoje, e as faixas documentadas."""
	import analyzers

	weights = {}
	for spec in analyzers.ANALYZERS:
		weights[spec['id']] = DEFAULT_ANALYZER_WEIGHTS.get(spec['id'], DEFAULT_WEIGHT)
	for factor in SIGNAL_FACTORS:
		weights[factor['id']] = factor['weight']
	return {
		'mode': DEFAULT_MODE,
		'weights': weights,
		'tiers': dict(DEFAULT_TIERS),
		# Triagem automática de massa: uma mensagem com gramática de lista cujo
		# domínio o servidor de entrada autenticou é rotulada `spam` em vez de
		# ocupar a fila como suspeito. Exige autenticação porque o resto do
		# cabeçalho é escrito por quem enviou
		'spamTriage': True,
		# Pular a análise inteira para essas mensagens poupa cota de fornecedor,
		# e é a única opção aqui que deixa de olhar para alguma coisa — por isso
		# começa desligada
		'spamSkipAnalysis': False
	}


def load_config(path = CONFIG_FILE):
	"""Configuração gravada sobre os padrões.

	Mesclar em vez de substituir é o que faz um `configuration.json` escrito antes
	de um analisador existir continuar produzindo uma configuração completa.
	"""
	config = default_config()
	try:
		with open(path) as conf_file:
			stored = json.load(conf_file).get(CONFIG_SECTION, {}) or {}
	except Exception:
		return config
	if not isinstance(stored, dict):
		return config

	mode = str(stored.get('mode', config['mode']))
	config['mode'] = mode if mode in MODES else DEFAULT_MODE

	stored_weights = stored.get('weights')
	if isinstance(stored_weights, dict):
		for key, value in stored_weights.items():
			weight = _clamp_weight(value)
			if weight is not None:
				config['weights'][str(key)] = weight

	stored_tiers = stored.get('tiers')
	if isinstance(stored_tiers, dict):
		candidate = dict(config['tiers'])
		for key in TIER_KEYS:
			if key in stored_tiers:
				try:
					candidate[key] = int(stored_tiers[key])
				except (TypeError, ValueError):
					pass
		# Faixas gravadas à mão fora de ordem voltam ao padrão inteiro: aplicar
		# metade delas produziria uma classificação que ninguém escreveu
		if _tiers_are_ordered(candidate):
			config['tiers'] = candidate

	config['spamTriage'] = bool(stored.get('spamTriage', config['spamTriage']))
	config['spamSkipAnalysis'] = bool(stored.get('spamSkipAnalysis', config['spamSkipAnalysis']))
	return config


def save_config(config, path = CONFIG_FILE):
	with open(path) as conf_file:
		conf_dict = json.load(conf_file)
	conf_dict[CONFIG_SECTION] = config
	with open(path, 'w') as conf_file:
		json.dump(conf_dict, conf_file, indent = '\t')


def _clamp_weight(raw):
	try:
		weight = float(raw)
	except (TypeError, ValueError):
		return None
	if weight != weight or weight in (float('inf'), float('-inf')):
		return None
	return round(max(WEIGHT_MIN, min(WEIGHT_MAX, weight)), 4)


def _tiers_are_ordered(tiers):
	return (0 <= tiers['legitimate'] < tiers['suspicious'] < tiers['phishing'] <= 100)


def validate_config(submitted, stored, known_ids):
	"""Valida o que a tela de Priorização mandou. Devolve (config, erro).

	`known_ids` são os fatores que existem — analisadores do registro, os
	customizados e os sinais. Um peso para um id que não existe é recusado em vez
	de gravado: peso órfão é uma linha que a analista ajustou e que nunca será
	lida, e ela não tem como perceber isso.
	"""
	submitted = submitted or {}
	config = dict(stored or default_config())
	config['weights'] = dict(config.get('weights') or {})
	config['tiers'] = dict(config.get('tiers') or DEFAULT_TIERS)

	if 'mode' in submitted:
		mode = str(submitted.get('mode') or '')
		if mode not in MODES:
			return None, 'Modo de pontuação inválido: {0}.'.format(mode)
		config['mode'] = mode

	# Restaurar os padrões é um caso à parte, e não "mandar um mapa vazio": a
	# validação mescla sobre o gravado, então um mapa vazio manteria tudo. O
	# padrão vem daqui, que é quem conhece o registro
	if submitted.get('resetWeights'):
		config['weights'] = default_config()['weights']

	if 'weights' in submitted:
		weights = submitted.get('weights')
		if not isinstance(weights, dict):
			return None, 'A lista de pesos é inválida.'
		known = set(known_ids or [])
		for key, raw in weights.items():
			key = str(key)
			if key not in known:
				return None, 'Fator desconhecido: {0}.'.format(key)
			weight = _clamp_weight(raw)
			if weight is None:
				return None, 'Peso inválido para {0}: use um número entre 0 e 1.'.format(key)
			config['weights'][key] = weight
		# Todos zerados é uma configuração que roda e não pontua nada: o score
		# sai 0 para todo e-mail, a fila para de ordenar e nada avisa
		participating = [config['weights'].get(key, 0.0) for key in known]
		if participating and not any(weight > 0 for weight in participating):
			return None, ('Ao menos um fator precisa ter peso maior que zero, ou o score sai '
				'zero para todo e-mail.')

	if 'tiers' in submitted:
		tiers = submitted.get('tiers')
		if not isinstance(tiers, dict):
			return None, 'As faixas são inválidas.'
		candidate = dict(config['tiers'])
		for key in TIER_KEYS:
			if key not in tiers:
				continue
			try:
				candidate[key] = int(tiers[key])
			except (TypeError, ValueError):
				return None, 'A faixa de {0} precisa ser um número inteiro.'.format(TIER_LABEL[key])
		if not _tiers_are_ordered(candidate):
			return None, ('As faixas precisam ser crescentes e caber em 0–100: legítimo < suspeito '
				'< phishing. Do jeito enviado, uma delas ficaria inalcançável.')
		config['tiers'] = candidate

	if 'spamTriage' in submitted:
		config['spamTriage'] = bool(submitted.get('spamTriage'))
	if 'spamSkipAnalysis' in submitted:
		config['spamSkipAnalysis'] = bool(submitted.get('spamSkipAnalysis'))
	return config, None


# --------------------------------------------------------------------------- #
# O registro de fatores que a tela ordena                                      #
# --------------------------------------------------------------------------- #

def factor_rows(native_config = None, custom_definitions = None, config = None):
	"""Uma linha por fator, na forma que a tela de Priorização renderiza.

	`weightShare` é o peso relativo dentro do total — é o número que responde "e
	se eu subir este?", que o peso absoluto sozinho não responde.
	"""
	import analyzers

	config = config or load_config()
	weights = config.get('weights') or {}
	native_config = native_config or {}
	rows = []

	for spec in analyzers.ANALYZERS:
		entry = native_config.get(spec['id']) or {}
		rows.append({
			'id': spec['id'],
			'kind': 'analyzer',
			'name': spec['name'],
			'source': _observable_source(spec.get('observables') or []),
			'description': spec.get('kind') or '',
			'detail': spec.get('description') or '',
			'enabled': bool(entry.get('enabled')),
			'conviction': True,
			'weight': weights.get(spec['id'],
				DEFAULT_ANALYZER_WEIGHTS.get(spec['id'], DEFAULT_WEIGHT))
		})

	for definition in custom_definitions or []:
		rows.append({
			'id': definition['id'],
			'kind': 'custom',
			'name': definition.get('name') or definition['id'],
			'source': _observable_source(definition.get('observables') or []),
			'description': 'analisador definido pela analista',
			'detail': definition.get('description') or '',
			'enabled': bool(definition.get('enabled')),
			'conviction': True,
			'weight': weights.get(definition['id'], DEFAULT_CUSTOM_WEIGHT)
		})

	for factor in SIGNAL_FACTORS:
		rows.append({
			'id': factor['id'],
			'kind': 'signal',
			'name': factor['name'],
			'source': factor['source'],
			'description': 'sinal do próprio e-mail',
			'detail': factor['description'],
			# Um sinal não tem chave de API para configurar: ele existe sempre que
			# o dado que o alimenta existe. Marcá-lo como desligado sugeriria um
			# botão que não há
			'enabled': True,
			'conviction': factor['conviction'],
			'weight': weights.get(factor['id'], factor['weight'])
		})

	total = sum(row['weight'] for row in rows) or 1.0
	for row in rows:
		row['weightShare'] = round(row['weight'] * 100.0 / total, 1)
	rows.sort(key = lambda row: (-row['weight'], row['name'].lower()))
	return rows


OBSERVABLE_LABEL = {'ip': 'IPs', 'domain': 'domínios', 'url': 'URLs',
	'hash': 'hashes', 'file': 'anexos', 'mail': 'endereços'}


def _observable_source(observables):
	labels = [OBSERVABLE_LABEL.get(str(o), str(o)) for o in observables]
	return ', '.join(labels) if labels else '—'


# --------------------------------------------------------------------------- #
# O cálculo                                                                    #
# --------------------------------------------------------------------------- #

def strongest_levels(reports_observables):
	"""O nível mais forte que cada analisador produziu nesta análise.

	Um analisador roda uma vez por observável e um e-mail traz dezenas deles.
	Somar cada execução como fator próprio faria um e-mail de marketing com
	quarenta URLs limpas afundar o score de um anexo malicioso por volume. Um
	analisador é *um* fator, e vale pelo pior que encontrou.
	"""
	levels = {}
	names = {}
	for report_obs in reports_observables or []:
		analyzer_id = report_obs.get('analyzer_id') or report_obs.get('analyzer_name')
		if not analyzer_id:
			continue
		level = report_obs.get('analyzer_result') or 'info'
		if level not in LEVEL_FACTOR:
			level = 'info'
		names.setdefault(analyzer_id, report_obs.get('analyzer_name') or analyzer_id)
		current = levels.get(analyzer_id)
		if current is None or _level_rank(level) > _level_rank(current):
			levels[analyzer_id] = level
	return levels, names


_LEVEL_RANK = {'info': 0, 'safe': 1, 'suspicious': 2, 'malicious': 3}


def _level_rank(level):
	return _LEVEL_RANK.get(level, 0)


def auth_factor(auth_results):
	"""Quanto a autenticação do remetente pesa contra a mensagem, em [0,1].

	`None` quando o servidor de entrada não registrou nada — sem cabeçalho de
	autenticação não há o que afirmar, e afirmar "não autenticado" seria condenar
	um caminho de entrega que simplesmente não escreve o cabeçalho.
	"""
	auth = auth_results or {}
	spf = str(auth.get('spf') or 'none').lower()
	dkim = str(auth.get('dkim') or 'none').lower()
	dmarc = str(auth.get('dmarc') or 'none').lower()
	if spf == 'none' and dkim == 'none' and dmarc == 'none' and not auth.get('raw'):
		return None
	if auth.get('authenticated'):
		return 0.0
	if dmarc == 'fail':
		# DMARC fail é a afirmação mais forte que o receptor faz: o domínio
		# publicou uma política e a mensagem não a cumpriu
		return 1.0
	if spf == 'fail' or dkim == 'fail':
		return 0.7
	if dkim == 'pass' and not auth.get('aligned'):
		# Assinado, mas por outro domínio: é o formato do phishing hospedado em
		# plataforma de terceiro, que assina com o domínio da plataforma
		return 0.5
	return 0.35


def llm_factor(llm_result):
	"""Risco de engenharia social em [0,1], ou None quando o modelo não rodou."""
	if not llm_result:
		return None
	if not llm_result.get('social_engineering_detected'):
		# Rodou e não viu engenharia social: é uma opinião, e vale zero — não
		# ausência. Deixá-la participar com zero é o que permite ao modelo
		# *diluir* um sinal fraco de contexto, sem nunca subtrair de ninguém
		return 0.0
	return RISK_FACTOR.get(str(llm_result.get('risk_level') or 'Low'), 0.0)


def tier_for(score, tiers = None):
	"""A faixa em que um score cai. Abaixo de tudo continua sendo legítimo."""
	tiers = tiers or DEFAULT_TIERS
	if score >= tiers['phishing']:
		return 'phishing'
	if score >= tiers['suspicious']:
		return 'suspicious'
	return 'legitimate'


def floor_for(verdict, tiers = None):
	"""O score mínimo que um veredito já decidido impõe."""
	tiers = tiers or DEFAULT_TIERS
	key = VERDICT_FLOOR_TIER.get(verdict)
	return float(tiers[key]) if key else 0.0


def compute(verdict, reports_observables = None, llm_result = None, auth_results = None,
		bulk_signals = None, config = None, custom_definitions = None):
	"""Calcula o score da análise e devolve a memória de cálculo junto.

	A memória não é enfeite: é a diferença entre uma analista discordar do número
	e uma analista discordar do número *sabendo de onde ele veio*. Cada linha diz
	qual peso, qual fator e quanto contribuiu; quem não participou diz por quê.
	"""
	config = config or load_config()
	tiers = config.get('tiers') or DEFAULT_TIERS
	weights = config.get('weights') or {}
	levels, names = strongest_levels(reports_observables)

	custom_ids = set(d['id'] for d in (custom_definitions or []))
	factors = []
	numerator = 0.0
	denominator = 0.0
	# Evidência, e não participação: um analisador que devolveu `safe` entra na
	# média e não levanta este sinalizador. Ver o teto de contexto no cabeçalho
	conviction_evidence = False

	def add(factor_id, label, weight, value, participation, reason = ''):
		nonlocal numerator, denominator
		share = weight * participation
		contribution = share * (value or 0.0)
		if share > 0:
			numerator += contribution
			denominator += share
		factors.append({
			'id': factor_id,
			'label': label,
			'weight': round(weight, 4),
			'factor': None if value is None else round(value, 4),
			'participation': round(participation, 4),
			'contribution': round(contribution, 4),
			'reason': reason
		})
		return share

	for analyzer_id, level in levels.items():
		value = LEVEL_FACTOR.get(level)
		default = DEFAULT_CUSTOM_WEIGHT if analyzer_id in custom_ids else \
			DEFAULT_ANALYZER_WEIGHTS.get(analyzer_id, DEFAULT_WEIGHT)
		weight = weights.get(analyzer_id, default)
		if value is None:
			add(analyzer_id, names.get(analyzer_id, analyzer_id), weight, None, 0.0,
				'não olhou (info): não entra na média')
			continue
		participation = CLEAN_PARTICIPATION if value == 0.0 else 1.0
		share = add(analyzer_id, names.get(analyzer_id, analyzer_id), weight, value, participation,
			'nível {0}'.format(level))
		if share > 0 and value > 0:
			conviction_evidence = True

	llm_value = llm_factor(llm_result)
	llm_weight = weights.get('signal:llm_risk', SIGNAL_BY_ID['signal:llm_risk']['weight'])
	if llm_value is None:
		add('signal:llm_risk', SIGNAL_BY_ID['signal:llm_risk']['name'], llm_weight, None, 0.0,
			'o modelo não rodou nesta análise')
	else:
		share = add('signal:llm_risk', SIGNAL_BY_ID['signal:llm_risk']['name'], llm_weight,
			llm_value, CLEAN_PARTICIPATION if llm_value == 0.0 else 1.0,
			'risco {0}'.format((llm_result or {}).get('risk_level') or 'Low')
				if (llm_result or {}).get('social_engineering_detected')
				else 'sem engenharia social detectada')
		if share > 0 and llm_value > 0:
			conviction_evidence = True

	auth_value = auth_factor(auth_results)
	auth_weight = weights.get('signal:sender_auth', SIGNAL_BY_ID['signal:sender_auth']['weight'])
	if auth_value is None:
		add('signal:sender_auth', SIGNAL_BY_ID['signal:sender_auth']['name'], auth_weight, None, 0.0,
			'o servidor de entrada não registrou autenticação')
	else:
		auth = auth_results or {}
		add('signal:sender_auth', SIGNAL_BY_ID['signal:sender_auth']['name'], auth_weight,
			auth_value, CLEAN_PARTICIPATION if auth_value == 0.0 else 1.0,
			'spf={0} dkim={1} dmarc={2}'.format(auth.get('spf'), auth.get('dkim'), auth.get('dmarc')))

	bulk = bulk_signals or None
	bulk_weight = weights.get('signal:bulk_headers', SIGNAL_BY_ID['signal:bulk_headers']['weight'])
	if bulk is None:
		add('signal:bulk_headers', SIGNAL_BY_ID['signal:bulk_headers']['name'], bulk_weight, None, 0.0,
			'os cabeçalhos não foram lidos nesta análise')
	else:
		import spam_headers
		bulk_value = float(bulk.get('value') or 0.0)
		add('signal:bulk_headers', SIGNAL_BY_ID['signal:bulk_headers']['name'], bulk_weight,
			bulk_value, CLEAN_PARTICIPATION if bulk_value == 0.0 else 1.0,
			spam_headers.summary(bulk))

	raw = (numerator * 100.0 / denominator) if denominator > 0 else 0.0
	capped = False
	if not conviction_evidence:
		# Contexto sozinho não convicta. O teto é um ponto abaixo da faixa de
		# phishing, e não a faixa em si, para que a fronteira continue sendo
		# "alcançou 50" e não "empatou em 50"
		ceiling = float(max(0, tiers['phishing'] - 1))
		if raw > ceiling:
			raw = ceiling
			capped = True

	floor = floor_for(verdict, tiers)
	score = round(max(raw, floor), 1)
	tier = tier_for(score, tiers)

	# `spam` não é uma quarta faixa de risco — é uma classificação de *natureza*,
	# não de severidade, e por isso não depende de onde o número caiu. Uma
	# newsletter bem autenticada pontua baixo justamente porque é legítima; o que
	# a analista precisa não é que ela suba de faixa, é que ela saia da fila.
	#
	# As três condições andam juntas, e a do meio é a que sustenta as outras: a
	# gramática de lista foi escrita por quem enviou e vale zero sozinha; a
	# autenticação foi escrita pelo servidor que recebeu. E nada disso rotula um
	# e-mail que os analisadores ou o LLM já condenaram — `verdict == 'Safe'` e a
	# faixa fora de phishing são o piso do rótulo.
	label = tier
	if (config.get('spamTriage', True) and verdict == 'Safe' and tier != 'phishing'
			and bulk and bulk.get('bulk')
			and (auth_results or {}).get('authenticated')):
		label = 'spam'

	return {
		'score': score,
		'tier': tier,
		'label': label,
		'raw': round(raw, 1),
		'floor': round(floor, 1),
		'capped': capped,
		'convictionEvidence': conviction_evidence,
		'weightTotal': round(denominator, 4),
		'tiers': dict(tiers),
		'mode': config.get('mode', DEFAULT_MODE),
		'factors': sorted(factors, key = lambda f: -f['contribution'])
	}


def verdict_after(verdict, result, auth_results = None):
	"""O veredito depois da faixa. Só sobe — ver o cabeçalho deste módulo.

	Devolve (veredito, motivo). O motivo é '' quando nada mudou, e é o que vai
	para o log da análise quando muda: uma escalada sem justificativa registrada
	é indistinguível de um bug para quem lê o caso seis semanas depois.
	"""
	if not result or result.get('mode') != 'escalate':
		return verdict, ''
	tier = result.get('tier')
	score = result.get('score')
	if tier == 'phishing' and verdict in ('Safe', 'Suspicious'):
		# O mesmo resguardo da regra 1 da escalada do LLM (§1.2): um domínio que o
		# servidor de entrada autenticou não é fechado como malicioso por um score
		# que a análise de conteúdo e o contexto sustentaram. A escalada mais
		# branda continua valendo, então um remetente legítimo comprometido não
		# desaparece — ele chega como suspeito
		if (auth_results or {}).get('authenticated'):
			if verdict == 'Safe':
				return 'Suspicious', ('Score {0} na faixa de phishing, mas o domínio remetente está '
					'autenticado: escalado para Suspicious em vez de Malicious').format(score)
			return verdict, ('Score {0} na faixa de phishing, mas o domínio remetente está '
				'autenticado: o veredito não foi elevado a Malicious').format(score)
		return 'Malicious', 'Score {0} na faixa de phishing (≥ {1})'.format(
			score, result['tiers']['phishing'])
	if tier == 'suspicious' and verdict == 'Safe' and result.get('label') != 'spam':
		return 'Suspicious', 'Score {0} na faixa de suspeito (≥ {1})'.format(
			score, result['tiers']['suspicious'])
	return verdict, ''


def summary(result):
	"""Uma linha para o log da análise e para a descrição do caso."""
	if not result:
		return ''
	return 'Score {0}/100 — faixa {1} (phishing ≥ {2}, suspeito ≥ {3}), {4} fator(es) na média'.format(
		result['score'], TIER_LABEL.get(result.get('label'), result.get('tier')),
		result['tiers']['phishing'], result['tiers']['suspicious'],
		len([f for f in result['factors'] if f['participation'] > 0]))
