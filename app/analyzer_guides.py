"""Guides for the analyzer screen — prose, never logic.

`analyzers.py` holds the registry, the credentials and the threshold logic. What
an analyst needs in order to *decide* something — where a key comes from, what a
threshold means in practice, why an absent answer is not a clean one — is prose,
and it lives here so the logic module stays readable.

Two levels:

  FAMILIES   what a whole class of analyzer can and cannot tell you. Four of
             them, and the difference between them is the difference between
             "nobody flagged it" and "somebody looked and found nothing".

  GUIDES     per analyzer: what it judges, how to get the credential, and how to
             read the verdict it produces.

The interface renders both from this dict, so writing a guide is editing text
here — never new markup. An analyzer with no guide still renders; it simply
shows no guide panel.
"""

# --------------------------------------------------------------------------- #
# Families                                                                     #
# --------------------------------------------------------------------------- #

FAMILIES = {
	'reputation': {
		'label': 'Reputação',
		'summary': 'Conta evidência acumulada sobre o indicador e a compara com um limiar seu.',
		'body': 'São os analisadores que devolvem um número — motores que apontaram, denúncias '
			'recebidas, pulses em que o indicador aparece — e é você quem decide a partir de que '
			'ponto aquilo vira um veredito. Mexer no limiar muda o veredito sem mudar o dado. '
			'Um indicador que o fornecedor nunca viu é "info", não "safe": ninguém olhou.'
	},
	'sandbox': {
		'label': 'Sandbox',
		'summary': 'Lê relatórios de detonação que já existem. Nunca submete nada.',
		'body': 'Uma sandbox executa a amostra num ambiente isolado e observa o comportamento. Os '
			'analisadores desta família apenas *consultam* relatórios que o fornecedor já produziu — '
			'nenhum deles envia o anexo ou a URL. Isso é deliberado: detonar leva minutos e o '
			'pipeline precisa de resposta imediata, e o conteúdo do e-mail não sai da rede. '
			'A consequência prática é que amostra que ninguém detonou volta "info", e isso é '
			'informação legítima, não falha.'
	},
	'blocklist': {
		'label': 'Blocklist',
		'summary': 'Resposta binária: está na lista ou não está. Não há limiar para ajustar.',
		'body': 'Presença condena. Ausência vale pouco: uma URL de phishing criada há dez minutos '
			'ainda não entrou em lista nenhuma, então "não consta" nunca é mais forte que "safe". '
			'Por isso estas famílias não declaram limiares — não há nada a calibrar num sim ou não. '
			'Use-as como corroboração, não como absolvição.'
	},
	'custom': {
		'label': 'Customizado',
		'summary': 'Definido por você. Chama um endereço que alguém digitou, com as travas que isso exige.',
		'body': 'Um analisador nativo chama um endereço que está no código; este chama um que foi '
			'digitado na tela. Por isso ele é mais restrito: só admin cria, e por padrão o destino '
			'precisa ser HTTPS público — endereço na rede interna é recusado. Um serviço interno, '
			'como um MISP on-prem, é alcançável ligando "permitir rede interna" naquele analisador; '
			'aí http também passa, porque serviço interno costuma não ter TLS. O serviço de '
			'metadados da nuvem é recusado dos dois jeitos: nunca é um analisador, e é onde ficam '
			'as credenciais da instância. A validação roda de novo a cada chamada, não só ao salvar. '
			'Redirecionamento não é seguido, porque o destino do redirecionamento nunca passou '
			'pela trava. Anexos não estão disponíveis: mandar arquivo para endereço arbitrário é '
			'exatamente o que esta tela evita. O veredito sai do mapa de valores que você definir, '
			'e o que não casar com regra nenhuma cai no nível de reserva.'
	},
	'local': {
		'label': 'Local',
		'summary': 'Roda dentro da sua infraestrutura. Sem chave, sem limite de consultas, sem saída de dado.',
		'body': 'Nada é enviado a terceiro e não há cota a estourar. Em troca, a cobertura é '
			'exatamente aquela que você mantiver: o analisador só sabe o que suas regras sabem. '
			'É o único tipo que enxerga conteúdo do anexo sem que ele saia da rede.'
	}
}


# --------------------------------------------------------------------------- #
# Per-analyzer guides                                                          #
# --------------------------------------------------------------------------- #

def _sections(judges, credential, reading):
	return [
		{'title': 'O que ele julga', 'body': judges},
		{'title': 'Credencial', 'body': credential},
		{'title': 'Lendo o veredito', 'body': reading}
	]


GUIDES = {
	'virustotal': _sections(
		'IPs, domínios, URLs e hashes contra cerca de 90 motores antivírus e serviços de '
		'blocklist. O que ele devolve é a contagem de motores que apontaram o indicador, não a '
		'opinião de um motor específico.',
		'Crie uma conta gratuita em virustotal.com e copie a chave em "API key" no seu perfil. '
		'A chave gratuita permite 4 consultas por minuto — suficiente para triagem manual, '
		'apertada para um lote grande. Um 429 na tela significa exatamente isso.',
		'Um único motor apontando costuma ser falso positivo; cinco motores independentes é sinal. '
		'Por isso o padrão é malicioso a partir de 5 e suspeito a partir de 1. Indicador que '
		'ninguém nunca submeteu volta "info" — a resposta é "desconhecido", não "limpo".'
	),
	'abuseipdb': _sections(
		'Só endereços IP. Devolve uma pontuação de 0 a 100 baseada nas denúncias de abuso que a '
		'comunidade registrou na janela consultada. Domínio, URL e hash passam batido.',
		'Conta gratuita em abuseipdb.com, seção "API". O plano gratuito dá 1000 consultas por dia.',
		'A pontuação é de confiança, não de gravidade: 100 quer dizer "temos muita certeza de que '
		'este IP foi denunciado", não "este IP é dez vezes pior". A janela de denúncias importa — '
		'90 dias é o padrão porque IP residencial troca de dono e uma denúncia de duas anos atrás '
		'não diz nada sobre quem o usa hoje.'
	),
	'yara': _sections(
		'Anexos, contra o conjunto de regras que você mantém no disco. É o único analisador que '
		'olha o conteúdo do arquivo em vez de consultar a reputação de um identificador.',
		'Não há chave. O que existe é um diretório de regras dentro do container. Use um caminho '
		'sob data/, que é bind-mount do host e sobrevive ao rebuild da imagem — regras gravadas '
		'fora dali desaparecem no próximo build.',
		'Uma regra bem escrita casando já é forte, e por isso o padrão condena com 1. Se suas '
		'regras forem amplas e ruidosas, suba o limiar para exigir corroboração entre regras. '
		'Sem regra no diretório o analisador reclama em vez de dizer que o arquivo está limpo.'
	),
	'safebrowsing': _sections(
		'URLs e domínios contra a mesma lista que o Chrome consulta antes de abrir uma página. '
		'Cobre malware, engenharia social e software indesejado.',
		'Chave do Google Cloud com a Safe Browsing API habilitada no projeto. O erro mais comum '
		'não é chave inválida e sim API não habilitada — os dois voltam como 403.',
		'Binário e sem limiar. Constar condena. Não constar é apenas "safe": a lista do Google é '
		'excelente para phishing de massa e lenta para campanha dirigida, que costuma morrer antes '
		'de ser catalogada.'
	),
	'phishtank': _sections(
		'URLs, contra uma base colaborativa onde denúncias passam por revisão humana.',
		'Opcional. Sem chave de aplicação o limite de consultas é menor, mas funciona.',
		'É o único blocklist com três estados, e vale entender: verificado e válido é malicioso; '
		'denunciado mas ainda em revisão é suspeito; revisado e rejeitado é safe. Não constar na '
		'base é "info" — a URL nunca foi submetida a ninguém.'
	),
	'openphish': _sections(
		'URLs, contra o feed público de phishing ativo.',
		'Sem chave. O que se configura é a URL do feed. Assinantes do feed premium apontam para o '
		'endereço deles aqui.',
		'Diferente dos outros, não é consulta por indicador: o feed inteiro é baixado e a URL é '
		'procurada dentro dele. Fica em cache por 15 minutos para não rebaixar o arquivo a cada '
		'observável de um mesmo e-mail.'
	),
	'urlhaus': _sections(
		'URLs, hosts e hashes de payload, contra a base da abuse.ch de distribuição de malware.',
		'Opcional, mas a abuse.ch passou a exigir Auth-Key em 2025 — sem ela a consulta pode ser '
		'recusada.',
		'Estar na base é sinal forte: são URLs confirmadas, não suspeitas. Uma URL já offline '
		'continua condenando — ela foi usada para distribuir malware, e ter sido derrubada não a '
		'absolve do e-mail que você está analisando agora.'
	),
	'otx': _sections(
		'IPs, domínios, URLs e hashes, contando em quantos "pulses" — coleções de IOCs publicadas '
		'por pesquisadores — o indicador aparece.',
		'Conta gratuita em otx.alienvault.com; a chave fica em Settings.',
		'Um pulse isolado pode ser ruído: qualquer um publica. Vários pulses independentes é '
		'corroboração, e é por isso que o padrão condena a partir de 3. Ajuste para baixo se a sua '
		'operação prefere sensibilidade a precisão.'
	),
	'hybridanalysis': _sections(
		'Hashes de anexo, procurando relatórios de detonação que a sandbox já produziu. Não submete '
		'o arquivo.',
		'Conta em hybrid-analysis.com. A chave fica no perfil, em "API key".',
		'O veredito da sandbox vence a pontuação: uma amostra que ela chama de maliciosa é '
		'maliciosa mesmo com threat score baixo. Hash que ninguém detonou volta "info" — a sandbox '
		'não tem opinião sobre o que nunca executou.'
	),
	'mdti': _sections(
		'Domínios e IPs, pela base da Microsoft, com a classificação e a pontuação que ela atribui '
		'e as regras que motivaram cada uma.',
		'Registro de aplicativo no Entra ID com a permissão de aplicação '
		'ThreatIntelligence.Read.All e consentimento do administrador. Autentica por OAuth 2.0 no '
		'Microsoft Graph, então são três campos: tenant, client id e secret.',
		'A classificação da Microsoft prevalece sobre o número: host que ela chama de malicioso é '
		'malicioso qualquer que seja a pontuação. Os limiares só decidem os casos que ela deixou '
		'como neutro ou desconhecido.'
	),
	'crowdstrike': _sections(
		'IPs, domínios, URLs e hashes contra a base de inteligência da CrowdStrike, usando o nível '
		'de malícia que ela atribui a cada indicador. Também traz a família de malware e o actor '
		'a que o indicador é atribuído, quando houver.',
		'Client id e secret da API do Falcon, com escopo de leitura de inteligência. A região do '
		'tenant importa: a errada devolve 401 mesmo com credenciais corretas.',
		'Indicador de alta malícia condena por padrão a partir de 1 — a base da CrowdStrike é '
		'curada, então presença já significa alguma coisa. Indicador conhecido sem alta malícia '
		'fica em suspeito. A atribuição a um actor é contexto para o caso, não entra no veredito.'
	),
	'crowdstrike_sandbox': _sections(
		'Hashes de anexo e URLs, procurando relatórios de detonação que a Falcon Sandbox já '
		'produziu. Não submete o arquivo nem a URL — é o que permite responder na hora e manter o '
		'conteúdo do e-mail dentro da rede.',
		'Mesmo par client id e secret do Falcon, mas o escopo é outro: precisa do escopo Sandbox '
		'(Falcon Intelligence). Credencial que só tem Intel devolve 403 aqui.',
		'O veredito da sandbox vence a pontuação, como no Hybrid Analysis. Hash detonado em vários '
		'ambientes é julgado pela pior execução, não pela primeira que voltar. Sem relatório é '
		'"info": ninguém detonou, então não há o que ler.'
	)
}


def guide_for(analyzer_id):
	"""Guide sections of one analyzer, or an empty list when it has none."""
	return GUIDES.get(analyzer_id, [])


def family_of(spec):
	"""Family metadata of one registry entry, or None when it declares none."""
	return FAMILIES.get(spec.get('family', ''))
