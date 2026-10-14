# Conector Genérico — arquitetura

Documento de arquitetura do módulo de integrações dinâmicas. O manual do usuário
final está em [conectores-manual.md](conectores-manual.md).

## 1. O problema

Hoje cada destino externo é código: `tickets.py` tem `create_jira()`,
`create_thehive()`, `create_disk()`, e cada um novo custa um release. O registro
`DESTINATIONS` é declarativo, mas o *cliente HTTP* de cada destino não é — ele
está escrito à mão, com o formato do corpo, o cabeçalho de autenticação e o
parser da resposta fixos no fonte.

O Conector Genérico troca o eixo: em vez de "um cliente por fornecedor", **um
cliente parametrizado por configuração**. O usuário lê a documentação da
ferramenta de destino, cola a estrutura de JSON que ela exige, marca onde entram
os dados da análise, e a plataforma dispara. Qualquer API REST que aceite um
POST com JSON passa a ser um destino — Jira, TheHive, Splunk HEC, ServiceNow,
PagerDuty, Slack, Teams, Opsgenie, Zendesk, Cortex XSOAR, Sentinel, Elastic,
Datadog, e assim por diante.

### O que isto NÃO substitui

Os destinos nativos continuam existindo e continuam melhores onde já existem.
O TheHive nativo cria observáveis marcados um a um, anexa o `.eml`, dispara
exportação MISP e alimenta as telas de Casos, Phishing e Executivo. Um conector
genérico apontado para o TheHive cria um caso — e só. Um destino nativo é um
conector genérico + integração de leitura + anexos + regras de negócio.

A regra de escolha: **nativo quando a plataforma precisa ler de volta; genérico
quando ela só precisa avisar.**

## 2. Princípios de projeto

1. **Configuração é dado, não código.** Nenhum template é avaliado como
   expressão. Nada de Jinja2, `eval`, `format()` com string do usuário. A
   renderização é substituição literal de placeholders de uma lista fechada.
   Um template Jinja controlado pelo usuário é execução remota de código no
   nosso servidor, e "só admins editam" não é uma resposta aceitável para isso.
2. **O destino é hostil até prova em contrário.** Um POST para uma URL digitada
   na tela é SSRF por construção — e o corpo carrega o e-mail da vítima, o que
   também faz dele um canal de exfiltração. Vale a mesma trava de
   `custom_analyzers.validate_destination()`, revalidada no disparo, não só ao
   salvar.
3. **Um disparo nunca derruba a análise.** Mesmo contrato de
   `tickets.create()`: falha vira registro, nunca exceção que sobe.
4. **Segredo entra e não sai.** A API devolve `hasAuthValue: true` para a
   credencial e `hasValue: true` para cada parâmetro secreto, jamais o valor.
   O resultado de cada disparo já carrega o request *redigido*; o log de entrega
   que o guardaria é planejado (fase 2) — não implementado.
5. **O usuário precisa ver o que vai sair.** Um construtor de payload sem
   pré-visualização do JSON renderizado é um gerador de tickets vazios.

## 3. Arquitetura

```
      run_analysis.main()  →  terminate_analysis()     (o veredito já está decidido)
                              │
                              ▼
                     departments.resolve_from_file()   → department ('' se não resolver)
                              │
                              ▼
                     tickets.build_report()          (report normalizado, sem TheHive dentro)
                              │                      + notifications, score, bulk
                              ▼
                     tickets.dispatch(report)  ──►  TheHive / Jira / disco
                              │         (TheHive primeiro: preenche report['caseRef'])
                              ▼
                     remember_analysis()             (impressão digital e original)
                              │
                              ▼
         ┌──────────── connectors.dispatch(report, connectors.load_all()) ────────────┐
         │ enabled_for(): enabled + accepts_verdict(minVerdict)                       │
         │ um por vez, síncrono, dentro de run_analysis.main():                       │
         │ main() só retorna quando o último termina                                  │
         │ um que falha não impede os outros                                          │
         └─────────────────────────────────────┬──────────────────────────────────────┘
                                               │  deliver(definition, report) — nunca levanta
                                               ▼
                     context_from_report(report, secret_map(definition))
                              │   ◄── params isSecret, por chave → {{secrets.<chave>}}
                              ▼
                     build_request(): render(url, payloadTemplate, params) + apply_auth()
                              │   ◄── authValue vai direto para header/query, fora do contexto
                              │   (os dois vêm da definição: configuration.json, seção connectors)
                              ▼
                     validate_destination(url, allowInternal)   ← revalidação no disparo
                              │
                              ▼
                     corpo serializado ≤ MAX_BODY_BYTES (512 KB)
                              │
                              ▼
                     pinned_http.request()   resolve o nome uma vez ao conectar, recusa
                              │              endereço proibido (DestinationRefused) e conecta
                              │              pelo IP; sem redirect, timeout (10 s conexão,
                              │              leitura 1–60 s, padrão 30), verifyTls
                              │              (via HTTP(S)_PROXY, quem resolve é o proxy)
                              ▼
                     classify(): status em successStatus → ok + ref de resultRefPath; senão, falha
                              │
                              ▼
                     resultado → run_analysis registra só detail/erro (log + websocket);
                                 o request redigido e a resposta são descartados — nada é gravado

   Se build_report() levantar, o try é abandonado e nenhum conector dispara.

   Mesmo caminho de disparo, outras entradas:
     POST /api/connectors/preview          → preview(): build_request() sem rede, segredos mascarados
     POST /api/connectors/<id>/test        → deliver(definição da tela, sample_report()), força enabled
     POST /api/alert-connectors/preview    → preview(definição, sample_alert(), alert_context)
     POST /api/alert-connectors/<id>/test  → deliver(definição, sample_alert(), alert_context)
     volume_alerts.fire() → deliver()      → deliver(definição, alerta, alert_context)
```

O desenho previa mais peças neste caminho, que ainda **não existem**: a fila de
saída `connector_outbox` com um worker, retry com backoff, circuit breaker e a
tabela `connector_deliveries` com status, latência e resposta truncada
(planejado, fase 2 — não implementado); o catálogo de presets (planejado, fase 3
— não implementado); resposta encadeada, corpo form-urlencoded ou XML e
assinatura HMAC (planejado, fase 4 — não implementado). O cofre de segredos
cifrado (KMS) é do modelo-alvo da seção 4.1 e também não foi construído: hoje o
segredo é o `authValue` ou um parâmetro `isSecret`, gravados na configuração.

Camadas, e por que cada uma existe separada — hoje como funções de um único
`app/connectors.py`, não como módulos:

| Camada | Onde | Responsabilidade |
|---|---|---|
| Registro/validação | `connectors.validate_definition()` | valida a definição vinda do formulário, gera id, aplica limites |
| Renderização | `connectors.render()` / `build_request()` | resolve placeholders → JSON final e monta headers/query/body. Puro, testável, sem rede |
| Segurança de destino | `custom_analyzers.validate_destination` + `pinned_http` | reuso, não reescrita; a conexão recusa endereço proibido no instante de conectar |
| Transporte | `connectors.deliver()` / `classify()` | executa, classifica o erro; síncrono, sem retry |
| Entrega assíncrona | planejado (fase 2) — não implementado | fila, retry com backoff, circuit breaker |
| Catálogo | planejado (fase 3) — não implementado | presets prontos (Jira, TheHive, Splunk, …) |

O desenho separava essas camadas num pacote `connectors/` (`template.py`,
`transport.py`, `outbox.py`, `catalog.py`); essa divisão é planejada para quando
outbox e catálogo existirem (fases 2 e 3) — não implementada.

A fronteira que faz isto funcionar já existe: `build_report()` normaliza o
resultado da análise em dado puro. O conector genérico consome exatamente esse
dicionário — não precisa saber que TheHive existe.

## 4. Modelagem de dados

### 4.1 Modelo relacional (Cloud, multi-tenant)

**Modelo-alvo, não implementado nesta base** (a implementação atual está em
4.2). Postgres. `tenant_id` em toda tabela, com RLS.

```sql
-- Definição do conector -------------------------------------------------------
CREATE TABLE connectors (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name              VARCHAR(60)  NOT NULL,          -- "Conector Jira"
    slug              VARCHAR(80)  NOT NULL,          -- conector_jira
    description       VARCHAR(400) NOT NULL DEFAULT '',
    enabled           BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Destino
    method            VARCHAR(6)   NOT NULL DEFAULT 'POST',   -- POST|PUT|PATCH
    url               TEXT         NOT NULL,                  -- pode conter {{...}}
    content_type      VARCHAR(80)  NOT NULL DEFAULT 'application/json',
    allow_internal    BOOLEAN      NOT NULL DEFAULT FALSE,    -- libera RFC1918
    verify_tls        BOOLEAN      NOT NULL DEFAULT TRUE,
    timeout_seconds   SMALLINT     NOT NULL DEFAULT 15 CHECK (timeout_seconds BETWEEN 1 AND 60),

    -- Autenticação
    auth_type         VARCHAR(16)  NOT NULL DEFAULT 'none',   -- none|basic|bearer|header|query
    auth_name         VARCHAR(120) NOT NULL DEFAULT '',       -- nome do header/param
    auth_user         VARCHAR(200) NOT NULL DEFAULT '',       -- basic: e-mail/usuário
    auth_secret_id    UUID         REFERENCES connector_secrets(id) ON DELETE SET NULL,

    -- Quando dispara
    trigger_event     VARCHAR(40)  NOT NULL DEFAULT 'analysis.completed',
    min_verdict       VARCHAR(16)  NOT NULL DEFAULT 'all',    -- all|Suspicious|Malicious
    department_filter TEXT[]       NOT NULL DEFAULT '{}',     -- vazio = todos

    -- Corpo
    payload_template  JSONB        NOT NULL DEFAULT '{}'::jsonb,

    -- Leitura da resposta (opcional): onde está o id do ticket criado
    result_ref_path   VARCHAR(200) NOT NULL DEFAULT '',       -- ex.: "key" (Jira), "_id" (TheHive)
    success_status    INT[]        NOT NULL DEFAULT '{200,201,202,204}',

    -- Proteção
    rate_limit_per_min SMALLINT    NOT NULL DEFAULT 60,
    max_retries        SMALLINT    NOT NULL DEFAULT 3,

    version           INTEGER      NOT NULL DEFAULT 1,
    created_by        UUID         NOT NULL REFERENCES users(id),
    updated_by        UUID         REFERENCES users(id),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, slug)
);

CREATE INDEX ON connectors (tenant_id, enabled, trigger_event);

-- Parâmetros dinâmicos: o "Adicionar Parâmetro" da tela ------------------------
-- Um parâmetro é um par chave/valor com um destino declarado. É isto que
-- permite mapear "authentication key" no header do Splunk e "queue name" no
-- corpo do Jira sem que o backend saiba a diferença.
CREATE TABLE connector_params (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id  UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL,

    location      VARCHAR(8)   NOT NULL,   -- header | query | body
    key           VARCHAR(200) NOT NULL,   -- "Authorization", "index", "fields.project.key"
    value         TEXT         NOT NULL,   -- literal ou template: "{{verdict}}"
    value_type    VARCHAR(12)  NOT NULL DEFAULT 'string', -- string|number|boolean|json
    is_secret     BOOLEAN      NOT NULL DEFAULT FALSE,
    secret_id     UUID REFERENCES connector_secrets(id) ON DELETE SET NULL,
    position      SMALLINT     NOT NULL DEFAULT 0,

    UNIQUE (connector_id, location, key)
);

-- Segredos: valor cifrado, nunca lido pela API de leitura ---------------------
CREATE TABLE connector_secrets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL,
    label          VARCHAR(120) NOT NULL,          -- "Jira API token"
    ciphertext     BYTEA        NOT NULL,          -- envelope encryption (KMS)
    key_version    SMALLINT     NOT NULL DEFAULT 1,
    last_four      VARCHAR(4)   NOT NULL DEFAULT '', -- só para a tela dizer "…a3f9"
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    rotated_at     TIMESTAMPTZ
);

-- Fila de saída: garante entrega mesmo com o destino fora do ar ---------------
CREATE TABLE connector_outbox (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    connector_id   UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    idempotency_key VARCHAR(80) NOT NULL,          -- sha256(connector_id + case_ref + event)
    payload        JSONB NOT NULL,                 -- já renderizado
    status         VARCHAR(12) NOT NULL DEFAULT 'pending', -- pending|sent|failed|dead
    attempt        SMALLINT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX ON connector_outbox (status, next_attempt_at);

-- Histórico de entregas: o que o suporte olha quando "não chegou no Jira" -----
CREATE TABLE connector_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    connector_id    UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    case_ref        VARCHAR(80) NOT NULL DEFAULT '',
    trigger_event   VARCHAR(40) NOT NULL,
    attempt         SMALLINT    NOT NULL DEFAULT 1,

    request_url     TEXT        NOT NULL,
    request_body    JSONB       NOT NULL,          -- REDIGIDO: segredos viram "***"
    request_headers JSONB       NOT NULL,          -- REDIGIDO

    status_code     SMALLINT,
    response_body   TEXT,                          -- truncado em 4 KB
    external_ref    VARCHAR(120) NOT NULL DEFAULT '', -- "SEC-1234" extraído de result_ref_path
    latency_ms      INTEGER,
    ok              BOOLEAN     NOT NULL DEFAULT FALSE,
    error           TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON connector_deliveries (tenant_id, connector_id, created_at DESC);

-- Catálogo de presets: é o que sustenta o "30+ integrações" ------------------
CREATE TABLE connector_catalog (
    id             VARCHAR(40) PRIMARY KEY,        -- "jira-cloud", "splunk-hec"
    vendor         VARCHAR(60) NOT NULL,
    category       VARCHAR(40) NOT NULL,           -- ticketing|siem|chat|soar|itsm
    display_name   VARCHAR(80) NOT NULL,
    docs_url       TEXT NOT NULL DEFAULT '',
    logo_slug      VARCHAR(40) NOT NULL DEFAULT '',
    template       JSONB NOT NULL,                 -- connector + params pré-preenchidos
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Auditoria -------------------------------------------------------------------
CREATE TABLE connector_audit (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    UUID NOT NULL,
    connector_id UUID,
    actor_id     UUID NOT NULL,
    action       VARCHAR(24) NOT NULL,     -- create|update|delete|enable|disable|test|rotate_secret
    diff         JSONB NOT NULL DEFAULT '{}'::jsonb,  -- REDIGIDO
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

**Por que `connector_params` é tabela e não um campo JSONB dentro de
`connectors`:** o requisito central é "adicionar parâmetros dinamicamente".
Como linha, cada parâmetro tem identidade estável — dá para reordenar, marcar um
como segredo, auditar a mudança de um sem reescrever o objeto inteiro, e validar
`UNIQUE(location, key)` no banco em vez de no aplicativo. O `payload_template`
segue JSONB porque ali a forma *é* aninhada e arbitrária: é o JSON que o
fornecedor exige, colado da documentação dele.

### 4.2 O mesmo modelo nesta base de código hoje

Esta aplicação guarda configuração em JSON (`analyzers.CONFIG_FILE`) e usa
SQLite (`models.py`) para usuários e para o estado das análises — histórico,
reclassificações, impressão digital, memória de veredito e o estado da
whitelist. O conector genérico entra pela mesma porta que
`custom_analyzers`: uma seção nova na configuração, com a mesma disciplina de
`public_config()` para o segredo não voltar ao navegador.

```python
# configuration.json
{
  "connectors": [
    {
      "id": "connector_jira",
      "name": "Conector Jira",
      "enabled": true,
      "method": "POST",
      "url": "https://suaempresa.atlassian.net/rest/api/2/issue",
      "allowInternal": false,
      "authType": "basic",
      "authUser": "soc@suaempresa.com",
      "authValue": "…",                 // nunca sai em GET
      "minVerdict": "Suspicious",       // dispara sempre ao fim da análise
      "params": [
        {"location": "header", "key": "X-Atlassian-Token", "value": "no-check"}
      ],
      "payloadTemplate": { … },
      "resultRefPath": "key",
      "timeout": 15
    }
  ]
}
```

O histórico de entregas é **planejado (fase 2) — não implementado**. Hoje
`connectors.deliver()` devolve o resultado, `run_analysis` registra no log da
análise, ao vivo, só o detalhe ou o erro, e nada é gravado no SQLite. Quando o
histórico existir, ganha uma tabela no SQLite existente (`models.py`), porque é
dado que cresce e precisa de índice — não pertence a um arquivo de configuração:

```python
# Planejado (fase 2) — esta classe não existe em models.py
class ConnectorDelivery(Base):
    __tablename__ = 'connector_deliveries'
    id           = Column(Integer, primary_key = True)
    connector_id = Column(String(80), nullable = False, index = True)
    case_ref     = Column(String(80), nullable = False, default = '')
    status_code  = Column(Integer)
    ok           = Column(Boolean, nullable = False, default = False)
    external_ref = Column(String(120), nullable = False, default = '')
    request_body = Column(Text, nullable = False, default = '')   # redigido
    response_body= Column(Text, nullable = False, default = '')   # truncado
    latency_ms   = Column(Integer)
    error        = Column(Text, nullable = False, default = '')
    created_at   = Column(DateTime, nullable = False, default = datetime.datetime.utcnow)
```

## 5. A linguagem de template

### 5.1 Variáveis disponíveis

Derivadas direto do `report` de `build_report()`:

| Placeholder | Tipo | Conteúdo |
|---|---|---|
| `{{subject}}` | string | assunto do e-mail analisado |
| `{{verdict}}` | string | `Safe` \| `Suspicious` \| `Malicious` |
| `{{reporter}}` | string | quem reportou |
| `{{department}}` | string | área resolvida por `departments.py` |
| `{{analyzedAt}}` | string | ISO-8601 |
| `{{caseRef}}` | string | id do caso no TheHive, quando houver |
| `{{report_markdown}}` | string | relatório completo em prosa |
| `{{report_text}}` | string | o mesmo sem marcação |
| `{{observables}}` | array | `[{type, value, ioc, malicious, …}]` |
| `{{observables_csv}}` | string | `1.2.3.4, evil.com, …` |
| `{{ioc_count}}` | number | quantidade de IOCs |
| `{{findings}}` | array | veredito por analisador |
| `{{llm.summary}}` | string | resumo da avaliação de engenharia social |
| `{{thehive_observables}}` | array | os observáveis já na forma `dataType/data/ioc/message` |
| `{{observable_count}}` | number | quantidade total de observáveis |
| `{{injection_detected}}` | boolean | o e-mail tentou manipular a própria análise |
| `{{injection_rules_csv}}` | string | regras de prompt injection acionadas |
| `{{body}}` | string | corpo do e-mail analisado |
| `{{severity_number}}` | number | 1/2/3 — para APIs que exigem inteiro |
| `{{secrets.<chave>}}` | string | valor de um parâmetro marcado como segredo, pela chave dele (mascarado na pré-visualização) |

Caminho pontilhado é aceito (`{{llm.summary}}`, `{{observables.0.value}}`),
reusando `custom_analyzers.read_path()`.

### 5.2 Renderização — a parte que precisa estar certa

Duas regras, e a segunda é a que costuma faltar:

1. **Placeholder sozinho preserva o tipo.** `"count": "{{ioc_count}}"` vira
   `"count": 3` (número), não `"3"`. Sem isso, toda API que exige inteiro
   rejeita o corpo.
2. **Placeholder embutido em texto vira string escapada.** `"title": "[{{verdict}}] {{subject}}"`
   passa pelo escape de JSON — um assunto com aspas ou quebra de linha não pode
   quebrar a estrutura do corpo. Isto é injeção de JSON, e o assunto do e-mail é
   controlado pelo atacante.

```python
PLACEHOLDER = re.compile(r'\{\{\s*([a-zA-Z0-9_.\[\]]+)\s*\}\}')

def render(node, context):
	"""Resolve placeholders numa estrutura JSON. Puro: sem rede, sem eval.

	Percorre o template como dado. Uma string que é *só* um placeholder devolve o
	valor no tipo nativo; uma string com texto em volta devolve string. Chaves
	também são renderizadas — há API que nomeia campo por variável.
	"""
	if isinstance(node, dict):
		return {render(k, context): render(v, context) for k, v in node.items()}
	if isinstance(node, list):
		return [render(item, context) for item in node]
	if not isinstance(node, str):
		return node

	whole = PLACEHOLDER.fullmatch(node.strip())
	if whole:
		# Placeholder sozinho: o tipo do valor é preservado
		return resolve(whole.group(1), context)

	def substitute(match):
		value = resolve(match.group(1), context)
		if value is None:
			return ''
		if isinstance(value, (dict, list)):
			return json.dumps(value, ensure_ascii = False)
		if isinstance(value, bool):
			return 'true' if value else 'false'
		return str(value)

	# json.dumps do resultado cuida do escape; aqui só concatenamos texto
	return PLACEHOLDER.sub(substitute, node)


def resolve(path, context):
	"""Devolve None quando o caminho não existe — é o que a pré-visualização aponta."""
	if path.startswith('secrets.'):
		return (context.get('_secrets') or {}).get(path[len('secrets.'):])
	return custom_analyzers.read_path(context, path)
```

**O que deliberadamente não existe:** condicionais, laços, filtros, chamada de
função. Se o template ganhar `{% if %}`, ganhou um interpretador — e um
interpretador editável por usuário é superfície de execução remota. Quem precisa
de lógica usa dois conectores com `minVerdict` diferente.

### 5.3 Redação de segredos

```python
def redact(rendered, secret_values):
	"""O corpo como sai na pré-visualização e no resultado do disparo: sem nenhum
	segredo dentro. (O log de entrega que o guardaria é planejado, fase 2.)

	Redigimos pelo *valor*, não pela chave: um token colado no meio de uma string
	de texto livre não seria pego por uma lista de nomes de campo.
	"""
	text = json.dumps(rendered, ensure_ascii = False)
	for secret in sorted(secret_values, key = len, reverse = True):
		if secret and len(secret) >= 6:
			text = text.replace(secret, '***')
	return json.loads(text)
```

## 6. Execução

```python
def deliver(connector, report, secrets):
	"""Dispara um conector. Nunca levanta — mesmo contrato de tickets.create()."""

	# 1. Revalidação do destino NO DISPARO. Um nome que resolvia para IP público
	#    ao salvar pode passar a resolver para 169.254.169.254 depois.
	url = render(connector['url'], context_of(report, secrets))
	ok, error = custom_analyzers.validate_destination(
		url, connector.get('allowInternal', False))
	if not ok:
		return failure('Destino recusado: {0}'.format(error))

	# 2. Renderização
	context = context_of(report, secrets)
	body    = render(connector['payloadTemplate'], context)
	headers = {'Content-Type': connector.get('contentType', 'application/json')}
	params  = {}
	for param in connector.get('params', []):
		value = render(param['value'], context)
		bucket = {'header': headers, 'query': params}.get(param['location'])
		if bucket is None:
			set_path(body, param['key'], coerce(value, param.get('valueType')))
		else:
			bucket[param['key']] = str(value)

	apply_auth(connector, headers, params, secrets)

	# 3. Teto de tamanho: um relatório grande não pode virar um POST de 40 MB
	encoded = json.dumps(body, ensure_ascii = False).encode('utf-8')
	if len(encoded) > MAX_BODY_BYTES:
		return failure('O corpo renderizado passou de {0} KB.'.format(MAX_BODY_BYTES // 1024))

	# 4. Disparo. allow_redirects=False: seguir levaria a um destino que nunca
	#    passou pela trava do passo 1. pinned_http, e não requests direto: a
	#    conexão fica fixada no endereço que a trava aprovou — chamar requests
	#    direto reabre o DNS rebinding.
	started = time.monotonic()
	try:
		response = pinned_http.request(
			connector.get('method', 'POST'), url, connector.get('allowInternal', False),
			headers = headers, params = params, data = encoded,
			timeout = (CONNECT_TIMEOUT, _read_timeout(connector)),
			allow_redirects = False,
			verify = connector.get('verifyTls', True))
	except pinned_http.DestinationRefused as refused:
		return failure('Destino recusado: {0}'.format(refused))
	except requests.exceptions.SSLError:
		return failure('Falha na validação do certificado TLS do destino.')
	except requests.exceptions.Timeout:
		return failure('{0} não respondeu dentro do tempo limite.'.format(connector['name']))
	except requests.exceptions.ConnectionError:
		return failure('Não foi possível alcançar {0}.'.format(host_of(url)))

	latency = int((time.monotonic() - started) * 1000)
	outcome = classify(connector, response)
	# O request volta no resultado já redigido; nada é gravado — o histórico
	# de entregas é planejado (fase 2)
	outcome['request'] = redact({'url': url, 'headers': headers, 'body': body},
		secrets.values())
	return outcome
```

Classificação do resultado, porque "2xx" não basta:

| Situação | Resultado | `retryable` |
|---|---|---|
| status em `successStatus` | ok, extrai `resultRefPath` | — |
| 401 / 403 | credencial recusada | não |
| 400 / 422 | payload rejeitado — a mensagem traz os primeiros 400 caracteres da resposta | não |
| 404 | confira a URL e a versão da API | não |
| 429 | limite atingido | sim (só marcado; nada relê) |
| 301/302/303/307/308 | recusado (redirect não é seguido) | não |
| 5xx, timeout, conexão | falha transitória | sim (só marcado; nada relê) |

Hoje não há retry nem circuito aberto: `connectors.dispatch()` chama `deliver()`
uma vez por conector, e `retryable` só marca no resultado quais falhas seriam
transitórias (429, 5xx, timeout, conexão). Um destino fora do ar perde aquele
disparo, e o log da análise diz qual e por quê.

**Planejado (fase 2) — não implementado:** as falhas marcadas `retryable`
voltariam com backoff exponencial, o 429 respeitando `Retry-After`; após
`max_retries`, a entrega iria para `dead` e o conector entraria em circuito
aberto por 15 minutos — um destino quebrado não deve consumir worker a cada
análise.

## 7. Endpoints da API

Todos sob `/api/connectors`, todos `@requires_admin` (o padrão que
`custom_analyzers` já segue), todos com CSRF.

| Método | Rota | O que faz |
|---|---|---|
| `GET` | `/api/connectors` | lista os conectores (credencial como `hasAuthValue`), com limite, variáveis, rótulos de veredito, métodos, tipos de auth, locais e tipos de valor |
| `POST` | `/api/connectors` | cria. Corpo = definição completa |
| `POST` | `/api/connectors/<id>` | atualiza. Segredo em branco mantém o gravado |
| `DELETE` | `/api/connectors/<id>` | remove |
| `POST` | `/api/connectors/preview` | **renderiza sem disparar** — devolve método, URL, headers/params/corpo redigidos, `missing` e `bytes` |
| `POST` | `/api/connectors/<id>/test` | dispara uma vez a definição da tela com um report de exemplo |

Planejados, não implementados: `GET /api/connectors/<id>/deliveries` (histórico
paginado) e `POST /api/connectors/deliveries/<delivery_id>/replay` (reenvia uma
entrega que falhou) na fase 2; `GET /api/connectors/catalog` e
`POST /api/connectors/from-catalog/<catalog_id>` (presets) na fase 3. O desenho
também previa `GET /api/connectors/<id>`, `/enable` e `/variables`, que não foram
construídos — as variáveis e os rótulos de veredito vêm no próprio
`GET /api/connectors`.

`/preview` é o endpoint mais importante da lista e o mais fácil de esquecer:
ele é o que transforma "colei um JSON e torço" em "vejo o que vai sair".

### Exemplos

**Criar** — `POST /api/connectors`

```json
{
  "name": "Conector Jira",
  "enabled": true,
  "method": "POST",
  "url": "https://suaempresa.atlassian.net/rest/api/2/issue",
  "authType": "basic",
  "authUser": "soc@suaempresa.com",
  "authValue": "ATATT3xFfGF0…",
  "minVerdict": "Suspicious",
  "params": [
    {"location": "header", "key": "X-Atlassian-Token", "value": "no-check"}
  ],
  "payloadTemplate": {
    "fields": {
      "project":   {"key": "SEC"},
      "issuetype": {"name": "Service Request"},
      "summary":   "[{{verdict}}] Phishing reportado: {{subject}}",
      "description": "{{report_markdown}}",
      "labels": ["bluephish", "{{verdict}}"]
    }
  },
  "resultRefPath": "key"
}
```

**Pré-visualizar** — `POST /api/connectors/preview`

O corpo é a definição do formulário — o `id` é opcional e serve para herdar os
segredos gravados.

```json
{ "id": "connector_jira", "name": "Conector Jira", "url": "…", "payloadTemplate": { … }, "sampleVerdict": "Malicious" }
```

Resposta (valores ilustrativos):

```json
{
  "url": "https://suaempresa.atlassian.net/rest/api/2/issue",
  "method": "POST",
  "headers": {"Authorization": "Basic ***", "Content-Type": "application/json"},
  "params": {},
  "body": {
    "fields": {
      "project": {"key": "SEC"},
      "issuetype": {"name": "Service Request"},
      "summary": "[Malicious] Phishing reportado: [EXEMPLO] Sua conta será suspensa em 24h",
      "description": "*Veredito:* Malicious\n*Analisado em:* 2026-08-10T14:02:11\n…",
      "labels": ["bluephish", "Malicious"]
    }
  },
  "missing": ["queue_id"],
  "bytes": 412
}
```

**Erro de validação** — a mensagem precisa dizer o que fazer, como as de
`custom_analyzers`:

```json
{
  "ok": false,
  "error": "O endereço precisa começar com https:// — em http o relatório e a credencial trafegam em claro. Para um serviço interno sem TLS, marque \"permitir rede interna\"."
}
```

## 8. Estrutura do frontend

Os conectores moram na aba **Tickets** de Integrações, abaixo dos destinos
nativos — mesma pergunta, onde a análise fica registrada. Segue o padrão de
card + modal já usado em `bluephish.js`; o mesmo modal serve aos webhooks do
alerta de volume.

### 8.1 Cards na aba Tickets

```
Integrações
[ Plataforma ] [ Analisadores ] [ Priorização ] [ Bloqueio ] [ Tickets ]  ← aba Tickets
  … cards dos destinos nativos: TheHive, Jira, disco …
────────────────────────────────────────────────────────────────────────────────────
  Integre com qualquer ferramenta que aceite uma API REST (i)
  1 de 2 habilitado — os desabilitados não recebem nada.
                                                                   [ Novo conector ]
┌───────────────────────────────────────┐  ┌───────────────────────────────────────┐
│ Conector Jira (i)          habilitado │  │ Conector Splunk             desligado │
│ POST suaempresa.atlassian.net         │  │ POST splunk.interno:8088              │
├───────────────────────────────────────┤  ├───────────────────────────────────────┤
│ suspeito ou malicioso        [Editar] │  │ todo e-mail analisado        [Editar] │
└───────────────────────────────────────┘  └───────────────────────────────────────┘
```

### 8.2 Modal de edição

O modal não tem títulos de seção; os grupos abaixo seguem a ordem dos campos
na tela.

**Seção 1 — Identificação**
- `Habilitar conector` (toggle)
- `Nome` (texto, obrigatório, ≤60) — "Conector Jira"
- `Descrição` (textarea, ≤400)

**Seção 2 — Destino**
- `Método` (select: POST, PUT, PATCH)
- `Endereço de destino` (texto, obrigatório) — aceita placeholders; validado
  pelo servidor ao salvar, pré-visualizar e testar
- `Permitir rede interna` (toggle) — com o aviso de por que existe

`verifyTls` não aparece na tela e fica sempre ligado.

**Seção 3 — Autenticação**
- `Autenticação` (select: nenhuma / basic (usuário + token) / bearer token /
  cabeçalho customizado / parâmetro na URL), na mesma linha do `Timeout`
  (número, 1–60 s)
- campos condicionais: `Usuário ou e-mail` (basic), `Nome do cabeçalho /
  parâmetro` (header, query), `Credencial` (password; com credencial gravada,
  placeholder "•••••••• (salva — deixe vazio para manter)")

**Seção 4 — Corpo da requisição**
- Textarea monoespaçada; o JSON é conferido no navegador ao salvar,
  pré-visualizar ou testar, e validado de novo no servidor
- Chips de **variáveis disponíveis**, clicáveis para inserir no cursor
- `Content-Type` fixo em `application/json`

**Seção 5 — Parâmetros** — o repeater dinâmico do requisito 4

```
  PARÂMETROS
  ┌───────────┬────────────────────────────┬────────────────────────┬───────────┬─────────────┬───┐
  │ header  ▾ │ X-Atlassian-Token          │ no-check               │ string  ▾ │ [ ] segredo │ × │
  │ body    ▾ │ fields.customfield_10010   │ {{department}}         │ string  ▾ │ [ ] segredo │ × │
  │ query   ▾ │ index                      │ phishing               │ string  ▾ │ [ ] segredo │ × │
  └───────────┴────────────────────────────┴────────────────────────┴───────────┴─────────────┴───┘
  [ Adicionar parâmetro ]
```

Chave em `body` aceita caminho pontilhado e é mesclada sobre o
`payloadTemplate` — assim dá para colar o JSON da documentação e depois
sobrescrever um campo pontual sem editar o bloco.

**Seção 6 — Quando disparar**
- `Disparar para` (select: todo e-mail analisado / suspeito ou malicioso /
  somente malicioso) — o conector dispara sempre ao fim da análise

`Evento` e `Departamentos`, do desenho original, não foram construídos.

**Seção 7 — Leitura da resposta**
- `Caminho do identificador` (texto) — ex.: `key` no Jira, `_id` no TheHive.
  O valor extraído aparece no log da análise ("registrado como SEC-1234"); ele
  não vira link na tela de Casos.
- `Status HTTP de sucesso` (texto separado por vírgula; padrão 200, 201, 202, 204)

**Conferir e rodapé**
```
CONFERIR ANTES DE LIGAR
[ Pré-visualizar ]  [ Testar disparo ]
  (quadro da pré-visualização: pílula 'MÉTODO · N B', 'Não resolveram: …', URL, headers e corpo)
──────────────────────────────────────────────────────────────────────────
montando… / erro                    [ Remover ]  [ Cancelar ]  [ Salvar ]
                                    (Remover só aparece ao editar)
```

`Pré-visualizar` mostra, no próprio modal, o request final (segredos
mascarados), o tamanho em bytes e a lista de placeholders não resolvidos.
`Testar disparo` executa de verdade e mostra status, latência e corpo da
resposta — com aviso explícito de que **cria um registro real na ferramenta de
destino**, ao contrário do "Testar" dos analisadores, que só sonda.

### 8.3 Aba Entregas (planejada)

**Planejado (fase 2) — não implementado.** Hoje o resultado de cada disparo
aparece no log da análise, ao vivo, e não fica guardado; não há Reenviar.
Quando existir: dentro do modal, tabela com data, veredito, status HTTP,
latência, referência externa, e um botão para abrir o request/resposta lado a
lado. Cada linha falha terá **Reenviar**.

## 9. Riscos e mitigações

| Risco | Mitigação |
|---|---|
| SSRF via URL configurável | `validate_destination()` ao salvar **e** no disparo; conexão fixada pelo `pinned_http`; sem redirect; `allowInternal` explícito na definição gravada (a auditoria registra a gravação, com `url=` e `enabled=`, mas não o valor de `allowInternal`) |
| Exfiltração do conteúdo do e-mail | destino só HTTPS público por padrão; log de entrega (planejado, fase 2 — não implementado); alerta ao habilitar destino novo (não implementado) |
| RCE por template | sem interpretador: substituição literal, gramática fechada |
| Injeção de JSON via assunto do e-mail | escape por serialização, nunca concatenação de string crua |
| Vazamento de segredo em log | redação por valor na pré-visualização e no request devolvido pelo disparo; a resposta do destino é truncada (4096 caracteres; 400 na mensagem de erro) e não é redigida |
| Destino lento derruba a análise | timeout (10 s de conexão, leitura de 1–60 s, padrão 30) e disparo depois do veredito, isolado por try/except — `deliver()` nunca levanta; o disparo é síncrono e segura o retorno de `run_analysis.main()` até o último conector; fila de saída e circuit breaker são planejados (fase 2) — não implementados |
| Duplicidade de ticket em retry | `idempotency_key` único por (conector, caso, evento) — planejado (fase 2), não implementado; sem retry, hoje não há duplicidade por reenvio |
| Admin hostil / conta comprometida | RBAC (`@requires_admin` em toda rota) e auditoria de cada gravação, com `url=` e `enabled=`; o diff redigido na auditoria e a notificação ao criar conector não foram implementados |

## 10. Fases de entrega

1. **Núcleo** — modelo, renderizador, `validate_destination`, `deliver()`
   síncrono, CRUD, cards na aba Tickets de Integrações, `/preview`.
   **Entregue** — já cobre o caso de uso inteiro. As fases 2 a 4 ainda não foram
   construídas.
2. **Confiabilidade** — outbox, retry, circuit breaker, entregas, replay.
3. **Catálogo** — presets de Jira, TheHive, Splunk, ServiceNow, PagerDuty,
   Slack, Teams, Opsgenie, Sentinel, XSOAR, Elastic, Zendesk, Datadog…
   com import/export de conector em JSON.
4. **Além do POST** — resposta encadeada (criar caso → anexar arquivo),
   `Content-Type: form-urlencoded` e XML/SOAP, assinatura HMAC de saída.
