# Conectores — integre o BluePhish com qualquer ferramenta

> ℹ️ **O que já funciona:** criar, editar, testar e disparar conectores —
> tudo neste manual, exceto os três itens abaixo, que ainda não foram
> construídos:
>
> - **Não há catálogo.** O botão é *Novo conector*, sem seta e sem modelos
>   prontos: todo conector começa em branco. A lista de ferramentas abaixo diz o
>   que o conector alcança, não o que já vem preenchido.
> - **Não há aba Entregas.** O resultado de cada disparo aparece no log da
>   análise, ao vivo, e não fica guardado. Não há botão Reenviar.
> - **Não há retry.** Um destino fora do ar perde aquele disparo; o log diz qual
>   e por quê.
>
> Arquitetura e fases em [conectores-genericos.md](conectores-genericos.md).

> **Mais de 30 integrações ao seu alcance, e qualquer outra que você precisar.**
>
> O BluePhish não escreve um cliente para cada fornecedor. Ele fala a única
> língua que praticamente toda ferramenta de segurança e de service desk entende:
> **uma requisição HTTP com um corpo JSON**. Você abre a documentação da
> ferramenta de destino, copia o JSON que ela pede, cola no construtor de payload
> e marca onde entram os dados da análise. Pronto — está integrado.

## Índice

- [O que é um conector](#o-que-é-um-conector)
- [Ferramentas que o conector alcança](#ferramentas-que-o-conector-alcança)
- [Criando seu primeiro conector](#criando-seu-primeiro-conector)
- [Variáveis disponíveis](#variáveis-disponíveis)
- [Tutorial: Jira](#tutorial-jira)
- [Tutorial: TheHive](#tutorial-thehive)
- [Adaptando para qualquer outra ferramenta](#adaptando-para-qualquer-outra-ferramenta)
- [Segurança](#segurança)
- [Resolvendo problemas](#resolvendo-problemas)

---

## O que é um conector

Toda vez que o BluePhish termina de analisar um e-mail reportado, ele produz um
**relatório**: o veredito, quem reportou, os observáveis encontrados, o que cada
analisador respondeu e a avaliação de engenharia social.

Um conector pega esse relatório e o entrega para uma ferramenta externa, no
formato que **ela** exige. Você define quatro coisas:

| O quê | Exemplo |
|---|---|
| **Para onde** vai a requisição | `https://suaempresa.atlassian.net/rest/api/2/issue` |
| **Como se autenticar** | Basic com e-mail + API token |
| **Qual o corpo** da requisição | o JSON da documentação do Jira |
| **Quando disparar** | só quando o veredito for suspeito ou malicioso |

O BluePhish faz o resto.

---

## Ferramentas que o conector alcança

O conector genérico atende **qualquer API REST**. Estas foram verificadas contra
a documentação pública de cada fornecedor — o formato do corpo está nos exemplos
deste manual ou é o mesmo caso do Jira. Ainda não há catálogo: você monta cada
uma a partir de *Novo conector*.

**Gestão de chamados e ITSM**
Jira Cloud · Jira Data Center · Jira Service Management · ServiceNow · Zendesk ·
Freshservice · GLPI · osTicket · Zammad

**Resposta a incidentes e SOAR**
TheHive 4 · TheHive 5 · Cortex XSOAR · Shuffle · Tines · Swimlane · IRIS

**SIEM e observabilidade**
Splunk (HTTP Event Collector) · Microsoft Sentinel · Elastic Security ·
IBM QRadar · Sumo Logic · Datadog · Graylog · Wazuh

**Alerta e plantão**
PagerDuty · Opsgenie · VictorOps

**Comunicação**
Slack · Microsoft Teams · Google Chat · Discord · Mattermost · Rocket.Chat ·
Telegram

**Inteligência de ameaças**
MISP · OpenCTI · ThreatConnect

**Genérico**
Webhook · AWS EventBridge · Azure Logic Apps · Zapier · Make · n8n

> Não achou a sua? Não é impedimento. As da lista não têm nada de especial: elas
> funcionam pelo mesmo mecanismo que qualquer outra API REST. Estão aqui porque
> alguém já conferiu o formato do corpo na documentação do fornecedor.

---

## Criando seu primeiro conector

1. Vá em **Integrações → Tickets** e desça até *Integre com qualquer ferramenta que aceite uma API REST*.
2. Clique em **+ Novo conector**.
3. Dê um nome — use algo que o próximo analista entenda: `Conector Jira — fila SEC`.
4. Preencha **Destino** e **Autenticação**.
5. Cole o JSON no **construtor de payload**.
6. Clique em **Pré-visualizar** e confira o que vai sair.
7. Clique em **Testar disparo**.
8. Ligue **Habilitar conector** e salve.

> **Atenção:** *Testar disparo* faz uma requisição de verdade. Ele vai criar um
> chamado, um alerta ou uma mensagem real na ferramenta de destino. Use uma fila
> ou canal de testes na primeira vez.

---

## Variáveis disponíveis

Escreva `{{nome}}` em qualquer lugar do payload, da URL ou de um parâmetro. O
BluePhish troca pelo valor da análise no momento do disparo.

| Variável | Tipo | O que contém |
|---|---|---|
| `{{subject}}` | texto | assunto do e-mail analisado |
| `{{verdict}}` | texto | `Safe`, `Suspicious` ou `Malicious` |
| `{{severity_number}}` | número | `1`, `2` ou `3` — para APIs que exigem inteiro |
| `{{reporter}}` | texto | quem reportou o e-mail |
| `{{department}}` | texto | área do reportante |
| `{{analyzedAt}}` | texto | data/hora ISO-8601 |
| `{{caseRef}}` | texto | número do caso no TheHive, se houver |
| `{{report_markdown}}` | texto | relatório completo, formatado |
| `{{report_text}}` | texto | o mesmo, sem formatação |
| `{{observables}}` | lista | `[{type, value, ioc, malicious}]` |
| `{{observables_csv}}` | texto | `1.2.3.4, evil.com, phish@mal.io` |
| `{{ioc_count}}` | número | quantidade de IOCs confirmados |
| `{{findings}}` | lista | veredito de cada analisador |
| `{{llm.summary}}` | texto | resumo da avaliação de engenharia social |

**Duas regras que valem sempre:**

- Placeholder **sozinho** preserva o tipo:
  `"severity": "{{severity_number}}"` → `"severity": 3` (número).
- Placeholder **dentro de um texto** vira texto:
  `"title": "[{{verdict}}] {{subject}}"` → `"title": "[Malicious] Sua conta será suspensa"`.

Um placeholder que não existe é substituído por vazio — e a
pré-visualização avisa quando isso acontece.

---

## Tutorial: Jira

Vamos abrir uma issue de *Service Request* na fila `SEC` a cada e-mail suspeito
ou malicioso.

### Passo 1 — Gerar o token

**Jira Cloud:** entre em `id.atlassian.com` → *Security* → *API tokens* →
*Create API token*. Copie o valor: ele não aparece de novo. A conta dona do
token precisa ter permissão de criar issue no projeto.

**Jira Data Center:** perfil → *Personal Access Tokens* → *Create token*.

### Passo 2 — Consultar a documentação do Jira

A referência é
[`POST /rest/api/2/issue`](https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-post).
O corpo mínimo que ela exige:

```json
{
  "fields": {
    "project":   { "key": "SEC" },
    "issuetype": { "name": "Service Request" },
    "summary":   "título da issue",
    "description": "corpo da issue"
  }
}
```

### Passo 3 — Preencher o conector

| Campo | Valor |
|---|---|
| **Nome** | `Conector Jira` |
| **Método** | `POST` |
| **URL** | `https://suaempresa.atlassian.net/rest/api/2/issue` |
| **Autenticação** | `Basic` |
| **Usuário** | `soc@suaempresa.com` |
| **Token** | o token do passo 1 |
| **Disparar para** | `suspeito ou malicioso` |
| **Caminho do identificador** | `key` |

> **Data Center:** troque *Autenticação* para `Bearer`, deixe *Usuário* vazio e
> use a URL do seu servidor. O resto é idêntico.

### Passo 4 — Colar o payload

Cole o JSON do passo 2 no construtor e troque os valores fixos pelas variáveis:

```json
{
  "fields": {
    "project":   { "key": "SEC" },
    "issuetype": { "name": "Service Request" },
    "summary":   "[{{verdict}}] Phishing reportado por {{reporter}}: {{subject}}",
    "description": "{{report_markdown}}",
    "labels": ["bluephish", "phishing", "{{verdict}}"],
    "priority": { "name": "High" }
  }
}
```

### Passo 5 — Mapear os campos da sua fila

Quase todo Jira Service Management tem campos customizados obrigatórios — o tipo
de solicitação, a fila, o time responsável. Eles aparecem como
`customfield_NNNNN`. Para descobrir os seus:

```bash
curl -u "soc@suaempresa.com:SEU_TOKEN" "https://suaempresa.atlassian.net/rest/api/2/field"
```

Depois use o bloco **PARÂMETROS** do formulário (botão *Adicionar parâmetro*) — sem precisar mexer no JSON:

| Onde | Chave | Valor |
|---|---|---|
| Body | `fields.customfield_10010` | `sd/1234` (Request Type) |
| Body | `fields.customfield_10002` | `12` (Organização) |
| Body | `fields.components.0.name` | `Segurança` |
| Header | `X-Atlassian-Token` | `no-check` |

Chave em `Body` aceita caminho pontilhado e é mesclada sobre o JSON colado.
Assim você mantém o payload igualzinho à documentação e ajusta o resto por fora.

### Passo 6 — Pré-visualizar

Clique em **Pré-visualizar**. Você deve ver algo como:

```json
{
  "fields": {
    "project": { "key": "SEC" },
    "issuetype": { "name": "Service Request" },
    "summary": "[Malicious] Phishing reportado por ana.silva@empresa.com: Sua conta será suspensa em 24h",
    "description": "*Veredito:* Malicious\n*Analisado em:* 2026-08-10T14:02:11\n*Reportado por:* ana.silva@empresa.com\n\n*Observáveis*\n- url: http://conta-segura[.]xyz/login (malicioso)\n- domain: conta-segura[.]xyz (malicioso)\n…",
    "labels": ["bluephish", "phishing", "Malicious"],
    "priority": { "name": "High" },
    "customfield_10010": "sd/1234",
    "customfield_10002": "12",
    "components": [{ "name": "Segurança" }]
  }
}
```

Confira o `summary` e os campos customizados. Se algum placeholder aparecer
vazio, o aviso amarelo diz qual.

### Passo 7 — Testar

**Testar disparo** → resposta esperada `201 Created`, e o BluePhish extrai o
`key`:

```
✅  201 Created · 412 ms · ticket criado: SEC-1847
```

Ligue **Habilitar conector** e salve.

---

## Tutorial: TheHive

Vamos criar um **alerta** no TheHive 5 — com os observáveis do e-mail já
anexados — a cada análise concluída.

> Alerta ou caso? Alerta cai na fila de triagem e o analista promove a caso se
> valer a pena. É a escolha certa para volume de phishing. Se você quer um caso
> direto, troque a URL para `/api/v1/case` e o corpo pelo formato de caso.

### Passo 1 — Gerar a chave de API

TheHive → *Organisation* → *Users* → escolha o usuário de serviço →
*Create API key*. Copie o valor. O usuário precisa do perfil `analyst` na
organização de destino.

### Passo 2 — Consultar a documentação do TheHive

A referência é
[`POST /api/v1/alert`](https://docs.strangebee.com/thehive/api-docs/). O corpo:

```json
{
  "type": "phishing",
  "source": "bluephish",
  "sourceRef": "identificador único",
  "title": "título do alerta",
  "description": "corpo em markdown",
  "severity": 2,
  "tlp": 2,
  "pap": 2,
  "tags": ["phishing"],
  "observables": [
    { "dataType": "url", "data": "http://exemplo", "ioc": true, "message": "" }
  ]
}
```

### Passo 3 — Preencher o conector

| Campo | Valor |
|---|---|
| **Nome** | `Conector TheHive` |
| **Método** | `POST` |
| **URL** | `https://thehive.suaempresa.com/api/v1/alert` |
| **Autenticação** | `Bearer` |
| **Token** | a chave de API do passo 1 |
| **Permitir rede interna** | marque se o TheHive é on-premises |
| **Disparar para** | `todo e-mail analisado` |
| **Caminho do identificador** | `_id` |

### Passo 4 — Colar o payload

```json
{
  "type": "phishing",
  "source": "bluephish",
  "sourceRef": "{{caseRef}}",
  "title": "[{{verdict}}] {{subject}}",
  "description": "{{report_markdown}}",
  "severity": "{{severity_number}}",
  "tlp": 2,
  "pap": 2,
  "tags": ["bluephish", "phishing", "{{department}}"],
  "observables": "{{thehive_observables}}"
}
```

Repare em duas coisas:

- `"severity": "{{severity_number}}"` — o placeholder está **sozinho** entre
  aspas, então o BluePhish envia o número `3`, não o texto `"3"`. O TheHive
  rejeita o texto com `400`.
- `"observables": "{{thehive_observables}}"` — mesma regra: o placeholder sozinho
  vira a **lista** inteira, já no formato de `dataType`/`data`/`ioc` que o
  TheHive espera. Se você preferir montar você mesmo, use `{{observables}}` e
  mapeie os nomes de campo na aba Parâmetros.

### Passo 5 — Pré-visualizar

```json
{
  "type": "phishing",
  "source": "bluephish",
  "sourceRef": "",
  "title": "[Malicious] Sua conta será suspensa em 24h",
  "description": "*Veredito:* Malicious\n…",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "tags": ["bluephish", "phishing", "Financeiro"],
  "observables": [
    { "dataType": "url",    "data": "http://conta-segura.xyz/login", "ioc": true,  "message": "VirusTotal: 14/89 malicioso" },
    { "dataType": "domain", "data": "conta-segura.xyz",              "ioc": true,  "message": "Domínio registrado há 2 dias" },
    { "dataType": "mail",   "data": "suporte@conta-segura.xyz",      "ioc": true,  "message": "" },
    { "dataType": "ip",     "data": "185.220.101.42",                "ioc": true,  "message": "AbuseIPDB: score 100" }
  ]
}
```

### Passo 6 — Testar

```
✅  201 Created · 233 ms · alerta criado: ~41230064
```

### O TheHive nativo continua existindo

O BluePhish tem um destino TheHive nativo em **Integrações → Tickets**, e ele
faz mais do que este conector: anexa o `.eml` original, cria a task de análise
com o relatório, dispara a exportação MISP, e é a fonte das telas de **Casos**,
**Phishing** e **Executivo**.

Use o conector genérico para o TheHive quando quiser **um segundo destino** — uma
organização diferente, outra instância, um formato próprio. Para a integração
principal, o nativo entrega mais.

---

## Adaptando para qualquer outra ferramenta

A lógica é sempre a mesma. Quatro perguntas para a documentação da ferramenta:

1. **Qual a URL do endpoint de criação?** → campo *URL*
2. **Como ela autentica?** → seção *Autenticação*
3. **Qual JSON ela exige?** → cole no *construtor de payload*
4. **Onde ela devolve o identificador?** → *Caminho do identificador*

Depois troque os valores de exemplo do JSON pelas `{{variáveis}}` que você quer.

### Três exemplos curtos

**Splunk HTTP Event Collector**

URL `https://splunk.suaempresa.com:8088/services/collector/event` ·
Autenticação: *header customizado*, nome `Authorization`, valor
`Splunk SEU_TOKEN_HEC`

```json
{
  "sourcetype": "bluephish:phishing",
  "index": "security",
  "event": {
    "verdict": "{{verdict}}",
    "subject": "{{subject}}",
    "reporter": "{{reporter}}",
    "department": "{{department}}",
    "ioc_count": "{{ioc_count}}",
    "observables": "{{observables}}",
    "analyzed_at": "{{analyzedAt}}"
  }
}
```

**Slack**

URL: a URL do Incoming Webhook · Autenticação: *nenhuma* (o segredo está na URL)

```json
{
  "text": "🎣 *{{verdict}}* — phishing reportado por {{reporter}}",
  "blocks": [
    { "type": "section", "text": { "type": "mrkdwn", "text": "*{{subject}}*" } },
    { "type": "section", "text": { "type": "mrkdwn", "text": "IOCs: {{observables_csv}}" } }
  ]
}
```

**PagerDuty Events API v2**

URL `https://events.pagerduty.com/v2/enqueue` · Autenticação: *nenhuma*

```json
{
  "routing_key": "SUA_INTEGRATION_KEY",
  "event_action": "trigger",
  "dedup_key": "{{caseRef}}",
  "payload": {
    "summary": "[{{verdict}}] Phishing: {{subject}}",
    "severity": "critical",
    "source": "bluephish",
    "custom_details": { "reporter": "{{reporter}}", "iocs": "{{observables_csv}}" }
  }
}
```

> Uma chave que aparece **dentro do corpo** (como `routing_key`) deve ser
> cadastrada em *Parâmetros* com **Secreto** marcado. Assim ela nunca volta ao navegador e sai mascarada (`***`) na pré-visualização e no resultado do teste. Ela continua gravada em texto claro no `configuration.json`, como toda credencial desta aplicação.

---

## Segurança

O conector envia o conteúdo de e-mails da sua empresa para um endereço que você
digitou. Por isso existem estas travas:

- **Só administradores** criam, editam ou habilitam conectores. Toda alteração
  fica na auditoria.
- **Só HTTPS público** por padrão. Um destino na rede interna exige marcar
  *permitir rede interna*. A auditoria registra cada gravação do conector (com `url=` e `enabled=`), mas não o valor dessa opção.
- **O serviço de metadados da nuvem é sempre recusado**, mesmo com a rede interna
  liberada. É onde ficam as credenciais da instância.
- **O destino é revalidado a cada disparo**, não só ao salvar. Um nome que
  resolvia para um IP público pode passar a resolver para dentro da rede.
- **Redirecionamento não é seguido.** Um `301` vira erro, porque o destino novo
  nunca passou pela validação.
- **Segredos entram e não saem.** Com credencial gravada, o campo mostra
  `•••••••• (salva — deixe vazio para manter)`, a API devolve apenas se existe ou
  não, e a pré-visualização e o resultado do teste mostram os segredos como `***`.
- **Um conector fora do ar não derruba a análise.** O veredito já foi decidido
  quando o disparo acontece; a falha vira um aviso no log ao vivo da análise, sem
  histórico e sem reenvio.

---

## Resolvendo problemas

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| `400 Bad Request` | campo obrigatório faltando ou tipo errado | leia a mensagem de erro no log da análise, ou rode **Testar disparo** — Jira e TheHive dizem qual campo. Cheque se um número está indo entre aspas |
| `401` / `403` | token inválido, expirado, ou conta sem permissão | regenere o token; confirme que a conta cria issue/alerta no projeto de destino |
| `404` | URL errada | confira a versão da API (`/rest/api/2` vs `/3`, `/api/v1` vs `/api`) |
| `429` | limite do fornecedor | aquele disparo é perdido e registrado no log. Reduza o escopo do gatilho em *Disparar para*, ou espere a janela do fornecedor |
| `O endereço precisa começar com https://` | destino em HTTP | use HTTPS, ou marque *permitir rede interna* se for um serviço interno sem TLS |
| `não é um endereço público` | destino em rede privada | marque *permitir rede interna* |
| `O destino respondeu com um redirecionamento` | a URL redireciona | use a URL final, sem redirecionamento |
| Campo chega vazio no destino | placeholder escrito errado | a pré-visualização lista os não resolvidos; confira maiúsculas e o painel de variáveis |
| Chamado duplicado | a reanálise de um caso dispara de novo todo conector habilitado, ou dois conectores apontam para a mesma ferramenta | use o `dedup_key`/`sourceRef` da ferramenta com `{{caseRef}}`, ou restrinja um dos conectores em *Disparar para* |

Durante uma análise, o log ao vivo mostra de cada disparo só o detalhe (por
exemplo, 'registrado como SEC-1234') ou o erro — num 400/422, com os primeiros 400
caracteres da resposta. Status, latência e corpo da resposta aparecem apenas no
**Testar disparo**. Nada disso fica guardado: para conferir uma definição sem
esperar um e-mail chegar, use **Pré-visualizar** e **Testar disparo** dentro do
conector.
