# Estudo: feeds de inteligência offline e revisão dos analisadores

> **Status: estudo + primeira implementação (branch `agent/feeds-publicos`).** O que a
> implementação mudou em relação ao desenho está na seção 9. O estudo original foi escrito lendo o código em `origin/main`
> (`analyzers.py`, `run_analysis.py`, `scoring.py`, `thephish_app.py`, `bluephish.js`,
> `Dockerfile`, `docker-compose.yml`) e o `GRAPH_REPORT.md`. Nada foi executado em Docker e a
> suíte não foi rodada. As licenças foram lidas nas páginas oficiais em 2026-10-23; **não sou
> advogado**, e o que está marcado "confirmar" precisa de decisão de quem responde pela
> empresa. Nomes de grupo na interface são provisórios (Grupo A / Grupo B), como pedido.

## 1. Resumo

1. **"Gratuito" não é "livre para uso empresarial".** Dos feeds citados, o OpenPhish
   Community **proíbe expressamente uso comercial, inclusive SOC e enriquecimento**, e o
   BluePhish já traz o OpenPhish como analisador. O URLhaus (abuse.ch) só é gratuito para
   fins sem lucro. Só dá para vir "de fábrica e sem risco jurídico" um conjunto menor (seção 3).
2. **Feeds em bloco combinam com consulta offline.** Baixar o arquivo, validar, indexar
   localmente e consultar só o índice local na hora da análise. Nenhum observável da vítima
   sai da rede, e a análise não depende de o fornecedor estar no ar.
3. **Existe um padrão a reaproveitar.** O OpenPhish já é "feed inteiro em memória por 15 min".
   A proposta generaliza: registro declarativo de feeds, armazenamento em disco, atualização
   em segundo plano e o mesmo contrato de nível (`info/safe/suspicious/malicious`).
4. **A auditoria achou problemas reais** (seção 6): um padrão ilegal para empresa, um campo de
   URL que escapa da trava SSRF, uma chave "opcional" que na prática é obrigatória, gravação
   não atômica do arquivo de configuração inteiro, segredos em texto claro e contêiner como root.

## 2. Como é hoje (fatos lidos no código)

| Ponto | Hoje |
|---|---|
| Registro | `ANALYZERS` em `analyzers.py`: 12 nativos, cada um com `family`, `observables`, `credentials`, `thresholds`. A tela monta cards e formulário a partir dele. |
| Famílias | `reputation`, `sandbox`, `blocklist`, `local`, `custom` (`analyzer_guides.FAMILIES`). Um só grid de cards, com filtro por texto. |
| Contrato | `run()` nunca lança; devolve `{level, signal, detail, error}`. Falha vira `info`, nunca `safe`. `level_for()` é pura. |
| Feed existente | `query_openphish`: baixa o feed inteiro, cache **em memória do processo**, TTL 900 s. Sem disco, sem validação do conteúdo. |
| PhishTank / URLhaus | Consulta por indicador, via API, com chave "opcional". |
| Config | `configuration.json` (bind-mount), seção `native_analyzers`, segredos em texto claro. |
| Peso na priorização | `scoring.DEFAULT_ANALYZER_WEIGHTS`; id novo sem entrada cai em `DEFAULT_WEIGHT` sem aviso. |
| Dados persistentes | `data/` (volume `./vol/thephish_data`). |

## 3. Candidatos a feed e licença

Lido nas fontes oficiais. "Confirmar" = o texto não resolve sozinho.

| Feed | Conteúdo | Obtenção | Licença / uso em empresa | Veredito |
|---|---|---|---|---|
| **CERT Polska** domínios maliciosos | domínios (phishing/malware) | `https://hole.cert.pl/domains/v2/domains.txt`, sem chave, a cada 5 min | **Qualquer uso, inclusive comercial**; sem atribuição obrigatória; sem garantia | **Pode vir de fábrica** |
| **Phishing.Database** | links, domínios e IPs de phishing (listas ACTIVE) | `https://phish.co.za/latest/phishing-links-ACTIVE.txt` etc., sem chave | **MIT** no repositório. Confirmar: a MIT cobre a compilação, não necessariamente cada fonte que ele agrega | **Pode vir de fábrica** (com nota) |
| **Feodo Tracker** (abuse.ch) | IPs de C2 de botnets | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`, sem chave, a cada 5 min | **CC0**, uso comercial livre (ToU abuse.ch §3.4). A página avisa que os datasets estão **vazios hoje** | Incluir; só serve se voltar a ter dado |
| **SSL Blacklist** (abuse.ch) | certificados/IPs de C2 | não verifiquei a URL exata | **CC0** (mesmo §3.4) | Incluir; confirmar URL |
| **PhishTank** | URLs de phishing verificadas | `data.phishtank.com/data/online-valid.json` (horário); sem chave só "alguns downloads por dia"; chave depende de cadastro | Termos remetem ao EULA da Cisco; **não estabelece** uso comercial. Confirmar | Opcional, desligado, com aviso |
| **OpenPhish Community** | URLs de phishing | feed atualizado a cada 12 h | ToU: *"not to use any part of the Services for any commercial purposes"*, citando SOC, inteligência de ameaças, detecção e enriquecimento; uso "pessoal" | **Não pode vir de fábrica numa empresa.** Só com licença deles |
| **URLhaus / ThreatFox / MalwareBazaar** (abuse.ch) | URLs e IOCs de malware | exige Auth-Key (conta) até para baixar | Gratuito **só sem fins lucrativos** (§3.1); empresa pode exigir assinatura via Spamhaus (§4.1) | **Não de fábrica.** Opt-in com aviso |
| **Spamhaus DROP** | blocos de IP sequestrados | arquivo público | Gratuito "sujeito aos termos"; uso comercial tem condições (fair use). Confirmar | Opcional |
| **OpenCTI** | **não é um feed**: é uma plataforma de TI que o cliente hospeda | API própria, com token | Os dados são os do conector que o cliente configurou | Integração à parte (4.7) |
| **MISP** (feeds, warning lists) | idem: plataforma | idem | idem | Idem; o analisador customizado já cobre |

**Não verificados nesta pesquisa** (não incluir sem checar): Tranco / Majestic (domínios
populares, úteis como *allowlist* contra falso positivo), nós de saída do Tor, blocklist.de,
Emerging Threats, FireHOL, CIRCL hashlookup.

**Conclusão para o "de fábrica":** pacote inicial = CERT Polska + Phishing.Database + (Feodo e
SSLBL, quando houver dado). O resto entra no catálogo, mas **desligado e com o aviso de licença
visível no card**. É o ponto que mais precisa de decisão sua (seção 8).

## 4. Arquitetura proposta

### 4.1 Visão geral

```
                 (segundo plano, a cada N min)              (na análise, sem rede)
 fonte pública ──HTTPS──► feeds.refresh() ──► data/feeds/<id>/  ◄── query_feed(id, tipo, valor)
                          │  valida, limita,   current.sqlite            │
                          │  troca atômica     meta.json                 ▼
                          └─ estado: ok/erro/idade            analyzers.run() → level_for()
```

### 4.2 Peças novas

- **`feeds.py`** (novo): registro `FEEDS` declarativo e o baixador. Cada entrada declara `id`,
  `name`, `url` **fixa no código**, `format` (um parser pequeno por formato: `lines`, `csv`,
  `json`), `indicator_types`, `interval_minutes`, `max_bytes`, `license` (`{class, note, url}`)
  e `default_on`.
- **Entra no registro de analisadores** como `family: 'feed'`, com `credentials: []` (ou só a
  chave opcional, quando houver) e `thresholds: []`. Assim `public_config`, `validate_entry`,
  `run()` e a tela continuam funcionando; o cliente `query_feed` consulta o índice local em vez
  de chamar `requests`.
- **Armazenamento:** um SQLite por feed em `data/feeds/<id>/current.sqlite`
  (`indicator(type, value_norm)` com índice), mais `meta.json` (`fetchedAt`, `etag`,
  `lastModified`, `sha256`, `count`, `lastError`). SQLite porque o projeto já o usa e não carrega
  a lista inteira na memória. O arquivo novo é montado como `.tmp` e trocado com `os.replace`.
- **Atualização:** tarefa em segundo plano (greenlet; ver §7.1/§7.5 da arquitetura) que roda
  `refresh()` para cada feed habilitado vencido. Requisição condicional (`If-None-Match` /
  `If-Modified-Since`); `304` não baixa nada.
- **Ao habilitar:** a rota de salvar dispara o primeiro download e a tela mostra o progresso.
  Se falhar, o analisador fica "ligado, sem dados" e devolve `info`, nunca `safe`.

### 4.3 Semântica de nível (segue o contrato existente)

- Presente no feed → `malicious` (phishing/C2) ou `suspicious` (menor confiança, declarado no registro).
- Ausente → **`info`, não `safe`** (corrigido na implementação: um `safe` de feed contaria como
  "um analisador respondeu" e desarmaria o piso que impede e-mail sem avaliação de fechar como Safe).
- **Feed vencido ou nunca baixado → `info` com o motivo**, jamais `safe` (§7.6: quem não olhou
  não diz que está limpo). Vencido = idade > 3× o intervalo.
- Domínio: casar o exato; domínio-pai só onde o registro declarar (hospedagem compartilhada já
  causou condenação indevida no URLhaus, §4.9 da arquitetura).
- URL: usar a normalização que o resto do projeto aplica antes de comparar.

### 4.4 Segurança do baixador (DevSecOps)

1. **URL fixa no código.** Nenhum campo digitável: o baixador não vira o oitavo consumidor da
   cadeia SSRF, e fecha o problema do `feedUrl` do OpenPhish (A2). Se um dia houver feed
   customizado, passa pela cadeia completa (`pinned_http`, sem redirecionamento) e entra em
   `test_ssrf_rebinding`.
2. Somente HTTPS, **sem seguir redirecionamento** (como `_vendor_get`), `User-Agent`
   identificável, timeouts de conexão e de leitura.
3. **Limite de tamanho** durante o download (aborta no meio), de descompressão (anti *zip
   bomb*), de linha e de nº de linhas.
4. **Validação antes de trocar:** formato bate, contagem > 0, e **queda abrupta** (ex.: mais de
   50% a menos) mantém a versão antiga e registra erro. Protege contra feed truncado ou
   envenenado.
5. **A allowlist do cliente vence o feed.** Já é assim para URL: `run_analysis` pula o
   observável que casa uma regra da whitelist antes de despachar qualquer analisador. Falta
   conferir se o mesmo vale para domínio e IP, que o feed também julgará (testar na Fase 2).
6. Falha de download nunca derruba a aplicação: mantém o índice anterior e mostra "desatualizado há X".
7. O módulo novo precisa constar em `logging_conf.json` (armadilha silenciosa do §7.3).
8. Egress: documentar no README os hosts que o contêiner precisa alcançar, para quem restringe saída.

### 4.5 Interface (UX)

Dois grupos na aba Integrações → Analisadores, **nomes provisórios**:

- **Grupo A: feeds públicos, consulta offline.** Sem chave. Card com estado (`atualizado há
  2 h` / `desatualizado` / `sem dados` / `desligado`), nº de indicadores, próxima atualização,
  botão **Atualizar agora**, **licença em uma linha** com link, e um interruptor só.
- **Grupo B: serviços com chave, consulta online.** O que existe hoje (VirusTotal, AbuseIPDB,
  OTX, MDTI, CrowdStrike, Hybrid Analysis, Safe Browsing...).
- Acima do Grupo A, **"Ativar pacote recomendado"** (só licença limpa), com confirmação
  mostrando o que será baixado e de onde. Nada baixa sem ação do admin.
- Regra do projeto mantida: **estado vazio explícito**, nunca número de exemplo.

### 4.6 Acoplamentos a respeitar (checklist do CLAUDE.md)

- `scoring.DEFAULT_ANALYZER_WEIGHTS`: peso para cada feed novo, senão cai no padrão sem aviso.
- `test_frontend_contract`: HTML e JS no mesmo commit; sem JS inline (CSP, §7.4).
- `eventlet.monkey_patch()` antes dos imports (§7.5), por causa da tarefa em segundo plano.
- `GET /api/analyzers`, `public_config` e `factor_rows` percorrem `ANALYZERS`: o estado novo do
  feed tem que ser opcional para os 12 existentes.
- **Vizinhança no grafo** (`graphify query`, 2026-10-23, grafo de 2026-10-15): `analyzers.py`
  é importado por `run_analysis`, `scoring`, `thephish_app`, `tickets`, `custom_analyzers`,
  `connectors`, `responders` e `bluephish.js`. A consulta truncou 343 de 409 nós, então a lista
  é parcial: refazer com `--budget` maior na Fase 0, e rodar `graphify update .` antes, porque o
  grafo é anterior a commits mais recentes. Nenhum desses vizinhos fica dentro da hyperedge SSRF
  por causa dos feeds, desde que o baixador use só URL fixa (4.4, item 1).

### 4.7 O que continua fora

OpenCTI e MISP seguem como analisador customizado (já suportado, com `allowInternal`). Vale um
*preset* de definição no catálogo, mas é plataforma do cliente, não feed.

## 5. Fases propostas (um PR por fase, branch `agent/<assunto>`)

0. **Preparação:** `graphify query` dos vizinhos; decidir a seção 8; base de testes verde.
1. **`feeds.py` + testes:** parsers, validação, troca atômica, vencimento. Sem tela.
2. **Cliente `query_feed` + registro + peso** (CERT Polska primeiro, o mais simples).
3. **Segundo plano + rota "atualizar agora" + estado na API.**
4. **Tela:** dois grupos, cards de feed, pacote recomendado, i18n.
5. **Demais feeds do pacote**, depois os opt-in com aviso de licença.
6. **Correções da auditoria** (seção 6), em PRs separados por serem independentes.

## 6. Auditoria dos analisadores existentes

Severidade: **A** alta, **M** média, **B** baixa. Tudo confirmado lendo o código; nada executado.

### 6.1 DevSecOps e jurídico

| # | Sev | Achado | Onde | Sugestão |
|---|---|---|---|---|
| A1 | **A** | OpenPhish vem com a URL do feed comunitário, cujos termos **proíbem uso comercial/SOC**. Quem habilita numa empresa assume o risco sem aviso na tela. | entrada `openphish` | Aviso de licença no card; fora do pacote padrão; só com licença própria |
| A2 | **M** | O campo `feedUrl` do OpenPhish é digitável e `query_openphish` chama `requests` direto, **sem** `validate_destination` nem `pinned_http`. Só admin altera, mas é a brecha que o CLAUDE.md descreve para analisadores do analista. | `validate_entry` + `query_openphish` | Passar pela cadeia ou fixar a URL |
| A3 | **M** | `save_config` lê o `configuration.json` **inteiro**, troca uma seção e reescreve com `open(path, 'w')`: sem escrita atômica e sem trava. Queda no meio, ou dois salvamentos simultâneos, podem corromper toda a configuração, não só a dos analisadores. | `analyzers.save_config` | `.tmp` + `os.replace`, com lock |
| A4 | **M** | Chaves de API em texto claro no `configuration.json` (bind-mount no host). A API não as devolve, o que é correto. | `save_config` | Permissão 0600 e/ou segredo fora do arquivo |
| A5 | **M** | O `Dockerfile` não tem `USER`: roda como root. | `app/Dockerfile` | Usuário sem privilégio (exige migrar permissão do volume) |
| A6 | **B** | Cache de 15 min para um feed atualizado a cada 12 h: dezenas de downloads por dia a um serviço gratuito, e o cache some a cada reinício. | `OPENPHISH_CACHE_TTL_SECONDS` | Requisição condicional + disco (o desenho acima resolve) |

### 6.2 UX e consistência

| # | Sev | Achado | Sugestão |
|---|---|---|---|
| U1 | **A** | **URLhaus** tem chave `required: False`, mas o próprio código reconhece que a abuse.ch exige Auth-Key e dá erro sem ela. O admin liga, o teste falha, e o campo diz "opcional". | Marcar obrigatório, ou esconder até haver chave |
| U2 | **M** | **PhishTank** por indicador: sem chave o limite é baixo e a chave depende de cadastro (o código já avisa). Na prática gera `info` em massa. | Trocar pelo download em bloco (Grupo A) |
| U3 | **M** | **CrowdStrike Falcon Intel e Sandbox** pedem os mesmos três campos (client id, secret, região) duas vezes. | Uma "conexão Falcon" compartilhada |
| U4 | **M** | Um único modal junta habilitar, credenciais, tipos de observável, limiares (barra **e** número), teste e guia. Muito campo para quem só quer ligar. | Modo simples (chave + ligar + testar) e "Avançado" recolhido |
| U5 | **M** | O card mostra `ativo / configurado, desligado / não configurado`, mas **não a saúde**: último sucesso, último erro, cota. Chave vencida só aparece como `info` dentro de cada análise. | Estado de saúde no card |
| U6 | **B** | O rótulo do campo não indica obrigatório (o JS só imprime `field.label`). | Marcar "obrigatório" / "opcional" |
| U7 | **B** | Analisador de um tipo só mostra caixas de tipo que o próprio texto diz serem equivalentes ao interruptor. | Ocultar quando só há um tipo |
| U8 | **B** | Um grid com 12 cards de naturezas diferentes (online com chave, local, feed). | Os dois grupos da seção 4.5 |

**Não auditei:** qualidade dos textos do guia por analisador, acessibilidade (foco, leitor de
tela) e tela pequena. Isso pede uma passada no navegador.

## 7. O que não pude testar

Sem Docker nesta máquina, a suíte (~1400 testes dependem da imagem) não foi executada, não subi
a aplicação nem vi a tela. Nenhum feed foi baixado: tamanhos, formato real dos arquivos e tempo
de indexação são **estimativas a medir** na Fase 1, em especial o Phishing.Database, cujo
tamanho não verifiquei.

## 8. Decisões que são suas

1. **Pacote de fábrica:** só licença limpa (CERT Polska, Phishing.Database, Feodo/SSLBL)? Recomendo que sim.
2. **Ligado ou desligado no primeiro boot?** Recomendo desligado + botão "pacote recomendado":
   baixar sem consentimento é saída de rede inesperada.
3. **OpenPhish:** manter com aviso, tirar do catálogo, ou exigir que o cliente informe a URL do
   feed licenciado? A segunda ou a terceira evitam o risco jurídico.
4. **URLhaus/abuse.ch:** manter como opt-in com aviso de "sem fins lucrativos"?
5. **Quem responde pela licença?** Os termos pedem validação jurídica antes de publicar o pacote.
6. **Nomes dos grupos** na interface.

## 9. Implementação (o que mudou em relação ao desenho)

Feito: `feeds.py`, cliente e registro em `analyzers.py`, peso em `scoring.py`, guias, laço em
segundo plano e rotas em `thephish_app.py`, grupo de cards na tela, `test_feeds.py` (56 testes).

- **Pacote recomendado: só o CERT Polska.** O Phishing.Database tem licença MIT sobre a
  compilação, mas o projeto não diz de onde vêm as entradas (lido na página oficial em
  2026-10-23), então não dá para afirmar que o uso em empresa é livre: os dois feeds dele existem,
  mostram "confirmar licença" no card e são ligados de propósito. Os domínios (11 MB) e as URLs
  (**66 MB**) ficam fora do pacote. Medido em
  2026-10-23: 125 mil, 392 mil e 775 mil entradas; índices de 3,5 MB, 14 MB e 70 MB; 1,2 s,
  3,4 s e 15,7 s para baixar e indexar.
- **Feodo e SSL Blacklist ficaram de fora:** o arquivo do Feodo está parado desde março de 2026
  (vazio), e a regra de "mínimo de entradas" o trataria como erro para sempre.
- **O espelho `phish.co.za` respondeu 503** durante o teste; a fonte usada é o GitHub raw do
  próprio projeto.
- **Achado novo:** o Phishing.Database lista `sites.google.com` e `bit.ly` como domínios. Sem
  tratamento, todo e-mail com link para Google Sites ficaria Suspicious. Há uma trava de
  plataformas compartilhadas (`feeds.SHARED_HOSTS`). Ela cobre os casos que encontrei, não
  garante que não existam outros.
- **Não verificado visualmente:** não há bibliotecas do Chromium nesta máquina e `sudo` é proibido.
  O JavaScript novo foi executado no Node contra um DOM mínimo, com as respostas reais das
  rotas; layout, cores e tela pequena **ainda precisam de uma olhada no navegador**.
- **OpenPhish e PhishTank não entraram no grupo offline por licença, não por falta de suporte
  técnico:** os termos do OpenPhish gratuito proíbem uso comercial, e os do PhishTank não
  autorizam. O analisador OpenPhish existente ganhou só o aviso de licença (descrição e guia);
  nenhum comportamento mudou.
- **Hosts de link viram observável `domain`** (conferido com `ioc_finder`), então os feeds de
  domínio enxergam os links dos e-mails.
- **Ainda de pé da seção 6:** A2 a A6 e U1 a U8. Nenhum foi alterado neste PR.
