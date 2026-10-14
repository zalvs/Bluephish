# Instruções para agentes de IA neste repositório

## Regra obrigatória: consulte o grafo de conhecimento antes de mexer no código

**Antes de editar qualquer arquivo deste projeto, consulte o grafo em `graphify-out/`.**
Não é sugestão. Nesta base de código o custo de errar não é um teste vermelho — é um
analista de SOC recebendo um veredito errado sobre um e-mail de phishing, ou uma falha
silenciosa que não aparece em lugar nenhum.

Esta regra existe porque este repositório tem uma quantidade incomum de **acoplamentos
invisíveis**: mudanças que parecem locais quebram algo três camadas adiante, sem erro,
sem log, sem teste falhando. O grafo mapeia exatamente esses vínculos. Ler o arquivo que
você vai editar não os revela; o grafo revela.

### Como consultar

O grafo fica em `graphify-out/` (gitignored — cada máquina gera o seu):

| Arquivo | Para quê |
|---|---|
| `graphify-out/GRAPH_REPORT.md` | **Leia primeiro.** God nodes, conexões surpreendentes, hyperedges, coesão por comunidade. |
| `graphify-out/graph.json` | Grafo bruto — para consultas programáticas. |
| `graphify-out/graph.html` | Visualização interativa; abra no navegador para inspecionar uma vizinhança. |

Consultas dirigidas:

```bash
graphify query "o que depende de run_analysis.analyze_observables?"
```

```bash
graphify path "app_analyzers_level_for" "app_run_analysis_analyze_observables"
```

```bash
graphify explain "thephish_architecture_csp_no_inline_js"
```

Se `graphify-out/` não existir na sua cópia, gere antes de começar — rode `/graphify`
(pipeline completo: AST + camada semântica dos documentos). O comando reduzido
`graphify extract . --code-only && graphify cluster-only . --no-label` gera só a camada
estrutural e **perde** os nós de doutrina descritos abaixo.

### O que verificar, especificamente

1. **A hyperedge `Traps that fail silently in this deployment`.** Armadilhas que já
   causaram incidente neste deploy e falham *em silêncio*: CSP sem inline JS (§7.4),
   `eventlet.monkey_patch()` antes de qualquer import (§7.5) e todo módulo listado em
   `logging_conf.json` (§7.3). Se sua mudança toca qualquer uma dessas
   superfícies, leia a seção correspondente de `THEPHISH_ARCHITECTURE.md` antes de editar.

   Duas outras falham pior, porque falham *mentindo*:

   * **O orçamento diário de download do provedor de e-mail** (§7.7.1). O Gmail deixa uma
     conta baixar 2,5 GB por dia via IMAP; passado isso ele aceita a conexão e fecha antes
     da saudação, e o `imaplib` chama isso de `socket error: EOF` de dentro do construtor —
     parece rede, é cota. Qualquer mudança que faça o ciclo de polling baixar corpo de
     mensagem por ciclo precisa passar `have`, ou volta a gastar 6,3 GB/dia relendo uma
     caixa que não mudou.
   * **As telas de histórico leem dos destinos habilitados** (§4.8), e um dia leram só do
     TheHive — o que fazia quem grava em disco analisar o dia inteiro vendo tela vazia.
     Ao mexer em `history.py`, `select_cases()` ou `observables_for()`, mantenha duas
     regras: nenhuma fonte pode virar a única, e uma fonte que não sabe responder algo
     responde `None`, nunca zero. O `notice` e o `partial` de `/api/cases` existem para
     dizer na tela o que falta; não os remova para "simplificar" o payload.

2. **A hyperedge `SSRF guard chain for analyst-defined analyzers`.** Analisadores definidos
   pelo analista chamam um endereço que alguém digitou, com o observável da vítima no
   lugar de `{value}` — é SSRF e caminho de exfiltração por construção. Nunca relaxe
   `validate_destination()`, a revalidação no momento da chamada, a recusa de redirects,
   ou a conexão fixada no endereço validado (`pinned_http`). Um consumidor que volte a
   chamar `requests` direto reabre o DNS rebinding sem nenhum teste de unidade falhar —
   só `test_ssrf_rebinding` pega — e só nos seis caminhos que ele exercita (`unshorten`,
   `email_render`, este só dentro da imagem, analisador customizado, conector, Jira e
   FortiGate). PAN-OS, Check Point, TheHive e `audit_store` ficam fora dele.

   **A cadeia tem sete consumidores, não um**, e eles não liberam a rede interna do mesmo
   jeito — mexer em `validate_destination()` mexe em todos:

   | Módulo | O que valida | Rede interna |
   |---|---|---|
   | `custom_analyzers` | endereço de analisador definido pelo analista | só com `allowInternal` na definição salva |
   | `connectors` | conector genérico — e os webhooks do alerta de volume, que passam por `connectors.deliver()` | só com `allowInternal` na definição salva |
   | `tickets` | URL do TheHive e do Jira | liberada (vivem na rede do compose ou num Data Center); o Jira é revalidado e fixado a cada chamada (`_jira_call`) — o TheHive, hoje, só é validado ao salvar: o `thehive4py` chama `requests` direto, brecha conhecida a corrigir no código |
   | `responders` | endereço de gerência dos firewalls (PAN-OS, FortiGate, Check Point) — o EOP não passa pela trava: fala só com hosts fixos da Microsoft | liberada |
   | `unshorten` | cada salto de uma cadeia de redirecionamento | **nunca** |
   | `email_render` | imagem remota do e-mail denunciado | **nunca** |
   | `audit_store` | servidor syslog que recebe a cópia da trilha de auditoria | liberada (um SIEM mora nela); o handler recebe o IP validado, nunca o nome — regra que hoje tem uma brecha conhecida: `resolve_syslog()` entrega o `infos[0]` de um segundo `getaddrinfo`, feito logo após a trava e não julgado de novo; é para corrigir no código, não um comportamento aceito |

   O do `email_render` é o menos óbvio e o mais exposto — dispara num clique comum, sobre
   endereços que ninguém revisou, escritos por quem mandou o phishing, na caixa de entrada e
   na mesa de trabalho. `allow_internal` nunca é passado ali, e não deve passar a ser.
   O grafo liga esta hyperedge a `volume_alerts` e não a `connectors`/`tickets` diretamente:
   confira no código (`grep -rn validate_destination app/*.py`) antes de concluir que um
   caminho não passa pela trava.

3. **A hyperedge `Authentication and session flow`.** Papéis, bloqueio de conta, política
   de sessão e revogação por troca de senha estão amarrados. Autorização é imposta no
   servidor, em toda rota: esconder um botão nunca é o controle.

4. **God nodes** — os nós mais conectados. Mexer neles propaga longe. Hoje o campeão é o
   próprio `THEPHISH_ARCHITECTURE.md`: ele é a fonte de verdade sobre por quê
   as decisões são o que são, e o grafo liga cada decisão ao código que a implementa.

5. **Nós de racional (`file_type: rationale`).** Antes de "simplificar" algo, procure se
   existe um nó explicando por que aquilo é assim. Exemplos reais: o LLM só *eleva* um
   veredito, nunca baixa; um analisador que falha devolve `info`, não `safe`; um segredo
   nunca volta para o navegador; `Referrer-Policy` precisa ficar em `same-origin`.

### Checklist antes de abrir o editor

- [ ] Li `graphify-out/GRAPH_REPORT.md`.
- [ ] Localizei no grafo os nós que vou tocar e listei seus vizinhos diretos.
- [ ] Verifiquei se algum deles participa de uma das três hyperedges acima.
- [ ] Procurei um nó de racional que explique o comportamento atual antes de mudá-lo.
- [ ] Se a mudança cruza fronteira de comunidade, escrevi na descrição do PR o que cruza.

### Depois de mudar o código

Regenere o grafo para que a próxima sessão não trabalhe com um mapa vencido:

```bash
graphify update .
```

---

## Contexto mínimo do projeto

Bluephish: análise automatizada de e-mails de phishing para SOC/CSIRT. Lê uma caixa
monitorada, extrai observáveis, passa pelos analisadores de reputação, pede uma avaliação
de engenharia social a um LLM e grava o veredito nos destinos habilitados — TheHive, Jira, disco e conectores genéricos, em qualquer combinação.

Referência de arquitetura, RBAC, rotas e armadilhas conhecidas:
[`THEPHISH_ARCHITECTURE.md`](THEPHISH_ARCHITECTURE.md). Instalação e operação:
[`README.md`](README.md). O que o handoff pede e ainda não existe: [`ROADMAP.md`](ROADMAP.md).

**Não invente dado na interface.** Painel sem dado real recebe estado vazio explícito,
nunca um número de exemplo — a razão está em `ROADMAP.md` e é a regra mais fácil de
quebrar sem perceber.
