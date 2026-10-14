# Roadmap — o que o handoff do bluephish pede e ainda não existe

O arquivo de design (`bluephish Dashboard.dc.html`, projeto Claude Design
`c75b48cc-5609-450e-9b4f-ce3f68a466b4`) é um protótipo com dados fictícios. A
implementação trouxe a marca, a paleta e todos os painéis, mas os blocos abaixo
dependem de dados que nenhuma parte do back-end produz hoje.

Eles estão na tela **em estado vazio explícito** — uma frase dizendo o que falta,
nunca um número de exemplo. Num produto cujo trabalho é dizer ao analista o que é
verdade sobre um e-mail, um placeholder que parece medição é pior do que painel
nenhum: o mock mostra "Financeiro 34%" e um analista não tem como saber que
aquilo foi inventado.

Cada item abaixo diz onde está a casca, o que falta e por onde começar.

---

## 1. Insights agregados da IA (Visão Executiva) — **implementado**

- **Onde:** `#execInsights`, montado por `render_exec_insights()`.
- **Como:** cada análise grava no caso o nível de risco (`risk:<nível>`) e, se
  houve, `se:detected`. `case_insights.summarize_llm()` conta essas tags sobre a
  janela e `/api/insights` devolve `llmInsights`.
- **O denominador é dito na tela:** todas as taxas são sobre `assessed`, os casos
  que o modelo de fato avaliou. Uma instância com o LLM desligado metade do mês
  não pode parecer uma instância onde o modelo olhou e não achou nada — é a única
  leitura errada que mandaria um executivo para o lado oposto.
- **Não é texto de LLM sobre texto de LLM:** o card conta avaliações; as frases
  são compostas no cliente a partir dos números.

## 2. Táticas de engenharia social (Visão Executiva e detalhe do caso) — **implementado**

- **Onde:** `#execTactics` e `#caseTactics`.
- **Como:** o contrato de saída em `llm_analysis.py` ganhou `tactics: []` com
  vocabulário fechado (`llm_analysis.TACTICS`), normalizado por
  `normalize_tactics()` — valor fora da lista é descartado, não contado como
  tática própria. Cada tática vira uma tag `tactic:<chave>` do caso, e
  `case_insights.count_tactics()` as soma na janela.
- **Por que vocabulário fechado:** o modelo já nomeava as táticas na prosa, mas
  com as palavras que escolhia naquela execução. "Senso de urgência", "urgency" e
  "pressure to act fast" são a mesma tática escrita de três jeitos, e é isso que
  tornava impossível contá-las.

## 3. Departamentos mais visados (Visão Executiva) — **implementado**

- **Onde:** `#execDepts`, configurado em Configurações → Departamentos.
- **Como:** `app/graph_directory.py` consulta o **Entra ID** (Microsoft Graph,
  `/users/{endereço}?$select=department`) pelo endereço de quem denunciou;
  `app/departments.py` é a configuração, o cache e a política em volta. A análise
  resolve o departamento e o grava como tag `dept:<nome>` do caso.
- **Por que o diretório, e não uma lista digitada:** uma lista declarada fica
  errada no dia em que alguém muda de time e ninguém atualiza, e o dashboard
  segue reportando o departamento antigo sem nenhum sinal de que derivou. O
  diretório é a resposta da própria organização, mantida por quem tem essa
  função.
- **Permissão:** `User.Read.All` de aplicativo no Microsoft Graph, com
  consentimento de administrador — **não** é a mesma que lê a caixa
  (`Mail.ReadWrite`). Por padrão reaproveita o registro de aplicativo do
  Microsoft 365 já configurado em E-mail; dá para apontar um registro separado
  (instalação com caixa no Gmail e diretório no Entra ID).
- **Cache:** um endereço resolvido é reaproveitado por `cacheHours` (24 por
  padrão), inclusive as respostas negativas — senão cada denúncia de um
  remetente externo custaria uma chamada ao Graph. Salvar a configuração limpa o
  cache.
- **Falha nunca custa a análise:** diretório fora do ar, credencial errada ou
  permissão faltando devolvem `''` e emitem um aviso no log da análise. O
  veredito já está decidido quando isso roda. O botão **Testar** é o oposto:
  reporta o erro literal, porque é exatamente essa a pergunta de quem o aperta.
- **O que não é atribuído fica visível:** denúncia de endereço fora do tenant,
  ou com o atributo vazio, é contada à parte embaixo do card, em vez de cair num
  balde inventado.
- **Vale a partir das próximas análises:** as tags são gravadas na criação do
  caso; casos já encerrados não são reprocessados.

## 4. Sinais de autenticação agregados (painel Phishing) — **implementado**

- **Onde:** `#phishAuthStats`.
- **Como:** `tickets.analysis_tags` passou a gravar `auth:spf=…`, `auth:dkim=…` e
  `auth:dmarc=…` no caso, e `case_insights.count_authentication()` os soma na
  janela. O dado já era extraído por e-mail; o que faltava era torná-lo contável.
- **A categoria que não podia sumir:** um caso sem a tag é contado em
  `unrecorded` e fica fora do percentual. Somá-lo a `fail` inventaria falha que
  ninguém observou — e é sobre esse número que alguém decide endurecer uma
  política de DMARC. Casos analisados antes desta versão não têm a tag, e o
  painel diz isso em vez de mostrar zero.

## 5. Ações recomendadas sobre a coletânea (painel Phishing) — **implementado**

- **Onde:** `#phishActions` e a coluna REMEDIAÇÃO do painel tático.
- **Como:** `case_insights.REMEDIATION_BY_TYPE` — um playbook por tipo de
  observável, uma ação por tipo e não uma por indicador (quarenta URLs da mesma
  campanha produzem uma recomendação, não quarenta).
- **Por que playbook e não modelo:** a ação que se toma sobre um IOC é função do
  que ele é. Era exatamente essa a objeção registrada aqui — recomendação sem
  agregação por trás é palpite apresentado como conclusão. Um playbook não
  precisa de agregação: ele não conclui nada sobre a coletânea, ele diz o que se
  faz com um indicador daquele tipo.
- **O que é medido, e não proposto:** se algum destino de bloqueio *habilitado*
  aceita aquele tipo. Vem de `responders.available_targets`, e não de `supports`:
  um FortiGate sem id de filtro de URL declara suporte a URL no registro e não
  tem para onde mandá-la. Quando não há destino, a linha diz que a ação é manual
  em vez de oferecer um botão inexequível.

## 5.1 Metodologia de score e triagem de massa — **implementado**

- **Onde:** `app/scoring.py`, `app/spam_headers.py`, Integrações → Priorização,
  e o painel tático de Phishing confirmado.
- **O que é:** `score = 100 × Σ(peso × fator)`, fatores em [0,1], pesos
  ajustáveis por fator, faixas phishing ≥ 50 · suspeito/spam ≥ 40 · legítimo ≥ 20.
  A razão de cada decisão está em `THEPHISH_ARCHITECTURE.md` §1.2.1 e §1.2.2.
- **O que ele resolve deste roadmap:** a nota composta que o item 6 pedia passa a
  existir, e ela é gravada como tag do caso — que é o que os itens 4, 5 e o
  ranking de remetentes por risco agregado consomem.
- **O que ele deliberadamente não faz:** rebaixar. Não há modo em que o score
  derrube um veredito. O piso do score é o próprio veredito, então a faixa só
  eleva. Rebaixamento continua sendo atribuição só da whitelist de remetente, que
  é auditada, contada e se suspende sozinha.

## 6. Faixa de risco no detalhe do caso — **parcial**

- **Onde:** `#caseMetrics`, tile `RISCO (LLM)`. Os outros três — veredito,
  observáveis, IOCs — sempre foram reais.
- **Hoje:** o tile mostra o nível da avaliação de engenharia social, gravado como
  tag `risk:<nível>` do caso pelo item 2. Fica `—` marcado como ausente quando o
  LLM não rodou; nunca zero.
- **Falta:** o tile ainda mostra só o nível do LLM. A nota numérica composta que
  o mock desenha passou a existir (item 5.1) e é gravada como tag `score:` do
  caso; falta trazê-la para `#caseMetrics`. O mock também mostra
  `VIRUSTOTAL 12/94` e `IDADE DO DOMÍNIO 3 dias`: ambos continuam exigindo
  guardar o resultado bruto do analisador, hoje ele só vira nível — o score
  consome o nível, não o número por trás dele.

## 7. Coluna origem nos observáveis extraídos

- **Onde:** `.obs-row` em `bluephish.css` já tem a grade de 4 colunas do
  handoff; `open_case()` monta 3.
- **Hoje:** `/api/cases/<n>` devolve `{type, value, ioc}`. Qual analisador
  produziu o veredito não é guardado.
- **Falta:** propagar o nome do analisador na criação do observável e devolvê-lo
  no detalhe. A quarta coluna já está estilizada esperando.

## 8. Coluna Risco · Status na lista de phishing

- **Hoje:** as linhas usam `render_case_list()`, com veredito, contagem de IOC e
  tags — tudo real. O mock acrescenta uma nota de risco e um status de
  tratamento por linha.
- **Falta:** o risco agora existe como tag `score:`/`tier:` do caso (item 5.1) e
  `case_row()` já o devolve; falta a coluna consumi-lo. O status de tratamento
  continua exigindo um campo de workflow que a aplicação não modela.
- **Decisão:** ao contrário dos painéis acima, esta coluna **não** foi incluída
  vazia. Um card vazio se explica em uma frase; uma coluna com `—` repetido em
  quarenta linhas é ruído em cada varredura da lista, todo dia. Volta junto com
  o item 6.

## 9. Bloquear remetente / bloquear no gateway — **implementado**

- **Onde:** `Bloquear indicadores` no detalhe do caso e `Bloquear no gateway` no
  card de IOC recorrente. Os dois botões inertes saíram.
- **Como:** `app/responders.py`, um registro declarativo no mesmo formato de
  `analyzers.py`, com quatro destinos — Microsoft 365 (Tenant Allow/Block List
  pelo endpoint de administração do Exchange Online), Palo Alto PAN-OS, Fortinet
  FortiGate e Check Point Management API. A tela fica em Integrações → Bloqueio,
  e monta card e formulário a partir do registro.
- **Auditoria:** `POST /api/block` grava um evento `indicator_block` por par
  indicador × destino, com valor, tipo, caso de origem e resultado; salvar e
  testar um destino gravam `responder_update` e `responder_test`. Era o que este
  item pedia.
- **O que continua fora:** desbloquear. Remover uma entrada é feito no console do
  destino. Um botão de remoção exigiria localizar a entrada exata que foi criada
  em cada fabricante, e errar isso apaga a regra de outra pessoa.
- **O que também continua fora:** bloqueio automático a partir do veredito.
  Nenhuma rota de bloqueio é chamada pelo pipeline; bloquear é sempre clique de
  um admin. Um falso positivo em bloqueio automático derruba tráfego legítimo da
  organização inteira sem ninguém no caminho.
- **Já disponível antes:** o caminho oposto — inocentar um observável — em
  **Adicionar à whitelist** no detalhe do caso.

## 10. Exportar relatório (Visão Executiva)

- **Onde:** botão inerte no cabeçalho da Visão Executiva.
- **Hoje:** existe `Exportar IOCs`, que baixa os indicadores da janela em JSON.
- **Falta:** definir o que é "relatório" (PDF executivo? CSV de casos?). Sem essa
  definição o botão não tem o que fazer.

## 11. Login: sessão persistente e recuperação — **SSO e MFA implementados**

- **Onde:** `app/templates/login.html`, `app/mfa.py`, `app/sso.py`, rotas
  `/auth/sso/*` e `/api/auth/mfa/*` em `app/auth.py`, aba **SSO** em
  Configurações. Testes em `app/test_sso.py`, `app/test_mfa.py` e
  `app/test_mfa_gate.py`.
- **Hoje:** `auth.py` faz sessão por cookie assinado com política de expiração e
  bloqueio por tentativas, e **exige um segundo fator TOTP de todo mundo**. Não
  há "lembrar de mim".
- **Implementado como:** checkbox **Manter conectado** visível e inerte, e a
  frase que diz o caminho real de recuperação (pedir a um `global_admin`, ou
  `manage.py reset-password`). A tela de recuperação por código que o mock
  desenhava não existe: o código de seis dígitos do login **é** o segundo fator,
  e não um caminho para repor a senha.
- **O SSO saiu do "falta" e virou código.** Detalhes que não podem ser
  afrouxados depois:
  - **É OIDC, não SAML**, apesar do que o mock escrevia embaixo do botão (a
    legenda saiu). *Authorization code + PKCE* é o que a Microsoft recomenda
    para aplicação web que assina usuário, e a `msal` já está na imagem —
    SAML exigiria `xmlsec1` compilado sobre uma base Python 3.8.
  - **O cargo vem do grupo no Entra ID**, e a ausência de mapeamento **nega**.
    Um token cujos grupos não casam com nenhum cargo não entra; é o oposto de
    conceder o cargo mais baixo por falta de informação.
  - **Excesso de grupos é recusa, não adivinhação.** Acima de ~200 grupos o
    Entra ID manda um ponteiro em vez da lista, e escolher cargo pelo que
    sobrou daria o cargo errado em silêncio. Daí a recomendação de App Roles.
  - **O último `global_admin` nunca é rebaixado** por mudança de grupo: senão
    uma edição no Entra ID tranca a instalação inteira para fora.
  - **A tela de login recebe código de erro, nunca texto.** Um parâmetro de URL
    que vira frase deixa qualquer um montar um `/login?erro=…` dizendo o que
    quiser numa página que pede senha.
- **O MFA obrigatório também saiu do "falta".** Aplicativo autenticador (TOTP)
  para 100% das contas, inclusive as que entram por SSO. Detalhes que não podem
  ser afrouxados depois:
  - **Não existe MFA por e-mail nem por SMS, e a ausência é a decisão.** SMS cai
    com uma troca de chip; e-mail cai junto com a caixa postal que esta
    plataforma existe para vigiar. `test_mfa_gate.MetodosProibidos` falha no dia
    em que alguém acrescentar um desses canais.
  - **A senha certa não abre sessão.** Ela abre um desafio de dez minutos; quem
    chama `flask_login.login_user` é a conferência do código, e nada antes dela.
    Assim toda rota já protegida continua fechada sem precisar saber que MFA
    existe. O `before_request` (`auth.enforce_mfa_policy`) é rede de proteção,
    não a defesa — ver o cabeçalho do bloco em `app/auth.py`.
  - **O SSO não é exceção.** O Entra ID prova um fator; o requisito é de dois.
    O retorno do provedor cai no mesmo desafio que o login por senha.
  - **Um código só vale uma vez.** O passo de tempo aceito fica guardado
    (`users.mfa_last_counter`), senão um código visto por cima do ombro vale por
    até 90 segundos em outro navegador.
  - **A recuperação é humana, de propósito.** Telefone perdido se resolve com um
    `global_admin` zerando o fator (ou `manage.py reset-mfa`), não com um código
    enviado por um canal que o atacante possa ter tomado.
- **Falta:** para a sessão persistente, decidir se ela sobrevive ao fecho da
  aba, que hoje é justamente o que encerra a sessão (item 13). E zerar o MFA de
  alguém não derruba as sessões que essa pessoa já tenha abertas — elas morrem
  sozinhas ao fechar a aba ou no limite de 12 horas, mas quem zera por suspeita
  de comprometimento deve trocar a senha junto, que aí sim revoga tudo.

---

## 12. Conector Genérico — **fase 1 implementada**

Este item não vem do handoff de design: os outros onze são telas que o mock pede
e o back-end não alimenta; este é um módulo inteiro que ainda não existe. Está
aqui porque é o mesmo tipo de dívida — decisão tomada, código não escrito — e
manter duas listas de pendência é como se perde uma delas.

- **Onde:** `app/connectors.py`, rotas `/api/connectors/*` em `thephish_app.py`,
  aba **Conectores** em Integrações, e o disparo no fim de `run_analysis.py`.
  Testes em `app/test_connectors.py` (84 casos, nenhum toca a rede).
- **Antes:** cada destino externo era código. `tickets.py` tem `create_jira()`,
  `create_thehive()` e `create_disk()` escritos à mão, e um destino novo custava
  um release. O registro `DESTINATIONS` é declarativo, mas o cliente HTTP de cada
  um não é.
- **Agora:** um conector parametrizado por configuração — endpoint, autenticação,
  parâmetros dinâmicos e o corpo JSON colado da documentação da ferramenta de
  destino. Atende qualquer API REST. Arquitetura em
  [`docs/conectores-genericos.md`](docs/conectores-genericos.md); manual com
  tutoriais de Jira e TheHive em
  [`docs/conectores-manual.md`](docs/conectores-manual.md).
- **O que sustenta a segurança disto, e não pode ser afrouxado depois:**
  - O renderizador **não é um interpretador**. Sem Jinja2, sem `eval`, sem
    `format()` com string do usuário. A gramática é `{{caminho.pontilhado}}` e
    nada mais — um template editável na tela e avaliado como expressão é execução
    remota de código no servidor, e "só admin edita" não cobre conta comprometida.
    `test_a_gramatica_nao_tem_expressao` existe para que isso não regrida.
  - `validate_destination()` de `custom_analyzers.py` roda **de novo no disparo**,
    não só ao salvar.
  - O escape sai da serialização, nunca de concatenação: o assunto do e-mail é
    escrito por quem atacou a vítima. `test_injecao_de_json_no_assunto...` fixa.
  - Redação de segredo **por valor**, não por nome de campo.
- **Falta (fases 2 a 4 do documento de arquitetura):**
  - **Histórico de entregas.** Hoje o resultado de cada disparo vai para o log da
    análise e sai da tela junto com ela. Falta a tabela `connector_deliveries`, a
    aba Entregas e o botão Reenviar. É o que o suporte vai pedir primeiro.
  - **Fila e retry.** Um destino fora do ar perde aquele disparo. Sem outbox, sem
    backoff, sem `idempotency_key` — o retry, quando vier, precisa dela junto, ou
    vira chamado duplicado.
  - **Catálogo de presets.** Não existe *Novo conector ▾*: todo conector começa em
    branco. Enquanto isso, a alegação de "mais de 30 integrações prontas" no
    manual segue sendo sobre o que o conector *alcança*, não sobre modelos que
    alguém validou. Não publicar essa frase como se fossem presets testados.
  - **Além do POST**: form-urlencoded, XML/SOAP, HMAC de saída, resposta
    encadeada (criar caso → anexar arquivo).

---

## 13. Sessão encerrada ao fechar a aba — **implementado**

- **Onde:** bloco "Sessão presa à aba" em `app/auth.py`, o correspondente em
  `app/static/assets/js/bluephish.js`, testes em `app/test_session_tab.py`.
- **Antes:** o cookie era de sessão de navegador. Ele sobrevive ao fechamento de
  uma aba e, com a restauração de sessão que Chrome e Firefox fazem, sobrevive
  até ao fechamento do navegador — quem fechava o painel numa máquina
  compartilhada deixava a sessão aberta para o próximo.
- **Por que não é só um `pagehide`:** esse evento dispara igual num F5. Tratá-lo
  como logout deslogaria a cada recarga.
- **Agora**, dois lados que se cobrem:
  - **Servidor.** Um registro em memória guarda o último sinal de vida por
    sessão. Passados `BLUEPHISH_TAB_GRACE_SECONDS` (300 por padrão) sem
    nenhum, a sessão é revogada na requisição seguinte. Aba fechada para de
    dar sinal; processo reiniciado esvazia o registro. As duas falham fechado.
  - **Navegador.** O token da aba vive no `sessionStorage`, que morre com a aba
    e sobrevive ao F5. Sem token, o painel não chega a carregar: desloga e
    volta para o login com o aviso. É isto que faz "fechei e abri de novo"
    pedir autenticação na hora, em vez de daqui a alguns minutos.
- **A carência é generosa de propósito:** navegador estrangula timer de aba em
  segundo plano para um disparo por minuto, e uma carência curta deslogaria quem
  só deixou o painel atrás de outra janela. Quem fecha a aba é pego pelo lado do
  navegador, na hora, então o lado do servidor não precisa ser agressivo.
- **Abrir o painel numa segunda aba não derruba a primeira:** a aba nova nasce
  sem `sessionStorage` e pergunta às irmãs, por `localStorage`, se alguma tem o
  token. A resposta é apagada em seguida — o token não fica guardado onde
  sobreviveria ao fechamento.

---

## 14. Mesa de trabalho do analista (Filas, detalhe, decisão) — **implementado**

Visão Tática no lugar da antiga guia Phishing; Filas de Trabalho (Suspeitos e Phishing) com só o
que espera decisão; o detalhe do caso com o e-mail como entregue a partir do original guardado,
o porquê do veredito, quantas pessoas denunciaram a mesma mensagem, os indicadores e um
assistente de IA ao lado, já com o contexto do caso. Decisões: marcar como legítimo, confirmar
malicioso, reanalisar. Errata ao denunciante configurável em Notificações. Memória de vereditos:
a mensagem idêntica a um falso positivo corrigido passa a ser liberada, e o remetente vira
proposta de whitelist. Ver `THEPHISH_ARCHITECTURE.md` §7.15–7.17.

**O que continua fora:**

- **Aplicar uma decisão a todas as denúncias da mesma campanha de uma vez.** O escopo já sabe
  quais são; decidir as quarenta num clique é um poder que precisa do seu próprio desenho de
  revisão, e não entrou.
- **A casca do painel em celular.** A lista e o detalhe continuam lado a lado numa tela estreita,
  como em "E-mails analisados" — a interface nunca foi adaptada para telefone.

## Fora do escopo por decisão, não por esquecimento

- **Interruptor de "buscar imagem remota" em Configurações.** A visualização
  *Como entregue* busca as imagens do e-mail denunciado a partir do servidor
  (§7.11 de `THEPHISH_ARCHITECTURE.md`), e isso é decisão de política de SOC:
  há operações para as quais qualquer requisição de saída para a infraestrutura
  do phisher é inaceitável. O parâmetro existe (`fetch_remote`, em
  `email_render.render()`) e já tem teste, mas não foi ligado a uma tela — quem
  precisar hoje muda o padrão no código. Vira um item de Configurações quando
  alguém disser que precisa dos dois comportamentos na mesma instalação, não
  antes: uma chave que ninguém usa é uma chave que ninguém testa.

- **Abrir a *Como entregue* de um e-mail do meio da fila continua esperando a
  listagem.** As duas pontas são pré-renderizadas e abrem na hora; o resto
  espera o semáforo da caixa, que uma listagem de milhares de mensagens segura
  por 60 a 80 segundos. Não é regressão — o `GET /email/<uid>` sempre teve essa
  espera. Resolver de verdade significa a listagem não segurar o semáforo do
  começo ao fim, que é uma mudança no ciclo de polling e não nesta tela.

- **Rodapé do login com "ISO 27001" e "SOC-BR".** O mock traz esses selos. São
  afirmações de conformidade: publicá-las sem a certificação seria declaração
  falsa numa tela de acesso. O rodapé manteve o que é verdade sobre a stack:
  `ThePhish 2.0 · TheHive · MISP`.
- **Abas de Configurações do mock (auto, IA, whitelist, e-mail, alertas).** A
  aplicação tem um conjunto maior e funcional (acrescenta Notificações e Caso).
  Trocar pelo do mock removeria configuração que funciona. Os limiares de risco
  da aba "Alertas" do mock dependem do item 6.
- **O lockup completo da marca.** `bluephish-logo.png` é só o alvo, recortado do
  lockup original (2000×2000, alvo em cima e a palavra "bluephish" embaixo). A
  interface só desenha a marca em quadrados de 26–34px, onde a palavra viraria
  borrão. O fundo externo virou transparente por preenchimento a partir da borda,
  e não trocando todo pixel branco: os vãos brancos entre os anéis fazem parte da
  marca, e apagá-los deixaria três arcos soltos no tema escuro. Se algum dia
  existir uma tela larga o bastante para o lockup inteiro, ele terá de ser
  exportado à parte — o recorte atual não o contém.
