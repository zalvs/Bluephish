# Bluephish — análise automatizada de e-mails de phishing

**Português (Brasil)** · [English](README.md)

Análise automatizada de e-mails de phishing para um SOC/CSIRT. O Bluephish lê uma caixa de
correio monitorada, extrai os observáveis de cada e-mail suspeito (URLs, domínios, IPs,
endereços, hashes de anexos), passa todos por analisadores de reputação próprios, pede a um
**LLM** uma avaliação de engenharia social e produz um veredito — `Safe`, `Suspicious` ou
`Malicious` — registrado onde você escolher: **TheHive**, **Jira**, disco local, qualquer API
REST por meio de um conector genérico, ou qualquer combinação desses destinos.

O Bluephish nasceu inspirado no [emalderson/ThePhish](https://github.com/emalderson/ThePhish)
e hoje é um projeto independente; não é mais mantido como fork. Ele acrescenta suporte ao
Microsoft 365, um agendador de análise automática, análise de engenharia social e de imagens
por LLM, verificação de remetente por SPF/DKIM/DMARC, um chat de IA para investigar casos e
autenticação corporativa (dois fatores TOTP obrigatório, RBAC, CSRF, bloqueio de conta e
trilha de auditoria). Parte do código original do ThePhish ainda faz parte deste repositório,
e o próprio ThePhish é publicado sob AGPL-3.0, a licença que este projeto agora segue.

> **Referência de arquitetura e migração:** [`THEPHISH_ARCHITECTURE.md`](THEPHISH_ARCHITECTURE.md)
> (em inglês) — modelo de dados, regras de RBAC, rotas, desenho de segurança e restrições
> conhecidas.
>
> **Diagramas:** [`diagrams.md`](diagrams.md) — implantação, módulos, o pipeline de análise,
> a cadeia do veredito, os destinos, a autenticação, a proteção contra SSRF e a trilha de
> auditoria, desenhados a partir do código atual.
>
> **Vai mudar o código com um agente de IA?** Leia o [`CLAUDE.md`](CLAUDE.md) antes —
> consultar o grafo de conhecimento em `graphify-out/` antes de editar é obrigatório aqui,
> porque vários acoplamentos desta implantação falham em silêncio.

---

## Início rápido

### Requisitos

| | Mínimo | Observações |
|---|---|---|
| Docker + plugin Compose | qualquer versão recente | `docker compose version` precisa funcionar |
| RAM | **6 GB livres** | Cassandra, TheHive e MISP rodam juntos |
| Disco | **~25 GB livres** | imagens mais os volumes de dados |
| Portas livres no localhost | 8080, 9000, 8008, 80, 443 | todas ligadas só a `127.0.0.1`. **80 e 443 são do MISP** e colidem com qualquer servidor web local — veja [Solução de problemas](#solução-de-problemas) |

### Um comando

```bash
git clone https://github.com/zalvs/Bluephish.git
cd Bluephish
./setup.sh
```

O `setup.sh` cria o `docker/.env` com uma chave de sessão recém-gerada, protege os arquivos de
configuração que vão guardar segredos reais, constrói e sobe todos os contêineres e espera a
interface ficar disponível. Pode ser executado de novo sem medo: nada que já esteja
configurado é sobrescrito.

> **No Windows, execute-o pelo Git Bash — não pelo PowerShell nem pelo CMD.**
> O PowerShell não executa arquivos `.sh`: digitar `./setup.sh` lá apenas abre o script no
> editor associado à extensão (muitas vezes o VS Code), o que parece o script "não fazendo
> nada".
>
> Para ficar no PowerShell, chame o bash do Git explicitamente — repare no caminho completo,
> porque o `bash.exe` solto em `System32` é o WSL, onde o Docker Desktop normalmente não está
> no `PATH`:
> ```powershell
> & 'C:\Program Files\Git\bin\bash.exe' -lc "cd '/c/caminho/para/Bluephish' && ./setup.sh"
> ```

Para fazer tudo manualmente, veja [Instalação manual](#instalação-manual).

### Criar o primeiro administrador

**Não existe conta padrão nem senha embutida no código.** Crie a primeira:

```bash
cd docker && docker compose exec thephish python3 manage.py create-admin
```

O comando pede um nome de usuário e uma senha (mínimo de **12 caracteres**), digitada duas
vezes e nunca exibida na tela.

> Os comandos usam `docker compose exec <serviço>` (executado a partir de `docker/`) em vez
> de `docker exec <contêiner>`, porque um `docker-compose.override.yml` local pode renomear
> os contêineres. O nome do serviço é sempre `thephish`.

### Entrar

Abra **<https://localhost:8080>**.

> O certificado é autoassinado, então o navegador avisa uma vez — escolha *Avançado →
> Continuar*. **HTTPS é obrigatório:** o cookie de sessão é emitido com a flag `Secure`, então
> o login não funciona por HTTP puro.

**Deixe um aplicativo autenticador pronto antes do primeiro acesso.** A autenticação em dois
fatores é obrigatória e não pode ser desligada, então a senha sozinha não basta: no primeiro
acesso aparece um QR code para ler com o Google Authenticator, o Microsoft Authenticator, o
Authy ou qualquer outro aplicativo TOTP, e o painel só abre depois que o código de seis
dígitos do aplicativo for aceito. Não há opção por e-mail nem por SMS — veja as
[Notas de segurança](#notas-de-segurança) para entender o motivo. Se o celular for perdido
depois, um `global_admin` limpa o fator em **Usuários**, ou, a partir do host, com
`docker compose exec thephish python3 manage.py reset-mfa NOME`.

A primeira subida leva alguns minutos, enquanto o Cassandra e o TheHive se inicializam.

**Fechar a aba encerra a sessão.** A sessão está presa à aba do navegador que a abriu, e não
ao cookie: feche a aba e o próximo acesso pede as credenciais de novo, e o servidor revoga a
sessão por conta própria quando a aba para de dar sinal. Recarregar (F5) e abrir o painel em
uma segunda aba mantêm você autenticado. Veja o [`ROADMAP.md`](ROADMAP.md) §13 para entender
como as duas metades funcionam.

O **SSO corporativo** (Microsoft Entra ID, OpenID Connect) é opcional e fica desligado até um
`global_admin` configurá-lo em *Configurações → SSO*. Passo a passo:
[`docs/sso-entra-setup.md`](docs/sso-entra-setup.md).

---

## Configuração (pela interface)

Tudo é configurado na interface web — você nunca deveria precisar editar um arquivo JSON à
mão. Entre como `global_admin` e abra **Configurações** (o ícone de engrenagem).

### 1. E-mail — caixa de correio

Escolha o provedor e preencha as credenciais:

- **Gmail:** o endereço mais uma [Senha de app](https://support.google.com/accounts/answer/185833)
  do Google (exige a verificação em duas etapas; a senha normal da conta não funciona).
- **Microsoft 365:** ID do locatário (Tenant ID), ID do cliente (Client ID), segredo do
  cliente (Client Secret) e caixa de correio de um registro de aplicativo do Azure AD com a
  permissão de aplicativo **`Mail.ReadWrite`** e consentimento do administrador. Acrescente
  **`User.Read.All`** ao mesmo registro para habilitar *Configurações → Departamentos*, que
  lê o departamento de cada denunciante no Entra ID e alimenta o cartão "Departamentos mais
  visados". Sem essa permissão o cartão fica vazio; nada mais é afetado.

O **modo de análise** decide o que o agendador automático pega:

| Modo | Comportamento |
|---|---|
| `Attached .eml` *(padrão)* | O agendador só pega e-mails que carregam um relatório `.eml` encaminhado (no Gmail a busca é restrita a e-mails não lidos com anexo). A fila continua listando todo e-mail não lido, e um que o analista escolha sem relatório é analisado como ele mesmo, com os avisos enviados à caixa monitorada. Use este modo para uma caixa dedicada a denúncias. |
| `Raw email` | O agendador também analisa, como ele mesmo, todo e-mail não lido que não traga relatório. É poderoso, mas veja o aviso abaixo. |

> ⚠️ **Em uma caixa pessoal, mantenha o agendador automático desligado no modo `Raw email`.**
> Ele analisaria seus e-mails comuns em massa, criaria um caso por mensagem e consumiria a
> cota gratuita do VirusTotal.

### 2. IA e Análise automática — LLM e agendador

| Provedor | Endpoint | Chave de API |
|---|---|---|
| **Ollama** (local, gratuito) | `http://host.docker.internal:11434/api/chat` | nenhuma |
| **OpenRouter** (hospedado, modelos mais fortes) | `https://openrouter.ai/api/v1/chat/completions` | obrigatória |

> No Linux, `host.docker.internal` não resolve dentro do `thephish` até você acrescentar
> `extra_hosts: ["host.docker.internal:host-gateway"]` a esse serviço em
> `docker/docker-compose.yml` (hoje só o `hive-ai-agent` tem isso).

Escolha o provedor na lista e ele preenche o endpoint; depois informe o modelo (por exemplo
`qwen2.5:7b` localmente, ou `anthropic/claude-3.5-sonnet` no OpenRouter). Para o Ollama
local, baixe o modelo antes: `ollama pull qwen2.5:7b`.

Dois controles de escalonamento decidem o quanto o LLM é levado em conta:

- **Escalar Safe → Suspicious** em `Medium`/`High`/`Critical` — mantém o caso aberto para revisão.
- **Deixar só o LLM marcar Malicious** — `off` por padrão. Ligado, permite que um modelo forte
  feche um caso sozinho, sem confirmação de nenhum analisador. Um remetente comprovadamente
  autêntico por DKIM/DMARC nunca é condenado automaticamente por esse caminho.

O **LLM System Prompt** é editável aqui; o contrato de saída em JSON e a proteção para dados
não confiáveis são acrescentados pelo código e não podem ser quebrados pela interface.

### 3. Integrações — destinos e analisadores (mais o SMTP, que fica em Configurações → E-mail)

A aba **Tickets** é onde uma análise terminada é registrada. Ela tem três destinos nativos e
eles são **combináveis**: TheHive, Jira, disco, os três, ou nenhum — mais qualquer número de
conectores genéricos mais abaixo na mesma aba. A análise em si não depende mais de nenhum
deles: os observáveis ficam em memória do parsing até o veredito, e um destino recebe o
relatório pronto e nada além disso.

O **TheHive** (<http://localhost:9000>) é um dos destinos que as telas **Casos**, **Phishing**
e **Visão Executiva** leem de volta, junto com o disco e o Jira quando estão ligados. Ele
precisa de uma chave de API e **não** pede para você criar uma conta no primeiro acesso: vem
com uma conta padrão, e deixá-la como está é uma exposição real:

1. Entre com **`admin@thehive.local`** / **`secret`**.
2. **Troque essa senha imediatamente** (avatar no canto superior direito → *Settings*). É um
   padrão publicado; qualquer pessoa que alcance a porta 9000 a conhece.
3. Crie uma organização: *Organisations* → **New organisation**, com qualquer nome.
4. Dentro dela, **Create new user** com o perfil `org-admin`, defina uma senha e depois
   **Create API key** → **Reveal** e copie a chave.
5. Cole `http://thehive:9000` e essa chave no cartão **TheHive** da aba
   **Integrações → Tickets** do Bluephish.

> A URL é `http://thehive:9000`, e não `localhost`: o Bluephish alcança o TheHive pela rede do
> Docker, pelo nome do serviço. `localhost` dentro desse contêiner é o próprio contêiner.

O **Jira** abre uma issue por análise, com o veredito no título e o relatório completo na
descrição. Funciona com o Cloud (e-mail da conta + token de API) e com o Data Center
(Personal Access Token). Você escolhe quais vereditos merecem um ticket — o padrão é
suspeito e malicioso, porque abrir um para cada e-mail Safe soterra a fila.

O **Disco** grava cada análise numa pasta datada: `report.json` para scripts, `report.md`
para ler e, opcionalmente, o `.eml` original. É a opção para rodar sem nenhum centralizador —
nada sai da máquina. Mantenha o diretório dentro de `data/`, que é montado do host, ou ele
desaparece no próximo rebuild da imagem. Há uma retenção opcional que apaga as pastas mais
antigas: um e-mail de phishing guardado é dado pessoal de quem o denunciou.

> **O TheHive é opcional, e qualquer outro destino também — mas as telas de histórico
> precisam de pelo menos um que registre.** A análise não depende mais de nenhum deles:
> nada é gravado num caso antes de o veredito existir. O que *depende* deles é o histórico —
> **Casos**, **Phishing** e **Visão Executiva** leem de todos os destinos ligados entre
> TheHive, disco e Jira, então só ficam vazias quando nenhum dos três está ligado, e nesse
> caso dizem que nada está registrando. Os conectores genéricos são só de escrita e não
> alimentam nenhuma tela. Desligue o TheHive quando o Jira ou o disco for o seu registro
> oficial.

Os **Conectores** são o quarto destino, e o único sem fornecedor embutido. Em vez de um
cliente escrito à mão para cada ferramenta, você configura um: o endpoint, a autenticação e o
corpo JSON colado da própria documentação da ferramenta de destino, com `{{variáveis}}`
marcando onde entra a análise. Isso alcança qualquer API REST — Splunk, ServiceNow,
PagerDuty, Slack, Sentinel, XSOAR e as demais — em **Integrações → Tickets**, abaixo dos três
destinos nativos.

A **Pré-visualização** monta a requisição sem enviá-la, para você ver o corpo exato antes de
qualquer coisa sair. O **Teste** envia de verdade, e avisa: ao contrário de todos os outros
botões de teste daqui, ele cria um ticket real na ferramenta de destino, porque num endpoint
escolhido pelo usuário não há como saber qual chamada é inofensiva.

> Ainda não existem: um catálogo de modelos prontos (todo conector começa em branco), um
> histórico de entregas e nova tentativa — um destino fora do ar perde aquele envio, e o log
> da análise diz qual e por quê. Detalhes: [arquitetura](docs/conectores-genericos.md) ·
> [manual do usuário](docs/conectores-manual.md).

Os **Analisadores** rodam dentro do próprio Bluephish — não existe mais Cortex. Em
**Integrações → Analisadores**, cada analisador (VirusTotal, AbuseIPDB, Google Safe Browsing,
URLhaus, OTX, PhishTank, OpenPhish, Hybrid Analysis, Defender TI, CrowdStrike, YARA, …) tem
um cartão próprio com a chave de API de que precisa, os limiares que separam malicioso de
suspeito e um botão **Testar** que faz uma consulta real, para você ver o veredito que um
limiar produz antes de ligá-lo. Um analisador que ninguém habilitou simplesmente não roda;
com nenhum habilitado, o veredito depende só da avaliação do LLM, e a tela diz isso
claramente.

Cada cartão também decide **o que é enviado àquele fornecedor**. O que um analisador *sabe*
julgar e o que *vale a pena* enviar a ele são perguntas diferentes, e a segunda depende da
cota que você paga e do movimento da caixa: uma chave gratuita do VirusTotal permite 4
consultas por minuto e cerca de 500 por dia, enquanto um único e-mail de marketing carrega
dezenas de URLs. Desmarcar um tipo ali não tira o observável da análise — todos os outros
analisadores habilitados continuam julgando-o — então, numa caixa movimentada, você pode
deixar o VirusTotal só nos hashes de anexo e deixar o Safe Browsing, o URLhaus, o OpenPhish e
o PhishTank cuidarem das URLs. Os tipos que não são enviados permanecem no cartão,
tracejados e esmaecidos, para a restrição ficar visível sem abrir o formulário.

Você também pode acrescentar um fornecedor que não está no registro, em **Novo analisador**:
informe o endpoint, onde o veredito está na resposta JSON e como os valores dele se
traduzem em níveis.

O **YARA** compara regras locais com os anexos do e-mail. Ele precisa de um diretório de
arquivos `.yar`, que não existe até você criá-lo — no host:

```bash
mkdir -p docker/vol/thephish_data/yara     # vira /root/thephish/data/yara no contêiner
```

Coloque suas regras lá e deixe o caminho do analisador no padrão. Esse diretório é um
bind mount, então as regras sobrevivem a um rebuild e você não precisa reiniciar nada para
acrescentar uma.

Os **e-mails de veredito** saíam pelo responder *Mailer* do Cortex. Agora saem por SMTP,
configurado em **Configurações → E-mail → Servidor de envio (SMTP)**. Há **um interruptor
por aviso** em **Configurações → Notificações** — análise iniciada, Safe, Malicious e a
errata, que começa desligada — mais o interruptor do próprio servidor SMTP na aba E-mail, e
um aviso só sai quando o interruptor dele **e** o servidor SMTP estão ligados. Um veredito
Suspicious nunca envia e-mail ao denunciante, e uma reanálise não envia a ninguém. O botão
**Testar** abre a sessão, negocia o TLS e autentica — e propositalmente não envia mensagem
nenhuma, para nunca mandar e-mail a alguém por acidente.

### 4. Caso e Whitelist

TLP/PAP e tags do caso, e a **whitelist**, que tem cinco tipos de regra:

| Tipo | O que casa | Efeito |
|---|---|---|
| **Sender** | um endereço completo, e só quando o servidor de e-mail autenticou o domínio (DMARC pass, ou uma assinatura DKIM alinhada) | **Rebaixa** o veredito para Safe, depois de a análise inteira rodar, e registra o rebaixamento |
| **Domain** | `empresa.com.br` cobre o domínio e todos os subdomínios; `*.empresa.com.br` cobre só os subdomínios | Suprime o observável |
| **URL** | host e caminho, cada um casado por uma regex, aplicada com `fullmatch` na URL já interpretada | Suprime o observável |
| **Hash** | o SHA-256 de um anexo — útil para impedir que uma imagem de assinatura recorrente seja reanalisada em todo e-mail | Suprime o observável |
| **IP** | um endereço roteável ou faixa CIDR; endereços privados, de loopback e reservados são ignorados em toda análise de qualquer forma | Suprime o observável |

Só o tipo sender altera um veredito, e ele nunca pula a análise: um remetente confiável cujo
e-mail continua voltando malicioso é uma caixa comprometida, então todo rebaixamento é
contado e a regra **se suspende sozinha** quando já escondeu vereditos não Safe demais.
Um *anexo* malicioso nunca é rebaixado.

Toda regra carrega um motivo e uma validade. O padrão é 180 dias; uma data específica é a
escolha certa para um contrato; "permanente" exige uma justificativa escrita e o papel
`global_admin`. Antes de salvar uma regra, você pode simulá-la contra os últimos 90 dias de
análises para ver o que ela teria escondido.

Para regras de URL você não precisa escrever a regex à mão: cole os endereços que quer
liberar e **Sugerir regex** deriva o padrão, explica cada escolha e informa se alguma das
quatro variações de evasão (userinfo antes do `@`, o domínio como sufixo de outro, o domínio
no fragmento, o domínio na query) também casaria. **Testar** passa as URLs coladas pelo
casador de verdade e mostra o host normalizado ao lado de cada uma — é assim que
`nf.empresa.com.br@evil.com` se revela como uma visita a evil.com.

> **A exportação para o MISP vem desligada e falha em silêncio até você ativá-la.** Um
> veredito `Malicious` pede ao TheHive que exporte o caso para o MISP sempre que o destino
> TheHive tem um nome de exportação MISP (a configuração que acompanha o projeto define
> `MISP THP`), mas o conector MISP do TheHive vem comentado em
> `docker/thehive/application.conf`. Até você descomentá-lo e colocar ali uma chave de API
> real do MISP, todo caso malicioso registrado no TheHive termina a linha do TheHive no log
> da análise com *"a exportação para o MISP falhou"* e é tratado normalmente no restante.
> Apagar o nome de exportação MISP no cartão **TheHive** (**Integrações → Tickets**) para
> a requisição de exportação por completo. Todo o resto — o veredito, o caso, a notificação —
> funciona sem o MISP, então deixá-lo desligado é uma escolha perfeitamente boa.

---

## Uso no dia a dia

1. **Listar e-mails** no painel — somente leitura, nunca inicia uma análise. A caixa também
   é relida por um temporizador e enviada à tela, então a fila se mantém atualizada sozinha.
2. Encontre o que você quer. A caixa de busca filtra a fila que o navegador já tem —
   remetente, assunto, UID, tipo e, para as denúncias cujo corpo já foi baixado, o conteúdo.
   Os termos se combinam, então `boleto itau` acha a denúncia cujo assunto diz um e cujo
   remetente é o outro. Nada é perguntado ao servidor, então ela responde enquanto você digita.
3. Abra uma denúncia para lê-la. **Abrir não é analisar** — a caixa é apenas espiada, então a
   mensagem continua não lida e continua na fila de todos. A prévia tem duas abas:
   - **Texto** (o padrão) — o texto extraído da mensagem. É o mais rápido de ler e não tem como
     se disfarçar.
   - **Como entregue** — a mensagem montada como o destinatário a viu, dentro de uma sandbox
     que não executa scripts nem segue links. Esta é a metade de um e-mail de phishing que
     faz a persuasão: o papel timbrado falsificado, o botão cujo rótulo e destino não
     combinam. Cada link mostra seu destino real ao lado do texto, e um link cujo texto cita
     um domínio mas aponta para outro é marcado. Os anexos são listados com o tamanho, o tipo
     real ao lado do declarado e um SHA-256 para copiar — o arquivo em si nunca sai do
     contêiner. **Leia a nota sobre requisições de saída nas [Notas de
     segurança](#notas-de-segurança) antes de usar esta visão numa rede isolada.**
4. Marque os e-mails que quer e use o botão de análise em lote (ou o *Analisar* de cada linha).
5. Acompanhe o log ao vivo; o veredito aparece no final. Safe e Malicious respondem ao
   denunciante, que recebe o veredito por e-mail quando esse aviso e o SMTP estão ambos
   ligados (os dois vêm desligados). Os Suspicious não avisam ninguém e esperam em **Filas de
   Trabalho** por um analista, desde que um destino que o histórico lê (TheHive, disco ou
   Jira) o tenha registrado. O resultado é entregue a todo destino habilitado cujo veredito
   mínimo ele alcança (TheHive, Jira, disco) e depois aos conectores genéricos. Um destino
   fora do ar nunca desfaz o veredito.
6. Use o **Chat AI** (ícone de robô) para interrogar um caso já analisado: informe o número do
   caso, carregue o contexto e faça perguntas sobre ele.

### Papéis

| Papel | Pode |
|---|---|
| `analyst` | Listar e-mails, analisar, reanalisar um original guardado, decidir uma reclassificação do caso, usar o chat de IA, ler a whitelist, trocar a própria senha |
| `admin` | Tudo isso **mais** as configurações (exceto o SSO corporativo e onde a trilha de auditoria é guardada), edições da whitelist, bloqueios, leitura da trilha de auditoria e desfazer uma reclassificação ou ensiná-la à memória de vereditos |
| `global_admin` | Tudo isso **mais** a gestão de usuários, reinício de senha e de segundo fator, o SSO corporativo, onde a trilha de auditoria é guardada e regras permanentes da whitelist |

Gerencie os usuários pelo ícone de **pessoas** (visível só para o `global_admin`).

---

## Comandos comuns

Todos rodam a partir do diretório `docker/`.

```bash
# Usuários
docker compose exec thephish python3 manage.py create-admin        # primeiro global_admin
docker compose exec thephish python3 manage.py create-user         # usuário adicional, qualquer papel
docker compose exec thephish python3 manage.py list-users
docker compose exec thephish python3 manage.py reset-password NOME
docker compose exec thephish python3 manage.py reset-mfa NOME       # celular perdido ou trocado
docker compose exec thephish python3 manage.py unlock NOME         # limpar o bloqueio de uma conta

# Stack
docker compose up -d --build thephish   # reconstrói só a aplicação depois de uma mudança no código
docker compose logs -f thephish
docker compose restart thephish
docker compose down                     # para tudo (os dados em vol/ são mantidos)

# Trilha de auditoria — -F (e não -f) continua acompanhando através das rotações (diárias,
# ou antes, por tamanho). Se uma pasta foi definida em Configurações → Auditoria, o arquivo
# ativo é /root/thephish/data/<pasta>/auth.log
docker compose exec thephish tail -F /root/thephish/data/auth.log
```

---

## Instalação manual

Se preferir não executar o `setup.sh`:

```bash
# 1. arquivo de ambiente com uma chave para assinar as sessões
cp docker/.env.example docker/.env
openssl rand -base64 48        # cole o resultado em THEPHISH_SECRET_KEY

# 2. mantenha os segredos de execução fora do git
#    (os dois arquivos são versionados como modelos, mas recebem credenciais reais em execução)
git update-index --skip-worktree \
    docker/thephish_conf_files/configuration.json \
    docker/thehive/application.conf

# 3. construir e subir
cd docker && docker compose up -d --build

# 4. primeiro administrador (ainda a partir de docker/)
docker compose exec thephish python3 manage.py create-admin
```

---

## Onde ficam as coisas

| Caminho | Conteúdo |
|---|---|
| `app/` | A aplicação Flask (embutida na imagem na hora do build) |
| `docs/` | Referência por funcionalidade: análise por LLM, OAuth do M365, o agente de IA, o conector genérico |
| `docker/docker-compose.yml` | Todos os serviços; toda porta ligada a `127.0.0.1` |
| `docker/.env` | **Segredos** — ignorado pelo git, criado pelo `setup.sh` |
| `docker/thephish_conf_files/` | Configuração viva, montada do host e escrita pela aplicação |
| `docker/vol/` | **Dados persistentes — faça backup.** Banco SQLite (usuários e as decisões da plataforma), log de auditoria, mensagens originais guardadas, chaves TLS, dados do TheHive/MISP |
| `hive_ai_agent/` | Serviço opcional que correlaciona IOCs nos webhooks do TheHive |

O `docker/vol/thephish_data/` guarda o `thephish.db` (usuários, decisões de reclassificação,
memória de vereditos, estado da whitelist e impressões digitais dos casos), o `auth.log`
(trilha de auditoria), o par de chaves TLS, as mensagens originais guardadas (`originals/`),
os e-mails renderizados (`rendered/`), o `volume_alerts.json` e — nos caminhos padrão — o
arquivo em disco (`analises/`) e as regras YARA (`yara/`). Perdê-lo significa recriar todas
as contas e perder o histórico de auditoria, as reclassificações dos analistas e a memória de
vereditos, os contadores da whitelist e as mensagens originais guardadas.

> **Rode sempre o `docker compose` a partir do diretório `docker/` deste repositório.** Todo
> volume é declarado relativo ao arquivo do compose, então rodá-lo a partir de um git
> worktree ou de uma cópia da árvore liga os contêineres, em silêncio, a um `vol/` diferente
> e vazio. A stack sobe com aparência saudável, sem usuários, sem casos e com credenciais de
> exemplo, e a única pista no log é um certificado TLS sendo gerado. Nada é destruído — os
> dados reais continuam onde estavam — mas nada funciona até a stack ser subida do lugar certo.

---

## Solução de problemas

| Sintoma | Causa e correção |
|---|---|
| `./setup.sh` abre o VS Code (ou um editor) em vez de executar | Você está no PowerShell/CMD, que não executa `.sh` — ele abre o arquivo com o programa associado. Use o **Git Bash**, ou chame o bash do Git explicitamente (veja o [Início rápido](#um-comando)). |
| `set: pipefail\r: invalid option name` ou `bad interpreter` | O script foi baixado com quebras de linha **CRLF**. Um `.gitattributes` agora força LF, então clone de novo ou corrija a cópia: `sed -i 's/\r$//' setup.sh`. |
| O navegador não alcança a aplicação | Use **`https://`** (e não `http://`) e **`localhost`** — as portas estão ligadas a `127.0.0.1`, então o IP da máquina na rede local não funciona, de propósito. |
| `port is already allocated` na 80 ou na 443 | Essas pertencem ao contêiner do MISP e colidem com qualquer servidor web local (IIS, Apache, outra stack). O MISP é opcional: comente os `ports:` dele em `docker/docker-compose.yml`, ou remapeie para algo como `127.0.0.1:8081:80`. Nada no pipeline de análise precisa alcançar a interface web do MISP. |
| O Bluephish não alcança o TheHive, embora `localhost:9000` funcione no navegador | A URL em **Integrações** tem que ser `http://thehive:9000` — o nome do serviço no Docker. Dentro do contêiner, `localhost` é o próprio contêiner. |
| Aviso de certificado | Esperado: o certificado é autoassinado. Aceite uma vez. |
| Deslogado a cada reinício | `THEPHISH_SECRET_KEY` está vazio em `docker/.env`. Rode `./setup.sh` ou defina-o manualmente. |
| Nenhum analisador rodou numa análise | Nenhum está habilitado, ou nenhum suporta os tipos de observável encontrados. Veja **Integrações → Analisadores**; o cabeçalho de lá diz quantos estão ligados. |
| Um analisador não informa nada enquanto os outros funcionam | O erro dele viaja com o relatório: `findings[].error` no `report.json` que o destino em disco grava, e o log da análise (o painel ao vivo, ou `docker logs thephish`). O log de tarefas do TheHive lista apenas o que foi sinalizado. Uma chave recusada, uma cota esgotada e um 429 dizem isso literalmente. |
| Os e-mails de veredito nunca chegam | Cada aviso tem o próprio interruptor em **Configurações → Notificações**, o servidor SMTP tem outro em **Configurações → E-mail**, e os dois precisam estar ligados. Um veredito Suspicious nunca envia e-mail ao denunciante. Use o botão **Testar** — ele autentica sem enviar. |
| O login diz "Invalid username or password" e você tem certeza de que está certo | A conta é bloqueada por **15 minutos** depois de 5 falhas. Libere-a: `docker compose exec thephish python3 manage.py unlock NOME` (a partir de `docker/`). |
| De repente toda conta é desconhecida, e o log mostra **um novo certificado TLS sendo gerado** | A stack foi subida do diretório errado. Todo volume no `docker-compose.yml` é relativo ao arquivo (`./vol/...`), então um `docker compose up` rodado de um git worktree ou de uma cópia aponta o contêiner para um `vol/` **vazio** — um banco novo sem usuários, um certificado novo e o `configuration.json` de exemplo no lugar das suas credenciais. Nada se perdeu: seus dados continuam no `docker/vol/` verdadeiro. Suba a stack a partir do `docker/` do próprio repositório e confira com `docker inspect thephish --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'` — nenhum caminho deve apontar para um lugar inesperado. |
| Abrir *Como entregue* é lento para uma denúncia | O layout de todo e-mail é carregado em segundo plano, página por página, e abre na hora quando fica pronto; as imagens remotas dele são então buscadas no clique, com limite de 20 s. Uma denúncia que o carregador ainda não alcançou é renderizada no clique, e essa renderização espera a vez de acessar a caixa atrás de qualquer ciclo de leitura em andamento. A linha abaixo dos botões de página diz até onde o carregador chegou. |
| As linhas continuam *aguardando carregamento* | O carregador em segundo plano lê dez e-mails por viagem ao servidor de e-mail e dá passagem a todo clique, então, na primeira subida, uma caixa com alguns milhares de não lidos demora para ser preenchida. Os layouts ficam em `docker/vol/thephish_data/rendered` e sobrevivem a reinícios e rebuilds. Se a linha abaixo dos botões de página disser que o carregamento em segundo plano está indisponível, esse diretório não é gravável — tudo continua abrindo, no clique. |
| As imagens em *Como entregue* aparecem como "não carregada" | O texto de substituição diz qual dos três motivos vale: a proteção contra SSRF recusou o endereço, o host nunca respondeu, ou o arquivo passou do limite de tamanho ou de tempo. Os três são o sistema funcionando. |
| Tentativas de login demais | A rota de login tem limite de **5 por minuto por IP**. Espere um minuto. |
| O código do autenticador é sempre rejeitado | O TOTP é um relógio, e não uma senha: a hora do celular precisa estar certa. Ligue a hora automática (Android: *Authenticator → Configurações → Correção de tempo para códigos*; iOS: *Ajustes → Geral → Data e Hora → Automaticamente*). O servidor aceita ±30 s. |
| Perdeu o celular com o autenticador | Um `global_admin` limpa o segundo fator em **Usuários → Resetar MFA**; o próximo acesso pede para configurá-lo de novo. Se ninguém consegue entrar, faça pelo host: `docker compose exec thephish python3 manage.py reset-mfa NOME`. |
| O LLM não contribui em nada para os vereditos | Veja no `docker logs thephish` um aviso do `llm_analysis`. A análise é fail-open: um modelo inalcançável nunca bloqueia o pipeline. |
| Nenhum e-mail listado | A fila lista todo e-mail não lido, qualquer que seja o modo de análise, então uma fila vazia significa que a caixa não pôde ser lida ou não tem nada não lido. A linha de status da fila e o `docker logs thephish` dizem o erro do provedor (para o limite diário de download do Gmail, veja o §7.7.1 do [`THEPHISH_ARCHITECTURE.md`](THEPHISH_ARCHITECTURE.md)). O modo de análise só muda o que o agendador automático pega. |

---

## Notas de segurança

- Toda porta é publicada somente em **`127.0.0.1`**. O Cassandra e o MySQL do MISP, em
  particular, rodam com credenciais de desenvolvimento e jamais devem ser expostos. Para
  alcançar a interface de outra máquina, coloque-a atrás de um proxy reverso com TLS em vez
  de mudar as ligações de porta.
- Os segredos nunca são devolvidos ao navegador — a API de configurações responde com
  booleanos (`hasApiKey`) e um campo vazio ao salvar significa "manter o valor guardado".
- **O contêiner faz requisições de saída para infraestrutura que o phisher escolheu.** Duas
  funcionalidades fazem isso por desenho: o desencurtador de URLs, durante a análise, e a
  visão *Como entregue*, que busca as imagens para as quais um e-mail denunciado aponta. Quem
  busca é o **contêiner**, nunca o navegador do analista — o endereço e o user agent da
  estação de trabalho nunca saem, e tudo o que chega ao navegador é uma URI `data:` dentro de
  uma sandbox. Mas a requisição sai da sua rede e avisa o remetente de que alguém olhou. A
  interface nomeia todo host que contatou. As imagens são buscadas **só quando alguém abre
  *Como entregue***: o carregador em segundo plano monta todo e-mail sem elas, então uma
  denúncia que ninguém abre não conta nada ao remetente.

  Três consequências que vale decidir antes da implantação: coloque a saída do contêiner
  atrás do proxy que a sua política de saída espera; espere que uma campanha de phishing
  descubra que esta caixa é monitorada; e, se isso for inaceitável para a sua operação, o
  `fetch_remote` em `app/email_render.py` desliga a busca de imagens na origem (links e
  scripts ficam inertes de qualquer forma). Toda busca é validada pela mesma proteção
  contra SSRF dos analisadores definidos pelo analista — a rede interna nunca é alcançável e
  o serviço de metadados da nuvem é recusado de saída — com redirecionamentos recusados,
  tipos de imagem lidos dos bytes e não do `Content-Type`, SVG rejeitado, e quantidade,
  tamanho e tempo total limitados.
- As senhas são guardadas com **bcrypt**; as sessões expiram após **30 min de inatividade /
  12 h no total**, são revogadas na troca de senha e terminam quando a aba do navegador que
  as abriu é fechada. Todos os eventos de autenticação são auditados em `auth.log`.
- **Um segundo fator é obrigatório para toda conta**, sem isenção por usuário ou por papel e
  sem nenhuma configuração que o desligue. Uma senha correta abre um desafio de 10 minutos,
  e não uma sessão: ninguém entra até apresentar um código TOTP válido, então uma senha
  roubada, sozinha, não alcança nada. As contas anteriores a isso são interceptadas no
  próximo acesso e precisam se cadastrar antes de entrar, e as sessões abertas antes disso
  são derrubadas.
- **Só aplicativos autenticadores** (Google Authenticator, Microsoft Authenticator, Authy ou
  qualquer cliente RFC 6238). Códigos por e-mail ou SMS não são oferecidos de propósito e não
  devem ser acrescentados: o SMS cai com a troca de chip (SIM swap), e o e-mail cai junto com
  a própria caixa que esta plataforma existe para vigiar. A recuperação é um `global_admin`
  limpando o fator, nunca um código enviado por um canal que um atacante pode já controlar.
- **Contas de SSO não são isentas.** O provedor de identidade comprova um fator; a plataforma
  exige dois, então o retorno do Entra ID cai no mesmo desafio TOTP.
- **Contas de SSO não têm senha nenhuma.** O hash guardado é de um valor aleatório que ninguém
  jamais viu, o login por senha as recusa de saída e o *Reset password* não é oferecido para
  elas — a revogação cabe ao provedor de identidade.
- Antes de abrir isto para uma rede mais ampla, leia a seção *Known constraints and traps* do
  [`THEPHISH_ARCHITECTURE.md`](THEPHISH_ARCHITECTURE.md).

## Licença

GNU AGPL-3.0 — veja o [LICENSE](LICENSE). Inspirado no
[emalderson/ThePhish](https://github.com/emalderson/ThePhish), que também é AGPL-3.0.
