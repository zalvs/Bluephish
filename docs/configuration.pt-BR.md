# Configuração

[English](configuration.md) · **Português (Brasil)**

Tudo é configurado na interface web; você nunca deveria precisar editar um arquivo JSON à
mão. Entre como `global_admin` e abra **Configurações** (o ícone de engrenagem).

Índice: [1. Caixa de e-mail](#1-caixa-de-e-mail) · [2. IA e análise automática](#2-ia-e-análise-automática) ·
[3. Destinos e analisadores](#3-destinos-e-analisadores) · [4. Caso e whitelist](#4-caso-e-whitelist)

## 1. Caixa de e-mail

Abra *Configurações → E-mail*, escolha o provedor e preencha as credenciais:

- **Gmail:** o endereço mais uma [Senha de app](https://support.google.com/accounts/answer/185833)
  do Google (exige a verificação em duas etapas; a senha normal da conta não funciona).
- **Microsoft 365:** ID do locatário (Tenant ID), ID do cliente (Client ID), segredo do
  cliente (Client Secret) e caixa de correio de um registro de aplicativo do Azure AD com a
  permissão de aplicativo **`Mail.ReadWrite`** e consentimento do administrador. Passo a passo:
  [`m365-oauth-setup.md`](m365-oauth-setup.md). Acrescente **`User.Read.All`** ao mesmo
  registro para habilitar *Configurações → Departamentos*, que lê o departamento de cada
  denunciante no Entra ID e alimenta o cartão "Departamentos mais visados". Sem essa permissão
  o cartão fica vazio; nada mais é afetado.

O **modo de análise** decide o que o agendador automático pega:

| Modo | Comportamento |
|---|---|
| `Attached .eml` *(padrão)* | O agendador só pega e-mails que carregam um relatório `.eml` encaminhado (no Gmail a busca é restrita a e-mails não lidos com anexo). A fila continua listando todo e-mail não lido, e um que o analista escolha sem relatório é analisado como ele mesmo, com os avisos enviados à caixa monitorada. Use este modo para uma caixa dedicada a denúncias. |
| `Raw email` | O agendador também analisa, como ele mesmo, todo e-mail não lido que não traga relatório. É poderoso, mas veja o aviso abaixo. |

> ⚠️ **Em uma caixa pessoal, mantenha o agendador automático desligado no modo `Raw email`.**
> Ele analisaria seus e-mails comuns em massa, criaria um registro por mensagem e consumiria a
> cota gratuita do VirusTotal.

## 2. IA e análise automática

Abra *Configurações → IA* e *Configurações → Análise automática* (modelo de linguagem e
agendador).

| Provedor | Endpoint | Chave de API |
|---|---|---|
| **Ollama** (local, gratuito) | `http://host.docker.internal:11434/api/chat` | nenhuma |
| **OpenRouter** (hospedado, modelos mais fortes) | `https://openrouter.ai/api/v1/chat/completions` | obrigatória |

> No Linux, `host.docker.internal` não resolve dentro do contêiner `thephish` até você
> acrescentar `extra_hosts: ["host.docker.internal:host-gateway"]` a esse serviço em
> `docker/docker-compose.yml`.

Escolha o provedor na lista e ele preenche o endpoint; depois informe o modelo (por exemplo
`qwen2.5:7b` localmente, ou `anthropic/claude-3.5-sonnet` no OpenRouter). Para o Ollama
local, baixe o modelo antes: `ollama pull qwen2.5:7b`. Mais detalhes em
[`llm-analysis.md`](llm-analysis.md); documentação dos provedores: <https://docs.ollama.com/>,
<https://openrouter.ai/docs>.

Dois controles de escalonamento decidem o quanto o LLM é levado em conta:

- **Escalar Safe → Suspicious** em `Medium`/`High`/`Critical` — mantém o caso aberto para revisão.
- **Deixar só o LLM marcar Malicious** — `off` por padrão. Ligado, permite que um modelo forte
  feche um caso sozinho, sem confirmação de nenhum analisador. Um remetente comprovadamente
  autêntico por DKIM/DMARC nunca é condenado automaticamente por esse caminho.

O **LLM System Prompt** é editável aqui; o contrato de saída em JSON e a proteção para dados
não confiáveis são acrescentados pelo código e não podem ser quebrados pela interface.

## 3. Destinos e analisadores

### Destinos

*Configurações → Integrações → Tickets* é onde uma análise pronta é registrada. Há três
destinos nativos e eles são **combináveis**: TheHive, Jira, disco, os três, ou nenhum, mais
qualquer número de conectores genéricos mais abaixo na mesma aba. A análise em si não depende
de nenhum deles: os observáveis ficam em memória do parsing até o veredito, e um destino
recebe o relatório pronto e nada além disso.

Numa instalação nova só o destino **Disco** vem ligado, então as telas de histórico têm dados
desde a primeira análise e nada tenta alcançar um serviço que não existe. Os outros são por
adesão. (Uma instalação que já tinha uma chave de API do TheHive salva, ou destinos já
gravados, mantém tudo como estava.)

O **Disco** grava cada análise numa pasta datada: `report.json` para scripts, `report.md`
para ler e, opcionalmente, o `.eml` original. É a opção para rodar sem nenhum centralizador, e
nada sai da máquina. Mantenha o diretório dentro de `data/`, que é montado do host, ou ele
desaparece no próximo rebuild da imagem. Uma retenção opcional apaga as pastas mais antigas:
um e-mail de phishing guardado é dado pessoal de quem o denunciou.

O **Jira** abre uma issue por análise, com o veredito no título e o relatório completo na
descrição. Funciona com o Cloud (e-mail da conta + token de API) e com o Data Center
(Personal Access Token). Você escolhe quais vereditos merecem um ticket; o padrão é suspeito
e malicioso, porque abrir um para cada e-mail Safe soterra a fila.

O **TheHive** registra a análise como um caso. É opcional e roda fora do Bluephish: veja as
[integrações](integrations.pt-BR.md) para saber como apontar o Bluephish para ele.

Os **Conectores** são o destino sem fornecedor embutido. Em vez de um cliente escrito à mão
para cada ferramenta, você configura um: o endpoint, a autenticação e o corpo JSON colado da
própria documentação da ferramenta de destino, com `{{variáveis}}` marcando onde entra a
análise. Isso alcança qualquer API REST (Splunk, ServiceNow, PagerDuty, Slack, Sentinel,
XSOAR e as demais) em *Integrações → Tickets*, abaixo dos destinos nativos.
A **Pré-visualização** monta a requisição sem enviá-la, para você ver o corpo exato antes de
qualquer coisa sair. O **Teste** envia de verdade, e avisa: ao contrário de todos os outros
botões de teste, ele cria um ticket real na ferramenta de destino, porque num endpoint
escolhido pelo usuário não há como saber qual chamada é inofensiva. Detalhes:
[arquitetura](conectores-genericos.md) · [manual do usuário](conectores-manual.md). Ainda não
existem: um catálogo de modelos prontos, um histórico de entregas e nova tentativa; um
destino fora do ar perde aquele envio, e o log da análise diz qual e por quê.

> **Nenhum destino é obrigatório, mas as telas de histórico precisam de pelo menos um que
> registre.** **Casos**, **Phishing** e **Visão Executiva** leem de todos os destinos
> habilitados entre TheHive, disco e Jira, então só ficam vazias quando nenhum dos três está
> ligado, e nesse caso dizem que nada está registrando. Os conectores genéricos são só de
> escrita e não alimentam nenhuma tela.

### Analisadores

Os analisadores rodam dentro do próprio Bluephish. Em *Integrações → Analisadores*, cada
analisador (VirusTotal, AbuseIPDB, Google Safe Browsing, URLhaus, OTX, PhishTank, OpenPhish,
Hybrid Analysis, Defender TI, CrowdStrike, YARA, …) tem um cartão próprio com a chave de API
de que precisa, os limiares que separam malicioso de suspeito e um botão **Testar** que faz
uma consulta real, para você ver o veredito que um limiar produz antes de ligá-lo. Um
analisador que ninguém habilitou simplesmente não roda; com nenhum habilitado, o veredito
depende só da avaliação do LLM, e a tela diz isso claramente.

Cada cartão também decide **o que é enviado àquele fornecedor**. O que um analisador *sabe*
julgar e o que *vale a pena* enviar a ele são perguntas diferentes, e a segunda depende da
cota que você paga e do movimento da caixa: uma chave gratuita do VirusTotal permite 4
consultas por minuto e cerca de 500 por dia, enquanto um único e-mail de marketing carrega
dezenas de URLs. Desmarcar um tipo ali não tira o observável da análise (todos os outros
analisadores habilitados continuam julgando-o), então, numa caixa movimentada, você pode
deixar o VirusTotal só nos hashes de anexo e deixar o Safe Browsing, o URLhaus, o OpenPhish e
o PhishTank cuidarem das URLs. Os tipos que não são enviados permanecem no cartão,
tracejados e esmaecidos, para a restrição ficar visível sem abrir o formulário.

Você também pode acrescentar um fornecedor que não está no registro, em **Novo analisador**:
informe o endpoint, onde o veredito está na resposta JSON e como os valores dele se
traduzem em níveis.

O **YARA** compara regras locais com os anexos do e-mail. Ele precisa de um diretório de
arquivos `.yar`, que não existe até você criá-lo, no host:

```bash
mkdir -p docker/vol/thephish_data/yara     # vira /root/thephish/data/yara no contêiner
```

Coloque suas regras lá e deixe o caminho do analisador no padrão. Esse diretório é um bind
mount, então as regras sobrevivem a um rebuild e você não precisa reiniciar nada para
acrescentar uma.

### E-mails de veredito

Saem por SMTP, configurado em *Configurações → E-mail → Servidor de envio (SMTP)*. Há **um
interruptor por aviso** em *Configurações → Notificações* (análise iniciada, Safe, Malicious
e a errata, que começa desligada), mais o interruptor do próprio servidor SMTP na aba E-mail,
e um aviso só sai quando o interruptor dele **e** o servidor SMTP estão ligados. Um veredito
Suspicious nunca envia e-mail ao denunciante, e uma reanálise não envia a ninguém. O botão
**Testar** abre a sessão, negocia o TLS e autentica, e propositalmente não envia mensagem
nenhuma, para nunca mandar e-mail a alguém por acidente.

## 4. Caso e whitelist

TLP/PAP e tags do caso, e a **whitelist**, que tem cinco tipos de regra:

| Tipo | O que casa | Efeito |
|---|---|---|
| **Sender** | um endereço completo, e só quando o servidor de e-mail autenticou o domínio (DMARC pass, ou uma assinatura DKIM alinhada) | **Rebaixa** o veredito para Safe, depois de a análise inteira rodar, e registra o rebaixamento |
| **Domain** | `empresa.com.br` cobre o domínio e todos os subdomínios; `*.empresa.com.br` cobre só os subdomínios | Suprime o observável |
| **URL** | host e caminho, cada um casado por uma regex, aplicada com `fullmatch` na URL já interpretada | Suprime o observável |
| **Hash** | o SHA-256 de um anexo, útil para impedir que uma imagem de assinatura recorrente seja reanalisada em todo e-mail | Suprime o observável |
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
casador de verdade e mostra o host normalizado ao lado de cada uma, que é como
`nf.empresa.com.br@evil.com` se revela como uma visita a evil.com.
