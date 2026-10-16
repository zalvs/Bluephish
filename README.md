# Bluephish — análise automatizada de e-mails de phishing

**Português (Brasil)** · [English](README.en.md)

Análise automatizada de e-mails de phishing para um SOC/CSIRT. O Bluephish lê uma caixa de
correio monitorada, extrai os observáveis de cada e-mail suspeito (URLs, domínios, IPs,
endereços, hashes de anexos), passa todos por analisadores de reputação, pede a um **LLM**
uma avaliação de engenharia social e produz um veredito (`Safe`, `Suspicious` ou
`Malicious`) que ele pode registrar onde você escolher: uma pasta em disco, o Jira, qualquer
API REST por um conector genérico, ou o TheHive.

- Roda de forma **manual** (um analista escolhe o e-mail) ou **100% automática** (um agendador).
- Lê caixas do **Gmail** e do **Microsoft 365**.
- Verifica **SPF/DKIM/DMARC** do remetente e lê imagens embutidas com um modelo de visão.
- Controle de acesso por papéis, **autenticação em dois fatores** obrigatória, SSO e trilha de auditoria.
- Um contêiner. Todo o resto é opcional.

O Bluephish nasceu inspirado no [ThePhish](https://github.com/emalderson/ThePhish) e hoje é
um projeto independente. Se você conhece o original e quer ver como os dois se diferenciam,
leia [Bluephish e ThePhish](docs/bluephish-vs-thephish.md).

## Documentação

| | |
|---|---|
| [Configuração](docs/configuracao.md) | Caixa de e-mail, IA, destinos, analisadores e a whitelist |
| [Dúvidas gerais](docs/duvidas-gerais.md) | Como trocar o certificado, a porta, atualizar, fazer backup e outras perguntas comuns |
| [Solução de problemas](docs/solucao-de-problemas.md) | O que fazer quando algo dá errado, sintoma por sintoma |
| [Integrações opcionais](docs/integracoes.md) | TheHive e MISP |
| [Segurança](docs/seguranca.md) | Exposição de rede, autenticação e o que sai da máquina |
| [Arquitetura](BLUEPHISH_ARCHITECTURE.md) | Modelo de dados, papéis, rotas e restrições conhecidas (em inglês) |
| [Diagramas](diagrams.md) | O pipeline, a cadeia do veredito e a stack, desenhados a partir do código (em inglês) |

> **Vai mudar o código com um agente de IA?** Leia o [`CLAUDE.md`](CLAUDE.md) antes:
> consultar o grafo de conhecimento em `graphify-out/` antes de editar é obrigatório aqui,
> porque vários acoplamentos falham em silêncio.

---

## Primeiros passos

Siga estes passos na ordem. Levam cerca de dez minutos, a maior parte na primeira construção
da imagem.

### 1. Instale os pré-requisitos

- **Docker** com o **plugin Compose**. Confira: `docker compose version` precisa mostrar uma
  versão.
- **Git**.
- A porta **8080** livre na sua máquina.
- **4 GB de RAM livres** e **2 GB de disco**. Em repouso a aplicação usa bem menos, mas a
  construção da imagem e o carregamento das primeiras telas pedem mais memória, e o tempo
  que isso dura depende da sua CPU.

> **No Windows, execute os próximos passos pelo Git Bash, e não pelo PowerShell nem pelo
> CMD.** O PowerShell não executa arquivos `.sh`: digitar `./setup.sh` lá apenas abre o
> script num editor. O Git Bash vem com o Git para Windows.

### 2. Baixe o projeto

```bash
git clone https://github.com/zalvs/Bluephish.git
```

### 3. Entre na pasta

```bash
cd Bluephish
```

### 4. Execute a instalação

```bash
./setup.sh
```

O script cria o `docker/.env` com uma chave de sessão recém-gerada, protege o arquivo de
configuração que vai guardar suas credenciais, constrói a imagem, sobe o Bluephish e espera
ele responder. A primeira execução leva alguns minutos. Pode ser executado de novo sem medo:
nada que já esteja configurado é sobrescrito. As mensagens dele saem em inglês; no fim você
deve ver `Setup complete - one manual step left`.

### 5. Crie o primeiro administrador

**Não existe conta padrão nem senha no código.** Crie a primeira:

```bash
cd docker
docker compose exec thephish python3 manage.py create-admin
```

O comando pede um nome de usuário e uma senha (no mínimo **12 caracteres**), digitada duas
vezes e nunca exibida na tela. (`thephish` é o nome do serviço no Docker e continua assim nos
comandos.)

### 6. Abra o Bluephish

Acesse **<https://localhost:8080>**.

O certificado é autoassinado, então o navegador avisa uma vez: escolha *Avançado* e depois
*Continuar para localhost* (no Firefox, *Aceitar o risco e continuar*). Use `https` e
`localhost`: o login não funciona por HTTP puro, e a porta não é alcançável de outras
máquinas, de propósito. Para usar um certificado seu, veja as
[Dúvidas gerais](docs/duvidas-gerais.md#como-troco-o-certificado-https).

### 7. Entre e configure o segundo fator

Deixe um aplicativo autenticador pronto no celular (Google Authenticator, Microsoft
Authenticator, Authy ou qualquer aplicativo TOTP). A autenticação em dois fatores é
obrigatória e não pode ser desligada.

1. Na tela **Entrar**, digite o usuário e a senha que você criou no passo 5.
2. Na primeira vez aparece **Verificação em duas etapas** com um QR code. Leia-o com o
   aplicativo.
3. Digite o código de 6 dígitos que o aplicativo mostrar e clique em **Confirmar e entrar**.

Você cai na **Visão Executiva**, que ainda estará vazia.

### 8. Conecte sua caixa de e-mail

1. No **menu lateral**, grupo **SISTEMA**, clique em **Configurações**.
2. Abra a aba **E-mail**.
3. Escolha **Microsoft 365** ou **Gmail / Workspace** e preencha as credenciais.
4. Clique em **Salvar**.

O que cada provedor pede está em [Configuração](docs/configuracao.md#1-caixa-de-e-mail).
Se o item **Configurações** não aparecer no menu, o seu usuário não é `admin` nem
`global_admin`: só esses papéis o enxergam.

### 9. Opcional: IA e destinos dos vereditos

- **Configurações → IA** liga a avaliação por modelo de linguagem.
- **ADMINISTRAÇÃO → Integrações → Tickets** escolhe onde os vereditos são registrados.

Os dois são opcionais e estão descritos na [Configuração](docs/configuracao.md). Numa
instalação nova, os vereditos já são gravados em disco.

### 10. Faça a primeira análise

1. No grupo **PRINCIPAL**, abra **Caixa de e-mail** e clique em **Listar e-mails**.
2. Clique num e-mail para abri-lo (isso não o analisa).
3. Clique em **Analisar este e-mail** e acompanhe o log ao vivo.
4. Quando o veredito aparecer, o resultado fica em **E-mails analisados**.

### Algo deu errado?

- A [Solução de problemas](docs/solucao-de-problemas.md) lista os problemas comuns, sintoma
  por sintoma: o script abrir um editor, o navegador não alcançar a página, uma conta
  bloqueada, um celular perdido.
- As [Dúvidas gerais](docs/duvidas-gerais.md) respondem como fazer coisas: trocar o
  certificado, mudar a porta, atualizar, fazer backup.

---

## Uso no dia a dia

O menu lateral tem três grupos: **PRINCIPAL** (as telas de trabalho), **ADMINISTRAÇÃO**
(Usuários, Integrações, Auditoria) e **SISTEMA** (Configurações, Minha conta).

1. **Caixa de e-mail → Listar e-mails.** É somente leitura e nunca inicia uma análise. A caixa
   também é relida por um temporizador, então a fila se mantém atualizada.
2. Encontre o que você quer. A caixa de busca filtra a fila que o navegador já tem:
   remetente, assunto, UID, tipo e, para as denúncias cujo corpo já foi baixado, o conteúdo.
   Os termos se combinam, então `boleto itau` acha a denúncia cujo assunto diz um e cujo
   remetente é o outro.
3. Clique num e-mail para lê-lo. **Abrir não é analisar**: a mensagem continua não lida e na
   fila de todos. A prévia tem duas abas:
   - **Texto**, o texto extraído da mensagem. É o mais rápido de ler e não tem como se
     disfarçar.
   - **Como entregue**, a mensagem montada como o destinatário a viu, dentro de uma sandbox
     que não executa scripts nem segue links. Cada link mostra seu destino real ao lado do
     texto, e um link cujo texto cita um domínio mas aponta para outro é marcado. Os anexos
     são listados com tamanho, tipo real e SHA-256; o arquivo em si nunca sai do contêiner.
     Leia a nota sobre requisições de saída em [Segurança](docs/seguranca.md) antes de usar
     esta visão numa rede isolada.
4. Para analisar um e-mail, clique em **Analisar este e-mail**. Para vários, marque-os na
   lista e clique em **Rodar scan**.
5. Acompanhe o log ao vivo; o veredito aparece no final. O resultado vai para todo destino
   habilitado, e um destino fora do ar nunca desfaz o veredito. Os e-mails Suspicious esperam
   em **Filas de Trabalho** por um analista.
6. Depois da análise:
   - **E-mails analisados** guarda o histórico, com filtros por veredito e período, e
     permite reanalisar, reclassificar, bloquear indicadores e adicionar à whitelist.
   - **Visão Tática** mostra o phishing confirmado e a metodologia do score.
   - **Visão Executiva** resume os indicadores do período.
   - **Chat AI** (no grupo PRINCIPAL) permite questionar um caso já analisado: informe o
     número do caso, clique em **Carregar** e faça perguntas.

### Papéis

| Papel | O que enxerga e pode fazer |
|---|---|
| `analyst` | Telas do grupo PRINCIPAL: listar e analisar e-mails, reanalisar um original guardado, decidir uma reclassificação, usar o Chat AI, ler a whitelist. Em **Minha conta**, troca a própria senha |
| `admin` | Tudo isso **mais** Configurações, Integrações e Auditoria (exceto SSO corporativo e onde a trilha de auditoria é guardada), edições da whitelist e desfazer uma reclassificação |
| `global_admin` | Tudo isso **mais** Usuários, reinício de senha e de segundo fator, SSO corporativo, o local da trilha de auditoria e regras permanentes da whitelist |

## Comandos comuns

Rode a partir do diretório `docker/`.

```bash
# Usuários
docker compose exec thephish python3 manage.py create-admin        # primeiro global_admin
docker compose exec thephish python3 manage.py create-user         # usuário adicional, qualquer papel
docker compose exec thephish python3 manage.py list-users
docker compose exec thephish python3 manage.py reset-password NOME
docker compose exec thephish python3 manage.py reset-mfa NOME      # celular perdido ou trocado
docker compose exec thephish python3 manage.py unlock NOME         # limpar o bloqueio de uma conta

# Em execução
docker compose up -d --build thephish   # reconstrói depois de uma mudança no código
docker compose logs -f thephish
docker compose restart thephish
docker compose down                     # para (os dados em vol/ são mantidos)
```

## Onde ficam as coisas

| Caminho | Conteúdo |
|---|---|
| `app/` | A aplicação, embutida na imagem na hora do build |
| `docs/` | Documentação em português; a versão em inglês fica em `docs/en/` |
| `docker/docker-compose.yml` | O Bluephish, ligado a `127.0.0.1` |
| `docker/docker-compose.integrations.yml` | Os extras opcionais ([integrações](docs/integracoes.md)) |
| `docker/.env` | **Segredos**: ignorado pelo git, criado pelo `setup.sh` |
| `docker/thephish_conf_files/` | Configuração viva, escrita pela aplicação |
| `docker/vol/` | **Dados persistentes: faça backup.** Banco de dados, log de auditoria, mensagens guardadas, chaves TLS |

> **Rode sempre o `docker compose` a partir do diretório `docker/` deste repositório.** Todo
> volume é relativo ao arquivo do compose, então rodá-lo a partir de uma cópia da árvore liga o
> contêiner, em silêncio, a um `vol/` diferente e vazio. Veja a
> [Solução de problemas](docs/solucao-de-problemas.md).

## Licença

GNU AGPL-3.0, veja o [LICENSE](LICENSE). Inspirado no
[emalderson/ThePhish](https://github.com/emalderson/ThePhish), que também é AGPL-3.0.
