# Bluephish — análise automatizada de e-mails de phishing

**Português (Brasil)** · [English](README.md)

Análise automatizada de e-mails de phishing para um SOC/CSIRT. O Bluephish lê uma caixa de
correio monitorada, extrai os observáveis de cada e-mail suspeito (URLs, domínios, IPs,
endereços, hashes de anexos), passa todos por analisadores de reputação, pede a um **LLM**
uma avaliação de engenharia social e produz um veredito (`Safe`, `Suspicious` ou
`Malicious`) que ele pode registrar onde você escolher: Jira, uma pasta em disco, qualquer
API REST por um conector genérico, ou o TheHive.

- Roda de forma **manual** (um analista escolhe o e-mail) ou **100% automática** (um agendador).
- Lê caixas do **Gmail** e do **Microsoft 365**.
- Verifica **SPF/DKIM/DMARC** do remetente e lê imagens embutidas com um modelo de visão.
- Controle de acesso por papéis, **autenticação em dois fatores** obrigatória, SSO e trilha de auditoria.
- Um contêiner. Todo o resto é opcional.

O Bluephish nasceu inspirado no [ThePhish](https://github.com/emalderson/ThePhish) e hoje é
um projeto independente. Se você conhece o original e quer ver como os dois se diferenciam,
leia [Bluephish e ThePhish](docs/bluephish-vs-thephish.pt-BR.md).

## Documentação

| | |
|---|---|
| [Configuração](docs/configuration.pt-BR.md) | Caixa de e-mail, IA, destinos, analisadores e a whitelist |
| [Solução de problemas](docs/troubleshooting.pt-BR.md) | Problemas comuns e como resolvê-los |
| [Integrações opcionais](docs/integrations.pt-BR.md) | TheHive, MISP e o agente de IA |
| [Notas de segurança](docs/security.pt-BR.md) | Exposição de rede, autenticação e o que sai da máquina |
| [Arquitetura](THEPHISH_ARCHITECTURE.md) | Modelo de dados, papéis, rotas e restrições conhecidas (em inglês) |
| [Diagramas](diagrams.md) | O pipeline, a cadeia do veredito e a stack, desenhados a partir do código |

> **Vai mudar o código com um agente de IA?** Leia o [`CLAUDE.md`](CLAUDE.md) antes:
> consultar o grafo de conhecimento em `graphify-out/` antes de editar é obrigatório aqui,
> porque vários acoplamentos falham em silêncio.

---

## Primeiros passos

Siga estes passos na ordem. Levam cerca de dez minutos, a maior parte na primeira construção.

### 1. Instale os pré-requisitos

- **Docker** com o **plugin Compose**. Confira: `docker compose version` precisa mostrar uma
  versão.
- **Git**.
- A porta **8080** livre na sua máquina.

O Bluephish sozinho é leve: a imagem tem cerca de 400 MB e a aplicação usa menos de 100 MB de
RAM em repouso. Tenha cerca de **1 GB de RAM livre** e **2 GB de disco**.

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

Ele cria o `docker/.env` com uma chave de sessão recém-gerada, protege o arquivo de
configuração que vai guardar suas credenciais, constrói a imagem, sobe o Bluephish e espera
ele responder. A primeira execução leva alguns minutos. Pode ser executado de novo sem medo:
nada que já esteja configurado é sobrescrito.

### 5. Crie o primeiro administrador

**Não existe conta padrão nem senha no código.** Crie a primeira:

```bash
cd docker
docker compose exec thephish python3 manage.py create-admin
```

O comando pede um nome de usuário e uma senha (no mínimo **12 caracteres**), digitada duas
vezes e nunca exibida na tela.

### 6. Abra o Bluephish

Acesse **<https://localhost:8080>**.

O certificado é autoassinado, então o navegador avisa uma vez: escolha *Avançado →
Continuar*. Use `https` e `localhost`: o login não funciona por HTTP puro, e a porta não é
alcançável de outras máquinas, de propósito.

### 7. Entre e configure o segundo fator

Deixe um aplicativo autenticador pronto (Google Authenticator, Microsoft Authenticator, Authy
ou qualquer aplicativo TOTP). A autenticação em dois fatores é obrigatória e não pode ser
desligada: no primeiro acesso aparece um QR code, você o lê, e o painel abre quando o código
de seis dígitos do aplicativo é aceito.

### 8. Conecte sua caixa de e-mail

Abra **Configurações** (o ícone de engrenagem) → **E-mail**, escolha Gmail ou Microsoft 365
e preencha as credenciais. Veja na [Configuração](docs/configuration.pt-BR.md#1-caixa-de-e-mail)
exatamente o que cada provedor pede.

### 9. Opcional: a avaliação por IA e onde os vereditos são registrados

Configure o modelo de linguagem em **Configurações → IA**, e os destinos em
**Configurações → Integrações → Tickets**. Os dois são opcionais e estão descritos na
[Configuração](docs/configuration.pt-BR.md).

### Algo deu errado?

Veja a [Solução de problemas](docs/troubleshooting.pt-BR.md): ela lista os problemas comuns,
como o script abrir um editor, o navegador não alcançar a página, uma conta bloqueada ou um
celular perdido, e como resolver cada um.

---

## Uso no dia a dia

1. **Listar e-mails** no painel. É somente leitura e nunca inicia uma análise. A caixa
   também é relida por um temporizador, então a fila se mantém atualizada.
2. Encontre o que você quer. A caixa de busca filtra a fila que o navegador já tem:
   remetente, assunto, UID, tipo e, para as denúncias cujo corpo já foi baixado, o conteúdo.
   Os termos se combinam, então `boleto itau` acha a denúncia cujo assunto diz um e cujo
   remetente é o outro.
3. Abra uma denúncia para lê-la. **Abrir não é analisar**: a mensagem continua não lida e na
   fila de todos. A prévia tem duas abas:
   - **Texto**, o texto extraído da mensagem. É o mais rápido de ler e não tem como se
     disfarçar.
   - **Como entregue**, a mensagem montada como o destinatário a viu, dentro de uma sandbox
     que não executa scripts nem segue links. Cada link mostra seu destino real ao lado do
     texto, e um link cujo texto cita um domínio mas aponta para outro é marcado. Os anexos
     são listados com tamanho, tipo real e SHA-256; o arquivo em si nunca sai do contêiner.
     Leia a nota sobre requisições de saída nas [Notas de segurança](docs/security.pt-BR.md)
     antes de usar esta visão numa rede isolada.
4. Marque os e-mails que quer e rode a análise (ou use o botão *Analisar* de uma linha).
5. Acompanhe o log ao vivo; o veredito aparece no final. O resultado vai para todo destino
   habilitado, e um destino fora do ar nunca desfaz o veredito. Os e-mails Suspicious esperam
   em **Filas de Trabalho** por um analista.
6. Use o **Chat AI** (ícone de robô) para questionar um caso analisado.

### Papéis

| Papel | Pode |
|---|---|
| `analyst` | Listar e-mails, analisar, reanalisar um original guardado, decidir uma reclassificação, usar o chat de IA, ler a whitelist, trocar a própria senha |
| `admin` | Tudo isso **mais** as configurações (exceto o SSO corporativo e onde a trilha de auditoria é guardada), edições da whitelist, leitura da trilha de auditoria, desfazer uma reclassificação |
| `global_admin` | Tudo isso **mais** a gestão de usuários, reinício de senha e de segundo fator, o SSO corporativo, onde a trilha de auditoria é guardada e regras permanentes da whitelist |

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
| `docs/` | Configuração, solução de problemas, integrações e referências por funcionalidade |
| `docker/docker-compose.yml` | O Bluephish, ligado a `127.0.0.1` |
| `docker/docker-compose.integrations.yml` | Os extras opcionais ([integrações](docs/integrations.pt-BR.md)) |
| `docker/.env` | **Segredos**: ignorado pelo git, criado pelo `setup.sh` |
| `docker/thephish_conf_files/` | Configuração viva, escrita pela aplicação |
| `docker/vol/` | **Dados persistentes: faça backup.** Banco de dados, log de auditoria, mensagens guardadas, chaves TLS |

> **Rode sempre o `docker compose` a partir do diretório `docker/` deste repositório.** Todo
> volume é relativo ao arquivo do compose, então rodá-lo a partir de uma cópia da árvore liga o
> contêiner, em silêncio, a um `vol/` diferente e vazio. Veja a
> [Solução de problemas](docs/troubleshooting.pt-BR.md).

## Licença

GNU AGPL-3.0, veja o [LICENSE](LICENSE). Inspirado no
[emalderson/ThePhish](https://github.com/emalderson/ThePhish), que também é AGPL-3.0.
