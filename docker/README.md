## The Docker stack

**The installation guide is the [root README](../README.md).** This file only covers what is
specific to the containers.

### What runs

`docker compose up -d` starts a single container:

| Service | Port (localhost) | Image | Needed for |
|---|---|---|---|
| **thephish** | **8080 (HTTPS)** | built from `../app` | the application itself |

TheHive, MISP and the AI companion agent are optional and live in
`docker-compose.integrations.yml`; see [integrations](../docs/integrations.md) to run them.

Every port is published on `127.0.0.1` only. The analyzers run inside the Bluephish container
(`app/analyzers.py`), configured from the **Integrações → Analisadores** screen, and the
verdict emails go out over SMTP from `app/mailer.py`.

### Where the app calls out to

The Bluephish container makes outbound connections you should know about before putting it
behind a restrictive egress policy: the mailbox (IMAP or Microsoft Graph), the LLM endpoint,
every enabled analyzer vendor (and each analyst-defined analyzer), the SMTP relay, each
enabled ticket destination, Entra ID (`login.microsoftonline.com`: SSO sign-in and the app
tokens for Graph, EOP and MDTI), the blocking destinations (EOP at `outlook.office365.com`,
the firewalls), the syslog server that receives the audit copy, every generic connector and
volume-alert webhook, and — by design — hosts named inside reported emails: each hop of a
shortened link and, when an email is rendered, its remote images.

The services are switched on and given credentials in the interface. The Microsoft and vendor
endpoints are fixed in the code (`imap.gmail.com` for the Gmail provider,
`graph.microsoft.com`, `login.microsoftonline.com`, `outlook.office365.com`, the analyzer
APIs); the LLM, SMTP, TheHive, Jira, firewall, syslog, connector and analyst-defined analyzer
addresses are the ones you type.

Two traps, both the same trap:

- A service started from the **integrations file** is reached by Docker service name, not
  `localhost`: `http://thehive:9000`, never `http://localhost:9000`. Inside the container,
  `localhost` is the container.
- A destination **on the host machine** (a self-hosted Jira, an internal Splunk) is reached at
  `host.docker.internal`, which `docker-compose.integrations.yml` maps for `hive-ai-agent` via
  `extra_hosts`. Add `extra_hosts: ["host.docker.internal:host-gateway"]` to the `thephish`
  service in `docker-compose.yml` if you need it there.

> This is also why a connector (**Integrações → Tickets**, below the built-in destinations —
> [architecture](../docs/conectores-genericos.md) ·
> [manual](../docs/conectores-manual.md)) refuses a private-network destination unless you
> tick *allow internal network*: from inside a container, "the internal network" includes the
> whole compose network and the host. The destination is re-checked on every dispatch, not
> only when you save it.

### Testar a metodologia de score no container

O código da aplicação é copiado para dentro da imagem (`COPY . /root/thephish/`
no `app/Dockerfile`), então **depois de um `git pull` é preciso reconstruir** —
um `restart` sobe a imagem antiga:

```bash
docker compose build thephish && docker compose up -d thephish
```

Nada além disso é necessário. `scoring.py` e `spam_headers.py` usam só a
biblioteca padrão, então o Dockerfile não ganhou nenhum `pip3 install` (§7.2 da
arquitetura: dependência nova ali é o que quebra esta imagem).

A seção `scoring` do `configuration.json` também não precisa ser criada à mão. A
configuração é mesclada sobre os padrões, então uma instalação que nunca a
tocou já roda com phishing ≥ 50, suspeito/spam ≥ 40 e legítimo ≥ 20; a seção é
gravada na primeira vez que alguém salvar em **Integrações → Priorização**. Isso
importa porque esse arquivo é `skip-worktree` e carrega as chaves reais (§7.8):
ele não é atualizado pelo `git pull`, e não precisa ser.

**Ver os pesos que estão valendo:**

```bash
docker compose exec thephish python3 manage.py weights
```

**Pontuar um `.eml` sem rede, sem cota de fornecedor e sem destino de registro:**

```bash
docker compose exec thephish python3 manage.py score samples/newsletter.eml \
    --analyzer virustotal=safe
```

Os cabeçalhos são lidos do arquivo de verdade — autenticação e gramática de
lista; o nível de cada analisador entra como argumento, o que permite calibrar
peso sem gastar uma análise real por tentativa. A saída traz a memória de
cálculo inteira: peso, fator e contribuição de cada linha, e por que quem não
participou não participou. `--json` para consumir em script.

Três amostras acompanham a imagem em `samples/` (`samples/README.md` explica o
que cada uma demonstra). O par que vale rodar junto:

```bash
docker compose exec thephish python3 manage.py score samples/newsletter.eml --analyzer virustotal=safe
docker compose exec thephish python3 manage.py score samples/phishing.eml   --analyzer virustotal=safe
```

As duas trazem `List-Unsubscribe`. A primeira sai como `spam` e some da fila; a
segunda não, porque o domínio dela não passou no DMARC — e é o servidor de
entrada que escreve isso, não quem mandou a mensagem.

**Um `.eml` seu:**

```bash
docker compose cp suspeito.eml thephish:/tmp/suspeito.eml
docker compose exec thephish python3 manage.py score /tmp/suspeito.eml \
    --analyzer virustotal=malicious --llm High
```

**A suíte de testes, dentro da imagem que vai rodar:**

```bash
docker compose exec --workdir /root/thephish thephish python3 -m unittest discover -p "test_*.py"
```

Não toca a rede e não escreve na árvore. É a mesma suíte que o CI roda, aqui
contra o Python 3.8 e as versões que a imagem de fato carrega — que é o que
`app/requirements.txt` documenta e o que o CI não consegue provar sozinho.

**Na interface**, depois de reconstruir: *Integrações → Priorização* traz o
ranking de fatores com o peso editável na linha, e *Phishing confirmado* traz a
faixa tática. Os painéis que dependem das tags novas (`score:`, `tier:`,
`auth:`) só enchem com análises feitas a partir desta versão — casos antigos
aparecem como "não pontuado", nunca como zero.

### Notes

**Linux file ownership (only with the integrations).** The containers write into `vol/`, and on
Linux the directories are created as root while TheHive runs as uid 1000. If the logs fill with
permission errors once the files exist:

```bash
docker compose stop
sudo chown -R 1000:1000 vol/index vol/data
docker compose up -d
```

**Firefox and the live analysis log.** On some Linux setups Firefox closes the AJAX connection
before the response arrives and garbles the WebSocket frames, which surfaces as an error
mid-analysis. Another browser is the simpler fix; to stay on Firefox, in `about:config` raise
`network.http.network-changed.timeout` from 5 to 60 and set
`network.websocket.extensions.permessage-deflate` to `false`.

> **⚠️ This stack is a minimal configuration, not a production deployment.** The certificate is
> self-signed, and the optional services in the integrations file run with development
> credentials. For production, put Bluephish behind a reverse proxy with TLS and install any
> integration from its maintainers' own guides.
