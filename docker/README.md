## The Docker stack

**The installation guide is the [root README](../README.md).** Clone, run `./setup.sh`, create
the first administrator, configure through the web interface. This file only covers what is
specific to the containers: what runs, and the two services that have their own admin UI to
set up (MISP and TheHive).

> This file used to be a second, full installation guide inherited from upstream. It
> contradicted the root README on almost every step — it cloned the upstream repository, told
> you to edit `configuration.json` by hand, and sent you to `http://localhost:8080` when the
> interface is HTTPS-only. Two guides that disagree is what makes a repository hard to
> install, so the flow now lives in one place.

### What runs

| Service | Port (localhost) | Image | Needed for |
|---|---|---|---|
| **thephish** | **8080 (HTTPS)** | built from `../app` | the application itself |
| thehive | 9000 | `thehiveproject/thehive4:4.1.9-1` | case management, and one of the sources of the Cases/Phishing/Executive screens — **optional, see below** |
| cassandra | (internal) | `cassandra:3.11` | TheHive's database |
| misp | 80 / 443 | `coolacid/misp-docker:core-v2.4.148a` | exporting malicious cases — **optional** |
| mysql · redis | (internal) | `mysql:8.0.26` · `redis:6.2.5` | MISP's backing stores |
| hive-ai-agent | 8008 | built from `../hive_ai_agent` | optional IOC correlation on webhooks |

Every port is published on `127.0.0.1` only. There is **no Cortex and no Elasticsearch**: the
analyzers run inside the ThePhish container (`app/analyzers.py`), configured from its own
**Integrações → Analisadores** screen, and the verdict emails go out over SMTP from
`app/mailer.py`. Both used to be Cortex's job.

MISP is the one service you can drop entirely. Its ports 80/443 collide with any local web
server, and nothing in the analysis pipeline needs it — only the export of a `Malicious` case.
To do without it, comment out the `misp`, `mysql` and `redis` services **and** remove `misp`
from the `depends_on` list of `thephish` — compose refuses a dependency on a service that no
longer exists.

**TheHive can also be dropped**, with a cost the table cannot express. The analysis does not
go through it any more: observables live in the ThePhish container's memory from parsing to
verdict, and TheHive receives the finished report like Jira and disk do. The **Cases**,
**Phishing** and **Executive** screens read their history from the enabled destinations, so
removing TheHive only empties them if neither disk nor Jira is recording — and Jira records
answer less (no observable counts) than TheHive or disk do. Comment out `thehive`,
`cassandra` and `hive-ai-agent` (it only works on TheHive webhooks), and remove `thehive`
from the `depends_on` of `thephish`, only if Jira or disk is your record of truth — that also
frees about 3 GB of RAM, which is most of the stack's requirement.

### Where the app calls out to

The ThePhish container makes outbound connections you should know about before putting it
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

- A destination **inside this stack** is reached by Docker service name, not `localhost` —
  `http://thehive:9000`, never `http://localhost:9000`. Inside the container, `localhost` is
  the container.
- A destination **on the host machine** (a self-hosted Jira, an internal Splunk) is reached at
  `host.docker.internal`, which `docker-compose.yml` already maps for `hive-ai-agent` via
  `extra_hosts`. Add the same `extra_hosts` entry to the `thephish` service if you need it
  there.

> This is also why a connector (**Integrações → Tickets**, below the built-in destinations —
> [architecture](../docs/conectores-genericos.md) ·
> [manual](../docs/conectores-manual.md)) refuses a private-network destination unless you
> tick *allow internal network*: from inside a container, "the internal network" includes the
> whole compose network and the host. The destination is re-checked on every dispatch, not
> only when you save it.

### Setting up TheHive

TheHive does **not** prompt you to create an account: it ships with a published default.

1. Go to `http://localhost:9000` and log in with `admin@thehive.local` / `secret`.
2. **Change that password now.** It is a documented default, and port 9000 is open on the host.
3. *Organisations* → **New organisation**, any name.
4. Inside it, **Create new user** with profile `org-admin`, set a password, then
   **Create API key** → **Reveal**.
5. Paste `http://thehive:9000` and that key into the **TheHive** card on ThePhish's **Integrações → Tickets** tab.
   The URL is the Docker service name, not `localhost` — inside the container, `localhost` is
   the container.

### Configure the MISP container (optional)

Skip this whole section unless you want malicious cases exported to MISP.

1. Go to `https://localhost` and log in with the default credentials `admin@admin.test` /
   `admin`. **Change the password immediately**, same reasoning as above.
2. *Administration* → *Add Organization*: give it a name, **Generate UUID**, submit.
3. *Administration* → *Add User*: email `sync_user@<yourdomain>`, your organization, role
   **Sync User**. Open the user, **Add authentication key**, and save the key.
4. Optionally enable feeds: *Sync Actions* → *List Feeds* → *Load default feed metadata* →
   select → *Enable selected*.

Then wire TheHive to it — **this is what is missing by default**, and without it every
malicious case records *"a exportação para o MISP falhou"* in the TheHive destination's outcome. Uncomment the MISP block
in `thehive/application.conf` and put the authentication key in it:

```
play.modules.enabled += org.thp.thehive.connector.misp.MispModule
misp {
  interval: 5 min
  servers: [
    {
      name = "MISP THP"                       # must match the MISP export name on the TheHive card (Integrações → Tickets)
      url = "https://misp/"
      auth {
        type = key
        key = "<AuthenticationKeyOfTheSyncUser>"
      }
      wsConfig { ssl { loose { acceptAnyCertificate: true } } }
    }
  ]
}
```

TheHive reads that file only at startup, so restart it:

```bash
docker compose restart thehive
```

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

**Pontuar um `.eml` sem rede, sem cota de fornecedor e sem TheHive:**

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

**Linux file ownership.** The containers write into `vol/`, and on Linux the directories are
created as root while TheHive runs as uid 1000. If the logs fill with permission errors once
the files exist:

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

> **⚠️ This stack is a minimal configuration, not a production deployment.** The backing
> stores run with development credentials and the certificates are self-signed. For production,
> follow the official installation guides of TheHive and MISP.
