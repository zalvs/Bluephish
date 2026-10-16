# Bluephish — automated phishing email analysis

[Português (Brasil)](README.md) · **English**

Automated phishing-email analysis for a SOC/CSIRT. Bluephish reads a monitored mailbox,
extracts the observables from each suspicious email (URLs, domains, IPs, addresses,
attachment hashes), runs them through its reputation analyzers, asks an **LLM** for a
social-engineering assessment, and produces a verdict (`Safe`, `Suspicious` or `Malicious`)
that it can record wherever you choose: a folder on disk, Jira, any REST API through a
generic connector, or TheHive.

- Runs **manually** (an analyst picks an email) or **fully automatically** (a scheduler).
- Reads **Gmail** and **Microsoft 365** mailboxes.
- Checks the sender's **SPF/DKIM/DMARC** and reads embedded images with a vision model.
- Role-based access, mandatory **two-factor authentication**, SSO and an audit log.
- One container. Everything else is optional.

Bluephish was born inspired by [ThePhish](https://github.com/emalderson/ThePhish) and is now
an independent project. If you know the original and want to see how the two differ, read
[Bluephish and ThePhish](docs/en/bluephish-vs-thephish.md).

> The interface is in Portuguese, so screen and button names below are written as they
> appear on screen.

## Documentation

| | |
|---|---|
| [Configuration](docs/en/configuration.md) | Mailbox, AI, destinations, analyzers and the whitelist |
| [FAQ](docs/en/faq.md) | How to change the certificate, the port, update, back up and other common questions |
| [Troubleshooting](docs/en/troubleshooting.md) | What to do when something goes wrong, symptom by symptom |
| [Optional integrations](docs/en/integrations.md) | TheHive and MISP |
| [Security notes](docs/en/security.md) | Network exposure, authentication and what leaves the machine |
| [Architecture](BLUEPHISH_ARCHITECTURE.md) | Data model, roles, routes and known constraints |
| [Diagrams](diagrams.md) | The pipeline, the verdict chain and the stack, drawn from the code |

> **Changing the code with an AI agent?** Read [`CLAUDE.md`](CLAUDE.md) first: consulting
> the knowledge graph in `graphify-out/` before editing is mandatory here, because several
> couplings fail silently.

---

## Getting started

Follow these steps in order. They take about ten minutes, most of it the first image build.

### 1. Install the prerequisites

- **Docker** with the **Compose plugin**. Check it: `docker compose version` must print a
  version.
- **Git**.
- Port **8080** free on your machine.
- **4 GB of free RAM** and **2 GB of disk**. At rest the application uses far less, but
  building the image and loading the first screens need more memory, and how long that lasts
  depends on your CPU.

> **On Windows, run the next steps from Git Bash, not from PowerShell or CMD.** PowerShell
> does not run `.sh` files: typing `./setup.sh` there just opens the script in an editor.
> Git Bash comes with Git for Windows.

### 2. Download the project

```bash
git clone https://github.com/zalvs/Bluephish.git
```

### 3. Enter the folder

```bash
cd Bluephish
```

### 4. Run the setup

```bash
./setup.sh
```

The script creates `docker/.env` with a freshly generated session key, protects the
configuration file that will hold your credentials, builds the image, starts Bluephish and
waits for it to answer. The first run takes a few minutes. It is safe to run again: nothing
already configured is overwritten. Its messages are in English; at the end you should see
`Setup complete - one manual step left`.

### 5. Create the first administrator

There is **no default account and no password in the code**. Create the first one:

```bash
cd docker
docker compose exec thephish python3 manage.py create-admin
```

You are asked for a username and a password (at least **12 characters**), typed twice and
never shown on screen. (`thephish` is the Docker service name and stays that way in the
commands.)

### 6. Open Bluephish

Go to **<https://localhost:8080>**.

The certificate is self-signed, so the browser warns once: choose *Advanced*, then *Proceed to
localhost* (in Firefox, *Accept the Risk and Continue*). Use `https` and `localhost`: the login
does not work over plain HTTP, and the port is not reachable from other machines on purpose.
To use a certificate of your own, see the
[FAQ](docs/en/faq.md#how-do-i-change-the-https-certificate).

### 7. Sign in and set up the second factor

Have an authenticator app ready on your phone (Google Authenticator, Microsoft Authenticator,
Authy or any TOTP app). Two-factor authentication is mandatory and cannot be turned off.

1. On the **Entrar** (sign-in) screen, enter the username and password you created in step 5.
2. The first time, **Verificação em duas etapas** appears with a QR code. Scan it with the app.
3. Enter the 6-digit code the app shows and click **Confirmar e entrar**.

You land on **Visão Executiva**, which will still be empty.

### 8. Connect your mailbox

1. In the **side menu**, under the **SISTEMA** group, click **Configurações**.
2. Open the **E-mail** tab.
3. Choose **Microsoft 365** or **Gmail / Workspace** and fill in the credentials.
4. Click **Salvar**.

What each provider needs is in [Configuration](docs/en/configuration.md#1-mailbox). If
**Configurações** does not appear in the menu, your user is neither `admin` nor
`global_admin`: only those roles see it.

### 9. Optional: AI and where verdicts are recorded

- **Configurações → IA** turns on the language-model assessment.
- **ADMINISTRAÇÃO → Integrações → Tickets** chooses where verdicts are recorded.

Both are optional and described in [Configuration](docs/en/configuration.md). On a fresh
installation, verdicts are already written to disk.

### 10. Run the first analysis

1. In the **PRINCIPAL** group, open **Caixa de e-mail** and click **Listar e-mails**.
2. Click an email to open it (this does not analyze it).
3. Click **Analisar este e-mail** and follow the live log.
4. When the verdict appears, the result is kept under **E-mails analisados**.

### Something went wrong?

- [Troubleshooting](docs/en/troubleshooting.md) lists the common problems, symptom by
  symptom: the script opening an editor, the browser not reaching the page, a locked account,
  a lost phone.
- The [FAQ](docs/en/faq.md) answers how to do things: change the certificate, change the
  port, update, back up.

---

## Everyday use

The side menu has three groups: **PRINCIPAL** (the work screens), **ADMINISTRAÇÃO**
(Usuários, Integrações, Auditoria) and **SISTEMA** (Configurações, Minha conta).

1. **Caixa de e-mail → Listar e-mails.** It is read-only and never starts an analysis. The
   mailbox is also reread on a timer, so the queue stays current.
2. Find the one you want. The search box filters the queue the browser already holds: sender,
   subject, UID, type and, for reports whose body has been downloaded, the content. Terms
   combine, so `boleto itau` finds the report whose subject says one and whose sender is the
   other.
3. Click an email to read it. **Opening is not analyzing**: the message stays unread and in
   everybody's queue. The preview has two tabs:
   - **Texto**, the text pulled out of the message. The fastest to read, and it cannot dress
     itself up.
   - **Como entregue**, the message laid out as its recipient saw it, inside a sandbox that
     cannot run scripts or follow links. Every link prints its real destination next to its
     text, and a link whose text names one domain while pointing at another is marked.
     Attachments are listed with their size, real type and SHA-256; the file itself never
     leaves the container. Read the note on outbound requests in
     [Security notes](docs/en/security.md) before using this view on an isolated network.
4. To analyze one email, click **Analisar este e-mail**. For several, tick them in the list
   and click **Rodar scan**.
5. Follow the live log; the verdict appears at the end. The result goes to every enabled
   destination, and a destination that is down never undoes the verdict. Suspicious emails
   wait in **Filas de Trabalho** for an analyst.
6. After the analysis:
   - **E-mails analisados** keeps the history, with filters by verdict and period, and lets
     you reanalyze, reclassify, block indicators and add to the whitelist.
   - **Visão Tática** shows the confirmed phishing and the scoring methodology.
   - **Visão Executiva** summarizes the indicators of the period.
   - **Chat AI** (in the PRINCIPAL group) lets you question an analyzed case: enter the case
     number, click **Carregar** and ask.

### Roles

| Role | What it sees and can do |
|---|---|
| `analyst` | The PRINCIPAL group: list and analyze emails, reanalyze a kept original, decide a reclassification, use Chat AI, read the whitelist. Under **Minha conta**, changes their own password |
| `admin` | Everything above **plus** Configurações, Integrações and Auditoria (except corporate SSO and where the audit trail is stored), whitelist edits and undoing a reclassification |
| `global_admin` | Everything above **plus** Usuários, password and second-factor resets, corporate SSO, the audit trail location and permanent whitelist rules |

## Common commands

Run from the `docker/` directory.

```bash
# Users
docker compose exec thephish python3 manage.py create-admin        # first global_admin
docker compose exec thephish python3 manage.py create-user         # additional user, any role
docker compose exec thephish python3 manage.py list-users
docker compose exec thephish python3 manage.py reset-password NAME
docker compose exec thephish python3 manage.py reset-mfa NAME      # lost or replaced phone
docker compose exec thephish python3 manage.py unlock NAME         # clear an account lockout

# Running it
docker compose up -d --build thephish   # rebuild after a code change
docker compose logs -f thephish
docker compose restart thephish
docker compose down                     # stop it (data in vol/ is kept)
```

## Where things live

| Path | Contents |
|---|---|
| `app/` | The application, baked into the image at build time |
| `docs/` | Documentation in Portuguese; the English version is in `docs/en/` |
| `docker/docker-compose.yml` | Bluephish, bound to `127.0.0.1` |
| `docker/docker-compose.integrations.yml` | The optional extras ([integrations](docs/en/integrations.md)) |
| `docker/.env` | **Secrets**: gitignored, created by `setup.sh` |
| `docker/thephish_conf_files/` | Live configuration, written by the application |
| `docker/vol/` | **Persistent data: back this up.** Database, audit log, stored messages, TLS keys |

> **Always run `docker compose` from this repository's own `docker/` directory.** Every volume
> is relative to the compose file, so running it from a copy of the tree silently attaches the
> container to a different, empty `vol/`. See [Troubleshooting](docs/en/troubleshooting.md).

## License

GNU AGPL-3.0, see [LICENSE](LICENSE). Inspired by
[emalderson/ThePhish](https://github.com/emalderson/ThePhish), which is also AGPL-3.0.
