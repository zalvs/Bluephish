# Bluephish — automated phishing email analysis

[Português (Brasil)](README.pt-BR.md) · **English**

Automated phishing-email analysis for a SOC/CSIRT. Bluephish reads a monitored mailbox,
extracts the observables from each suspicious email (URLs, domains, IPs, addresses,
attachment hashes), runs them through its reputation analyzers, asks an **LLM** for a
social-engineering assessment, and produces a verdict (`Safe`, `Suspicious` or `Malicious`)
that it can record wherever you choose: Jira, a folder on disk, any REST API through a
generic connector, or TheHive.

- Runs **manually** (an analyst picks an email) or **fully automatically** (a scheduler).
- Reads **Gmail** and **Microsoft 365** mailboxes.
- Checks the sender's **SPF/DKIM/DMARC** and reads embedded images with a vision model.
- Role-based access, mandatory **two-factor authentication**, SSO and an audit log.
- One container. Everything else is optional.

Bluephish was born inspired by [ThePhish](https://github.com/emalderson/ThePhish) and is now
an independent project. If you know the original and want to see how the two differ, read
[Bluephish and ThePhish](docs/bluephish-vs-thephish.md).

## Documentation

| | |
|---|---|
| [Configuration](docs/configuration.md) | Mailbox, AI, destinations, analyzers and the whitelist |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and how to fix them |
| [Optional integrations](docs/integrations.md) | TheHive, MISP and the AI companion agent |
| [Security notes](docs/security.md) | Network exposure, authentication and what leaves the machine |
| [Architecture](THEPHISH_ARCHITECTURE.md) | Data model, roles, routes and known constraints |
| [Diagrams](diagrams.md) | The pipeline, the verdict chain and the stack, drawn from the code |

> **Changing the code with an AI agent?** Read [`CLAUDE.md`](CLAUDE.md) first: consulting
> the knowledge graph in `graphify-out/` before editing is mandatory here, because several
> couplings fail silently.

---

## Getting started

Follow these steps in order. They take about ten minutes, most of it the first build.

### 1. Install the prerequisites

- **Docker** with the **Compose plugin**. Check it: `docker compose version` must print a
  version.
- **Git**.
- Port **8080** free on your machine.

Bluephish alone is light: the image is about 400 MB and the application idles under 100 MB
of RAM. Have about **1 GB of free RAM** and **2 GB of disk**.

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

It creates `docker/.env` with a freshly generated session key, protects the configuration
file that will hold your credentials, builds the image, starts Bluephish and waits for it to
answer. The first run takes a few minutes. It is safe to run again: nothing already
configured is overwritten.

### 5. Create the first administrator

There is **no default account and no password in the code**. Create the first one:

```bash
cd docker
docker compose exec thephish python3 manage.py create-admin
```

You are asked for a username and a password (at least **12 characters**), typed twice and
never shown on screen.

### 6. Open Bluephish

Go to **<https://localhost:8080>**.

The certificate is self-signed, so the browser warns once: choose *Advanced → Proceed*.
Use `https` and `localhost`: the login does not work over plain HTTP, and the port is not
reachable from other machines on purpose.

### 7. Sign in and set up the second factor

Have an authenticator app ready (Google Authenticator, Microsoft Authenticator, Authy or any
TOTP app). Two-factor authentication is mandatory and cannot be turned off: on the first
sign-in a QR code appears, you scan it, and the panel opens once the app's six-digit code is
accepted.

### 8. Connect your mailbox

Open **Configurações** (the gear icon) → **E-mail**, choose Gmail or Microsoft 365 and fill
in the credentials. See [Configuration](docs/configuration.md#1-mailbox) for exactly what
each provider needs.

### 9. Optional: the AI assessment and where verdicts are recorded

Set up the language model under **Configurações → IA**, and the destinations under
**Configurações → Integrações → Tickets**. Both are optional and described in
[Configuration](docs/configuration.md).

### Something went wrong?

Check [Troubleshooting](docs/troubleshooting.md): it lists the common problems, such as the
script opening an editor, the browser not reaching the page, a locked account or a lost
phone, and how to fix each one.

---

## Everyday use

1. **Listar e-mails** (List emails) on the dashboard. It is read-only and never starts an
   analysis. The mailbox is also reread on a timer, so the queue stays current.
2. Find the one you want. The search box filters the queue the browser already holds: sender,
   subject, UID, type and, for reports whose body has been downloaded, the content. Terms
   combine, so `boleto itau` finds the report whose subject says one and whose sender is the
   other.
3. Open a report to read it. **Opening is not analyzing**: the message stays unread and in
   everybody's queue. The preview has two tabs:
   - **Texto**, the text pulled out of the message. The fastest to read, and it cannot dress
     itself up.
   - **Como entregue**, the message laid out as its recipient saw it, inside a sandbox that
     cannot run scripts or follow links. Every link prints its real destination next to its
     text, and a link whose text names one domain while pointing at another is marked.
     Attachments are listed with their size, real type and SHA-256; the file itself never
     leaves the container. Read the note on outbound requests in
     [Security notes](docs/security.md) before using this view on an isolated network.
4. Tick the emails you want and run the analysis (or use the *Analisar* button on a row).
5. Follow the live log; the verdict appears at the end. The result goes to every enabled
   destination, and a destination that is down never undoes the verdict. Suspicious emails
   wait in **Filas de Trabalho** for an analyst.
6. Use the **Chat AI** (robot icon) to question an analyzed case.

### Roles

| Role | Can do |
|---|---|
| `analyst` | List emails, analyze, reanalyze a kept original, decide a reclassification, use the AI chat, read the whitelist, change own password |
| `admin` | Everything above **plus** the settings (except corporate SSO and where the audit trail is stored), whitelist edits, reading the audit trail, undoing a reclassification |
| `global_admin` | Everything above **plus** user management, password and second-factor resets, corporate SSO, where the audit trail is stored, and permanent whitelist rules |

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
| `docs/` | Configuration, troubleshooting, integrations and per-feature references |
| `docker/docker-compose.yml` | Bluephish, bound to `127.0.0.1` |
| `docker/docker-compose.integrations.yml` | The optional extras ([integrations](docs/integrations.md)) |
| `docker/.env` | **Secrets**: gitignored, created by `setup.sh` |
| `docker/thephish_conf_files/` | Live configuration, written by the application |
| `docker/vol/` | **Persistent data: back this up.** Database, audit log, stored messages, TLS keys |

> **Always run `docker compose` from this repository's own `docker/` directory.** Every volume
> is relative to the compose file, so running it from a copy of the tree silently attaches the
> container to a different, empty `vol/`. See [Troubleshooting](docs/troubleshooting.md).

## License

GNU AGPL-3.0, see [LICENSE](LICENSE). Inspired by
[emalderson/ThePhish](https://github.com/emalderson/ThePhish), which is also AGPL-3.0.
