# Bluephish — automated phishing email analysis

[Português (Brasil)](README.md) · **English**

Automated phishing-email analysis for a SOC/CSIRT. Bluephish reads a monitored mailbox,
extracts the observables from each suspicious email (URLs, domains, IPs, addresses,
attachment hashes), runs them through its own reputation analyzers, asks an **LLM**
for a social-engineering assessment, and produces a verdict — `Safe`, `Suspicious` or
`Malicious` — recorded wherever you choose: local disk (the default), **Jira**, **TheHive**,
any REST API through a generic connector, or any combination of them.

It runs as four containers started by `setup.sh`: an nginx **vhost** (the only published
ports), an nginx **frontend**, the **API** and **PostgreSQL**, on separate Docker networks with
TLS between them. TheHive and MISP are optional integrations installed apart from it
([`docs/integracoes/thehive.md`](docs/integracoes/thehive.md)), not part of the stack.

> **Upgrading from 1.x?** Read the [CHANGELOG](CHANGELOG.md) first: 2.0 moves to Python 3.14,
> PostgreSQL and a four-container stack, and the old `thephish` container has to go.

This is an extended fork of [emalderson/ThePhish](https://github.com/emalderson/ThePhish),
adding Microsoft 365 support, an automatic analysis scheduler, LLM-based social-engineering
and image analysis, SPF/DKIM/DMARC sender verification, an AI assistant beside each case for investigating it,
and enterprise authentication (mandatory TOTP two-factor, RBAC, CSRF, account lockout,
audit logging).

> **Architecture and migration reference:** [`BLUEPHISH_ARCHITECTURE.md`](BLUEPHISH_ARCHITECTURE.md)
> — data model, RBAC rules, routes, security design and known constraints.
>
> **Diagrams:** [`diagrams.md`](diagrams.md) — deployment, modules, the analysis pipeline,
> the verdict chain, destinations, authentication, the SSRF guard and the audit trail,
> drawn from the current code.
>
> **Changing the code with an AI agent?** Read [`CLAUDE.md`](CLAUDE.md) first — consulting
> the knowledge graph in `graphify-out/` before editing is mandatory here, because several
> of this deployment's couplings fail silently.

---

## Quick start

### Requirements

| | Minimum | Notes |
|---|---|---|
| Docker + Compose plugin | any recent version | `docker compose version` must work, and so must `docker info` for the user who runs the setup. On a server where Docker is root-only, run `sudo ./setup.sh` and put `sudo` in front of every `docker` command on this page |
| RAM and disk | no fixed minimum | the API, two nginx, a PostgreSQL and the folders of the recorded analyses. The 6 GB of RAM and ~25 GB of disk older versions asked for were Cassandra, TheHive and MISP, which are no longer part of the stack |
| Ports free on localhost | 443 and 80 | the vhost, bound to `127.0.0.1` by default (`BLUEPHISH_BIND` in `docker/.env` opens it) |

### One command

```bash
git clone https://github.com/zalvs/Bluephish.git
cd Bluephish
./setup.sh
```

`setup.sh` creates `docker/.env` with a freshly generated session key, protects the config
file that will hold live secrets, builds and starts the container, and waits for the
interface. It is safe to re-run — nothing already configured is overwritten.

> **Coming from an installation that had TheHive and MISP in the same compose file?** Do not
> run `setup.sh` or `docker compose up` over it. The upgrade stops those containers and has
> one manual git step; follow
> [`docker/README.md`](docker/README.md#atualizando-de-uma-instalação-com-thehive-e-misp).

> **On Windows, run it from Git Bash — not PowerShell or CMD.**
> PowerShell does not execute `.sh` files: typing `./setup.sh` there just opens the script in
> whatever editor is associated with the extension (often VS Code), which looks like the
> script "doing nothing".
>
> To stay in PowerShell, invoke Git's bash explicitly — note the full path, because the bare
> `bash.exe` in `System32` is WSL, where Docker Desktop is usually not on the `PATH`:
> ```powershell
> & 'C:\Program Files\Git\bin\bash.exe' -lc "cd '/c/path/to/Bluephish' && ./setup.sh"
> ```

To do it manually instead, see [Manual setup](#manual-setup).

### Create the first administrator

There is **no default account and no hardcoded password**. Create the first one:

```bash
cd docker && docker compose exec bluephish python3 manage.py create-admin
```

You are prompted for a username and a password (minimum **12 characters**), typed twice and
never echoed.

> Commands use `docker compose exec <service>` (run from `docker/`) rather than
> `docker exec <container>`, because a local `docker-compose.override.yml` may rename the
> container. The service name is always `bluephish`.

### Sign in

Open **<https://localhost>**.

> The certificate is self-signed, so the browser warns once — choose *Advanced → Proceed*.
> **HTTPS is mandatory:** the session cookie is issued with the `Secure` flag, so login
> cannot work over plain HTTP.

Every screen has its own address, so you can bookmark one or send the link to a colleague —
for example `https://localhost/config/ia` (Settings → AI), `/integr/tickets`
(Integrations → Tickets), `/done/<case>` (the archive, with that case open), `/queues/<case>`
(the work desk) or `/inbox/<uid>` (an e-mail of the monitored mailbox). The menu and the tabs
are real links: middle-click or Ctrl/Cmd-click opens a screen in a new tab, and every tab shares
the one session — idle time counts only your own activity in any tab, and signing out in one
tab signs out all of them. Opening a link
without a session sends you to the sign-in screen and brings you back to it afterwards; a
link to a screen your role cannot use answers *403*. Reference: `BLUEPHISH_ARCHITECTURE.md` §5.3
and §7.18.

**Have an authenticator app ready before the first sign-in.** Two-factor authentication is
mandatory and cannot be switched off, so the password alone does not get you in: the first
sign-in shows a QR code to scan with Google Authenticator, Microsoft Authenticator, Authy or
any other TOTP app, and the panel opens only after the app's six-digit code is accepted.
There is no e-mail or SMS option — see [Security notes](#security-notes) for why. If the
phone is later lost, a `global_admin` clears the factor in **Usuários**, or from the host
with `docker compose exec bluephish python3 manage.py reset-mfa NAME`.

The first build takes a few minutes: `yara-python` has no wheel for Python 3.14 and is
compiled from source.

**Closing the tab signs you out.** The session is tied to the browser tab that opened it,
not to the cookie: close the tab and the next visit asks for credentials again, and the
server revokes the session on its own once the tab stops reporting in. Reloading (F5) and
opening the panel in a second tab both keep you signed in. See
[`ROADMAP.md`](ROADMAP.md) §13 for how the two halves work.

**Corporate SSO** (Microsoft Entra ID, OpenID Connect) is optional and off until a
`global_admin` configures it under *Settings → SSO*. Walkthrough:
[`docs/sso-entra-setup.md`](docs/sso-entra-setup.md).

---

## Configure it (through the interface)

Everything is configured in the web UI — you should never need to edit a JSON file by hand.
Sign in as `global_admin` and open **Settings** (the gear icon).

### 1. E-mail — mailbox

Choose the provider and fill in the credentials:

- **Gmail:** the address plus a Google [App Password](https://support.google.com/accounts/answer/185833)
  (requires 2-Step Verification; the normal account password will not work).
- **Microsoft 365:** Tenant ID, Client ID, Client Secret and mailbox of an Azure AD app
  registration with the **`Mail.ReadWrite`** application permission and admin consent.
  Add **`User.Read.All`** to the same registration to enable *Settings → Departamentos*,
  which reads each reporter's department from Entra ID and feeds the "Departamentos mais
  visados" card. Without it that card stays empty; nothing else is affected.

**Analysis mode** decides what the automatic scheduler picks up:

| Mode | Behaviour |
|---|---|
| `Attached .eml` *(default)* | The scheduler only picks up emails carrying a forwarded `.eml` report (on Gmail the search is narrowed to unread mail with an attachment). The queue still lists every unread email, and one an analyst picks without a report is analyzed as itself, with its notices sent to the monitored mailbox. Use this for a dedicated reporting mailbox. |
| `Raw email` | The scheduler also analyzes every unread email that carries no report, as itself. Powerful, but see the warning below. |

> ⚠️ **On a personal mailbox, keep the automatic scheduler disabled in `Raw email` mode.** It
> would analyze your ordinary email in bulk, create a case per message and burn the
> VirusTotal free-tier quota.

### 2. IA and Análise automática — LLM and scheduler

| Provider | Endpoint | API key |
|---|---|---|
| **Ollama** (local, free) | `http://host.docker.internal:11434/api/chat` | none |
| **OpenRouter** (hosted, stronger models) | `https://openrouter.ai/api/v1/chat/completions` | required |

> On Linux, `host.docker.internal` does not resolve inside the container until you add
> `extra_hosts: ["host.docker.internal:host-gateway"]` to the `bluephish` service, in a
> `docker/docker-compose.override.yml` (the snippet is in
> [`docker/README.md`](docker/README.md#where-the-app-calls-out-to)).

Pick the provider from the dropdown and it fills the endpoint for you; then set the model
(e.g. `qwen2.5:7b` locally, or `anthropic/claude-3.5-sonnet` on OpenRouter). For local
Ollama, pull the model first: `ollama pull qwen2.5:7b`.

Two escalation controls decide how much the LLM is trusted:

- **Escalate Safe → Suspicious** at `Medium`/`High`/`Critical` — keeps a case open for review.
- **Let the LLM alone mark Malicious** — `off` by default. Enabling it lets a strong model
  auto-close a case with no analyzer confirmation. A sender proven authentic by DKIM/DMARC is
  never auto-condemned this way.

The **LLM System Prompt** is editable here; the JSON output contract and the
untrusted-data guardrail are appended by the code and cannot be broken from the UI.

### 3. Integrations — destinations and analyzers (plus SMTP, which lives in Settings → E-mail)

The **Tickets** tab is where a finished analysis gets recorded. It holds three built-in
destinations and they are **combinable**: disk, Jira, TheHive, all three, or none — plus any
number of generic connectors further down the same tab. The
analysis itself does not depend on any of them — the observables live in memory from
parsing to verdict, and a destination receives the finished report and nothing else.

**Disk** is the one that is on from the start. It writes each analysis to a dated folder:
`report.json` for scripts, `report.md` to read, and the original `.eml`. Nothing leaves the
machine, and nothing else has to be installed. Keep the directory under `data/`, which is
bind-mounted, or it disappears on the next image rebuild. **Set a retention before the
mailbox goes into production:** the default keeps every folder forever, and a stored phishing
email is personal data belonging to whoever reported it.

**Jira** opens one issue per analysis, with the verdict in the title and the full report in
the description. Works with Cloud (account email + API token) and Data Center (Personal
Access Token). You choose which verdicts deserve a ticket — the default is suspicious and
malicious, because opening one for every Safe email buries the queue.

**TheHive** receives the analysis as a case, with the observables marked and the report in
the analysis task. It is not installed by this repository: point the card at a TheHive you
run elsewhere, with its address and an API key.
[`docs/integracoes/thehive.md`](docs/integracoes/thehive.md) has the steps, the MISP export,
and how an installation that came with TheHive in the same compose file keeps it.

> **Every destination is optional — but the history screens need at least one that
> records.** The analysis does not depend on any of them: nothing is written anywhere until
> the verdict exists. What *does* depend on them is history — **Cases**, **Phishing** and
> **Executive** read from every enabled destination among disk, Jira and TheHive, so they go
> empty only when none of those three is on, and then they say that nothing is recording.
> Generic connectors are write-only and feed no screen. A Jira issue keeps the report as
> text, so a history that comes only from Jira has no observable counts.

**Connectors** is the fourth destination, and the one with no vendor baked in. Instead of a
hand-written client per tool, you configure one: the endpoint, the authentication, and the
JSON body pasted from the destination tool's own documentation, with `{{variables}}` marking
where the analysis goes. That reaches any REST API — Splunk, ServiceNow, PagerDuty, Slack,
Sentinel, XSOAR, and the rest — from **Integrations → Tickets**, below the three built-in
destinations.

**Preview** renders the request without sending it, so you see the exact body before anything
leaves. **Test** does send, and says so: unlike every other Test button here, it creates a
real ticket in the destination tool, because on a user-chosen endpoint there is no way to know
which call is harmless.

> Not yet built: a preset catalogue (every connector starts blank), a delivery history, and
> retry — a destination that is down loses that one dispatch, and the analysis log says which
> and why. Details: [architecture](docs/conectores-genericos.md) ·
> [user manual](docs/conectores-manual.md).

**Analyzers** run inside ThePhish itself — there is no Cortex any more. In
**Integrations → Analyzers**, each analyzer (VirusTotal, AbuseIPDB, Google Safe Browsing,
URLhaus, OTX, PhishTank, OpenPhish, Hybrid Analysis, Defender TI, CrowdStrike, YARA, …) has
its own card carrying the API key it needs, the thresholds that separate malicious from
suspicious, and a **Test** button that runs a real query so you can see the verdict a
threshold produces before enabling it. An analyzer nobody enabled simply does not run; with
none enabled, the verdict rests on the LLM assessment alone, which the screen says out loud.

Each card also decides **what gets sent to that vendor**. What an analyzer *can* judge and
what is *worth* sending it are different questions, and the second one depends on the quota
you pay for and how busy the mailbox is: a free VirusTotal key allows 4 queries a minute and
about 500 a day, while a single marketing email carries dozens of URLs. Unticking a type
there does not remove the observable from the analysis — every other enabled analyzer keeps
judging it — so on a busy mailbox you can leave VirusTotal on attachment hashes only and let
Safe Browsing, URLhaus, OpenPhish and PhishTank carry the URLs. Types that are not sent stay
on the card, dashed and dimmed, so the restriction is visible without opening the form.

You can also add a vendor that is not in the registry, in **New analyzer**: you give the
endpoint, where the verdict sits in the JSON response, and how its values map to levels.

**YARA** matches local rules against the email's attachments. It needs a directory of `.yar`
files, which does not exist until you create it — on the host:

```bash
mkdir -p docker/vol/thephish_data/yara     # becomes /root/thephish/data/yara in the container
```

Drop your rules there and leave the analyzer's path at the default. That directory is a bind
mount, so rules survive a rebuild and you do not need to restart anything to add one.

**Verdict emails** used to leave through Cortex's *Mailer* responder. They now go out over
SMTP, configured in **Settings → E-mail → Servidor de envio (SMTP)**. There is **one switch per notice** in **Settings → Notifications** — analysis started, Safe, Malicious, and the errata, which starts off — plus the SMTP server's own switch in the E-mail tab, and a notice leaves only when its switch **and** the SMTP server are both on.
notice** — analysis started, Safe, Malicious, and the errata, which starts off — plus the SMTP
server's own switch below them, and a notice leaves only when its switch **and** the SMTP
server are both on. A Suspicious verdict never mails the reporter, and a reanalysis mails
nobody. The **Test** button opens the session, negotiates TLS and authenticates — and
deliberately sends no message, so it never mails anyone by accident.

### 4. Caso and Whitelist

Case TLP/PAP and tags, and the **whitelist**, which has five rule types:

| Type | What it matches | Effect |
|---|---|---|
| **Sender** | one full address, and only when the mail server authenticated the domain (DMARC pass, or an aligned DKIM signature) | **Downgrades** the verdict to Safe, after the whole analysis ran, and records the downgrade |
| **Domain** | `empresa.com.br` covers the domain and every subdomain; `*.empresa.com.br` covers only the subdomains | Suppresses the observable |
| **URL** | host and path each matched by a regex, applied with `fullmatch` on the parsed URL | Suppresses the observable |
| **Hash** | the SHA-256 of an attachment — useful to stop a recurring signature image from being re-analyzed on every email | Suppresses the observable |
| **IP** | a routable address or CIDR range; private, loopback and reserved addresses are skipped in every analysis anyway | Suppresses the observable |

Only the sender type changes a verdict, and it never skips the analysis: a trusted sender
whose mail keeps coming back malicious is a compromised mailbox, so every downgrade is
counted and the rule **suspends itself** once it has hidden too many non-Safe verdicts.
A malicious *attachment* is never downgraded at all.

Every rule carries a reason and an expiry. The default is 180 days; a specific date is the
right choice for a contract; "permanent" needs a written justification and the
`global_admin` role. Before saving a rule you can simulate it against the last 90 days of
analyses to see what it would have hidden.

For URL rules you do not have to write the regex by hand: paste the addresses you want to
allow and **Sugerir regex** derives the pattern, explains every choice, and reports whether
any of four evasion variants (userinfo before the `@`, the domain as a suffix of another,
the domain in the fragment, the domain in the query) would also match. **Testar** runs your
pasted URLs through the real matcher and shows the normalized host next to each one — which
is how `nf.empresa.com.br@evil.com` reveals itself as a visit to evil.com.

> **MISP export belongs to TheHive, and is off unless you name it.** A `Malicious` verdict
> asks TheHive to export the case to MISP only when the TheHive destination has a MISP
> export name. With a name set and TheHive's own MISP connector not configured, every
> malicious case recorded in TheHive ends its TheHive line in the analysis log with *"a
> exportação para o MISP falhou"* and is otherwise handled normally. Everything else — the
> verdict, the case, the notification — works without MISP. Details:
> [`docs/integracoes/thehive.md`](docs/integracoes/thehive.md).

---

## Everyday use

1. **List emails** on the dashboard — read-only, never starts an analysis. The mailbox is
   also reread on a timer and pushed to the screen, so the queue stays current on its own.
2. Find the one you want. The search box filters the queue the browser already holds —
   sender, subject, UID, type and, for reports whose body has been downloaded, the content.
   Terms are combined, so `boleto itau` finds the report whose subject says one and whose
   sender is the other. Nothing is asked of the server, so it answers as you type.
3. Open a report to read it. **Opening is not analyzing** — the mailbox is peeked, so the
   message stays unread and stays in everybody's queue. The preview has two tabs:
   - **Texto** (the default) — the text pulled out of the message. Fastest to read, and it
     cannot dress itself up.
   - **Como entregue** — the message laid out as its recipient saw it, inside a sandbox that
     cannot run scripts or follow links. This is the half of a phishing email that does the
     persuading: the forged letterhead, the button whose label and destination disagree.
     Every link prints its real destination next to its text, and a link whose text names one
     domain while pointing at another is marked. Attachments are listed with their size,
     their real type next to the declared one, and a SHA-256 to copy — the file itself never
     leaves the container. **Read the outbound-request note under [Security
     notes](#security-notes) before using this view on an isolated network.**
4. Tick the emails you want and press **Analyze Selected** (or use the per-row *Analyze*).
5. Follow the live log; the verdict appears at the end. Safe and Malicious answer the
   reporter, who is emailed the verdict when that notice and SMTP are both on (both ship
   off). Suspicious emails nobody and waits in **Filas de Trabalho** for an analyst, provided
   a destination the history reads (TheHive, disk or Jira) recorded it. The result is handed
   to every enabled destination whose minimum verdict it reaches (TheHive, Jira, disk), then
   to the generic connectors. A destination that is down never undoes the verdict.
6. Open an analyzed case (**Analyzed emails** or **Work queues**) and use the **AI assistant**
   button to interrogate it: the case's context is loaded automatically, and the conversation
   is scoped to that case alone.

### Interface language

The interface is written in Portuguese (pt-BR) and stays that way by default. The **EN / PT**
button — in the top-right dock of the panel and on the sign-in screen — switches the whole
interface to English and back; the choice is kept in the browser (`localStorage`,
`bluephish.lang`). Translation is a Portuguese → English dictionary applied in the browser
(`app/static/assets/js/i18n.js` + `i18n-en.js`), so a text the dictionary does not know stays in
Portuguese rather than disappearing. Messages built from several pieces (counts, names) are
translated by their known fragments. When you add a Portuguese label to a template, add its
English to the dictionary: `python -m unittest test_i18n` (from `app/`) fails on any template text
without a translation.

### Roles

| Role | Can do |
|---|---|
| `analyst` | List emails, analyze, reanalyze a kept original, decide a reclassification for the case, case AI assistant, read the whitelist, change own password |
| `admin` | Everything above **plus** the settings (except corporate SSO and where the audit trail is stored), whitelist edits, blocking, reading the audit trail, and undoing a reclassification or teaching it to verdict memory |
| `global_admin` | Everything above **plus** user management, password and second-factor resets, corporate SSO, where the audit trail is stored, and permanent whitelist rules |

Manage users under the **people** icon (visible to `global_admin` only).

---

## Common commands

All of these run from the `docker/` directory.

```bash
# Users
docker compose exec bluephish python3 manage.py create-admin        # first global_admin
docker compose exec bluephish python3 manage.py create-user         # additional user, any role
docker compose exec bluephish python3 manage.py list-users
docker compose exec bluephish python3 manage.py reset-password NAME
docker compose exec bluephish python3 manage.py reset-mfa NAME       # lost or replaced phone
docker compose exec bluephish python3 manage.py unlock NAME         # clear an account lockout

# Stack
docker compose up -d --build bluephish   # rebuild just the app after a code change
docker compose logs -f bluephish
docker compose restart bluephish
docker compose down                     # stop everything (data in vol/ is kept)

# Audit trail — -F (not -f) keeps following it across rotations (daily, or sooner by
# size). If a folder is set in Settings → Auditoria, the live file is
# /root/thephish/data/<folder>/auth.log
docker compose exec bluephish tail -F /root/thephish/data/auth.log
```

---

## Manual setup

If you prefer not to run `setup.sh`:

```bash
# 1. environment file with a session signing key
cp docker/.env.example docker/.env
openssl rand -base64 48        # paste the result into THEPHISH_SECRET_KEY

# 2. keep runtime secrets out of git
#    (the file is tracked as a template but receives real credentials at runtime)
git update-index --skip-worktree docker/thephish_conf_files/configuration.json

# 3. build and start
cd docker && docker compose up -d --build

# 4. first administrator (still from docker/)
docker compose exec bluephish python3 manage.py create-admin
```

---

## Where things live

| Path | Contents |
|---|---|
| `app/` | The Flask application (baked into the image at build time) |
| `docs/` | Per-feature reference: LLM analysis, M365 OAuth, SSO, the generic connector, the TheHive integration |
| `docker/docker-compose.yml` | Four services: `vhost` (the only published ports, bound to `127.0.0.1` by default), `frontend`, `bluephish` (the API) and `db` (PostgreSQL) |
| `docker/.env` | Settings — gitignored, created by `setup.sh` |
| `docker/secrets/` | **Back this up apart.** `master.key` (the vault) and `db.password` (PostgreSQL), created by `setup.sh` |
| `docker/thephish_conf_files/` | Live configuration, bind-mounted and written by the app |
| `docker/vol/` | **Persistent data — back this up.** PostgreSQL data in `vol/postgres/` (users and the platform's decisions), audit log, the recorded analyses, stored original messages, TLS keys |

`docker/vol/postgres/` is the database (users, reclassification decisions, verdict memory,
whitelist state and case fingerprints). `docker/vol/thephish_data/` holds `auth.log` (audit trail), the TLS key pair,
the stored original messages (`originals/`), rendered emails (`rendered/`),
`volume_alerts.json`, and — at their default paths — the disk archive (`analises/`) and YARA
rules (`yara/`). Losing it means recreating every account and losing the audit history, the
analysts' reclassifications and verdict memory, the whitelist counters and the stored original
messages.

> **Always run `docker compose` from this repository's own `docker/` directory.** Every volume
> is declared relative to the compose file, so running it from a git worktree or a copy of the
> tree silently binds the containers to a different, empty `vol/`. The stack comes up looking
> healthy with no users, no cases and placeholder credentials, and the only hint in the log is
> a TLS certificate being generated. Nothing is destroyed — the real data stays where it was —
> but nothing works until the stack is brought up from the right place.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `./setup.sh` opens VS Code (or an editor) instead of running | You are in PowerShell/CMD, which cannot execute `.sh` — it opens the file with the associated program. Use **Git Bash**, or call Git's bash explicitly (see [Quick start](#one-command)). |
| `set: pipefail\r: invalid option name`, or `bad interpreter` | The script was checked out with **CRLF** line endings. A `.gitattributes` now forces LF, so re-clone or fix the copy in place: `sed -i 's/\r$//' setup.sh`. |
| Browser cannot reach the app | Use **`https://`** (not `http://`) and **`localhost`** — ports are bound to `127.0.0.1`, so the machine's LAN IP will not work by design. |
| `port is already allocated` on 8080, right after an update | The container of the previous stack, `thephish`, is still running and holds the port. That installation needs the upgrade steps in [`docker/README.md`](docker/README.md#atualizando-de-uma-instalação-com-thehive-e-misp), not a plain `up`. |
| A destination on the same machine cannot be reached though it opens in the browser | Inside the container, `localhost` is the container itself. Use the Docker service name for another container of the same network, or `host.docker.internal` for the host — see [`docker/README.md`](docker/README.md#where-the-app-calls-out-to). |
| Certificate warning | Expected on a fresh install: the vhost starts with a self-signed certificate. Accept it once, or install a real one in **Configurações → Certificados** (PEM, PFX or Let's Encrypt). |
| `port is already allocated` on 443 or 80 | Another web server on the host holds the port. Set `BLUEPHISH_HTTPS_PORT` / `BLUEPHISH_HTTP_PORT` in `docker/.env`, or put that server in front of the vhost and list it in `BLUEPHISH_TRUSTED_PROXIES` together with `172.30.10.0/24,172.30.11.0/24`. |
| Panel shows `502 Bad Gateway` | The frontend could not verify the API over the internal TLS hop. `docker compose logs frontend` says why; after replacing the internal CA, restart the API (`docker compose restart bluephish`). |
| Logged out after every restart | There is no vault master key (`docker/secrets/master.key`) and no `THEPHISH_SECRET_KEY`. Run `./setup.sh`: it generates the key, and the application then keeps its session key in the vault. |
| No analyzer ran on an analysis | None is enabled, or none supports the observable types found. Check **Integrations → Analyzers**; the header there states how many are on. |
| One analyzer reports nothing while the others work | Its own error travels with the report: `findings[].error` in the `report.json` the disk destination writes, and the analysis log (the live panel, or `docker logs bluephish`). The TheHive task log lists only what was flagged. A refused key, an expired quota and a 429 all say so verbatim. |
| Verdict emails never arrive | Each notice has its own switch in **Settings → Notifications**, the SMTP server has another in **Settings → E-mail**, and both must be on. A Suspicious verdict never mails the reporter. Use the **Test** button — it authenticates without sending. |
| Login says "Invalid username or password" and you are sure it is right | The account locks for **15 minutes** after 5 failures. Clear it: `docker compose exec bluephish python3 manage.py unlock NAME` (from `docker/`). |
| Every account is suddenly unknown, and the log shows a **new TLS certificate being generated** | The stack was brought up from the wrong directory. Every volume in `docker-compose.yml` is relative to the file (`./vol/...`), so `docker compose up` run from a git worktree or a copy points the container at an **empty** `vol/` — a fresh database with no users, a new certificate, and the placeholder `configuration.json` instead of your credentials. Nothing is lost: your data is still in the real `docker/vol/`. Bring the stack up from the repository's own `docker/` directory and check with `docker inspect thephish --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'` — no path should point anywhere unexpected. |
| Opening *Como entregue* is slow for one report | The layout of every email is loaded in the background, page by page, and opens at once when it is ready; its remote images are then fetched on the click, bounded at 20 s. A report the loader has not reached yet is rendered on the click instead, and that render waits its turn for the mailbox behind any polling cycle in progress. The line under the page buttons says how far the loader has got. |
| Rows stay *aguardando carregamento* | The background loader reads ten emails per trip to the mail server and gives way to every click, so on first start a mailbox of a few thousand unread takes a while to fill. Layouts are stored under `docker/vol/thephish_data/rendered` and survive restarts and rebuilds. If the line under the page buttons says the background load is unavailable, that directory is not writable — everything still opens, on the click. |
| Images in *Como entregue* show as "não carregada" | The placeholder says which of three reasons applies: the SSRF guard refused the address, the host never answered, or the file was over the size or time budget. All three are the system working. |
| Too many login attempts | The login route is rate-limited to **5 per minute per IP**. Wait a minute. |
| The authenticator code is always rejected | TOTP is a clock, not a password: the phone's time must be right. Turn on automatic time (Android: *Authenticator → Settings → Time correction for codes*; iOS: *Settings → General → Date & Time → Set Automatically*). The server accepts ±30 s. |
| Lost the phone with the authenticator | A `global_admin` clears the second factor in **Usuários → Resetar MFA**; the next sign-in asks to set it up again. If nobody can sign in, do it from the host: `docker compose exec bluephish python3 manage.py reset-mfa NAME`. |
| LLM contributes nothing to verdicts | Check `docker logs bluephish` for a warning from `llm_analysis`. Analysis is fail-open: an unreachable model never blocks the pipeline. |
| No emails listed | The queue lists every unread email whatever the analysis mode, so an empty queue means the mailbox could not be read or holds nothing unread. The queue's status line and `docker logs bluephish` name the provider error (for Gmail's daily download cap, see §7.7.1 of [`BLUEPHISH_ARCHITECTURE.md`](BLUEPHISH_ARCHITECTURE.md)). The analysis mode only changes what the automatic scheduler picks up. |

---

## Security notes

- The port is published on **`127.0.0.1`** only. To reach the UI from another machine, put
  it behind a reverse proxy with TLS instead of changing the binding.
- Secrets are never returned to the browser — the settings API answers with booleans
  (`hasApiKey`) and an empty field on save means "keep the stored value".
- **The container makes outbound requests to infrastructure the phisher chose.** Two features
  do this by design: the URL unshortener, while analyzing, and the *Como entregue* view, which
  fetches the images a reported email points at. It is the **container** that fetches them,
  never the analyst's browser — the workstation's address and user agent never leave, and
  everything reaching the browser is a `data:` URI inside a sandbox. But the request does
  leave your network, and it tells the sender that somebody looked. The interface names every
  host it contacted. Images are fetched **only when somebody opens *Como entregue***: the
  background loader lays every email out without them, so a report nobody opens tells its
  sender nothing.

  Three consequences worth deciding on before deployment: put the container's egress behind
  whatever proxy your outbound policy expects; expect a phishing campaign to learn that this
  mailbox is monitored; and if that is unacceptable for your operation, `fetch_remote` in
  `app/email_render.py` turns image fetching off at the source (links and scripts are inert
  either way). Every fetch is validated against the same SSRF guard as the analyst-defined
  analyzers — the internal network is never reachable and the cloud metadata service is
  refused outright — with redirects refused, image types read from the bytes rather than the
  `Content-Type`, SVG rejected, and count, size and wall-clock all capped.
- Passwords are hashed with **bcrypt**; sessions expire after **30 min idle / 12 h absolute**,
  are revoked on password change, and end when the browser tab that opened them is closed.
  All authentication events are audited to `auth.log`.
- **A second factor is mandatory for every account**, with no per-user or per-role exemption
  and no setting that turns it off. A correct password opens a 10-minute challenge, not a
  session: nothing is signed in until a valid TOTP code is presented, so a stolen password
  on its own reaches nothing. Accounts that predate this are intercepted at their next
  sign-in and must enrol before they get in, and sessions opened before it are dropped.
- **Authenticator apps only** (Google Authenticator, Microsoft Authenticator, Authy, or any
  RFC 6238 client). Codes by e-mail or SMS are deliberately not offered and should not be
  added: SMS falls to a SIM swap, and e-mail falls together with the very mailbox this
  platform exists to watch. Recovery is a `global_admin` clearing the factor, never a code
  sent through a channel an attacker may already hold.
- **SSO accounts are not exempt.** The identity provider proves one factor; the platform
  requires two, so the return from Entra ID lands on the same TOTP challenge.
- **SSO accounts have no password at all.** The stored hash is of a random value nobody has
  ever seen, password login refuses them outright, and *Reset password* is not offered for
  them — revocation belongs to the identity provider.
- Before opening this to a wider network, read the *Known constraints and traps* section of
  [`BLUEPHISH_ARCHITECTURE.md`](BLUEPHISH_ARCHITECTURE.md).

## License

MIT — see [LICENSE](LICENSE). Original project by
[emalderson](https://github.com/emalderson/ThePhish).
