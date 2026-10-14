# Configuration

**English** · [Português (Brasil)](configuration.pt-BR.md)

Everything is configured in the web interface; you should never need to edit a JSON file by
hand. Sign in as `global_admin` and open **Configurações** (Settings, the gear icon).

> The interface itself is in Portuguese, so the screen and button names below are written as
> they appear on screen, with a gloss where it helps.

Contents: [1. Mailbox](#1-mailbox) · [2. AI and automatic analysis](#2-ai-and-automatic-analysis) ·
[3. Destinations and analyzers](#3-destinations-and-analyzers) · [4. Case and whitelist](#4-case-and-whitelist)

## 1. Mailbox

Open *Configurações → E-mail*, choose the provider and fill in the credentials:

- **Gmail:** the address plus a Google [App Password](https://support.google.com/accounts/answer/185833)
  (requires 2-Step Verification; the normal account password will not work).
- **Microsoft 365:** Tenant ID, Client ID, Client Secret and mailbox of an Azure AD app
  registration with the **`Mail.ReadWrite`** application permission and admin consent. Walkthrough:
  [`m365-oauth-setup.md`](m365-oauth-setup.md). Add **`User.Read.All`** to the same registration
  to enable *Configurações → Departamentos*, which reads each reporter's department from
  Entra ID and feeds the "Departamentos mais visados" card. Without it that card stays empty;
  nothing else is affected.

**Analysis mode** decides what the automatic scheduler picks up:

| Mode | Behaviour |
|---|---|
| `Attached .eml` *(default)* | The scheduler only picks up emails carrying a forwarded `.eml` report (on Gmail the search is narrowed to unread mail with an attachment). The queue still lists every unread email, and one an analyst picks without a report is analyzed as itself, with its notices sent to the monitored mailbox. Use this for a dedicated reporting mailbox. |
| `Raw email` | The scheduler also analyzes every unread email that carries no report, as itself. Powerful, but see the warning below. |

> ⚠️ **On a personal mailbox, keep the automatic scheduler disabled in `Raw email` mode.** It
> would analyze your ordinary email in bulk, create a record per message and burn the
> VirusTotal free-tier quota.

## 2. AI and automatic analysis

Open *Configurações → IA* and *Configurações → Análise automática* (language model and scheduler).

| Provider | Endpoint | API key |
|---|---|---|
| **Ollama** (local, free) | `http://host.docker.internal:11434/api/chat` | none |
| **OpenRouter** (hosted, stronger models) | `https://openrouter.ai/api/v1/chat/completions` | required |

> On Linux, `host.docker.internal` does not resolve inside the `thephish` container until you
> add `extra_hosts: ["host.docker.internal:host-gateway"]` to that service in
> `docker/docker-compose.yml`.

Pick the provider from the dropdown and it fills the endpoint for you; then set the model
(e.g. `qwen2.5:7b` locally, or `anthropic/claude-3.5-sonnet` on OpenRouter). For local
Ollama, pull the model first: `ollama pull qwen2.5:7b`. More detail in
[`llm-analysis.md`](llm-analysis.md); provider documentation: <https://docs.ollama.com/>,
<https://openrouter.ai/docs>.

Two escalation controls decide how much the LLM is trusted:

- **Escalate Safe → Suspicious** at `Medium`/`High`/`Critical` — keeps a case open for review.
- **Let the LLM alone mark Malicious** — `off` by default. Enabling it lets a strong model
  auto-close a case with no analyzer confirmation. A sender proven authentic by DKIM/DMARC is
  never auto-condemned this way.

The **LLM System Prompt** is editable here; the JSON output contract and the
untrusted-data guardrail are appended by the code and cannot be broken from the UI.

## 3. Destinations and analyzers

### Destinations

*Configurações → Integrações → Tickets* is where a finished analysis gets recorded. It holds
three built-in destinations and they are **combinable**: TheHive, Jira, disk, all three, or
none, plus any number of generic connectors further down the same tab. The analysis itself
does not depend on any of them: the observables live in memory from parsing to verdict, and
a destination receives the finished report and nothing else.

On a fresh installation only the **disk** destination is on, so the history screens have
data from the first analysis and nothing tries to reach a service that is not there. The
others are opt-in. (An installation that already had a TheHive API key saved, or destinations
already saved, keeps them as they were.)

**Disk** writes each analysis to a dated folder: `report.json` for scripts, `report.md` to
read, and optionally the original `.eml`. This is the option for running without any
centralizer at all, and nothing leaves the machine. Keep the directory under `data/`, which
is bind-mounted, or it disappears on the next image rebuild. An optional retention prunes
older folders: a stored phishing email is personal data belonging to whoever reported it.

**Jira** opens one issue per analysis, with the verdict in the title and the full report in
the description. It works with Cloud (account email + API token) and Data Center (Personal
Access Token). You choose which verdicts deserve a ticket; the default is suspicious and
malicious, because opening one for every Safe email buries the queue.

**TheHive** records the analysis as a case. It is optional and runs outside Bluephish: see
[integrations](integrations.md) for how to point Bluephish at it.

**Connectors** are the destination with no vendor baked in. Instead of a hand-written client
per tool, you configure one: the endpoint, the authentication, and the JSON body pasted from
the destination tool's own documentation, with `{{variables}}` marking where the analysis
goes. That reaches any REST API (Splunk, ServiceNow, PagerDuty, Slack, Sentinel, XSOAR and
the rest) from *Integrações → Tickets*, below the built-in destinations.
**Pré-visualização** renders the request without sending it, so you see the exact body
before anything leaves. **Teste** does send, and says so: unlike every other test button, it
creates a real ticket in the destination tool, because on a user-chosen endpoint there is no
way to know which call is harmless. Details: [architecture](conectores-genericos.md) ·
[user manual](conectores-manual.md). Not built yet: a preset catalogue, a delivery history
and retry, so a destination that is down loses that one dispatch and the analysis log says
which and why.

> **No destination is required, but the history screens need at least one that records.**
> **Casos**, **Phishing** and **Visão Executiva** read from every enabled destination among
> TheHive, disk and Jira, so they go empty only when none of those three is on, and then
> they say that nothing is recording. Generic connectors are write-only and feed no screen.

### Analyzers

Analyzers run inside Bluephish itself. In *Integrações → Analisadores*, each analyzer
(VirusTotal, AbuseIPDB, Google Safe Browsing, URLhaus, OTX, PhishTank, OpenPhish, Hybrid
Analysis, Defender TI, CrowdStrike, YARA, …) has its own card carrying the API key it needs,
the thresholds that separate malicious from suspicious, and a **Testar** button that runs a
real query so you can see the verdict a threshold produces before enabling it. An analyzer
nobody enabled simply does not run; with none enabled, the verdict rests on the LLM
assessment alone, which the screen says out loud.

Each card also decides **what gets sent to that vendor**. What an analyzer *can* judge and
what is *worth* sending it are different questions, and the second one depends on the quota
you pay for and how busy the mailbox is: a free VirusTotal key allows 4 queries a minute and
about 500 a day, while a single marketing email carries dozens of URLs. Unticking a type
there does not remove the observable from the analysis (every other enabled analyzer keeps
judging it), so on a busy mailbox you can leave VirusTotal on attachment hashes only and let
Safe Browsing, URLhaus, OpenPhish and PhishTank carry the URLs. Types that are not sent stay
on the card, dashed and dimmed, so the restriction is visible without opening the form.

You can also add a vendor that is not in the registry, in **Novo analisador**: you give the
endpoint, where the verdict sits in the JSON response, and how its values map to levels.

**YARA** matches local rules against the email's attachments. It needs a directory of `.yar`
files, which does not exist until you create it, on the host:

```bash
mkdir -p docker/vol/thephish_data/yara     # becomes /root/thephish/data/yara in the container
```

Drop your rules there and leave the analyzer's path at the default. That directory is a bind
mount, so rules survive a rebuild and you do not need to restart anything to add one.

### Verdict emails

They go out over SMTP, configured in *Configurações → E-mail → Servidor de envio (SMTP)*.
There is **one switch per notice** in *Configurações → Notificações* (analysis started, Safe,
Malicious, and the errata, which starts off), plus the SMTP server's own switch in the E-mail
tab, and a notice leaves only when its switch **and** the SMTP server are both on. A
Suspicious verdict never mails the reporter, and a reanalysis mails nobody. The **Testar**
button opens the session, negotiates TLS and authenticates, and deliberately sends no
message, so it never mails anyone by accident.

## 4. Case and whitelist

Case TLP/PAP and tags, and the **whitelist**, which has five rule types:

| Type | What it matches | Effect |
|---|---|---|
| **Sender** | one full address, and only when the mail server authenticated the domain (DMARC pass, or an aligned DKIM signature) | **Downgrades** the verdict to Safe, after the whole analysis ran, and records the downgrade |
| **Domain** | `empresa.com.br` covers the domain and every subdomain; `*.empresa.com.br` covers only the subdomains | Suppresses the observable |
| **URL** | host and path each matched by a regex, applied with `fullmatch` on the parsed URL | Suppresses the observable |
| **Hash** | the SHA-256 of an attachment, useful to stop a recurring signature image from being re-analyzed on every email | Suppresses the observable |
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
pasted URLs through the real matcher and shows the normalized host next to each one, which
is how `nf.empresa.com.br@evil.com` reveals itself as a visit to evil.com.
