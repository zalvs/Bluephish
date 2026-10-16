# Optional integrations

[Português (Brasil)](../integracoes.md) · **English**

Bluephish runs on its own: `./setup.sh` starts the application and nothing else. The services
below are **optional**. None of them is needed to read a mailbox, analyze emails or record
verdicts (the disk destination and the generic connectors work with no extra container). Add
them only if you already use them, or want them.

| Service | What it is for | Port (localhost only) |
|---|---|---|
| **TheHive** (+ Cassandra) | A place the finished analysis can be recorded as a case | 9000 |
| **MISP** (+ MySQL, Redis) | A threat-intelligence platform TheHive can export malicious cases to | 80, 443 |

## Starting them

They live in their own compose file. Run both files together, from `docker/`:

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.integrations.yml up -d
```

Or, on a fresh clone, let the setup script do it, which also prepares TheHive's session key:

```bash
./setup.sh --with-integrations
```

You need about **6 GB of free RAM** and **25 GB of disk** for these integrations alone, on top
of what Bluephish uses, and the ports above free on the host. Ports 80 and 443 belong to MISP
and collide with any local web server.

To go back to Bluephish alone, run `docker compose up -d` from `docker/` without the second
file, and stop the extras with
`docker compose -f docker-compose.yml -f docker-compose.integrations.yml down`.

## TheHive

Bluephish can record every finished analysis as a case in TheHive. It is one destination among
others: the analysis itself never depends on it.

**On the Bluephish side**, open **ADMINISTRAÇÃO → Integrações → Tickets** and fill the
**TheHive** card:

| Field | Value |
|---|---|
| URL | `http://thehive:9000` when TheHive runs from the integrations file; the address of your own TheHive otherwise |
| API key | a key created in TheHive for a user of the organisation that should own the cases |

> The URL is `http://thehive:9000`, not `localhost`: Bluephish reaches TheHive over the Docker
> network by service name, and `localhost` inside the Bluephish container is the container
> itself.

**Setting up TheHive itself** (first sign-in, organisations, users, API keys, hardening) is
TheHive's own business and is documented by its maintainers: <https://docs.strangebee.com/>.
The integrations file ships TheHive 4.1.9, so look for the TheHive 4 documentation there. Do
not leave the initial account as it ships: change it before you leave TheHive running, and
keep its port bound to `127.0.0.1`.

If you already run a TheHive somewhere else, you do not need these containers: use its URL and
an API key from it.

### Exporting malicious cases to MISP

Bluephish only decides **whether to ask**: when the TheHive card has a *MISP export name*, a
`Malicious` verdict asks TheHive to export the case. The MISP connector itself belongs to
TheHive and ships commented out in `docker/thehive/application.conf`; enabling it (MISP
address and API key) is described in MISP and TheHive documentation
(<https://www.misp-project.org/documentation/>).

Until it is enabled, every malicious case recorded in TheHive ends its line in the analysis
log with *"a exportação para o MISP falhou"* and is otherwise handled normally. If you do not
use MISP, clear the export name on the TheHive card and the request stops being made.

## Jira, disk and generic connectors

These are destinations too, but they need **no container**: Jira is configured with its
address and a token, the disk destination writes to a folder, and generic connectors call any
REST API. See [configuration](configuration.md#3-destinations-and-analyzers) and the
[connector manual](../conectores-manual.md) (in Portuguese).
