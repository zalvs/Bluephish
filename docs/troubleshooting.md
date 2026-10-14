# Troubleshooting

**English** · [Português (Brasil)](troubleshooting.pt-BR.md)

Common problems and how to fix them. Commands are run from the `docker/` directory unless
said otherwise. Find your symptom in the group that fits, or search the page for the error
text.

- [Starting Bluephish](#starting-bluephish)
- [Signing in](#signing-in)
- [Mailbox and analysis](#mailbox-and-analysis)
- [The interface](#the-interface)
- [Optional integrations](#optional-integrations)

## Starting Bluephish

| Symptom | Cause and fix |
|---|---|
| `./setup.sh` opens VS Code (or an editor) instead of running | You are in PowerShell/CMD, which cannot execute `.sh` files, so it opens the file with the associated program. Use **Git Bash**, or call Git's bash explicitly: `& 'C:\Program Files\Git\bin\bash.exe' -lc "cd '/c/path/to/Bluephish' && ./setup.sh"`. The bare `bash.exe` in `System32` is WSL, where Docker Desktop is usually not on the `PATH`. |
| `set: pipefail\r: invalid option name`, or `bad interpreter` | The script was checked out with **CRLF** line endings. A `.gitattributes` now forces LF, so re-clone, or fix the copy in place: `sed -i 's/\r$//' setup.sh`. |
| `the 'docker compose' plugin is required` | `docker compose version` must work. Install Docker Desktop, or the `docker-compose-plugin` package on Linux. |
| Browser cannot reach the app | Use **`https://`** (not `http://`) and **`localhost`**: the port is bound to `127.0.0.1`, so the machine's LAN IP will not work, by design. |
| Certificate warning | Expected: the certificate is self-signed. Accept it once. |
| `port is already allocated` on 8080 | Something else on the machine uses 8080. Stop it, or remap the port in `docker/docker-compose.yml` (for example `127.0.0.1:8081:8080`) and open that port instead. |
| Every account is suddenly unknown, and the log shows a **new TLS certificate being generated** | Bluephish was started from the wrong directory. Every volume in `docker-compose.yml` is relative to the file (`./vol/...`), so `docker compose up` run from a git worktree or a copy of the tree points the container at an **empty** `vol/`: a fresh database with no users, a new certificate, and the placeholder `configuration.json` instead of your credentials. Nothing is lost: your data is still in the real `docker/vol/`. Start it from the repository's own `docker/` directory and check with `docker inspect thephish --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'`: no path should point anywhere unexpected. |

## Signing in

| Symptom | Cause and fix |
|---|---|
| Logged out after every restart | `THEPHISH_SECRET_KEY` is empty in `docker/.env`. Run `./setup.sh` or set it manually (`openssl rand -base64 48`). |
| Login says "Invalid username or password" and you are sure it is right | The account locks for **15 minutes** after 5 failures. Clear it: `docker compose exec thephish python3 manage.py unlock NAME`. |
| Too many login attempts | The login route is rate-limited to **5 per minute per IP**. Wait a minute. |
| The authenticator code is always rejected | TOTP is a clock, not a password: the phone's time must be right. Turn on automatic time (Android: *Authenticator → Settings → Time correction for codes*; iOS: *Settings → General → Date & Time → Set Automatically*). The server accepts ±30 s. |
| Lost the phone with the authenticator | A `global_admin` clears the second factor in *Usuários → Resetar MFA*; the next sign-in asks to set it up again. If nobody can sign in, do it from the host: `docker compose exec thephish python3 manage.py reset-mfa NAME`. |

## Mailbox and analysis

| Symptom | Cause and fix |
|---|---|
| No emails listed | The queue lists every unread email whatever the analysis mode, so an empty queue means the mailbox could not be read or holds nothing unread. The queue's status line and `docker logs thephish` name the provider error (for Gmail's daily download cap, see §7.7.1 of [`BLUEPHISH_ARCHITECTURE.md`](../BLUEPHISH_ARCHITECTURE.md)). The analysis mode only changes what the automatic scheduler picks up. |
| No analyzer ran on an analysis | None is enabled, or none supports the observable types found. Check *Integrações → Analisadores*; the header there states how many are on. |
| One analyzer reports nothing while the others work | Its own error travels with the report: `findings[].error` in the `report.json` the disk destination writes, and the analysis log (the live panel, or `docker logs thephish`). A refused key, an expired quota and a 429 all say so verbatim. |
| The LLM contributes nothing to verdicts | Check `docker logs thephish` for a warning from `llm_analysis`. Analysis is fail-open: an unreachable model never blocks the pipeline. Remember that on Linux `host.docker.internal` needs an `extra_hosts` entry (see [configuration](configuration.md#2-ai-and-automatic-analysis)). |
| Verdict emails never arrive | Each notice has its own switch in *Configurações → Notificações*, the SMTP server has another in *Configurações → E-mail*, and both must be on. A Suspicious verdict never mails the reporter. Use the **Testar** button: it authenticates without sending. |

## The interface

| Symptom | Cause and fix |
|---|---|
| Opening *Como entregue* is slow for one report | The layout of every email is loaded in the background, page by page, and opens at once when it is ready; its remote images are then fetched on the click, bounded at 20 s. A report the loader has not reached yet is rendered on the click instead, and that render waits its turn for the mailbox behind any polling cycle in progress. The line under the page buttons says how far the loader has got. |
| Rows stay *aguardando carregamento* | The background loader reads ten emails per trip to the mail server and gives way to every click, so on first start a mailbox of a few thousand unread takes a while to fill. Layouts are stored under `docker/vol/thephish_data/rendered` and survive restarts and rebuilds. If the line under the page buttons says the background load is unavailable, that directory is not writable: everything still opens, on the click. |
| Images in *Como entregue* show as "não carregada" | The placeholder says which of three reasons applies: the SSRF guard refused the address, the host never answered, or the file was over the size or time budget. All three are the system working. |

## Optional integrations

These only apply if you run the services described in [integrations](integrations.md).

| Symptom | Cause and fix |
|---|---|
| Bluephish cannot reach TheHive though `localhost:9000` works in the browser | The URL in *Integrações → Tickets* must be `http://thehive:9000`, the Docker service name. Inside the Bluephish container, `localhost` is the container itself. |
| `port is already allocated` on 80 or 443 | Those belong to MISP and collide with any local web server (IIS, Apache, another stack). Start without the integrations file, or remap the ports in `docker/docker-compose.integrations.yml` (for example `127.0.0.1:8081:80`). Nothing in the analysis needs MISP's web interface. |
| Malicious cases end with *"a exportação para o MISP falhou"* | TheHive was asked to export to MISP but its MISP connector is not enabled. Enable it (see [integrations](integrations.md#exporting-malicious-cases-to-misp)) or clear the MISP export name on the TheHive card. |
| TheHive, its dependencies or MISP will not start | They are heavy: about 6 GB of free RAM for the set. Check `docker compose logs thehive` (or `cassandra`, `misp`) and stop the integrations if the machine is short on memory: Bluephish does not depend on them. |
