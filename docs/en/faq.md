# FAQ

[Português (Brasil)](../duvidas-gerais.md) · **English**

Answers to "how do I do X?". Each one has the full step by step. If something **went wrong**,
the place is [Troubleshooting](troubleshooting.md), which lists symptoms.

`docker compose` commands run from the repository's `docker/` directory.

- [How do I change the HTTPS certificate?](#how-do-i-change-the-https-certificate)
- [How do I change the port?](#how-do-i-change-the-port)
- [How do I access it from another machine?](#how-do-i-access-it-from-another-machine)
- [How do I use an Ollama running on my machine on Linux?](#how-do-i-use-an-ollama-running-on-my-machine-on-linux)
- [How do I update to a new version?](#how-do-i-update-to-a-new-version)
- [How do I back up and restore?](#how-do-i-back-up-and-restore)
- [Where are the data and the logs?](#where-are-the-data-and-the-logs)
- [How do I create a user, change a password or unlock an account?](#how-do-i-create-a-user-change-a-password-or-unlock-an-account)
- [How do I stop, start and remove everything?](#how-do-i-stop-start-and-remove-everything)
- [How do I change the session key?](#how-do-i-change-the-session-key)
- [Why does `thephish` still show up?](#why-does-thephish-still-show-up)
- [Do I need TheHive, Jira or an LLM?](#do-i-need-thehive-jira-or-an-llm)

## How do I change the HTTPS certificate?

In 2.0 the public certificate is the **vhost**'s (the nginx in front of everything), and it is
replaced from the interface: **Configurações → Certificados**. Upload a PEM pair or a PFX, or
request one from Let's Encrypt; the vhost reloads by itself within 30 seconds. On the first
start it uses a self-signed one, hence the browser warning.

- **Let's Encrypt** needs port 80 reachable from the internet: set `BLUEPHISH_BIND=0.0.0.0` in
  `docker/.env` and apply with `docker compose up -d`.
- Certificates live in `docker/vol/certs/` and survive image rebuilds.
- **Emergency exit:** if a wrong certificate locks you out of the screen, swap the pair from a
  terminal, from `docker/` (the files must be inside the container):
  ```bash
  docker cp cert.pem bluephish:/tmp/cert.pem
  docker cp key.pem  bluephish:/tmp/key.pem
  docker compose exec bluephish python3 manage.py cert-import /tmp/cert.pem /tmp/key.pem
  ```
- **Check** which certificate the server now presents:
  ```bash
  openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```
- Traffic between the vhost, the frontend and the API is TLS too, with an internal CA the API
  generates on first start. It has nothing to do with the public certificate.

## How do I change the port?

The vhost publishes ports **443** (HTTPS) and **80**, bound to `127.0.0.1` only. To change the
host ports without editing `docker-compose.yml`, set in `docker/.env`:

```bash
BLUEPHISH_HTTPS_PORT=9443
BLUEPHISH_HTTP_PORT=9080
```

Apply from `docker/` with `docker compose up -d` and open `https://localhost:9443`. `setup.sh`
reads the same variable when it waits for the interface.

**Coming from 1.x?** Port 8080 is gone: the panel now answers on the vhost. An old
`docker-compose.override.yml` that changed the `ports` of the `thephish` service no longer
applies and should be removed or rewritten.

## How do I access it from another machine?

For safety the ports only answer on the machine itself (`127.0.0.1`), and login requires HTTPS.
Three ways:

- **SSH tunnel** (simplest, nothing to change in Bluephish). On the machine you want to use:
  ```bash
  ssh -L 8443:127.0.0.1:443 user@bluephish-server
  ```
  Keep it open and browse to `https://localhost:8443` there.
- **Open the vhost to the network:** `BLUEPHISH_BIND=0.0.0.0` in `docker/.env`, with a real
  certificate (above), a firewall limiting who gets in, and `BLUEPHISH_BASE_URL` set to the
  public address if you use SSO.
- **Your own reverse proxy in front of the vhost:** list it in `BLUEPHISH_TRUSTED_PROXIES`,
  together with the vhost and frontend addresses (the default is
  `172.30.10.10/32,172.30.11.20/32`). Read [Security](security.md) too.

## How do I use an Ollama running on my machine on Linux?

On Docker Desktop (Windows and macOS) the name `host.docker.internal` already points to your
machine. On **Linux** it does not exist by default:

1. Create (or edit) `docker/docker-compose.override.yml`:
   ```yaml
   services:
     bluephish:
       extra_hosts:
         - "host.docker.internal:host-gateway"
   ```
2. Make Ollama accept connections coming from Docker. By default it listens only on
   `127.0.0.1`, which the container cannot reach; start it with the variable
   `OLLAMA_HOST=0.0.0.0`.
3. Apply with `docker compose up -d` and, in **Configurações → IA**, use the endpoint
   `http://host.docker.internal:11434/api/chat`.

## How do I update to a new version?

From the repository root, take a backup (next section) and then:

```bash
git pull --ff-only
./setup.sh
```

`setup.sh` only creates what is missing (the vault master key and the database password, in
`docker/secrets/`), overwrites nothing, and rebuilds the images with `docker compose up -d
--build`. A plain `restart` brings back the **old** image.

**Coming from 1.x (single container, SQLite)** there are extra steps, in the
[CHANGELOG](../../CHANGELOG.md#200---2026-11-27) and in [`docker/README.md`](../../docker/README.md):
the old `thephish` container has to be removed first, and on the first start the API copies
`thephish.db` into PostgreSQL by itself, keeping a copy of the file.

**If `git pull` aborts** with `Your local changes to the following files would be overwritten
by merge: docker/thephish_conf_files/configuration.json`, the new version also changed that
file, which holds your credentials. From the repository root:

```bash
F=docker/thephish_conf_files/configuration.json
cp $F ../configuration.backup.json     # 1. keep your credentials, OUTSIDE the repository
git update-index --no-skip-worktree $F # 2. release the file
git checkout -- $F                     #    drop the local copy (the backup is saved)
git pull --ff-only                     # 3. update
git update-index --skip-worktree $F    # 4. lock the file again
```

5. **Put your credentials back** over the new file, keeping the version's new keys (use
   `python` instead of `python3` on Windows):
   ```bash
   python3 - <<'PYEOF'
   import json
   def merge(base, mine):
       for key, value in mine.items():
           if isinstance(value, dict) and isinstance(base.get(key), dict):
               merge(base[key], value)
           else:
               base[key] = value
       return base
   path = 'docker/thephish_conf_files/configuration.json'
   new = json.load(open(path, encoding='utf-8'))
   mine = json.load(open('../configuration.backup.json', encoding='utf-8'))
   open(path, 'w', encoding='utf-8').write(json.dumps(merge(new, mine), indent='\t'))
   PYEOF
   ```
6. Run `./setup.sh` again. In 2.0 the configuration secrets move into the vault
   (`manage.py vault-seal` does it by hand).

## How do I back up and restore?

What matters lives in five places: `docker/vol/` (PostgreSQL in `vol/postgres/`, the audit
trail, stored messages, certificates), `docker/secrets/` (`master.key`, the vault key, and
`db.password`), `docker/thephish_conf_files/` (`configuration.json` and `whitelist.json`),
`docker/.env` and, if you created it, `docker/docker-compose.override.yml`.

**Keep `docker/secrets/` in a backup apart from `docker/vol/`:** without `master.key` the
secrets encrypted in the database do not open, and with both together whoever gets one backup
gets everything.

**Database backup**, with everything running, from `docker/`:

```bash
docker compose exec db pg_dump -U bluephish bluephish > bluephish-$(date +%F).sql
```

**Full backup**, from the repository root, with the stack stopped:

```bash
( cd docker && docker compose stop )
tar czf bluephish-data-$(date +%F).tar.gz docker/vol docker/thephish_conf_files docker/.env $(ls docker/docker-compose.override.yml 2>/dev/null)
tar czf bluephish-secrets-$(date +%F).tar.gz docker/secrets
( cd docker && docker compose start )
```

**Restore** on a new installation (after `git clone`), from the repository root: extract both
archives and run `./setup.sh`. It overwrites nothing, so it just starts the stack on the
restored data. Keep the backups off the machine: they contain credentials.

## Where are the data and the logs?

- **Database:** PostgreSQL in the `db` container, data in `docker/vol/postgres/` (users,
  analyst decisions, history, verdict memory, the vault).
- **Files:** `docker/vol/thephish_data/`: `auth.log` (the audit trail), original messages
  (`originals/`), rendered screens (`rendered/`), what the Disk destination records
  (`analises/`), your YARA rules (`yara/`) and, after the 1.x migration, the old `thephish.db`
  with its `.pre-postgres-<date>.bak` copy.
- **Certificates:** `docker/vol/certs/`.
- **Logs:** `docker compose logs -f bluephish` (the API); `vhost`, `frontend` and `db` for the rest.
- **Audit trail:** `docker compose exec bluephish tail -F /root/thephish/data/auth.log`
  (if you picked a folder in **Configurações → Auditoria**, the file is in it).

## How do I create a user, change a password or unlock an account?

From the interface, a `global_admin` does it in **ADMINISTRAÇÃO → Usuários**. From the command
line, from `docker/`:

```bash
docker compose exec bluephish python3 manage.py create-user               # new user, any role
docker compose exec bluephish python3 manage.py list-users
docker compose exec bluephish python3 manage.py reset-password NAME
docker compose exec bluephish python3 manage.py reset-mfa NAME            # lost or replaced phone
docker compose exec bluephish python3 manage.py unlock NAME               # account locked by failed attempts
```

Each command asks for what is missing and never echoes the password. The last active
`global_admin` cannot be demoted, deactivated or deleted.

## How do I stop, start and remove everything?

From `docker/`:

```bash
docker compose stop        # stops the stack; data stays
docker compose start       # starts it again
docker compose restart     # restarts (does not re-read docker/.env; use `up -d` for that)
docker compose down        # removes the containers; data in vol/ and secrets/ stays
```

To delete **everything**, data included (**no way back**; back up first): run `docker compose
down`, delete `docker/vol/` and `docker/secrets/` and, if you want, the `bluephish`,
`bluephish-frontend` and `bluephish-vhost` images.

## How do I change the session key?

In 2.0 the key that signs the session (a strict JWT, revocable by its `jti`) is generated by
the application itself and kept **encrypted in the vault**, under the master key
`docker/secrets/master.key`. `THEPHISH_SECRET_KEY` in `docker/.env` is no longer needed: if it
is still there, `setup.sh` warns, and removing it signs everybody out once.

If you suspect `master.key` leaked, treat the secrets kept in the vault (API keys, destination
passwords) as exposed and rotate them at their source.

## Why does `thephish` still show up?

Historical names, kept for compatibility: the `/root/thephish` path inside the container, the
`docker/thephish_conf_files/` folder and `docker/vol/thephish_data/`. In 2.0 the services and
containers are named `bluephish`, `bluephish-db`, `bluephish-frontend` and `bluephish-vhost`.
The product, on screen and in the docs, is **Bluephish**.

## Do I need TheHive, Jira or an LLM?

**No.** The minimum for Bluephish to work is a connected mailbox. Verdicts are written to
disk by default, and the reputation analyzers run inside it. The LLM adds the
social-engineering assessment, and TheHive and Jira are optional destinations to record
verdicts elsewhere. See [Configuration](configuration.md) and
[Optional integrations](integrations.md).
