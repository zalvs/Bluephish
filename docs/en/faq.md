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
- [Why is the service called `thephish`?](#why-is-the-service-called-thephish)
- [Do I need TheHive, Jira or an LLM?](#do-i-need-thehive-jira-or-an-llm)

## How do I change the HTTPS certificate?

Bluephish ships with a **self-signed** certificate, generated on first start, which is why the
browser warns. To use a certificate of your own (from a certificate authority, or an internal
CA):

1. **Have both files in PEM format:** the certificate and the private key **without a
   passphrase**. If the certificate came with an intermediate chain, put the server
   certificate followed by the intermediates **in the same file**. The certificate must be
   the **pair** of the key: with a wrong pair the application does not start, so check **before copying** (the command
   prints nothing if it is a pair):
   ```bash
   diff <(openssl x509 -in your-certificate.pem -noout -pubkey) <(openssl pkey -in your-key.pem -pubout) && echo "pair OK"
   ```
2. **Keep the current ones**, so you can go back:
   ```bash
   cd docker/vol/thephish_data
   cp thephish-cert.pem thephish-cert.pem.bak
   cp thephish-key.pem thephish-key.pem.bak
   ```
3. **Replace the files**, keeping exactly these names:
   ```bash
   cp /path/to/your-certificate.pem thephish-cert.pem
   cp /path/to/your-key.pem         thephish-key.pem
   ```
4. **Restart** (from `docker/`):
   ```bash
   cd ../..
   docker compose restart thephish
   ```
5. **Check** which certificate the server now presents:
   ```bash
   openssl s_client -connect localhost:8080 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
   ```
   The `subject` line must show the name of **your** certificate.

Details that matter:

- Bluephish **only generates** the factory certificate when **both** files are missing. With
  yours in place it never overwrites them.
- **To go back to the factory certificate:** delete `thephish-cert.pem` and `thephish-key.pem`
  and restart; a new self-signed one is generated.
- The files live on your computer, in `docker/vol/thephish_data/`, and survive image rebuilds.
- If the log shows `KEY_VALUES_MISMATCH` and the page does not open, the certificate and key
  are not a pair: see [Troubleshooting](troubleshooting.md#starting-bluephish).
- The browser compares the address you type with the name inside the certificate. The port is
  only reachable on `localhost` (see [How do I access it from another machine](#how-do-i-access-it-from-another-machine)),
  so the name only matters if you put a proxy in front.
- *Optional, to keep them elsewhere:* the application reads the `THEPHISH_TLS_CERT` and
  `THEPHISH_TLS_KEY` environment variables (paths **inside the container**). You can set them
  in a `docker/docker-compose.override.yml`, under the `environment` of the `thephish`
  service.
- To **generate a test certificate** with `openssl`, in Git Bash on Windows put
  `MSYS_NO_PATHCONV=1` in front of the command; without it Git Bash turns the `/CN=...` of
  `-subj` into a file path and `openssl` fails:
  ```bash
  MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout key.pem -out certificate.pem -days 30 \
    -subj "/CN=bluephish.example" -addext "subjectAltName=DNS:bluephish.example,DNS:localhost"
  ```

## How do I change the port?

The default port is **8080**, bound to `127.0.0.1` only. `setup.sh` reads the published port,
so the file below can be created before or after the first `./setup.sh`; **do not edit
`docker-compose.yml`**, so `git pull` updates do not conflict:

1. Create the file `docker/docker-compose.override.yml` (git ignores it) with:
   ```yaml
   services:
     thephish:
       ports: !override
         - '127.0.0.1:9443:8080'
   ```
   Replace `9443` with the port you want. The `8080` on the right **does not change**: it is
   the port inside the container.
2. Apply it, from `docker/`:
   ```bash
   docker compose up -d
   ```
3. Open `https://localhost:9443`.

`!override` needs **Docker Compose 2.24 or newer** (check with `docker compose version`).
Without it, the new port is **added** to the old one and both stay open, instead of one
replacing the other.

**Is another Bluephish/ThePhish already on the same computer?** The container is called
`thephish` and the image `thephish-custom:latest`; a second `up` would fight over the name and
a `build` would overwrite the other one's image. Set other names in `docker/.env`:

```bash
BLUEPHISH_CONTAINER=bluephish2
BLUEPHISH_IMAGE=bluephish2:local
```

Then use that name instead of `thephish` in `docker exec` and `docker inspect` commands (the
`docker compose ... thephish` ones use the service name and stay the same).

## How do I access it from another machine?

For safety the port only answers on the machine itself (`127.0.0.1`), and login requires
HTTPS. **Do not** change `127.0.0.1` to `0.0.0.0` to "open it up": that exposes the panel to
the whole network. Two safe ways:

- **SSH tunnel** (the simplest, changes nothing in Bluephish). On the machine you want to
  access it from:
  ```bash
  ssh -L 8080:127.0.0.1:8080 user@bluephish-server
  ```
  Leave the command open and browse to `https://localhost:8080` on that machine.
- **A reverse proxy with TLS** in front, for continuous use by several analysts. If you use
  SSO in that setup, set `BLUEPHISH_BASE_URL` in `docker/.env` to the public address (see the
  comments in `docker/.env.example`). Also read [Security notes](security.md).

## How do I use an Ollama running on my machine on Linux?

On Docker Desktop (Windows and macOS) the name `host.docker.internal` already points to your
machine. On **Linux** it does not exist by default:

1. Create (or edit) `docker/docker-compose.override.yml`:
   ```yaml
   services:
     thephish:
       extra_hosts:
         - "host.docker.internal:host-gateway"
   ```
2. Make Ollama accept connections coming from Docker. By default it listens only on
   `127.0.0.1`, which the container cannot reach; start it with the variable
   `OLLAMA_HOST=0.0.0.0`.
3. Apply with `docker compose up -d` and, in **Configurações → IA**, use the endpoint
   `http://host.docker.internal:11434/api/chat`.

## How do I update to a new version?

From the repository root:

```bash
git pull --ff-only
cd docker
docker compose up -d --build thephish
```

The `--build` is needed: a plain `restart` starts the **old** image. Your data in
`docker/vol/` and your credentials are kept.

A `docker-compose.override.yml`, if you have one, is ignored by git and stays in force; `up
-d --build` applies both. `whitelist.json` is also written by the application: if the abort
names that file, use the same procedure below with that name, then re-import your rules in
the interface (Whitelist → Import) from the copy you kept.

**If `git pull` aborts** with `Your local changes to the following files would be overwritten
by merge: docker/thephish_conf_files/configuration.json`, it is because the new version also
changed that file, which holds your credentials. This is rare and has a fix that loses
nothing. From the repository root:

```bash
F=docker/thephish_conf_files/configuration.json
cp $F ../configuration.backup.json     # 1. keep your credentials, OUTSIDE the repository
git update-index --no-skip-worktree $F # 2. release the file
git checkout -- $F                     #    discard the local copy (the backup is saved)
git pull --ff-only                     # 3. update
git update-index --skip-worktree $F    # 4. lock the file again
```

5. **Put your credentials back** on top of the new file, keeping the version's new keys (use
   `python` instead of `python3` on Windows):
   ```bash
   python3 - <<'EOF'
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
   EOF
   ```
6. Rebuild: `cd docker && docker compose up -d --build thephish`.

## How do I back up and restore?

What matters lives in four places: `docker/vol/` (database, audit trail, stored messages,
TLS keys), `docker/thephish_conf_files/` (`configuration.json` and `whitelist.json`, the
analysts' rules), `docker/.env` (the session key) and, if you created it,
`docker/docker-compose.override.yml` (port, names).

**Back up**, from the repository root. Stop the application first so the database is
consistent:

```bash
cd docker && docker compose stop thephish && cd ..
tar czf bluephish-backup-$(date +%F).tar.gz docker/vol docker/thephish_conf_files docker/.env $(ls docker/docker-compose.override.yml 2>/dev/null)
cd docker && docker compose start thephish
```

**Restore**, on a fresh installation (after `git clone`), from the repository root:

```bash
tar xzf bluephish-backup-YYYY-MM-DD.tar.gz
./setup.sh
```

`setup.sh` does not overwrite what is already configured, so it just starts Bluephish with
the restored data. Keep the backup file off the machine: it contains credentials.

## Where are the data and the logs?

- **Data:** `docker/vol/thephish_data/`, on your computer. It holds the `thephish.db`
  database (users, analysts' decisions, history), `auth.log` (the audit trail), the TLS pair,
  the original messages (`originals/`), rendered screens (`rendered/`), the files written by
  the Disk destination (`analises/`) and your YARA rules (`yara/`).
- **Application log:** `docker compose logs -f thephish`.
- **Audit trail:** `docker compose exec thephish tail -F /root/thephish/data/auth.log` (if
  you set a folder under **Configurações → Auditoria**, the file lives inside it).

## How do I create a user, change a password or unlock an account?

Through the interface, a `global_admin` does it in **ADMINISTRAÇÃO → Usuários**. From the
command line, from `docker/`:

```bash
docker compose exec thephish python3 manage.py create-user               # new user, any role
docker compose exec thephish python3 manage.py list-users
docker compose exec thephish python3 manage.py reset-password NAME
docker compose exec thephish python3 manage.py reset-mfa NAME            # lost or replaced phone
docker compose exec thephish python3 manage.py unlock NAME               # account locked by failed attempts
```

Each command asks for what is missing (password, role) and never shows the password on screen.

## How do I stop, start and remove everything?

From `docker/`:

```bash
docker compose stop thephish      # stops; the data stays
docker compose start thephish     # starts again
docker compose restart thephish   # restarts (does not reread docker/.env; for that use `up -d`)
docker compose down               # removes the container; data in vol/ stays
```

To delete **everything**, data included (**no way back**; back up first): run `docker compose
down`, delete the `docker/vol/` folder and, if you want, the image with `docker image rm
thephish-custom:latest`.

## How do I change the session key?

The key signs the session cookie. To change it (for example if you suspect it leaked):

1. Generate a new one: `openssl rand -base64 48`.
2. Paste it after `THEPHISH_SECRET_KEY=` in the `docker/.env` file.
3. Recreate the container: `docker compose up -d`. (`restart` does **not** reread `.env`.)

Everyone is signed out and has to sign in again.

## Why is the service called `thephish`?

It is a historical name, kept in the commands for compatibility: the service and the
container in Docker, the `THEPHISH_SECRET_KEY` variable and the `docker/thephish_conf_files/`
folder. Renaming them would break existing installations. The product, on screen and in the
documentation, is **Bluephish**.

## Do I need TheHive, Jira or an LLM?

**No.** The minimum for Bluephish to work is a connected mailbox. Verdicts are written to
disk by default, and the reputation analyzers run inside it. The LLM adds the
social-engineering assessment, and TheHive and Jira are optional destinations to record
verdicts elsewhere. See [Configuration](configuration.md) and
[Optional integrations](integrations.md).
