#!/usr/bin/env bash
#
# BluePhish - first-run setup.
#
# Prepares everything that a fresh clone is missing and starts the application:
#   1. creates docker/.env and the vault master key (docker/secrets/master.key)
#   2. protects the config file that receives live secrets at runtime
#   3. builds and starts the container
#   4. waits for the web interface and points you at the admin bootstrap
#
# Safe to re-run: nothing already configured is overwritten.

set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(pwd)"
ENV_FILE="docker/.env"
SERVICE="bluephish"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[0;32mok\033[0m %s\n' "$1"; }
warn() { printf '    \033[0;33m!\033[0m  %s\n' "$1"; }

# --- 0. prerequisites -------------------------------------------------------
say "Checking prerequisites"
command -v docker >/dev/null 2>&1 || { echo "docker is required but was not found in PATH."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the 'docker compose' plugin is required (Docker Desktop or docker-compose-plugin)."; exit 1; }
# `docker info` fails for two unrelated reasons, and telling somebody to "start
# Docker" when it is running and merely not theirs to talk to sends them looking
# in the wrong place. The daemon's own message says which one it is.
if ! DOCKER_ERROR="$(docker info 2>&1 >/dev/null)"; then
	if grep -qi 'permission denied' <<< "$DOCKER_ERROR"; then
		echo "Docker is running, but this user ($(id -un)) may not talk to it: permission denied on the Docker socket."
		echo "Either run this script with sudo (sudo ./setup.sh, and sudo in front of the docker commands afterwards),"
		echo "or add the user to the 'docker' group and log in again (sudo usermod -aG docker $(id -un))."
		echo "Membership of that group is equivalent to root on this machine."
	else
		echo "the Docker daemon is not reachable. Start Docker and re-run."
		echo "docker info said: ${DOCKER_ERROR}"
	fi
	exit 1
fi
ok "docker and the compose plugin are available"

# --- 1. environment file ----------------------------------------------------
say "Preparing $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
	cp docker/.env.example "$ENV_FILE"
	ok "created from .env.example"
fi

# A chave mestra do cofre de segredos (app/secret_vault.py): os segredos da
# configuração e a chave que assina o cookie de sessão ficam cifrados no banco
# com ela. Mora fora de docker/vol/ de propósito — um backup do volume de dados
# não leva a chave junto — e é montada no contêiner como secret do Docker.
# Gerada só se não existe: uma chave nova apaga o acesso aos segredos já
# cifrados com a anterior.
MASTER_KEY="docker/secrets/master.key"
if [ -s "$MASTER_KEY" ]; then
	ok "$MASTER_KEY already exists (left untouched)"
else
	mkdir -p docker/secrets
	chmod 700 docker/secrets
	( umask 077
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -base64 32 | tr -d '\n' > "$MASTER_KEY"
	else
		docker run --rm python:3.14-slim-trixie python -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode(), end="")' > "$MASTER_KEY"
	fi )
	ok "generated the vault master key in $MASTER_KEY — back it up apart from docker/vol/"
fi
# A senha do PostgreSQL (contêiner db). Mesmo cuidado da chave mestra: gerada
# só se não existe, porque o banco já criado guarda a senha antiga. 0600: o
# entrypoint do Postgres lê o arquivo como root, antes de baixar para o usuário
# postgres, e a API roda como root
DB_PASSWORD="docker/secrets/db.password"
if [ -s "$DB_PASSWORD" ]; then
	ok "$DB_PASSWORD already exists (left untouched)"
else
	mkdir -p docker/secrets
	chmod 700 docker/secrets
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 32 | tr -d '\n' > "$DB_PASSWORD"
	else
		docker run --rm python:3.14-slim-trixie python -c 'import secrets; print(secrets.token_hex(32), end="")' > "$DB_PASSWORD"
	fi
	chmod 600 "$DB_PASSWORD"
	ok "generated the database password in $DB_PASSWORD"
fi
if grep -qE '^THEPHISH_SECRET_KEY=.+' "$ENV_FILE"; then
	warn "THEPHISH_SECRET_KEY is still in $ENV_FILE. With the vault it is no longer needed:"
	warn "the application keeps its own session key, encrypted. Removing it signs everybody out once."
fi

# Run with sudo, the file above is root's and, coming out of mktemp, readable by
# root alone. The checkout belongs to whoever called sudo, and so does its .env:
# left as it was, their next `docker compose` fails on "open docker/.env:
# permission denied", which says nothing about what is actually missing (sudo).
if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
	chown "$SUDO_UID:$SUDO_GID" "$ENV_FILE"
	chown -R "$SUDO_UID:$SUDO_GID" docker/secrets
fi

# --- 2. protect the file that will hold live secrets ------------------------
# The file is tracked (so a clone gets a working template) but the running
# application writes real credentials into it. skip-worktree keeps those
# runtime secrets from ever being staged by a `git add`.
say "Protecting the runtime configuration file"
LIVE_CONFIG="docker/thephish_conf_files/configuration.json"
if git -C "$REPO_ROOT" ls-files --error-unmatch "$LIVE_CONFIG" >/dev/null 2>&1; then
	git -C "$REPO_ROOT" update-index --skip-worktree "$LIVE_CONFIG" 2>/dev/null && ok "skip-worktree: $LIVE_CONFIG"
fi

# --- 3. build and start -----------------------------------------------------
# An installation made while TheHive and MISP shipped in this compose file still
# has the application's container under its old name, holding port 8080.
# Starting next to it fails with "port is already allocated". Replacing it also
# stops TheHive and MISP, and that is not this script's decision to make.
#
# The names are read into a variable first: `docker ps | grep -q` under pipefail
# can report "no match" when grep exits before docker finishes writing.
EXISTING_CONTAINERS="$(docker ps -a --format '{{.Names}}')"
if grep -qx 'thephish' <<< "$EXISTING_CONTAINERS" \
	&& [ -z "$( cd docker && docker compose ps -aq "$SERVICE" 2>/dev/null )" ]; then
	warn "this installation was made with the previous stack (containers thephish, thehive, misp...)."
	warn "Follow 'Atualizando de uma instalação com TheHive e MISP' in docker/README.md:"
	warn "the upgrade stops those containers, and when to do it is yours to decide."
	exit 1
fi

say "Building and starting BluePhish (the first build compiles yara-python; allow a few minutes)"
( cd docker && docker compose up -d --build )

# --- 4. wait for the interface ----------------------------------------------
say "Waiting for the web interface on https://localhost (the vhost)"
deadline=$(( $(date +%s) + 300 ))
until curl -sk -m 3 -o /dev/null "https://localhost:${BLUEPHISH_HTTPS_PORT:-443}/login" 2>/dev/null; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		warn "not up after 5 minutes. Check the logs with:  docker logs $SERVICE"
		exit 1
	fi
	sleep 5
done
ok "BluePhish is responding"

# --- 5. next step -----------------------------------------------------------
# The container name is resolved from compose rather than hardcoded: a local
# docker-compose.override.yml may rename the container
CONTAINER="$( cd docker && docker compose ps -q "$SERVICE" 2>/dev/null | head -1 )"
CONTAINER_NAME="$( docker inspect --format '{{.Name}}' "$CONTAINER" 2>/dev/null | sed 's|^/||' )"
CONTAINER_NAME="${CONTAINER_NAME:-$SERVICE}"

# `grep -c` prints the count even when it is zero, and exits 1 when it is: an
# `|| echo 0` here printed a second zero, and "0\n0" is not a number — the test
# below failed with "integer expression expected" on every fresh installation.
USER_COUNT="$( docker exec "$CONTAINER_NAME" python3 manage.py list-users 2>/dev/null | grep -cE '^[0-9]+' || true )"

# Whoever ran this with sudo needs sudo in front of docker too
DOCKER="docker"
if [ -n "${SUDO_USER:-}" ]; then
	DOCKER="sudo docker"
fi

if [ "${USER_COUNT:-0}" -gt 0 ]; then
	say "Setup complete"
	printf '    Users already exist. Sign in at https://localhost\n\n'
else
	say "Setup complete - one manual step left"
	printf '    There is deliberately no default account. Create the first administrator\n'
	printf '    (you will be prompted for a password, which is never echoed or logged):\n\n'
	printf '        %s exec -it %s python3 manage.py create-admin\n\n' "$DOCKER" "$CONTAINER_NAME"
	printf '    Then open https://localhost and accept the self-signed certificate (or install a real one in Configurações → Certificados)\n'
	printf '    warning once (the session cookie requires HTTPS).\n\n'
fi
