#!/usr/bin/env bash
#
# Bluephish - first-run setup.
#
# Prepares everything that a fresh clone is missing and starts Bluephish:
#   1. creates docker/.env with a freshly generated session signing key
#   2. protects the config file that receives live secrets at runtime
#   3. builds and starts the container
#   4. waits for the web interface and points you at the admin bootstrap
#
# Option:
#   --with-integrations   also prepares and starts TheHive and MISP
#                         (docs/integracoes.md). They are heavy
#                         (about 6 GB of RAM) and Bluephish does not need them.
#
# Safe to re-run: nothing already configured is overwritten.

set -euo pipefail

WITH_INTEGRATIONS=0
for arg in "$@"; do
	case "$arg" in
		--with-integrations) WITH_INTEGRATIONS=1 ;;
		-h|--help) sed -n '3,17p' "$0"; exit 0 ;;
		*) echo "unknown option: $arg (try --help)"; exit 2 ;;
	esac
done

# The compose files to use, always from inside docker/. Without -f, Compose reads
# docker-compose.yml and merges a local docker-compose.override.yml on its own;
# once -f is given it stops doing that, so the override is added back by hand.
COMPOSE_FILES=()
if [ "$WITH_INTEGRATIONS" = 1 ]; then
	COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.integrations.yml)
	if [ -f docker/docker-compose.override.yml ]; then
		COMPOSE_FILES+=(-f docker-compose.override.yml)
	fi
fi

cd "$(dirname "$0")"
REPO_ROOT="$(pwd)"
ENV_FILE="docker/.env"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[0;32mok\033[0m %s\n' "$1"; }
warn() { printf '    \033[0;33m!\033[0m  %s\n' "$1"; }

# --- 0. prerequisites -------------------------------------------------------
say "Checking prerequisites"
command -v docker >/dev/null 2>&1 || { echo "docker is required but was not found in PATH."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the 'docker compose' plugin is required (Docker Desktop or docker-compose-plugin)."; exit 1; }
docker info >/dev/null 2>&1 || { echo "the Docker daemon is not reachable. Start Docker and re-run."; exit 1; }
ok "docker and the compose plugin are available"

# --- 1. environment file ----------------------------------------------------
say "Preparing $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
	cp docker/.env.example "$ENV_FILE"
	ok "created from .env.example"
fi

# Generate the session signing key only if it is still empty, so re-running
# never invalidates existing sessions
if grep -qE '^THEPHISH_SECRET_KEY=.+' "$ENV_FILE"; then
	ok "THEPHISH_SECRET_KEY already set (left untouched)"
else
	if command -v openssl >/dev/null 2>&1; then
		KEY="$(openssl rand -base64 48 | tr -d '\n')"
	else
		KEY="$(docker run --rm python:3.8-slim python -c 'import secrets; print(secrets.token_urlsafe(48))')"
	fi
	# Portable in-place edit (GNU and BSD sed disagree on -i)
	tmp="$(mktemp)"
	sed "s|^THEPHISH_SECRET_KEY=.*|THEPHISH_SECRET_KEY=${KEY}|" "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
	ok "generated a random THEPHISH_SECRET_KEY (sessions now survive restarts)"
fi

# --- 1b. TheHive session signing key (integrations only) ---------------------
# Play signs TheHive's session cookies with it. The repository ships a
# placeholder on purpose: a key committed to a public repository is a key
# everybody already has, and TheHive is reachable on port 9000.
THEHIVE_CONF="docker/thehive/application.conf"
if [ "$WITH_INTEGRATIONS" = 1 ]; then
	say "Preparing the TheHive session key"
	if grep -q 'CHANGEME_GENERATED_BY_SETUP' "$THEHIVE_CONF" 2>/dev/null; then
		if command -v openssl >/dev/null 2>&1; then
			HIVE_KEY="$(openssl rand -hex 32)"
		else
			HIVE_KEY="$(docker run --rm python:3.8-slim python -c 'import secrets; print(secrets.token_hex(32))')"
		fi
		tmp="$(mktemp)"
		sed "s|CHANGEME_GENERATED_BY_SETUP|${HIVE_KEY}|" "$THEHIVE_CONF" > "$tmp" && mv "$tmp" "$THEHIVE_CONF"
		ok "generated a random play.http.secret.key for TheHive"
	else
		ok "TheHive already has its own signing key (left untouched)"
	fi
fi

# --- 2. protect the files that will hold live secrets -----------------------
# These files are tracked (so a clone gets a working template) but the running
# application writes real credentials into them. skip-worktree keeps those
# runtime secrets from ever being staged by a `git add`.
say "Protecting the runtime configuration files"
PROTECTED_FILES=(docker/thephish_conf_files/configuration.json)
if [ "$WITH_INTEGRATIONS" = 1 ]; then
	PROTECTED_FILES+=("$THEHIVE_CONF")
fi
for f in "${PROTECTED_FILES[@]}"; do
	if git -C "$REPO_ROOT" ls-files --error-unmatch "$f" >/dev/null 2>&1; then
		git -C "$REPO_ROOT" update-index --skip-worktree "$f" 2>/dev/null && ok "skip-worktree: $f"
	fi
done

# --- 3. build and start -----------------------------------------------------
if [ "$WITH_INTEGRATIONS" = 1 ]; then
	say "Building and starting Bluephish and the integrations (first run downloads several GB)"
else
	say "Building and starting Bluephish (the first run downloads the base image)"
fi
( cd docker && docker compose ${COMPOSE_FILES[@]+"${COMPOSE_FILES[@]}"} up -d --build )

# --- 4. wait for the interface ----------------------------------------------
say "Waiting for the web interface on https://localhost:8080"
deadline=$(( $(date +%s) + 300 ))
until curl -sk -m 3 -o /dev/null https://localhost:8080/login 2>/dev/null; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		warn "not up after 5 minutes. Check the logs with:  docker logs thephish"
		exit 1
	fi
	sleep 5
done
ok "Bluephish is responding"

# --- 5. next step -----------------------------------------------------------
# The container name is resolved from compose rather than hardcoded: a local
# docker-compose.override.yml may rename the containers (e.g. to thp-thephish)
CONTAINER="$( cd docker && docker compose ${COMPOSE_FILES[@]+"${COMPOSE_FILES[@]}"} ps -q thephish 2>/dev/null | head -1 )"
CONTAINER_NAME="$( docker inspect --format '{{.Name}}' "$CONTAINER" 2>/dev/null | sed 's|^/||' )"
CONTAINER_NAME="${CONTAINER_NAME:-thephish}"

if [ "$( docker exec "$CONTAINER_NAME" python3 manage.py list-users 2>/dev/null | grep -cE '^[0-9]+' || true )" -gt 0 ]; then
	say "Setup complete"
	printf '    Users already exist. Sign in at https://localhost:8080\n\n'
else
	say "Setup complete - one manual step left"
	printf '    There is deliberately no default account. Create the first administrator\n'
	printf '    (you will be prompted for a password, which is never echoed or logged):\n\n'
	printf '        docker exec -it %s python3 manage.py create-admin\n\n' "$CONTAINER_NAME"
	printf '    Then open https://localhost:8080 and accept the self-signed certificate\n'
	printf '    warning once (the session cookie requires HTTPS).\n\n'
fi
