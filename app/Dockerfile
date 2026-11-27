# BluePhish image, built from a plain Python base.
#
# It used to be built FROM emalderson/thephish:latest, the image of the project
# this one was forked from, and only layered the customizations on top. That made
# a third-party image, outside this repository's control, the source of the
# interpreter, of libmagic and of every pinned dependency. Everything that came
# from it is now stated here: the Python base, the system packages, and
# app/requirements.txt as the package set.
#
# Python 3.14 on Debian 13 (trixie), pinned by digest: a tag can be moved, a
# digest cannot, and Dependabot (docker) bumps the digest within 3.14. 3.14 and
# not 3.15 on purpose: the newest minor is weeks old and the wheels of the
# compiled dependencies arrive months after it; 3.14 has had a year of patch
# releases and has security support until 2030. Moving to the next minor is a
# migration of its own (docs/devsecops.md), not a Dependabot bump.
FROM python:3.14-slim-trixie@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b

WORKDIR /root/thephish

# Python buffers stdout when it is not a tty, so every print() the application
# makes — including the error paths that log a traceback — sat in a buffer and
# never reached `docker logs`. An analyzer failing was invisible from outside
# the container, which is precisely when the log is needed.
ENV PYTHONUNBUFFERED=1

# What the application needs from the system at run time:
# - libmagic1t64  python-magic loads it through ctypes; without it `import magic`
#              raises, and with it goes the listing of the mailbox (trixie's name
#              for libmagic1, after the 64-bit time_t transition)
# - openssl    generates the self-signed certificate on first start: the session
#              cookie is issued with the Secure flag, so the interface must be
#              served over HTTPS for authentication to work at all
# - netbase    owns /etc/protocols, without which socket.getprotobyname('tcp')
#              raises and eventlet cannot even be imported. It is named here and
#              marked manual so that the `--auto-remove` further down cannot
#              take it: on the previous base that cascade removed it and left
#              the application crash-looping on start
# `apt-get upgrade` first: the digest pins the base, and the security fixes
# Debian published after it (openssl, zstd, ...) come in at build time instead
# of waiting for the next digest bump. The image scan in CI is a gate.
RUN apt-get update \
	&& apt-get upgrade -y --no-install-recommends \
	&& apt-get install -y --no-install-recommends libmagic1t64 openssl netbase \
	&& apt-mark manual netbase \
	&& rm -rf /var/lib/apt/lists/*

# The package set is app/requirements.txt, the same file CI installs on Python
# 3.14 — so the combination CI proves is the one the container runs. It is copied
# on its own, ahead of the code, so that editing a module does not invalidate
# this layer and recompile yara-python.
#
# yara-python backs the local YARA analyzer (analyzers.py). There is no manylinux
# wheel for Python 3.14 (the newest is for 3.13), so it is compiled from source: it needs a toolchain and
# the OpenSSL headers, neither of which is wanted in the shipped image. Build and
# purge in one layer — the resulting .so links against the libssl runtime the
# base already carries.
#
# The import at the end is what turns a broken set into a failed build instead of
# a failed deploy: it loads every third-party module the application imports
# (yara and magic are the two that load a system library), and resolves
# 'tcp' the way eventlet does on start.
#
# pip leaves the image with the build: nothing installs packages at run time,
# and its vendored copies of urllib3, msgpack and setuptools age with the base
# (they were the only HIGH findings of the image scan on the base alone).
COPY requirements.txt /tmp/requirements.txt
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential libssl-dev \
	&& pip3 install --no-cache-dir -r /tmp/requirements.txt \
	&& apt-get purge -y --auto-remove build-essential libssl-dev \
	&& rm -rf /var/lib/apt/lists/* /tmp/requirements.txt \
	&& python3 -c "import bcrypt, bs4, emoji, eventlet, flask, flask_limiter, flask_login, flask_socketio, flask_wtf, ioc_finder, magic, msal, psycopg2, pyotp, qrcode, requests, sqlalchemy, thehive4py, yara, socket; socket.getprotobyname('tcp')" \
	&& python3 -m pip uninstall -y pip

# The application code (Python modules, templates and static assets)
COPY . /root/thephish/

# The user database, the audit log and the TLS key pair live here; the directory
# is bind-mounted in the compose file so they survive a rebuild
RUN mkdir -p /root/thephish/data

EXPOSE 8080

# The login page is the one route that answers without a session, is not rate
# limited and writes nothing to the audit trail, and rendering it goes through
# Flask, the templates and the user database. The certificate is not verified:
# on a default installation it is the self-signed pair generated on first start.
# Health is reported, not acted on — nothing restarts the container because of it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
	CMD python3 -c "import os, ssl, urllib.request; host = os.environ.get('BLUEPHISH_LISTEN_ADDRESS') or '0.0.0.0'; host = '127.0.0.1' if host == '0.0.0.0' else host; urllib.request.urlopen('https://' + host + ':8080/login', context = ssl._create_unverified_context(), timeout = 4)" || exit 1

CMD ["python3", "thephish_app.py"]
