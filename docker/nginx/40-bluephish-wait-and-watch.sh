#!/bin/sh
# Roda pelo entrypoint da imagem oficial do nginx, antes de ele subir. Os
# certificados são gerados pela API na primeira subida (app/cert_store.py): até
# eles existirem o nginx não teria o que carregar, então espera. Depois deixa o
# vigia de recarga rodando ao lado.
set -u
for file in $BLUEPHISH_WATCH_FILES; do
	waited=0
	until [ -s "$file" ]; do
		[ "$waited" -eq 0 ] && echo "bluephish: esperando $file (a API gera na primeira subida)"
		waited=$((waited + 1))
		sleep 2
	done
done
/usr/local/bin/reload-on-change.sh $BLUEPHISH_WATCH_FILES &
