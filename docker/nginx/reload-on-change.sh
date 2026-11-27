#!/bin/sh
# Recarrega o nginx quando um dos arquivos que ele lê muda (o certificado que a
# tela de certificados trocou). Sem socket do Docker: o próprio contêiner confere
# o hash a cada 30 s e só recarrega se a configuração nova passa no `nginx -t` —
# um par ruim deixa o nginx com o anterior, e o erro vai para o log.
set -u
files="$*"
digest() { cat $files 2>/dev/null | md5sum; }
last="$(digest)"
while sleep "${RELOAD_EVERY_SECONDS:-30}"; do
	now="$(digest)"
	[ "$now" = "$last" ] && continue
	if nginx -t >/dev/null 2>&1; then
		nginx -s reload && last="$now" && echo "bluephish: certificado mudou, nginx recarregado"
	else
		echo "bluephish: certificado novo recusado pelo nginx -t; segue o anterior" >&2
		nginx -t
		last="$now"
	fi
done
