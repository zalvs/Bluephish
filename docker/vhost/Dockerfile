# vhost: a porta de entrada. TLS público e cabeçalhos de segurança; repassa
# tudo ao frontend pela rede edge. Ver docker/vhost/nginx.conf
FROM nginx:1.29-alpine
ENV BLUEPHISH_WATCH_FILES="/etc/nginx/certs/fullchain.pem /etc/nginx/certs/privkey.pem"
ENV BLUEPHISH_HTTPS_PORT=443
COPY nginx/reload-on-change.sh /usr/local/bin/reload-on-change.sh
COPY nginx/40-bluephish-wait-and-watch.sh /docker-entrypoint.d/40-bluephish-wait-and-watch.sh
# Template: o entrypoint da imagem o grava em conf.d/default.conf com a porta
COPY vhost/default.conf.template /etc/nginx/templates/default.conf.template
RUN chmod +x /usr/local/bin/reload-on-change.sh /docker-entrypoint.d/40-bluephish-wait-and-watch.sh
