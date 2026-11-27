# frontend: o salto que confere a API por TLS interno. O HTML e os arquivos
# estáticos vêm dela: o token de CSRF, o reCAPTCHA e a versão dos arquivos são do
# servidor. Ver docker/frontend/nginx.conf
FROM nginx:1.27-alpine
ENV BLUEPHISH_WATCH_FILES="/etc/nginx/trust/ca.pem"
COPY nginx/reload-on-change.sh /usr/local/bin/reload-on-change.sh
COPY nginx/40-bluephish-wait-and-watch.sh /docker-entrypoint.d/40-bluephish-wait-and-watch.sh
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
RUN chmod +x /usr/local/bin/reload-on-change.sh /docker-entrypoint.d/40-bluephish-wait-and-watch.sh
