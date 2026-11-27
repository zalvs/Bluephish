# Changelog

Todas as mudanças relevantes do Bluephish ficam aqui. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e as versões seguem o
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [2.0.0] - 2026-11-27

A 2.0 troca a base inteira da instalação: Python 3.14, PostgreSQL e uma stack de quatro
contêineres em redes separadas. **Uma instalação 1.x não atualiza com um `git pull` simples:**
siga [Atualizando da 1.x](#atualizando-da-1x) abaixo.

### Mudanças incompatíveis

- **Python 3.8 → 3.14.** A imagem da API parte de `python:3.14-slim-trixie` fixada por digest,
  com um lock novo de dependências (`app/requirements.txt`). O Python 3.8 estava sem suporte.
- **SQLite → PostgreSQL.** O banco sai do arquivo `thephish.db` e vai para um PostgreSQL 17 em
  contêiner próprio (`db`), numa rede `internal` que só a API alcança. Na primeira subida a API
  copia o `thephish.db` para o PostgreSQL numa transação só, guarda uma cópia
  `thephish.db.pre-postgres-<data>.bak` e grava `thephish.db.migrated` para nunca copiar duas
  vezes. Se a cópia falha, nada é gravado e a API não sobe (`docker logs bluephish` diz por quê).
- **O `setup.sh` gera a senha do banco e a chave mestra do cofre** em `docker/secrets/`
  (`db.password` e `master.key`). Os dois arquivos ficam fora de `docker/vol/`, o git os ignora,
  e devem ir num backup separado do de `docker/vol/`.
- **Um contêiner → quatro.** `vhost` (nginx, as únicas portas publicadas), `frontend` (nginx),
  `bluephish` (a API) e `db` (PostgreSQL). Entre vhost, frontend e API o tráfego é TLS com uma CA
  interna que a API gera na primeira subida.
- **A porta 8080 deixou de existir.** O painel responde em `https://localhost` (443 e 80, ligadas a
  `127.0.0.1` por padrão). `BLUEPHISH_HTTPS_PORT`, `BLUEPHISH_HTTP_PORT` e `BLUEPHISH_BIND` em
  `docker/.env` trocam isso. Um `docker-compose.override.yml` da 1.x que mexia nas `ports` do
  serviço `thephish` não vale mais.
- **Serviços e contêineres renomeados:** o serviço `thephish` virou `bluephish`, e os contêineres
  são `bluephish`, `bluephish-db`, `bluephish-frontend` e `bluephish-vhost`. Os comandos
  `docker compose exec thephish ...` passam a ser `docker compose exec bluephish ...`.
  `BLUEPHISH_CONTAINER` e `BLUEPHISH_IMAGE` saíram do `.env`.
- **`THEPHISH_SECRET_KEY` não é mais necessário.** A sessão é um JWT estrito com a chave guardada
  cifrada no cofre. Se a variável continuar no `.env`, o `setup.sh` avisa; removê-la desloga todo
  mundo uma vez.
- **O `docker-compose.integrations.yml` saiu.** TheHive e MISP são instalados à parte; o TheHive
  continua como destino de registro. Veja [docs/integracoes/thehive.md](docs/integracoes/thehive.md).
- **SSO:** o endereço público muda (o vhost na 443). Defina `BLUEPHISH_BASE_URL` e atualize a
  redirect URI no Entra ID.

### Adicionado

- **Cofre de segredos:** AES-256-GCM com salt por segredo, fora do `configuration.json` e do
  `.env`. Os segredos que ainda estiverem em texto no `configuration.json` são selados na subida
  (`manage.py vault-seal` e `vault-status` fazem isso à mão).
- **Sessão local em JWT estrito**, com revogação no servidor pelo `jti`.
- **Perfis de acesso:** telas, abas e ações por conta, para mais ou para menos que o papel.
- **Auto logoff** configurável, com aviso antes de desligar.
- **Limite de requisições por IP** e banimento de IP, com lista de liberados.
- **reCAPTCHA v3** opcional no login por senha (aba Segurança).
- **Tela de certificados** (Configurações → Certificados): PEM, PFX ou Let's Encrypt, com recarga
  do vhost; `manage.py cert-import` como saída de emergência.
- **Feeds públicos de inteligência** com consulta offline (tela de analisadores).
- **Panorama externo:** coleta de RSS de fontes públicas, classificação, cruzamento com os casos,
  card na Visão Executiva e resumo por IA opcional.
- **Esteira DevSecOps no CI:** gitleaks no histórico inteiro, Bandit, Semgrep, Trivy (SCA, IaC e
  imagem como gate), hadolint, SBOM e ações fixadas por SHA. Veja [docs/devsecops.md](docs/devsecops.md).
- `SECURITY.md`, `CODEOWNERS` e um script de carga e estresse em `loadtest/`.

### Alterado

- **O último `global_admin` local ativo fica travado:** não pode ser rebaixado, desativado nem
  excluído, mesmo com um `global_admin` vindo do SSO.
- **CSP sem `'unsafe-inline'`** em `style-src`, e com `frame-ancestors`, `base-uri`, `object-src`
  e `form-action` fechados. Toda resposta, menos `/static`, sai com `Cache-Control: no-store`.
- `no-new-privileges` nos contêineres.
- O segundo fator tem desafio com prazo de 45 s e 3 tentativas, e pareamento com 2 minutos.
- Ninguém muda o próprio papel.

### Corrigido

- Um e-mail hostil não congela mais o servidor na extração de indicadores, não esgota a cota
  das APIs de reputação e não grava milhares de observáveis no TheHive.
- Chamadas ao Microsoft Graph, ao Exchange Online, ao TheHive, ao LLM e dos analisadores não
  seguem redirect; a paginação do Graph só segue `nextLink` que continua no Graph; o `feedUrl`
  do OpenPhish e o IP do syslog passam pela trava de SSRF; as chamadas da MSAL têm prazo.
- O JWT recusa cabeçalho com campo que a aplicação não emite.
- A sessão não cai quando o relógio recua alguns segundos (VM do Docker Desktop).
- Os achados altos e médios da revisão de segurança da stack.

### Removido

- O `docker-compose.integrations.yml` e o `docker/thehive/application.conf` (veja acima).
- Os diagramas estáticos em `docs/diagramas/`: o [`diagrams.md`](diagrams.md) volta a trazer o
  Mermaid embutido, que o GitHub desenha. Os diagramas de deployment e do modelo de dados ainda
  mostram a stack 1.x (um contêiner, SQLite) e serão redesenhados; para a stack da 2.0 vale o
  [`docker/README.md`](docker/README.md).

### Atualizando da 1.x

Faça na raiz do repositório, na máquina que roda o Bluephish. Comandos para Linux.

1. **Backup**, com a 1.x ainda instalada:
   ```bash
   cd docker && docker compose stop && cd ..
   sudo tar czf ~/bluephish-1x-$(date +%F).tar.gz docker/vol docker/thephish_conf_files docker/.env $(ls docker/docker-compose.override.yml 2>/dev/null)
   ```
2. **Derrube a stack 1.x antes de atualizar** (o compose novo não conhece o serviço `thephish`):
   ```bash
   cd docker && docker compose down && cd ..
   docker ps -a --format '{{.Names}}' | grep -x thephish && docker rm -f thephish
   ```
   Um `docker-compose.override.yml` que mudava a porta ou os nomes da 1.x deve ser removido
   (ou reescrito para o serviço `bluephish`).
3. **Atualize o código:**
   ```bash
   git pull --ff-only
   ```
   Se o `git pull` abortar por causa do `docker/thephish_conf_files/configuration.json`, siga
   [Como atualizo para uma versão nova](docs/duvidas-gerais.md#como-atualizo-para-uma-versão-nova).
4. **Rode o setup:**
   ```bash
   ./setup.sh
   ```
   Ele cria `docker/secrets/master.key` e `docker/secrets/db.password`, constrói as três imagens
   (a primeira compilação do `yara-python` leva alguns minutos) e sobe a stack. Na primeira
   subida a API migra o `thephish.db` para o PostgreSQL e sela os segredos do `configuration.json`
   no cofre.
5. **Confira a migração:**
   ```bash
   cd docker
   docker compose ps                                   # vhost, frontend, bluephish e db em Up
   docker compose logs bluephish | grep -i migra       # "migração do SQLite para o PostgreSQL concluída"
   ls vol/thephish_data/ | grep thephish.db            # .migrated e .pre-postgres-<data>.bak
   ```
   Entre com os mesmos usuários de antes em `https://localhost` (numa VPS, por túnel:
   `ssh -L 8443:127.0.0.1:443 usuario@servidor` e `https://localhost:8443`).
6. **Opcional:** remova `THEPHISH_SECRET_KEY` de `docker/.env` e rode `docker compose up -d`
   (todos são deslogados uma vez). Se usa SSO, defina `BLUEPHISH_BASE_URL` e atualize a redirect
   URI. Para expor o painel, `BLUEPHISH_BIND=0.0.0.0` com um certificado real em
   Configurações → Certificados.
7. **Daqui para frente**, faça backup de `docker/vol/` (ou `docker compose exec db pg_dump -U
   bluephish bluephish`) e, separado, de `docker/secrets/`.

Para voltar à 1.x: `docker compose down`, `git checkout v1.0.0` (ou o commit anterior), restaure o
backup do passo 1 e suba como antes. O `thephish.db` original não é alterado pela migração.

**Diff completo:** [v1.0.0...v2.0.0](https://github.com/zalvs/Bluephish/compare/v1.0.0...v2.0.0)

## [1.0.0] - 2026-10-15

Primeira versão pública: um contêiner, SQLite, Python 3.8, documentação em português com
versão em inglês.

[2.0.0]: https://github.com/zalvs/Bluephish/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/zalvs/Bluephish/releases/tag/v1.0.0
