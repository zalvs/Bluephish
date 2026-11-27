# Dúvidas gerais

**Português (Brasil)** · [English](en/faq.md)

Respostas para "como eu faço X?". Cada uma traz o passo a passo completo. Se algo **deu
errado**, o lugar é a [Solução de problemas](solucao-de-problemas.md), que lista os sintomas.

Os comandos `docker compose` rodam a partir do diretório `docker/` do repositório.

- [Como troco o certificado HTTPS?](#como-troco-o-certificado-https)
- [Como mudo a porta?](#como-mudo-a-porta)
- [Como acesso de outra máquina?](#como-acesso-de-outra-máquina)
- [Como uso um Ollama que roda na minha máquina no Linux?](#como-uso-um-ollama-que-roda-na-minha-máquina-no-linux)
- [Como atualizo para uma versão nova?](#como-atualizo-para-uma-versão-nova)
- [Como faço backup e restauro?](#como-faço-backup-e-restauro)
- [Onde ficam os dados e os logs?](#onde-ficam-os-dados-e-os-logs)
- [Como crio um usuário, troco uma senha ou desbloqueio uma conta?](#como-crio-um-usuário-troco-uma-senha-ou-desbloqueio-uma-conta)
- [Como paro, religo e removo tudo?](#como-paro-religo-e-removo-tudo)
- [Como troco a chave de sessão?](#como-troco-a-chave-de-sessão)
- [Por que ainda aparece `thephish`?](#por-que-ainda-aparece-thephish)
- [Preciso do TheHive, do Jira ou de um LLM?](#preciso-do-thehive-do-jira-ou-de-um-llm)

## Como troco o certificado HTTPS?

Na 2.0 o certificado público é o do **vhost** (o nginx na frente de tudo), e ele é trocado
pela interface: **Configurações → Certificados**. Lá você envia um par PEM, um PFX ou pede um
certificado ao Let's Encrypt, e o vhost recarrega sozinho em até 30 segundos. Na primeira
subida ele usa um autoassinado, e por isso o navegador avisa.

Detalhes que importam:

- **Let's Encrypt** precisa da porta 80 alcançável pela internet: defina `BLUEPHISH_BIND=0.0.0.0`
  em `docker/.env` e aplique com `docker compose up -d`.
- Os certificados ficam em `docker/vol/certs/` e sobrevivem a reconstruções da imagem.
- **Saída de emergência:** se um certificado errado deixar a tela fora de alcance, troque o par
  pelo terminal, a partir de `docker/` (os arquivos precisam estar dentro do contêiner):
  ```bash
  docker cp certificado.pem bluephish:/tmp/cert.pem
  docker cp chave.pem       bluephish:/tmp/key.pem
  docker compose exec bluephish python3 manage.py cert-import /tmp/cert.pem /tmp/key.pem
  ```
- **Confira** qual certificado o servidor passou a apresentar:
  ```bash
  openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```
- Entre o vhost, o frontend e a API o tráfego também é TLS, com uma CA interna que a própria
  API gera na primeira subida. Ela não tem relação com o certificado público.

## Como mudo a porta?

O vhost publica as portas **443** (HTTPS) e **80**, ligadas só a `127.0.0.1`. Para trocar as
portas do host, sem editar o `docker-compose.yml`, defina em `docker/.env`:

```bash
BLUEPHISH_HTTPS_PORT=9443
BLUEPHISH_HTTP_PORT=9080
```

Aplique a partir de `docker/` com `docker compose up -d` e abra `https://localhost:9443`.
O `setup.sh` lê a mesma variável para esperar a interface.

**Vindo da 1.x?** A porta 8080 deixou de existir: o painel passa a responder no vhost. Um
`docker-compose.override.yml` antigo que mexia nas `ports` do serviço `thephish` não vale mais
e deve ser removido ou reescrito.

## Como acesso de outra máquina?

Por segurança as portas só respondem na própria máquina (`127.0.0.1`), e o login exige HTTPS.
Três caminhos:

- **Túnel SSH** (o mais simples, sem mudar nada no Bluephish). Na máquina de onde você quer
  acessar:
  ```bash
  ssh -L 8443:127.0.0.1:443 usuario@servidor-do-bluephish
  ```
  Deixe o comando aberto e acesse `https://localhost:8443` nessa máquina.
- **Abrir o vhost para a rede:** `BLUEPHISH_BIND=0.0.0.0` em `docker/.env`, com um certificado
  de verdade (veja acima), firewall restringindo quem chega e `BLUEPHISH_BASE_URL` com o
  endereço público se você usa SSO.
- **Proxy reverso seu na frente do vhost:** liste-o em `BLUEPHISH_TRUSTED_PROXIES`, junto das
  endereços do vhost e do frontend (o padrão é `172.30.10.10/32,172.30.11.20/32`). Leia também a [Segurança](seguranca.md).

## Como uso um Ollama que roda na minha máquina no Linux?

No Docker Desktop (Windows e macOS), o nome `host.docker.internal` já aponta para a sua
máquina. No **Linux** ele não existe por padrão:

1. Crie (ou edite) o `docker/docker-compose.override.yml`:
   ```yaml
   services:
     bluephish:
       extra_hosts:
         - "host.docker.internal:host-gateway"
   ```
2. Faça o Ollama aceitar conexões vindas do Docker. Por padrão ele escuta só em `127.0.0.1`,
   que o contêiner não alcança; inicie-o com a variável `OLLAMA_HOST=0.0.0.0`.
3. Aplique com `docker compose up -d` e, em **Configurações → IA**, use o endpoint
   `http://host.docker.internal:11434/api/chat`.

## Como atualizo para uma versão nova?

Na raiz do repositório, faça um backup (seção abaixo) e então:

```bash
git pull --ff-only
./setup.sh
```

O `setup.sh` só cria o que falta (a chave mestra do cofre e a senha do banco, em
`docker/secrets/`), não sobrescreve nada e reconstrói as imagens com `docker compose up -d
--build`. Um simples `restart` sobe a imagem **antiga**.

**Vindo da 1.x (um contêiner só, SQLite)** há passos a mais, descritos no
[CHANGELOG](../CHANGELOG.md#200---2026-11-27) e no [`docker/README.md`](../docker/README.md):
o contêiner antigo `thephish` precisa ser removido antes, e na primeira subida a API copia o
`thephish.db` para o PostgreSQL sozinha, guardando uma cópia do arquivo.

**Se o `git pull` abortar** com `Your local changes to the following files would be overwritten
by merge: docker/thephish_conf_files/configuration.json`, é porque a versão nova também mexeu
nesse arquivo, que guarda as suas credenciais. Na raiz do repositório:

```bash
F=docker/thephish_conf_files/configuration.json
cp $F ../configuration.backup.json     # 1. guarda suas credenciais, FORA do repositório
git update-index --no-skip-worktree $F # 2. libera o arquivo
git checkout -- $F                     #    descarta a cópia local (o backup está salvo)
git pull --ff-only                     # 3. atualiza
git update-index --skip-worktree $F    # 4. trava o arquivo de novo
```

5. **Devolva as suas credenciais** por cima do arquivo novo, mantendo as chaves novas da
   versão (use `python` no lugar de `python3` no Windows):
   ```bash
   python3 - <<'PYEOF'
   import json
   def juntar(base, meu):
       for chave, valor in meu.items():
           if isinstance(valor, dict) and isinstance(base.get(chave), dict):
               juntar(base[chave], valor)
           else:
               base[chave] = valor
       return base
   caminho = 'docker/thephish_conf_files/configuration.json'
   novo = json.load(open(caminho, encoding='utf-8'))
   meu = json.load(open('../configuration.backup.json', encoding='utf-8'))
   open(caminho, 'w', encoding='utf-8').write(json.dumps(juntar(novo, meu), indent='\t'))
   PYEOF
   ```
6. Rode `./setup.sh` de novo. Na 2.0 os segredos da configuração passam para o cofre
   (`manage.py vault-seal` faz isso à mão).

## Como faço backup e restauro?

O que importa fica em cinco lugares: `docker/vol/` (PostgreSQL em `vol/postgres/`, trilha de
auditoria, mensagens guardadas, certificados), `docker/secrets/` (`master.key`, a chave do
cofre, e `db.password`), `docker/thephish_conf_files/` (`configuration.json` e
`whitelist.json`), `docker/.env` e, se você criou, `docker/docker-compose.override.yml`.

**Guarde `docker/secrets/` num backup separado do de `docker/vol/`:** sem a `master.key` os
segredos cifrados no banco não abrem, e com as duas juntas quem pega um backup pega tudo.

**Backup** do banco, com tudo no ar, a partir de `docker/`:

```bash
docker compose exec db pg_dump -U bluephish bluephish > bluephish-$(date +%F).sql
```

**Backup completo**, na raiz do repositório, com a stack parada:

```bash
( cd docker && docker compose stop )
tar czf bluephish-dados-$(date +%F).tar.gz docker/vol docker/thephish_conf_files docker/.env $(ls docker/docker-compose.override.yml 2>/dev/null)
tar czf bluephish-segredos-$(date +%F).tar.gz docker/secrets
( cd docker && docker compose start )
```

**Restauro**, numa instalação nova (depois do `git clone`), na raiz do repositório: extraia os
dois arquivos e rode `./setup.sh`. Ele não sobrescreve o que já existe, então só sobe a stack
com os dados restaurados. Guarde os backups fora da máquina: eles contêm credenciais.

## Onde ficam os dados e os logs?

- **Banco:** PostgreSQL no contêiner `db`, com os dados em `docker/vol/postgres/` (usuários,
  decisões dos analistas, histórico, memória de vereditos, o cofre).
- **Arquivos:** `docker/vol/thephish_data/`: o `auth.log` (trilha de auditoria), as mensagens
  originais (`originals/`), as telas renderizadas (`rendered/`), os arquivos gravados pelo
  destino Disco (`analises/`), as suas regras YARA (`yara/`) e, depois da migração da 1.x, o
  `thephish.db` antigo com a cópia `.pre-postgres-<data>.bak`.
- **Certificados:** `docker/vol/certs/`.
- **Logs:** `docker compose logs -f bluephish` (a API), `vhost`, `frontend` e `db` para os demais.
- **Trilha de auditoria:** `docker compose exec bluephish tail -F /root/thephish/data/auth.log`
  (se você definiu uma pasta em **Configurações → Auditoria**, o arquivo fica dentro dela).

## Como crio um usuário, troco uma senha ou desbloqueio uma conta?

Pela interface, um `global_admin` faz isso em **ADMINISTRAÇÃO → Usuários**. Pela linha de
comando, a partir de `docker/`:

```bash
docker compose exec bluephish python3 manage.py create-user               # novo usuário, qualquer papel
docker compose exec bluephish python3 manage.py list-users
docker compose exec bluephish python3 manage.py reset-password NOME
docker compose exec bluephish python3 manage.py reset-mfa NOME            # celular perdido ou trocado
docker compose exec bluephish python3 manage.py unlock NOME               # conta bloqueada por tentativas
```

Cada comando pede o que falta (senha, papel) e nunca mostra a senha na tela. O último
`global_admin` ativo não pode ser rebaixado, desativado nem excluído.

## Como paro, religo e removo tudo?

A partir de `docker/`:

```bash
docker compose stop        # para a stack; os dados ficam
docker compose start       # religa
docker compose restart     # reinicia (não relê o docker/.env; para isso use `up -d`)
docker compose down        # remove os contêineres; os dados em vol/ e secrets/ ficam
```

Para apagar **tudo**, inclusive os dados (**sem volta**; faça backup antes): rode `docker compose
down`, apague `docker/vol/` e `docker/secrets/` e, se quiser, as imagens `bluephish`,
`bluephish-frontend` e `bluephish-vhost`.

## Como troco a chave de sessão?

Na 2.0 a chave que assina a sessão (um JWT estrito, revogável pelo `jti`) é gerada pela própria
aplicação e guardada **cifrada no cofre**, com a chave mestra `docker/secrets/master.key`. O
`THEPHISH_SECRET_KEY` do `docker/.env` deixou de ser necessário: se ainda estiver lá, o
`setup.sh` avisa, e removê-lo desloga todo mundo uma vez.

Se você suspeitar que a `master.key` vazou, trate os segredos guardados no cofre (chaves de API,
senhas de destinos) como expostos e troque-os na origem.

## Por que ainda aparece `thephish`?

São nomes históricos, mantidos por compatibilidade: o caminho `/root/thephish` dentro do
contêiner, a pasta `docker/thephish_conf_files/` e `docker/vol/thephish_data/`. Na 2.0 os
serviços e contêineres passaram a se chamar `bluephish`, `bluephish-db`, `bluephish-frontend`
e `bluephish-vhost`. O produto, na tela e na documentação, é o **Bluephish**.

## Preciso do TheHive, do Jira ou de um LLM?

**Não.** O mínimo para o Bluephish funcionar é uma caixa de e-mail conectada. Os vereditos
são gravados em disco por padrão, e os analisadores de reputação rodam dentro dele. O LLM
acrescenta a avaliação de engenharia social, e o TheHive e o Jira são destinos opcionais para
registrar os vereditos em outro lugar. Veja a [Configuração](configuracao.md) e as
[Integrações opcionais](integracoes/thehive.md).
