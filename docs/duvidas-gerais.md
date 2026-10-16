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
- [Por que o serviço se chama `thephish`?](#por-que-o-serviço-se-chama-thephish)
- [Preciso do TheHive, do Jira ou de um LLM?](#preciso-do-thehive-do-jira-ou-de-um-llm)

## Como troco o certificado HTTPS?

O Bluephish já vem com um certificado **autoassinado**, gerado na primeira subida, e por isso
o navegador avisa. Para usar um certificado seu (de uma autoridade certificadora, ou de uma
CA interna):

1. **Tenha os dois arquivos em formato PEM:** o certificado e a chave privada **sem senha**.
   Se o certificado veio com cadeia intermediária, ponha o certificado do servidor e depois as
   intermediárias **no mesmo arquivo**. O certificado precisa ser o **par** da chave: com um
   par errado a aplicação não sobe: confira **antes de copiar** (o comando não imprime nada se
   for um par):
   ```bash
   diff <(openssl x509 -in seu-certificado.pem -noout -pubkey) <(openssl pkey -in sua-chave.pem -pubout) && echo "par OK"
   ```
2. **Guarde os atuais**, para poder voltar:
   ```bash
   cd docker/vol/thephish_data
   cp thephish-cert.pem thephish-cert.pem.bak
   cp thephish-key.pem thephish-key.pem.bak
   ```
3. **Troque os arquivos**, mantendo exatamente estes nomes:
   ```bash
   cp /caminho/do/seu-certificado.pem thephish-cert.pem
   cp /caminho/da/sua-chave.pem       thephish-key.pem
   ```
4. **Reinicie** (a partir de `docker/`):
   ```bash
   cd ../..
   docker compose restart thephish
   ```
5. **Confira** qual certificado o servidor passou a apresentar:
   ```bash
   openssl s_client -connect localhost:8080 </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
   ```
   A linha `subject` deve mostrar o nome do **seu** certificado.

Detalhes que importam:

- O Bluephish **só gera** o certificado de fábrica quando os **dois** arquivos não existem.
  Com os seus no lugar, ele nunca os sobrescreve.
- **Para voltar ao certificado de fábrica:** apague `thephish-cert.pem` e `thephish-key.pem` e
  reinicie; um novo autoassinado é gerado.
- Os arquivos ficam no seu computador, em `docker/vol/thephish_data/`, e sobrevivem a
  reconstruções da imagem.
- Se o log mostrar `KEY_VALUES_MISMATCH` e a página não abrir, o certificado e a chave não
  são um par: veja a [Solução de problemas](solucao-de-problemas.md#subir-o-bluephish).
- O navegador compara o endereço que você digita com o nome dentro do certificado. A porta
  só é alcançável em `localhost` (veja [Como acesso de outra máquina](#como-acesso-de-outra-máquina)),
  então o nome só importa se você puser um proxy na frente.
- *Opcional, para guardar em outro caminho:* a aplicação lê as variáveis de ambiente
  `THEPHISH_TLS_CERT` e `THEPHISH_TLS_KEY` (caminhos **dentro do contêiner**). Você pode
  defini-las num `docker/docker-compose.override.yml`, na seção `environment` do serviço
  `thephish`.
- Para **gerar um certificado de teste** com o `openssl`, no Git Bash do Windows use
  `MSYS_NO_PATHCONV=1` na frente do comando; sem isso o Git Bash troca o `/CN=...` do
  `-subj` por um caminho de arquivo e o `openssl` falha:
  ```bash
  MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout chave.pem -out certificado.pem -days 30 \
    -subj "/CN=bluephish.exemplo" -addext "subjectAltName=DNS:bluephish.exemplo,DNS:localhost"
  ```

## Como mudo a porta?

A porta padrão é a **8080**, ligada só a `127.0.0.1`. Mude-a **depois** da primeira instalação
(o `setup.sh` lê a porta publicada, então o arquivo abaixo pode ser criado antes ou depois do
primeiro `./setup.sh`) e **sem editar o `docker-compose.yml`**, para as atualizações com
`git pull` não conflitarem:

1. Crie o arquivo `docker/docker-compose.override.yml` (o git o ignora) com:
   ```yaml
   services:
     thephish:
       ports: !override
         - '127.0.0.1:9443:8080'
   ```
   Troque `9443` pela porta que você quer. O `8080` à direita **não muda**: é a porta de
   dentro do contêiner.
2. Aplique, a partir de `docker/`:
   ```bash
   docker compose up -d
   ```
3. Abra `https://localhost:9443`.

O `!override` exige o **Docker Compose 2.24 ou mais novo** (confira com `docker compose version`).
Sem ele, a porta nova **se soma** à antiga e as duas ficam abertas, em vez de uma trocar a outra.

**Já existe outro Bluephish/ThePhish no mesmo computador?** O contêiner se chama `thephish` e a
imagem `thephish-custom:latest`; um segundo `up` brigaria pelo nome e um `build` sobrescreveria
a imagem do outro. Defina outros nomes em `docker/.env`:

```bash
BLUEPHISH_CONTAINER=bluephish2
BLUEPHISH_IMAGE=bluephish2:local
```

Nesse caso, troque também `thephish` por esse nome nos comandos `docker exec` e `docker inspect`
(os `docker compose ... thephish` usam o nome do serviço e continuam iguais).

## Como acesso de outra máquina?

Por segurança a porta só responde na própria máquina (`127.0.0.1`), e o login exige HTTPS.
**Não** troque `127.0.0.1` por `0.0.0.0` para "liberar": isso expõe o painel a toda a rede.
Dois caminhos seguros:

- **Túnel SSH** (o mais simples, sem mudar nada no Bluephish). Na máquina de onde você quer
  acessar:
  ```bash
  ssh -L 8080:127.0.0.1:8080 usuario@servidor-do-bluephish
  ```
  Deixe o comando aberto e acesse `https://localhost:8080` nessa máquina.
- **Proxy reverso com TLS** na frente, para uso contínuo por vários analistas. Se você usa SSO
  nessa configuração, defina `BLUEPHISH_BASE_URL` em `docker/.env` com o endereço público
  (veja os comentários do `docker/.env.example`). Leia também a [Segurança](seguranca.md).

## Como uso um Ollama que roda na minha máquina no Linux?

No Docker Desktop (Windows e macOS), o nome `host.docker.internal` já aponta para a sua
máquina. No **Linux** ele não existe por padrão:

1. Crie (ou edite) o `docker/docker-compose.override.yml`:
   ```yaml
   services:
     thephish:
       extra_hosts:
         - "host.docker.internal:host-gateway"
   ```
2. Faça o Ollama aceitar conexões vindas do Docker. Por padrão ele escuta só em `127.0.0.1`,
   que o contêiner não alcança; inicie-o com a variável `OLLAMA_HOST=0.0.0.0`.
3. Aplique com `docker compose up -d` e, em **Configurações → IA**, use o endpoint
   `http://host.docker.internal:11434/api/chat`.

## Como atualizo para uma versão nova?

Na raiz do repositório:

```bash
git pull --ff-only
cd docker
docker compose up -d --build thephish
```

O `--build` é necessário: um simples `restart` sobe a imagem **antiga**. Seus dados em
`docker/vol/` e suas credenciais são mantidos.

O `docker-compose.override.yml`, se existir, o git ignora e continua valendo; o `up -d --build`
aplica os dois. O `whitelist.json` também é gravado pela aplicação: se o aborto do `git pull`
citar esse arquivo, use o mesmo procedimento abaixo trocando o nome e, depois, reimporte suas
regras pela interface (Whitelist → Importar) a partir da cópia guardada.

**Se o `git pull` abortar** com `Your local changes to the following files would be overwritten
by merge: docker/thephish_conf_files/configuration.json`, é porque a versão nova também mexeu
nesse arquivo, que guarda as suas credenciais. Isso é raro e tem solução sem perder nada.
Na raiz do repositório:

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
   python3 - <<'EOF'
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
   EOF
   ```
6. Reconstrua: `cd docker && docker compose up -d --build thephish`.

## Como faço backup e restauro?

O que importa fica em quatro lugares: `docker/vol/` (banco de dados, trilha de auditoria,
mensagens guardadas, chaves TLS), `docker/thephish_conf_files/` (`configuration.json` e
`whitelist.json`, as regras dos analistas), `docker/.env` (a chave de sessão) e, se você criou,
`docker/docker-compose.override.yml` (porta, nomes).

**Backup**, na raiz do repositório. Pare a aplicação antes, para o banco ficar consistente:

```bash
cd docker && docker compose stop thephish && cd ..
tar czf bluephish-backup-$(date +%F).tar.gz docker/vol docker/thephish_conf_files docker/.env $(ls docker/docker-compose.override.yml 2>/dev/null)
cd docker && docker compose start thephish
```

**Restauro**, numa instalação nova (depois do `git clone`), na raiz do repositório:

```bash
tar xzf bluephish-backup-AAAA-MM-DD.tar.gz
./setup.sh
```

O `setup.sh` não sobrescreve o que já está configurado, então ele só sobe o Bluephish com os
dados restaurados. Guarde o arquivo de backup fora da máquina: ele contém credenciais.

## Onde ficam os dados e os logs?

- **Dados:** `docker/vol/thephish_data/`, no seu computador. Lá estão o banco `thephish.db`
  (usuários, decisões dos analistas, histórico), o `auth.log` (trilha de auditoria), o par TLS,
  as mensagens originais (`originals/`), as telas renderizadas (`rendered/`), os arquivos
  gravados pelo destino Disco (`analises/`) e as suas regras YARA (`yara/`).
- **Log da aplicação:** `docker compose logs -f thephish`.
- **Trilha de auditoria:** `docker compose exec thephish tail -F /root/thephish/data/auth.log`
  (se você definiu uma pasta em **Configurações → Auditoria**, o arquivo fica dentro dela).

## Como crio um usuário, troco uma senha ou desbloqueio uma conta?

Pela interface, um `global_admin` faz isso em **ADMINISTRAÇÃO → Usuários**. Pela linha de
comando, a partir de `docker/`:

```bash
docker compose exec thephish python3 manage.py create-user               # novo usuário, qualquer papel
docker compose exec thephish python3 manage.py list-users
docker compose exec thephish python3 manage.py reset-password NOME
docker compose exec thephish python3 manage.py reset-mfa NOME            # celular perdido ou trocado
docker compose exec thephish python3 manage.py unlock NOME               # conta bloqueada por tentativas
```

Cada comando pede o que falta (senha, papel) e nunca mostra a senha na tela.

## Como paro, religo e removo tudo?

A partir de `docker/`:

```bash
docker compose stop thephish      # para; os dados ficam
docker compose start thephish     # religa
docker compose restart thephish   # reinicia (não relê o docker/.env; para isso use `up -d`)
docker compose down               # remove o contêiner; os dados em vol/ ficam
```

Para apagar **tudo**, inclusive os dados (**sem volta**; faça backup antes): rode `docker compose
down`, apague a pasta `docker/vol/` e, se quiser, a imagem com `docker image rm thephish-custom:latest`.

## Como troco a chave de sessão?

A chave assina o cookie de sessão. Para trocá-la (por exemplo, se suspeitar que vazou):

1. Gere uma nova: `openssl rand -base64 48`.
2. Cole em `THEPHISH_SECRET_KEY=` no arquivo `docker/.env`.
3. Recrie o contêiner: `docker compose up -d`. (`restart` **não** relê o `.env`.)

Todo mundo é deslogado e precisa entrar de novo.

## Por que o serviço se chama `thephish`?

É um nome histórico, mantido nos comandos por compatibilidade: o serviço e o contêiner no
Docker, a variável `THEPHISH_SECRET_KEY` e a pasta `docker/thephish_conf_files/`. Renomeá-los
quebraria instalações existentes. O produto, na tela e na documentação, é o **Bluephish**.

## Preciso do TheHive, do Jira ou de um LLM?

**Não.** O mínimo para o Bluephish funcionar é uma caixa de e-mail conectada. Os vereditos
são gravados em disco por padrão, e os analisadores de reputação rodam dentro dele. O LLM
acrescenta a avaliação de engenharia social, e o TheHive e o Jira são destinos opcionais para
registrar os vereditos em outro lugar. Veja a [Configuração](configuracao.md) e as
[Integrações opcionais](integracoes.md).
