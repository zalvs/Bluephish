# Solução de problemas

**Português (Brasil)** · [English](en/troubleshooting.md)

Problemas comuns e como resolvê-los, **sintoma por sintoma**. Os comandos rodam a partir do
diretório `docker/`, salvo indicação em contrário. Se a sua pergunta é "como faço X" (trocar o
certificado, mudar a porta, atualizar, fazer backup), veja as [Dúvidas gerais](duvidas-gerais.md).

- [Subir o Bluephish](#subir-o-bluephish)
- [Entrar](#entrar)
- [Caixa de e-mail e análise](#caixa-de-e-mail-e-análise)
- [A interface](#a-interface)
- [Integrações opcionais](#integrações-opcionais)

Para ver o que a aplicação está dizendo, use sempre:

```bash
docker compose logs --tail 100 thephish
```

## Subir o Bluephish

| Sintoma | Causa e correção |
|---|---|
| `./setup.sh` abre o VS Code (ou um editor) em vez de executar | Você está no PowerShell/CMD, que não executa arquivos `.sh`, então ele abre o arquivo com o programa associado. Use o **Git Bash**, ou chame o bash do Git explicitamente: `& 'C:\Program Files\Git\bin\bash.exe' -lc "cd '/c/caminho/para/Bluephish' && ./setup.sh"`. O `bash.exe` solto em `System32` é o WSL, onde o Docker Desktop normalmente não está no `PATH`. |
| `docker is required but was not found in PATH.` | O Docker não está instalado, ou o terminal foi aberto antes da instalação. Instale o Docker e **abra um terminal novo**. |
| `the 'docker compose' plugin is required (Docker Desktop or docker-compose-plugin).` | `docker compose version` precisa funcionar. Instale o Docker Desktop, ou o pacote `docker-compose-plugin` no Linux. |
| `the Docker daemon is not reachable. Start Docker and re-run.` | O Docker está instalado, mas parado. No Windows e no macOS, abra o **Docker Desktop** e espere o ícone indicar que ele está rodando; no Linux, `sudo systemctl start docker`. Rode o `./setup.sh` de novo. |
| `set: pipefail: invalid option name`, ou `/usr/bin/env: 'bash\r': No such file or directory` | **Linux e macOS.** O script foi baixado com quebras de linha **CRLF**. Um `.gitattributes` agora força LF, então clone de novo, ou corrija a cópia: `sed -i 's/\r$//' setup.sh` (no macOS: `sed -i '' 's/\r$//' setup.sh`). No Git Bash do Windows o script roda mesmo com CRLF. |
| `ports are not available: exposing port TCP 127.0.0.1:8080 ... bind: Only one usage of each socket address` (Windows), ou `port is already allocated` (Linux) | Outro programa já usa a porta 8080. Descubra qual: no Windows, `netstat -ano \| findstr :8080`; no Linux, `ss -ltnp \| grep 8080`. Feche-o, ou mude a porta do Bluephish (veja [Como mudo a porta](duvidas-gerais.md#como-mudo-a-porta)). O `setup.sh` termina nesse ponto, com o erro do Docker. |
| `not up after 5 minutes. Check the logs with: cd docker && docker compose logs --tail 100 thephish` | A imagem foi construída, mas a aplicação não respondeu. Leia o log (`docker compose logs --tail 100 thephish`) e procure o último erro. As causas mais comuns são o par de certificado e chave que não combina (linha mais abaixo) e falta de memória: confira se há 4 GB livres. |
| O navegador não alcança a aplicação | Use **`https://`** (e não `http://`) e **`localhost`**: a porta está ligada a `127.0.0.1`, então o IP da máquina na rede local não funciona, de propósito. Se precisa de acesso de outra máquina, veja as [Dúvidas gerais](duvidas-gerais.md#como-acesso-de-outra-máquina). |
| Aviso de certificado no navegador | Esperado: o certificado de fábrica é autoassinado. Aceite uma vez, ou troque-o por um seu: [Como troco o certificado HTTPS](duvidas-gerais.md#como-troco-o-certificado-https). |
| Depois de trocar o certificado, a página não abre, e o log mostra `ssl.SSLError: [X509: KEY_VALUES_MISMATCH]` | O certificado e a chave que você colocou **não são um par**: a chave não pertence àquele certificado, e o contêiner fica reiniciando em laço (`docker compose ps` mostra `Restarting`, ou `Up` por poucos segundos) e a página não abre. Coloque o par correto em `docker/vol/thephish_data/` (nomes `thephish-cert.pem` e `thephish-key.pem`) e reinicie com `docker compose restart thephish`. Se você guardou os `.bak` (veja o [passo a passo](duvidas-gerais.md#como-troco-o-certificado-https)), basta copiá-los de volta. Para voltar ao certificado de fábrica, apague os dois arquivos e reinicie: o Bluephish gera um novo. |
| De repente toda conta é desconhecida, e o log mostra **um novo certificado TLS sendo gerado** | O Bluephish foi iniciado do diretório errado. Todo volume no `docker-compose.yml` é relativo ao arquivo (`./vol/...`), então um `docker compose up` rodado de um git worktree ou de uma cópia da árvore aponta o contêiner para um `vol/` **vazio**: um banco novo sem usuários, um certificado novo e o `configuration.json` de exemplo no lugar das suas credenciais. Nada se perdeu: seus dados continuam no `docker/vol/` verdadeiro. Inicie a partir do `docker/` do próprio repositório e confira com `docker inspect $(docker compose ps -q thephish) --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'`: nenhum caminho deve apontar para um lugar inesperado. |

## Entrar

| Sintoma | Causa e correção |
|---|---|
| Deslogado a cada reinício, e o log tem `THEPHISH_SECRET_KEY is not set` | `THEPHISH_SECRET_KEY` está vazio em `docker/.env`. Rode `./setup.sh` de novo, ou defina-o manualmente (`openssl rand -base64 48`) e recrie o contêiner com `docker compose up -d`. |
| O login diz "Invalid username or password" e você tem certeza de que está certo | A conta é bloqueada por **15 minutos** depois de 5 falhas. Libere-a: `docker compose exec thephish python3 manage.py unlock NOME`. |
| Tentativas de login demais | A rota de login tem limite de **5 por minuto por IP**. Espere um minuto. |
| O código do autenticador é sempre rejeitado | O TOTP é um relógio, e não uma senha: a hora do celular precisa estar certa. Ligue a hora automática (Android: *Configurações → Data e hora → Data e hora automáticas*; iOS: *Ajustes → Geral → Data e Hora → Definir Automaticamente*). O servidor aceita ±30 s. |
| Perdeu o celular com o autenticador | Um `global_admin` limpa o segundo fator em **ADMINISTRAÇÃO → Usuários → Resetar MFA**; o próximo acesso pede para configurá-lo de novo. Se ninguém consegue entrar, faça pelo host: `docker compose exec thephish python3 manage.py reset-mfa NOME`. |
| Esqueceu a senha | A tela de login diz para pedir a reposição a um `global_admin`. Sem nenhum acessível: `docker compose exec thephish python3 manage.py reset-password NOME`. |
| O item **Configurações** (ou **Integrações**, **Auditoria**) não aparece no menu lateral | Esses itens só aparecem para `admin` e `global_admin`, e **Usuários** só para `global_admin`. Peça a um `global_admin` para ajustar o seu papel, ou entre com um usuário que tenha o papel certo. |

## Caixa de e-mail e análise

| Sintoma | Causa e correção |
|---|---|
| Nenhum e-mail listado | A fila lista todo e-mail não lido, qualquer que seja o modo de análise, então uma fila vazia significa que a caixa não pôde ser lida ou não tem nada não lido. A linha de status da fila e `docker compose logs thephish` dizem o erro do provedor (para o limite diário de download do Gmail, veja o §7.7.1 da [arquitetura](../BLUEPHISH_ARCHITECTURE.md)). O modo de análise só muda o que o agendador automático pega. |
| Nenhum analisador rodou numa análise | Nenhum está habilitado, ou nenhum suporta os tipos de observável encontrados. Veja **Integrações → Analisadores**; o cabeçalho de lá diz quantos estão ligados. |
| Um analisador não informa nada enquanto os outros funcionam | O erro dele viaja com o relatório: `findings[].error` no `report.json` que o destino em disco grava, e o log da análise (o painel ao vivo, ou `docker compose logs thephish`). Uma chave recusada, uma cota esgotada e um 429 dizem isso literalmente. |
| O LLM não contribui em nada para os vereditos | Veja no log um aviso do `llm_analysis`. A análise é fail-open: um modelo inalcançável nunca bloqueia o pipeline. Lembre que, no Linux, o `host.docker.internal` precisa de uma entrada `extra_hosts` ([como fazer](duvidas-gerais.md#como-uso-um-ollama-que-roda-na-minha-máquina-no-linux)). |
| Os e-mails de veredito nunca chegam | Cada aviso tem o próprio interruptor em **Configurações → Notificações**, o servidor SMTP tem outro em **Configurações → E-mail**, e os dois precisam estar ligados. Um veredito Suspicious nunca envia e-mail ao denunciante. Use o botão **Testar**: ele autentica sem enviar. |

## A interface

| Sintoma | Causa e correção |
|---|---|
| Abrir *Como entregue* é lento para uma denúncia | O layout de todo e-mail é carregado em segundo plano, página por página, e abre na hora quando fica pronto; as imagens remotas dele são então buscadas no clique, com limite de 20 s. Uma denúncia que o carregador ainda não alcançou é renderizada no clique, e essa renderização espera a vez de acessar a caixa atrás de qualquer ciclo de leitura em andamento. A linha abaixo dos botões de página diz até onde o carregador chegou. |
| As linhas continuam *aguardando carregamento* | O carregador em segundo plano lê dez e-mails por viagem ao servidor de e-mail e dá passagem a todo clique, então, na primeira subida, uma caixa com alguns milhares de não lidos demora para ser preenchida. Os layouts ficam em `docker/vol/thephish_data/rendered` e sobrevivem a reinícios e rebuilds. Se a linha abaixo dos botões de página disser que o carregamento em segundo plano está indisponível, esse diretório não é gravável: tudo continua abrindo, no clique. |
| As imagens em *Como entregue* aparecem como "não carregada" | O texto de substituição diz qual dos três motivos vale: a proteção contra SSRF recusou o endereço, o host nunca respondeu, ou o arquivo passou do limite de tamanho ou de tempo. Os três são o sistema funcionando. |

## Integrações opcionais

Só valem se você roda os serviços descritos em [integrações](integracoes.md).

| Sintoma | Causa e correção |
|---|---|
| O Bluephish não alcança o TheHive, embora `localhost:9000` funcione no navegador | A URL em **Integrações → Tickets** tem que ser `http://thehive:9000`, o nome do serviço no Docker. Dentro do contêiner do Bluephish, `localhost` é o próprio contêiner. |
| Porta 80 ou 443 ocupada ao subir as integrações | Essas pertencem ao MISP e colidem com qualquer servidor web local (IIS, Apache, outra stack). Suba sem o arquivo de integrações, ou remapeie as portas em `docker/docker-compose.integrations.yml` (por exemplo `127.0.0.1:8081:80`). Nada na análise precisa da interface web do MISP. |
| Casos maliciosos terminam com *"a exportação para o MISP falhou"* | Pediu-se ao TheHive que exportasse para o MISP, mas o conector MISP dele não está ativo. Ative-o (veja as [integrações](integracoes.md#exportar-casos-maliciosos-para-o-misp)) ou apague o nome de exportação MISP no cartão do TheHive. |
| O TheHive, as dependências dele ou o MISP não sobem | São pesados: cerca de 6 GB de RAM livres para o conjunto, além do Bluephish. Veja `docker compose -f docker-compose.yml -f docker-compose.integrations.yml logs thehive` (ou `cassandra`, `misp`) e pare as integrações se a máquina estiver curta de memória: o Bluephish não depende delas. |
