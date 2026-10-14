# Solução de problemas

[English](troubleshooting.md) · **Português (Brasil)**

Problemas comuns e como resolvê-los. Os comandos rodam a partir do diretório `docker/`, salvo
indicação em contrário. Procure o sintoma no grupo que combina, ou busque na página o texto
do erro.

- [Subir o Bluephish](#subir-o-bluephish)
- [Entrar](#entrar)
- [Caixa de e-mail e análise](#caixa-de-e-mail-e-análise)
- [A interface](#a-interface)
- [Integrações opcionais](#integrações-opcionais)

## Subir o Bluephish

| Sintoma | Causa e correção |
|---|---|
| `./setup.sh` abre o VS Code (ou um editor) em vez de executar | Você está no PowerShell/CMD, que não executa arquivos `.sh`, então ele abre o arquivo com o programa associado. Use o **Git Bash**, ou chame o bash do Git explicitamente: `& 'C:\Program Files\Git\bin\bash.exe' -lc "cd '/c/caminho/para/Bluephish' && ./setup.sh"`. O `bash.exe` solto em `System32` é o WSL, onde o Docker Desktop normalmente não está no `PATH`. |
| `set: pipefail\r: invalid option name` ou `bad interpreter` | O script foi baixado com quebras de linha **CRLF**. Um `.gitattributes` agora força LF, então clone de novo, ou corrija a cópia: `sed -i 's/\r$//' setup.sh`. |
| `the 'docker compose' plugin is required` | `docker compose version` precisa funcionar. Instale o Docker Desktop, ou o pacote `docker-compose-plugin` no Linux. |
| O navegador não alcança a aplicação | Use **`https://`** (e não `http://`) e **`localhost`**: a porta está ligada a `127.0.0.1`, então o IP da máquina na rede local não funciona, de propósito. |
| Aviso de certificado | Esperado: o certificado é autoassinado. Aceite uma vez. |
| `port is already allocated` na 8080 | Outro programa da máquina usa a 8080. Pare-o, ou troque a porta em `docker/docker-compose.yml` (por exemplo `127.0.0.1:8081:8080`) e abra essa porta. |
| De repente toda conta é desconhecida, e o log mostra **um novo certificado TLS sendo gerado** | O Bluephish foi iniciado do diretório errado. Todo volume no `docker-compose.yml` é relativo ao arquivo (`./vol/...`), então um `docker compose up` rodado de um git worktree ou de uma cópia da árvore aponta o contêiner para um `vol/` **vazio**: um banco novo sem usuários, um certificado novo e o `configuration.json` de exemplo no lugar das suas credenciais. Nada se perdeu: seus dados continuam no `docker/vol/` verdadeiro. Inicie a partir do `docker/` do próprio repositório e confira com `docker inspect thephish --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'`: nenhum caminho deve apontar para um lugar inesperado. |

## Entrar

| Sintoma | Causa e correção |
|---|---|
| Deslogado a cada reinício | `THEPHISH_SECRET_KEY` está vazio em `docker/.env`. Rode `./setup.sh` ou defina-o manualmente (`openssl rand -base64 48`). |
| O login diz "Invalid username or password" e você tem certeza de que está certo | A conta é bloqueada por **15 minutos** depois de 5 falhas. Libere-a: `docker compose exec thephish python3 manage.py unlock NOME`. |
| Tentativas de login demais | A rota de login tem limite de **5 por minuto por IP**. Espere um minuto. |
| O código do autenticador é sempre rejeitado | O TOTP é um relógio, e não uma senha: a hora do celular precisa estar certa. Ligue a hora automática (Android: *Authenticator → Configurações → Correção de tempo para códigos*; iOS: *Ajustes → Geral → Data e Hora → Automaticamente*). O servidor aceita ±30 s. |
| Perdeu o celular com o autenticador | Um `global_admin` limpa o segundo fator em *Usuários → Resetar MFA*; o próximo acesso pede para configurá-lo de novo. Se ninguém consegue entrar, faça pelo host: `docker compose exec thephish python3 manage.py reset-mfa NOME`. |

## Caixa de e-mail e análise

| Sintoma | Causa e correção |
|---|---|
| Nenhum e-mail listado | A fila lista todo e-mail não lido, qualquer que seja o modo de análise, então uma fila vazia significa que a caixa não pôde ser lida ou não tem nada não lido. A linha de status da fila e o `docker logs thephish` dizem o erro do provedor (para o limite diário de download do Gmail, veja o §7.7.1 do [`BLUEPHISH_ARCHITECTURE.md`](../BLUEPHISH_ARCHITECTURE.md)). O modo de análise só muda o que o agendador automático pega. |
| Nenhum analisador rodou numa análise | Nenhum está habilitado, ou nenhum suporta os tipos de observável encontrados. Veja *Integrações → Analisadores*; o cabeçalho de lá diz quantos estão ligados. |
| Um analisador não informa nada enquanto os outros funcionam | O erro dele viaja com o relatório: `findings[].error` no `report.json` que o destino em disco grava, e o log da análise (o painel ao vivo, ou `docker logs thephish`). Uma chave recusada, uma cota esgotada e um 429 dizem isso literalmente. |
| O LLM não contribui em nada para os vereditos | Veja no `docker logs thephish` um aviso do `llm_analysis`. A análise é fail-open: um modelo inalcançável nunca bloqueia o pipeline. Lembre que, no Linux, o `host.docker.internal` precisa de uma entrada `extra_hosts` (veja a [configuração](configuration.pt-BR.md#2-ia-e-análise-automática)). |
| Os e-mails de veredito nunca chegam | Cada aviso tem o próprio interruptor em *Configurações → Notificações*, o servidor SMTP tem outro em *Configurações → E-mail*, e os dois precisam estar ligados. Um veredito Suspicious nunca envia e-mail ao denunciante. Use o botão **Testar**: ele autentica sem enviar. |

## A interface

| Sintoma | Causa e correção |
|---|---|
| Abrir *Como entregue* é lento para uma denúncia | O layout de todo e-mail é carregado em segundo plano, página por página, e abre na hora quando fica pronto; as imagens remotas dele são então buscadas no clique, com limite de 20 s. Uma denúncia que o carregador ainda não alcançou é renderizada no clique, e essa renderização espera a vez de acessar a caixa atrás de qualquer ciclo de leitura em andamento. A linha abaixo dos botões de página diz até onde o carregador chegou. |
| As linhas continuam *aguardando carregamento* | O carregador em segundo plano lê dez e-mails por viagem ao servidor de e-mail e dá passagem a todo clique, então, na primeira subida, uma caixa com alguns milhares de não lidos demora para ser preenchida. Os layouts ficam em `docker/vol/thephish_data/rendered` e sobrevivem a reinícios e rebuilds. Se a linha abaixo dos botões de página disser que o carregamento em segundo plano está indisponível, esse diretório não é gravável: tudo continua abrindo, no clique. |
| As imagens em *Como entregue* aparecem como "não carregada" | O texto de substituição diz qual dos três motivos vale: a proteção contra SSRF recusou o endereço, o host nunca respondeu, ou o arquivo passou do limite de tamanho ou de tempo. Os três são o sistema funcionando. |

## Integrações opcionais

Só valem se você roda os serviços descritos em [integrações](integrations.pt-BR.md).

| Sintoma | Causa e correção |
|---|---|
| O Bluephish não alcança o TheHive, embora `localhost:9000` funcione no navegador | A URL em *Integrações → Tickets* tem que ser `http://thehive:9000`, o nome do serviço no Docker. Dentro do contêiner do Bluephish, `localhost` é o próprio contêiner. |
| `port is already allocated` na 80 ou na 443 | Essas pertencem ao MISP e colidem com qualquer servidor web local (IIS, Apache, outra stack). Suba sem o arquivo de integrações, ou remapeie as portas em `docker/docker-compose.integrations.yml` (por exemplo `127.0.0.1:8081:80`). Nada na análise precisa da interface web do MISP. |
| Casos maliciosos terminam com *"a exportação para o MISP falhou"* | Pediu-se ao TheHive que exportasse para o MISP, mas o conector MISP dele não está ativo. Ative-o (veja as [integrações](integrations.pt-BR.md#exportar-casos-maliciosos-para-o-misp)) ou apague o nome de exportação MISP no cartão do TheHive. |
| O TheHive, as dependências dele ou o MISP não sobem | São pesados: cerca de 6 GB de RAM livres para o conjunto. Veja `docker compose logs thehive` (ou `cassandra`, `misp`) e pare as integrações se a máquina estiver curta de memória: o Bluephish não depende delas. |
