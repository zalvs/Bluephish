# Teste de carga e de estresse

`loadtest.sh` é um script bash (curl, openssl, awk) que sobe a pressão sobre uma instância do
BluePhish em degraus de concorrência e diz em que degrau ela cedeu.

> **Só contra homologação.** O script se recusa a rodar sem `LOADTEST_CONFIRM=homologacao`.
> Ele cria sessões, enche a trilha de auditoria e, nas fases opcionais, lê a caixa de e-mail e
> consome cota dos analisadores e da IA. Rode de **outra máquina**: o gerador usa um processo
> curl por requisição, e acima de algumas centenas de requisições por segundo o limite passa a
> ser dele.

## Preparo

1. Suba uma instância de homologação, com caixa de e-mail e chaves de teste, nunca as de produção.
2. Crie uma conta só para isto (papel `analyst` basta):
   `docker compose exec bluephish python3 manage.py create-user`
3. Entre uma vez pelo navegador com essa conta e configure o segundo fator. Guarde o **segredo
   base32** que acompanha o QR (parâmetro `secret=` do endereço `otpauth://`). O script gera os
   códigos TOTP sozinho; o relógio da máquina que o roda precisa estar certo (NTP).
4. Se o certificado é autoassinado, use `LOADTEST_INSECURE=1`.

## Execução

```bash
export LOADTEST_TARGET=https://homolog.exemplo.local:8080
export LOADTEST_CONFIRM=homologacao
export LOADTEST_USER=loadtest
export LOADTEST_PASSWORD='...'
export LOADTEST_TOTP_SECRET='...'
export LOADTEST_INSECURE=1
./loadtest.sh
```

Senha e segredo só entram por variável de ambiente, nunca por argumento.

## Fases

| # | Fase | Liga | O que faz |
|---|---|---|---|
| 1 | Entrada anônima | sempre | `GET /login` em degraus. Não toca no banco |
| 2 | Rampa autenticada | sempre | `GET /api/auth/me`, `/api/whitelist` e `/` em degraus. Com `LOADTEST_ADMIN=1` (conta `admin`) soma `/api/analyzers`, `/api/scoring` e `/api/tickets` |
| 3 | Leitura da caixa | `LOADTEST_ALLOW_MAILBOX=1` | `GET /list` em 1, 2 e 5 conexões. Abre IMAP/Graph e gasta o teto diário de download do provedor |
| 4 | Análise | `LOADTEST_ALLOW_ANALYSIS=sim-consome-cota` e `LOADTEST_ANALYSIS_UID` | `POST /analysis`. Roda os analisadores e a IA de verdade. A primeira análise marca o e-mail como lido; as seguintes recebem 404 da fila, então use para medir o caminho completo uma vez, não como carga repetida |
| 5 | Sustentação | `LOADTEST_SOAK_SECONDS=1800` | Carga fixa por mais tempo. Acompanhe `docker stats bluephish` no servidor: a memória não deve subir sem parar |
| 6 | Limite de login | `LOADTEST_LOGIN_PROBE=1` (padrão) | 8 logins com usuário **inexistente**, para ver o 401 virar 429 depois da quinta. Não bloqueia nenhuma conta real |

## Ajustes

| Variável | Padrão | Significado |
|---|---|---|
| `LOADTEST_LEVELS` | `1 5 10 25 50 100` | Conexões simultâneas de cada degrau |
| `LOADTEST_STEP_SECONDS` | `30` | Duração de cada degrau |
| `LOADTEST_ERROR_LIMIT` | `5` | Erros (%), incluindo 429, acima dos quais o degrau conta como quebra |
| `LOADTEST_P95_LIMIT` | `5` | p95 em segundos acima do qual o degrau conta como quebra |
| `LOADTEST_REQ_TIMEOUT` | `30` | Timeout de cada requisição, em segundos |
| `LOADTEST_CACERT` | vazio | CA própria, no lugar de `LOADTEST_INSECURE=1` |

## Como ler o resultado

Cada degrau imprime uma linha como esta (números ilustrativos):

```
leitura, 25 conexões
  req=4210 rps=140.3 ok=4210 429=0 falhas=0 (0.0%) media=0.176s p50=0.121s p95=0.402s p99=0.780s max=1.912s
```

A rampa para no primeiro degrau que passa de `LOADTEST_ERROR_LIMIT` ou de `LOADTEST_P95_LIMIT` e
imprime `QUEBRA com N conexões`. O número do degrau anterior é a capacidade sustentável medida.

Pontos para o relatório:

- **Um processo só.** A aplicação roda em um processo eventlet com SQLite. Se o p95 sobe de
  forma suave com a concorrência, é a fila do processo; se aparecem falhas `000` (timeout ou
  conexão recusada), é saturação.
- **Atrás de proxy**, confira `BLUEPHISH_TRUSTED_PROXIES`. Sem ele o limite de login vê o IP do
  proxy e passa a valer para todos juntos.
- **Os gargalos de verdade** costumam ser externos: teto diário do provedor de e-mail, cota do
  VirusTotal e latência do gateway de IA (a fase 4 mede o conjunto).

## O que o script não cobre

- Socket.IO (painel em tempo real) e o log ao vivo da análise.
- Carga mista de várias contas ao mesmo tempo: usa uma sessão só, copiada por trabalhador.
- Resposta do gateway de IA sob carga, a não ser pela fase 4. Para isolar a IA, aponte a
  homologação para um mock com a latência que quiser (por exemplo 120 s) e rode a fase 4.

## Como foi verificado

Executado sem a aplicação: o gerador de TOTP contra os vetores da RFC 6238, as estatísticas
com dados sintéticos e o motor de degraus contra um servidor HTTP descartável. **Login, MFA,
heartbeat, a fase 4 e a sonda de login nunca rodaram contra a aplicação real.** Na primeira
execução, confira essas partes primeiro com `LOADTEST_LEVELS=1 LOADTEST_STEP_SECONDS=5`.
