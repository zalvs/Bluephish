# Integrações opcionais

[English](integrations.md) · **Português (Brasil)**

O Bluephish roda sozinho: o `./setup.sh` sobe a aplicação e mais nada. Os serviços abaixo são
**opcionais**. Nenhum deles é necessário para ler uma caixa de e-mail, analisar mensagens ou
registrar vereditos (o destino em disco e os conectores genéricos funcionam sem nenhum
contêiner extra). Acrescente-os só se você já os usa, ou quer usá-los.

| Serviço | Para que serve | Porta (só no localhost) |
|---|---|---|
| **TheHive** (+ Cassandra) | Um lugar onde a análise pronta pode ser registrada como caso | 9000 |
| **MISP** (+ MySQL, Redis) | Plataforma de inteligência de ameaças para a qual o TheHive pode exportar casos maliciosos | 80, 443 |
| **Agente de IA** | Um serviço à parte que lê casos do TheHive e comenta cada um com um LLM | 8008 |

## Como subi-los

Eles ficam num arquivo de compose próprio. Rode os dois arquivos juntos, a partir de `docker/`:

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.integrations.yml up -d
```

Ou, num clone novo, deixe o script de instalação fazer isso, o que também prepara a chave de
sessão do TheHive:

```bash
./setup.sh --with-integrations
```

Você precisa de cerca de **6 GB de RAM livres** e **25 GB de disco** para o conjunto
inteiro, e das portas acima livres no host. As portas 80 e 443 são do MISP e colidem com
qualquer servidor web local.

Para voltar ao Bluephish sozinho, rode `docker compose up -d` em `docker/` sem o segundo
arquivo, e pare os extras com
`docker compose -f docker-compose.yml -f docker-compose.integrations.yml down`.

## TheHive

O Bluephish pode registrar cada análise pronta como um caso no TheHive. É um destino entre
outros: a análise em si nunca depende dele.

**Do lado do Bluephish**, abra *Configurações → Integrações → Tickets* e preencha o cartão
**TheHive**:

| Campo | Valor |
|---|---|
| URL | `http://thehive:9000` quando o TheHive roda pelo arquivo de integrações; o endereço do seu próprio TheHive nos outros casos |
| Chave de API | uma chave criada no TheHive para um usuário da organização que deve ser dona dos casos |

> A URL é `http://thehive:9000`, e não `localhost`: o Bluephish alcança o TheHive pela rede do
> Docker, pelo nome do serviço, e `localhost` dentro do contêiner do Bluephish é o próprio
> contêiner.

**Configurar o TheHive em si** (primeiro acesso, organizações, usuários, chaves de API,
endurecimento) é assunto do TheHive e está documentado por quem o mantém:
<https://docs.strangebee.com/>. O arquivo de integrações traz o TheHive 4.1.9, então procure
a documentação do TheHive 4 lá. Não deixe a conta inicial como ela vem: troque-a antes de
deixar o TheHive no ar, e mantenha a porta dele ligada a `127.0.0.1`.

Se você já tem um TheHive em outro lugar, não precisa destes contêineres: use a URL dele e
uma chave de API dele.

### Exportar casos maliciosos para o MISP

O Bluephish só decide **se pede**: quando o cartão do TheHive tem um *nome de exportação
MISP*, um veredito `Malicious` pede ao TheHive que exporte o caso. O conector MISP em si é do
TheHive e vem comentado em `docker/thehive/application.conf`; ativá-lo (endereço e chave de
API do MISP) está descrito na documentação do MISP e do TheHive
(<https://www.misp-project.org/documentation/>).

Enquanto não estiver ativo, todo caso malicioso registrado no TheHive termina a linha dele no
log da análise com *"a exportação para o MISP falhou"* e é tratado normalmente no restante.
Se você não usa o MISP, apague o nome de exportação no cartão do TheHive e a requisição
deixa de ser feita.

## Agente de IA

`hive_ai_agent/` é um serviço à parte que escuta os webhooks do TheHive e comenta um caso com
um LLM. Ele precisa do TheHive. Documentação própria: [`hive-ai-agent.md`](hive-ai-agent.md).
As variáveis dele (`THEHIVE_APIKEY`, `LLM_API_ENDPOINT`, `LLM_MODEL_NAME`, `WEBHOOK_SECRET`)
ficam no `docker/.env`; veja o `docker/.env.example`.

## Jira, disco e conectores genéricos

Também são destinos, mas **não precisam de contêiner**: o Jira se configura com o endereço e
um token, o destino em disco grava numa pasta e os conectores genéricos chamam qualquer API
REST. Veja a [configuração](configuration.pt-BR.md#3-destinos-e-analisadores) e o
[manual dos conectores](conectores-manual.md).
