# TheHive, MISP e hive-ai-agent

O BluePhish não precisa de nenhum dos três. Uma instalação nova é um contêiner só: ela
analisa, decide o veredito e grava cada análise em disco, e as telas de Casos, Phishing e
Executivo leem o que foi gravado.

O TheHive é um **destino de registro opcional**, como o Jira. O MISP e o hive-ai-agent
existem do lado do TheHive: o BluePhish nunca fala com eles diretamente.

| Componente | O que faz aqui | Quem fala com ele |
|---|---|---|
| TheHive | Recebe a análise pronta como um caso (observáveis, relatório, veredito) | O BluePhish, pelo destino TheHive |
| MISP | Recebe os casos maliciosos que o TheHive exporta | O TheHive |
| hive-ai-agent | Correlaciona IOCs entre casos e comenta no caso | O TheHive, por webhook |

Os três já fizeram parte do `docker-compose.yml` deste repositório e saíram dele. Instale-os
à parte, pelos guias oficiais ([TheHive](https://docs.strangebee.com/thehive/),
[MISP](https://www.misp-project.org/download/)), ou veja abaixo como manter os contêineres
de uma instalação antiga.

## Ligar o BluePhish a um TheHive

1. No TheHive, crie um usuário de serviço com perfil `analyst` na organização de destino e
   gere a chave dele em *Organisation → Users → Create API key*.
2. No BluePhish, abra **Integrações → Tickets → TheHive**.
3. Preencha o endereço e a chave. O endereço é o que o contêiner do BluePhish enxerga:
   - TheHive em outra máquina: o nome ou IP dela, por exemplo `https://thehive.exemplo.com`.
   - TheHive em outro contêiner da mesma rede Docker: o nome do serviço, por exemplo
     `http://thehive:9000`. Dentro do contêiner, `localhost` é o próprio contêiner.
   - TheHive na máquina hospedeira: `http://host.docker.internal:9000`, com
     `extra_hosts: ["host.docker.internal:host-gateway"]` no serviço `bluephish`
     (num `docker/docker-compose.override.yml`).
4. Clique em **Testar**: ele lê a quem a chave pertence e não cria caso nenhum. Confira a
   organização que aparece. Chave certa na organização errada é a falha silenciosa: os casos
   chegam onde ninguém olha.
5. Habilite o destino e salve.

O disco pode ficar ligado junto. Com os dois habilitados, cada análise vai para os dois, e
as telas de histórico juntam as duas fontes sem contar a mesma análise duas vezes. Se o
TheHive ficar fora do ar, o disco continua gravando e a tela avisa qual fonte faltou.

O endereço é validado ao salvar. A rede interna é aceita para este destino, porque é onde um
TheHive costuma morar; o serviço de metadados da nuvem é recusado sempre.

## Exportar casos maliciosos para o MISP

A exportação é feita pelo TheHive. O BluePhish só pede, e só quando o destino TheHive tem um
**nome da exportação MISP** preenchido.

1. Configure o conector MISP no `application.conf` do TheHive e reinicie o TheHive:

   ```hocon
   play.modules.enabled += org.thp.thehive.connector.misp.MispModule
   misp {
     interval: 5 min
     servers: [
       {
         name = "MISP THP"          # o nome que vai no card do destino TheHive
         url = "https://misp.exemplo.com/"
         auth {
           type = key
           key = "<chave de autenticação do usuário de sincronização>"
         }
       }
     ]
   }
   ```

2. No BluePhish, em **Integrações → Tickets → TheHive**, escreva o mesmo nome em **Nome da
   exportação MISP**.

Com o campo em branco, nenhum caso é exportado. Com o nome preenchido e o conector
desligado no TheHive, todo caso malicioso termina a linha do TheHive no log da análise com
*"a exportação para o MISP falhou"*, e o resto da análise segue normalmente.

## hive-ai-agent

O hive-ai-agent é um serviço separado, que escuta os webhooks do TheHive e comenta no caso.
Ele não é chamado pelo BluePhish e não participa do veredito. O código e a documentação
dele saíram deste repositório; o último commit da `main` que os contém é `4275102`:

```bash
git show 4275102:docs/hive-ai-agent.md        # como instalar e configurar o webhook
git archive 4275102 hive_ai_agent | tar -x    # extrai a pasta do serviço
```

## Manter os contêineres de uma instalação antiga

Quem instalou enquanto o TheHive vinha no compose tem os dados dele em `docker/vol/`
(`cassandra-data`, `data`, `index`) e o `application.conf` em `docker/thehive/`. Para
continuar com esse TheHive, declare os serviços dele num arquivo
`docker/docker-compose.override.yml`. O compose carrega esse arquivo sozinho, ele é ignorado
pelo git, e os serviços ficam no mesmo projeto e na mesma rede — o endereço
`http://thehive:9000` gravado no BluePhish continua valendo.

```yaml
services:

  cassandra:
    image: cassandra:3.11
    container_name: cassandra
    restart: unless-stopped
    hostname: cassandra
    environment:
      - MAX_HEAP_SIZE=1G
      - HEAP_NEWSIZE=1G
      - CASSANDRA_CLUSTER_NAME=thp
    volumes:
      - ./vol/cassandra-data:/var/lib/cassandra/data

  thehive:
    image: thehiveproject/thehive4:4.1.9-1
    container_name: thehive
    restart: unless-stopped
    depends_on:
      - cassandra
    ports:
      - '127.0.0.1:9000:9000'
    volumes:
      - ./thehive/application.conf:/etc/thehive/application.conf
      - ./vol/data:/opt/data
      - ./vol/index:/opt/index
    command: '--no-config --no-config-secret'
```

São os mesmos dois serviços que o compose trazia, com as mesmas pastas. Crie o arquivo
**antes** de atualizar: o passo de atualização remove os contêineres que não estão mais
declarados, e com o override no lugar esses dois continuam declarados. O roteiro completo
está em [docker/README.md](../../docker/README.md), "Atualizando de uma instalação com
TheHive e MISP".

O `docker/thehive/application.conf` deixou de ser versionado. A cópia que você mantiver ali
fica só na sua máquina (a pasta está no `.gitignore`), com a chave de sessão que o
`setup.sh` gerou para ela.

Esta é a configuração mínima que o repositório trazia, com credenciais de desenvolvimento e
a porta só em `127.0.0.1`. Para produção, siga o guia oficial do TheHive.
