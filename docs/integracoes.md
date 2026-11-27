# Integrações opcionais

**Português (Brasil)** · [English](en/integrations.md)

O Bluephish não precisa de nenhuma integração para funcionar: uma instalação nova analisa,
decide o veredito e grava cada análise em disco.

Na 2.0 o TheHive, o MISP e o hive-ai-agent **saíram da stack** (e o
`docker-compose.integrations.yml` da 1.x saiu do repositório). O TheHive passou a ser só um
**destino de registro**, como o Jira, configurado em **Integrações → Tickets → TheHive**, e o
MISP é algo para onde o TheHive exporta. Instale-os à parte, pelos guias oficiais.

O passo a passo, inclusive como manter os contêineres do TheHive e do MISP de uma instalação
1.x funcionando ao lado da 2.0, está em [Integrações: TheHive, MISP e hive-ai-agent](integracoes/thehive.md).

Outros destinos (Jira, disco e qualquer API REST por conector genérico) estão na
[Configuração](configuracao.md) e no [manual dos conectores](conectores-manual.md).
