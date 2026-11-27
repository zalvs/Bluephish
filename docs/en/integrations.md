# Optional integrations

[Português (Brasil)](../integracoes.md) · **English**

Bluephish needs no integration to work: a fresh installation analyzes, decides the verdict and
records every analysis to disk.

In 2.0, TheHive, MISP and hive-ai-agent **left the stack** (and the 1.x
`docker-compose.integrations.yml` left the repository). TheHive is now only a **recording
destination**, like Jira, set up in **Integrações → Tickets → TheHive**, and MISP is something
TheHive exports to. Install them apart, from their official guides
([TheHive](https://docs.strangebee.com/thehive/), [MISP](https://www.misp-project.org/download/)).

To connect a TheHive: create a service user with the `analyst` profile in the target
organisation, generate its API key, and fill the address and key in **Integrações → Tickets →
TheHive**. The address is what the Bluephish container sees: another host's name or IP, the
service name of a container on the same Docker network (`http://thehive:9000`), or
`http://host.docker.internal:9000` for the host itself. Inside the container, `localhost` is the
container.

The full guide, including how to keep the TheHive and MISP containers of a 1.x installation
running next to 2.0, is in Portuguese: [docs/integracoes/thehive.md](../integracoes/thehive.md).
