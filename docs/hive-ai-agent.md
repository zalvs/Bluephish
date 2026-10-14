# hive_ai_agent — TheHive AI middleware

Standalone FastAPI service that listens to TheHive webhooks, correlates new IOCs with
the recent history (thehive4py 2.x, TheHive 4/5 API v1), asks a local LLM to detect
repeating patterns (campaigns) and posts actionable detection content back to the case
as an **IA-Insight** comment: regexes, network filters (FortiGate/Palo Alto/Squid) and
hunting queries (KQL / Splunk SPL).

## Install & run

```bash
cd hive_ai_agent
pip install -r requirements.txt
# edit configuration.json (TheHive URL/API key, LLM endpoint/model)
python hive_ai_agent.py          # listens on 0.0.0.0:8008
```

Secrets can be provided via environment variables instead of the JSON file:
`THEHIVE_URL`, `THEHIVE_APIKEY`, `LLM_API_ENDPOINT`, `LLM_MODEL_NAME`, `WEBHOOK_SECRET`.

### Docker

The agent ships with a [Dockerfile](../hive_ai_agent/Dockerfile) and is integrated in
[docker/docker-compose.yml](../docker/docker-compose.yml) as the `hive-ai-agent` service
(reachable by TheHive at `http://hive-ai-agent:8008`). Its configuration is mounted from
`docker/hive_ai_agent_conf/configuration.json`; the API key and other secrets come from
the environment (e.g. a `.env` file next to the compose file):

```bash
cd docker
echo "THEHIVE_APIKEY=<your-service-account-key>" >> .env
docker compose up -d --build hive-ai-agent   # or the whole stack: docker compose up -d
```

The default LLM endpoint inside the container is `http://host.docker.internal:11434/api/chat`
(Ollama on the host); the compose file already adds the `host-gateway` mapping for Linux.

The TheHive API key must belong to a (service) user with permission to read cases and
observables and to create comments — in TheHive 5 use a dedicated **Analyst** service
account, not an org-admin.

## Configuring the webhook in TheHive

### TheHive 4 (`application.conf` + API call)

1. Declare the endpoint in `application.conf` and restart TheHive:

```hocon
notification.webhook.endpoints = [
  {
    name: "hive-ai-agent"
    url: "http://hive-ai-agent:8008/webhook/thehive"
    version: 0
    wsConfig: {}
    includedTheHiveOrganisations: ["*"]
    excludedTheHiveOrganisations: []
  }
]
```

2. Activate the notification (once, as an org-admin):

```bash
curl -XPUT -u thehive_admin:password -H 'Content-Type: application/json' \
  http://thehive:9000/api/config/organisation/notification -d '
{
  "value": [
    {
      "delegate": false,
      "trigger": { "name": "AnyEvent" },
      "notifier": { "name": "webhook", "endpoint": "hive-ai-agent" }
    }
  ]
}'
```

### TheHive 5 (UI)

**Admin organisation → Entities Management → Notifications → + (add)**:

- Trigger: `AnyEvent` (the agent filters Creation of Case/Observable by itself; you can
  also create two notifications with triggers `CaseCreated` and `ObservableCreated` to
  reduce traffic)
- Notifier: `webhook`
- URL: `http://hive-ai-agent:8008/webhook/thehive`

## Example webhook payloads the agent accepts

TheHive 4 style:

```json
{
  "operation": "Creation",
  "objectType": "case",
  "objectId": "~40984576",
  "rootId": "~40984576",
  "object": { "_id": "~40984576", "title": "[ThePhish] Urgent wire transfer", "tags": ["email", "ThePhish"] }
}
```

TheHive 5 style (observable):

```json
{
  "action": "create",
  "objectType": "Observable",
  "object": { "_id": "~41005120", "dataType": "domain", "data": "login-secure-payportal.xyz" },
  "context": { "_id": "~40984576" }
}
```

Manual smoke test:

```bash
curl -XPOST http://localhost:8008/webhook/thehive -H 'Content-Type: application/json' \
  -d '{"action":"create","objectType":"Observable","object":{"_id":"~1","dataType":"domain","data":"secure-login-bank.xyz"},"context":{"_id":"~CASE_ID"}}'
```

## Behavior notes

- **Event filter**: only `Creation`/`create` of `Case`/`Observable`; everything else is ignored.
- **Cooldown** (`case_cooldown_seconds`, default 120 s): a ThePhish case creation fires one
  event per observable in a burst; the agent analyzes the case once per window.
- **Similarity**: strong matches = same registered domain, same mail domain, IP in the same
  /24 (v4) or /64 (v6); weak matches = same TLD (capped by `max_weak_matches`). The LLM is
  only called when at least `min_similar_iocs` similar IOCs exist.
- **Fail-open**: LLM offline/invalid → logged warning, no comment, TheHive unaffected.
- **TheHive 4 compatibility** (verified against TheHive 4.1.9): the v1 filter dialect and
  the comment API of thehive4py 2.x are TheHive 5 features; on TheHive 4 the agent
  automatically falls back to client-side history filtering and posts the insight as a
  task log of an **IA-Insight** task (v0 API) instead of a comment.
- **Security**: set `webhook_secret` and send it from a reverse proxy as the
  `X-Webhook-Secret` header if your TheHive cannot add custom headers; IOC values are
  treated as untrusted input in the prompt; the agent never auto-deploys any rule —
  a human validates the suggestions posted in the comment.
