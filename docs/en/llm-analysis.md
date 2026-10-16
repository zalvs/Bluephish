# Social engineering analysis with an LLM

[Português (Brasil)](../llm-analysis.md) · **English**

Bluephish can send the reported email (subject, clean body text, attached or inline images)
together with the sender authentication results and the analyzers' findings and link
destinations to an LLM, either local (Ollama, llama.cpp, vLLM) or a hosted OpenAI-compatible
provider such as OpenRouter, to detect **Business Email Compromise (BEC)** and other
social engineering patterns that produce no IoCs — no malicious links, no attachments —
and would therefore be classified as *Safe* by the reputation analyzers alone.

## Configuration

`app/configuration.json` (also editable from the web interface):

```json
"llm_analysis" : {
	"enabled" : false,
	"api_endpoint" : "http://localhost:11434/api/chat",
	"model_name" : "llama3"
}
```

- **Ollama native API**: any endpoint containing `/api/chat` uses the Ollama chat format
  with `"format": "json"` (forces valid JSON output). Setup: `ollama pull llama3`.
- **OpenAI-compatible API**: any other endpoint (e.g. `http://localhost:8000/v1/chat/completions`)
  uses the OpenAI chat completions format — works with llama.cpp server, vLLM, LM Studio, LocalAI.
- **Docker**: the Bluephish container must reach the LLM on the host — the default in
  `docker/thephish_conf_files/configuration.json` is `http://host.docker.internal:11434/api/chat`.
  On Linux add to the Bluephish service in `docker-compose.yml`:
  `extra_hosts: ["host.docker.internal:host-gateway"]`.

## How it works

1. `case_from_email.py` extracts the clean body text of the attached email (text/plain
   parts preferred, HTML-to-text via BeautifulSoup as fallback).
2. `llm_analysis.py` sends subject + body (truncated to 6000 chars), the sender
   authentication results, the analyzers' findings and any images to the model with a
   system prompt made of an editable core (`llm_analysis.system_prompt`; default:
   `DEFAULT_SYSTEM_PROMPT`), the fixed `ANALYSIS_OUTPUT_CONTRACT` and the spotlighting
   instruction. The expected answer is:

   ```json
   {"risk_level": "Low|Medium|High|Critical", "justification": "...", "social_engineering_detected": true, "tactics": [...], "evidence": [...]}
   ```

   `tactics` is chosen from a closed vocabulary; values outside it are dropped.

3. `run_analysis.py` hands the result to every enabled recording destination
   (`tickets.py`): the TheHive destination writes it as a **task log on the "ThePhish
   analysis" task**, and the disk destination keeps it in the `llm` field of `report.json`.
   The web interface shows it next to the final verdict.
4. **Verdict escalation**: if the analyzers say *Safe* but the LLM reports
   `social_engineering_detected: true` at or above `escalation_threshold` (default
   `Medium`; `High` for authenticated bulk mail with a DKIM-signed one-click unsubscribe,
   RFC 8058), the verdict is escalated to **Suspicious** — the case stays open for the
   analyst instead of being auto-closed with a "safe" reply to the (potential) BEC victim.
   A suspicious observable plus a `High` or `Critical` assessment becomes **Malicious**.
   The LLM escalates to *Malicious* on its own only when `malicious_escalation` is set
   (default `off`), the sender is not authenticated and, in `review` and `debate`, the
   reviewer answered without withholding trust and the agents agreed. The LLM can never
   downgrade a verdict (`BLUEPHISH_ARCHITECTURE.md` §1.2).

## Multiple agents (optional)

*Settings → IA → Agentes e revisão* chooses how many models look at each email:

| Mode | Calls | What it adds |
|---|---|---|
| `single` | 1 | Nothing — the default pipeline. |
| `review` | 2 | A reviewer that reads the assessment (never the email) and can withhold trust. |
| `debate` | up to 5 | Two analysts in parallel, one rebuttal each, then the reviewer. |

Two things worth knowing before turning `debate` on:

- **Consensus does not protect against prompt injection.** Both analysts read the same
  hostile email, so an injection that works lands on both and their agreement is the
  same failure twice. What debate buys is a *divergence* signal — an injection tuned
  for one model family often fails on another — which is why setting a **different**
  model for the second analyst is what makes the mode worth its cost. The rebuttal
  round can only raise a risk level, never lower one, so an attacker cannot use it to
  argue an agent down.
- **The reviewer is the part that adds security**, because it never sees the email:
  it gets the structured conclusions, the guardrail findings and the analyzers' output,
  and it can only *withhold* trust. `proceed` changes nothing; `hold_for_human` sends
  the case to a person and blocks autonomous escalation to Malicious. A reviewer that
  is unreachable counts as "did not look", never as "approved".

Full rationale in [`BLUEPHISH_ARCHITECTURE.md` §8.5](../../BLUEPHISH_ARCHITECTURE.md).

## Fail-open behavior

The LLM step never blocks the pipeline: if the endpoint is offline, times out
(10 s connect / 120 s read per socket; 240 s for the whole request in single mode, 420 s for
the whole council in review and debate), returns unparseable output, or leaks the request
canary, a warning is logged and the link/attachment analysis continues normally.

## Security notes

- The email content is attacker-controlled and is treated as such by `prompt_guard.py`, not
  only by asking the model nicely. Before the model sees it, the text is stripped of hidden
  Unicode carriers, scanned for injection markers and fenced with a per-request random
  delimiter; afterwards the answer is checked for a canary that only ever existed in the
  system prompt. A leaked canary means the injection worked, so the assessment is discarded
  and the analysis continues on the analyzers alone. The response is schema-validated
  (`risk_level` whitelist, justification truncated to 500 chars, closed tactics vocabulary).
  Full rationale in [`BLUEPHISH_ARCHITECTURE.md` §8.3](../../BLUEPHISH_ARCHITECTURE.md).
- An email that carries injection markers cannot be closed as *Safe*: the verdict floor
  raises it to **Suspicious** so a human reads it. It stops there — never *Malicious* — and
  it applies even when the LLM is disabled, because the payload is a fact about the email
  rather than about the model.
- The LLM justification is HTML-escaped before being rendered in the web interface.
- Keep the endpoint on localhost or an internal segment: email bodies may contain
  sensitive data and must not leave your environment (that is the point of a *local* LLM).
