# Análise de engenharia social com um LLM

**Português (Brasil)** · [English](en/llm-analysis.md)

O Bluephish pode enviar o e-mail denunciado (assunto, texto limpo do corpo, imagens anexas ou
embutidas), junto com o resultado da autenticação do remetente e os achados e destinos de
links dos analisadores, a um LLM, local (Ollama, llama.cpp, vLLM) ou um provedor hospedado
compatível com a API da OpenAI, como o OpenRouter. O objetivo é detectar **Business Email
Compromise (BEC)** e outros padrões de engenharia social que não geram IoCs (nem links
maliciosos, nem anexos) e que, por isso, seriam classificados como *Seguro* só pelos
analisadores de reputação.

## Configuração

`app/configuration.json` (também editável pela interface web, em **Configurações → IA**):

```json
"llm_analysis" : {
	"enabled" : false,
	"api_endpoint" : "http://localhost:11434/api/chat",
	"model_name" : "llama3"
}
```

- **API nativa do Ollama**: qualquer endpoint que contenha `/api/chat` usa o formato de chat
  do Ollama com `"format": "json"` (força uma saída JSON válida). Preparação: `ollama pull llama3`.
- **API compatível com a OpenAI**: qualquer outro endpoint (por exemplo
  `http://localhost:8000/v1/chat/completions`) usa o formato de *chat completions* da OpenAI,
  que funciona com o servidor do llama.cpp, vLLM, LM Studio e LocalAI.
- **Docker**: o contêiner do Bluephish precisa alcançar o LLM que roda na máquina hospedeira.
  O padrão em `docker/thephish_conf_files/configuration.json` é
  `http://host.docker.internal:11434/api/chat`. No Linux, esse nome não existe por padrão:
  veja [como usar um Ollama da sua máquina no Linux](duvidas-gerais.md#como-uso-um-ollama-que-roda-na-minha-máquina-no-linux).

## Como funciona

1. `case_from_email.py` extrai o texto limpo do corpo do e-mail anexado (prefere as partes
   `text/plain`; usa HTML convertido em texto pelo BeautifulSoup como alternativa).
2. `llm_analysis.py` envia assunto e corpo (truncado em 6000 caracteres), o resultado da
   autenticação do remetente, os achados dos analisadores e as imagens ao modelo, com um
   prompt de sistema formado por um núcleo editável (`llm_analysis.system_prompt`; padrão:
   `DEFAULT_SYSTEM_PROMPT`), o `ANALYSIS_OUTPUT_CONTRACT` fixo e a instrução de
   *spotlighting*. A resposta esperada é:

   ```json
   {"risk_level": "Low|Medium|High|Critical", "justification": "...", "social_engineering_detected": true, "tactics": [...], "evidence": [...]}
   ```

   `tactics` vem de um vocabulário fechado; valores fora dele são descartados.

3. `run_analysis.py` entrega o resultado a todos os destinos de registro habilitados
   (`tickets.py`): o destino TheHive o grava como um **registro na tarefa "ThePhish
   analysis"**, e o destino em disco o guarda no campo `llm` do `report.json`. A interface web
   o mostra ao lado do veredito final.
4. **Escalonamento do veredito**: se os analisadores dizem *Seguro*, mas o LLM informa
   `social_engineering_detected: true` no nível `escalation_threshold` ou acima (padrão
   `Medium`; `High` para e-mail em massa autenticado, com cancelamento de inscrição em um
   clique assinado por DKIM, RFC 8058), o veredito sobe para **Suspeito**: o caso fica
   aberto para o analista, em vez de ser encerrado sozinho com uma resposta de "seguro" à
   (potencial) vítima de BEC. Um observável suspeito somado a uma avaliação `High` ou
   `Critical` vira **Malicioso**. O LLM só escala para *Malicioso* por conta própria quando
   `malicious_escalation` está ligado (padrão `off`), o remetente não está autenticado e,
   nos modos `review` e `debate`, o revisor respondeu sem retirar a confiança e os agentes
   concordaram. O LLM nunca pode rebaixar um veredito (`BLUEPHISH_ARCHITECTURE.md` §1.2).

## Vários agentes (opcional)

*Configurações → IA → Agentes e revisão* escolhe quantos modelos olham cada e-mail:

| Modo | Chamadas | O que acrescenta |
|---|---|---|
| `single` | 1 | Nada: é o fluxo padrão. |
| `review` | 2 | Um revisor que lê a avaliação (nunca o e-mail) e pode retirar a confiança. |
| `debate` | até 5 | Dois analistas em paralelo, uma réplica de cada um e, por fim, o revisor. |

Duas coisas que valem saber antes de ligar o `debate`:

- **Consenso não protege contra prompt injection.** Os dois analistas leem o mesmo e-mail
  hostil, então uma injeção que funciona cai nos dois e a concordância deles é a mesma falha
  duas vezes. O que o debate entrega é um sinal de *divergência*: uma injeção feita para uma
  família de modelos costuma falhar em outra, e por isso usar um modelo **diferente** no
  segundo analista é o que faz o modo valer o custo. A rodada de réplica só pode subir um
  nível de risco, nunca baixar, então um atacante não consegue usá-la para convencer um
  agente a recuar.
- **O revisor é a parte que acrescenta segurança**, porque nunca vê o e-mail: ele recebe as
  conclusões estruturadas, os achados da proteção e a saída dos analisadores, e só pode
  *retirar* a confiança. `proceed` não muda nada; `hold_for_human` manda o caso a uma pessoa
  e bloqueia a escalada autônoma para Malicioso. Um revisor inalcançável conta como "não
  olhou", nunca como "aprovou".

Justificativa completa em [`BLUEPHISH_ARCHITECTURE.md` §8.5](../BLUEPHISH_ARCHITECTURE.md).

## Comportamento em caso de falha

A etapa do LLM nunca bloqueia o fluxo: se o endpoint estiver fora do ar, estourar o tempo
(10 s de conexão e 120 s de leitura por socket; 240 s para a requisição inteira no modo
single, 420 s para todo o conselho em review e debate), devolver uma saída que não dá para
interpretar ou vazar o canário da requisição, um aviso vai para o log e a análise de links e
anexos segue normalmente.

## Notas de segurança

- O conteúdo do e-mail é controlado pelo atacante e é tratado assim pelo `prompt_guard.py`,
  não apenas pedindo com educação ao modelo. Antes de o modelo ver o texto, ele é limpo de
  portadores Unicode ocultos, varrido atrás de marcadores de injeção e cercado por um
  delimitador aleatório por requisição; depois, a resposta é conferida contra um canário que
  só existiu no prompt de sistema. Canário vazado significa que a injeção funcionou: a
  avaliação é descartada e a análise segue só com os analisadores. A resposta é validada
  contra um esquema (lista de `risk_level` permitidos, justificativa truncada em 500
  caracteres, vocabulário fechado de táticas). Justificativa completa em
  [`BLUEPHISH_ARCHITECTURE.md` §8.3](../BLUEPHISH_ARCHITECTURE.md).
- Um e-mail com marcadores de injeção não pode ser encerrado como *Seguro*: o piso do
  veredito o eleva a **Suspeito** para que uma pessoa o leia. Ele para aí, nunca em
  *Malicioso*, e vale mesmo com o LLM desligado, porque a carga é um fato sobre o e-mail, e
  não sobre o modelo.
- A justificativa do LLM tem o HTML escapado antes de aparecer na interface web.
- Mantenha o endpoint em `localhost` ou num segmento interno: o corpo dos e-mails pode
  conter dados sensíveis e não deve sair do seu ambiente (é esse o sentido de um LLM *local*).
