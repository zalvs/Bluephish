# Amostras para exercitar a metodologia de score

Três `.eml` sintéticos — nenhum endereço, domínio ou marca aqui existe — que
cobrem os três desfechos que a metodologia precisa distinguir. Eles são copiados
para dentro da imagem, então de dentro do container o caminho é `samples/`:

```
docker compose exec thephish python3 manage.py score samples/newsletter.eml \
    --analyzer virustotal=safe
```

`manage.py score` não toca a rede: os cabeçalhos são lidos do arquivo de verdade
(autenticação e gramática de lista), e o nível de cada analisador é informado no
argumento. Calibrar peso não custa cota de fornecedor nem uma análise real.

| Arquivo | O que demonstra |
|---|---|
| `newsletter.eml` | Massa **legítima**: gramática de lista completa (RFC 2369/2919/8058) e DMARC pass. Pontua baixo porque é legítima mesmo, e sai da fila com o rótulo `spam`. |
| `phishing.eml` | `List-Unsubscribe` **forjado** num domínio com DMARC fail. É o caso que justifica a regra: mesma família de cabeçalho da newsletter, e nenhuma triagem — o rótulo `spam` exige autenticação, que o remetente não escreve. |
| `interno.eml` | Correspondência comum autenticada, sem marcador nenhum. Pontua zero. |

O par que vale rodar lado a lado é o primeiro com o segundo:

```
docker compose exec thephish python3 manage.py score samples/newsletter.eml --analyzer virustotal=safe
docker compose exec thephish python3 manage.py score samples/phishing.eml  --analyzer virustotal=safe --llm High
```

E o resguardo do §1.2, que é o mais fácil de quebrar sem perceber — remetente
autenticado não é fechado como malicioso pelo conteúdo sozinho:

```
docker compose exec thephish python3 manage.py score samples/newsletter.eml --llm Critical
```

O score cai na faixa de phishing e o veredito para em `Suspicious`, não em
`Malicious`. Era isso que transformava marketing de marca real em veredito
malicioso.
