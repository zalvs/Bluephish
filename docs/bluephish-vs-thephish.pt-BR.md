# Bluephish e ThePhish

[English](bluephish-vs-thephish.md) · **Português (Brasil)**

O Bluephish nasceu inspirado no [ThePhish](https://github.com/emalderson/ThePhish), de
Emanuele Galdi (`emalderson`), e hoje é um projeto independente. Esta página é para quem
conhece o original e quer ver onde os dois se separam. Se você nunca usou o ThePhish, não
precisa dela: comece pelo [README](../README.pt-BR.md).

A coluna do ThePhish vem do README público daquele projeto, na data em que isto foi escrito;
o repositório dele é a referência do que ele faz hoje.

| | ThePhish | Bluephish |
|---|---|---|
| **Quem inicia uma análise** | O analista escolhe um e-mail na interface web e a inicia | Manual (o analista escolhe) **ou** 100% automática, por um agendador |
| **O que precisa para rodar** | TheHive, Cortex e MISP | Só ele mesmo: um contêiner. TheHive e MISP são extras opcionais |
| **Onde rodam os analisadores** | No Cortex, um serviço à parte | Dentro do Bluephish: analisadores nativos, fornecedores que você mesmo acrescenta e regras YARA locais |
| **Onde o resultado é registrado** | Um caso no TheHive, exportado ao MISP quando malicioso | Qualquer combinação de TheHive, Jira, um arquivo em disco e conectores genéricos para qualquer API REST, ou nenhum deles |
| **Como o veredito é formado** | A partir dos vereditos dos analisadores | Os analisadores, a avaliação de engenharia social de um LLM, a autenticação do remetente (SPF/DKIM/DMARC) e uma pontuação ponderada, cada um numa ordem fixa que só pode elevar um veredito |
| **Avisos ao denunciante** | Enviados por um responder do Cortex | Enviados por SMTP, configurado no Bluephish, com um interruptor por aviso |
| **Caixas de e-mail** | Uma caixa que a aplicação lê | Gmail (IMAP) e Microsoft 365 (Graph API) |
| **Quem pode o quê** | (não faz parte da descrição dele) | Três papéis, segundo fator TOTP obrigatório, SSO corporativo, bloqueio de conta e trilha de auditoria |

## O que o Bluephish acrescenta

- Caixas do Microsoft 365 pela Graph API.
- Um agendador de análise automática, com limite por ciclo.
- Uma avaliação do LLM sobre a mensagem e, para phishing feito só de imagem, sobre as imagens.
- Autenticação do remetente (SPF, DKIM, DMARC) para distinguir um e-mail genuíno de uma marca
  de uma imitação.
- Um chat de IA para questionar um caso já analisado.
- Uma whitelist com cinco tipos de regra, validade em toda regra, simulação contra análises
  passadas e suspensão automática de uma regra que esconde vereditos ruins demais.
- Reclassificação pelos analistas, lembrada para mensagens parecidas.
- Controle de acesso por papéis, segundo fator obrigatório, SSO e um log de auditoria.

## O que ele mantém da ideia original

Uma caixa monitorada para onde as pessoas encaminham e-mails suspeitos como anexos `.eml`, a
extração dos observáveis de cada um, a análise deles, um veredito Safe, Suspicious ou
Malicious, um aviso a quem denunciou e uma whitelist. Os dois são publicados sob a AGPL-3.0.

Para o desenho detalhado do Bluephish, veja o
[`THEPHISH_ARCHITECTURE.md`](../THEPHISH_ARCHITECTURE.md).
