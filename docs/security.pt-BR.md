# Notas de segurança

[English](security.md) · **Português (Brasil)**

- A porta é publicada somente em **`127.0.0.1`**. Se você roda as
  [integrações opcionais](integrations.pt-BR.md), o mesmo vale para as portas delas, e o
  Cassandra e o MySQL do MISP, em particular, rodam com credenciais de desenvolvimento e
  jamais devem ser expostos. Para alcançar a interface de outra máquina, coloque-a atrás de
  um proxy reverso com TLS em vez de mudar as ligações de porta.
- Os segredos nunca são devolvidos ao navegador: a API de configurações responde com
  booleanos (`hasApiKey`) e um campo vazio ao salvar significa "manter o valor guardado".
- **O contêiner faz requisições de saída para infraestrutura que o phisher escolheu.** Duas
  funcionalidades fazem isso por desenho: o desencurtador de URLs, durante a análise, e a
  visão *Como entregue*, que busca as imagens para as quais um e-mail denunciado aponta. Quem
  busca é o **contêiner**, nunca o navegador do analista: o endereço e o user agent da
  estação de trabalho nunca saem, e tudo o que chega ao navegador é uma URI `data:` dentro de
  uma sandbox. Mas a requisição sai da sua rede e avisa o remetente de que alguém olhou. A
  interface nomeia todo host que contatou. As imagens são buscadas **só quando alguém abre
  *Como entregue***: o carregador em segundo plano monta todo e-mail sem elas, então uma
  denúncia que ninguém abre não conta nada ao remetente.

  Três consequências que vale decidir antes da implantação: coloque a saída do contêiner
  atrás do proxy que a sua política de saída espera; espere que uma campanha de phishing
  descubra que esta caixa é monitorada; e, se isso for inaceitável para a sua operação, o
  `fetch_remote` em `app/email_render.py` desliga a busca de imagens na origem (links e
  scripts ficam inertes de qualquer forma). Toda busca é validada pela mesma proteção contra
  SSRF dos analisadores definidos pelo analista: a rede interna nunca é alcançável e o
  serviço de metadados da nuvem é recusado de saída, com redirecionamentos recusados, tipos
  de imagem lidos dos bytes e não do `Content-Type`, SVG rejeitado, e quantidade, tamanho e
  tempo total limitados.
- As senhas são guardadas com **bcrypt**; as sessões expiram após **30 min de inatividade /
  12 h no total**, são revogadas na troca de senha e terminam quando a aba do navegador que
  as abriu é fechada. Todos os eventos de autenticação são auditados em `auth.log`.
- **Um segundo fator é obrigatório para toda conta**, sem isenção por usuário ou por papel e
  sem nenhuma configuração que o desligue. Uma senha correta abre um desafio de 10 minutos,
  e não uma sessão: ninguém entra até apresentar um código TOTP válido, então uma senha
  roubada, sozinha, não alcança nada. As contas anteriores a isso são interceptadas no
  próximo acesso e precisam se cadastrar antes de entrar, e as sessões abertas antes disso
  são derrubadas.
- **Só aplicativos autenticadores** (Google Authenticator, Microsoft Authenticator, Authy ou
  qualquer cliente RFC 6238). Códigos por e-mail ou SMS não são oferecidos de propósito e não
  devem ser acrescentados: o SMS cai com a troca de chip (SIM swap), e o e-mail cai junto com
  a própria caixa que esta plataforma existe para vigiar. A recuperação é um `global_admin`
  limpando o fator, nunca um código enviado por um canal que um atacante pode já controlar.
- **Contas de SSO não são isentas.** O provedor de identidade comprova um fator; a plataforma
  exige dois, então o retorno do Entra ID cai no mesmo desafio TOTP.
- **Contas de SSO não têm senha nenhuma.** O hash guardado é de um valor aleatório que ninguém
  jamais viu, o login por senha as recusa de saída e o *Reset password* não é oferecido para
  elas: a revogação cabe ao provedor de identidade.
- Antes de abrir isto para uma rede mais ampla, leia a seção *Known constraints and traps* do
  [`BLUEPHISH_ARCHITECTURE.md`](../BLUEPHISH_ARCHITECTURE.md).
