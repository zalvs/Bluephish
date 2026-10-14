# SSO corporativo — Microsoft Entra ID

Entrada no painel pelo provedor de identidade da organização, em vez de mais uma
senha guardada aqui dentro. Quem entra e com qual cargo passa a ser decidido pelo
**grupo no Entra ID**: uma pessoa que sai da empresa perde o painel junto com o
resto, sem ninguém precisar lembrar de vir aqui apagar a conta.

Quinze minutos, e nada disso mexe no login por senha — os dois convivem.

## O que é, e o que não é

- **É OpenID Connect**, com *authorization code + PKCE*. É o fluxo que a
  Microsoft recomenda para aplicação web que assina usuário, e o que faz a MFA e
  as políticas de acesso condicional do tenant valerem também para o painel.
- **Não é SAML**, apesar de a tela de projeto original falar dele. A legenda
  saiu do botão; o resto da tela é o desenho aprovado.
- **Não substitui o login por senha.** Ele continua ali, e é por ele que se entra
  quando o provedor está fora do ar — desde que exista ao menos uma conta local
  com `global_admin`. Guarde uma.

---

## Passo 1 — Registrar o aplicativo

No [portal do Entra ID](https://entra.microsoft.com) → **Identidade** →
**Aplicativos** → **Registros de aplicativo** → **Novo registro**.

| Campo | Valor |
|---|---|
| **Nome** | `bluephish` (só aparece no consentimento) |
| **Tipos de conta com suporte** | *Somente contas neste diretório organizacional* |
| **URI de Redirecionamento** | plataforma **Web**, e o endereço que a tela de SSO do painel mostra |

> O URI tem de bater **byte a byte**. O painel o exibe pronto em
> *Configurações → SSO*; copie de lá, não digite. Ele termina em
> `/auth/sso/callback`.
>
> Rodando atrás de um proxy que termina o TLS? O processo só enxerga o endereço
> interno, então defina `BLUEPHISH_BASE_URL` em `docker/.env` com a origem
> pública (`https://bluephish.acme.com`, sem barra no fim) — é dela que o URI
> mostrado na tela é montado.

Anote o **ID do aplicativo (cliente)** e o **ID do diretório (locatário)** da
página de visão geral.

## Passo 2 — Criar o segredo

Em **Certificados e segredos** → **Novo segredo do cliente**. Copie o **Valor**
(não o *Secret ID*) na hora: o portal não o mostra de novo.

Anote também a data de expiração. Quando ele vencer, o botão de SSO passa a
recusar todo mundo — e o login por senha é o que segura a instalação até alguém
gerar outro.

## Passo 3 — Decidir quem entra: App Roles ou grupos

O cargo no painel vem daqui. Duas formas, e a primeira é melhor.

### App Roles (recomendado)

Em **Funções de aplicativo** → **Criar função de aplicativo**, uma por cargo que
você for usar:

| Nome de exibição | Valor | Tipos de membro permitidos |
|---|---|---|
| bluephish Analista | `bluephish-analistas` | Usuários/Grupos |
| bluephish Admin | `bluephish-admins` | Usuários/Grupos |
| bluephish Global Admin | `bluephish-donos` | Usuários/Grupos |

Depois, em **Aplicativos empresariais** → o seu aplicativo → **Usuários e
grupos**, atribua pessoas ou grupos a cada função.

Por que esta e não a outra: acima de ~200 grupos por pessoa o Entra ID para de
mandar a lista de grupos no token e manda um ponteiro no lugar. O painel recusa
o login nesse caso, porque escolher cargo pelo que sobrou daria o cargo errado
em silêncio. App Role não tem esse limite, e o valor é legível na tela de
configuração — `bluephish-admins` diz o que é, um GUID não diz.

### Grupos de segurança

Se preferir usar grupos que já existem: em **Configuração do token** →
**Adicionar declaração de grupos** → *Grupos de segurança*, e depois use o
**object id** de cada grupo na configuração do painel.

## Passo 4 — Configurar no painel

Entre como `global_admin` → **Configurações** → aba **SSO**:

1. **Tenant ID**, **Client ID** e **Client secret** dos passos 1 e 2.
2. Confira o **URI de redirecionamento** contra o que ficou registrado.
3. Em *Quem entra, e com qual cargo*, uma entrada por linha em cada cargo — o
   valor da App Role, ou o object id do grupo.
4. Ligue a chave e **Salvar**.

O botão **Entrar com SSO corporativo** passa a aparecer na tela de login. Sem
configuração completa ele não chega nem a existir no HTML: um botão que só sabe
recusar é pior que botão nenhum.

## Passo 5 — Testar

Numa janela anônima, abra o painel e use o botão. O que esperar:

| O que acontece | O que significa |
|---|---|
| Volta à tela de login pedindo o código do aplicativo autenticador (no primeiro acesso, o QR para configurá-lo) e, depois dele, cai no painel | Pronto. Confira o cargo em *Usuários* — a conta aparece marcada `SSO` |
| "Sua conta não está em nenhum grupo com acesso ao painel" | O token chegou, mas o valor não casa com nenhuma linha do passo 4. Compare o valor da App Role, com atenção a espaço sobrando |
| "O provedor de identidade recusou o login" | Segredo errado ou vencido, ou URI de redirecionamento diferente do registrado |
| "O pedido de login expirou" | A ida ao provedor demorou demais, ou os cookies foram limpos no meio. Tente de novo |
| "O token não trouxe seus grupos" | Excesso de grupos na conta. Migre para App Roles (passo 3) |

Todas as tentativas ficam em `data/auth.log`, como `event=sso_login`, com o
motivo da recusa:

```bash
cd docker && docker compose exec thephish tail -F data/auth.log   # data/<pasta>/auth.log se uma pasta foi definida em Configurações → Auditoria
```

---

## Como o cargo se comporta depois

- **O grupo manda, a cada entrada.** Tirar alguém do grupo de admin rebaixa a
  conta na próxima vez que ela entrar. Não é preciso mexer em *Usuários*.
- **O último `global_admin` nunca é rebaixado por mudança de grupo.** Senão uma
  edição no Entra ID trancaria a instalação inteira para fora.
- **Quem não casa com nenhum grupo não entra** — a ausência de mapeamento nega,
  nunca concede o cargo mais baixo.
- **Uma conta local que entre por SSO continua local**, com a senha valendo. É a
  porta de trás para quando o provedor cair.
- **Conta criada por SSO não tem senha.** O hash guardado é de um valor aleatório
  que ninguém viu; o login por senha a recusa antes de conferir qualquer coisa, e
  *Resetar senha* nem aparece para ela.

## Revogar acesso

Tire a pessoa da App Role ou do grupo no Entra ID. Isso vale no próximo login —
e a sessão que ela já tem no painel morre por conta própria: por inatividade (30
min), pelo limite absoluto (12 h) ou quando ela fechar a aba, o que vier antes.
Para cortar na hora, exclua a conta em *Usuários*.
