# Configurar o Microsoft 365 (OAuth 2.0) no Bluephish

**Português (Brasil)** · [English](en/m365-oauth-setup.md)

Desde que a Microsoft desativou a autenticação básica no Exchange Online, o Bluephish usa a
autenticação moderna (OAuth 2.0) pelo **fluxo de credenciais do cliente** (acesso só do
aplicativo, sem login interativo, o que serve a um serviço sem tela).

Quando o Microsoft 365 é escolhido na aba **E-mail** de **Configurações**, o Bluephish lê a
caixa pela **Microsoft Graph API**. O caminho IMAP XOAUTH2 descrito mais abaixo continua
aceito pela configuração legada.

## 1. Registrar um aplicativo no Microsoft Entra ID (Azure AD)

1. Acesse o **Centro de administração do Microsoft Entra → Identidade → Aplicativos →
   Registros de aplicativo → Novo registro**.
2. Dê um nome (por exemplo `Bluephish-IMAP`), locatário único, sem URI de redirecionamento.
3. Anote o **ID do aplicativo (cliente)** e o **ID do diretório (locatário)**.
4. Em **Certificados e segredos → Novo segredo do cliente**, crie um segredo e anote o
   **valor** dele (o portal o mostra uma única vez).

## 2a. Conceder a permissão de aplicativo do Microsoft Graph (aba E-mail)

Necessária quando a caixa é lida pela Graph API (o padrão do provedor Microsoft 365
configurado pela interface web):

1. No registro do aplicativo, vá em **Permissões de API → Adicionar uma permissão →
   Microsoft Graph**.
2. Selecione **Permissões de aplicativo → Mail.ReadWrite** (leitura e escrita, para que os
   e-mails processados possam ser marcados como lidos).
3. Clique em **Conceder consentimento do administrador** para o locatário.
4. Se quiser, restrinja o aplicativo só à caixa do Bluephish com uma
   [política de acesso de aplicativo](https://learn.microsoft.com/pt-br/graph/auth-limit-mailbox-access):
   `New-ApplicationAccessPolicy -AppId <CLIENT_ID> -PolicyScopeGroupId <GrupoDeSegurancaComEmail> -AccessRight RestrictAccess`.

Depois, preencha **Tenant ID**, **Client ID**, **Client Secret** e **Caixa** na aba **E-mail**
e clique em Salvar. Os passos 2b e 3 não são necessários para a Graph.

## 2b. Conceder a permissão de aplicativo IMAP (caminho legado IMAP XOAUTH2)

1. No registro do aplicativo, vá em **Permissões de API → Adicionar uma permissão → APIs que
   minha organização usa**.
2. Procure **Office 365 Exchange Online** (`00000002-0000-0ff1-ce00-000000000000`).
3. Selecione **Permissões de aplicativo → IMAP.AccessAsApp**.
4. Clique em **Conceder consentimento do administrador** para o locatário.

## 3. Autorizar a entidade de serviço na caixa (PowerShell do Exchange Online)

O acesso IMAP só do aplicativo exige, além disso, registrar a entidade de serviço do
aplicativo no Exchange Online e dar a ela acesso à caixa específica:

```powershell
Install-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -Organization <locatario>.onmicrosoft.com

# ObjectId = o "ID do objeto" do APLICATIVO EMPRESARIAL (entidade de serviço),
# e não o ID do objeto do registro de aplicativo
New-ServicePrincipal -AppId <CLIENT_ID_DO_APLICATIVO> -ObjectId <OBJECT_ID_DA_ENTIDADE_DE_SERVICO> -DisplayName "Bluephish IMAP"

# Dê ao aplicativo acesso total somente à caixa do Bluephish
Add-MailboxPermission -Identity "thephish@seudominio.com" -User <OBJECT_ID_DA_ENTIDADE_DE_SERVICO> -AccessRights FullAccess
```

Se o IMAP estiver desativado na caixa, ative-o:

```powershell
Set-CASMailbox -Identity "thephish@seudominio.com" -ImapEnabled $true
```

## 4. Configurar o Bluephish

Edite `app/configuration.json` (ou `docker/thephish_conf_files/configuration.json` quando usar
Docker):

```json
{
	"imap" : {
		"host" : "outlook.office365.com",
		"port" : "993",
		"user" : "thephish@seudominio.com",
		"password" : "",
		"authType" : "oauth2",
		"folder" : "inbox"
	},
	"oauth2" : {
		"tenantId" : "<ID_DO_DIRETORIO_LOCATARIO>",
		"clientId" : "<ID_DO_APLICATIVO_CLIENTE>",
		"clientSecret" : "<VALOR_DO_SEGREDO>"
	}
}
```

Definir `"authType"` como `"basic"` (ou omiti-lo) mantém o comportamento original de usuário e
senha, para provedores que ainda o aceitam (por exemplo, o Gmail com senha de aplicativo).

## Gerenciamento do token

A obtenção e o cache do token ficam em `app/m365_auth.py`, que usa o MSAL:

- O `ConfidentialClientApplication` é um singleton do processo, então o cache de tokens em
  memória é compartilhado entre `list_emails.py` e `case_from_email.py`.
- `acquire_token_for_client()` devolve o token de acesso em cache enquanto ele é válido e pede
  um novo ao Azure AD, de forma transparente, quando ele falta ou está perto de expirar (os
  tokens do fluxo de credenciais do cliente duram cerca de 60 a 90 minutos; esse fluxo não tem
  token de atualização, então simplesmente se pede outro).
- O token segue para o Exchange Online pelo mecanismo SASL `XOAUTH2` na conexão `imaplib`
  existente, então a lógica de leitura dos e-mails é a mesma para todos os provedores.

## Solução de problemas

- `AUTHENTICATE failed` logo depois de configurar: falta o consentimento do administrador ou
  o passo `New-ServicePrincipal` / `Add-MailboxPermission`, ou você usou o ID do objeto do
  registro de aplicativo em vez do ID do objeto do aplicativo empresarial (entidade de
  serviço).
- `invalid_client`: segredo do cliente errado (copie o **valor** do segredo, não o ID).
- Funcionava e parou depois de meses: o segredo do cliente venceu. Crie um novo.
