# Microsoft 365 (OAuth 2.0) setup for ThePhish

Since Microsoft disabled basic authentication on Exchange Online, ThePhish supports
Modern Authentication (OAuth 2.0) using the **client credentials flow**
(app-only access, no interactive login required — suitable for a headless service).

When Microsoft 365 is selected in the **Email synchronization** panel of the web
interface, ThePhish reads the mailbox through the **Microsoft Graph API**; the IMAP
XOAUTH2 path described below is still supported through the legacy configuration.

## 1. Register an application in Microsoft Entra ID (Azure AD)

1. Go to **Microsoft Entra admin center → Identity → Applications → App registrations → New registration**.
2. Name it (e.g. `ThePhish-IMAP`), single tenant, no redirect URI needed.
3. Note down the **Application (client) ID** and the **Directory (tenant) ID**.
4. Under **Certificates & secrets → New client secret**, create a secret and note down its **value**
   (it is shown only once).

## 2a. Grant the Microsoft Graph application permission (Email synchronization panel)

Required when the mailbox is read through the Graph API (the default for the
Microsoft 365 provider configured from the web interface):

1. In the app registration, go to **API permissions → Add a permission → Microsoft Graph**.
2. Select **Application permissions → Mail.ReadWrite** (read/write is needed so that the
   processed emails can be marked as read).
3. Click **Grant admin consent** for the tenant.
4. Optionally restrict the app to the ThePhish mailbox only with an
   [application access policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access):
   `New-ApplicationAccessPolicy -AppId <CLIENT_ID> -PolicyScopeGroupId <MailEnabledSecurityGroup> -AccessRight RestrictAccess`.

Then fill in **Tenant ID**, **Client ID**, **Client Secret** and **Mailbox** in the
Email synchronization panel and click Save. Steps 2b and 3 are not needed for Graph.

## 2b. Grant the IMAP application permission (legacy IMAP XOAUTH2 path)

1. In the app registration, go to **API permissions → Add a permission → APIs my organization uses**.
2. Search for **Office 365 Exchange Online** (`00000002-0000-0ff1-ce00-000000000000`).
3. Select **Application permissions → IMAP.AccessAsApp**.
4. Click **Grant admin consent** for the tenant.

## 3. Authorize the service principal on the mailbox (Exchange Online PowerShell)

App-only IMAP access additionally requires registering the app's service principal in
Exchange Online and giving it access to the specific mailbox:

```powershell
Install-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -Organization <tenant>.onmicrosoft.com

# ObjectId = the "Object ID" of the ENTERPRISE APPLICATION (service principal),
# not the object id of the app registration
New-ServicePrincipal -AppId <APPLICATION_CLIENT_ID> -ObjectId <SERVICE_PRINCIPAL_OBJECT_ID> -DisplayName "ThePhish IMAP"

# Give the app full access to the ThePhish mailbox only
Add-MailboxPermission -Identity "thephish@yourdomain.com" -User <SERVICE_PRINCIPAL_OBJECT_ID> -AccessRights FullAccess
```

If IMAP is disabled for the mailbox, enable it:

```powershell
Set-CASMailbox -Identity "thephish@yourdomain.com" -ImapEnabled $true
```

## 4. Configure ThePhish

Edit `app/configuration.json` (or `docker/thephish_conf_files/configuration.json` when using Docker):

```json
{
	"imap" : {
		"host" : "outlook.office365.com",
		"port" : "993",
		"user" : "thephish@yourdomain.com",
		"password" : "",
		"authType" : "oauth2",
		"folder" : "inbox"
	},
	"oauth2" : {
		"tenantId" : "<DIRECTORY_TENANT_ID>",
		"clientId" : "<APPLICATION_CLIENT_ID>",
		"clientSecret" : "<CLIENT_SECRET_VALUE>"
	}
}
```

Setting `"authType"` to `"basic"` (or omitting it) keeps the original username/password
behavior for providers that still support it (e.g. Gmail with app passwords).

## Token management

Token acquisition and caching are handled by `app/m365_auth.py` using MSAL:

- The `ConfidentialClientApplication` is a process-wide singleton, so its in-memory
  token cache is shared by `list_emails.py` and `case_from_email.py`.
- `acquire_token_for_client()` returns the cached access token while it is still valid
  and transparently requests a new one from Azure AD when it is missing or close to
  expiry (client-credentials tokens last ~60–90 minutes; there is no refresh token in
  this flow — a new token is simply requested).
- The token is passed to Exchange Online through the SASL `XOAUTH2` mechanism on the
  existing `imaplib` connection, so the whole email parsing logic of ThePhish is unchanged.

## Troubleshooting

- `AUTHENTICATE failed` right after setup: admin consent or the `New-ServicePrincipal` /
  `Add-MailboxPermission` step is missing, or you used the app registration object id
  instead of the enterprise application (service principal) object id.
- `invalid_client`: wrong client secret (remember to copy the secret **value**, not its id).
- Works, then stops after months: the client secret expired — create a new one.
