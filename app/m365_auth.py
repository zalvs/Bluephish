import msal

# Module-level MSAL application instance
# It is kept as a singleton so that the in-memory token cache is shared by all the
# modules that import this one (list_emails, case_from_email) within the same process
# MSAL transparently returns the cached access token while it is still valid and only
# contacts Azure AD again when the token is missing or about to expire
_msal_app = None
_msal_app_config = None

# Scope used for app-only IMAP/POP/SMTP access on Exchange Online
# The Azure AD app registration must have the "IMAP.AccessAsApp" application
# permission (Office 365 Exchange Online) with admin consent granted
SCOPES = ['https://outlook.office365.com/.default']


def _get_msal_app(tenant_id, client_id, client_secret):
	global _msal_app
	global _msal_app_config
	current_config = (tenant_id, client_id, client_secret)
	if _msal_app is None or _msal_app_config != current_config:
		_msal_app = msal.ConfidentialClientApplication(
			client_id,
			client_credential = client_secret,
			authority = 'https://login.microsoftonline.com/{0}'.format(tenant_id)
		)
		_msal_app_config = current_config
	return _msal_app


# Obtain an OAuth 2.0 access token from Azure AD using the client credentials flow
# The default scope targets Exchange Online (IMAP XOAUTH2); other callers can pass
# their own scopes (e.g. graph_mail passes the Microsoft Graph scope)
def get_access_token(tenant_id, client_id, client_secret, scopes = None):
	msal_app = _get_msal_app(tenant_id, client_id, client_secret)
	result = msal_app.acquire_token_for_client(scopes = scopes or SCOPES)
	if 'access_token' not in result:
		raise RuntimeError('Unable to obtain the OAuth 2.0 access token from Azure AD: {0} - {1}'.format(result.get('error'), result.get('error_description')))
	return result['access_token']


# Build the SASL XOAUTH2 string as required by Microsoft 365
def generate_xoauth2_string(user, access_token):
	return 'user={0}\x01auth=Bearer {1}\x01\x01'.format(user, access_token)


# Authenticate an already established imaplib connection using Modern Authentication
# imaplib takes care of the base64 encoding of the SASL XOAUTH2 string
def oauth2_login(connection, user, tenant_id, client_id, client_secret):
	access_token = get_access_token(tenant_id, client_id, client_secret)
	connection.authenticate('XOAUTH2', lambda challenge: generate_xoauth2_string(user, access_token).encode())
