"""Reading a user's organizational attributes from Entra ID.

Sibling of graph_mail.py: same app-only token through MSAL, same base URL, same
timeout. What it reads is the directory rather than a mailbox — the department
of the person who reported an email, which is the one fact about a report this
application could never derive from the message itself.

The application permission required is **User.Read.All** (Microsoft Graph), with
admin consent. It is not the same permission the mailbox uses (Mail.ReadWrite),
so an app registration that already reads the mailbox still has to be granted
this one; the settings screen says so, and probe() is what proves it.
"""

import urllib.parse

import requests

import m365_auth

GRAPH_SCOPES = ['https://graph.microsoft.com/.default']

GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0'

# Timeout (in seconds) applied to every request towards Microsoft Graph. This
# runs inside the analysis pipeline, so it is deliberately short: a directory
# that does not answer must cost the analysis seconds, not minutes
REQUEST_TIMEOUT = 15

# The attributes an organization may keep the "which area does this person belong
# to" answer in. `department` is the standard one; the others are here because
# plenty of tenants never filled it in and use one of these instead
ATTRIBUTES = ['department', 'officeLocation', 'jobTitle', 'companyName']

DEFAULT_ATTRIBUTE = 'department'


class DirectoryError(Exception):
	"""A lookup that failed for a reason worth showing to an admin."""


def normalize_attribute(attribute):
	attribute = str(attribute or '').strip()
	return attribute if attribute in ATTRIBUTES else DEFAULT_ATTRIBUTE


def _auth_headers(tenant_id, client_id, client_secret):
	access_token = m365_auth.get_access_token(tenant_id, client_id, client_secret, scopes = GRAPH_SCOPES)
	return {'Authorization': 'Bearer ' + access_token}


def _explain(response):
	"""Turn a Graph failure into something an admin can act on.

	A bare "HTTP 403" in a settings screen is a dead end: the two ways this
	realistically fails — the permission was never granted, or it was granted but
	never consented — look identical from the outside and are fixed in the same
	place, so the message names it.
	"""
	if response.status_code in (401, 403):
		return ('O Entra ID recusou a consulta (HTTP {0}). O registro de aplicativo precisa da permissão '
			'de aplicativo User.Read.All no Microsoft Graph, com consentimento de administrador '
			'concedido.').format(response.status_code)
	if response.status_code == 429:
		return 'O Entra ID está limitando as consultas (HTTP 429). Tente de novo em alguns minutos.'
	return 'O Entra ID respondeu HTTP {0}.'.format(response.status_code)


def lookup_user(tenant_id, client_id, client_secret, address, attribute = DEFAULT_ATTRIBUTE):
	"""The organizational attribute of one address, as (value, found).

	`found` distinguishes the two empty answers that must never be confused: a
	user who is not in this tenant at all (an outside reporter, HTTP 404) from a
	user who is there with the attribute blank. Both leave the report
	unattributed, but only the second one means the directory needs filling in.

	Raises DirectoryError on anything else — a missing permission is an operator
	problem, and swallowing it would show an empty dashboard card as if the
	organization simply had no departments.
	"""
	attribute = normalize_attribute(attribute)
	address = str(address or '').strip()
	if not address:
		return '', False
	url = '{0}/users/{1}'.format(GRAPH_BASE_URL, urllib.parse.quote(address, safe = ''))
	try:
		response = requests.get(url, headers = _auth_headers(tenant_id, client_id, client_secret),
			params = {'$select': attribute}, timeout = REQUEST_TIMEOUT)
	except requests.RequestException as error:
		raise DirectoryError('Não foi possível falar com o Entra ID: {0}'.format(error))
	except Exception as error:
		# MSAL raises its own errors when the client credentials are wrong
		raise DirectoryError('Não foi possível obter o token do Entra ID: {0}'.format(error))
	if response.status_code == 404:
		return '', False
	if not response.ok:
		raise DirectoryError(_explain(response))
	value = (response.json() or {}).get(attribute)
	return str(value).strip() if value else '', True


def probe(tenant_id, client_id, client_secret):
	"""Check the credentials and the permission without naming a user.

	Reads one user from the directory, which is the cheapest call that fails in
	exactly the same way a real lookup would: wrong credentials, missing
	User.Read.All, or no consent.
	"""
	url = '{0}/users'.format(GRAPH_BASE_URL)
	try:
		response = requests.get(url, headers = _auth_headers(tenant_id, client_id, client_secret),
			params = {'$select': 'id', '$top': '1'}, timeout = REQUEST_TIMEOUT)
	except requests.RequestException as error:
		raise DirectoryError('Não foi possível falar com o Entra ID: {0}'.format(error))
	except Exception as error:
		raise DirectoryError('Não foi possível obter o token do Entra ID: {0}'.format(error))
	if not response.ok:
		raise DirectoryError(_explain(response))
	return True
