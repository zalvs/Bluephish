import urllib.parse
import requests
import m365_auth

# Scope used for app-only Microsoft Graph access
# The Azure AD app registration must have the "Mail.ReadWrite" application
# permission (Microsoft Graph) with admin consent granted, so that the
# processed emails can be marked as read
GRAPH_SCOPES = ['https://graph.microsoft.com/.default']

GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0'

# Timeout (in seconds) applied to every request towards Microsoft Graph
REQUEST_TIMEOUT = 30

# How many messages one Graph page asks for. Graph caps $top well below the
# thousands an inbox listing may need, so the pages are followed to the end
PAGE_SIZE = 100


# Base URL of the mailbox that ThePhish reads the emails from
def _mailbox_url(mailbox):
	return '{0}/users/{1}'.format(GRAPH_BASE_URL, urllib.parse.quote(mailbox, safe = ''))


# Authorization header with an app-only token obtained through MSAL
# The token is cached in memory by m365_auth, so a network round trip towards
# Azure AD only happens when the cached token is missing or about to expire
def auth_headers(tenant_id, client_id, client_secret):
	access_token = m365_auth.get_access_token(tenant_id, client_id, client_secret, scopes = GRAPH_SCOPES)
	return {'Authorization': 'Bearer ' + access_token}


# Return the unread emails of the folder as (envelopes, more), where envelopes
# is a list of the message metadata Graph can answer without downloading
# anything (id, subject, sender, arrival time) and `more` says whether the
# mailbox holds at least one unread message beyond max_messages.
#
# Enumerating is deliberately separate from downloading: the interface lists
# every unread report, and only the handful the analyst is actually looking at
# have their MIME pulled (download_mime below, or peek_message on demand). One
# id past the limit is collected on purpose and then dropped - it costs a place
# in a page that was already being read and it is what lets the interface tell
# "these are all the pending reports" from "there are more behind them". A
# $count over a filtered message collection would answer it exactly, but it
# needs ConsistencyLevel=eventual and is not supported on every tenant, so this
# stays on the documented path.
#
# Listing does not mark the messages as read: that only happens in fetch_message,
# which mirrors the behavior of the IMAP flow (list keeps unseen, fetch marks seen)
def list_unread_envelopes(tenant_id, client_id, client_secret, mailbox, folder = 'inbox', max_messages = 25, ascending = False):
	headers = auth_headers(tenant_id, client_id, client_secret)
	url = _mailbox_url(mailbox) + '/mailFolders/{0}/messages'.format(urllib.parse.quote(folder, safe = ''))
	probe = max_messages + 1
	params = {
		'$filter': 'isRead eq false',
		'$select': 'id,subject,from,receivedDateTime',
		'$orderby': 'receivedDateTime asc' if ascending else 'receivedDateTime desc',
		'$top': str(min(probe, PAGE_SIZE))
	}
	try:
		envelopes = _page_through(url, headers, params, probe)
	except requests.HTTPError:
		# Combining $filter with $orderby is rejected by some tenants ("the
		# restriction or sort order is too complex"). The default order of a
		# message collection is receivedDateTime descending, so the listing is
		# still correct without it - it is only the oldest-first request that
		# then has to be satisfied by sorting what came back
		params.pop('$orderby')
		envelopes = _page_through(url, headers, params, probe)
		envelopes.sort(key = lambda envelope: envelope.get('receivedDateTime') or '', reverse = not ascending)
	more = len(envelopes) > max_messages
	return envelopes[:max_messages], more


def _page_through(url, headers, params, wanted):
	collected = []
	next_url = url
	next_params = params
	# Follow the @odata.nextLink pagination until enough messages have been collected
	while next_url is not None and len(collected) < wanted:
		response = requests.get(next_url, headers = headers, params = next_params, timeout = REQUEST_TIMEOUT)
		response.raise_for_status()
		data = response.json()
		collected.extend(data.get('value', []))
		next_url = data.get('@odata.nextLink')
		# The nextLink URL already embeds the query parameters
		next_params = None
	return collected[:wanted]


# Download the full RFC822 MIME content of a message
def download_mime(headers, mailbox, message_id):
	url = _mailbox_url(mailbox) + '/messages/{0}/$value'.format(urllib.parse.quote(message_id, safe = ''))
	response = requests.get(url, headers = headers, timeout = REQUEST_TIMEOUT)
	response.raise_for_status()
	return response.content


# Read the full MIME content of a single message WITHOUT marking it as read.
# This is what backs the on-demand body load: an analyst opening an email that
# was listed from its envelope alone is reading it, not analyzing it, so it has
# to stay in the pending queue exactly as it was
def peek_message(tenant_id, client_id, client_secret, mailbox, message_id):
	headers = auth_headers(tenant_id, client_id, client_secret)
	try:
		return download_mime(headers, mailbox, message_id)
	except requests.HTTPError as error:
		if error.response is not None and error.response.status_code == 404:
			return None
		raise


# Fetch a single message by id and mark it as read, mirroring the IMAP fetch behavior
# Returns None when the message does not exist anymore or has already been read
# (which means that it has already been analyzed, possibly by another analyst)
def fetch_message(tenant_id, client_id, client_secret, mailbox, message_id):
	headers = auth_headers(tenant_id, client_id, client_secret)
	message_url = _mailbox_url(mailbox) + '/messages/{0}'.format(urllib.parse.quote(message_id, safe = ''))
	response = requests.get(message_url, headers = headers, params = {'$select': 'isRead'}, timeout = REQUEST_TIMEOUT)
	if response.status_code == 404:
		return None
	response.raise_for_status()
	if response.json().get('isRead'):
		return None
	raw_message = download_mime(headers, mailbox, message_id)
	patch_headers = dict(headers)
	patch_headers['Content-Type'] = 'application/json'
	response = requests.patch(message_url, headers = patch_headers, json = {'isRead': True}, timeout = REQUEST_TIMEOUT)
	response.raise_for_status()
	return raw_message
