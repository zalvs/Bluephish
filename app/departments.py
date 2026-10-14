"""Which area of the organization a report came from.

The application never knew anything about the reporter beyond the address the
message arrived from, so "Departamentos mais visados" had nothing to count. The
missing link is the directory: Entra ID already holds, for every person in the
organization, the department they belong to. This module asks it.

It is deliberately *not* a mapping the SOC declares by hand. A hand-written list
is wrong the day somebody changes team and nobody notices, and the dashboard
keeps reporting the old department with no sign that it drifted. The directory
is the organization's own answer to the question, kept current by the people
whose job that is.

Shape of the module:

  load_config()     the `departments` section of configuration.json, normalized.
                    By default it borrows the Microsoft 365 credentials already
                    configured for the mailbox — same tenant, same app
                    registration — so the only new thing an admin has to do is
                    grant User.Read.All to it.

  resolve()         address → department, through the cache. Never raises: the
                    analysis pipeline calls it, and a directory that is down
                    must cost a label on a chart, not the analysis.

  probe() / test()  what the settings screen calls. These *do* surface the
                    error, because an admin pressing Testar is asking exactly
                    that question.

graph_directory.py is the Graph client; this module is the configuration, the
cache and the policy around it.
"""

import json
import re
import time

import graph_directory

CONFIG_SECTION = 'departments'

# A department name longer than this is a paste accident, not a name
MAX_NAME_LENGTH = 60

# How long a resolved address is reused before Entra ID is asked again, when the
# configuration names no lifetime. A department changes a few times a year; the
# same reporter can send a dozen reports in an afternoon
DEFAULT_CACHE_HOURS = 24

# Bounds on the configured lifetime. Zero would mean a directory round trip
# inside every analysis; a month would outlive a reorganization
MIN_CACHE_HOURS = 1
MAX_CACHE_HOURS = 720

# {address: (expires_at_epoch, department)}. Negative answers are cached too —
# an outside reporter who is not in the tenant would otherwise cost a Graph call
# on every single report they send
_cache = {}


def default_config():
	"""The shape the settings screen and the analysis both expect."""
	return {
		'enabled': False,
		'attribute': graph_directory.DEFAULT_ATTRIBUTE,
		# Borrow the mailbox credentials by default: same tenant, same app
		'useEmailCredentials': True,
		'tenantId': '',
		'clientId': '',
		'clientSecret': '',
		'cacheHours': DEFAULT_CACHE_HOURS
	}


def address_of(reporter):
	"""The bare address inside a From value, which may carry a display name."""
	value = str(reporter or '').strip()
	match = re.search(r'<([^<>]+)>', value)
	if match:
		value = match.group(1)
	return value.strip().strip('<>').lower()


def normalize_name(name):
	"""A department name usable as a case tag: single line, bounded, no comma.

	The comma is what separates tags everywhere else in this application, so a
	name carrying one would split into two departments the moment it is read
	back off the case.
	"""
	name = ' '.join(str(name or '').split()).replace(',', ' ')
	return name[:MAX_NAME_LENGTH].strip()


def normalize_config(raw):
	"""Coerce whatever configuration.json holds into the documented shape."""
	raw = raw if isinstance(raw, dict) else {}
	config = default_config()
	config['enabled'] = bool(raw.get('enabled', False))
	config['attribute'] = graph_directory.normalize_attribute(raw.get('attribute'))
	config['useEmailCredentials'] = bool(raw.get('useEmailCredentials', True))
	config['tenantId'] = str(raw.get('tenantId') or '').strip()
	config['clientId'] = str(raw.get('clientId') or '').strip()
	config['clientSecret'] = str(raw.get('clientSecret') or '')
	try:
		hours = int(raw.get('cacheHours', DEFAULT_CACHE_HOURS))
	except (TypeError, ValueError):
		hours = DEFAULT_CACHE_HOURS
	config['cacheHours'] = max(MIN_CACHE_HOURS, min(hours, MAX_CACHE_HOURS))
	return config


def email_credentials(conf_dict):
	"""The Microsoft 365 credentials configured for the mailbox, if any."""
	m365 = ((conf_dict or {}).get('email_sync') or {}).get('m365') or {}
	return (
		str(m365.get('tenantId') or '').strip(),
		str(m365.get('clientId') or '').strip(),
		str(m365.get('clientSecret') or '')
	)


def credentials_for(config, conf_dict):
	"""Which credentials this lookup uses, and where they came from.

	Borrowing the mailbox app registration is the default because it is the same
	tenant and one fewer secret on disk. A Gmail installation whose directory is
	still Entra ID has no mailbox credentials to borrow, which is what the second
	branch is for.
	"""
	if config['useEmailCredentials']:
		return email_credentials(conf_dict)
	return config['tenantId'], config['clientId'], config['clientSecret']


def credentials_are_complete(credentials):
	return all(bool(part) for part in credentials)


def load_config(path = 'configuration.json'):
	"""The departments section plus the credentials it resolves to.

	Returns (config, credentials). Never raises: a missing or unreadable
	configuration file leaves the feature off, which is what every caller wants
	when it cannot even read the settings.
	"""
	try:
		with open(path) as conf_file:
			conf_dict = json.load(conf_file)
	except Exception:
		return default_config(), ('', '', '')
	config = normalize_config(conf_dict.get(CONFIG_SECTION))
	return config, credentials_for(config, conf_dict)


def cache_get(address):
	entry = _cache.get(address)
	if entry is None or entry[0] <= time.time():
		return None
	return entry[1]


def cache_put(address, department, cache_hours):
	_cache[address] = (time.time() + cache_hours * 3600, department)


def clear_cache():
	"""Forget every resolved address.

	Called when the settings change: a lookup answered under the old attribute or
	the old credentials says nothing about what the new ones would answer.
	"""
	_cache.clear()


def resolve(reporter, config, credentials, on_error = None):
	"""The department of a reporter, or '' when the directory has none.

	Never raises. `on_error` is called with a message when the directory could
	not answer, so the caller can log it — the analysis continues either way, and
	an unattributed report is exactly what the dashboards are prepared to show.
	"""
	if not config['enabled']:
		return ''
	address = address_of(reporter)
	if not address:
		return ''
	if not credentials_are_complete(credentials):
		if on_error:
			on_error('As credenciais do Entra ID para a consulta de departamento estão incompletas')
		return ''

	cached = cache_get(address)
	if cached is not None:
		return cached

	try:
		value, _found = graph_directory.lookup_user(
			credentials[0], credentials[1], credentials[2], address, config['attribute'])
	except graph_directory.DirectoryError as error:
		# Not cached: a permission that gets granted, or a directory that comes
		# back, must take effect on the next report and not in a day
		if on_error:
			on_error(str(error))
		return ''
	except Exception as error:
		if on_error:
			on_error('Falha inesperada ao consultar o Entra ID: {0}'.format(error))
		return ''

	department = normalize_name(value)
	cache_put(address, department, config['cacheHours'])
	return department


def resolve_from_file(reporter, path = 'configuration.json', on_error = None):
	"""Department of a reporter according to the configuration on disk."""
	config, credentials = load_config(path)
	return resolve(reporter, config, credentials, on_error = on_error)
