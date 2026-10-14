"""Tests for analyst-defined analyzers.

The part worth pinning down is the part that decides where the server is allowed
to send a request, and how a vendor's answer becomes a verdict. The HTTP call
itself is deliberately not mocked, for the same reason the native clients are
not: a test asserting against a hand-written fake proves only that the fake
matches the code.

Run with:  python -m unittest test_custom_analyzers   (from the app/ directory)
"""

import unittest

import custom_analyzers as ca


def definition(**over):
	base = {
		'name': 'Meu Fornecedor',
		'url': 'https://api.exemplo.com/v1/lookup?indicator={value}',
		'method': 'GET',
		'authType': 'header',
		'authName': 'X-Api-Key',
		'authValue': 'segredo',
		'observables': ['ip', 'domain'],
		'valuePath': 'data.classification',
		'levelMap': [{'value': 'malicious', 'level': 'malicious'},
			{'value': 'clean', 'level': 'safe'}],
		'fallbackLevel': 'info'
	}
	base.update(over)
	return base


class Destination(unittest.TestCase):
	"""The SSRF guard. Everything else in this module rests on it."""

	def refuse(self, url):
		ok, error = ca.validate_destination(url)
		self.assertFalse(ok, url)
		return error

	def test_localhost_is_refused(self):
		self.refuse('https://127.0.0.1/lookup')
		self.refuse('https://[::1]/lookup')

	def test_a_private_range_is_refused(self):
		for host in ('10.0.0.5', '192.168.1.10', '172.16.4.4'):
			self.refuse('https://{0}/lookup'.format(host))

	def test_the_cloud_metadata_address_is_refused(self):
		# The one that holds the instance credentials
		error = self.refuse('https://169.254.169.254/latest/meta-data/')
		self.assertIn('169.254.169.254', error)

	def test_link_local_and_unspecified_are_refused(self):
		self.refuse('https://169.254.1.1/x')
		self.refuse('https://0.0.0.0/x')

	def test_plain_http_is_refused(self):
		error = self.refuse('http://api.exemplo.com/lookup')
		self.assertIn('https', error)

	def test_an_empty_address_is_refused(self):
		self.refuse('')

	def test_a_name_that_does_not_resolve_is_refused(self):
		self.refuse('https://este-nome-nao-existe-mesmo-12345.invalid/x')

	def test_a_public_address_passes(self):
		ok, error = ca.validate_destination('https://8.8.8.8/lookup')
		self.assertTrue(ok, error)


class AddressesIsPrivateForgets(unittest.TestCase):
	"""Ranges that are not the internet, but that `is_private` alone lets through.

	The guard used to add up is_private, is_loopback, is_link_local and friends.
	On Python 3.8 (the image) 100.64.0.0/10 is none of those, and an IPv4 address
	can travel inside an IPv6 one. The rule now is `is_global`, with the embedded
	IPv4 judged as the IPv4 it is (BP-SEC-05).
	"""

	def forbidden(self, address, allow_internal = False):
		self.assertTrue(ca._is_forbidden_address(address, allow_internal),
			'{0} passou (allow_internal={1})'.format(address, allow_internal))

	def test_cgnat_is_not_the_internet(self):
		# Tailscale lives here, and so does Alibaba Cloud's metadata service
		self.forbidden('100.64.0.1')
		self.forbidden('100.100.100.200')

	def test_alibaba_metadata_stays_refused_with_the_internal_network_open(self):
		self.forbidden('100.100.100.200', allow_internal = True)

	def test_ipv4_mapped_metadata_is_the_metadata(self):
		self.forbidden('::ffff:169.254.169.254')
		self.forbidden('::ffff:169.254.169.254', allow_internal = True)

	def test_nat64_and_6to4_carry_the_ipv4_they_embed(self):
		# 169.254.169.254 = a9fe:a9fe
		self.forbidden('64:ff9b::a9fe:a9fe')
		self.forbidden('64:ff9b::a9fe:a9fe', allow_internal = True)
		self.forbidden('2002:a9fe:a9fe::1')
		self.forbidden('2002:a9fe:a9fe::1', allow_internal = True)
		self.forbidden('64:ff9b::7f00:1')

	def test_a_non_canonical_spelling_of_the_metadata_address_is_the_same_address(self):
		# The metadata list used to be compared as text
		self.forbidden('fd00:ec2:0:0::254', allow_internal = True)

	def test_ipv6_site_local_is_not_the_internet(self):
		self.forbidden('fec0::1')

	def test_a_public_address_still_passes(self):
		for address in ('8.8.8.8', '93.184.216.34', '2606:4700:4700::1111'):
			self.assertFalse(ca._is_forbidden_address(address), address)

	def test_the_internal_network_still_opens_when_opted_in(self):
		for address in ('10.0.0.5', '127.0.0.1', '100.64.0.1', 'fd12::1'):
			self.assertFalse(ca._is_forbidden_address(address, True), address)


class InternalNetwork(unittest.TestCase):
	"""An on-prem MISP has no public address. Reaching it is an explicit opt-in."""

	def allowed(self, url):
		ok, error = ca.validate_destination(url, True)
		self.assertTrue(ok, '{0}: {1}'.format(url, error))

	def refused(self, url):
		ok, error = ca.validate_destination(url, True)
		self.assertFalse(ok, url)
		return error

	def test_a_private_address_is_allowed_once_opted_in(self):
		for host in ('10.0.0.5', '192.168.1.10', '172.16.4.4'):
			self.allowed('https://{0}/lookup'.format(host))

	def test_localhost_is_allowed_once_opted_in(self):
		self.allowed('https://127.0.0.1/lookup')

	def test_plain_http_is_allowed_once_opted_in(self):
		# An internal service usually has no TLS, or a certificate of its own
		self.allowed('http://10.0.0.5/lookup')

	def test_the_metadata_address_stays_refused(self):
		# The highest-value SSRF target there is; never a legitimate analyzer
		error = self.refused('https://169.254.169.254/latest/meta-data/')
		self.assertIn('metadados', error.lower())

	def test_multicast_and_unspecified_stay_refused(self):
		self.refused('https://224.0.0.1/x')
		self.refused('https://0.0.0.0/x')

	def test_the_default_still_refuses_the_internal_network(self):
		# Opting in has to be a decision, not the starting state
		ok, error = ca.validate_destination('https://10.0.0.5/lookup')
		self.assertFalse(ok)
		self.assertIn('permitir rede interna', error)

	def test_the_flag_is_read_from_the_saved_definition(self):
		d, error = ca.validate_definition(definition(
			url = 'http://10.0.0.5/lookup?i={value}', allowInternal = True))
		self.assertIsNone(error)
		self.assertTrue(d['allowInternal'])

	def test_an_internal_address_without_the_flag_is_refused_on_save(self):
		_, error = ca.validate_definition(definition(url = 'https://10.0.0.5/x?i={value}'))
		self.assertIsNotNone(error)


class Description(unittest.TestCase):

	def test_the_description_is_optional(self):
		d, error = ca.validate_definition(definition())
		self.assertIsNone(error)
		self.assertEqual(d['description'], '')

	def test_the_description_reaches_the_card(self):
		d, _ = ca.validate_definition(definition(description = 'MISP da equipe de TI'))
		self.assertEqual(ca.to_spec(d)['description'], 'MISP da equipe de TI')

	def test_without_one_the_card_still_says_something_useful(self):
		d, _ = ca.validate_definition(definition())
		self.assertIn('api.exemplo.com', ca.to_spec(d)['description'])

	def test_an_overlong_description_is_refused(self):
		_, error = ca.validate_definition(definition(description = 'x' * 401))
		self.assertIn('400', error)

	def test_an_internal_analyzer_says_so_on_the_card(self):
		d, _ = ca.validate_definition(definition(
			url = 'http://10.0.0.5/x?i={value}', allowInternal = True))
		self.assertEqual(ca.to_spec(d)['kind'], 'rede interna')


class DefinitionValidation(unittest.TestCase):

	def test_a_valid_definition_is_accepted(self):
		result, error = ca.validate_definition(definition())
		self.assertIsNone(error)
		self.assertTrue(result['id'].startswith('custom_'))

	def test_a_name_is_required(self):
		_, error = ca.validate_definition(definition(name = ''))
		self.assertIn('nome', error.lower())

	def test_the_address_must_carry_the_value_placeholder(self):
		_, error = ca.validate_definition(definition(url = 'https://api.exemplo.com/v1/lookup'))
		self.assertIn('{value}', error)

	def test_a_private_destination_is_refused_at_save_time(self):
		_, error = ca.validate_definition(definition(url = 'https://10.1.2.3/x?i={value}'))
		self.assertIn('interna', error.lower())

	def test_files_are_never_an_allowed_observable(self):
		# Sending an attachment to an arbitrary endpoint is the exfiltration path
		# this whole module exists to close
		_, error = ca.validate_definition(definition(observables = ['file']))
		self.assertIsNotNone(error)
		self.assertNotIn('file', ca.ALLOWED_OBSERVABLES)

	def test_at_least_one_observable_is_required(self):
		_, error = ca.validate_definition(definition(observables = []))
		self.assertIsNotNone(error)

	def test_at_least_one_mapping_is_required(self):
		_, error = ca.validate_definition(definition(levelMap = []))
		self.assertIn('mapeie', error.lower())

	def test_an_unknown_level_is_refused(self):
		_, error = ca.validate_definition(
			definition(levelMap = [{'value': 'x', 'level': 'catastrofico'}]))
		self.assertIn('Nível inválido', error)

	def test_an_empty_secret_keeps_the_stored_one(self):
		stored = {'id': 'custom_x', 'authValue': 'guardado'}
		result, error = ca.validate_definition(definition(authValue = ''), stored)
		self.assertIsNone(error)
		self.assertEqual(result['authValue'], 'guardado')

	def test_authentication_none_needs_no_secret(self):
		result, error = ca.validate_definition(
			definition(authType = 'none', authName = '', authValue = ''))
		self.assertIsNone(error)
		self.assertEqual(result['authType'], 'none')

	def test_a_header_auth_needs_a_header_name(self):
		_, error = ca.validate_definition(definition(authName = ''))
		self.assertIsNotNone(error)

	def test_an_id_never_collides_with_a_native_analyzer(self):
		self.assertNotEqual(ca.make_id('virustotal', []), 'virustotal')

	def test_two_analyzers_with_the_same_name_get_different_ids(self):
		first = ca.make_id('Meu Fornecedor', [])
		second = ca.make_id('Meu Fornecedor', [first])
		self.assertNotEqual(first, second)

	def test_the_secret_never_reaches_the_browser(self):
		result, _ = ca.validate_definition(definition())
		public = ca.public_definition(result)
		self.assertNotIn('authValue', public)
		self.assertTrue(public['hasAuthValue'])


class ValueMapping(unittest.TestCase):
	"""Turning a vendor's answer into a level."""

	def setUp(self):
		self.d, _ = ca.validate_definition(definition())

	def level(self, value):
		return ca.level_from_map(self.d, {'value': value, 'path': 'data.classification'})

	def test_a_mapped_value_yields_its_level(self):
		self.assertEqual(self.level('malicious'), 'malicious')
		self.assertEqual(self.level('clean'), 'safe')

	def test_the_match_ignores_case_and_padding(self):
		self.assertEqual(self.level('  MALICIOUS '), 'malicious')

	def test_an_unmapped_value_falls_back(self):
		# A value nobody taught it to read is not a clean bill of health
		self.assertEqual(self.level('quem sabe'), 'info')

	def test_an_absent_value_falls_back(self):
		self.assertEqual(self.level(None), 'info')

	def test_no_signal_at_all_is_info(self):
		self.assertEqual(ca.level_from_map(self.d, None), 'info')

	def test_the_fallback_is_configurable(self):
		d, _ = ca.validate_definition(definition(fallbackLevel = 'suspicious'))
		self.assertEqual(ca.level_from_map(d, {'value': 'desconhecido'}), 'suspicious')


class PathReading(unittest.TestCase):

	def test_it_follows_a_dotted_path(self):
		self.assertEqual(ca.read_path({'data': {'attributes': {'score': 7}}}, 'data.attributes.score'), 7)

	def test_it_indexes_into_a_list(self):
		self.assertEqual(ca.read_path({'results': [{'verdict': 'bad'}]}, 'results.0.verdict'), 'bad')

	def test_a_missing_key_reads_as_absent(self):
		self.assertIsNone(ca.read_path({'data': {}}, 'data.score'))

	def test_a_path_through_a_scalar_reads_as_absent(self):
		self.assertIsNone(ca.read_path({'data': 5}, 'data.score'))

	def test_an_out_of_range_index_reads_as_absent(self):
		self.assertIsNone(ca.read_path({'r': []}, 'r.3'))


class Running(unittest.TestCase):

	def test_a_disabled_analyzer_does_not_reach_the_network(self):
		d, _ = ca.validate_definition(definition(enabled = False))
		result = ca.run(d, 'ip', '8.8.8.8')
		self.assertEqual(result['level'], 'info')
		self.assertIn('desabilitado', result['error'])

	def test_an_unsupported_observable_is_refused_before_any_call(self):
		d, _ = ca.validate_definition(definition(enabled = True, observables = ['ip']))
		result = ca.run(d, 'hash', 'a' * 64)
		self.assertEqual(result['level'], 'info')
		self.assertIn('não avalia', result['error'])

	def test_a_destination_that_turned_private_is_refused_at_call_time(self):
		# Saved while public, resolving to the internal network now
		d, _ = ca.validate_definition(definition(enabled = True))
		d['url'] = 'https://127.0.0.1/x?i={value}'
		result = ca.run(d, 'ip', '8.8.8.8')
		self.assertEqual(result['level'], 'info')
		self.assertIn('recusado', result['error'].lower())


if __name__ == '__main__':
	unittest.main()
