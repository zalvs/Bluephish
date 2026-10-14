"""Tests for the blocking destinations.

Same rule as the analyzer tests: the vendor HTTP call is not mocked, because a
test asserting against a hand-written fake of a PAN-OS response proves only that
the fake matches the code. What gets pinned here is everything that decides
*whether* a call happens and *with what* — and here that matters more than in
`test_analyzers.py`, because a mistake in this module does not produce a wrong
verdict, it drops legitimate traffic.

Four things carry the risk, and all four are pure:

  normalize_target()    refuses what cannot be blocked before anything leaves
                        the process — an MD5 sent to a list that only takes
                        SHA-256, a value with a space in it, a bare word posing
                        as a domain.
  available_targets()   the difference between what a destination *can* block
                        and what it can block *as configured*. A FortiGate with
                        no URL filter id declares url support and has nowhere to
                        put one.
  validate_entry()      a secret must never be cleared by an empty field, and a
                        management address must pass the same destination guard
                        as a custom analyzer's.
  public_config()       a stored secret must never travel back to the browser.

Run with:  python -m unittest test_responders   (from the app/ directory)
"""

import unittest

import responders as rp


def entry(responder_id, **over):
	"""A saved configuration for one destination, defaults filled in."""
	base = dict(rp.default_config()[responder_id])
	base['enabled'] = True
	base.update(over)
	return base


class Targets(unittest.TestCase):
	"""normalize_target: the gate every block passes through."""

	def refuse(self, target_type, value):
		with self.assertRaises(rp.ResponderError) as caught:
			rp.normalize_target(target_type, value)
		return str(caught.exception)

	def test_only_sha256_can_be_blocked(self):
		# The Tenant Allow/Block List takes SHA-256 and nothing else, so an MD5 is
		# refused here rather than sent to fail on the other side
		sha256 = 'a' * 64
		self.assertEqual(rp.normalize_target('hash', sha256), ('hash', sha256))
		self.assertIn('SHA-256', self.refuse('hash', 'd' * 32))
		self.assertIn('SHA-256', self.refuse('hash', 'e' * 40))

	def test_a_hash_is_lowercased(self):
		# The same hash in two cases must not become two block entries
		_type, value = rp.normalize_target('hash', 'A' * 64)
		self.assertEqual(value, 'a' * 64)

	def test_a_domain_is_lowercased(self):
		self.assertEqual(rp.normalize_target('domain', 'Exemplo.COM'), ('domain', 'exemplo.com'))

	def test_a_bare_word_is_not_a_domain(self):
		self.refuse('domain', 'localhost')

	def test_an_address_without_an_at_is_not_a_sender(self):
		self.refuse('mail', 'exemplo.com')

	def test_an_invalid_ip_is_refused(self):
		self.refuse('ip', '999.1.1.1')
		self.refuse('ip', 'exemplo.com')

	def test_a_value_with_whitespace_is_refused(self):
		# Two indicators pasted as one would block neither correctly
		self.refuse('domain', 'exemplo.com outro.com')
		self.refuse('url', 'exemplo.com/a\nexemplo.com/b')

	def test_a_filename_is_not_blockable(self):
		# No destination here blocks by file name; offering it would be a lie
		error = self.refuse('filename', 'fatura.pdf')
		self.assertIn('filename', error)

	def test_the_thehive_compound_type_is_reduced(self):
		# The pipeline tags forwarded attachments as 'file_message/rfc822'; the
		# same reduction analyzers.supports() does must happen here
		self.assertEqual(rp.normalize_target('domain_x', 'exemplo.com')[0], 'domain')


class Normalization(unittest.TestCase):
	"""The value shapes each vendor expects."""

	def test_the_scheme_is_stripped(self):
		self.assertEqual(rp.strip_scheme('https://exemplo.com/pagina/'), 'exemplo.com/pagina')
		self.assertEqual(rp.strip_scheme('http://exemplo.com/'), 'exemplo.com')

	def test_a_host_comes_out_of_a_url(self):
		self.assertEqual(rp.host_of('https://exemplo.com/a/b'), 'exemplo.com')
		self.assertEqual(rp.host_of('exemplo.com/a'), 'exemplo.com')
		self.assertEqual(rp.host_of('exemplo.com'), 'exemplo.com')

	def test_a_panos_domain_covers_the_whole_site(self):
		# exemplo.com/ matches the site; exemplo.com alone matches nothing there
		self.assertEqual(rp.panos_url_entry('exemplo.com'), 'exemplo.com/')
		self.assertEqual(rp.panos_url_entry('https://exemplo.com'), 'exemplo.com/')

	def test_a_panos_path_is_kept_as_typed(self):
		self.assertEqual(rp.panos_url_entry('https://exemplo.com/login'), 'exemplo.com/login')

	def test_a_fortigate_object_name_is_valid_and_prefixed(self):
		name = rp.fortigate_object_name('https://exemplo.com/a?b=c')
		self.assertTrue(name.startswith('bp-'))
		self.assertLessEqual(len(name), 63)
		for character in name:
			self.assertTrue(character.isalnum() or character in '._-', character)

	def test_a_domain_is_a_sender_block_not_a_url_block(self):
		# Not obvious, and getting it wrong blocks the wrong thing: a sender domain
		# belongs in the Sender list, not in the Url list
		self.assertEqual(rp.eop_list_type('domain'), 'Sender')
		self.assertEqual(rp.eop_list_type('mail'), 'Sender')
		self.assertEqual(rp.eop_list_type('url'), 'Url')
		self.assertEqual(rp.eop_list_type('hash'), 'FileHash')

	def test_an_ip_has_no_place_in_the_tenant_list(self):
		# EOP's list holds no IP entries; the firewalls take those
		with self.assertRaises(rp.ResponderError):
			rp.eop_list_type('ip')

	def test_an_eop_url_travels_without_its_scheme(self):
		self.assertEqual(rp.eop_entry_value('url', 'https://exemplo.com/x'), 'exemplo.com/x')
		self.assertEqual(rp.eop_entry_value('mail', 'a@exemplo.com'), 'a@exemplo.com')


class AvailableTargets(unittest.TestCase):
	"""What a destination blocks as configured, not as declared."""

	def test_a_fortigate_without_a_url_filter_refuses_urls(self):
		available = rp.available_targets('fortigate', entry('fortigate', urlFilter = ''))
		self.assertNotIn('url', available)
		# and keeps everything that does not depend on it
		self.assertIn('ip', available)
		self.assertIn('domain', available)

	def test_a_fortigate_with_a_url_filter_accepts_urls(self):
		self.assertIn('url', rp.available_targets('fortigate', entry('fortigate', urlFilter = '1')))

	def test_a_checkpoint_without_an_application_site_refuses_names(self):
		available = rp.available_targets('checkpoint', entry('checkpoint', applicationSite = ''))
		self.assertEqual(available, ['ip'])

	def test_eop_never_offers_ip(self):
		self.assertNotIn('ip', rp.available_targets('eop', entry('eop')))

	def test_no_firewall_offers_hash(self):
		for responder_id in ('panos', 'fortigate', 'checkpoint'):
			self.assertNotIn('hash', rp.available_targets(responder_id, entry(responder_id)))

	def test_responders_for_skips_the_disabled(self):
		config = rp.default_config()
		config['eop'] = entry('eop')
		config['panos']['enabled'] = False
		self.assertEqual(rp.responders_for('mail', config), ['eop'])
		self.assertEqual(rp.responders_for('ip', config), [])


class Validation(unittest.TestCase):
	"""validate_entry: what the settings form is allowed to save."""

	def submit(self, responder_id, **over):
		base = {'enabled': True}
		base.update(rp.default_config()[responder_id])
		base['enabled'] = True
		base.update(over)
		return base

	def test_a_blank_secret_keeps_the_stored_one(self):
		stored = {'clientSecret': 'guardado'}
		result, error = rp.validate_entry('eop', self.submit('eop',
			tenantId = 't', clientId = 'c', clientSecret = '', organization = 'contoso.onmicrosoft.com'), stored)
		self.assertIsNone(error)
		self.assertEqual(result['clientSecret'], 'guardado')

	def test_a_missing_credential_only_blocks_enabling(self):
		# Filling the form in stages must be possible; running without a key must not
		half, error = rp.validate_entry('eop', self.submit('eop', enabled = False,
			tenantId = '', clientId = '', clientSecret = '', organization = ''), None)
		self.assertIsNone(error)
		self.assertFalse(half['enabled'])

		_result, error = rp.validate_entry('eop', self.submit('eop',
			tenantId = '', clientId = 'c', clientSecret = 's', organization = 'o'), None)
		self.assertIsNotNone(error)

	def test_the_expiration_stays_inside_what_microsoft_accepts(self):
		_result, error = rp.validate_entry('eop', self.submit('eop',
			tenantId = 't', clientId = 'c', clientSecret = 's',
			organization = 'o', expirationDays = 400), None)
		self.assertIsNotNone(error)

	def test_zero_days_is_a_valid_permanent_block(self):
		result, error = rp.validate_entry('eop', self.submit('eop',
			tenantId = 't', clientId = 'c', clientSecret = 's',
			organization = 'o', expirationDays = 0), None)
		self.assertIsNone(error)
		self.assertEqual(result['expirationDays'], 0)

	def test_an_unknown_option_is_refused(self):
		_result, error = rp.validate_entry('panos', self.submit('panos',
			url = 'https://192.0.2.10', apiKey = 'k', commit = 'talvez'), None)
		self.assertIsNotNone(error)

	def test_a_private_management_address_is_allowed(self):
		# A perimeter firewall never has a public address. Refusing one would make
		# the whole screen useless for the operations that most want it.
		result, error = rp.validate_entry('panos', self.submit('panos',
			url = 'https://192.168.1.1', apiKey = 'k'), None)
		self.assertIsNone(error)
		self.assertEqual(result['url'], 'https://192.168.1.1')

	def test_the_cloud_metadata_address_is_still_refused(self):
		# Internal is allowed; the instance credential store never is
		_result, error = rp.validate_entry('panos', self.submit('panos',
			url = 'https://169.254.169.254', apiKey = 'k'), None)
		self.assertIsNotNone(error)
		self.assertIn('169.254.169.254', error)

	def test_an_address_without_a_scheme_is_refused(self):
		_result, error = rp.validate_entry('fortigate', self.submit('fortigate',
			url = '192.0.2.20', apiToken = 't'), None)
		self.assertIsNotNone(error)

	def test_an_unknown_responder_is_refused(self):
		_result, error = rp.validate_entry('naoexiste', {}, None)
		self.assertIsNotNone(error)


class Secrets(unittest.TestCase):
	"""public_config: what the browser is allowed to see."""

	def test_no_secret_travels_back(self):
		config = rp.default_config()
		config['eop']['clientSecret'] = 'muito-secreto'
		config['panos']['apiKey'] = 'chave-panos'
		config['fortigate']['apiToken'] = 'token-forti'
		config['checkpoint']['password'] = 'senha-cp'

		serialized = repr(rp.public_config(config))
		for secret in ('muito-secreto', 'chave-panos', 'token-forti', 'senha-cp'):
			self.assertNotIn(secret, serialized)

	def test_the_presence_of_a_secret_is_reported(self):
		config = rp.default_config()
		config['eop']['clientSecret'] = 'x'
		public = rp.public_config(config)
		self.assertTrue(public['eop']['hasClientSecret'])
		self.assertFalse(public['panos']['hasApiKey'])

	def test_a_non_secret_field_round_trips(self):
		config = rp.default_config()
		config['panos']['url'] = 'https://192.0.2.10'
		self.assertEqual(rp.public_config(config)['panos']['url'], 'https://192.0.2.10')


class Registry(unittest.TestCase):
	"""Integrity of the registry the interface renders itself from."""

	def test_every_responder_has_a_client_and_a_probe(self):
		# A destination in the registry with no client would render a card whose
		# Save works and whose block raises KeyError
		for spec in rp.RESPONDERS:
			self.assertIn(spec['id'], rp.BLOCKERS, spec['id'])
			self.assertIn(spec['id'], rp.PROBES, spec['id'])

	def test_every_responder_has_a_guide(self):
		import responder_guides
		for spec in rp.RESPONDERS:
			self.assertTrue(responder_guides.guide_for(spec['id']), spec['id'])
			self.assertIn(spec['family'], responder_guides.FAMILIES, spec['id'])

	def test_every_declared_target_is_a_known_type(self):
		for spec in rp.RESPONDERS:
			for target in spec['targets']:
				self.assertIn(target, rp.TARGET_TYPES, spec['id'])
				self.assertIn(target, rp.TARGET_LABEL, target)

	def test_every_firewall_asks_about_tls_validation(self):
		# A management interface almost always has its own certificate, and the way
		# out of that must be an explicit choice with a warning, never a silent
		# verify=False in the client
		for spec in rp.RESPONDERS:
			if spec['family'] != 'firewall':
				continue
			keys = [field['key'] for field in spec['credentials']]
			self.assertIn('verifyTls', keys, spec['id'])
			self.assertIn('url', keys, spec['id'])

	def test_tls_validation_is_on_by_default(self):
		config = rp.default_config()
		for spec in rp.RESPONDERS:
			if spec['family'] != 'firewall':
				continue
			self.assertEqual(config[spec['id']]['verifyTls'], 'sim', spec['id'])

	def test_a_disabled_destination_never_calls_out(self):
		config = rp.default_config()
		result = rp.run('eop', 'mail', 'a@exemplo.com', config)
		self.assertFalse(result['ok'])
		self.assertEqual(result['status'], 'error')
		self.assertIn('desabilitado', result['error'])

	def test_run_refuses_a_type_the_destination_cannot_block(self):
		config = rp.default_config()
		config['eop'] = entry('eop', tenantId = 't', clientId = 'c',
			clientSecret = 's', organization = 'o')
		result = rp.run('eop', 'ip', '198.51.100.7', config)
		self.assertFalse(result['ok'])
		self.assertIn('não bloqueia', result['error'])

	def test_run_never_raises_on_a_malformed_indicator(self):
		config = rp.default_config()
		config['panos'] = entry('panos', url = 'https://192.0.2.10', apiKey = 'k')
		result = rp.run('panos', 'ip', 'nao-e-um-ip', config)
		self.assertFalse(result['ok'])
		self.assertIn('não é um endereço IP', result['error'])


if __name__ == '__main__':
	unittest.main()
