"""Tests for the reporter → department lookup.

The department reaches an executive chart, so the failure that matters is the
silent one: a directory that is off, unreachable or missing a permission must
never look like an organization where nobody has a department. These pin down
which answers are cached, which are not, and what an analysis does when Entra ID
does not answer — without touching the network.

Run with:  python -m unittest test_departments   (from the app/ directory)
"""

import unittest

import departments
import graph_directory


class FakeDirectory:
	"""Stands in for graph_directory, counting the calls it receives."""

	def __init__(self, answers = None, raises = None):
		self.answers = answers or {}
		self.raises = raises
		self.calls = []

	def lookup_user(self, tenant_id, client_id, client_secret, address, attribute):
		self.calls.append((address, attribute))
		if self.raises is not None:
			raise self.raises
		if address not in self.answers:
			# Not in this tenant: an outside reporter
			return '', False
		return self.answers[address], True


def config(**overrides):
	built = departments.default_config()
	built['enabled'] = True
	built.update(overrides)
	return departments.normalize_config(built)


CREDENTIALS = ('tenant', 'client', 'secret')


class Setup(unittest.TestCase):

	def setUp(self):
		self.real_lookup = graph_directory.lookup_user
		self.directory = FakeDirectory({'ana@acme.com': 'Jurídico'})
		graph_directory.lookup_user = self.directory.lookup_user
		departments.clear_cache()

	def tearDown(self):
		graph_directory.lookup_user = self.real_lookup
		departments.clear_cache()


class AddressExtraction(unittest.TestCase):

	def test_a_display_name_is_stripped(self):
		self.assertEqual(departments.address_of('Fulano de Tal <fulano@acme.com>'), 'fulano@acme.com')

	def test_the_comparison_is_case_insensitive(self):
		self.assertEqual(departments.address_of('  Fulano@ACME.com '), 'fulano@acme.com')

	def test_nothing_in_gives_nothing_out(self):
		self.assertEqual(departments.address_of(None), '')
		self.assertEqual(departments.address_of(''), '')


class Resolution(Setup):

	def test_the_directory_answer_becomes_the_department(self):
		self.assertEqual(departments.resolve('Ana <ana@acme.com>', config(), CREDENTIALS), 'Jurídico')

	def test_a_reporter_outside_the_tenant_is_left_unattributed(self):
		# Not an error: an outside address simply has no area in this organization
		self.assertEqual(departments.resolve('eve@outra.com', config(), CREDENTIALS), '')

	def test_a_disabled_lookup_never_touches_the_directory(self):
		self.assertEqual(departments.resolve('ana@acme.com', config(enabled = False), CREDENTIALS), '')
		self.assertEqual(self.directory.calls, [])

	def test_incomplete_credentials_report_instead_of_calling(self):
		errors = []
		self.assertEqual(departments.resolve('ana@acme.com', config(), ('tenant', '', ''),
			on_error = errors.append), '')
		self.assertEqual(self.directory.calls, [])
		self.assertEqual(len(errors), 1)

	def test_the_configured_attribute_is_the_one_asked_for(self):
		departments.resolve('ana@acme.com', config(attribute = 'officeLocation'), CREDENTIALS)
		self.assertEqual(self.directory.calls[0][1], 'officeLocation')

	def test_an_unknown_attribute_falls_back_to_department(self):
		self.assertEqual(config(attribute = 'inventado')['attribute'], 'department')


class DirectoryFailure(Setup):

	def test_a_failing_directory_costs_a_label_and_not_the_analysis(self):
		# The verdict is already decided when this runs; a chart label is never
		# worth failing an analysis over
		graph_directory.lookup_user = FakeDirectory(
			raises = graph_directory.DirectoryError('sem permissão')).lookup_user
		errors = []
		self.assertEqual(departments.resolve('ana@acme.com', config(), CREDENTIALS,
			on_error = errors.append), '')
		self.assertEqual(errors, ['sem permissão'])

	def test_an_unexpected_exception_is_swallowed_too(self):
		graph_directory.lookup_user = FakeDirectory(raises = RuntimeError('boom')).lookup_user
		errors = []
		self.assertEqual(departments.resolve('ana@acme.com', config(), CREDENTIALS,
			on_error = errors.append), '')
		self.assertEqual(len(errors), 1)

	def test_a_failure_is_not_cached(self):
		# A permission that gets granted, or a directory that comes back, has to
		# take effect on the next report — not in a day
		failing = FakeDirectory(raises = graph_directory.DirectoryError('sem permissão'))
		graph_directory.lookup_user = failing.lookup_user
		departments.resolve('ana@acme.com', config(), CREDENTIALS)
		graph_directory.lookup_user = self.directory.lookup_user
		self.assertEqual(departments.resolve('ana@acme.com', config(), CREDENTIALS), 'Jurídico')


class Caching(Setup):

	def test_a_resolved_address_is_not_asked_twice(self):
		for _ in range(3):
			departments.resolve('ana@acme.com', config(), CREDENTIALS)
		self.assertEqual(len(self.directory.calls), 1)

	def test_an_outside_reporter_is_cached_too(self):
		# Otherwise every report from the same outside address costs a Graph call
		for _ in range(3):
			departments.resolve('eve@outra.com', config(), CREDENTIALS)
		self.assertEqual(len(self.directory.calls), 1)

	def test_the_cache_expires(self):
		departments.resolve('ana@acme.com', config(), CREDENTIALS)
		# Rewrite the entry as already expired
		expires, value = departments._cache['ana@acme.com']
		departments._cache['ana@acme.com'] = (0, value)
		departments.resolve('ana@acme.com', config(), CREDENTIALS)
		self.assertEqual(len(self.directory.calls), 2)

	def test_clearing_the_cache_forces_a_new_lookup(self):
		departments.resolve('ana@acme.com', config(), CREDENTIALS)
		departments.clear_cache()
		departments.resolve('ana@acme.com', config(), CREDENTIALS)
		self.assertEqual(len(self.directory.calls), 2)


class Credentials(unittest.TestCase):

	def conf(self):
		return {'email_sync': {'m365': {'tenantId': 't', 'clientId': 'c', 'clientSecret': 's'}}}

	def test_the_mailbox_registration_is_borrowed_by_default(self):
		self.assertEqual(departments.credentials_for(config(), self.conf()), ('t', 'c', 's'))

	def test_its_own_registration_is_used_when_asked(self):
		own = config(useEmailCredentials = False, tenantId = 'T', clientId = 'C', clientSecret = 'S')
		self.assertEqual(departments.credentials_for(own, self.conf()), ('T', 'C', 'S'))

	def test_a_gmail_installation_has_nothing_to_borrow(self):
		self.assertFalse(departments.credentials_are_complete(
			departments.credentials_for(config(), {'email_sync': {'provider': 'gmail'}})))


class Naming(unittest.TestCase):

	def test_a_comma_in_a_name_is_removed(self):
		# The comma separates tags everywhere else, so a name carrying one would
		# split into two departments the moment it is read back off the case
		self.assertNotIn(',', departments.normalize_name('Jurídico, Compliance'))

	def test_a_name_is_bounded(self):
		self.assertEqual(len(departments.normalize_name('x' * 200)), departments.MAX_NAME_LENGTH)

	def test_a_malformed_config_does_not_raise(self):
		self.assertEqual(departments.normalize_config(None), departments.default_config())
		self.assertEqual(departments.normalize_config({'cacheHours': 'muitas'})['cacheHours'],
			departments.DEFAULT_CACHE_HOURS)

	def test_the_cache_lifetime_is_bounded(self):
		self.assertEqual(departments.normalize_config({'cacheHours': 0})['cacheHours'], departments.MIN_CACHE_HOURS)
		self.assertEqual(departments.normalize_config({'cacheHours': 99999})['cacheHours'], departments.MAX_CACHE_HOURS)


if __name__ == '__main__':
	unittest.main()
