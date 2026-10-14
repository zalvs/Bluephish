"""Tests for the SMTP sender that replaced the Mailer responder of Cortex.

What is pinned down here is the part that decides *what gets sent and whether it
gets sent at all*: the validation of the form, the promise that a stored password
never leaves the process, and the shape of the message. The SMTP conversation
itself is deliberately not mocked — a test against a hand-written fake server
proves only that the fake matches the code, so the connection logic is kept thin
and the "Testar" button is what verifies it against a real server.

Run with:  python -m unittest test_mailer   (from the app/ directory)
"""

import email.header
import unittest

import mailer


def subject_of(message):
	"""The subject as a human reads it.

	A subject with an accent is RFC 2047 encoded on the wire, which is correct and
	is why it cannot be asserted against directly.
	"""
	return str(email.header.make_header(email.header.decode_header(str(message['Subject']))))


def filled(**overrides):
	entry = {
		'enabled': True,
		'host': 'smtp.exemplo.com',
		'port': 587,
		'security': 'starttls',
		'user': 'avisos@exemplo.com',
		'password': 'senha',
		'sender': 'avisos@exemplo.com',
		'senderName': 'BluePhish',
		'subjectPrefix': '[BluePhish]'
	}
	entry.update(overrides)
	return entry


class NotificationFlags(unittest.TestCase):
	"""O interruptor geral virou um por aviso, sem mudar o que ninguém recebia."""

	def test_a_legacy_switch_on_keeps_every_notice_on(self):
		self.assertEqual(mailer.notification_flags({'enabled': True}),
			{'start': True, 'safe': True, 'malicious': True, 'errata': False})

	def test_a_legacy_switch_off_keeps_every_notice_off(self):
		self.assertEqual(mailer.notification_flags({'enabled': False}),
			{'start': False, 'safe': False, 'malicious': False, 'errata': False})

	def test_a_missing_section_is_the_original_behavior(self):
		self.assertEqual(mailer.notification_flags({}), {'start': True, 'safe': True, 'malicious': True, 'errata': False})
		self.assertEqual(mailer.notification_flags(None), {'start': True, 'safe': True, 'malicious': True, 'errata': False})

	def test_each_notice_follows_its_own_key(self):
		flags = mailer.notification_flags({'enabled': True, 'startEnabled': False, 'maliciousEnabled': True})
		self.assertEqual(flags, {'start': False, 'safe': True, 'malicious': True, 'errata': False})


class Validation(unittest.TestCase):

	def validate(self, submitted, stored = None):
		return mailer.validate_entry(submitted, stored or {})

	def test_a_complete_form_is_accepted(self):
		entry, error = self.validate(filled())
		self.assertIsNone(error)
		self.assertEqual(entry['host'], 'smtp.exemplo.com')
		self.assertEqual(entry['port'], 587)

	def test_the_port_comes_back_as_a_number(self):
		entry, error = self.validate(filled(port = '465'))
		self.assertIsNone(error)
		self.assertEqual(entry['port'], 465)

	def test_a_non_numeric_port_is_refused(self):
		entry, error = self.validate(filled(port = 'quinhentos'))
		self.assertIsNone(entry)
		self.assertIn('número', error)

	def test_a_port_outside_the_range_is_refused(self):
		entry, error = self.validate(filled(port = 70000))
		self.assertIsNone(entry)
		self.assertIn('entre 1 e 65535', error)

	def test_an_unknown_security_mode_is_refused(self):
		entry, error = self.validate(filled(security = 'quase-tls'))
		self.assertIsNone(entry)
		self.assertIn('segurança', error)

	def test_a_sender_that_is_not_an_address_is_refused(self):
		# Caught here rather than at the end of every analysis, which is where it
		# would otherwise show up
		entry, error = self.validate(filled(sender = 'avisos'))
		self.assertIsNone(entry)
		self.assertIn('não parece um endereço', error)

	def test_a_missing_host_is_only_refused_when_sending_is_on(self):
		entry, error = self.validate(filled(enabled = False, host = ''))
		self.assertIsNone(error)
		self.assertEqual(entry['host'], '')

		entry, error = self.validate(filled(enabled = True, host = ''))
		self.assertIsNone(entry)
		self.assertIn('obrigatório', error)

	def test_a_password_without_a_user_is_refused(self):
		# The session would be opened unauthenticated and the server would refuse
		# the send without saying why
		entry, error = self.validate(filled(user = ''))
		self.assertIsNone(entry)
		self.assertIn('usuário', error)

	def test_a_blank_password_keeps_the_stored_one(self):
		entry, error = self.validate(filled(password = ''), stored = {'password': 'guardada'})
		self.assertIsNone(error)
		self.assertEqual(entry['password'], 'guardada')

	def test_a_typed_password_replaces_the_stored_one(self):
		entry, error = self.validate(filled(password = 'nova'), stored = {'password': 'guardada'})
		self.assertIsNone(error)
		self.assertEqual(entry['password'], 'nova')

	def test_a_blank_non_secret_field_falls_back_to_its_default(self):
		entry, error = self.validate(filled(senderName = '', subjectPrefix = ''))
		self.assertIsNone(error)
		self.assertEqual(entry['senderName'], 'BluePhish')
		self.assertEqual(entry['subjectPrefix'], '[BluePhish]')


class PublicConfig(unittest.TestCase):

	def test_the_password_never_leaves_the_process(self):
		public = mailer.public_config(filled())
		self.assertNotIn('password', public)
		self.assertTrue(public['hasPassword'])

	def test_an_unset_password_is_reported_as_absent(self):
		public = mailer.public_config(filled(password = ''))
		self.assertFalse(public['hasPassword'])

	def test_the_non_secret_fields_do_come_back(self):
		public = mailer.public_config(filled())
		self.assertEqual(public['host'], 'smtp.exemplo.com')
		self.assertEqual(public['user'], 'avisos@exemplo.com')
		self.assertTrue(public['enabled'])


class ConfigMerging(unittest.TestCase):

	def test_a_configuration_without_the_section_yields_usable_defaults(self):
		config = mailer.load_config(path = 'no-such-file.json')
		self.assertFalse(config['enabled'])
		self.assertEqual(config['port'], 587)
		self.assertEqual(config['security'], 'starttls')


class MessageShape(unittest.TestCase):

	def build(self, entry = None, subject = 'Assunto', body = 'Corpo'):
		return mailer.build_message(entry or filled(), 'quem@denunciou.com', subject, body)

	def test_the_prefix_is_applied_to_the_subject(self):
		self.assertEqual(subject_of(self.build()), '[BluePhish] Assunto')

	def test_without_a_prefix_the_subject_is_untouched(self):
		message = self.build(entry = filled(subjectPrefix = ''))
		self.assertEqual(subject_of(message), 'Assunto')

	def test_the_sender_name_travels_with_the_address(self):
		message = self.build()
		self.assertIn('avisos@exemplo.com', message['From'])
		self.assertIn('BluePhish', message['From'])

	def test_the_message_carries_a_message_id(self):
		# Without one many servers treat the message as suspicious, and a security
		# notification is the last thing that should land in spam
		message = self.build()
		self.assertTrue(message['Message-ID'])
		self.assertIn('exemplo.com', message['Message-ID'])

	def test_the_message_declares_itself_automatic(self):
		self.assertEqual(self.build()['Auto-Submitted'], 'auto-generated')

	def test_an_accented_subject_survives_the_encoding(self):
		# On the wire it travels RFC 2047 encoded; what matters is that it decodes
		# back to what the analyst typed
		message = self.build(subject = 'Análise concluída')
		self.assertEqual(subject_of(message), '[BluePhish] Análise concluída')
		# Serialized, the header carries no bare non-ASCII byte — which is what
		# would make a strict server reject the message
		serialized = message.as_string()
		self.assertNotIn('Análise', serialized)
		self.assertIn('=?utf-8?', serialized)


class Sending(unittest.TestCase):

	def test_a_disabled_mailer_does_not_reach_the_network(self):
		result = mailer.send('quem@denunciou.com', 'a', 'b', filled(enabled = False))
		self.assertFalse(result['ok'])
		self.assertIn('desabilitado', result['error'])

	def test_an_invalid_recipient_is_refused_before_any_connection(self):
		result = mailer.send('nao-e-endereco', 'a', 'b', filled())
		self.assertFalse(result['ok'])
		self.assertIn('destino válido', result['error'])

	def test_a_missing_sender_is_refused_before_any_connection(self):
		result = mailer.send('quem@denunciou.com', 'a', 'b', filled(sender = ''))
		self.assertFalse(result['ok'])
		self.assertIn('Remetente', result['error'])


if __name__ == '__main__':
	unittest.main()
