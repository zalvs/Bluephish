"""Testes da errata ao denunciante e das transições de veredito que a disparam.

A errata é o único aviso que sai de uma pessoa e não de uma análise. Os erros
que importam aqui são dois, e nenhum levanta exceção: mandar quando não devia (a
confirmação de um malicioso virando "era legítimo") e dizer "enviada" quando não
foi (um registro sem denunciante, ou um SMTP fora do ar).

Rodar com:  python -m unittest test_errata   (a partir de app/)
"""

import unittest

import errata
import mailer
import reclassification


class Composing(unittest.TestCase):

	def test_the_subject_is_named_in_the_mail_subject_and_body(self):
		subject, body = errata.compose('Sua fatura venceu')
		self.assertEqual(subject, 'Errata: Sua fatura venceu')
		self.assertIn('[Sua fatura venceu]', body)

	def test_the_configured_message_replaces_the_default(self):
		_subject, body = errata.compose('Aviso', 'O e-mail {subject} era seguro.')
		self.assertEqual(body, 'O e-mail Aviso era seguro.')

	def test_an_email_without_subject_still_reads(self):
		subject, body = errata.compose('')
		self.assertEqual(subject, 'Errata: (sem assunto)')
		self.assertNotIn('{subject}', body)


class Sending(unittest.TestCase):

	def setUp(self):
		self.sent = []

	def fake(self, ok = True, error = ''):
		def send_mail(to, subject, body):
			self.sent.append((to, subject, body))
			return {'ok': ok, 'detail': '', 'error': error}
		return send_mail

	def test_it_is_sent_when_the_errata_switch_is_on(self):
		outcome = errata.send('ana@empresa.com', 'Aviso', {'errataEnabled': True}, self.fake())
		self.assertTrue(outcome['ok'])
		self.assertEqual(self.sent[0][0], 'ana@empresa.com')

	def test_it_is_not_sent_when_the_switch_is_off(self):
		outcome = errata.send('ana@empresa.com', 'Aviso', {'errataEnabled': False}, self.fake())
		self.assertFalse(outcome['ok'])
		self.assertEqual(self.sent, [])
		self.assertIn('desligada', outcome['detail'])

	def test_the_legacy_switch_is_not_inherited(self):
		# Um tipo novo de e-mail não nasce ligado só porque os avisos antigos estão
		self.assertFalse(errata.enabled({'enabled': True}))
		self.assertFalse(errata.enabled({}))
		self.assertTrue(errata.enabled({'enabled': False, 'errataEnabled': True}))

	def test_an_unknown_reporter_is_said_not_sent(self):
		outcome = errata.send('', 'Aviso', {'errataEnabled': True}, self.fake())
		self.assertFalse(outcome['ok'])
		self.assertEqual(self.sent, [])
		self.assertIn('não guardou quem denunciou', outcome['detail'])

	def test_a_failed_send_is_named_with_the_reason(self):
		outcome = errata.send('ana@empresa.com', 'Aviso', {'errataEnabled': True},
			self.fake(ok = False, error = 'Remetente não configurado.'))
		self.assertFalse(outcome['ok'])
		self.assertIn('Remetente não configurado.', outcome['detail'])

	def test_errata_is_a_notification_event(self):
		self.assertIn('errata', mailer.NOTIFICATION_EVENTS)


class Transitions(unittest.TestCase):
	"""Quais decisões existem, de onde partem, e quais disparam errata e memória."""

	def test_legitimate_starts_from_malicious_or_suspicious(self):
		self.assertTrue(reclassification.can_reclassify('Malicious', 'Safe'))
		self.assertTrue(reclassification.can_reclassify('Suspicious', 'Safe'))
		self.assertFalse(reclassification.can_reclassify('Safe', 'Safe'))

	def test_malicious_starts_from_suspicious_or_confirms_malicious(self):
		self.assertTrue(reclassification.can_reclassify('Suspicious', 'Malicious'))
		self.assertTrue(reclassification.can_reclassify('Malicious', 'Malicious'))

	def test_a_safe_verdict_is_never_condemned_from_here(self):
		self.assertFalse(reclassification.can_reclassify('Safe', 'Malicious'))
		self.assertEqual(reclassification.targets_for('Safe'), [])

	def test_the_default_target_is_still_legitimate(self):
		# Uma chamada anterior a esta versão continua significando "legítimo"
		self.assertTrue(reclassification.can_reclassify('Suspicious'))
		self.assertFalse(reclassification.can_reclassify('Safe'))

	def test_targets_in_screen_order(self):
		self.assertEqual(reclassification.targets_for('Suspicious'), ['Safe', 'Malicious'])
		self.assertEqual(reclassification.targets_for('Malicious'), ['Safe', 'Malicious'])

	def test_only_a_corrected_false_positive_is_one(self):
		fp = {'action': 'reclassify', 'previousVerdict': 'Malicious', 'verdict': 'Safe'}
		self.assertTrue(reclassification.is_false_positive(fp))
		self.assertFalse(reclassification.is_false_positive(dict(fp, verdict = 'Malicious', previousVerdict = 'Suspicious')))
		# Desfazer não é corrigir um falso positivo, mesmo terminando em Safe
		self.assertFalse(reclassification.is_false_positive(dict(fp, action = 'revert')))
		self.assertFalse(reclassification.is_false_positive(None))

	def test_a_confirmation_keeps_the_verdict(self):
		self.assertTrue(reclassification.is_confirmation(
			{'action': 'reclassify', 'previousVerdict': 'Malicious', 'verdict': 'Malicious'}))
		self.assertFalse(reclassification.is_confirmation(
			{'action': 'reclassify', 'previousVerdict': 'Suspicious', 'verdict': 'Malicious'}))


if __name__ == '__main__':
	unittest.main()
