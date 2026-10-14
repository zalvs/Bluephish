"""Testes do alerta de volume.

O que precisa estar fixado é o que decide *se* a equipe é avisada, porque os dois
erros possíveis falham em silêncio: um alerta que nunca dispara não aparece em
lugar nenhum, e um que dispara a cada ciclo ensina a equipe a ignorá-lo.

  * a contagem é por e-mail distinto, dentro da janela, a partir do limiar;
  * envelope sem corpo não conta — nada é baixado para esta contagem;
  * no modo de denúncia por anexo, o remetente é o do e-mail denunciado, não o
    do colega que encaminhou;
  * o cooldown segura a repetição, e é gravado na detecção, antes do envio;
  * um Date forjado no futuro não mantém o e-mail na janela para sempre.

O envio (SMTP e webhook) não é simulado, pela mesma razão de test_connectors: o
que dá para fixar sem rede é tudo que decide o que sai.

Roda com:  python -m unittest test_volume_alerts   (a partir do diretório app/)
"""

import json
import os
import shutil
import tempfile
import unittest

import volume_alerts

MINUTE = 60 * 1000
NOW = 1_800_000_000_000


def mail(uid, minutes_ago, subject = 'Seu boleto vence hoje', sender = 'Cobrança <cobranca@golpe.xyz>', **over):
	entry = {
		'mailUID': str(uid),
		'from': 'colega{0}@empresa.com'.format(uid),
		'subject': 'Fwd: ' + subject,
		'receivedAt': NOW - minutes_ago * MINUTE,
		'attachedMail': subject,
		'attachedFrom': sender,
		'bodyLoaded': True
	}
	entry.update(over)
	return entry


def config(**over):
	base = dict(volume_alerts.DEFAULTS, enabled = True, threshold = 3, windowMinutes = 60, cooldownMinutes = 240)
	base.update(over)
	return base


class Detection(unittest.TestCase):

	def test_the_threshold_is_inclusive(self):
		emails = [mail(i, i) for i in range(3)]
		alerts = volume_alerts.detect(emails, config(bySender = False), NOW)
		self.assertEqual(len(alerts), 1)
		self.assertEqual(alerts[0]['count'], 3)
		self.assertEqual(alerts[0]['patternType'], 'subject')

	def test_below_the_threshold_nothing_fires(self):
		self.assertEqual(volume_alerts.detect([mail(1, 1), mail(2, 2)], config(), NOW), [])

	def test_emails_outside_the_window_do_not_count(self):
		emails = [mail(1, 5), mail(2, 10), mail(3, 61)]
		self.assertEqual(volume_alerts.detect(emails, config(bySender = False), NOW), [])

	def test_the_same_uid_twice_is_one_email(self):
		emails = [mail(1, 1), mail(1, 1), mail(2, 2)]
		self.assertEqual(volume_alerts.detect(emails, config(bySender = False), NOW), [])

	def test_an_envelope_without_body_is_not_counted(self):
		# Sem o corpo não se sabe o assunto nem o remetente do e-mail denunciado;
		# contar pelo envelope agruparia pelo "Fwd:" de quem encaminhou
		emails = [mail(1, 1), mail(2, 2), mail(3, 3, bodyLoaded = False)]
		self.assertEqual(volume_alerts.detect(emails, config(bySender = False), NOW), [])
		self.assertEqual(volume_alerts.pending_count(emails), 1)

	def test_subjects_are_grouped_after_normalization(self):
		emails = [mail(1, 1, subject = 'Fatura 4471-22 em aberto'),
			mail(2, 2, subject = 'RE: Fatura 9910-01 em aberto'),
			mail(3, 3, subject = 'Fatura 1234-56 em aberto')]
		alerts = volume_alerts.detect(emails, config(bySender = False), NOW)
		self.assertEqual(len(alerts), 1)

	def test_the_sender_is_the_reported_one_not_the_colleague(self):
		emails = [mail(i, i, subject = 'assunto {0}'.format(i)) for i in range(3)]
		alerts = volume_alerts.detect(emails, config(bySubject = False), NOW)
		self.assertEqual(len(alerts), 1)
		self.assertEqual(alerts[0]['pattern'], 'cobranca@golpe.xyz')
		self.assertEqual(len(alerts[0]['samples']), 3)

	def test_a_disabled_pattern_does_not_fire(self):
		emails = [mail(i, i) for i in range(3)]
		alerts = volume_alerts.detect(emails, config(bySender = False), NOW)
		self.assertEqual([a['patternType'] for a in alerts], ['subject'])

	def test_a_forged_future_date_does_not_stay_in_the_window(self):
		emails = [mail(1, 1), mail(2, 2), mail(3, -24 * 60)]
		self.assertEqual(volume_alerts.detect(emails, config(bySender = False), NOW), [])

	def test_the_cooldown_holds_the_repeat(self):
		emails = [mail(i, i) for i in range(3)]
		key = volume_alerts.pattern_key('subject', 'Seu boleto vence hoje')
		held = volume_alerts.detect(emails, config(bySender = False), NOW, {key: NOW - 10 * MINUTE})
		self.assertEqual(held, [])
		released = volume_alerts.detect(emails, config(bySender = False), NOW, {key: NOW - 241 * MINUTE})
		self.assertEqual(len(released), 1)

	def test_disabled_detects_nothing(self):
		emails = [mail(i, i) for i in range(5)]
		self.assertEqual(volume_alerts.detect(emails, config(enabled = False), NOW), [])


class Validation(unittest.TestCase):

	def submitted(self, **over):
		base = {'enabled': True, 'bySubject': True, 'bySender': False,
			'threshold': '7', 'windowMinutes': '90', 'cooldownMinutes': '120',
			'recipients': 'soc@empresa.com; SOC@empresa.com\nsi@empresa.com'}
		base.update(over)
		return base

	def test_free_values_inside_the_limits_are_kept(self):
		entry, error = volume_alerts.validate_config(self.submitted())
		self.assertIsNone(error)
		self.assertEqual((entry['threshold'], entry['windowMinutes'], entry['cooldownMinutes']), (7, 90, 120))
		self.assertEqual(entry['recipients'], ['soc@empresa.com', 'si@empresa.com'])

	def test_out_of_range_values_are_refused(self):
		for key, value in (('threshold', '1'), ('windowMinutes', '0'), ('cooldownMinutes', '4'),
				('threshold', 'muitos')):
			entry, error = volume_alerts.validate_config(self.submitted(**{key: value}))
			self.assertIsNone(entry, key)
			self.assertTrue(error)

	def test_enabled_without_any_pattern_is_refused(self):
		entry, error = volume_alerts.validate_config(self.submitted(bySubject = False))
		self.assertIsNone(entry)

	def test_an_invalid_recipient_is_refused(self):
		entry, error = volume_alerts.validate_config(self.submitted(recipients = ['nao-e-endereco']))
		self.assertIsNone(entry)


class State(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp()
		self.path = os.path.join(self.directory, 'sub', 'volume_alerts.json')

	def tearDown(self):
		shutil.rmtree(self.directory)

	def test_evaluate_marks_the_cooldown_before_anything_is_sent(self):
		emails = [mail(i, i) for i in range(3)]
		first = volume_alerts.evaluate(emails, NOW, config(bySender = False), self.path)
		second = volume_alerts.evaluate(emails, NOW + MINUTE, config(bySender = False), self.path)
		self.assertEqual(len(first), 1)
		self.assertEqual(second, [])
		with open(self.path) as handle:
			self.assertIn(first[0]['key'], json.load(handle)['cooldowns'])

	def test_an_unreadable_state_file_starts_empty(self):
		os.makedirs(os.path.dirname(self.path))
		with open(self.path, 'w') as handle:
			handle.write('{nao e json')
		self.assertEqual(volume_alerts.load_state(self.path), {'cooldowns': {}, 'recent': []})


class Context(unittest.TestCase):

	def test_the_webhook_context_carries_the_alert_and_a_ready_sentence(self):
		alert = volume_alerts.sample_alert()
		context = volume_alerts.alert_context(alert)
		for variable in volume_alerts.VARIABLES:
			self.assertIn(variable['name'], context, variable['name'])
		self.assertIn(str(alert['count']), context['message'])
		self.assertNotIn('key', context)

	def test_the_email_keeps_real_line_breaks(self):
		subject, body = volume_alerts.email_text(volume_alerts.sample_alert())
		self.assertIn('\n', body)
		self.assertIn('7', subject)


if __name__ == '__main__':
	unittest.main()
