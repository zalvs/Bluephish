"""Onde a trilha de auditoria é escrita e por quanto tempo fica (audit_store.py).

O que estes testes seguram, e por que cada um falharia em silêncio:

* O piso. Uma retenção de 1 dia não passa nem pelo formulário nem gravada à mão
  no configuration.json — é o jeito de alguém zerar o próprio rastro.
* O teto vencendo o prazo sem ninguém saber: a poda tem de dizer quando cortou.
* A pasta configurável virando caminho livre (`..`, `/etc`) ou caindo dentro da
  pasta de outro recurso, cuja limpeza apagaria a trilha.
* Trocar a pasta e a tela de Auditoria perder o histórico.
* O syslog como sétimo consumidor da trava de SSRF: metadados da nuvem nunca, e
  o handler preso ao IP que foi validado.

Rodar com:  python -m unittest test_audit_store   (a partir de app/)
"""

import datetime
import logging
import os
import shutil
import socket
import tempfile
import time
import unittest
from unittest import mock

import audit_store
import audit_trail


def touch(path, text = 'x\n', days_ago = 0):
	with open(path, 'w', encoding = 'utf-8') as handle:
		handle.write(text)
	stamp = time.time() - days_ago * 86400
	os.utime(path, (stamp, stamp))


class Base(unittest.TestCase):

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-audit-store-')
		self.path = os.path.join(self.directory, 'auth.log')
		self.logger = logging.getLogger('test.audit_store.{0}'.format(id(self)))
		audit_store._state.update({'path': None, 'base': None, 'syslog': None, 'syslogError': None, 'config': None})

	def tearDown(self):
		for handler in list(self.logger.handlers):
			self.logger.removeHandler(handler)
			handler.close()
		audit_store._state.update({'path': None, 'base': None, 'syslog': None, 'syslogError': None, 'config': None})
		shutil.rmtree(self.directory, ignore_errors = True)

	def config(self, **overrides):
		config = {'folder': '', 'retentionDays': 365, 'maxMegabytes': 30,
			'syslog': {'enabled': False, 'host': '', 'port': 514, 'protocol': 'udp'}}
		config.update(overrides)
		return config


class RotatedFiles(Base):

	def test_legacy_copies_come_first_then_stamped_in_order(self):
		for name in ('auth.log.2', 'auth.log.1', 'auth.log.20260920-000000', 'auth.log.20260921-000000',
				'auth.log.20260921-000000-1', 'auth.log', 'outro.log'):
			touch(os.path.join(self.directory, name))
		self.assertEqual([os.path.basename(name) for name in audit_store.trail_files(self.path)], [
			'auth.log.2', 'auth.log.1', 'auth.log.20260920-000000', 'auth.log.20260921-000000',
			'auth.log.20260921-000000-1', 'auth.log'])

	def test_the_reader_sees_the_same_files(self):
		touch(os.path.join(self.directory, 'auth.log.20260920-000000'))
		touch(self.path)
		self.assertEqual(audit_trail.log_files(self.path), audit_store.trail_files(self.path))


class Prune(Base):

	def test_files_past_retention_are_removed(self):
		touch(os.path.join(self.directory, 'auth.log.20250101-000000'), days_ago = 400)
		touch(os.path.join(self.directory, 'auth.log.20260901-000000'), days_ago = 10)
		touch(self.path)
		removed = audit_store.prune(self.path, 365, 30 * 1024 * 1024)
		self.assertEqual(removed, {'expired': 1, 'overCap': 0})
		self.assertEqual(len(audit_store.trail_files(self.path)), 2)

	def test_cap_removes_oldest_and_says_so(self):
		for index in range(4):
			touch(os.path.join(self.directory, 'auth.log.2026090{0}-000000'.format(index + 1)), 'x' * 400, days_ago = 5 - index)
		touch(self.path, 'x' * 400)
		removed = audit_store.prune(self.path, 365, 1000)
		self.assertEqual(removed['overCap'], 3)
		self.assertEqual([os.path.basename(name) for name in audit_store.trail_files(self.path)],
			['auth.log.20260904-000000', 'auth.log'])

	def test_current_file_is_never_removed(self):
		touch(self.path, 'x' * 5000)
		audit_store.prune(self.path, 30, 10)
		self.assertTrue(os.path.isfile(self.path))


class Rotation(Base):

	def test_rolls_over_when_the_day_changes(self):
		handler = audit_store.AuditFileHandler(self.path, 365, 30 * 1024 * 1024)
		handler.setFormatter(logging.Formatter('%(message)s'))
		self.logger.addHandler(handler)
		self.logger.setLevel(logging.INFO)
		self.logger.info('ontem')
		handler.opened_day = datetime.date.today() - datetime.timedelta(days = 1)
		self.logger.info('hoje')
		files = audit_store.trail_files(self.path)
		self.assertEqual(len(files), 2)
		with open(files[0], encoding = 'utf-8') as handle:
			self.assertEqual(handle.read().strip(), 'ontem')
		with open(self.path, encoding = 'utf-8') as handle:
			self.assertEqual(handle.read().strip(), 'hoje')

	def test_rolls_over_when_the_file_passes_a_tenth_of_the_cap(self):
		handler = audit_store.AuditFileHandler(self.path, 365, 10 * 1024 * 1024)
		self.assertEqual(handler.segment_bytes, 1024 * 1024)
		handler.segment_bytes = 50
		handler.setFormatter(logging.Formatter('%(message)s'))
		self.logger.addHandler(handler)
		self.logger.setLevel(logging.INFO)
		for _ in range(5):
			self.logger.info('x' * 30)
		self.assertGreater(len(audit_store.trail_files(self.path)), 2)


class Floors(unittest.TestCase):

	def form(self, **overrides):
		form = {'folder': '', 'retentionDays': '365', 'maxMegabytes': '30', 'syslogEnabled': 'false',
			'syslogHost': '', 'syslogPort': '514', 'syslogProtocol': 'udp'}
		form.update(overrides)
		return form

	def test_retention_below_the_floor_is_refused(self):
		config, error = audit_store.validate(self.form(retentionDays = '1'))
		self.assertIsNone(config)
		self.assertIn('30', error)

	def test_cap_below_the_floor_is_refused(self):
		config, _ = audit_store.validate(self.form(maxMegabytes = '1'))
		self.assertIsNone(config)

	def test_a_hand_written_config_below_the_floor_is_raised(self):
		directory = tempfile.mkdtemp()
		try:
			path = os.path.join(directory, 'configuration.json')
			with open(path, 'w') as handle:
				handle.write('{"auditLog": {"retentionDays": 1, "maxMegabytes": 0, "folder": "../../etc"}}')
			config = audit_store.load_config(path)
			self.assertEqual(config['retentionDays'], audit_store.MIN_RETENTION_DAYS)
			self.assertEqual(config['maxMegabytes'], audit_store.MIN_MEGABYTES)
			self.assertEqual(config['folder'], '')
		finally:
			shutil.rmtree(directory, ignore_errors = True)

	def test_folder_must_be_a_plain_name_outside_other_features(self):
		for folder in ('../etc', '/etc/x', 'a/b', '..', 'originals', 'Rendered', 'a b'):
			config, _ = audit_store.validate(self.form(folder = folder))
			self.assertIsNone(config, folder)
		config, error = audit_store.validate(self.form(folder = 'auditoria'))
		self.assertIsNone(error)
		self.assertEqual(config['folder'], 'auditoria')


class Syslog(unittest.TestCase):

	def test_cloud_metadata_is_refused(self):
		ip, error = audit_store.resolve_syslog('169.254.169.254', 514, 'udp')
		self.assertIsNone(ip)
		self.assertIn('metadados', error)

	def test_internal_network_is_allowed(self):
		ip, error = audit_store.resolve_syslog('10.0.0.20', 514, 'udp')
		self.assertEqual((ip, error), ('10.0.0.20', None))

	def test_a_name_resolving_to_metadata_is_refused(self):
		fake = [(socket.AF_INET, socket.SOCK_DGRAM, 0, '', ('169.254.169.254', 514))]
		with mock.patch('socket.getaddrinfo', return_value = fake):
			ip, _ = audit_store.resolve_syslog('siem.example', 514, 'udp')
		self.assertIsNone(ip)

	def test_enabled_without_host_is_refused(self):
		config, _ = audit_store.validate({'retentionDays': '365', 'maxMegabytes': '30',
			'syslogEnabled': 'true', 'syslogHost': '', 'syslogPort': '514', 'syslogProtocol': 'udp'})
		self.assertIsNone(config)


class Apply(Base):

	def test_writes_to_the_configured_folder(self):
		audit_store.apply(self.logger, self.path, self.config(folder = 'auditoria'))
		self.logger.info('event=login status=success ip=- actor=- target=x detail=')
		expected = os.path.join(self.directory, 'auditoria', 'auth.log')
		self.assertTrue(os.path.isfile(expected))
		self.assertEqual(audit_store.current_path(self.path), expected)

	def test_changing_the_folder_takes_the_trail_along(self):
		audit_store.apply(self.logger, self.path, self.config())
		self.logger.info('primeiro')
		touch(os.path.join(self.directory, 'auth.log.20260901-000000'), 'antigo\n', days_ago = 5)
		audit_store.apply(self.logger, self.path, self.config(folder = 'auditoria'))
		self.logger.info('segundo')
		moved = audit_store.trail_files(os.path.join(self.directory, 'auditoria', 'auth.log'))
		self.assertEqual(len(moved), 2)
		self.assertFalse(os.path.exists(self.path))
		with open(moved[-1], encoding = 'utf-8') as handle:
			self.assertEqual([line.split()[-1] for line in handle.read().splitlines()], ['primeiro', 'segundo'])

	def test_a_smaller_cap_applies_at_once_and_the_cut_is_reported(self):
		for index in range(3):
			touch(os.path.join(self.directory, 'auth.log.2026090{0}-000000'.format(index + 1)),
				'x' * (6 * 1024 * 1024), days_ago = 5 - index)
		state = audit_store.apply(self.logger, self.path, self.config(maxMegabytes = 10))
		self.assertTrue(state['capCut'])
		self.assertLessEqual(state['usage']['bytes'], 10 * 1024 * 1024)

	def test_syslog_handler_is_pinned_to_the_validated_ip(self):
		fake = [(socket.AF_INET, socket.SOCK_DGRAM, 0, '', ('10.9.8.7', 514))]
		with mock.patch('socket.getaddrinfo', return_value = fake):
			state = audit_store.apply(self.logger, self.path, self.config(
				syslog = {'enabled': True, 'host': 'siem.corp.local', 'port': 514, 'protocol': 'udp'}))
		self.assertTrue(state['syslogActive'])
		handler = [h for h in self.logger.handlers if isinstance(h, audit_store.AuditSyslogHandler)][0]
		self.assertEqual(handler.address, ('10.9.8.7', 514))

	def test_a_refused_syslog_keeps_the_local_trail(self):
		state = audit_store.apply(self.logger, self.path, self.config(
			syslog = {'enabled': True, 'host': '169.254.169.254', 'port': 514, 'protocol': 'udp'}))
		self.assertFalse(state['syslogActive'])
		self.assertTrue(state['syslogError'])
		self.logger.info('ainda grava')
		self.assertTrue(os.path.isfile(self.path))


class RoutesAreGlobalAdminOnly(unittest.TestCase):
	"""Encurtar a retenção apaga histórico: as rotas são global_admin, no servidor."""

	def test_every_config_route_requires_global_admin(self):
		with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'thephish_app.py'), encoding = 'utf-8') as handle:
			source = handle.read().splitlines()
		routes = [index for index, text in enumerate(source) if text.startswith("@app.route('/audit-log-config")]
		self.assertEqual(len(routes), 3)
		for index in routes:
			self.assertEqual(source[index + 1].strip(), '@requires_global_admin', source[index])


if __name__ == '__main__':
	unittest.main()
