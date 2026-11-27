"""Tests for the ticket destinations — the seam that will outlive TheHive.

What is pinned down is the part that decides *whether* and *what*: the verdict
filter, the validation of each form, the promise that a stored token never
leaves the process, and the shape of the normalized report every destination
consumes. The disk destination is exercised for real against a temporary
directory, because it has no vendor to stand in for.

The Jira HTTP conversation is deliberately not mocked, for the same reason the
analyzer clients are not: a fake only proves it matches the code. The "Testar"
button is what verifies it against a real Jira.

Run with:  python -m unittest test_tickets   (from the app/ directory)
"""

import json
import os
import shutil
import tempfile
import unittest

import tickets


def jira_entry(**overrides):
	entry = {
		'enabled': True, 'url': 'https://exemplo.atlassian.net', 'authType': 'basic',
		'user': 'soc@exemplo.com', 'token': 'segredo', 'project': 'SOC',
		'issueType': 'Task', 'labels': 'bluephish', 'attachEml': 'sim',
		'verifyTls': 'sim', 'minVerdict': 'Suspicious'
	}
	entry.update(overrides)
	return entry


def disk_entry(path, **overrides):
	entry = {
		'enabled': True, 'path': path, 'writeEml': 'sim', 'writeBody': 'não',
		'minVerdict': 'all', 'retentionDays': 0
	}
	entry.update(overrides)
	return entry


def all_off():
	"""Defaults com todo destino desligado.

	O disco vem ligado de fábrica (é o destino que não depende de serviço nenhum).
	Um teste que queira isolar um destino precisa desligá-lo explicitamente.
	"""
	config = tickets.default_config()
	for destination_id in config:
		config[destination_id]['enabled'] = False
	return config


def sample_report(verdict = 'Malicious'):
	return tickets.build_report(
		subject = 'Sua conta será bloqueada',
		verdict = verdict,
		reporter = 'quem@denunciou.com',
		observables_info = [
			{'id': 'o1', 'type': 'url', 'name': 'http://mau.exemplo/login'},
			{'id': 'o2', 'type': 'ip', 'name': '8.8.8.8'}
		],
		reports_observables = [
			{'observable_id': 'o1', 'observable_type': 'url', 'observable_name': 'http://mau.exemplo/login',
			 'analyzer_name': 'PhishTank', 'analyzer_result': 'malicious',
			 'analyzer_detail': 'consta e foi verificado', 'analyzer_error': ''},
			{'observable_id': 'o2', 'observable_type': 'ip', 'observable_name': '8.8.8.8',
			 'analyzer_name': 'AbuseIPDB', 'analyzer_result': 'safe',
			 'analyzer_detail': 'confiança 0/100', 'analyzer_error': ''}
		],
		llm_result = {'risk_level': 'High', 'social_engineering_detected': True,
			'justification': 'Urgência e pedido de credencial.',
			'tactics': ['urgency', 'credential_harvesting']},
		auth_results = {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail',
			'authenticated': False, 'fromDomain': 'mau.exemplo'},
		email_body = 'Clique aqui para não perder o acesso.',
		case_ref = '142',
		department = 'Jurídico')


class VerdictFilter(unittest.TestCase):
	"""O filtro é o que separa 'abrir chamado de tudo' de 'só do que importa'."""

	def test_all_accepts_every_verdict(self):
		for verdict in tickets.VERDICTS:
			self.assertTrue(tickets.accepts_verdict('all', verdict))

	def test_suspicious_accepts_itself_and_malicious(self):
		self.assertTrue(tickets.accepts_verdict('Suspicious', 'Suspicious'))
		self.assertTrue(tickets.accepts_verdict('Suspicious', 'Malicious'))

	def test_suspicious_refuses_safe(self):
		self.assertFalse(tickets.accepts_verdict('Suspicious', 'Safe'))

	def test_malicious_refuses_everything_below(self):
		self.assertFalse(tickets.accepts_verdict('Malicious', 'Safe'))
		self.assertFalse(tickets.accepts_verdict('Malicious', 'Suspicious'))
		self.assertTrue(tickets.accepts_verdict('Malicious', 'Malicious'))

	def test_an_unknown_verdict_never_slips_through(self):
		# Um veredito que a gente não reconhece não pode virar chamado por engano
		self.assertFalse(tickets.accepts_verdict('Malicious', 'Sei-la'))


class ReportShape(unittest.TestCase):
	"""O report é a fronteira: nenhum objeto do TheHive pode vazar nele."""

	def setUp(self):
		self.report = sample_report()

	def test_it_is_json_serializable(self):
		# Um destino grava isto em disco e outro manda por HTTP; qualquer objeto
		# do TheHive que sobrasse aqui quebraria os dois
		json.dumps(self.report)

	def test_an_observable_flagged_by_an_analyzer_is_marked(self):
		by_value = dict((o['value'], o) for o in self.report['observables'])
		self.assertTrue(by_value['http://mau.exemplo/login']['malicious'])
		self.assertFalse(by_value['8.8.8.8']['malicious'])

	def test_every_analyzer_answer_is_kept(self):
		self.assertEqual(len(self.report['findings']), 2)
		self.assertEqual(self.report['findings'][0]['analyzer'], 'PhishTank')

	def test_the_verdict_and_the_reporter_travel(self):
		self.assertEqual(self.report['verdict'], 'Malicious')
		self.assertEqual(self.report['reporter'], 'quem@denunciou.com')

	def test_a_missing_subject_does_not_produce_an_empty_title(self):
		report = tickets.build_report(None, 'Safe', '', [], [])
		self.assertEqual(report['subject'], '(sem assunto)')


class Markdown(unittest.TestCase):

	def test_the_flagged_observable_appears(self):
		text = tickets.report_as_markdown(sample_report())
		self.assertIn('PhishTank', text)
		self.assertIn('http://mau.exemplo/login', text)

	def test_the_llm_assessment_appears(self):
		text = tickets.report_as_markdown(sample_report())
		self.assertIn('High', text)
		self.assertIn('Urgência', text)

	def test_an_unauthenticated_sender_is_called_out(self):
		self.assertIn('NÃO está autenticado', tickets.report_as_markdown(sample_report()))

	def test_a_clean_sheet_states_its_own_limitation(self):
		# Nenhum apontamento não é atestado de inocência, e o texto tem de dizer
		report = tickets.build_report('Assunto', 'Safe', '', [], [])
		text = tickets.report_as_markdown(report)
		self.assertIn('não prova que o e-mail é seguro', text)


class AnalysisTags(unittest.TestCase):
	"""As tags que tornam o histórico contável.

	Sem elas o departamento e a tática só existiriam na prosa do log da tarefa:
	visíveis para quem abre um caso, incontáveis para quem olha o mês. O
	vocabulário é o de case_insights, que é quem lê de volta.
	"""

	def test_the_department_the_risk_and_the_tactics_all_become_tags(self):
		tags = tickets.analysis_tags(sample_report())
		self.assertIn('dept:Jurídico', tags)
		self.assertIn('risk:High', tags)
		self.assertIn('se:detected', tags)
		self.assertIn('tactic:urgency', tags)
		self.assertIn('tactic:credential_harvesting', tags)

	def test_an_analysis_with_no_llm_and_no_department_adds_nothing(self):
		# Uma instância sem LLM e sem mapeamento não pode ganhar tag nenhuma: uma
		# tag inventada aqui vira um número no dashboard executivo
		report = tickets.build_report('Assunto', 'Safe', 'quem@denunciou.com', [], [])
		self.assertEqual(tickets.analysis_tags(report), [])

	def test_a_clean_assessment_records_the_risk_but_not_the_detection(self):
		report = tickets.build_report('Assunto', 'Safe', '', [], [],
			llm_result = {'risk_level': 'Low', 'social_engineering_detected': False,
				'justification': '', 'tactics': []})
		self.assertEqual(tickets.analysis_tags(report), ['risk:Low'])

	def test_the_department_reaches_the_markdown_the_analyst_reads(self):
		self.assertIn('Jurídico', tickets.report_as_markdown(sample_report()))

	def test_the_tactics_reach_the_markdown_too(self):
		self.assertIn('urgency', tickets.report_as_markdown(sample_report()))


class JiraValidation(unittest.TestCase):

	def validate(self, submitted, stored = None):
		return tickets.validate_entry('jira', submitted, stored or {})

	def test_a_complete_form_is_accepted(self):
		entry, error = self.validate(jira_entry())
		self.assertIsNone(error)
		self.assertEqual(entry['project'], 'SOC')

	def test_basic_auth_without_the_account_email_is_refused(self):
		# É a causa mais comum de 401 e o Jira não diz o que faltou
		entry, error = self.validate(jira_entry(user = ''))
		self.assertIsNone(entry)
		self.assertIn('e-mail da conta', error)

	def test_bearer_auth_does_not_require_the_email(self):
		entry, error = self.validate(jira_entry(authType = 'bearer', user = ''))
		self.assertIsNone(error)
		self.assertEqual(entry['authType'], 'bearer')

	def test_a_project_key_that_is_not_a_key_is_refused(self):
		entry, error = self.validate(jira_entry(project = 'SOC-142'))
		self.assertIsNone(entry)
		self.assertIn('chave de projeto', error)

	def test_a_plain_http_internal_jira_is_accepted(self):
		# Um Data Center vive na rede interna; exigir https tornaria o campo inútil.
		# O endereço é um IP literal de propósito: um nome interno não resolve na
		# máquina que roda os testes, e o que se quer fixar aqui é a trava, não o DNS
		entry, error = self.validate(jira_entry(url = 'http://10.20.30.40:8080'))
		self.assertIsNotNone(entry, error)

	def test_a_name_that_does_not_resolve_is_refused(self):
		# Não dá para saber para onde o pacote iria, então não se manda
		entry, error = self.validate(jira_entry(url = 'https://jira.que-nao-existe.invalid'))
		self.assertIsNone(entry)
		self.assertIn('resolver', error)

	def test_the_cloud_metadata_service_is_refused_as_a_jira(self):
		entry, error = self.validate(jira_entry(url = 'http://169.254.169.254'))
		self.assertIsNone(entry)
		self.assertIn('metadados', error)

	def test_a_blank_token_keeps_the_stored_one(self):
		entry, error = self.validate(jira_entry(token = ''), stored = {'token': 'guardado'})
		self.assertIsNone(error)
		self.assertEqual(entry['token'], 'guardado')

	def test_an_unknown_min_verdict_is_refused(self):
		entry, error = self.validate(jira_entry(minVerdict = 'Talvez'))
		self.assertIsNone(entry)
		self.assertIn('abrir chamado para', error.lower())

	def test_a_disabled_destination_may_be_saved_half_filled(self):
		entry, error = self.validate(jira_entry(enabled = False, project = '', token = ''))
		self.assertIsNone(error)


class JiraSummary(unittest.TestCase):

	def test_the_verdict_leads_the_title(self):
		self.assertTrue(tickets.jira_summary(sample_report()).startswith('[Malicious]'))

	def test_a_very_long_subject_is_cut_before_jira_refuses_it(self):
		report = sample_report()
		report['subject'] = 'a' * 500
		self.assertLessEqual(len(tickets.jira_summary(report)), 250)


class DiskDestination(unittest.TestCase):

	def setUp(self):
		self.root = tempfile.mkdtemp(prefix = 'bluephish-test-')

	def tearDown(self):
		shutil.rmtree(self.root, ignore_errors = True)

	def test_it_writes_the_report_in_both_shapes(self):
		result = tickets.create_disk(disk_entry(self.root), sample_report(), b'From: a@b\r\n\r\ncorpo')
		self.assertTrue(result['ok'])
		folder = result['ref']
		self.assertTrue(os.path.isfile(os.path.join(folder, 'report.json')))
		self.assertTrue(os.path.isfile(os.path.join(folder, 'report.md')))

	def test_the_json_it_writes_is_the_report(self):
		result = tickets.create_disk(disk_entry(self.root), sample_report(), None)
		with open(os.path.join(result['ref'], 'report.json'), encoding = 'utf-8') as report_file:
			stored = json.load(report_file)
		self.assertEqual(stored['verdict'], 'Malicious')
		self.assertEqual(len(stored['findings']), 2)

	def test_the_eml_is_written_when_asked(self):
		result = tickets.create_disk(disk_entry(self.root), sample_report(), b'RAW EML')
		with open(os.path.join(result['ref'], 'email.eml'), 'rb') as eml_file:
			self.assertEqual(eml_file.read(), b'RAW EML')

	def test_the_eml_is_not_written_when_refused(self):
		result = tickets.create_disk(disk_entry(self.root, writeEml = 'não'), sample_report(), b'RAW')
		self.assertFalse(os.path.exists(os.path.join(result['ref'], 'email.eml')))

	def test_a_subject_from_an_attacker_cannot_escape_the_directory(self):
		# O assunto vem do e-mail analisado: barra e .. não podem virar caminho
		report = sample_report()
		report['subject'] = '../../etc/passwd'
		result = tickets.create_disk(disk_entry(self.root), report, None)
		self.assertTrue(result['ok'])
		self.assertEqual(os.path.dirname(os.path.normpath(result['ref'])),
			os.path.normpath(self.root))

	def test_two_analyses_do_not_overwrite_each_other(self):
		first = tickets.create_disk(disk_entry(self.root), sample_report(), None)
		second = sample_report()
		second['analyzedAt'] = '2026-01-01T00:00:00'
		second = tickets.create_disk(disk_entry(self.root), second, None)
		self.assertNotEqual(first['ref'], second['ref'])

	def test_the_probe_leaves_nothing_behind(self):
		detail = tickets.probe_disk(disk_entry(self.root))
		self.assertIn('gravável', detail)
		self.assertEqual(os.listdir(self.root), [])

	def test_the_probe_warns_when_the_path_will_not_survive_a_rebuild(self):
		outside = tempfile.mkdtemp(prefix = 'bluephish-outside-')
		try:
			self.assertIn('ATENÇÃO', tickets.probe_disk(disk_entry(outside)))
		finally:
			shutil.rmtree(outside, ignore_errors = True)

	def test_retention_of_zero_never_deletes(self):
		tickets.create_disk(disk_entry(self.root, retentionDays = 0), sample_report(), None)
		self.assertEqual(tickets.prune_old_analyses(self.root, 0), 0)
		self.assertEqual(len(os.listdir(self.root)), 1)

	def test_retention_deletes_only_what_is_older(self):
		import datetime
		result = tickets.create_disk(disk_entry(self.root), sample_report(), None)
		# O nome precisa ser o de uma pasta de análise: a retenção só apaga o que
		# ela própria criou, e um diretório qualquer é deixado em paz de propósito
		old = os.path.join(self.root, '2020-01-01T00-00-00-antiga')
		os.makedirs(old)
		stale = (datetime.datetime.now() - datetime.timedelta(days = 40)).timestamp()
		os.utime(old, (stale, stale))
		removed = tickets.prune_old_analyses(self.root, 30)
		self.assertEqual(removed, 1)
		self.assertFalse(os.path.isdir(old))
		self.assertTrue(os.path.isdir(result['ref']))


class DiskValidation(unittest.TestCase):

	def test_a_relative_path_is_refused_when_enabled(self):
		entry, error = tickets.validate_entry('disk', disk_entry('analises'), {})
		self.assertIsNone(entry)
		self.assertIn('caminho absoluto', error)

	def test_retention_outside_the_range_is_refused(self):
		entry, error = tickets.validate_entry('disk', disk_entry('/tmp/x', retentionDays = 99999), {})
		self.assertIsNone(entry)
		self.assertIn('entre 0 e 3650', error)

	def test_a_non_numeric_retention_is_refused(self):
		entry, error = tickets.validate_entry('disk', disk_entry('/tmp/x', retentionDays = 'nunca'), {})
		self.assertIsNone(entry)
		self.assertIn('número', error)


class PublicConfig(unittest.TestCase):

	def test_the_jira_token_never_leaves_the_process(self):
		config = tickets.default_config()
		config['jira'] = jira_entry()
		public = tickets.public_config(config)
		self.assertNotIn('token', public['jira'])
		self.assertTrue(public['jira']['hasToken'])

	def test_the_non_secret_fields_do_come_back(self):
		config = tickets.default_config()
		config['jira'] = jira_entry()
		public = tickets.public_config(config)
		self.assertEqual(public['jira']['project'], 'SOC')
		self.assertEqual(public['jira']['minVerdict'], 'Suspicious')


class Dispatch(unittest.TestCase):

	def test_a_disabled_destination_is_never_reached(self):
		config = all_off()
		result = tickets.create('jira', sample_report(), None, None, config)
		self.assertFalse(result['ok'])
		self.assertIn('desabilitado', result['error'])

	def test_a_verdict_below_the_minimum_stops_before_any_call(self):
		config = all_off()
		config['jira'] = jira_entry(minVerdict = 'Malicious')
		result = tickets.create('jira', sample_report('Safe'), None, None, config)
		self.assertFalse(result['ok'])
		self.assertIn('abaixo do mínimo', result['error'])

	def test_enabled_for_lists_only_what_acts_on_this_verdict(self):
		config = all_off()
		config['jira'] = jira_entry(minVerdict = 'Malicious')
		config['disk'] = disk_entry('/tmp/x', minVerdict = 'all')
		self.assertEqual(tickets.enabled_for('Safe', config), ['disk'])
		self.assertEqual(sorted(tickets.enabled_for('Malicious', config)), ['disk', 'jira'])

	def test_one_destination_failing_does_not_stop_the_others(self):
		root = tempfile.mkdtemp(prefix = 'bluephish-test-')
		try:
			config = all_off()
			# Um Jira que não resolve, e um disco que funciona
			config['jira'] = jira_entry(url = 'https://jira-que-nao-existe.invalid')
			config['disk'] = disk_entry(root)
			results = dict(tickets.dispatch(sample_report(), None, None, config))
			self.assertFalse(results['jira']['ok'])
			self.assertTrue(results['disk']['ok'])
		finally:
			shutil.rmtree(root, ignore_errors = True)


class RegistryIntegrity(unittest.TestCase):

	def test_every_destination_has_a_creator_and_a_probe(self):
		for spec in tickets.DESTINATIONS:
			self.assertIn(spec['id'], tickets.CREATORS)
			self.assertIn(spec['id'], tickets.PROBES)

	def test_every_destination_can_be_filtered_by_verdict(self):
		# Sem o filtro, habilitar um destino significaria chamado para todo e-mail
		for spec in tickets.DESTINATIONS:
			keys = [f['key'] for f in spec['settings']]
			self.assertIn('minVerdict', keys)

	def test_the_defaults_produce_a_complete_entry(self):
		config = tickets.default_config()
		for spec in tickets.DESTINATIONS:
			self.assertIn(spec['id'], config)
			for field in spec['credentials'] + spec['settings']:
				self.assertIn(field['key'], config[spec['id']])

	def test_only_disk_ships_enabled(self):
		# O disco é o único destino que não precisa de nada fora deste processo:
		# uma instalação nova registra as análises sem configurar serviço nenhum.
		# TheHive e Jira são adesão explícita.
		config = tickets.default_config()
		self.assertTrue(config['disk']['enabled'])
		self.assertFalse(config['thehive']['enabled'])
		self.assertFalse(config['jira']['enabled'])

	def test_the_default_disk_path_survives_a_rebuild(self):
		# Ligado de fábrica, o disco grava onde o padrão apontar. Fora de data/
		# (o bind-mount) o histórico sumiria no primeiro rebuild da imagem
		path = tickets.default_config()['disk']['path']
		self.assertTrue(path.startswith('/root/thephish/data/'))

	def test_thehive_is_imported_only_where_it_is_used(self):
		# O TheHive é opcional: a aplicação tem de subir, analisar e gravar em
		# disco sem que o thehive4py seja sequer carregado. Um import no topo de
		# tickets.py faria dele uma dependência de toda análise outra vez
		import ast
		here = os.path.dirname(os.path.abspath(__file__))
		with open(os.path.join(here, 'tickets.py'), encoding = 'utf-8') as source:
			tree = ast.parse(source.read())
		at_module_level = []
		for node in tree.body:
			names = []
			if isinstance(node, ast.Import):
				names = [alias.name for alias in node.names]
			elif isinstance(node, ast.ImportFrom):
				names = [node.module or '']
			at_module_level.extend(name for name in names if name.split('.')[0] == 'thehive4py')
		self.assertEqual(at_module_level, [])

	def test_a_configuration_without_the_section_still_loads(self):
		config = tickets.load_config(path = 'no-such-file.json')
		self.assertFalse(config['jira']['enabled'])
		self.assertEqual(config['disk']['minVerdict'], 'all')


class DefaultsOnUpgrade(unittest.TestCase):
	"""O padrão mudou de TheHive para disco, e quem já usava o TheHive não pode notar.

	A instalação típica de antes nunca salvou a seção `ticketing`: ela registrava
	no TheHive porque esse era o padrão, e o que a identifica é ter endereço e
	chave na seção `thehive`. Se a troca de padrão a alcançasse, o upgrade
	desligaria o TheHive e passaria a gravar todo e-mail denunciado em disco —
	sem erro nenhum, só casos que param de chegar.
	"""

	def setUp(self):
		handle, self.path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)

	def tearDown(self):
		os.unlink(self.path)

	def load(self, document):
		with open(self.path, 'w') as conf_file:
			json.dump(document, conf_file)
		return tickets.load_config(path = self.path)

	def test_a_fresh_installation_records_to_disk(self):
		config = self.load({'thehive': {'url': '', 'apikey': ''}})
		self.assertTrue(config['disk']['enabled'])
		self.assertFalse(config['thehive']['enabled'])

	def test_a_configuration_without_any_of_the_sections_records_to_disk(self):
		config = self.load({})
		self.assertTrue(config['disk']['enabled'])
		self.assertFalse(config['thehive']['enabled'])

	def test_an_installation_already_on_thehive_stays_on_thehive(self):
		config = self.load({'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'}})
		self.assertTrue(config['thehive']['enabled'])

	def test_and_does_not_start_writing_reported_mail_to_disk(self):
		# O e-mail denunciado é dado pessoal de quem denunciou. Começar a gravá-lo
		# em disco tem de ser decisão de alguém, não efeito de um upgrade
		config = self.load({'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'}})
		self.assertFalse(config['disk']['enabled'])
		self.assertFalse(config['jira']['enabled'])

	def test_an_address_that_never_got_a_key_is_not_an_installation_on_thehive(self):
		# O arquivo de exemplo trazia o endereço preenchido e a chave em branco.
		# Quem nunca pôs a chave nunca gravou um caso lá
		config = self.load({'thehive': {'url': 'http://thehive:9000', 'apikey': ''}})
		self.assertFalse(config['thehive']['enabled'])
		self.assertTrue(config['disk']['enabled'])

	def test_the_address_the_template_shipped_is_not_carried_into_the_card(self):
		# O arquivo de configuração vivo não é atualizado por `git pull`, então o
		# endereço do contêiner do TheHive continua nele em toda instalação. Sem
		# chave, levá-lo para o card impede até de salvar o card: campo em branco
		# volta ao valor gravado, e `thehive` não resolve onde não há TheHive
		config = self.load({
			'thehive': {'url': 'http://thehive:9000', 'apikey': ''},
			'misp': {'id': 'MISP THP'}
		})
		self.assertEqual(config['thehive']['url'], '')
		self.assertEqual(config['thehive']['mispId'], '')
		entry, error = tickets.validate_entry('thehive', {'enabled': False, 'url': ''}, config['thehive'])
		self.assertIsNone(error)
		self.assertEqual(entry['url'], '')

	def test_with_a_key_the_same_address_is_a_real_one(self):
		config = self.load({
			'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'},
			'misp': {'id': 'MISP THP'}
		})
		self.assertEqual(config['thehive']['url'], 'http://thehive:9000')
		self.assertEqual(config['thehive']['mispId'], 'MISP THP')

	def test_an_address_somebody_typed_is_kept_while_the_key_is_missing(self):
		# O formulário pode ser preenchido em etapas: endereço hoje, chave amanhã
		config = self.load({
			'thehive': {'url': 'https://thehive.exemplo.com', 'apikey': ''},
			'misp': {'id': 'MISP da equipe'}
		})
		self.assertEqual(config['thehive']['url'], 'https://thehive.exemplo.com')
		self.assertEqual(config['thehive']['mispId'], 'MISP da equipe')

	def test_what_the_administrator_saved_outranks_both_defaults(self):
		config = self.load({
			'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'},
			'ticketing': {'thehive': {'enabled': False}, 'disk': {'enabled': True}}
		})
		self.assertFalse(config['thehive']['enabled'])
		self.assertTrue(config['disk']['enabled'])

	def test_disk_switched_off_on_purpose_stays_off(self):
		config = self.load({
			'thehive': {'url': '', 'apikey': ''},
			'ticketing': {'disk': {'enabled': False}}
		})
		self.assertFalse(config['disk']['enabled'])

	def test_saving_once_makes_the_inherited_choice_explicit(self):
		# Depois do primeiro Salvar a escolha está no arquivo, e deixa de depender
		# de a chave continuar lá
		config = self.load({'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'}})
		tickets.save_config(config, path = self.path)
		with open(self.path) as conf_file:
			stored = json.load(conf_file)
		self.assertTrue(stored['ticketing']['thehive']['enabled'])
		self.assertFalse(stored['ticketing']['disk']['enabled'])


class TheApplicationDoesNotNeedTheHive(unittest.TestCase):
	"""O que em thephish_app.py supunha que o TheHive estava lá.

	Lido no texto, como em test_page_routes: thephish_app não se importa fora da
	imagem. São três suposições, e nenhuma delas dava erro que alguém ligasse ao
	TheHive — uma listagem de casos que não abre, um nome de exportação que some.
	"""

	def setUp(self):
		here = os.path.dirname(os.path.abspath(__file__))
		with open(os.path.join(here, 'thephish_app.py'), encoding = 'utf-8') as source:
			self.source = source.read()

	def function(self, name):
		start = self.source.index('\ndef {0}('.format(name))
		end = self.source.find('\ndef ', start + 1)
		return self.source[start:end if end != -1 else len(self.source)]

	def test_the_settings_do_not_require_the_section(self):
		# conf_dict['thehive']['url'] era um KeyError à espera de uma configuração
		# que nunca teve TheHive
		body = self.function('thehive_settings')
		self.assertNotIn("conf_dict['thehive']", body)
		self.assertIn("conf_dict.get('thehive')", body)

	def test_a_listing_with_no_thehive_record_does_not_read_the_settings(self):
		# observables_for chama isto em toda listagem. Com o histórico vindo do
		# disco não há nada a buscar, e a saída tem de vir antes da leitura
		body = self.function('thehive_observables_for')
		self.assertLess(body.index('if not case_ids:'), body.index('thehive_settings()'))

	def test_thehive_reads_do_not_call_requests_directly(self):
		# thehive_query e a leitura do .eml do chat são as duas chamadas HTTP ao
		# TheHive que não passam pelo thehive4py. Com `requests.post/get` direto
		# seguiriam redirect e pulariam a revalidação da hora da chamada
		for name in ('thehive_query', 'chat_extract_email_body'):
			body = self.function(name)
			self.assertNotIn('requests.', body, name)
			self.assertIn('tickets.thehive_call(', body, name)

	def test_a_thehive_reference_without_thehive_gets_an_answer(self):
		body = self.function('build_chat_context')
		self.assertIn('not (base_url and apikey)', body)
		self.assertLess(body.index('not (base_url and apikey)'), body.index('thehive_query('))

	def test_the_test_button_validates_as_a_call_and_saving_does_not(self):
		# validate_entry dispensa a trava num único caso (desligar sem mexer no
		# endereço), e só no salvar. Se a rota de teste perdesse o `probing`, o
		# botão Testar chamaria um endereço que ninguém conferiu
		self.assertIn('probing = True', self.function('test_ticket_destination'))
		self.assertNotIn('probing', self.function('update_ticket_destination'))

	def test_saving_the_case_parameters_leaves_the_misp_name_alone(self):
		# O campo saiu do formulário. Ler a ausência dele como "em branco" apagaria
		# o nome da exportação de quem usa o TheHive ao salvar o TLP
		body = self.function('update_case_config')
		self.assertIn('if misp_id is not None:', body)
		self.assertLess(body.index('if misp_id is not None:'), body.index("misp_conf['id']"))


class TheHiveCredentials(unittest.TestCase):
	"""O endereço e a chave do TheHive, agora editados pelo card do destino.

	Eles moravam num segundo card, escrito à mão só para eles. O card saiu e os
	campos entraram no registro — mas o *arquivo* não mudou: a seção `thehive`
	continua sendo a única fonte, porque `thephish_app` e as telas de histórico
	vão direto lá. Se `save_config` gravasse só na seção `ticketing`, a chave
	sumiria para todo o resto da aplicação, e o sintoma seria uma tela de Casos
	vazia sem nenhum erro. É isto que estes testes seguram.
	"""

	def setUp(self):
		import tempfile
		handle, self.path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)
		with open(self.path, 'w') as conf_file:
			json.dump({'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-antiga'}}, conf_file)

	def tearDown(self):
		os.unlink(self.path)

	def stored(self):
		with open(self.path) as conf_file:
			return json.load(conf_file)

	def test_o_registro_declara_endereco_e_chave(self):
		keys = [f['key'] for f in tickets.BY_ID['thehive']['credentials']]
		self.assertIn('url', keys)
		self.assertIn('apikey', keys)

	def test_load_traz_o_que_esta_na_secao_thehive(self):
		config = tickets.load_config(path = self.path)
		self.assertEqual(config['thehive']['url'], 'http://thehive:9000')
		self.assertEqual(config['thehive']['apikey'], 'chave-antiga')

	def test_um_apikey_vazio_gravado_nao_apaga_a_chave_real(self):
		# O bug que estava no ar: uma versão anterior gravava `apikey: ""` na seção
		# ticketing, e essa string vazia vencia a chave real da seção thehive na
		# leitura. O destino recusava criar caso dizendo que a chave não estava
		# configurada — com a chave no arquivo, visível a olho nu. Configurações
		# assim já existem instaladas, então a leitura precisa ignorá-las.
		with open(self.path, 'w') as conf_file:
			json.dump({
				'thehive': {'url': 'http://thehive:9000', 'apikey': 'chave-real'},
				'ticketing': {'thehive': {'enabled': True, 'url': '', 'apikey': '', 'tlp': 3}}
			}, conf_file)
		config = tickets.load_config(path = self.path)
		self.assertEqual(config['thehive']['apikey'], 'chave-real')
		self.assertEqual(config['thehive']['url'], 'http://thehive:9000')
		# O resto da entrada gravada continua valendo normalmente
		self.assertEqual(config['thehive']['tlp'], 3)
		self.assertTrue(config['thehive']['enabled'])

	def test_save_grava_de_volta_na_secao_thehive(self):
		config = tickets.load_config(path = self.path)
		config['thehive']['url'] = 'http://thehive:9000/'
		config['thehive']['apikey'] = 'chave-nova'
		tickets.save_config(config, path = self.path)
		self.assertEqual(self.stored()['thehive']['apikey'], 'chave-nova')
		self.assertEqual(self.stored()['thehive']['url'], 'http://thehive:9000/')

	def test_a_chave_nao_fica_duplicada_na_secao_ticketing(self):
		# Duas cópias da mesma chave é como se depura a errada
		config = tickets.load_config(path = self.path)
		tickets.save_config(config, path = self.path)
		self.assertNotIn('apikey', self.stored()['ticketing']['thehive'])
		self.assertNotIn('url', self.stored()['ticketing']['thehive'])

	def test_uma_volta_completa_preserva_a_chave(self):
		# Salvar sem tocar em nada não pode perder a credencial: é o que acontece
		# quando o analista muda só o TLP e clica em Salvar
		for _ in range(3):
			tickets.save_config(tickets.load_config(path = self.path), path = self.path)
		self.assertEqual(self.stored()['thehive']['apikey'], 'chave-antiga')
		self.assertEqual(tickets.load_config(path = self.path)['thehive']['apikey'], 'chave-antiga')

	def test_a_chave_nunca_volta_para_o_navegador(self):
		public = tickets.public_config(tickets.load_config(path = self.path))
		self.assertNotIn('apikey', public['thehive'])
		self.assertTrue(public['thehive']['hasApikey'])
		self.assertEqual(public['thehive']['url'], 'http://thehive:9000')

	def test_chave_em_branco_mantem_a_gravada(self):
		stored = tickets.load_config(path = self.path)['thehive']
		entry, error = tickets.validate_entry('thehive',
			{'enabled': True, 'url': 'http://127.0.0.1:9000', 'apikey': ''}, stored)
		self.assertIsNone(error)
		self.assertEqual(entry['apikey'], 'chave-antiga')

	def test_um_nome_que_nao_resolve_e_recusado(self):
		# Comportamento novo, e vale dizer em voz alta: o formulário antigo do
		# TheHive só olhava o esquema da URL. Agora vale a mesma trava do Jira, que
		# resolve o nome — então salvar exige que o TheHive esteja alcançável. É o
		# caso dentro do compose, onde `thehive` resolve pelo nome do serviço; num
		# ambiente onde não resolva, o erro diz exatamente isso.
		stored = tickets.load_config(path = self.path)['thehive']
		entry, error = tickets.validate_entry('thehive',
			{'enabled': True, 'url': 'http://nome-que-nao-existe.invalid:9000', 'apikey': 'x'},
			stored)
		self.assertIsNone(entry)
		self.assertIn('resolver', error)

	def stored_without_a_host(self):
		"""O que tem gravado quem atualizou de uma instalação com o TheHive no compose."""
		return {'enabled': True, 'url': 'http://thehive-que-saiu.invalid:9000', 'apikey': 'chave-antiga'}

	def test_desligar_nao_exige_que_o_endereco_gravado_ainda_resolva(self):
		# O TheHive saiu do compose e o nome dele não resolve mais. A trava,
		# cobrada no salvar, recusava exatamente o salvar que desliga o destino —
		# e o destino ficava ligado, falhando a cada análise, sem saída pela tela
		stored = self.stored_without_a_host()
		for submitted_url in ('', stored['url']):
			entry, error = tickets.validate_entry('thehive',
				{'enabled': False, 'url': submitted_url, 'apikey': ''}, stored)
			self.assertIsNone(error)
			self.assertFalse(entry['enabled'])
			self.assertEqual(entry['url'], stored['url'])
			self.assertEqual(entry['apikey'], 'chave-antiga')

	def test_ligar_continua_exigindo(self):
		stored = self.stored_without_a_host()
		entry, error = tickets.validate_entry('thehive',
			{'enabled': True, 'url': '', 'apikey': ''}, stored)
		self.assertIsNone(entry)
		self.assertIn('resolver', error)

	def test_um_endereco_novo_e_conferido_mesmo_com_o_destino_desligado(self):
		# A exceção é para o endereço que já estava gravado. Um endereço novo,
		# gravado sem conferir num destino desligado, seria lido depois pelas
		# telas que consultam um caso do TheHive pelo número
		stored = self.stored_without_a_host()
		entry, error = tickets.validate_entry('thehive',
			{'enabled': False, 'url': 'http://outro-nome.invalid:9000', 'apikey': ''}, stored)
		self.assertIsNone(entry)
		self.assertIn('resolver', error)

	def test_o_botao_testar_nunca_dispensa_a_trava(self):
		# Testar usa a entrada agora, numa chamada ao destino
		stored = self.stored_without_a_host()
		entry, error = tickets.validate_entry('thehive',
			{'enabled': False, 'url': '', 'apikey': ''}, stored, probing = True)
		self.assertIsNone(entry)
		self.assertIn('resolver', error)

	def test_endereco_invalido_e_recusado(self):
		stored = tickets.load_config(path = self.path)['thehive']
		entry, error = tickets.validate_entry('thehive',
			{'enabled': True, 'url': 'nao-e-url', 'apikey': 'x'}, stored)
		self.assertIsNone(entry)
		self.assertIn('TheHive', error)

	def test_nome_de_servico_do_docker_e_aceito(self):
		# http e rede interna: dentro do compose o TheHive não tem TLS e resolve
		# para um endereço privado. Exigir https aqui quebraria toda instalação.
		stored = tickets.load_config(path = self.path)['thehive']
		entry, error = tickets.validate_entry('thehive',
			{'enabled': True, 'url': 'http://127.0.0.1:9000', 'apikey': 'x'}, stored)
		self.assertIsNone(error)
		self.assertEqual(entry['url'], 'http://127.0.0.1:9000')


if __name__ == '__main__':
	unittest.main()


class RetentionScope(unittest.TestCase):
	"""A retenção só pode apagar o que ela própria criou.

	O caminho natural para apontar o destino de disco é o próprio data/, que é o
	bind mount — e é onde moram as regras do YARA e o banco de usuários. Apagar
	"o que está velho" sem olhar o nome levava as regras junto.
	"""

	def setUp(self):
		self.root = tempfile.mkdtemp(prefix = 'bluephish-test-')

	def tearDown(self):
		shutil.rmtree(self.root, ignore_errors = True)

	def _age(self, name, days):
		import datetime
		path = os.path.join(self.root, name)
		os.makedirs(path, exist_ok = True)
		stale = (datetime.datetime.now() - datetime.timedelta(days = days)).timestamp()
		os.utime(path, (stale, stale))
		return path

	def test_a_directory_that_is_not_an_analysis_is_never_touched(self):
		rules = self._age('yara', 99)
		database = self._age('thephish_data', 99)
		self.assertEqual(tickets.prune_old_analyses(self.root, 30), 0)
		self.assertTrue(os.path.isdir(rules))
		self.assertTrue(os.path.isdir(database))

	def test_an_old_analysis_folder_is_removed(self):
		old = self._age('2020-01-01T00-00-00-assunto-velho', 99)
		self.assertEqual(tickets.prune_old_analyses(self.root, 30), 1)
		self.assertFalse(os.path.isdir(old))

	def test_the_two_together(self):
		rules = self._age('yara', 99)
		old = self._age('2020-01-01T00-00-00-antigo', 99)
		self.assertEqual(tickets.prune_old_analyses(self.root, 30), 1)
		self.assertTrue(os.path.isdir(rules))
		self.assertFalse(os.path.isdir(old))

	def test_what_create_disk_produces_is_recognized_as_ours(self):
		# O padrão e o nome gerado têm de continuar casando, ou a retenção deixa
		# de limpar sem ninguém perceber
		result = tickets.create_disk(disk_entry(self.root), sample_report(), None)
		self.assertTrue(tickets.is_analysis_dir(os.path.basename(result['ref'])))
