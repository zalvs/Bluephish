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

	TheHive vem ligado de fábrica de propósito (antes da refatoração toda análise
	criava um caso lá, e um upgrade que parasse de criar pareceria perda de dado).
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

	def test_only_thehive_ships_enabled(self):
		# Antes da refatoração toda análise criava um caso no TheHive; um upgrade
		# que parasse de criar pareceria que a aplicação perdeu os casos. Os outros
		# destinos são adesão explícita.
		config = tickets.default_config()
		self.assertTrue(config['thehive']['enabled'])
		self.assertFalse(config['jira']['enabled'])
		self.assertFalse(config['disk']['enabled'])

	def test_a_configuration_without_the_section_still_loads(self):
		config = tickets.load_config(path = 'no-such-file.json')
		self.assertFalse(config['jira']['enabled'])
		self.assertEqual(config['disk']['minVerdict'], 'all')


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
