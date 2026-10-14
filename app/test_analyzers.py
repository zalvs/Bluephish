"""Tests for the native analyzers.

What is pinned down here is the part that decides a verdict: the thresholds, the
validation that keeps a threshold pair coherent, and the promise that a stored
secret never leaves the process. The vendor HTTP calls are deliberately not
mocked — a test that asserts against a hand-written fake of the VirusTotal
response proves only that the fake matches the code, so the clients are kept
thin and the judgement they feed is what gets tested.

Run with:  python -m unittest test_analyzers   (from the app/ directory)
"""

import unittest

import analyzers as an
import analyzer_guides as guides


def vt(malicious, suspicious = 0, total = 90):
	return {'malicious': malicious, 'suspicious': suspicious, 'total': total}


class VirusTotalThresholds(unittest.TestCase):

	def setUp(self):
		# The example from the brief: malicious from 5 engines up, suspicious from 1
		self.t = {'maliciousMin': 5, 'suspiciousMin': 1}

	def level(self, signal):
		return an.level_for('virustotal', self.t, signal)

	def test_at_the_malicious_threshold_it_is_malicious(self):
		self.assertEqual(self.level(vt(5)), 'malicious')

	def test_above_the_threshold_it_is_malicious(self):
		self.assertEqual(self.level(vt(40)), 'malicious')

	def test_one_engine_below_the_threshold_is_only_suspicious(self):
		self.assertEqual(self.level(vt(4)), 'suspicious')

	def test_a_single_engine_is_enough_to_be_suspicious(self):
		self.assertEqual(self.level(vt(1)), 'suspicious')

	def test_a_clean_indicator_that_was_actually_scanned_is_safe(self):
		self.assertEqual(self.level(vt(0, 0, total = 90)), 'safe')

	def test_an_indicator_nobody_scanned_is_info_not_safe(self):
		# Never looked at is not the same as looked at and found clean
		self.assertEqual(self.level(vt(0, 0, total = 0)), 'info')

	def test_suspicious_engines_alone_can_reach_the_suspicious_band(self):
		self.assertEqual(self.level(vt(0, 3)), 'suspicious')

	def test_suspicious_engines_alone_never_reach_malicious(self):
		# 30 "suspicious" votes and no "malicious" one is still not a conviction
		self.assertEqual(self.level(vt(0, 30)), 'suspicious')

	def test_a_stricter_setting_moves_the_line(self):
		self.t = {'maliciousMin': 1, 'suspiciousMin': 1}
		self.assertEqual(self.level(vt(1)), 'malicious')

	def test_a_looser_setting_moves_it_the_other_way(self):
		self.t = {'maliciousMin': 20, 'suspiciousMin': 10}
		self.assertEqual(self.level(vt(12)), 'suspicious')
		self.assertEqual(self.level(vt(9)), 'safe')


class AbuseIpdbThresholds(unittest.TestCase):

	def setUp(self):
		self.t = {'maliciousMin': 80, 'suspiciousMin': 25}

	def level(self, score):
		return an.level_for('abuseipdb', self.t, {'score': score, 'reports': 1})

	def test_a_high_confidence_score_is_malicious(self):
		self.assertEqual(self.level(80), 'malicious')
		self.assertEqual(self.level(100), 'malicious')

	def test_a_middling_score_is_suspicious(self):
		self.assertEqual(self.level(25), 'suspicious')
		self.assertEqual(self.level(79), 'suspicious')

	def test_a_low_score_is_safe(self):
		self.assertEqual(self.level(24), 'safe')
		self.assertEqual(self.level(0), 'safe')


class YaraThresholds(unittest.TestCase):

	def test_a_match_convicts_by_default(self):
		self.assertEqual(an.level_for('yara', {'maliciousMin': 1, 'suspiciousMin': 1}, {'matches': 1}), 'malicious')

	def test_no_match_is_safe(self):
		self.assertEqual(an.level_for('yara', {'maliciousMin': 1, 'suspiciousMin': 1}, {'matches': 0}), 'safe')

	def test_a_higher_bar_needs_corroborating_rules(self):
		t = {'maliciousMin': 3, 'suspiciousMin': 1}
		self.assertEqual(an.level_for('yara', t, {'matches': 2}), 'suspicious')
		self.assertEqual(an.level_for('yara', t, {'matches': 3}), 'malicious')


class CrowdStrikeThresholds(unittest.TestCase):

	def setUp(self):
		self.t = {'maliciousMin': 1, 'suspiciousMin': 1}

	def test_a_high_confidence_indicator_is_malicious(self):
		self.assertEqual(an.level_for('crowdstrike', self.t, {'indicators': 2, 'highConfidence': 1}), 'malicious')

	def test_a_known_indicator_without_high_confidence_is_suspicious(self):
		self.assertEqual(an.level_for('crowdstrike', self.t, {'indicators': 2, 'highConfidence': 0}), 'suspicious')

	def test_an_unknown_indicator_is_safe(self):
		self.assertEqual(an.level_for('crowdstrike', self.t, {'indicators': 0, 'highConfidence': 0}), 'safe')


class CrowdStrikeSandboxVerdict(unittest.TestCase):
	"""Reading a report CrowdStrike already produced — never a submission."""

	def setUp(self):
		self.t = {'maliciousMin': 70, 'suspiciousMin': 30}

	def level(self, **signal):
		signal.setdefault('reports', 1)
		return an.level_for('crowdstrike_sandbox', self.t, signal)

	def test_the_sandbox_verdict_outranks_a_low_score(self):
		self.assertEqual(self.level(verdict = 'malicious', threatScore = 0), 'malicious')

	def test_a_high_score_convicts_without_an_explicit_verdict(self):
		self.assertEqual(self.level(verdict = '', threatScore = 70), 'malicious')

	def test_a_suspicious_verdict_survives_a_low_score(self):
		self.assertEqual(self.level(verdict = 'suspicious', threatScore = 0), 'suspicious')

	def test_a_clean_report_is_safe(self):
		self.assertEqual(self.level(verdict = 'no specific threat', threatScore = 0), 'safe')

	def test_an_indicator_nobody_detonated_is_info_not_safe(self):
		# Absence of a report is not a clean bill of health
		self.assertEqual(an.level_for('crowdstrike_sandbox', self.t, {'reports': 0}), 'info')

	def test_it_judges_urls_as_well_as_hashes(self):
		# The URL path is the whole point of the module: a detonated URL is
		# reachable without submitting anything
		self.assertTrue(an.supports('crowdstrike_sandbox', 'url'))
		self.assertTrue(an.supports('crowdstrike_sandbox', 'hash'))

	def test_it_never_claims_to_judge_a_raw_file(self):
		# Judging a file would mean uploading it, which this analyzer does not do
		self.assertFalse(an.supports('crowdstrike_sandbox', 'file'))


class BlocklistAnalyzers(unittest.TestCase):
	"""Safe Browsing, OpenPhish and URLhaus answer yes or no — nothing to tune."""

	def test_safe_browsing_presence_convicts(self):
		self.assertEqual(an.level_for('safebrowsing', {}, {'matches': 1, 'threats': ['SOCIAL_ENGINEERING']}), 'malicious')

	def test_safe_browsing_absence_is_safe_never_stronger(self):
		# Not being on a blocklist is weak evidence, so it is 'safe' and no more
		self.assertEqual(an.level_for('safebrowsing', {}, {'matches': 0, 'threats': []}), 'safe')

	def test_openphish_membership_convicts(self):
		self.assertEqual(an.level_for('openphish', {}, {'listed': True, 'feedSize': 2000}), 'malicious')
		self.assertEqual(an.level_for('openphish', {}, {'listed': False, 'feedSize': 2000}), 'safe')

	def test_urlhaus_membership_convicts(self):
		# URLhaus only holds confirmed malware-distribution URLs
		self.assertEqual(an.level_for('urlhaus', {}, {'listed': True, 'threat': 'malware_download'}), 'malicious')
		self.assertEqual(an.level_for('urlhaus', {}, {'listed': False}), 'safe')

	def test_urlhaus_convicts_even_when_the_url_is_already_offline(self):
		# It was still used to distribute malware; taken down is not exonerated
		self.assertEqual(an.level_for('urlhaus', {}, {'listed': True, 'online': False}), 'malicious')


class PhishTankReview(unittest.TestCase):

	def level(self, **signal):
		return an.level_for('phishtank', {}, signal)

	def test_a_verified_phishing_entry_convicts(self):
		self.assertEqual(self.level(inDatabase = True, valid = True, verified = True), 'malicious')

	def test_a_report_still_awaiting_review_is_only_suspicious(self):
		# Someone reported it; nobody has confirmed it yet
		self.assertEqual(self.level(inDatabase = True, valid = True, verified = False), 'suspicious')

	def test_a_report_the_reviewers_rejected_is_safe(self):
		self.assertEqual(self.level(inDatabase = True, valid = False, verified = True), 'safe')

	def test_an_url_nobody_ever_reported_is_info_not_safe(self):
		# Absence from a community database says nothing either way
		self.assertEqual(self.level(inDatabase = False), 'info')


class OtxCorroboration(unittest.TestCase):

	def setUp(self):
		self.t = {'maliciousMin': 3, 'suspiciousMin': 1}

	def level(self, pulses):
		return an.level_for('otx', self.t, {'pulses': pulses})

	def test_several_independent_pulses_convict(self):
		self.assertEqual(self.level(3), 'malicious')

	def test_a_lone_pulse_is_only_suspicious(self):
		# One researcher's collection can be noise; it is not a conviction
		self.assertEqual(self.level(1), 'suspicious')
		self.assertEqual(self.level(2), 'suspicious')

	def test_no_pulse_at_all_is_safe(self):
		self.assertEqual(self.level(0), 'safe')


class HybridAnalysisVerdict(unittest.TestCase):

	def setUp(self):
		self.t = {'maliciousMin': 70, 'suspiciousMin': 30}

	def level(self, **signal):
		signal.setdefault('reports', 1)
		return an.level_for('hybridanalysis', self.t, signal)

	def test_the_sandbox_verdict_outranks_the_score(self):
		# A low score does not rescue a sample the sandbox called malicious
		self.assertEqual(self.level(verdict = 'malicious', threatScore = 5), 'malicious')

	def test_a_high_score_convicts_without_an_explicit_verdict(self):
		self.assertEqual(self.level(verdict = '', threatScore = 70), 'malicious')

	def test_a_suspicious_verdict_survives_a_low_score(self):
		self.assertEqual(self.level(verdict = 'suspicious', threatScore = 0), 'suspicious')

	def test_a_clean_report_is_safe(self):
		self.assertEqual(self.level(verdict = 'no specific threat', threatScore = 0), 'safe')

	def test_a_hash_nobody_detonated_is_info_not_safe(self):
		self.assertEqual(an.level_for('hybridanalysis', self.t, {'reports': 0}), 'info')


class MdtiReputation(unittest.TestCase):

	def setUp(self):
		self.t = {'maliciousMin': 75, 'suspiciousMin': 25}

	def level(self, **signal):
		return an.level_for('mdti', self.t, signal)

	def test_microsofts_own_classification_is_authoritative(self):
		# Even at a score below the threshold
		self.assertEqual(self.level(classification = 'malicious', score = 10), 'malicious')

	def test_a_high_score_convicts_a_host_left_neutral(self):
		self.assertEqual(self.level(classification = 'neutral', score = 80), 'malicious')

	def test_a_suspicious_classification_survives_a_low_score(self):
		self.assertEqual(self.level(classification = 'suspicious', score = 0), 'suspicious')

	def test_a_neutral_host_with_a_low_score_is_safe(self):
		self.assertEqual(self.level(classification = 'neutral', score = 5), 'safe')

	def test_a_host_microsoft_has_never_seen_is_info(self):
		self.assertEqual(self.level(classification = '', score = 0), 'info')


class RegistryIntegrity(unittest.TestCase):
	"""Guards the promise that a registry entry is all an analyzer needs."""

	def test_every_analyzer_has_a_client(self):
		for spec in an.ANALYZERS:
			self.assertIn(spec['id'], an.CLIENTS, spec['id'])

	def test_every_analyzer_produces_a_level_without_raising(self):
		for spec in an.ANALYZERS:
			thresholds = dict((f['key'], f['default']) for f in spec['thresholds'])
			for signal in ({}, {'matches': 1}, {'listed': True}, {'pulses': 9}, {'score': 99}):
				an.level_for(spec['id'], thresholds, signal)

	def test_every_analyzer_declares_at_least_one_observable_type(self):
		for spec in an.ANALYZERS:
			self.assertTrue(spec['observables'], spec['id'])

	def test_every_analyzer_describes_what_it_saw(self):
		samples = {
			'safebrowsing': {'matches': 1, 'threats': ['MALWARE']},
			'phishtank': {'inDatabase': True, 'valid': True, 'verified': True},
			'openphish': {'listed': True, 'feedSize': 1500},
			'urlhaus': {'listed': True, 'threat': 'malware_download', 'online': True},
			'otx': {'pulses': 4, 'names': ['Emotet']},
			'hybridanalysis': {'reports': 2, 'verdict': 'malicious', 'threatScore': 90, 'family': 'Emotet'},
			'mdti': {'classification': 'malicious', 'score': 88, 'rules': ['phishing kit']}
		}
		for analyzer_id, signal in samples.items():
			self.assertTrue(an.describe(analyzer_id, signal), analyzer_id)

	def test_thresholds_are_ordered_coherently_by_default(self):
		# Ship no default that the validator would refuse
		for spec in an.ANALYZERS:
			keys = dict((f['key'], f['default']) for f in spec['thresholds'])
			if 'maliciousMin' in keys and 'suspiciousMin' in keys:
				self.assertLessEqual(keys['suspiciousMin'], keys['maliciousMin'], spec['id'])

	def test_a_blocklist_analyzer_needs_no_thresholds(self):
		for analyzer_id in ('safebrowsing', 'phishtank', 'openphish', 'urlhaus'):
			self.assertEqual(an.BY_ID[analyzer_id]['thresholds'], [], analyzer_id)


class Guides(unittest.TestCase):
	"""The screen renders prose from the registry, so the prose must be complete."""

	def test_every_analyzer_declares_a_known_family(self):
		for spec in an.ANALYZERS:
			self.assertIn(spec.get('family'), guides.FAMILIES, spec['id'])

	def test_every_analyzer_has_a_guide(self):
		for spec in an.ANALYZERS:
			self.assertTrue(guides.guide_for(spec['id']), spec['id'])

	def test_every_guide_section_has_a_title_and_a_body(self):
		for spec in an.ANALYZERS:
			for section in guides.guide_for(spec['id']):
				self.assertTrue(section.get('title'), spec['id'])
				self.assertTrue(section.get('body'), spec['id'])

	def test_a_guide_covers_credential_and_verdict(self):
		# The two questions an analyst actually arrives with
		for spec in an.ANALYZERS:
			titles = [s['title'] for s in guides.guide_for(spec['id'])]
			self.assertIn('Credencial', titles, spec['id'])
			self.assertIn('Lendo o veredito', titles, spec['id'])

	def test_every_family_explains_itself(self):
		for name, family in guides.FAMILIES.items():
			self.assertTrue(family.get('label'), name)
			self.assertTrue(family.get('summary'), name)
			self.assertTrue(family.get('body'), name)

	def test_no_guide_is_written_for_an_analyzer_that_does_not_exist(self):
		# A guide left behind after an analyzer is removed would render nowhere
		# and rot unnoticed
		for analyzer_id in guides.GUIDES:
			self.assertIn(analyzer_id, an.BY_ID, analyzer_id)

	def test_an_unknown_analyzer_simply_has_no_guide(self):
		self.assertEqual(guides.guide_for('nao-existe'), [])

	def test_the_two_sandboxes_are_in_the_sandbox_family(self):
		self.assertEqual(an.BY_ID['hybridanalysis']['family'], 'sandbox')
		self.assertEqual(an.BY_ID['crowdstrike_sandbox']['family'], 'sandbox')

	def test_the_blocklists_are_in_the_blocklist_family(self):
		for analyzer_id in ('safebrowsing', 'phishtank', 'openphish', 'urlhaus'):
			self.assertEqual(an.BY_ID[analyzer_id]['family'], 'blocklist', analyzer_id)


class MissingSignal(unittest.TestCase):

    # An analyzer that could not answer must not vouch for the observable
	def test_no_signal_is_info_for_every_analyzer(self):
		for analyzer_id in an.BY_ID:
			self.assertEqual(an.level_for(analyzer_id, {}, None), 'info', analyzer_id)

	def test_an_unknown_analyzer_is_info(self):
		self.assertEqual(an.level_for('nao-existe', {}, {'malicious': 99}), 'info')


class ObservableSupport(unittest.TestCase):

	def test_abuseipdb_only_judges_ips(self):
		self.assertTrue(an.supports('abuseipdb', 'ip'))
		for other in ('domain', 'url', 'hash', 'file', 'mail'):
			self.assertFalse(an.supports('abuseipdb', other), other)

	def test_virustotal_covers_the_reputation_types(self):
		for good in ('ip', 'domain', 'url', 'hash'):
			self.assertTrue(an.supports('virustotal', good), good)
		self.assertFalse(an.supports('virustotal', 'mail'))

	def test_a_forwarded_eml_still_counts_as_a_file(self):
		# The pipeline tags it 'file_message/rfc822'
		self.assertTrue(an.supports('yara', 'file_message/rfc822'))

	def test_an_unknown_analyzer_supports_nothing(self):
		self.assertFalse(an.supports('nao-existe', 'ip'))


class ObservableSelection(unittest.TestCase):
	"""A escolha de quais tipos vão para cada fornecedor.

	`supports` responde o que ele sabe avaliar e não muda; `sends` responde o que
	esta instalação escolheu mandar. Um erro aqui é silencioso do pior jeito: o
	observável simplesmente não é consultado e o veredito sai Safe sem que nada
	na tela diga que faltou uma consulta.
	"""

	def config_with(self, analyzer_id, observables):
		config = an.default_config()
		config[analyzer_id]['enabled'] = True
		config[analyzer_id]['observables'] = observables
		return config

	def test_by_default_everything_the_analyzer_supports_is_sent(self):
		config = an.default_config()
		for good in ('ip', 'domain', 'url', 'hash'):
			self.assertTrue(an.sends('virustotal', good, config), good)

	def test_an_unselected_type_is_not_sent(self):
		config = self.config_with('virustotal', ['hash'])
		self.assertTrue(an.sends('virustotal', 'hash', config))
		for dropped in ('ip', 'domain', 'url'):
			self.assertFalse(an.sends('virustotal', dropped, config), dropped)

	def test_selecting_a_type_the_analyzer_cannot_judge_does_not_send_it(self):
		# A validação recusa isso na entrada; se algo escrever à mão no arquivo,
		# a capacidade do fornecedor continua sendo o limite
		config = self.config_with('abuseipdb', ['ip', 'url'])
		self.assertFalse(an.sends('abuseipdb', 'url', config))

	def test_a_forwarded_eml_is_matched_against_the_base_type(self):
		config = self.config_with('yara', ['file'])
		self.assertTrue(an.sends('yara', 'file_message/rfc822', config))

	def test_an_empty_selection_falls_back_to_everything(self):
		# Um arquivo gravado à mão com a lista vazia não pode significar "este
		# analisador está ligado e nunca roda"
		config = self.config_with('virustotal', [])
		self.assertTrue(an.sends('virustotal', 'url', config))

	def test_a_missing_selection_falls_back_to_everything(self):
		# É o caso de uma instalação anterior a esta escolha
		config = an.default_config()
		config['virustotal']['enabled'] = True
		del config['virustotal']['observables']
		self.assertTrue(an.sends('virustotal', 'url', config))

	def test_the_selection_keeps_the_registry_order(self):
		# A tela lista a partir daqui, e a ordem não pode depender de como o
		# formulário ou o arquivo entregaram a lista
		self.assertEqual(an.normalize_observables('virustotal', ['url', 'ip']), ['ip', 'url'])

	def test_defaults_select_every_supported_type(self):
		config = an.default_config()
		for spec in an.ANALYZERS:
			self.assertEqual(config[spec['id']]['observables'], list(spec['observables']), spec['id'])


class TypeGuessing(unittest.TestCase):

	def test_it_recognises_each_shape(self):
		cases = [
			('8.8.8.8', 'ip'),
			('2001:db8::1', 'ip'),
			('exemplo.com.br', 'domain'),
			('https://exemplo.com/a', 'url'),
			('http://exemplo.com', 'url'),
			('d41d8cd98f00b204e9800998ecf8427e', 'hash'),
			('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hash'),
			('golpe@dominio.net', 'mail'),
			('/root/thephish/data/x.eml', 'file'),
		]
		for value, expected in cases:
			self.assertEqual(an.guess_observable_type(value), expected, value)

	def test_an_out_of_range_octet_is_not_an_ip(self):
		self.assertNotEqual(an.guess_observable_type('999.1.1.1'), 'ip')

	def test_nothing_recognisable_yields_nothing(self):
		self.assertEqual(an.guess_observable_type(''), '')
		self.assertEqual(an.guess_observable_type('   '), '')


class Validation(unittest.TestCase):

	def submit(self, analyzer_id, submitted, stored = None):
		return an.validate_entry(analyzer_id, submitted, stored)

	def test_a_valid_submission_is_accepted(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1})
		self.assertIsNone(error)
		self.assertEqual(entry['maliciousMin'], 5)
		self.assertTrue(entry['enabled'])

	def test_an_empty_secret_keeps_the_stored_one(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': '', 'maliciousMin': 5, 'suspiciousMin': 1},
			stored = {'apiKey': 'guardada'})
		self.assertIsNone(error)
		self.assertEqual(entry['apiKey'], 'guardada')

	def test_enabling_without_a_credential_is_refused(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': '', 'maliciousMin': 5, 'suspiciousMin': 1})
		self.assertIsNone(entry)
		self.assertIn('obrigat', error)

	def test_a_submitted_selection_is_stored_in_registry_order(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1,
			 'observables': ['url', 'hash']})
		self.assertIsNone(error)
		self.assertEqual(entry['observables'], ['url', 'hash'])

	def test_selecting_a_type_the_analyzer_cannot_judge_is_refused(self):
		entry, error = self.submit('abuseipdb',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 80, 'suspiciousMin': 25,
			 'maxAgeInDays': 90, 'observables': ['ip', 'url']})
		self.assertIsNone(entry)
		self.assertIn('url', error)

	def test_enabling_with_no_type_selected_is_refused(self):
		# Ligado e sem tipo nenhum é um analisador que aparece ativo na tela e
		# nunca roda — recusar é mais honesto que deixar descobrir pelo silêncio
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1,
			 'observables': []})
		self.assertIsNone(entry)
		self.assertIn('ao menos um tipo', error)

	def test_a_disabled_analyzer_may_be_saved_with_no_type_selected(self):
		# Mesma regra das credenciais: preencher em etapas é permitido enquanto
		# ele estiver desligado
		entry, error = self.submit('virustotal',
			{'enabled': False, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1,
			 'observables': []})
		self.assertIsNone(error)
		self.assertEqual(entry['observables'], ['ip', 'domain', 'url', 'hash'])

	def test_an_absent_selection_keeps_the_stored_one(self):
		# É o que a rota de teste manda, e o que uma integração antiga mandaria
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1},
			stored = {'apiKey': 'k', 'observables': ['hash']})
		self.assertIsNone(error)
		self.assertEqual(entry['observables'], ['hash'])

	def test_a_selection_that_is_not_a_list_is_refused(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 5, 'suspiciousMin': 1,
			 'observables': 'url'})
		self.assertIsNone(entry)
		self.assertIn('inválida', error)

	def test_a_disabled_analyzer_may_be_saved_half_filled(self):
		# So the form can be filled in stages without fighting the validator
		entry, error = self.submit('virustotal',
			{'enabled': False, 'apiKey': '', 'maliciousMin': 5, 'suspiciousMin': 1})
		self.assertIsNone(error)
		self.assertFalse(entry['enabled'])

	def test_unticking_the_only_type_of_a_single_type_analyzer_is_refused(self):
		# A tela mostra a seção em todo analisador, inclusive nos de um tipo só.
		# Ali a caixa e o botão de habilitar dizem a mesma coisa, e a mensagem
		# tem de mandar desabilitar em vez de deixar salvar um analisador ligado
		# que nunca roda
		entry, error = self.submit('yara',
			{'enabled': True, 'rulesPath': '/root/thephish/data/yara',
			 'maliciousMin': 1, 'suspiciousMin': 1, 'observables': []})
		self.assertIsNone(entry)
		self.assertIn('desabilite', error)

	def test_keeping_the_only_type_of_a_single_type_analyzer_is_accepted(self):
		entry, error = self.submit('yara',
			{'enabled': True, 'rulesPath': '/root/thephish/data/yara',
			 'maliciousMin': 1, 'suspiciousMin': 1, 'observables': ['file']})
		self.assertIsNone(error)
		self.assertEqual(entry['observables'], ['file'])

	def test_a_suspicious_threshold_above_the_malicious_one_is_refused(self):
		# It would make the suspicious band unreachable
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 2, 'suspiciousMin': 5})
		self.assertIsNone(entry)
		self.assertIn('inalcanç', error)

	def test_equal_thresholds_are_allowed(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 1, 'suspiciousMin': 1})
		self.assertIsNone(error)

	def test_a_threshold_out_of_range_is_refused(self):
		for bad in (0, 999):
			entry, error = self.submit('virustotal',
				{'enabled': True, 'apiKey': 'k', 'maliciousMin': bad, 'suspiciousMin': 1})
			self.assertIsNone(entry, bad)
			self.assertIn('entre', error)

	def test_a_non_numeric_threshold_is_refused(self):
		entry, error = self.submit('virustotal',
			{'enabled': True, 'apiKey': 'k', 'maliciousMin': 'cinco', 'suspiciousMin': 1})
		self.assertIsNone(entry)
		self.assertIn('número', error)

	def test_an_invalid_option_is_refused(self):
		entry, error = self.submit('crowdstrike',
			{'enabled': True, 'clientId': 'a', 'clientSecret': 'b', 'cloud': 'marte',
			 'maliciousMin': 1, 'suspiciousMin': 1})
		self.assertIsNone(entry)
		self.assertIn('inválido', error)

	def test_an_unknown_analyzer_is_refused(self):
		entry, error = self.submit('nao-existe', {'enabled': True})
		self.assertIsNone(entry)

	def test_a_non_secret_field_falls_back_to_its_default(self):
		entry, error = self.submit('yara', {'enabled': False, 'maliciousMin': 1, 'suspiciousMin': 1})
		self.assertIsNone(error)
		self.assertEqual(entry['rulesPath'], '/root/thephish/data/yara')


class TestingBeforeSaving(unittest.TestCase):
	"""The path behind the "Testar" button.

	The first version of that button ran against the *saved* credentials, so an
	analyst who pasted a key and pressed it was told no key was configured. The
	route now validates the submitted settings the same way a save does and runs
	those — which is what these pin down.
	"""

	def test_a_key_typed_but_never_saved_is_usable(self):
		entry, error = an.validate_entry('virustotal',
			{'enabled': False, 'apiKey': 'recem-colada', 'maliciousMin': 5, 'suspiciousMin': 1},
			stored = {})
		self.assertIsNone(error)
		self.assertEqual(entry['apiKey'], 'recem-colada')

	def test_a_typed_key_wins_over_the_stored_one(self):
		# Replacing a key must be testable before it is committed
		entry, _ = an.validate_entry('virustotal',
			{'enabled': True, 'apiKey': 'nova', 'maliciousMin': 5, 'suspiciousMin': 1},
			stored = {'apiKey': 'antiga'})
		self.assertEqual(entry['apiKey'], 'nova')

	def test_testing_a_disabled_analyzer_is_allowed(self):
		# Proving it works is the whole point of testing before switching it on
		entry, error = an.validate_entry('abuseipdb',
			{'enabled': False, 'apiKey': 'k', 'maliciousMin': 80, 'suspiciousMin': 25, 'maxAgeInDays': 90},
			stored = {})
		self.assertIsNone(error)
		self.assertEqual(entry['apiKey'], 'k')

	def test_an_incoherent_threshold_is_caught_on_test_too(self):
		entry, error = an.validate_entry('virustotal',
			{'enabled': False, 'apiKey': 'k', 'maliciousMin': 2, 'suspiciousMin': 9}, stored = {})
		self.assertIsNone(entry)
		self.assertIn('inalcanç', error)

	def test_with_a_key_present_the_run_gets_past_the_credential_check(self):
		# It will fail at the network in a test environment, but the point is
		# that it no longer stops at "chave não configurada"
		config = an.default_config()
		config['virustotal'].update({'enabled': True, 'apiKey': 'k'})
		result = an.run('virustotal', 'ip', '203.0.113.1', config)
		self.assertNotIn('não configurada', result['error'])


class PublicConfig(unittest.TestCase):

	def test_a_stored_secret_is_never_echoed_back(self):
		config = an.default_config()
		config['virustotal']['apiKey'] = 'segredo-que-nao-pode-vazar'
		public = an.public_config(config)
		self.assertNotIn('apiKey', public['virustotal'])
		self.assertTrue(public['virustotal']['hasApiKey'])
		self.assertNotIn('segredo-que-nao-pode-vazar', str(public))

	def test_an_absent_secret_is_reported_as_absent(self):
		public = an.public_config(an.default_config())
		self.assertFalse(public['virustotal']['hasApiKey'])

	def test_non_secret_fields_do_come_back(self):
		# The analyst has to see which rules directory is configured
		public = an.public_config(an.default_config())
		self.assertEqual(public['yara']['rulesPath'], '/root/thephish/data/yara')
		self.assertEqual(public['crowdstrike']['cloud'], 'us-1')

	def test_thresholds_come_back(self):
		public = an.public_config(an.default_config())
		self.assertEqual(public['virustotal']['maliciousMin'], 5)

	def test_every_registered_analyzer_is_present(self):
		public = an.public_config(an.default_config())
		self.assertEqual(set(public), set(an.BY_ID))


class ConfigMerging(unittest.TestCase):

	def test_defaults_start_disabled(self):
		# Nothing may start reaching out to a vendor without being switched on
		for entry in an.default_config().values():
			self.assertFalse(entry['enabled'])

	def test_the_registry_and_the_defaults_agree(self):
		config = an.default_config()
		for spec in an.ANALYZERS:
			entry = config[spec['id']]
			for field in spec.get('credentials', []) + spec.get('thresholds', []):
				self.assertIn(field['key'], entry, spec['id'] + '.' + field['key'])


class Descriptions(unittest.TestCase):

	def test_each_analyzer_explains_what_it_saw(self):
		samples = {
			'virustotal': vt(12, 3),
			'abuseipdb': {'score': 90, 'reports': 5, 'country': 'NG'},
			'yara': {'matches': 2, 'rules': ['r1', 'r2'], 'ruleFiles': 3},
			'crowdstrike': {'indicators': 4, 'highConfidence': 2},
			'crowdstrike_sandbox': {'reports': 1, 'verdict': 'malicious', 'threatScore': 88,
				'family': 'Emotet', 'environment': 'Windows 10 64 bit'}
		}
		for analyzer_id, signal in samples.items():
			text = an.describe(analyzer_id, signal)
			self.assertTrue(text, analyzer_id)

	def test_falcon_intel_names_the_family_and_the_actor_it_found(self):
		text = an.describe('crowdstrike',
			{'indicators': 4, 'highConfidence': 2, 'families': ['Emotet'], 'actors': ['MUMMY SPIDER']})
		self.assertIn('Emotet', text)
		self.assertIn('MUMMY SPIDER', text)

	def test_falcon_intel_still_describes_a_signal_without_attribution(self):
		# The older signal shape carried neither families nor actors
		self.assertTrue(an.describe('crowdstrike', {'indicators': 1, 'highConfidence': 0}))

	def test_a_sandbox_report_nobody_produced_says_so(self):
		text = an.describe('crowdstrike_sandbox', {'reports': 0})
		self.assertIn('nenhum relatório', text)

	def test_an_indicator_unknown_to_virustotal_says_so(self):
		text = an.describe('virustotal', {'malicious': 0, 'suspicious': 0, 'total': 0, 'unknown': True})
		self.assertIn('desconhecido', text)


class Running(unittest.TestCase):

	def test_a_disabled_analyzer_does_not_reach_the_network(self):
		result = an.run('virustotal', 'ip', '8.8.8.8', an.default_config())
		self.assertEqual(result['level'], 'info')
		self.assertIn('desabilitado', result['error'])

	def test_an_unsupported_observable_is_refused_before_any_call(self):
		config = an.default_config()
		config['abuseipdb']['enabled'] = True
		config['abuseipdb']['apiKey'] = 'k'
		result = an.run('abuseipdb', 'domain', 'exemplo.com', config)
		self.assertEqual(result['level'], 'info')
		self.assertIn('não avalia', result['error'])

	def test_a_missing_credential_is_reported_not_raised(self):
		config = an.default_config()
		config['virustotal']['enabled'] = True
		result = an.run('virustotal', 'ip', '8.8.8.8', config)
		self.assertEqual(result['level'], 'info')
		self.assertIn('não configurada', result['error'])


if __name__ == '__main__':
	unittest.main()
