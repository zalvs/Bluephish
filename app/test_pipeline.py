"""Tests for the analysis pipeline that replaced the Cortex job machinery.

Two pure pieces carry the decisions worth pinning down:

  run_analysis.plan_jobs   which analyzer runs on which observable. Getting this
                           wrong is silent: an observable simply never gets
                           judged, and the verdict comes out Safe.

  unshorten._next_hop      how a redirect chain is followed, including the
                           relative Location that a real shortener does send.

The network paths are not mocked, for the same reason the vendor clients are not:
a fake only proves it matches the code. What is asserted here is that the guard
around them refuses what it must — a redirect into the internal network, the
metadata service, an empty URL.

Run with:  python -m unittest test_pipeline   (from the app/ directory)
"""

import time
import unittest

import analyzers
import custom_analyzers
import run_analysis
import unshorten


def observable(name, obs_type, obs_id = 'o1'):
	return {'name': name, 'type': obs_type, 'tags': [], 'id': obs_id, 'attachment_id': ''}


def enabled(*analyzer_ids):
	config = analyzers.default_config()
	for analyzer_id in analyzer_ids:
		config[analyzer_id]['enabled'] = True
	return config


def custom(observables, enabled_flag = True, definition_id = 'custom_tip'):
	return {
		'id': definition_id, 'enabled': enabled_flag, 'name': 'TIP interno',
		'url': 'https://tip.exemplo.com/lookup?i={value}', 'method': 'GET',
		'authType': 'none', 'authName': '', 'authValue': '',
		'observables': observables, 'valuePath': 'verdict',
		'levelMap': [{'value': 'bad', 'level': 'malicious'}], 'fallbackLevel': 'info'
	}


class Planning(unittest.TestCase):

	def plan(self, observables, config = None, definitions = None):
		return run_analysis.plan_jobs(observables, config or analyzers.default_config(),
			definitions or [])

	def test_nothing_enabled_plans_nothing(self):
		self.assertEqual(self.plan([observable('8.8.8.8', 'ip')]), [])

	def test_an_enabled_analyzer_is_planned_for_a_type_it_supports(self):
		planned = self.plan([observable('8.8.8.8', 'ip')], enabled('abuseipdb'))
		self.assertEqual([job['id'] for job in planned], ['abuseipdb'])

	def test_an_enabled_analyzer_is_skipped_for_a_type_it_cannot_judge(self):
		# AbuseIPDB only scores IPs; planning it on a domain would guarantee an
		# 'info' that says nothing
		planned = self.plan([observable('exemplo.com', 'domain')], enabled('abuseipdb'))
		self.assertEqual(planned, [])

	def test_every_applicable_analyzer_is_planned_for_the_same_observable(self):
		planned = self.plan([observable('http://mau.exemplo/a', 'url')],
			enabled('virustotal', 'safebrowsing', 'phishtank', 'abuseipdb'))
		self.assertEqual(sorted(job['id'] for job in planned),
			['phishtank', 'safebrowsing', 'virustotal'])

	def test_the_forwarded_eml_is_planned_for_yara_only(self):
		# The .eml carries the whole reported email; sending its hash to a
		# reputation vendor says nothing, matching rules against it can
		planned = self.plan([observable('denuncia.eml', 'file_message/rfc822')],
			enabled('yara', 'virustotal', 'hybridanalysis'))
		self.assertEqual([job['id'] for job in planned], ['yara'])

	def test_a_custom_analyzer_is_planned_alongside_the_native_ones(self):
		planned = self.plan([observable('exemplo.com', 'domain')],
			enabled('virustotal'), [custom(['domain'])])
		self.assertEqual(sorted(job['id'] for job in planned), ['custom_tip', 'virustotal'])
		kinds = dict((job['id'], job['kind']) for job in planned)
		self.assertEqual(kinds['custom_tip'], 'custom')
		self.assertEqual(kinds['virustotal'], 'native')

	def test_a_disabled_custom_analyzer_is_not_planned(self):
		planned = self.plan([observable('exemplo.com', 'domain')],
			analyzers.default_config(), [custom(['domain'], enabled_flag = False)])
		self.assertEqual(planned, [])

	def test_a_custom_analyzer_is_skipped_for_a_type_it_does_not_declare(self):
		planned = self.plan([observable('exemplo.com', 'domain')],
			analyzers.default_config(), [custom(['ip'])])
		self.assertEqual(planned, [])

	def test_each_observable_gets_its_own_job(self):
		planned = self.plan(
			[observable('8.8.8.8', 'ip', 'a'), observable('1.1.1.1', 'ip', 'b')],
			enabled('abuseipdb'))
		self.assertEqual(len(planned), 2)
		self.assertEqual(sorted(job['observable']['id'] for job in planned), ['a', 'b'])

	def test_a_job_carries_the_display_name_the_reports_will_use(self):
		planned = self.plan([observable('8.8.8.8', 'ip')], enabled('abuseipdb'))
		self.assertEqual(planned[0]['name'], 'AbuseIPDB')

	def test_a_type_the_admin_unselected_is_not_planned(self):
		# O VirusTotal sabe avaliar URL; nesta instalação ele só recebe hash
		config = enabled('virustotal')
		config['virustotal']['observables'] = ['hash']
		self.assertEqual(self.plan([observable('http://mau.exemplo/a', 'url')], config), [])

	def test_the_types_still_selected_keep_being_planned(self):
		config = enabled('virustotal')
		config['virustotal']['observables'] = ['hash']
		planned = self.plan([observable('a' * 64, 'hash')], config)
		self.assertEqual([job['id'] for job in planned], ['virustotal'])

	def test_restricting_one_analyzer_does_not_silence_the_others(self):
		# É a promessa que a tela faz ao explicar a escolha: desmarcar um tipo
		# num fornecedor não tira o observável da análise
		config = enabled('virustotal', 'safebrowsing')
		config['virustotal']['observables'] = ['hash']
		planned = self.plan([observable('http://mau.exemplo/a', 'url')], config)
		self.assertEqual([job['id'] for job in planned], ['safebrowsing'])


class AnalyzerCache(unittest.TestCase):
	"""O cache que impede uma campanha de refazer as mesmas consultas.

	Dezenas de denúncias do mesmo e-mail chegam em minutos, e sem isto cada uma
	repete as consultas do observável — que é exatamente o pico em que as cotas
	gratuitas estouram.
	"""

	def setUp(self):
		run_analysis._analyzer_cache.clear()

	tearDown = setUp

	def job(self, name, obs_type, analyzer_id = 'virustotal', kind = 'native'):
		return {'observable': observable(name, obs_type), 'kind': kind,
			'id': analyzer_id, 'name': analyzer_id}

	def report(self, level = 'malicious', error = '', retryable = False):
		return {'level': level, 'signal': None, 'detail': '', 'error': error,
			'retryable': retryable}

	def test_a_stored_report_comes_back(self):
		key = run_analysis.cache_key(self.job('8.8.8.8', 'ip'), '8.8.8.8')
		run_analysis.cache_put(key, self.report())
		self.assertEqual(run_analysis.cache_get(key)['level'], 'malicious')

	def test_the_same_value_for_another_analyzer_is_a_different_entry(self):
		first = run_analysis.cache_key(self.job('8.8.8.8', 'ip', 'virustotal'), '8.8.8.8')
		second = run_analysis.cache_key(self.job('8.8.8.8', 'ip', 'abuseipdb'), '8.8.8.8')
		run_analysis.cache_put(first, self.report())
		self.assertIsNone(run_analysis.cache_get(second))

	def test_a_file_is_never_cached(self):
		# O caminho é temporário e muda a cada análise; casar dois arquivos
		# diferentes que calharam no mesmo caminho seria pior que não cachear
		self.assertIsNone(run_analysis.cache_key(
			self.job('anexo.pdf', 'file_message/rfc822', 'yara'), '/tmp/x/anexo.pdf'))

	def test_an_error_is_not_cached(self):
		# Fornecedor fora do ar é estado do momento, não veredito
		key = run_analysis.cache_key(self.job('8.8.8.8', 'ip'), '8.8.8.8')
		run_analysis.cache_put(key, self.report(level = 'info', error = 'sem resposta'))
		self.assertIsNone(run_analysis.cache_get(key))

	def test_a_rate_limited_result_is_not_cached(self):
		# Cacheá-lo fixaria por uma hora o 429 que a próxima tentativa resolveria
		key = run_analysis.cache_key(self.job('8.8.8.8', 'ip'), '8.8.8.8')
		run_analysis.cache_put(key, self.report(level = 'info', retryable = True))
		self.assertIsNone(run_analysis.cache_get(key))

	def test_an_expired_entry_is_dropped(self):
		key = run_analysis.cache_key(self.job('8.8.8.8', 'ip'), '8.8.8.8')
		run_analysis._analyzer_cache[key] = (time.time() - 1, self.report())
		self.assertIsNone(run_analysis.cache_get(key))
		self.assertNotIn(key, run_analysis._analyzer_cache)

	def test_a_hit_hands_back_a_copy(self):
		# Quem recebe acrescenta os campos do observável ao relatório, e o
		# original tem de continuar servindo o próximo acerto intacto
		key = run_analysis.cache_key(self.job('8.8.8.8', 'ip'), '8.8.8.8')
		run_analysis.cache_put(key, self.report())
		run_analysis.cache_get(key)['level'] = 'mexido'
		self.assertEqual(run_analysis.cache_get(key)['level'], 'malicious')

	def test_the_cache_stays_bounded(self):
		for index in range(run_analysis.ANALYZER_CACHE_MAX_ENTRIES + 50):
			key = ('native', 'virustotal', 'ip', '10.0.0.{0}'.format(index))
			run_analysis.cache_put(key, self.report())
		self.assertLessEqual(len(run_analysis._analyzer_cache),
			run_analysis.ANALYZER_CACHE_MAX_ENTRIES)


class RateLimitSignal(unittest.TestCase):

	def test_a_rate_limit_is_a_distinct_exception(self):
		# The pipeline requeues on this one and only this one, so it must not
		# collapse back into the generic failure
		self.assertTrue(issubclass(analyzers.RateLimited, analyzers.AnalyzerError))

	def test_an_ordinary_failure_is_not_retryable(self):
		result = analyzers.run('virustotal', 'ip', '8.8.8.8', enabled('virustotal'))
		self.assertEqual(result['level'], 'info')
		self.assertFalse(result.get('retryable'))


class RedirectChain(unittest.TestCase):

	class Response(object):
		def __init__(self, status_code, location = None):
			self.status_code = status_code
			self.headers = {'Location': location} if location else {}

	def hop(self, response, current = 'https://curto.exemplo/abc'):
		return unshorten._next_hop(response, current)

	def test_a_non_redirect_ends_the_chain(self):
		self.assertEqual(self.hop(self.Response(200)), '')

	def test_a_redirect_without_a_location_ends_the_chain(self):
		self.assertEqual(self.hop(self.Response(302)), '')

	def test_an_absolute_location_is_followed_as_is(self):
		self.assertEqual(self.hop(self.Response(301, 'https://destino.exemplo/pagina')),
			'https://destino.exemplo/pagina')

	def test_a_relative_location_is_resolved_against_the_current_url(self):
		# Legitimate and common; not resolving it would silently truncate the chain
		self.assertEqual(self.hop(self.Response(302, '/final')),
			'https://curto.exemplo/final')

	def test_every_redirect_status_counts(self):
		for status in (301, 302, 303, 307, 308):
			self.assertEqual(self.hop(self.Response(status, 'https://d.exemplo/x')),
				'https://d.exemplo/x')


class RedirectGuard(unittest.TestCase):
	"""The URL comes from an attacker's email, so each hop passes the SSRF guard."""

	def test_an_empty_url_is_refused_without_a_request(self):
		result = unshorten.resolve('')
		self.assertFalse(result['found'])
		self.assertIn('vazia', result['error'])

	def test_a_url_pointing_at_the_internal_network_is_refused(self):
		result = unshorten.resolve('http://127.0.0.1/redirect')
		self.assertFalse(result['found'])
		self.assertIn('recusado', result['error'])

	def test_the_cloud_metadata_service_is_refused(self):
		result = unshorten.resolve('http://169.254.169.254/latest/meta-data/')
		self.assertFalse(result['found'])
		self.assertIn('recusado', result['error'])

	def test_the_address_guard_holds_even_with_http_allowed(self):
		# resolve() must never allow the internal network: an email's URL is not a
		# firewall address an admin typed
		ok, _error = custom_analyzers.validate_destination(
			'http://10.0.0.5/x', require_https = False)
		self.assertFalse(ok)

	def test_a_shortener_reached_over_http_is_not_refused_for_the_scheme(self):
		# Nothing leaves in this request — no credential, no observable — so the
		# https rule would only stop http shorteners from ever being resolved
		ok, _error = custom_analyzers.validate_destination(
			'http://bit.ly/abc', require_https = False)
		self.assertTrue(ok)

	def test_an_analyzer_endpoint_over_http_is_still_refused(self):
		# The default is unchanged: an analyzer does send a credential
		ok, error = custom_analyzers.validate_destination('http://api.exemplo.com/x')
		self.assertFalse(ok)
		self.assertIn('https://', error)


if __name__ == '__main__':
	unittest.main()
