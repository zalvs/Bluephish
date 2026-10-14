"""Testes do whitelist v2 — o casamento, as travas e a migração.

Uma whitelist errada não faz barulho: ela cala um alerta que devia ter tocado.
Por isso o que estes testes prendem não é o caminho feliz, é a evasão — o
`endswith` que deixa passar `evil-empresa.com`, o `re.search` que casa
`paypal.com` dentro de `evil.com/?ref=paypal.com`, o `@` que troca o host da
URL, o homóglifo cirílico que ninguém distingue na tela, e a regra que devia ter
expirado.

Rodar com:  python -m unittest test_whitelist   (a partir de app/)
"""

import datetime
import json
import os
import re
import tempfile
import unittest

import whitelist
import whitelist_migration


AUTHENTICATED = {'authenticated': True, 'dmarc': 'pass', 'fromDomain': 'empresa.com.br'}
NOT_AUTHENTICATED = {'authenticated': False, 'spf': 'pass', 'dkim': 'none', 'dmarc': 'fail'}

NOW = datetime.datetime(2026, 8, 23, 12, 0, 0)
FUTURE = whitelist._format_timestamp(NOW + datetime.timedelta(days = 30))
PAST = whitelist._format_timestamp(NOW - datetime.timedelta(days = 1))


def rule(rule_type, value, **extra):
	payload = {'type': rule_type, 'value': value, 'expires_at': FUTURE}
	payload.update(extra)
	return whitelist.normalize_rule(payload, NOW)


def ruleset(*rules, **kwargs):
	return whitelist.Ruleset(rules = list(rules), **kwargs)


class DomainNormalization(unittest.TestCase):

	def test_lowercases_and_drops_the_absolute_dot(self):
		self.assertEqual(whitelist.normalize_domain('  Empresa.COM.br.  '), 'empresa.com.br')

	def test_converts_a_non_ascii_label_to_punycode(self):
		# O ponto de guardar sempre punycode: o cirílico "р" vira algo que não se
		# confunde mais com o "p" latino
		self.assertEqual(whitelist.normalize_domain('рaypal.com'), 'xn--aypal-uye.com')
		self.assertNotEqual(whitelist.normalize_domain('рaypal.com'), 'paypal.com')

	def test_refuses_anything_that_is_not_a_bare_domain(self):
		for value in ('http://empresa.com', 'empresa.com/rh', 'a@empresa.com',
				'empresa .com', 'empresa..com', '-empresa.com', ''):
			self.assertEqual(whitelist.normalize_domain(value), '', value)


class AddressNormalization(unittest.TestCase):

	def test_lowercases_both_sides(self):
		self.assertEqual(whitelist.normalize_address('Faturamento@Empresa.COM.br'), 'faturamento@empresa.com.br')

	def test_keeps_the_sub_addressing_tag(self):
		# Apagar o rótulo faria a regra `nf@` valer para `nf+qualquer-coisa@`
		self.assertEqual(whitelist.normalize_address('nf+jan@empresa.com'), 'nf+jan@empresa.com')
		self.assertNotEqual(whitelist.normalize_address('nf+jan@empresa.com'), 'nf@empresa.com')

	def test_refuses_a_malformed_address(self):
		for value in ('faturamento', '@empresa.com', 'faturamento@', 'a b@empresa.com', ''):
			self.assertEqual(whitelist.normalize_address(value), '', value)


class HashNormalization(unittest.TestCase):

	def test_accepts_sha256_in_any_case(self):
		digest = 'A' * 64
		self.assertEqual(whitelist.normalize_hash(digest), 'a' * 64)

	def test_refuses_md5_and_sha1(self):
		self.assertEqual(whitelist.normalize_hash('a' * 32), '')
		self.assertEqual(whitelist.normalize_hash('a' * 40), '')


class UrlNormalization(unittest.TestCase):

	def test_the_authoritative_host_is_after_the_last_at(self):
		# `http://exemplo.com@evil.com` visita evil.com. Casar contra o texto cru
		# é o que faz uma whitelist liberar exatamente o phishing
		host, _target = whitelist.normalize_url('http://exemplo.com@evil.com/entrar')
		self.assertEqual(host, 'evil.com')

	def test_the_fragment_never_reaches_the_server(self):
		host, target = whitelist.normalize_url('http://evil.com/x#exemplo.com')
		self.assertEqual(host, 'evil.com')
		self.assertNotIn('exemplo.com', target)

	def test_resolves_percent_encoding_and_dot_segments(self):
		_host, target = whitelist.normalize_url('http://exemplo.com/rh/../%61dmin/painel')
		self.assertEqual(target, '/admin/painel')

	def test_drops_the_port_and_accepts_a_url_without_scheme(self):
		self.assertEqual(whitelist.normalize_url('exemplo.com:443/rh')[0], 'exemplo.com')
		self.assertEqual(whitelist.normalize_url('exemplo.com/rh')[0], 'exemplo.com')

	def test_keeps_the_query_because_that_is_where_open_redirect_lives(self):
		_host, target = whitelist.normalize_url('https://exemplo.com/url?q=http://evil.com')
		self.assertEqual(target, '/url?q=http://evil.com')

	def test_refuses_a_url_past_the_length_cap(self):
		self.assertEqual(whitelist.normalize_url('http://exemplo.com/' + 'a' * 4000), (None, None))


class DomainMatching(unittest.TestCase):

	def test_the_bare_form_covers_the_domain_and_everything_under_it(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'empresa.com'))
		self.assertTrue(rules.match_domain('empresa.com', NOW))
		self.assertTrue(rules.match_domain('nf.empresa.com', NOW))
		self.assertTrue(rules.match_domain('a.b.empresa.com', NOW))

	def test_the_wildcard_form_excludes_the_apex(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, '*.empresa.com'))
		self.assertFalse(rules.match_domain('empresa.com', NOW))
		self.assertTrue(rules.match_domain('nf.empresa.com', NOW))

	def test_a_lookalike_label_does_not_match(self):
		# O erro de `endswith` sem ponto e o de `in`: os dois liberariam estes
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'empresa.com'))
		for impostor in ('evil-empresa.com', 'empresa.com.atacante.net',
				'naoempresa.com', 'empresa.com.br'):
			self.assertFalse(rules.match_domain(impostor, NOW), impostor)

	def test_a_specific_subdomain_covers_only_its_own_branch(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'nf.empresa.com'))
		self.assertTrue(rules.match_domain('nf.empresa.com', NOW))
		self.assertTrue(rules.match_domain('a.nf.empresa.com', NOW))
		self.assertFalse(rules.match_domain('empresa.com', NOW))
		self.assertFalse(rules.match_domain('rh.empresa.com', NOW))


class SenderMatching(unittest.TestCase):

	def setUp(self):
		self.rules = ruleset(rule(whitelist.TYPE_SENDER, 'faturamento@empresa.com.br'))

	def test_matches_an_authenticated_sender(self):
		match = self.rules.match_sender('Faturamento@Empresa.com.br', AUTHENTICATED, '', NOW)
		self.assertTrue(match)

	def test_an_unauthenticated_sender_never_matches(self):
		# É a trava central: sem DMARC/DKIM alinhado, qualquer um escreve este
		# From. A confiança vale para o domínio autenticado, não para o texto
		match = self.rules.match_sender('faturamento@empresa.com.br', NOT_AUTHENTICATED, '', NOW)
		self.assertFalse(match)
		self.assertIn('não está autenticado', match.reason)

	def test_a_reply_to_pointing_elsewhere_breaks_the_trust(self):
		match = self.rules.match_sender('faturamento@empresa.com.br', AUTHENTICATED,
			'financeiro@gmail.com', NOW)
		self.assertFalse(match)
		self.assertIn('Reply-To', match.reason)

	def test_a_reply_to_in_the_same_domain_is_fine(self):
		self.assertTrue(self.rules.match_sender('faturamento@empresa.com.br', AUTHENTICATED,
			'nf@empresa.com.br', NOW))
		self.assertTrue(self.rules.match_sender('faturamento@empresa.com.br', AUTHENTICATED,
			'nf@cobranca.empresa.com.br', NOW))

	def test_the_alignment_check_can_be_turned_off_per_rule(self):
		relaxed = ruleset(rule(whitelist.TYPE_SENDER, 'faturamento@empresa.com.br',
			require_reply_to_alignment = False))
		self.assertTrue(relaxed.match_sender('faturamento@empresa.com.br', AUTHENTICATED,
			'financeiro@gmail.com', NOW))

	def test_a_different_address_at_the_same_domain_does_not_match(self):
		# Confiança é por caixa: uma conta comprometida em outro canto do
		# domínio não vem junto
		self.assertFalse(self.rules.match_sender('rh@empresa.com.br', AUTHENTICATED, '', NOW))


class UrlMatching(unittest.TestCase):

	def test_prefix_mode_matches_below_the_path(self):
		rules = ruleset(rule(whitelist.TYPE_URL, '', mode = whitelist.URL_MODE_PREFIX,
			host_pattern = 'intranet.empresa.com', path_pattern = '/rh/'))
		self.assertTrue(rules.match_url('https://intranet.empresa.com/rh/ferias', NOW))
		self.assertFalse(rules.match_url('https://intranet.empresa.com/financeiro', NOW))

	def test_regex_mode_is_fullmatch_not_search(self):
		# Com re.search, `paypal\.com` casaria dentro de
		# `evil.com/?ref=paypal.com`. É o erro que o v1 tinha
		rules = ruleset(rule(whitelist.TYPE_URL, '', mode = whitelist.URL_MODE_REGEX,
			host_pattern = r'paypal\.com', path_pattern = r'/.*'))
		self.assertTrue(rules.match_url('https://paypal.com/conta', NOW))
		self.assertFalse(rules.match_url('https://evil.com/?ref=paypal.com', NOW))
		self.assertFalse(rules.match_url('https://paypal.com.evil.com/conta', NOW))

	def test_a_userinfo_prefix_does_not_borrow_the_trust(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'exemplo.com'))
		self.assertFalse(rules.match_url('http://exemplo.com@evil.com/entrar', NOW))

	def test_a_domain_rule_covers_every_url_of_that_domain(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'exemplo.com'))
		self.assertTrue(rules.match_url('https://www.exemplo.com/qualquer/coisa', NOW))


class IpMatching(unittest.TestCase):

	def test_a_bare_address_matches_itself_only(self):
		rules = ruleset(rule(whitelist.TYPE_IP, '93.184.216.34'))
		self.assertTrue(rules.match_ip('93.184.216.34', NOW))
		self.assertFalse(rules.match_ip('93.184.216.35', NOW))

	def test_a_cidr_matches_everything_inside_it(self):
		rules = ruleset(rule(whitelist.TYPE_IP, '93.184.216.0/24'))
		self.assertTrue(rules.match_ip('93.184.216.1', NOW))
		self.assertTrue(rules.match_ip('93.184.216.254', NOW))
		self.assertFalse(rules.match_ip('93.184.217.1', NOW))

	def test_the_host_bits_of_a_cidr_are_normalized_away(self):
		# Quem digita 93.184.216.7/24 quis dizer a rede, e recusar seria
		# pedantismo; guardar as duas formas seria regra duplicada
		self.assertEqual(whitelist.normalize_ip('93.184.216.7/24'), '93.184.216.0/24')

	def test_a_v6_rule_never_matches_a_v4_address(self):
		rules = ruleset(rule(whitelist.TYPE_IP, '2606:2800:220::/48'))
		self.assertTrue(rules.match_ip('2606:2800:220::1', NOW))
		self.assertFalse(rules.match_ip('93.184.216.34', NOW))


class IpValidation(unittest.TestCase):

	def check(self, value):
		return whitelist.validate_rule({'type': whitelist.TYPE_IP, 'value': value,
			'expires_at': FUTURE}, now = NOW)

	def test_a_routable_address_or_range_is_accepted(self):
		for value in ('8.8.8.8', '93.184.216.0/24', '2606:2800:220::/48'):
			self.assertEqual(self.check(value)[0], [], value)

	def test_a_non_routable_address_is_refused_as_pointless(self):
		# Ja e descartado na extracao; a regra so ocuparia a tela sugerindo uma
		# protecao que nao existe
		for value in ('192.168.1.10', '10.0.0.0/8', '127.0.0.1', '169.254.1.1'):
			errors = self.check(value)[0]
			self.assertTrue(errors, value)
			self.assertIn('já são ignorados', errors[0])

	def test_a_range_wider_than_the_floor_is_refused(self):
		errors = self.check('93.0.0.0/8')[0]
		self.assertTrue(any('/16' in error for error in errors))

	def test_a_wide_but_allowed_range_only_warns(self):
		errors, warnings = self.check('93.184.0.0/18')
		self.assertEqual(errors, [])
		self.assertTrue(warnings)
		self.assertIn('16384', warnings[0])

	def test_garbage_is_refused(self):
		self.assertTrue(self.check('nao-e-ip')[0])


class UrlPatternTester(unittest.TestCase):
	"""O testador é a peça que precisa ser confiável acima de todas.

	Ele existe para responder "essa regra vai ser efetiva?" antes de a regra
	valer. Se ele divergir do casamento real, ele produz confiança onde não
	deveria haver — o que é pior do que não existir. Por isso o que estes testes
	prendem é que ele usa o MESMO caminho da análise, e que as variantes de
	evasão realmente denunciam um padrão frouxo.
	"""

	def test_the_probe_is_the_same_matcher_the_analysis_uses(self):
		probe = whitelist.probe_ruleset(r'nf\.empresa\.com', r'/boleto/.*')
		stored = ruleset(rule(whitelist.TYPE_URL, '', mode = whitelist.URL_MODE_REGEX,
			host_pattern = r'nf\.empresa\.com', path_pattern = r'/boleto/.*'))
		for url in ('https://nf.empresa.com/boleto/1', 'https://nf.empresa.com/admin',
				'http://nf.empresa.com@evil.com/boleto/1', 'https://evil.com/?x=nf.empresa.com'):
			self.assertEqual(bool(probe.match_url(url)), bool(stored.match_url(url, NOW)), url)

	def test_a_tight_pattern_closes_every_evasion(self):
		probe = whitelist.probe_ruleset(r'nf\.empresa\.com', r'/boleto/.*')
		for variant in whitelist.evasion_variants('https://nf.empresa.com/boleto/1'):
			self.assertFalse(probe.match_url(variant['url']), variant['label'])

	def test_a_loose_pattern_is_denounced_by_a_variant(self):
		# `.*empresa\.com.*` é o que alguém escreve achando que está liberando a
		# empresa. Ele aceita `nf.empresa.com.evil-exemplo.test`, e é exatamente
		# isso que o testador precisa mostrar antes de a regra existir
		probe = whitelist.probe_ruleset(r'.*empresa\.com.*', r'.*')
		leaked = [variant for variant in whitelist.evasion_variants('https://nf.empresa.com/boleto/1')
			if probe.match_url(variant['url'])]
		self.assertTrue(leaked)

	def test_the_variants_are_built_from_the_normalized_url(self):
		variants = whitelist.evasion_variants('HTTPS://NF.Empresa.com:443/boleto/../boleto/1')
		self.assertTrue(variants)
		for variant in variants:
			self.assertIn('nf.empresa.com', variant['url'])
			self.assertIn(whitelist.EVASION_HOST, variant['url'])

	def test_an_unreadable_url_yields_no_variants(self):
		self.assertEqual(whitelist.evasion_variants('nao é uma url'), [])


class UrlPatternSuggestion(unittest.TestCase):
	"""O sugeridor existe para que a regex não precise ser escrita à mão.

	Os dois erros que este módulo passa a vida barrando nascem na digitação: o
	ponto sem escapar, que faz `empresa.com.br` também aceitar `empresaXcomYbr`,
	e o `.*` frouxo na ponta, que deixa o host virar sufixo de outro domínio.
	Uma sugestão que cometesse qualquer um dos dois seria pior do que nenhuma —
	ela vem com a autoridade do sistema.
	"""

	CASE = ['https://nf.empresa.com.br/relatorios/2026',
		'https://rh.empresa.com.br/relatorios/agosto']

	def suggest(self, urls = None):
		return whitelist.suggest_url_patterns(urls or self.CASE)

	def test_it_derives_the_pattern_a_person_would_have_written(self):
		suggestions, hosts, problems = self.suggest()
		self.assertEqual(problems, [])
		self.assertEqual(hosts, ['nf.empresa.com.br', 'rh.empresa.com.br'])
		for suggestion in suggestions:
			self.assertEqual(suggestion['host_pattern'], r'(nf|rh)\.empresa\.com\.br')

	def test_every_suggestion_covers_every_pasted_url(self):
		for suggestion in self.suggest()[0]:
			probe = whitelist.probe_ruleset(suggestion['host_pattern'], suggestion['path_pattern'])
			for url in self.CASE:
				self.assertTrue(probe.match_url(url), (suggestion['level'], url))

	def test_no_suggestion_leaks_an_evasion(self):
		# A sugestão vem com a autoridade do sistema; se ela vazasse, o testador
		# ao lado estaria denunciando a própria recomendação
		for suggestion in self.suggest()[0]:
			probe = whitelist.probe_ruleset(suggestion['host_pattern'], suggestion['path_pattern'])
			for url in self.CASE:
				for variant in whitelist.evasion_variants(url):
					self.assertFalse(probe.match_url(variant['url']),
						(suggestion['level'], variant['label']))

	def test_every_suggestion_survives_the_normal_validation(self):
		# Oferecer um padrão que o botão Incluir recusaria seria um beco sem saída
		for suggestion in self.suggest()[0]:
			errors, _warnings = whitelist.validate_rule({
				'type': whitelist.TYPE_URL, 'mode': whitelist.URL_MODE_REGEX,
				'host_pattern': suggestion['host_pattern'],
				'path_pattern': suggestion['path_pattern'],
				'expires_at': FUTURE}, now = NOW)
			self.assertEqual(errors, [], suggestion['level'])

	def test_the_dots_are_always_escaped(self):
		for suggestion in self.suggest()[0]:
			self.assertNotIn('empresa.com', suggestion['host_pattern'])
			self.assertIn(r'empresa\.com', suggestion['host_pattern'])

	def test_the_strict_level_pins_the_exact_paths(self):
		strict = next(item for item in self.suggest()[0] if item['level'] == 'strict')
		probe = whitelist.probe_ruleset(strict['host_pattern'], strict['path_pattern'])
		self.assertTrue(probe.match_url('https://nf.empresa.com.br/relatorios/2026'))
		self.assertFalse(probe.match_url('https://nf.empresa.com.br/relatorios/2027'))

	def test_the_balanced_level_follows_what_changes(self):
		balanced = next(item for item in self.suggest()[0] if item['level'] == 'balanced')
		self.assertEqual(balanced['path_pattern'], re.escape('/relatorios/') + '.*')
		probe = whitelist.probe_ruleset(balanced['host_pattern'], balanced['path_pattern'])
		self.assertTrue(probe.match_url('https://nf.empresa.com.br/relatorios/2027/q1'))
		self.assertFalse(probe.match_url('https://nf.empresa.com.br/financeiro'))

	def test_the_broad_level_accepts_any_path(self):
		broad = next(item for item in self.suggest()[0] if item['level'] == 'broad')
		self.assertEqual(broad['path_pattern'], '')
		probe = whitelist.probe_ruleset(broad['host_pattern'], broad['path_pattern'])
		self.assertTrue(probe.match_url('https://nf.empresa.com.br/qualquer/coisa'))

	def test_a_single_url_still_yields_usable_levels(self):
		suggestions, _hosts, _problems = self.suggest(['https://portal.empresa.com/nf/1'])
		self.assertEqual({item['level'] for item in suggestions}, {'strict', 'balanced', 'broad'})
		for suggestion in suggestions:
			self.assertEqual(suggestion['host_pattern'], r'portal\.empresa\.com')

	def test_hosts_that_share_no_parent_are_alternated_whole(self):
		suggestions, _hosts, _problems = self.suggest(
			['https://portal.acme.com/a', 'https://intranet.outra.com.br/a'])
		pattern = suggestions[0]['host_pattern']
		probe = whitelist.probe_ruleset(pattern, '')
		self.assertTrue(probe.match_url('https://portal.acme.com/x'))
		self.assertTrue(probe.match_url('https://intranet.outra.com.br/x'))
		# Nunca mais amplo do que o que foi colado
		self.assertFalse(probe.match_url('https://outro.acme.com/x'))

	def test_a_common_prefix_is_cut_at_the_slash(self):
		# `/relatorios` e `/relatos` não devem virar o prefixo `/relat`: um pedaço
		# de nome de pasta não descreve nada que alguém queira liberar
		suggestions, _hosts, _problems = self.suggest(
			['https://x.empresa.com/relatorios/a', 'https://x.empresa.com/relatos/b'])
		levels = {item['level'] for item in suggestions}
		self.assertNotIn('balanced', levels)

	def test_an_unreadable_url_is_reported_and_the_rest_still_works(self):
		suggestions, hosts, problems = self.suggest(
			['nao é uma url', 'https://nf.empresa.com.br/relatorios/2026'])
		self.assertTrue(problems)
		self.assertEqual(hosts, ['nf.empresa.com.br'])
		self.assertTrue(suggestions)

	def test_nothing_readable_yields_no_suggestion(self):
		suggestions, hosts, problems = self.suggest(['nao é uma url'])
		self.assertEqual(suggestions, [])
		self.assertEqual(hosts, [])
		self.assertTrue(problems)

	def test_every_level_explains_itself(self):
		for suggestion in self.suggest()[0]:
			self.assertTrue(suggestion['why'])
			self.assertTrue(suggestion['scope'])


class UrlRuleValidation(unittest.TestCase):

	def check(self, host_pattern, path_pattern = ''):
		return whitelist.validate_rule({'type': whitelist.TYPE_URL,
			'mode': whitelist.URL_MODE_REGEX, 'host_pattern': host_pattern,
			'path_pattern': path_pattern, 'expires_at': FUTURE}, now = NOW)

	def test_a_specific_pattern_passes_clean(self):
		errors, warnings = self.check(r'(nf|rh)\.empresa\.com\.br', r'/boleto/.*')
		self.assertEqual(errors, [])
		self.assertEqual(warnings, [])

	def test_an_empty_path_means_any_path(self):
		self.assertEqual(self.check(r'nf\.empresa\.com')[0], [])
		rules = ruleset(rule(whitelist.TYPE_URL, '', mode = whitelist.URL_MODE_REGEX,
			host_pattern = r'nf\.empresa\.com', path_pattern = ''))
		self.assertTrue(rules.match_url('https://nf.empresa.com/qualquer/coisa', NOW))

	def test_a_host_pattern_that_accepts_any_tenant_of_a_public_suffix_warns(self):
		# A aba de domínio recusa *.sharepoint.com; sem esta checagem o mesmo
		# alcance sairia por aqui e a trava viraria decoração
		errors, warnings = self.check(r'.*\.sharepoint\.com')
		self.assertEqual(errors, [])
		self.assertTrue(warnings)
		self.assertIn('sharepoint.com', warnings[0])

	def test_a_specific_tenant_of_the_same_suffix_passes(self):
		self.assertEqual(self.check(r'contoso\.sharepoint\.com')[1], [])

	def test_an_explosive_pattern_is_still_refused(self):
		self.assertTrue(any('retrocesso' in error for error in self.check(r'(a+)+')[0]))

	def test_the_host_pattern_is_required(self):
		self.assertTrue(self.check('', r'/x')[0])


class HashMatching(unittest.TestCase):

	def test_matches_regardless_of_case(self):
		digest = 'b' * 64
		rules = ruleset(rule(whitelist.TYPE_HASH, digest.upper()))
		self.assertTrue(rules.match_hash(digest, NOW))


class EffectiveState(unittest.TestCase):

	def test_an_expired_rule_stops_matching_without_any_cleanup_job(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'empresa.com', expires_at = PAST))
		self.assertFalse(rules.match_domain('empresa.com', NOW))

	def test_a_permanent_rule_keeps_matching(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'empresa.com', expires_at = None,
			permanent_reason = 'domínio interno da holding'))
		self.assertTrue(rules.match_domain('empresa.com', NOW + datetime.timedelta(days = 4000)))

	def test_a_disabled_rule_never_matches(self):
		rules = ruleset(rule(whitelist.TYPE_DOMAIN, 'empresa.com', enabled = False))
		self.assertFalse(rules.match_domain('empresa.com', NOW))

	def test_a_suspended_rule_never_matches(self):
		suspended = rule(whitelist.TYPE_SENDER, 'faturamento@empresa.com.br')
		rules = ruleset(suspended, suspended_ids = [suspended['id']])
		self.assertFalse(rules.match_sender('faturamento@empresa.com.br', AUTHENTICATED, '', NOW))


class Validation(unittest.TestCase):

	def errors(self, payload, **kwargs):
		return whitelist.validate_rule(payload, now = NOW, **kwargs)[0]

	def warnings(self, payload, **kwargs):
		return whitelist.validate_rule(payload, now = NOW, **kwargs)[1]

	def test_a_homoglyph_is_refused_with_its_punycode_shown(self):
		errors = self.errors({'type': whitelist.TYPE_DOMAIN, 'value': 'рaypal.com',
			'expires_at': FUTURE})
		self.assertTrue(errors)
		self.assertIn('xn--aypal-uye.com', errors[0])

	def test_a_public_suffix_is_refused(self):
		for value in ('com.br', '*.sharepoint.com', 'ngrok-free.app', '*.web.app'):
			self.assertTrue(self.errors({'type': whitelist.TYPE_DOMAIN, 'value': value,
				'expires_at': FUTURE}), value)

	def test_being_the_parent_of_a_multi_tenant_suffix_only_warns(self):
		payload = {'type': whitelist.TYPE_DOMAIN, 'value': 'google.com', 'expires_at': FUTURE}
		self.assertEqual(self.errors(payload), [])
		self.assertTrue(self.warnings(payload))
		self.assertIn('sites.google.com', self.warnings(payload)[0])

	def test_md5_and_sha1_are_named_in_the_refusal(self):
		errors = self.errors({'type': whitelist.TYPE_HASH, 'value': 'a' * 32, 'expires_at': FUTURE})
		self.assertTrue(any('SHA-256' in error for error in errors))

	def test_permanent_needs_the_role_and_a_written_justification(self):
		payload = {'type': whitelist.TYPE_DOMAIN, 'value': 'empresa.com', 'expires_at': None,
			'permanent_reason': 'domínio interno da holding'}
		self.assertTrue(any('global_admin' in error for error in self.errors(payload)))
		self.assertEqual(self.errors(payload, allow_permanent = True), [])

		short = dict(payload, permanent_reason = 'interno')
		self.assertTrue(any('justificativa' in error for error in
			self.errors(short, allow_permanent = True)))

	def test_an_expiry_in_the_past_or_too_far_ahead_is_refused(self):
		for expires_at in (PAST, whitelist._format_timestamp(NOW + datetime.timedelta(days = 4000))):
			self.assertTrue(self.errors({'type': whitelist.TYPE_DOMAIN, 'value': 'empresa.com',
				'expires_at': expires_at}), expires_at)

	def test_a_url_prefix_rule_must_carry_a_path(self):
		# Sem caminho a regra libera o host inteiro, que é uma regra de domínio
		# — e é lá que estão as travas de sufixo público
		errors = self.errors({'type': whitelist.TYPE_URL, 'mode': whitelist.URL_MODE_PREFIX,
			'host_pattern': 'exemplo.com', 'path_pattern': '', 'expires_at': FUTURE})
		self.assertTrue(any('regra de domínio' in error for error in errors))

	def test_an_explosive_regex_is_refused_at_save_time(self):
		errors = self.errors({'type': whitelist.TYPE_URL, 'mode': whitelist.URL_MODE_REGEX,
			'host_pattern': r'(a+)+', 'path_pattern': r'/.*', 'expires_at': FUTURE})
		self.assertTrue(any('retrocesso explosivo' in error for error in errors))

	def test_a_broken_regex_is_refused(self):
		errors = self.errors({'type': whitelist.TYPE_URL, 'mode': whitelist.URL_MODE_REGEX,
			'host_pattern': r'(exemplo', 'path_pattern': '', 'expires_at': FUTURE})
		self.assertTrue(any('inválida' in error for error in errors))


class Effects(unittest.TestCase):

	def test_only_sender_downgrades_a_verdict(self):
		self.assertEqual(whitelist.effect_of({'type': whitelist.TYPE_SENDER}), whitelist.EFFECT_DOWNGRADE)
		for rule_type in (whitelist.TYPE_DOMAIN, whitelist.TYPE_URL, whitelist.TYPE_HASH):
			self.assertEqual(whitelist.effect_of({'type': rule_type}), whitelist.EFFECT_SUPPRESS)


class Persistence(unittest.TestCase):

	def setUp(self):
		handle, self.path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)

	def tearDown(self):
		for path in (self.path, self.path + '.tmp'):
			if os.path.isfile(path):
				os.remove(path)

	def test_save_and_load_round_trip(self):
		whitelist.save([rule(whitelist.TYPE_DOMAIN, 'empresa.com')], self.path)
		rules = whitelist.load(self.path)
		self.assertEqual(rules.error, '')
		self.assertTrue(rules.match_domain('nf.empresa.com', NOW))

	def test_a_v1_file_loads_as_empty_instead_of_being_misread(self):
		with open(self.path, 'w', encoding = 'utf-8') as handle:
			json.dump({'exactMatching': {'domain': ['empresa.com']}}, handle)
		rules = whitelist.load(self.path)
		self.assertTrue(rules.error)
		self.assertFalse(rules.match_domain('empresa.com', NOW))

	def test_a_corrupt_file_fails_closed_without_raising(self):
		with open(self.path, 'w', encoding = 'utf-8') as handle:
			handle.write('{"version": 2, "rules": [')
		rules = whitelist.load(self.path)
		self.assertTrue(rules.error)
		self.assertFalse(rules.match_domain('empresa.com', NOW))

	def test_a_missing_file_fails_closed(self):
		rules = whitelist.load(os.path.join(tempfile.gettempdir(), 'nao-existe-bluephish.json'))
		self.assertTrue(rules.error)
		self.assertFalse(rules.match_domain('empresa.com', NOW))

	def test_saving_falls_back_when_the_filesystem_refuses_the_rename(self):
		"""O caso do container: whitelist.json e bind mount de arquivo unico.

		os.replace sobre o ponto de montagem devolve EBUSY, e sem o caminho de
		reserva toda gravacao falha em silencio — a regra some da tela e volta no
		refresh seguinte, que foi exatamente o que aconteceu em producao.
		"""
		real_replace = os.replace
		calls = []

		def refusing_replace(source, target):
			calls.append((source, target))
			raise OSError(16, 'Device or resource busy')

		os.replace = refusing_replace
		try:
			whitelist.save([rule(whitelist.TYPE_DOMAIN, 'empresa.com')], self.path)
		finally:
			os.replace = real_replace

		self.assertTrue(calls, 'o caminho atomico deve ser tentado primeiro')
		loaded = whitelist.load(self.path)
		self.assertEqual(loaded.error, '')
		self.assertTrue(loaded.match_domain('empresa.com', NOW))
		# O temporario nao pode ficar para tras acumulando a cada gravacao
		self.assertFalse(os.path.isfile(self.path + '.tmp'))

	def test_saving_leaves_no_temporary_behind(self):
		whitelist.save([rule(whitelist.TYPE_DOMAIN, 'empresa.com')], self.path)
		self.assertFalse(os.path.isfile(self.path + '.tmp'))


V1_DOCUMENT = {
	'exactMatching': {
		'mail': ['Faturamento@Empresa.com.br'],
		'ip': ['8.8.8.8', '192.168.0.1'],
		'url': ['https://intranet.empresa.com/rh/ferias', 'https://portal.empresa.com/'],
		'domain': ['bit.ly', 'tinyurl'],
		'filename': ['assinatura.png'],
		'filetype': ['application/pdf'],
		'hash': ['c' * 64, 'd' * 32],
	},
	'regexMatching': {
		'mail': [r'.*@empresa\.com'],
		'ip': [],
		'domain': [r'.*\.empresa\.com'],
		'url': [r'paypal\.com'],
		'filename': [],
	},
	'domainsInSubdomains': ['hackerone.com', 'parceiro-local.com.br'],
	'domainsInURLs': ['hackerone.com'],
	'domainsInEmails': ['empresa.com.br'],
}

SHIPPED = {'hackerone.com', 'bit.ly', 'tinyurl'}


class Migration(unittest.TestCase):

	def setUp(self):
		self.rules, self.report = whitelist_migration.migrate_document(V1_DOCUMENT, SHIPPED, NOW)
		self.by_value = {(item['type'], item['value']): item for item in self.rules}

	def test_domain_lists_become_enabled_domain_rules(self):
		entry = self.by_value[(whitelist.TYPE_DOMAIN, 'hackerone.com')]
		self.assertTrue(entry['enabled'])

	def test_the_same_domain_in_two_v1_lists_produces_one_rule(self):
		matches = [item for item in self.rules
			if item['type'] == whitelist.TYPE_DOMAIN and item['value'] == 'hackerone.com']
		self.assertEqual(len(matches), 1)

	def test_a_shipped_entry_becomes_permanent_and_an_operator_entry_gets_180_days(self):
		self.assertIsNone(self.by_value[(whitelist.TYPE_DOMAIN, 'hackerone.com')]['expires_at'])
		operator = self.by_value[(whitelist.TYPE_DOMAIN, 'parceiro-local.com.br')]
		self.assertEqual(operator['expires_at'], whitelist.default_expiry(NOW))

	def test_an_address_becomes_a_disabled_sender_rule(self):
		# Ligar sozinho transformaria uma entrada de conveniência do v1 em
		# concessão de confiança
		entry = self.by_value[(whitelist.TYPE_SENDER, 'faturamento@empresa.com.br')]
		self.assertFalse(entry['enabled'])

	def test_a_url_with_a_path_becomes_an_escaped_regex_rule(self):
		# Escapada, e não prefixo: o modo prefixo saiu da interface, e a migração
		# não pode ser a última coisa a produzir regra que ninguém edita na tela
		entry = next(item for item in self.rules if item['type'] == whitelist.TYPE_URL)
		self.assertEqual(entry['mode'], whitelist.URL_MODE_REGEX)
		probe = whitelist.Ruleset(rules = [entry])
		self.assertTrue(probe.match_url('https://intranet.empresa.com/rh/ferias', NOW))
		self.assertTrue(probe.match_url('https://intranet.empresa.com/rh/ferias/2026', NOW))
		self.assertFalse(probe.match_url('https://intranet.empresa.com/financeiro', NOW))

	def test_a_url_without_a_path_becomes_a_domain_rule(self):
		self.assertIn((whitelist.TYPE_DOMAIN, 'portal.empresa.com'), self.by_value)

	def test_a_migrated_url_rule_is_editable_in_the_interface(self):
		# Toda regra de URL criada pela migração precisa passar na mesma validação
		# da criação manual, senão ela existe mas não dá para salvar de novo
		for entry in self.rules:
			if entry['type'] != whitelist.TYPE_URL:
				continue
			errors, _warnings = whitelist.validate_rule(dict(entry, expires_at = FUTURE), now = NOW)
			self.assertEqual(errors, [], entry)

	def test_every_v1_regex_is_reported_instead_of_converted(self):
		sources = {item['source'] for item in self.report.needs_rewrite}
		self.assertEqual(sources, {'regexMatching.mail', 'regexMatching.domain',
			'regexMatching.url', 'domainsInEmails'})
		# As regex do v1 não viram regra nenhuma: a única regra de URL criada é a
		# que veio de `exactMatching.url`, e o padrão dela é literal escapado
		url_rules = [item for item in self.rules if item['type'] == whitelist.TYPE_URL]
		self.assertEqual(len(url_rules), 1)
		self.assertNotIn('paypal', url_rules[0]['host_pattern'])

	def test_the_types_that_left_the_model_are_dropped_with_a_reason(self):
		dropped = {item['value'] for item in self.report.dropped}
		self.assertIn('application/pdf', dropped)
		self.assertIn('assinatura.png', dropped)

	def test_a_routable_ip_becomes_a_rule_and_a_private_one_is_dropped(self):
		self.assertIn((whitelist.TYPE_IP, '8.8.8.8/32'), self.by_value)
		dropped = {item['value']: item['why'] for item in self.report.dropped}
		self.assertIn('192.168.0.1', dropped)
		self.assertIn('não roteável', dropped['192.168.0.1'])

	def test_a_non_sha256_hash_is_dropped_and_the_sha256_survives(self):
		self.assertIn((whitelist.TYPE_HASH, 'c' * 64), self.by_value)
		self.assertIn('d' * 32, {item['value'] for item in self.report.dropped})

	def test_a_domain_without_a_tld_is_dropped_as_dead(self):
		# `tinyurl` está assim na lista de fábrica e nunca casou com nada no v1
		self.assertIn('tinyurl', {item['value'] for item in self.report.dropped})

	def test_the_result_survives_a_save_and_load(self):
		handle, path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)
		try:
			whitelist.save(self.rules, path)
			loaded = whitelist.load(path)
			self.assertEqual(loaded.error, '')
			self.assertTrue(loaded.match_domain('hackerone.com', NOW))
			self.assertTrue(loaded.match_url('https://intranet.empresa.com/rh/ferias/2026', NOW))
			# O remetente migrado continua desligado depois da volta pelo disco
			self.assertFalse(loaded.match_sender('faturamento@empresa.com.br', AUTHENTICATED, '', NOW))
		finally:
			os.remove(path)

	def test_migrating_a_file_twice_is_a_no_op(self):
		handle, path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)
		try:
			with open(path, 'w', encoding = 'utf-8') as whitelist_file:
				json.dump(V1_DOCUMENT, whitelist_file)
			first = whitelist_migration.migrate_file(path, now = NOW, backup = False)
			self.assertTrue(first.migrated)
			second = whitelist_migration.migrate_file(path, now = NOW, backup = False)
			self.assertEqual(second.migrated, [])
		finally:
			for leftover in (path, path.replace('.json', '') + '.v1.backup.json'):
				if os.path.isfile(leftover):
					os.remove(leftover)


if __name__ == '__main__':
	unittest.main()
