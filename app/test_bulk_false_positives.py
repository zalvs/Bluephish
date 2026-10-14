"""Falsos positivos em correio legítimo de marca — medidos, e o que os fecha.

Nesta instalação, entre 2026-09-09 e 09-15, 21 mensagens de remetente
autenticado foram analisadas e 8 delas, todas legítimas, saíram acima de Safe:
Netflix, AliExpress (duas), Uber, LinkedIn, McDonald's, C6 e Strava — este como
Malicious. Cada classe de causa tem um teste aqui:

* **Marketing autenticado lido como engenharia social.** Com remetente
  autenticado e baixa por um clique assinada pelo próprio domínio (RFC 8058 §4),
  risco Medium da IA não eleva Safe. High continua elevando.
* **Listagem de host compartilhado no URLhaus.** Uma CDN com uma URL antiga de
  malware, toda offline, vale suspeito — não condenação.
* **Identificador de app com forma de domínio.** `com.linkedin.android`, do
  selo do Google Play, não vai a analisador de reputação.
* **Data lida no formato errado e persuasão comercial.** O prompt diz a data de
  hoje, que datas são DD/MM e o que é marketing.

Rodar com:  python -m unittest test_bulk_false_positives   (a partir de app/)
"""

import datetime
import unittest

import analyzers
import ioc_noise
import llm_analysis
import run_analysis
import spam_headers

import test_scoring_pipeline as pipeline


def c6_headers(**overrides):
	headers = {
		'Authentication-Results': ('mx.google.com; dkim=pass header.i=@mail.c6bank.com.br header.s=200608 '
			'header.b=abc; dkim=pass header.i=@s10.y.mc.salesforce.com header.s=fbldkim10; '
			'spf=pass smtp.mailfrom=bounce.mail.c6bank.com.br; dmarc=pass (p=REJECT) header.from=mail.c6bank.com.br'),
		'DKIM-Signature': ('v=1; a=rsa-sha256; c=relaxed/relaxed; s=200608; d=mail.c6bank.com.br; '
			'h=From:To:Subject:Date:List-Unsubscribe:List-Unsubscribe-Post:Message-ID; bh=x; b=y'),
		'List-Unsubscribe': '<https://click.mail.c6bank.com.br/subscription_center.aspx?jwt=abc>',
		'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'
	}
	headers.update(overrides)
	return [(name, value) for name, value in headers.items() if value is not None]


class OneClickSignedPerRfc8058(unittest.TestCase):

	def test_a_brand_signing_its_own_unsubscribe_headers(self):
		self.assertTrue(spam_headers.one_click_signed(c6_headers(), 'mail.c6bank.com.br'))

	def test_a_signature_that_leaves_the_post_header_out_does_not_count(self):
		headers = c6_headers(**{'DKIM-Signature': 'v=1; d=mail.c6bank.com.br; h=From:To:List-Unsubscribe; b=y'})
		self.assertFalse(spam_headers.one_click_signed(headers, 'mail.c6bank.com.br'))

	def test_only_the_platform_signing_is_not_the_sender_signing(self):
		# O ESP assinar com o próprio domínio prova que o ESP enviou, não que a marca enviou
		headers = c6_headers(**{'DKIM-Signature': ('v=1; d=s10.y.mc.salesforce.com; '
			'h=From:List-Unsubscribe:List-Unsubscribe-Post; b=y')})
		self.assertFalse(spam_headers.one_click_signed(headers, 'mail.c6bank.com.br'))

	def test_a_signature_the_receiver_did_not_validate_does_not_count(self):
		headers = c6_headers(**{'Authentication-Results': 'mx.google.com; dkim=fail header.i=@mail.c6bank.com.br; dmarc=fail'})
		self.assertFalse(spam_headers.one_click_signed(headers, 'mail.c6bank.com.br'))

	def test_a_forged_result_below_the_receivers_own_is_ignored(self):
		headers = [('Authentication-Results', 'mx.google.com; dkim=fail header.i=@golpe.example'),
			('Authentication-Results', 'forjado; dkim=pass header.i=@golpe.example'),
			('DKIM-Signature', 'v=1; d=golpe.example; h=From:List-Unsubscribe:List-Unsubscribe-Post; b=y'),
			('List-Unsubscribe', '<https://golpe.example/u>'),
			('List-Unsubscribe-Post', 'List-Unsubscribe=One-Click')]
		self.assertFalse(spam_headers.one_click_signed(headers, 'golpe.example'))

	def test_the_parent_domain_signing_a_subdomain_sender_counts(self):
		headers = c6_headers(**{
			'Authentication-Results': 'mx; dkim=pass header.i=noreply@linkedin.com; dmarc=pass',
			'DKIM-Signature': 'v=1; d=linkedin.com; h=From : List-Unsubscribe : List-Unsubscribe-Post; b=y'})
		self.assertTrue(spam_headers.one_click_signed(headers, 'mailb.linkedin.com'))

	def test_no_post_header_means_no_one_click(self):
		self.assertFalse(spam_headers.one_click_signed(c6_headers(**{'List-Unsubscribe-Post': None}), 'mail.c6bank.com.br'))


class MediumRiskOnSignedListMail(unittest.TestCase):
	"""A regra 3 da escalada, na forma de envio que só um remetente real monta."""

	SIGNED = {'value': 0.75, 'bulk': True, 'oneClick': True, 'oneClickSigned': True,
		'filtered': False, 'markers': [], 'scl': None, 'bcl': None}

	def setUp(self):
		self.harness = pipeline.TerminateAnalysisComScore('run_it')
		self.harness.setUp()

	def tearDown(self):
		self.harness.tearDown()

	def decide(self, risk, bulk, auth):
		trail = []
		llm = {'social_engineering_detected': True, 'risk_level': risk, 'tactics': ['reward'], 'justification': 'oferta'}
		verdict, _score = run_analysis.terminate_analysis(
			'Ganhe cashback', 'quem@denunciou.com', [pipeline.observable()],
			[pipeline.finding('virustotal', 'safe')], llm, self.harness.wsl,
			auth_results = auth, sent_log = [], observables_seen = None, bulk_signals = bulk, trail = trail)
		return verdict, trail

	def test_medium_on_authenticated_signed_list_mail_stays_safe(self):
		verdict, trail = self.decide('Medium', self.SIGNED, pipeline.AUTHENTICATED)
		self.assertEqual(verdict, 'Safe')
		self.assertTrue(any('RFC 8058' in step['reason'] for step in trail))

	def test_high_still_escalates_the_compromised_legitimate_sender(self):
		verdict, _trail = self.decide('High', self.SIGNED, pipeline.AUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')

	def test_unsigned_one_click_gets_no_relief(self):
		# Escrever o cabeçalho é de graça; assiná-lo com o domínio do From, não
		unsigned = dict(self.SIGNED, oneClickSigned = False)
		verdict, _trail = self.decide('Medium', unsigned, pipeline.AUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')

	def test_an_unauthenticated_sender_gets_no_relief(self):
		# DMARC fail com cabeçalho de lista é o formato do phishing que se fantasia
		# de newsletter: a regra 3 eleva, e o score (autenticação falha + massa + IA)
		# ainda pode levá-lo a Malicious — o que importa aqui é que o alívio não vale
		verdict, trail = self.decide('Medium', self.SIGNED, pipeline.UNAUTHENTICATED)
		self.assertIn(verdict, ('Suspicious', 'Malicious'))
		self.assertFalse(any('RFC 8058' in step['reason'] for step in trail))

	def test_plain_mail_is_unchanged(self):
		verdict, _trail = self.decide('Medium', None, pipeline.AUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')


class UrlhausHostListing(unittest.TestCase):

	def test_an_offline_listing_of_a_shared_host_is_suspicious(self):
		signal = {'listed': True, 'online': False, 'scope': 'host', 'threat': 'malware_download', 'count': 1}
		self.assertEqual(analyzers.level_for('urlhaus', {}, signal), 'suspicious')
		self.assertIn('todas já offline', analyzers.describe('urlhaus', signal))

	def test_a_host_still_serving_a_listed_url_convicts(self):
		self.assertEqual(analyzers.level_for('urlhaus', {}, {'listed': True, 'online': True, 'scope': 'host'}), 'malicious')

	def test_the_exact_url_convicts_even_offline(self):
		self.assertEqual(analyzers.level_for('urlhaus', {}, {'listed': True, 'online': False, 'scope': 'url'}), 'malicious')

	def test_a_payload_hash_convicts_even_offline(self):
		self.assertEqual(analyzers.level_for('urlhaus', {}, {'listed': True, 'online': False, 'scope': 'payload'}), 'malicious')


LINKEDIN_FOOTER = ('<a href="https://play.google.com/store/apps/details?id=com.linkedin.android&amp;'
	'referrer=st_appsite_flagship" target="_blank"><img src="badge.png"></a>')


class AppStorePackageIds(unittest.TestCase):

	def test_the_google_play_package_is_not_a_domain(self):
		self.assertTrue(ioc_noise.is_app_package_only('com.linkedin.android', LINKEDIN_FOOTER))

	def test_a_package_id_after_another_parameter_is_recognized(self):
		body = 'https://play.google.com/store/apps/details?hl=pt_BR&amp;id=br.com.c6bank.app'
		self.assertTrue(ioc_noise.is_app_package_only('br.com.c6bank.app', body))

	def test_the_market_scheme_is_recognized(self):
		self.assertTrue(ioc_noise.is_app_package_only('com.ubercab', 'market://details?id=com.ubercab'))

	def test_the_same_name_written_elsewhere_is_kept(self):
		body = LINKEDIN_FOOTER + ' Acesse também com.linkedin.android pelo navegador.'
		self.assertFalse(ioc_noise.is_app_package_only('com.linkedin.android', body))

	def test_a_redirect_target_in_a_query_string_is_kept(self):
		body = 'https://safelinks.example/?url=https://golpe.example/login&id=golpe.example'
		self.assertFalse(ioc_noise.is_app_package_only('golpe.example', body))

	def test_an_ordinary_domain_is_kept(self):
		self.assertFalse(ioc_noise.is_app_package_only('linkedin.com', LINKEDIN_FOOTER + ' linkedin.com'))


class PromptContextForLegitimateMail(unittest.TestCase):

	def test_the_model_knows_today_and_the_date_format(self):
		_, user, _ = llm_analysis.build_analysis_prompt('Pedido confirmado', 'Pedido de 07/09/2026')
		self.assertIn('Today is {0}'.format(datetime.datetime.utcnow().strftime('%Y-%m-%d')), user)
		self.assertIn('DD/MM/YYYY', user)

	def test_commercial_persuasion_is_named_on_the_trusted_side(self):
		_, user, guard = llm_analysis.build_analysis_prompt('Oferta', 'Só hoje: 70% off')
		context = user.index('Context for judging legitimate mail')
		self.assertLess(context, user.index('<<<BEGIN UNTRUSTED-EMAIL-{0}>>>'.format(guard['nonce'])))
		self.assertIn('Commercial persuasion in marketing', user)


if __name__ == '__main__':
	unittest.main()
