"""As invariantes da metodologia de score.

Três delas são a razão de o arquivo existir, e todas falhariam em silêncio:

1. **O score nunca rebaixa um veredito.** O piso é o próprio veredito, então um
   e-mail que os analisadores condenaram não pode aparecer na faixa de legítimo
   porque a média ponderada saiu baixa.
2. **`info` não dilui.** Um analisador que estourou a cota não participa da
   média. Se participasse, uma falha de infraestrutura viraria um veredito mais
   brando — que é exatamente o que o nível `info` existe para impedir (§7.6).
3. **Contexto sozinho não convicta.** Cabeçalho de massa e falha de autenticação
   descrevem a forma da mensagem. Sem nenhum analisador nem o LLM tendo
   participado, eles não alcançam a faixa de phishing.

Rodar com:  python -m unittest test_scoring   (a partir de app/)
"""

import unittest

import scoring


def report(analyzer_id, level, observable = 'exemplo.com'):
	return {'analyzer_id': analyzer_id, 'analyzer_name': analyzer_id,
		'analyzer_result': level, 'observable_name': observable,
		'observable_type': 'domain', 'observable_id': 'obs-0'}


def config(**overrides):
	base = {
		'mode': 'escalate',
		'weights': dict(scoring.DEFAULT_ANALYZER_WEIGHTS),
		'tiers': dict(scoring.DEFAULT_TIERS),
		'spamTriage': True,
		'spamSkipAnalysis': False
	}
	for factor in scoring.SIGNAL_FACTORS:
		base['weights'][factor['id']] = factor['weight']
	base.update(overrides)
	return base


AUTHENTICATED = {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass', 'aligned': True,
	'authenticated': True, 'raw': 'spf=pass'}
UNAUTHENTICATED = {'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail', 'aligned': False,
	'authenticated': False, 'raw': 'spf=fail'}
SEM_REGISTRO = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none', 'aligned': False,
	'authenticated': False, 'raw': ''}


class OVereditoEPisoDoScore(unittest.TestCase):

	def test_malicious_nunca_cai_abaixo_da_faixa_de_phishing(self):
		# Um acerto do VirusTotal contra cinco blocklists limpas: a média ponderada
		# sozinha ficaria abaixo de 50, e o e-mail já está condenado
		reports = [report('virustotal', 'malicious')]
		reports += [report(blocklist, 'safe') for blocklist in
			('safebrowsing', 'phishtank', 'openphish', 'urlhaus', 'otx')]
		result = scoring.compute('Malicious', reports, None, SEM_REGISTRO, None, config())
		self.assertGreaterEqual(result['score'], result['tiers']['phishing'])
		self.assertEqual(result['tier'], 'phishing')

	def test_suspicious_nunca_cai_abaixo_da_faixa_de_suspeito(self):
		result = scoring.compute('Suspicious', [report('otx', 'suspicious')], None,
			SEM_REGISTRO, None, config())
		self.assertGreaterEqual(result['score'], result['tiers']['suspicious'])

	def test_o_piso_fica_registrado_para_quem_conferir_a_conta(self):
		result = scoring.compute('Malicious', [report('otx', 'safe')], None,
			SEM_REGISTRO, None, config())
		self.assertEqual(result['floor'], 50.0)
		self.assertLess(result['raw'], result['score'])


class InfoNaoParticipaDaMedia(unittest.TestCase):

	def test_analisador_que_falhou_nao_dilui(self):
		com_falha = scoring.compute('Suspicious',
			[report('virustotal', 'suspicious'), report('abuseipdb', 'info')],
			None, SEM_REGISTRO, None, config())
		sozinho = scoring.compute('Suspicious', [report('virustotal', 'suspicious')],
			None, SEM_REGISTRO, None, config())
		self.assertEqual(com_falha['raw'], sozinho['raw'])

	def test_info_aparece_na_memoria_de_calculo_com_o_motivo(self):
		result = scoring.compute('Safe', [report('abuseipdb', 'info')], None,
			SEM_REGISTRO, None, config())
		linha = [f for f in result['factors'] if f['id'] == 'abuseipdb'][0]
		self.assertEqual(linha['participation'], 0.0)
		self.assertIn('info', linha['reason'])

	def test_so_info_nao_produz_conviccao(self):
		result = scoring.compute('Safe', [report('virustotal', 'info')], None,
			SEM_REGISTRO, None, config())
		self.assertFalse(result['convictionEvidence'])


class SafeParticipaComPesoReduzido(unittest.TestCase):
	"""'Não está na lista' é evidência fraca (§4.9): não pode arrastar como um acerto."""

	def test_uma_blocklist_limpa_pesa_menos_que_um_acerto(self):
		result = scoring.compute('Safe',
			[report('virustotal', 'suspicious'), report('urlhaus', 'safe')],
			None, SEM_REGISTRO, None, config())
		virustotal = [f for f in result['factors'] if f['id'] == 'virustotal'][0]
		urlhaus = [f for f in result['factors'] if f['id'] == 'urlhaus'][0]
		self.assertEqual(virustotal['participation'], 1.0)
		self.assertEqual(urlhaus['participation'], scoring.CLEAN_PARTICIPATION)

	def test_vale_para_qualquer_fator_zerado_e_nao_so_para_safe(self):
		# Sem isto, uma newsletter perfeitamente autenticada pontuava *menos* que
		# a mesma newsletter sem cabeçalho de autenticação nenhum
		result = scoring.compute('Safe', [], None, AUTHENTICATED, None, config())
		linha = [f for f in result['factors'] if f['id'] == 'signal:sender_auth'][0]
		self.assertEqual(linha['participation'], scoring.CLEAN_PARTICIPATION)


class ContextoSozinhoNaoConvicta(unittest.TestCase):

	def test_massa_e_falha_de_autenticacao_nao_alcancam_phishing(self):
		bulk = {'value': 1.0, 'bulk': True, 'oneClick': True, 'filtered': True,
			'markers': [{'id': 'x', 'label': 'x', 'rfc': 'x', 'weight': 1.0}],
			'scl': None, 'bcl': None}
		result = scoring.compute('Safe', [], None, UNAUTHENTICATED, bulk, config())
		self.assertTrue(result['capped'])
		self.assertLess(result['score'], result['tiers']['phishing'])
		self.assertNotEqual(result['tier'], 'phishing')

	def test_um_analisador_limpo_nao_levanta_o_teto(self):
		# O falso positivo que este teste fixa: DMARC fail + List-Unsubscribe
		# forjado + toda a reputacao limpa + LLM desligado fechava como malicioso.
		# DMARC quebra em encaminhamento e em lista de discussao o tempo todo —
		# esse e-mail pertence a fila da analista, nao ao arquivo de maliciosos
		bulk = {'value': 0.25, 'bulk': True, 'oneClick': False, 'filtered': False,
			'markers': [{'id': 'list_unsubscribe', 'label': 'descadastramento',
				'rfc': 'RFC 2369', 'weight': 0.25}], 'scl': None, 'bcl': None}
		result = scoring.compute('Safe', [report('virustotal', 'safe')], None,
			UNAUTHENTICATED, bulk, config())
		self.assertFalse(result['convictionEvidence'])
		self.assertTrue(result['capped'])
		self.assertLess(result['score'], result['tiers']['phishing'])

	def test_um_analisador_que_encontrou_algo_levanta_o_teto(self):
		result = scoring.compute('Safe', [report('virustotal', 'suspicious')], None,
			UNAUTHENTICATED, None, config())
		self.assertTrue(result['convictionEvidence'])
		self.assertFalse(result['capped'])

	def test_o_llm_que_nao_viu_nada_nao_levanta_o_teto(self):
		llm = {'social_engineering_detected': False, 'risk_level': 'Low'}
		result = scoring.compute('Safe', [], llm, UNAUTHENTICATED, None, config())
		self.assertFalse(result['convictionEvidence'])
		self.assertTrue(result['capped'])

	def test_com_o_llm_participando_o_teto_sai(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'Critical'}
		result = scoring.compute('Safe', [], llm, UNAUTHENTICATED, None, config())
		self.assertFalse(result['capped'])
		self.assertTrue(result['convictionEvidence'])


class NenhumFatorSubtrai(unittest.TestCase):

	def test_remetente_autenticado_contribui_zero_e_nao_negativo(self):
		result = scoring.compute('Safe', [], None, AUTHENTICATED, None, config())
		linha = [f for f in result['factors'] if f['id'] == 'signal:sender_auth'][0]
		self.assertEqual(linha['factor'], 0.0)
		self.assertGreaterEqual(linha['contribution'], 0.0)

	def test_sem_cabecalho_de_autenticacao_o_fator_nao_participa(self):
		result = scoring.compute('Safe', [], None, SEM_REGISTRO, None, config())
		linha = [f for f in result['factors'] if f['id'] == 'signal:sender_auth'][0]
		self.assertIsNone(linha['factor'])
		self.assertEqual(linha['participation'], 0.0)

	def test_dmarc_fail_pesa_mais_que_spf_indefinido(self):
		self.assertEqual(scoring.auth_factor(UNAUTHENTICATED), 1.0)
		self.assertEqual(scoring.auth_factor(AUTHENTICATED), 0.0)
		self.assertIsNone(scoring.auth_factor(SEM_REGISTRO))
		self.assertEqual(scoring.auth_factor(
			{'spf': 'neutral', 'dkim': 'none', 'dmarc': 'none', 'raw': 'spf=neutral'}), 0.35)


class UmAnalisadorEUmFator(unittest.TestCase):

	def test_o_pior_nivel_de_cada_analisador_e_o_que_vale(self):
		reports = [report('virustotal', 'safe', 'a.com'), report('virustotal', 'malicious', 'b.com'),
			report('virustotal', 'safe', 'c.com')]
		levels, _names = scoring.strongest_levels(reports)
		self.assertEqual(levels['virustotal'], 'malicious')

	def test_quarenta_urls_limpas_nao_afundam_um_anexo_malicioso(self):
		reports = [report('virustotal', 'safe', 'url{0}'.format(n)) for n in range(40)]
		reports.append(report('virustotal', 'malicious', 'anexo'))
		result = scoring.compute('Safe', reports, None, SEM_REGISTRO, None, config())
		self.assertEqual(result['raw'], 100.0)


class Faixas(unittest.TestCase):

	def test_fronteiras(self):
		tiers = dict(scoring.DEFAULT_TIERS)
		self.assertEqual(scoring.tier_for(50, tiers), 'phishing')
		self.assertEqual(scoring.tier_for(49.9, tiers), 'suspicious')
		self.assertEqual(scoring.tier_for(40, tiers), 'suspicious')
		self.assertEqual(scoring.tier_for(39.9, tiers), 'legitimate')
		self.assertEqual(scoring.tier_for(0, tiers), 'legitimate')


class EscaladaSoSobe(unittest.TestCase):

	def test_faixa_de_phishing_eleva_safe_a_malicious(self):
		result = {'mode': 'escalate', 'tier': 'phishing', 'score': 72.0,
			'tiers': dict(scoring.DEFAULT_TIERS), 'label': 'phishing'}
		verdict, reason = scoring.verdict_after('Safe', result, SEM_REGISTRO)
		self.assertEqual(verdict, 'Malicious')
		self.assertIn('72.0', reason)

	def test_remetente_autenticado_nao_e_fechado_como_malicioso_pelo_score(self):
		# Mesmo resguardo da regra 1 da escalada do LLM (§1.2): o que virou
		# marketing legítimo de marca real em veredito malicioso
		result = {'mode': 'escalate', 'tier': 'phishing', 'score': 72.0,
			'tiers': dict(scoring.DEFAULT_TIERS), 'label': 'phishing'}
		verdict, reason = scoring.verdict_after('Safe', result, AUTHENTICATED)
		self.assertEqual(verdict, 'Suspicious')
		self.assertIn('autenticado', reason)

	def test_faixa_de_legitimo_nunca_rebaixa_um_malicious(self):
		result = {'mode': 'escalate', 'tier': 'legitimate', 'score': 12.0,
			'tiers': dict(scoring.DEFAULT_TIERS), 'label': 'legitimate'}
		verdict, reason = scoring.verdict_after('Malicious', result, SEM_REGISTRO)
		self.assertEqual(verdict, 'Malicious')
		self.assertEqual(reason, '')

	def test_modo_advisory_nao_toca_no_veredito(self):
		result = {'mode': 'advisory', 'tier': 'phishing', 'score': 90.0,
			'tiers': dict(scoring.DEFAULT_TIERS), 'label': 'phishing'}
		verdict, reason = scoring.verdict_after('Safe', result, SEM_REGISTRO)
		self.assertEqual(verdict, 'Safe')
		self.assertEqual(reason, '')

	def test_spam_nao_vira_suspicious(self):
		result = {'mode': 'escalate', 'tier': 'suspicious', 'score': 43.0,
			'tiers': dict(scoring.DEFAULT_TIERS), 'label': 'spam'}
		verdict, reason = scoring.verdict_after('Safe', result, AUTHENTICATED)
		self.assertEqual(verdict, 'Safe')
		self.assertEqual(reason, '')


class TriagemDeSpam(unittest.TestCase):

	BULK = {'value': 0.8, 'bulk': True, 'oneClick': True, 'filtered': False,
		'markers': [{'id': 'list_unsubscribe_post', 'label': 'one-click', 'rfc': 'RFC 8058',
			'weight': 0.3}], 'scl': None, 'bcl': None}

	def test_massa_de_dominio_autenticado_vira_spam(self):
		# A newsletter pontua baixo porque de fato é legítima; o rótulo é de
		# natureza, não de severidade, e é ele que a tira da fila da analista
		result = scoring.compute('Safe', [report('virustotal', 'safe')], None,
			AUTHENTICATED, self.BULK, config())
		self.assertEqual(result['tier'], 'legitimate')
		self.assertEqual(result['label'], 'spam')

	def test_massa_num_e_mail_condenado_pela_faixa_nao_e_spam(self):
		llm = {'social_engineering_detected': True, 'risk_level': 'Critical'}
		result = scoring.compute('Safe', [report('virustotal', 'malicious')], llm,
			AUTHENTICATED, self.BULK, config())
		self.assertEqual(result['tier'], 'phishing')
		self.assertNotEqual(result['label'], 'spam')

	def test_massa_de_dominio_nao_autenticado_nunca_vira_spam(self):
		# É o caso que importa: List-Unsubscribe forjado num domínio que ninguém
		# autenticou não compra triagem nenhuma
		result = scoring.compute('Safe', [report('virustotal', 'safe')], None,
			UNAUTHENTICATED, self.BULK, config())
		self.assertNotEqual(result['label'], 'spam')

	def test_triagem_desligada_mantem_a_faixa(self):
		result = scoring.compute('Safe', [report('virustotal', 'safe')], None,
			AUTHENTICATED, self.BULK, config(spamTriage = False))
		self.assertNotEqual(result['label'], 'spam')

	def test_um_e_mail_condenado_nunca_e_rotulado_spam(self):
		result = scoring.compute('Malicious', [report('virustotal', 'malicious')], None,
			AUTHENTICATED, self.BULK, config())
		self.assertEqual(result['label'], 'phishing')


class ValidacaoDaConfiguracao(unittest.TestCase):

	KNOWN = ['virustotal', 'signal:llm_risk', 'signal:sender_auth', 'signal:bulk_headers']

	def test_peso_de_fator_desconhecido_e_recusado(self):
		_entry, error = scoring.validate_config(
			{'weights': {'nao-existe': 0.5}}, config(), self.KNOWN)
		self.assertIn('desconhecido', error)

	def test_peso_fora_da_faixa_e_aparado(self):
		entry, error = scoring.validate_config(
			{'weights': {'virustotal': 7.0}}, config(), self.KNOWN)
		self.assertIsNone(error)
		self.assertEqual(entry['weights']['virustotal'], 1.0)

	def test_tudo_zerado_e_recusado(self):
		_entry, error = scoring.validate_config(
			{'weights': dict((key, 0) for key in self.KNOWN)}, config(), self.KNOWN)
		self.assertIn('peso maior que zero', error)

	def test_faixas_fora_de_ordem_sao_recusadas(self):
		_entry, error = scoring.validate_config(
			{'tiers': {'phishing': 30, 'suspicious': 40, 'legitimate': 20}}, config(), self.KNOWN)
		self.assertIn('inalcançável', error)

	def test_faixa_acima_de_cem_e_recusada(self):
		_entry, error = scoring.validate_config(
			{'tiers': {'phishing': 140}}, config(), self.KNOWN)
		self.assertIsNotNone(error)

	def test_restaurar_padroes_devolve_o_registro_inteiro(self):
		# Mandar um mapa vazio não restauraria nada — a validação mescla sobre o
		# gravado. O padrão vem do módulo, que é quem conhece o registro
		alterada = config()
		alterada['weights']['virustotal'] = 0.05
		entry, error = scoring.validate_config({'resetWeights': True}, alterada, self.KNOWN)
		self.assertIsNone(error)
		self.assertEqual(entry['weights']['virustotal'],
			scoring.DEFAULT_ANALYZER_WEIGHTS['virustotal'])

	def test_modo_invalido_e_recusado(self):
		_entry, error = scoring.validate_config({'mode': 'autoritativo'}, config(), self.KNOWN)
		self.assertIn('Modo', error)

	def test_peso_que_nao_e_numero_e_recusado(self):
		_entry, error = scoring.validate_config(
			{'weights': {'virustotal': 'meio'}}, config(), self.KNOWN)
		self.assertIn('Peso inválido', error)


class RegistroDeFatores(unittest.TestCase):

	def test_todo_analisador_do_registro_tem_linha(self):
		import analyzers
		rows = scoring.factor_rows({}, [], config())
		ids = set(row['id'] for row in rows)
		for spec in analyzers.ANALYZERS:
			self.assertIn(spec['id'], ids)
		for factor in scoring.SIGNAL_FACTORS:
			self.assertIn(factor['id'], ids)

	def test_a_participacao_relativa_soma_cem(self):
		rows = scoring.factor_rows({}, [], config())
		self.assertAlmostEqual(sum(row['weightShare'] for row in rows), 100.0, delta = 0.5)

	def test_um_analisador_novo_no_registro_entra_com_peso_medio(self):
		# Peso zero seria pior do que ausência: ele rodaria, a tela o mostraria
		# habilitado, e ele não afetaria score nenhum
		rows = scoring.factor_rows({}, [{'id': 'meu-tip', 'name': 'Meu TIP',
			'observables': ['url'], 'enabled': True}], config())
		linha = [row for row in rows if row['id'] == 'meu-tip'][0]
		self.assertEqual(linha['weight'], scoring.DEFAULT_CUSTOM_WEIGHT)


if __name__ == '__main__':
	unittest.main()
