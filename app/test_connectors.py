"""Testes do conector genérico.

O que precisa estar fixado aqui é o que quebra silenciosamente: a preservação de
tipo (um número que vira texto só aparece como um 400 do fornecedor), o escape
(um assunto de e-mail escrito pelo atacante não pode virar estrutura no corpo da
requisição), e a trava de destino (um conector mal apontado é exfiltração com
nome de integração).

A chamada HTTP não é simulada, pela mesma razão dos analisadores: um teste que
afirma contra um falso escrito à mão prova só que o falso combina com o código.
O que dá para fixar sem rede é tudo que decide *o que* sai e *para onde* — e é
justamente onde moram os erros que importam.

Roda com:  python -m unittest test_connectors   (a partir do diretório app/)
"""

import json
import unittest

import connectors


# Um endereço público literal: evita DNS, então o teste não depende de rede para
# exercitar o caminho em que a trava de destino aceita
PUBLIC_URL = 'https://93.184.216.34/rest/api/2/issue'


def report(**over):
	base = {
		'subject': 'Sua conta será suspensa',
		'verdict': 'Malicious',
		'reporter': 'ana.silva@empresa.com',
		'department': 'Financeiro',
		'analyzedAt': '2026-08-10T14:02:11',
		'caseRef': '',
		'observables': [
			{'id': '1', 'type': 'url', 'value': 'http://conta-segura.xyz/login',
			 'ioc': True, 'message': 'VirusTotal 14/89', 'tags': [],
			 'malicious': True, 'suspicious': False},
			{'id': '2', 'type': 'domain', 'value': 'conta-segura.xyz',
			 'ioc': False, 'message': '', 'tags': [],
			 'malicious': False, 'suspicious': True}
		],
		'findings': [],
		'llm': {'summary': 'Urgência fabricada e domínio recém-registrado.'},
		'authentication': None,
		'body': 'clique aqui'
	}
	base.update(over)
	return base


def definition(**over):
	base = {
		'id': 'connector_jira',
		'name': 'Conector Jira',
		'enabled': True,
		'method': 'POST',
		'url': PUBLIC_URL,
		'allowInternal': False,
		'verifyTls': True,
		'timeout': 15,
		'contentType': 'application/json',
		'authType': 'bearer',
		'authName': '',
		'authUser': '',
		'authValue': 'token-secretissimo',
		'params': [],
		'payloadTemplate': {'fields': {'summary': '[{{verdict}}] {{subject}}'}},
		'minVerdict': 'all',
		'resultRefPath': 'key',
		'successStatus': [200, 201]
	}
	base.update(over)
	return base


def submitted(**over):
	"""O que o formulário manda — nem sempre igual ao que fica gravado."""
	base = {
		'name': 'Conector Jira',
		'url': PUBLIC_URL,
		'method': 'POST',
		'authType': 'bearer',
		'authValue': 'token-secretissimo',
		'payloadTemplate': {'fields': {'summary': '{{subject}}'}}
	}
	base.update(over)
	return base


class Render(unittest.TestCase):
	"""A gramática. É fechada de propósito, e o tipo do resultado é a parte sutil."""

	def setUp(self):
		self.context = connectors.context_from_report(report())

	def test_placeholder_sozinho_preserva_o_tipo(self):
		# O caso que decide se a integração funciona: o TheHive recusa "3" com 400
		self.assertEqual(connectors.render('{{severity_number}}', self.context), 3)
		self.assertIsInstance(connectors.render('{{severity_number}}', self.context), int)
		self.assertEqual(connectors.render('{{ioc_count}}', self.context), 1)

	def test_placeholder_sozinho_devolve_estrutura(self):
		rendered = connectors.render('{{thehive_observables}}', self.context)
		self.assertIsInstance(rendered, list)
		self.assertEqual(rendered[0]['dataType'], 'url')
		self.assertTrue(rendered[0]['ioc'])
		self.assertFalse(rendered[1]['ioc'])

	def test_espaco_dentro_das_chaves_e_tolerado(self):
		self.assertEqual(connectors.render('{{ severity_number }}', self.context), 3)

	def test_placeholder_embutido_vira_texto(self):
		self.assertEqual(
			connectors.render('[{{verdict}}] {{subject}}', self.context),
			'[Malicious] Sua conta será suspensa')

	def test_numero_embutido_em_texto_nao_vira_numero(self):
		self.assertEqual(connectors.render('{{ioc_count}} IOCs', self.context), '1 IOCs')

	def test_caminho_pontilhado(self):
		self.assertEqual(connectors.render('{{llm.summary}}', self.context),
			'Urgência fabricada e domínio recém-registrado.')
		self.assertEqual(connectors.render('{{observables.0.value}}', self.context),
			'http://conta-segura.xyz/login')

	def test_placeholder_inexistente_vira_vazio_e_e_reportado(self):
		missing = []
		self.assertEqual(connectors.render('fila {{queue_id}}', self.context, missing), 'fila ')
		self.assertEqual(missing, ['queue_id'])

	def test_placeholder_inexistente_sozinho_vira_none(self):
		missing = []
		self.assertIsNone(connectors.render('{{queue_id}}', self.context, missing))
		self.assertEqual(missing, ['queue_id'])

	def test_chaves_tambem_sao_renderizadas(self):
		rendered = connectors.render({'{{verdict}}': 'x'}, self.context)
		self.assertEqual(rendered, {'Malicious': 'x'})

	def test_valor_nao_textual_passa_intacto(self):
		rendered = connectors.render({'tlp': 2, 'on': True, 'nada': None}, self.context)
		self.assertEqual(rendered, {'tlp': 2, 'on': True, 'nada': None})

	def test_a_gramatica_nao_tem_expressao(self):
		# Se algum dia isto passar a ser avaliado, o template vira execução remota
		for hostile in ('{% for x in y %}', '{{ 7*7 }}', "{{ ''.__class__ }}",
				'${jndi:ldap://x}', '{{__import__("os")}}'):
			self.assertEqual(connectors.render(hostile, self.context), hostile)


class Escape(unittest.TestCase):
	"""O assunto do e-mail é escrito por quem atacou. Ele não pode virar estrutura."""

	def rendered_body(self, subject):
		context = connectors.context_from_report(report(subject = subject))
		template = {'fields': {'summary': '[{{verdict}}] {{subject}}', 'project': {'key': 'SEC'}}}
		return connectors.render(template, context)

	def test_aspas_no_assunto_nao_quebram_o_corpo(self):
		body = self.rendered_body('Ela disse "urgente" agora')
		roundtrip = json.loads(json.dumps(body, ensure_ascii = False))
		self.assertEqual(roundtrip['fields']['summary'], '[Malicious] Ela disse "urgente" agora')
		self.assertEqual(roundtrip['fields']['project'], {'key': 'SEC'})

	def test_injecao_de_json_no_assunto_continua_sendo_texto(self):
		hostile = '", "project": {"key": "ADMIN"}, "x": "'
		body = self.rendered_body(hostile)
		roundtrip = json.loads(json.dumps(body, ensure_ascii = False))
		# A chave forjada não existe, e o projeto continua sendo o configurado
		self.assertNotIn('x', roundtrip['fields'])
		self.assertEqual(roundtrip['fields']['project'], {'key': 'SEC'})
		self.assertIn(hostile, roundtrip['fields']['summary'])

	def test_quebra_de_linha_e_barra_invertida_sobrevivem(self):
		body = self.rendered_body('linha\numa\\barra')
		roundtrip = json.loads(json.dumps(body, ensure_ascii = False))
		self.assertEqual(roundtrip['fields']['summary'], '[Malicious] linha\numa\\barra')


class SetPath(unittest.TestCase):
	"""Colar o JSON da documentação intacto e ajustar um campo por fora."""

	def test_cria_o_que_falta(self):
		body = {}
		connectors.set_path(body, 'fields.customfield_10010', 'sd/1234')
		self.assertEqual(body, {'fields': {'customfield_10010': 'sd/1234'}})

	def test_preserva_o_que_ja_existe(self):
		body = {'fields': {'summary': 'mantido'}}
		connectors.set_path(body, 'fields.priority.name', 'High')
		self.assertEqual(body['fields']['summary'], 'mantido')
		self.assertEqual(body['fields']['priority'], {'name': 'High'})

	def test_indice_numerico_cria_lista(self):
		body = {}
		connectors.set_path(body, 'fields.components.0.name', 'Segurança')
		self.assertEqual(body['fields']['components'], [{'name': 'Segurança'}])

	def test_sobrescreve_valor_existente(self):
		body = {'index': 'antigo'}
		connectors.set_path(body, 'index', 'novo')
		self.assertEqual(body['index'], 'novo')

	def test_caminho_vazio_nao_faz_nada(self):
		body = {'a': 1}
		connectors.set_path(body, '', 'x')
		self.assertEqual(body, {'a': 1})


class Coerce(unittest.TestCase):

	def test_number(self):
		self.assertEqual(connectors.coerce('12', 'number'), 12)
		self.assertEqual(connectors.coerce('1.5', 'number'), 1.5)
		self.assertEqual(connectors.coerce('-3', 'number'), -3)

	def test_number_invalido_passa_como_veio(self):
		# Quem sabe o que aceita é o destino; um 400 dele diz mais que um erro nosso
		self.assertEqual(connectors.coerce('alto', 'number'), 'alto')

	def test_boolean(self):
		self.assertTrue(connectors.coerce('true', 'boolean'))
		self.assertTrue(connectors.coerce('sim', 'boolean'))
		self.assertFalse(connectors.coerce('nao', 'boolean'))

	def test_json(self):
		self.assertEqual(connectors.coerce('{"a": 1}', 'json'), {'a': 1})
		self.assertEqual(connectors.coerce('{quebrado', 'json'), '{quebrado')

	def test_string_mantem_estrutura(self):
		self.assertEqual(connectors.coerce([1, 2], 'string'), [1, 2])


class Destination(unittest.TestCase):
	"""A trava de destino. Tudo neste módulo repousa sobre ela."""

	def refuse(self, url, **over):
		result, error = connectors.validate_definition(submitted(url = url, **over))
		self.assertIsNone(result, url)
		return error

	def test_rede_privada_recusada(self):
		for url in ('https://192.168.0.10/api', 'https://10.0.0.1/api',
				'https://127.0.0.1/api', 'https://172.16.5.4/api'):
			self.assertTrue(self.refuse(url))

	def test_metadados_da_nuvem_recusados_mesmo_com_rede_interna(self):
		error = self.refuse('https://169.254.169.254/latest/meta-data/', allowInternal = True)
		self.assertIn('metadados', error)

	def test_http_recusado_sem_rede_interna(self):
		error = self.refuse('http://93.184.216.34/api')
		self.assertIn('https://', error)

	def test_http_aceito_com_rede_interna(self):
		# Um serviço interno costuma não ter TLS; exigir https tornaria a
		# liberação da rede interna inútil na prática
		result, error = connectors.validate_definition(
			submitted(url = 'http://192.168.0.10/api', allowInternal = True))
		self.assertIsNone(error)
		self.assertTrue(result['allowInternal'])

	def test_placeholder_na_url_nao_atrapalha_a_validacao(self):
		result, error = connectors.validate_definition(
			submitted(url = PUBLIC_URL + '?ref={{caseRef}}'))
		self.assertIsNone(error)
		self.assertIn('{{caseRef}}', result['url'])

	def test_deliver_revalida_no_disparo_sem_tocar_a_rede(self):
		# O caminho que importa: a definição foi gravada quando o destino era
		# público e agora aponta para dentro. Nenhuma requisição pode sair.
		outcome = connectors.deliver(definition(url = 'https://127.0.0.1/api'), report())
		self.assertFalse(outcome['ok'])
		self.assertIn('Destino recusado', outcome['error'])

	def test_deliver_recusa_metadados_no_disparo(self):
		outcome = connectors.deliver(
			definition(url = 'https://169.254.169.254/latest/meta-data/', allowInternal = True),
			report())
		self.assertFalse(outcome['ok'])
		self.assertIn('metadados', outcome['error'])


class Definition(unittest.TestCase):

	def test_nome_obrigatorio(self):
		result, error = connectors.validate_definition(submitted(name = '  '))
		self.assertIsNone(result)
		self.assertIn('nome', error)

	def test_metodo_sem_corpo_recusado(self):
		result, error = connectors.validate_definition(submitted(method = 'GET'))
		self.assertIsNone(result)
		self.assertIn('POST', error)

	def test_payload_vazio_recusado(self):
		result, error = connectors.validate_definition(submitted(payloadTemplate = {}))
		self.assertIsNone(result)
		self.assertIn('corpo', error)

	def test_payload_vazio_aceito_quando_ha_parametro_de_corpo(self):
		result, error = connectors.validate_definition(submitted(
			payloadTemplate = {},
			params = [{'location': 'body', 'key': 'event.verdict', 'value': '{{verdict}}'}]))
		self.assertIsNone(error)
		self.assertEqual(result['params'][0]['key'], 'event.verdict')

	def test_payload_como_texto_e_aceito(self):
		result, error = connectors.validate_definition(
			submitted(payloadTemplate = '{"a": "{{verdict}}"}'))
		self.assertIsNone(error)
		self.assertEqual(result['payloadTemplate'], {'a': '{{verdict}}'})

	def test_payload_como_texto_invalido_recusado(self):
		result, error = connectors.validate_definition(submitted(payloadTemplate = '{quebrado'))
		self.assertIsNone(result)
		self.assertIn('JSON', error)

	def test_credencial_obrigatoria_quando_ha_autenticacao(self):
		result, error = connectors.validate_definition(submitted(authValue = ''))
		self.assertIsNone(result)
		self.assertIn('credencial', error)

	def test_credencial_em_branco_mantem_a_gravada(self):
		stored = definition()
		result, error = connectors.validate_definition(submitted(authValue = ''), stored)
		self.assertIsNone(error)
		self.assertEqual(result['authValue'], 'token-secretissimo')

	def test_basic_exige_usuario(self):
		result, error = connectors.validate_definition(submitted(authType = 'basic'))
		self.assertIsNone(result)
		self.assertIn('usuário', error)

	def test_header_exige_nome(self):
		result, error = connectors.validate_definition(submitted(authType = 'header'))
		self.assertIsNone(result)
		self.assertIn('cabeçalho', error)

	def test_parametro_repetido_recusado(self):
		result, error = connectors.validate_definition(submitted(params = [
			{'location': 'header', 'key': 'X-Token', 'value': 'a'},
			{'location': 'header', 'key': 'X-Token', 'value': 'b'}]))
		self.assertIsNone(result)
		self.assertIn('repetido', error)

	def test_mesma_chave_em_locais_diferentes_e_valida(self):
		result, error = connectors.validate_definition(submitted(params = [
			{'location': 'header', 'key': 'index', 'value': 'a'},
			{'location': 'query', 'key': 'index', 'value': 'b'}]))
		self.assertIsNone(error)
		self.assertEqual(len(result['params']), 2)

	def test_local_invalido_recusado(self):
		result, error = connectors.validate_definition(submitted(params = [
			{'location': 'cookie', 'key': 'x', 'value': 'a'}]))
		self.assertIsNone(result)
		self.assertIn('header', error)

	def test_parametro_secreto_em_branco_mantem_o_gravado(self):
		stored = definition(params = [
			{'location': 'body', 'key': 'routing_key', 'value': 'chave-antiga', 'isSecret': True}])
		result, error = connectors.validate_definition(submitted(params = [
			{'location': 'body', 'key': 'routing_key', 'value': '', 'isSecret': True}]), stored)
		self.assertIsNone(error)
		self.assertEqual(result['params'][0]['value'], 'chave-antiga')

	def test_timeout_fora_da_faixa_recusado(self):
		for bad in (0, 61, 900):
			result, error = connectors.validate_definition(submitted(timeout = bad))
			self.assertIsNone(result, bad)
			self.assertIn('segundos', error)

	def test_id_gerado_nao_colide_com_destino_nativo(self):
		result, _ = connectors.validate_definition(submitted(name = 'Jira'))
		self.assertTrue(result['id'].startswith(connectors.ID_PREFIX))
		self.assertNotIn(result['id'], ('jira', 'thehive', 'disk'))

	def test_id_gerado_nao_colide_com_outro_conector(self):
		first, _ = connectors.validate_definition(submitted(name = 'Splunk'), None, [])
		second, _ = connectors.validate_definition(submitted(name = 'Splunk'), None, [first['id']])
		self.assertNotEqual(first['id'], second['id'])

	# O id gravado manda: renomear um conector não pode criar um segundo
	def test_id_gravado_e_preservado(self):
		result, _ = connectors.validate_definition(
			submitted(name = 'Outro nome'), definition())
		self.assertEqual(result['id'], 'connector_jira')


class Secrets(unittest.TestCase):
	"""Segredo entra e não sai — nem para o navegador, nem para o histórico."""

	def test_public_definition_nao_devolve_a_credencial(self):
		public = connectors.public_definition(definition())
		self.assertNotIn('authValue', public)
		self.assertTrue(public['hasAuthValue'])

	def test_public_definition_nao_devolve_parametro_secreto(self):
		public = connectors.public_definition(definition(params = [
			{'location': 'body', 'key': 'routing_key', 'value': 'chave-real', 'isSecret': True},
			{'location': 'query', 'key': 'index', 'value': 'security', 'isSecret': False}]))
		self.assertEqual(public['params'][0]['value'], '')
		self.assertTrue(public['params'][0]['hasValue'])
		self.assertEqual(public['params'][1]['value'], 'security')

	def test_redacao_e_por_valor_nao_por_nome_de_campo(self):
		# Um token colado no meio de texto livre não seria pego por lista de nomes
		redacted = connectors.redact(
			{'description': 'use o token abcdef123456 para autenticar'}, ['abcdef123456'])
		self.assertNotIn('abcdef123456', json.dumps(redacted))
		self.assertIn('***', redacted['description'])

	def test_segredo_curto_nao_e_redigido(self):
		# Trocar toda ocorrência de três caracteres deixaria o registro ilegível
		redacted = connectors.redact({'texto': 'abc def'}, ['abc'])
		self.assertEqual(redacted['texto'], 'abc def')

	def test_preview_mascara_a_credencial(self):
		shown = connectors.preview(definition(), report())
		self.assertNotIn('token-secretissimo', json.dumps(shown))
		self.assertIn('***', shown['headers']['Authorization'])

	def test_preview_mascara_o_basic_na_forma_codificada(self):
		# Achado rodando no container: o cabeçalho basic carrega usuario:senha em
		# base64, e redigir só o valor cru devolvia a credencial inteira para a
		# tela, a uma decodificação de distância. base64 não é cifra.
		import base64
		connector = definition(authType = 'basic', authUser = 'soc@empresa.com',
			authValue = 'token-secretissimo')
		shown = connectors.preview(connector, report())
		serialized = json.dumps(shown)
		self.assertNotIn('token-secretissimo', serialized)
		encoded = base64.b64encode(b'soc@empresa.com:token-secretissimo').decode('ascii')
		self.assertNotIn(encoded, serialized)
		self.assertIn('***', shown['headers']['Authorization'])

	def test_o_disparo_ainda_manda_o_basic_correto(self):
		# A redação vale para o que volta à tela; o que sai na requisição precisa
		# continuar sendo a credencial de verdade
		import base64
		connector = definition(authType = 'basic', authUser = 'soc@empresa.com',
			authValue = 'token-secretissimo')
		context = connectors.context_from_report(report(), connectors.secret_map(connector))
		_, headers, _, _, _ = connectors.build_request(connector, context)
		expected = base64.b64encode(b'soc@empresa.com:token-secretissimo').decode('ascii')
		self.assertEqual(headers['Authorization'], 'Basic ' + expected)

	def test_request_registrado_no_disparo_tambem_esconde_o_basic(self):
		# O mesmo cuidado no que vai para o log: `deliver` devolve o request já
		# redigido justamente para quem registra não precisar lembrar disso
		import base64
		connector = definition(url = 'https://127.0.0.1/api', authType = 'basic',
			authUser = 'soc@empresa.com', authValue = 'token-secretissimo')
		encoded = base64.b64encode(b'soc@empresa.com:token-secretissimo').decode('ascii')
		self.assertIn(encoded, connectors.redact({'h': 'Basic ' + encoded}, ['x'])['h'])
		self.assertNotIn(encoded,
			json.dumps(connectors.redact({'h': 'Basic ' + encoded},
				connectors.secret_values(connector))))

	def test_secrets_namespace_resolve_parametro_secreto(self):
		connector = definition(
			authType = 'none', authValue = '',
			params = [{'location': 'body', 'key': 'routing_key',
				'value': 'chave-real', 'isSecret': True}],
			payloadTemplate = {'texto': 'chave: {{secrets.routing_key}}'})
		context = connectors.context_from_report(report(), connectors.secret_map(connector))
		self.assertEqual(connectors.render('{{secrets.routing_key}}', context), 'chave-real')
		# E ainda assim ela não aparece na pré-visualização
		self.assertNotIn('chave-real', json.dumps(connectors.preview(connector, report())))


class BuildRequest(unittest.TestCase):
	"""Onde cada coisa entra na requisição."""

	def build(self, connector):
		context = connectors.context_from_report(connector and report(),
			connectors.secret_map(connector))
		return connectors.build_request(connector, context)

	def test_bearer(self):
		_, headers, _, _, _ = self.build(definition())
		self.assertEqual(headers['Authorization'], 'Bearer token-secretissimo')

	def test_basic_codifica_usuario_e_token(self):
		import base64
		_, headers, _, _, _ = self.build(definition(
			authType = 'basic', authUser = 'soc@empresa.com', authValue = 'segredo'))
		expected = base64.b64encode(b'soc@empresa.com:segredo').decode('ascii')
		self.assertEqual(headers['Authorization'], 'Basic ' + expected)

	def test_header_customizado(self):
		_, headers, _, _, _ = self.build(definition(
			authType = 'header', authName = 'X-Api-Key', authValue = 'segredo'))
		self.assertEqual(headers['X-Api-Key'], 'segredo')

	def test_query(self):
		_, _, params, _, _ = self.build(definition(
			authType = 'query', authName = 'token', authValue = 'segredo'))
		self.assertEqual(params['token'], 'segredo')

	def test_parametro_de_corpo_com_caminho_pontilhado(self):
		_, _, _, body, _ = self.build(definition(params = [
			{'location': 'body', 'key': 'fields.customfield_10010',
			 'value': 'sd/1234', 'valueType': 'string'}]))
		self.assertEqual(body['fields']['customfield_10010'], 'sd/1234')
		# E o que veio do payload colado continua lá
		self.assertIn('summary', body['fields'])

	def test_parametro_de_corpo_respeita_o_tipo_declarado(self):
		_, _, _, body, _ = self.build(definition(params = [
			{'location': 'body', 'key': 'severity', 'value': '{{severity_number}}',
			 'valueType': 'number'}]))
		self.assertEqual(body['severity'], 3)
		self.assertIsInstance(body['severity'], int)

	def test_parametro_de_corpo_em_payload_de_lista_e_erro_legivel(self):
		with self.assertRaises(connectors.ConnectorError):
			self.build(definition(
				payloadTemplate = [{'a': 1}],
				params = [{'location': 'body', 'key': 'x', 'value': '1'}]))

	def test_url_com_placeholder_e_renderizada(self):
		url, _, _, _, _ = self.build(definition(url = PUBLIC_URL + '?v={{verdict}}'))
		self.assertTrue(url.endswith('?v=Malicious'))

	def test_content_type_vai_no_cabecalho(self):
		_, headers, _, _, _ = self.build(definition(contentType = 'application/vnd.api+json'))
		self.assertEqual(headers['Content-Type'], 'application/vnd.api+json')


class Classify(unittest.TestCase):
	"""Um 2xx não basta, e cada falha tem conduta diferente."""

	def test_sucesso_extrai_a_referencia(self):
		outcome = connectors.classify(definition(), 201, {'key': 'SEC-1847'}, '')
		self.assertTrue(outcome['ok'])
		self.assertEqual(outcome['ref'], 'SEC-1847')
		self.assertIn('SEC-1847', outcome['detail'])

	def test_sucesso_sem_referencia_ainda_e_sucesso(self):
		outcome = connectors.classify(definition(resultRefPath = ''), 200, {}, '')
		self.assertTrue(outcome['ok'])
		self.assertEqual(outcome['ref'], '')

	def test_caminho_de_referencia_inexistente_nao_derruba_o_sucesso(self):
		outcome = connectors.classify(definition(), 201, {'outro': 1}, '')
		self.assertTrue(outcome['ok'])
		self.assertEqual(outcome['ref'], '')

	def test_status_fora_da_lista_configurada_e_falha(self):
		outcome = connectors.classify(definition(successStatus = [201]), 200, {}, '')
		self.assertFalse(outcome['ok'])

	def test_credencial_recusada(self):
		for status in (401, 403):
			outcome = connectors.classify(definition(), status, None, '')
			self.assertFalse(outcome['ok'])
			self.assertIn('credencial', outcome['error'])
			self.assertFalse(outcome['retryable'])

	def test_payload_recusado_carrega_a_resposta_do_destino(self):
		# É a única coisa que diz *qual* campo faltou
		outcome = connectors.classify(definition(), 400, None,
			'{"errors":{"customfield_10010":"required"}}')
		self.assertFalse(outcome['ok'])
		self.assertIn('customfield_10010', outcome['error'])

	def test_limite_de_requisicoes_e_retentavel(self):
		outcome = connectors.classify(definition(), 429, None, '')
		self.assertTrue(outcome['retryable'])

	def test_erro_do_servidor_e_retentavel(self):
		outcome = connectors.classify(definition(), 503, None, '')
		self.assertTrue(outcome['retryable'])

	def test_redirecionamento_e_recusado_nao_seguido(self):
		outcome = connectors.classify(definition(), 302, None, '')
		self.assertFalse(outcome['ok'])
		self.assertIn('redirecionamento', outcome['error'])

	def test_404_aponta_a_url(self):
		outcome = connectors.classify(definition(), 404, None, '')
		self.assertIn('URL', outcome['error'])


class Dispatch(unittest.TestCase):
	"""Quem dispara para este veredito."""

	def test_desabilitado_nao_dispara(self):
		self.assertEqual(
			connectors.enabled_for('Malicious', [definition(enabled = False)]), [])

	def test_veredito_abaixo_do_minimo_nao_dispara(self):
		definitions = [definition(minVerdict = 'Malicious')]
		self.assertEqual(connectors.enabled_for('Suspicious', definitions), [])
		self.assertEqual(len(connectors.enabled_for('Malicious', definitions)), 1)

	def test_all_aceita_qualquer_veredito(self):
		definitions = [definition(minVerdict = 'all')]
		for verdict in ('Safe', 'Suspicious', 'Malicious'):
			self.assertEqual(len(connectors.enabled_for(verdict, definitions)), 1)

	def test_um_conector_que_falha_nao_impede_os_outros(self):
		# Ambos apontam para dentro, então nenhum toca a rede; o que se fixa aqui
		# é que o dispatch percorre a lista inteira em vez de parar no primeiro
		results = connectors.dispatch(report(), [
			definition(id = 'a', url = 'https://127.0.0.1/api'),
			definition(id = 'b', url = 'https://10.0.0.1/api')])
		self.assertEqual([r[0] for r in results], ['a', 'b'])
		self.assertTrue(all(not r[1]['ok'] for r in results))

	def test_deliver_nunca_levanta(self):
		# O veredito já foi decidido quando isto roda: uma definição corrompida
		# precisa virar registro, nunca exceção que desfaz a análise.
		#
		# Todas apontam para dentro de propósito: a trava recusa antes de abrir
		# conexão, então o teste fixa o contrato sem depender de rede.
		private = 'https://127.0.0.1/api'
		for broken in ({}, {'url': None}, {'url': 'nao-e-url'},
				definition(url = private, payloadTemplate = None),
				definition(url = private, params = None),
				definition(url = private, timeout = 'x'),
				definition(url = private, successStatus = None)):
			outcome = connectors.deliver(broken, report())
			self.assertFalse(outcome['ok'])
			self.assertTrue(outcome['error'])

	def test_timeout_corrompido_na_configuracao_cai_no_padrao(self):
		# `deliver` lê a definição do disco, e essa seção pode ter sido editada à
		# mão. Um timeout inválido faria requests levantar ValueError antes de
		# abrir a conexão, o que contradiria "nunca levanta".
		for bad in ('x', None, 0, 999, [1]):
			self.assertEqual(connectors._read_timeout({'timeout': bad}),
				connectors.DEFAULT_TIMEOUT)
		self.assertEqual(connectors._read_timeout({'timeout': 20}), 20)


class Context(unittest.TestCase):

	def test_derivadas(self):
		context = connectors.context_from_report(report())
		self.assertEqual(context['ioc_count'], 1)
		self.assertEqual(context['observable_count'], 2)
		self.assertEqual(context['severity_number'], 3)
		self.assertIn('conta-segura.xyz', context['observables_csv'])

	def test_severidade_por_veredito(self):
		for verdict, expected in (('Safe', 1), ('Suspicious', 2), ('Malicious', 3)):
			context = connectors.context_from_report(report(verdict = verdict))
			self.assertEqual(context['severity_number'], expected)

	def test_relatorio_em_prosa_esta_disponivel(self):
		context = connectors.context_from_report(report())
		self.assertIn('Malicious', context['report_markdown'])
		self.assertNotIn('*', context['report_text'])

	def test_toda_variavel_anunciada_existe_no_contexto(self):
		# A tela oferece esta lista no painel lateral. Um nome que saia daqui sem
		# sair do contexto vira um placeholder que resolve para vazio na cara do
		# usuário, e ele não teria como saber que a culpa não é dele.
		context = connectors.context_from_report(report())
		for variable in connectors.VARIABLES:
			self.assertIsNotNone(connectors.resolve(variable['name'], context),
				'{0} está anunciada e não resolve'.format(variable['name']))


class WebhookDeAlerta(unittest.TestCase):
	"""O webhook do alerta de volume é um conector com outro contexto.

	O que não pode mudar entre os dois é o caminho de disparo: a trava de destino
	e o escape valem igual, porque o assunto do alerta também é escrito por quem
	atacou.
	"""

	def setUp(self):
		import volume_alerts
		self.volume_alerts = volume_alerts

	def test_toda_variavel_do_alerta_resolve(self):
		context = self.volume_alerts.alert_context(self.volume_alerts.sample_alert())
		for variable in self.volume_alerts.VARIABLES:
			self.assertIsNotNone(connectors.resolve(variable['name'], context),
				'{0} está anunciada e não resolve'.format(variable['name']))

	def test_o_template_de_alerta_renderiza_pelo_mesmo_build_request(self):
		alert = self.volume_alerts.sample_alert()
		alert['pattern'] = 'assunto com "aspas" e }chaves{'
		hook = definition(payloadTemplate = {'text': '{{message}}', 'count': '{{count}}'}, params = [])
		shown = connectors.preview(hook, alert, context_builder = self.volume_alerts.alert_context)
		self.assertEqual(shown['body']['count'], alert['count'])
		self.assertIn('"aspas"', shown['body']['text'])
		self.assertEqual(shown['missing'], [])

	def test_a_trava_de_destino_vale_para_o_webhook(self):
		hook = definition(url = 'http://169.254.169.254/latest/meta-data', allowInternal = True)
		outcome = connectors.deliver(hook, self.volume_alerts.sample_alert(),
			context_builder = self.volume_alerts.alert_context)
		self.assertFalse(outcome['ok'])
		self.assertIn('recusado', outcome['error'])

	def test_as_secoes_nao_se_misturam(self):
		import os
		import tempfile
		handle, path = tempfile.mkstemp(suffix = '.json')
		os.close(handle)
		try:
			with open(path, 'w') as conf_file:
				json.dump({'connectors': [definition()]}, conf_file)
			connectors.save_all([definition(id = 'connector_teams')], path,
				self.volume_alerts.CONNECTORS_SECTION)
			self.assertEqual([d['id'] for d in connectors.load_all(path)], ['connector_jira'])
			self.assertEqual([d['id'] for d in self.volume_alerts.load_connectors(path)], ['connector_teams'])
		finally:
			os.remove(path)


if __name__ == '__main__':
	unittest.main()
