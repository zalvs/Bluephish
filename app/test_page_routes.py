"""Caminhos de página (`/config/ia`, `/done/<caso>`...) e o retorno ao ponto de partida após o login.

Até aqui o painel tinha duas páginas — `/` e `/login` — e as "abas" eram só
`data-view` trocados no navegador: a URL nunca mudava, então não havia como
mandar o link de uma tela, nem voltar a ela depois de a sessão cair.

Três coisas aqui podem falhar sem barulho, e por isso têm teste:

**Cada caminho tem o papel mínimo da tela que abre.** O servidor entrega o mesmo
`index.html` para todos eles, e é a rota — não o JavaScript — que decide quem
pode abri-lo. Esconder o item de menu nunca foi o controle (§3.2); um caminho
novo que esquecesse o papel seria uma tela de administração aberta a qualquer
analista que digitasse o endereço.

**Um caminho de página não pode ocupar o lugar de uma rota de dados.** `/email`,
`/list` ou `/scheduler` já respondem JSON ao painel; uma página com o mesmo
endereço trocaria a resposta e o painel quebraria sem erro nenhum.

**O `next` do login só aceita caminho de página.** Honrar um endereço qualquer
vindo da URL é redirecionamento aberto numa tela que pede senha — o endereço da
vítima trocado pelo de um site do atacante, depois de ela ter acabado de
digitar a credencial no lugar certo.

Roda com:  python -m unittest test_page_routes   (a partir do diretório app/)
"""

import io
import os
import re
import time
import unittest
import urllib.parse

import werkzeug.exceptions
import werkzeug.routing

import auth
import models
import page_routes
import test_mfa_gate as gate

BASE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(BASE, 'templates', 'index.html')

ANALYST = models.ROLE_ANALYST
ADMIN = models.ROLE_ADMIN
GLOBAL_ADMIN = models.ROLE_GLOBAL_ADMIN

# Escrito à mão e de propósito: um teste que lesse a tabela do módulo para saber
# o que esperar estaria conferindo a tabela contra ela mesma
EXPECTED = (
	('/exec', ANALYST), ('/intel', ANALYST), ('/tactic', ANALYST), ('/inbox', ANALYST), ('/done', ANALYST),
	('/queues', ANALYST), ('/account', ANALYST),
	('/done/12', ANALYST), ('/queues/12', ANALYST), ('/inbox/12', ANALYST),
	('/audit', ADMIN),
	('/integr', ADMIN), ('/integr/analisadores', ADMIN),
	('/integr/priorizacao', ADMIN), ('/integr/bloqueio', ADMIN), ('/integr/tickets', ADMIN),
	('/config', ADMIN), ('/config/auto', ADMIN), ('/config/ia', ADMIN), ('/config/email', ADMIN),
	('/config/notificacao', ADMIN), ('/config/caso', ADMIN), ('/config/departamentos', ADMIN),
	('/config/whitelist', ADMIN),
	('/config/sso', GLOBAL_ADMIN), ('/config/auditoria', GLOBAL_ADMIN), ('/config/seguranca', GLOBAL_ADMIN), ('/config/certificados', GLOBAL_ADMIN),
	('/users', GLOBAL_ADMIN),
)


def read(path):
	with io.open(path, encoding = 'utf-8') as handle:
		return handle.read()


def level(role):
	return models.ROLES.index(role)


class PagesBase(gate.Base):
	"""A aplicação mínima do teste do segundo fator, com as páginas montadas nela."""

	def setUp(self):
		super().setUp()
		self.app.context_processor(lambda: {'asset_version': '1'})
		page_routes.register(self.app)

	def client_as(self, role):
		"""Um cliente novo, já dentro como alguém com este papel (segundo fator incluído)."""
		self.client = self.app.test_client()
		self.enrolled_user('pessoa-' + role, role)
		return self.client


class TheTableMatchesTheScreens(unittest.TestCase):
	"""Toda tela do painel tem caminho, e todo caminho abre uma tela que existe."""

	def tokens(self, attribute):
		markup = re.sub(r'<!--.*?-->', '', read(TEMPLATE), flags = re.S)
		found = set()
		for value in re.findall(r'\b' + attribute + r'="([^"]+)"', markup):
			found.update(value.split())
		return found

	def test_every_view_in_the_template_has_a_path(self):
		self.assertEqual(self.tokens('data-view'), set(page_routes.VIEW_ROLES))

	def test_every_config_tab_in_the_template_has_a_path(self):
		self.assertEqual(self.tokens('data-config-tab'), set(page_routes.CONFIG_TABS))

	def test_every_integr_tab_in_the_template_has_a_path(self):
		self.assertEqual(self.tokens('data-integr-tab'), set(page_routes.INTEGR_TABS))

	def test_the_table_lists_exactly_the_expected_paths(self):
		listed = {re.sub(r'/sample$', '/12', page_routes.sample_path(rule)): role
			for rule, role in page_routes.PAGES}
		self.assertEqual(dict(EXPECTED), listed)

	def test_a_retired_path_is_not_a_screen_and_points_at_one(self):
		# Um caminho aposentado que continuasse na tabela seria uma tela sem aba;
		# um que apontasse para fora dela seria um redirecionamento para o nada
		screens = dict(EXPECTED)
		for retired, target in page_routes.RETIRED_PAGES.items():
			self.assertNotIn(retired, screens)
			self.assertIn(target, screens)


class EverythingButTheAssetsIsNeverCached(unittest.TestCase):
	"""`Cache-Control: no-store` em toda resposta que não seja um arquivo estático.

	Só as telas o tinham. Uma resposta de dados (`/api/cases`, o que o assistente
	lê, o `.eml`, a exportação da auditoria) sem ele fica disponível ao Voltar
	depois de sair, e a um proxy intermediário. Os arquivos de `/static` ficam de
	fora de propósito: a semana de cache deles evita que a rajada de requisições a
	cada F5 derrube conexões do eventlet (comentário em thephish_app.py).
	"""

	def setUp(self):
		import flask
		self.app = flask.Flask(__name__, static_folder = os.path.join(BASE, 'static'))
		self.app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 7 * 24 * 60 * 60
		self.app.after_request(lambda response: page_routes.no_store_unless_static(response, flask.request.endpoint))

		@self.app.route('/api/cases')
		def cases():
			return flask.jsonify([])

		@self.app.route('/login')
		def login():
			return 'login'

		@self.app.route('/api/ja-publico')
		def already_public():
			response = flask.jsonify([])
			response.headers['Cache-Control'] = 'public, max-age=604800'
			return response

		self.client = self.app.test_client()

	def test_a_data_response_is_not_cached(self):
		self.assertEqual('no-store', self.client.get('/api/cases').headers.get('Cache-Control'))

	def test_the_login_is_not_cached(self):
		self.assertEqual('no-store', self.client.get('/login').headers.get('Cache-Control'))

	def test_an_error_is_not_cached(self):
		self.assertEqual('no-store', self.client.get('/nao-existe').headers.get('Cache-Control'))

	def test_a_route_that_asked_to_be_public_is_overruled(self):
		# `send_file` põe `public, max-age` sozinho; um .eml servido assim ficaria uma semana em qualquer cache
		self.assertEqual('no-store', self.client.get('/api/ja-publico').headers.get('Cache-Control'))

	def test_a_static_asset_keeps_its_week_of_cache(self):
		css = [name for name in os.listdir(os.path.join(BASE, 'static', 'assets', 'css')) if name.endswith('.css')][0]
		response = self.client.get('/static/assets/css/' + css)
		self.assertEqual(200, response.status_code)
		self.assertIn('max-age=604800', response.headers.get('Cache-Control', ''))
		self.assertNotIn('no-store', response.headers.get('Cache-Control', ''))

	def test_the_application_applies_it_to_every_response(self):
		# thephish_app não se importa fora da imagem: confere-se no texto
		source = read(os.path.join(BASE, 'thephish_app.py'))
		self.assertRegex(source, r'page_routes\.no_store_unless_static\(\s*response\s*,\s*flask\.request\.endpoint\s*\)')


class NoPageShadowsADataRoute(unittest.TestCase):
	"""As rotas de dados do painel continuam sendo delas."""

	def existing_rules(self):
		rules = []
		for name in ('thephish_app.py', 'auth.py'):
			source = read(os.path.join(BASE, name))
			rules.extend(re.findall(r"@(?:app|application)\.route\(\s*['\"]([^'\"]+)['\"]", source))
		self.assertGreater(len(rules), 80, 'o teste deixou de enxergar as rotas')
		return rules

	def test_no_page_path_matches_an_existing_route(self):
		# `/` é a página inicial, e continua em thephish_app.py
		url_map = werkzeug.routing.Map(
			[werkzeug.routing.Rule(rule) for rule in self.existing_rules() if rule != '/'])
		adapter = url_map.bind('localhost')
		for rule, _role in page_routes.PAGES:
			path = page_routes.sample_path(rule)
			with self.assertRaises(werkzeug.exceptions.NotFound, msg = path):
				adapter.match(path, method = 'GET')

	def test_the_reserved_data_names_are_not_pages(self):
		pages = {page_routes.sample_path(rule) for rule, _role in page_routes.PAGES}
		for reserved in ('/email', '/list', '/scheduler', '/analysis', '/inbox-poll', '/login', '/api'):
			self.assertNotIn(reserved, pages)


class EachPathKeepsItsRole(PagesBase):

	def test_anonymous_navigation_goes_to_login_carrying_the_path(self):
		for path, _role in EXPECTED:
			response = self.app.test_client().get(path)
			self.assertEqual(302, response.status_code, path)
			location = urllib.parse.urlparse(response.headers['Location'])
			self.assertEqual('/login', location.path, path)
			self.assertEqual([path], urllib.parse.parse_qs(location.query).get('next'), path)

	def test_every_role_gets_exactly_what_it_may_open(self):
		for role in models.ROLES:
			client = self.client_as(role)
			for path, minimum in EXPECTED:
				expected = 200 if level(role) >= level(minimum) else 403
				self.assertEqual(expected, client.get(path).status_code,
					'{0} como {1}'.format(path, role))

	def test_the_page_is_the_same_document_for_every_path(self):
		client = self.client_as(GLOBAL_ADMIN)
		bodies = {client.get(path).get_data() for path, _role in EXPECTED}
		self.assertEqual(1, len(bodies))
		self.assertIn(b'data-view="config"', bodies.pop())

	def test_a_refusal_for_lack_of_role_is_audited(self):
		client = self.client_as(ANALYST)
		self.assertEqual(403, client.get('/config/ia').status_code)
		with io.open(auth.audit_log_path(), encoding = 'utf-8') as handle:
			trail = handle.read()
		self.assertIn('event=authorization_denied', trail)
		self.assertIn('path=/config/ia required=admin', trail)

	def test_a_screen_is_never_cached(self):
		# O documento é o mesmo para todos, mas só abre para quem tem sessão; sem isto
		# o botão Voltar, depois de sair, reabriria a tela do cache sem passar pelo login
		client = self.client_as(ADMIN)
		for path in ('/config/ia', '/done/12', '/queues/12', '/inbox/12', '/exec'):
			self.assertIn('no-store', client.get(path).headers.get('Cache-Control', ''), path)

	def test_unknown_paths_are_not_found_not_login(self):
		client = self.client_as(GLOBAL_ADMIN)
		for path in ('/config/nada', '/integr/nada', '/nada', '/done/a/b', '/queues/a/b', '/inbox/a/b', '/users/1', '/exec/x'):
			self.assertEqual(404, client.get(path).status_code, path)

	def test_a_retired_path_leads_to_the_screen_that_replaced_it(self):
		# /integr/plataforma era o endereço em que Integrações abria, e é o que
		# ficou nos favoritos. A aba saiu; o endereço leva à tela, não a um 404
		client = self.client_as(ADMIN)
		for retired, target in page_routes.RETIRED_PAGES.items():
			response = client.get(retired)
			self.assertEqual(302, response.status_code, retired)
			self.assertEqual(target, urllib.parse.urlparse(response.headers['Location']).path, retired)
			self.assertEqual(200, client.get(target).status_code, target)

	def test_a_retired_path_gives_nobody_a_screen_they_could_not_open(self):
		# O redirecionamento não é a tela: quem chega por ele ainda passa pelo
		# papel da tela de destino
		client = self.client_as(ANALYST)
		screens = dict(EXPECTED)
		for retired, target in page_routes.RETIRED_PAGES.items():
			response = client.get(retired)
			self.assertEqual(302, response.status_code, retired)
			opens = level(ANALYST) >= level(screens[target])
			self.assertEqual(200 if opens else 403, client.get(target).status_code, target)

	def test_the_chat_tab_address_leads_to_the_cases_screen(self):
		# /chat era a aba "Chat AI". A conversa ficou no assistente do caso aberto;
		# quem tem o endereço guardado cai na tela dos casos, não num 404
		client = self.client_as(ANALYST)
		response = client.get('/chat')
		self.assertEqual(302, response.status_code)
		self.assertEqual('/done', urllib.parse.urlparse(response.headers['Location']).path)
		self.assertNotIn('chat', page_routes.VIEW_ROLES)

	def test_a_trailing_slash_opens_the_same_page(self):
		client = self.client_as(ADMIN)
		self.assertEqual(200, client.get('/config/').status_code)
		self.assertEqual(200, client.get('/config/ia/').status_code)

	def test_pages_only_answer_get(self):
		client = self.client_as(GLOBAL_ADMIN)
		for path in ('/config/ia', '/done/12', '/users'):
			for method in ('post', 'put', 'delete'):
				self.assertEqual(405, getattr(client, method)(path).status_code,
					'{0} {1}'.format(method, path))


class SafeNext(PagesBase):
	"""O que `next` pode ser: caminho de página deste painel, e nada além."""

	def check(self, value):
		with self.app.test_request_context('/'):
			return page_routes.safe_next(value)

	def test_page_paths_are_accepted(self):
		for path in ('/', '/config', '/config/ia', '/integr/tickets', '/done/12', '/users', '/exec'):
			self.assertEqual(path, self.check(path), path)

	def test_a_retired_path_is_not_a_place_to_return_to(self):
		# Ele existe no roteador, mas não é página: o login não devolve ninguém a
		# um endereço cujo único papel é mandar para outro
		for retired in page_routes.RETIRED_PAGES:
			self.assertIsNone(self.check(retired), retired)

	def test_everything_else_is_refused(self):
		hostile = (
			None, '', 12, [], {}, 'config', 'config/ia',
			'//evil.example', '//evil.example/config', '/\\evil.example', '\\\\evil.example',
			'https://evil.example', 'javascript:alert(1)', 'http:/evil.example',
			'/config?x=1', '/config#x', '/config/ia?next=/users',
			'/api/users', '/list', '/login', '/auth/sso/start', '/static/assets/js/bluephish.js',
			'/nada', '/config/nada', '/done/a/b', '/config//ia',
			# Casam com `/done/<case_ref>`, mas o navegador ou um proxy que decodifique
			# o `%2f` os transformaria em outro caminho: um GET arbitrário no painel
			'/done/..', '/done/.', '/queues/..', '/inbox/..', '/inbox/%2e%2e', '/exec/.', '/./exec', '/done/%2e%2e', '/done/..%2f..%2fapi%2fusers',
			'/done/%2fapi', '/config/%69a',
			'/config/ia\r\nSet-Cookie: a=b', '/config\n', '/config\x00', '/con fig',
			'/' + 'a' * 400, '/done/' + 'a' * 400,
		)
		for value in hostile:
			self.assertIsNone(self.check(value), repr(value))


class LoginReturnsToWhereTheUserWas(PagesBase):

	def login_with(self, username, next_path = None):
		body = {'username': username, 'password': gate.SENHA}
		if next_path is not None:
			body['next'] = next_path
		return self.client.post('/api/auth/login', json = body)

	def finish_enrollment(self, username):
		self.client.post('/api/auth/mfa/setup')
		return self.client.post('/api/auth/mfa/activate',
			json = {'code': gate.code_for(self.secret_of(username))})

	def test_the_login_page_carries_a_valid_next_to_the_script(self):
		body = self.client.get('/login?next=/config/ia').get_data(as_text = True)
		self.assertIn('data-next="/config/ia"', body)

	def test_the_login_page_never_echoes_a_hostile_next(self):
		for value in ('//evil.example', 'https://evil.example', '/api/users', '"><script>x</script>'):
			body = self.client.get('/login', query_string = {'next': value}).get_data(as_text = True)
			self.assertNotIn('evil.example', body, value)
			self.assertNotIn('<script>x', body, value)
			self.assertNotIn('data-next="/api', body, value)

	def test_enrollment_hands_back_the_page_the_user_wanted(self):
		self.create()
		self.login_with('analista', '/config/ia')
		answer = self.finish_enrollment('analista')
		self.assertEqual(200, answer.status_code)
		self.assertEqual('/config/ia', answer.get_json()['next'])

	def test_a_hostile_next_in_the_login_becomes_the_home_page(self):
		self.create()
		self.login_with('analista', '//evil.example')
		answer = self.finish_enrollment('analista')
		self.assertEqual('/', answer.get_json()['next'])

	def test_no_next_means_the_home_page(self):
		self.create()
		self.login_with('analista')
		self.assertEqual('/', self.finish_enrollment('analista').get_json()['next'])

	def test_the_second_factor_of_an_enrolled_account_hands_it_back_too(self):
		secret = self.enrolled_user()
		self.client.post('/api/auth/logout')
		self.login_with('analista', '/done/55')
		# Um código já usado não vale de novo: o seguinte é o da próxima janela
		code = gate.code_for(secret, time.time() + 30)
		answer = self.client.post('/api/auth/mfa/verify', json = {'code': code})
		self.assertEqual(200, answer.status_code, answer.get_data(as_text = True))
		self.assertEqual('/done/55', answer.get_json()['next'])

	def test_a_new_login_replaces_the_destination_of_the_old_challenge(self):
		self.create()
		self.login_with('analista', '/config/ia')
		self.login_with('analista', '/users')
		self.assertEqual('/users', self.finish_enrollment('analista').get_json()['next'])

	def test_a_signed_in_user_opening_login_goes_to_the_page_asked_for(self):
		self.enrolled_user()
		response = self.client.get('/login?next=/config/ia')
		self.assertEqual(302, response.status_code)
		self.assertEqual('/config/ia', urllib.parse.urlparse(response.headers['Location']).path)

	def test_a_signed_in_user_is_never_sent_to_a_hostile_next(self):
		self.enrolled_user()
		response = self.client.get('/login', query_string = {'next': '//evil.example'})
		self.assertEqual(302, response.status_code)
		self.assertNotIn('evil.example', response.headers['Location'])
		self.assertEqual('/', urllib.parse.urlparse(response.headers['Location']).path)


class NextSurvivesTheIdentityProvider(PagesBase):
	"""O retorno do Entra ID limpa a sessão; o destino tem de atravessar isso."""

	def setUp(self):
		super().setUp()
		self.saved = (auth.sso.is_available, auth.sso.load_config, auth.sso.begin, auth.sso.complete,
			auth.sso.role_for_claims)
		auth.sso.is_available = lambda config: True
		auth.sso.load_config = lambda: {}
		auth.sso.begin = lambda config, uri: ('https://idp.example/authorize', {'state': 'abc'})
		auth.sso.complete = lambda config, flow, args: ({'preferred_username': 'Pessoa@Empresa.Example'}, None)
		auth.sso.role_for_claims = lambda config, claims: ANALYST

	def tearDown(self):
		(auth.sso.is_available, auth.sso.load_config, auth.sso.begin, auth.sso.complete,
			auth.sso.role_for_claims) = self.saved
		super().tearDown()

	def stored(self, key):
		with self.client.session_transaction() as session:
			return session.get(key)

	def test_a_valid_next_is_kept_through_the_round_trip(self):
		start = self.client.get('/auth/sso/start?next=/config/ia')
		self.assertEqual(302, start.status_code)
		self.assertEqual('/config/ia', self.stored('sso_next'))
		self.client.get('/auth/sso/callback?code=1&state=abc')
		challenge = self.stored(auth.MFA_PENDING)
		self.assertEqual('/config/ia', challenge['next'])
		self.assertEqual('sso', challenge['source'])
		# O que foi guardado para a ida já cumpriu o papel dele
		self.assertIsNone(self.stored('sso_next'))

	def test_a_hostile_next_is_not_stored(self):
		self.client.get('/auth/sso/start', query_string = {'next': '//evil.example'})
		self.assertIsNone(self.stored('sso_next'))
		self.client.get('/auth/sso/callback?code=1&state=abc')
		self.assertIsNone(self.stored(auth.MFA_PENDING).get('next'))

	def test_the_login_page_points_the_sso_button_at_the_same_destination(self):
		body = self.client.get('/login?next=/config/ia').get_data(as_text = True)
		# Lido pelo destino, não pelo texto: o Werkzeug 2.0 da imagem escreve
		# next=%2Fconfig%2Fia e o mais novo, next=/config/ia — a mesma URL. Comparar
		# o texto literal deixou o CI vermelho na main desde o #57 sem bug nenhum
		href = re.search(r'id="ssoBtn" href="([^"]+)"', body).group(1)
		link = urllib.parse.urlsplit(href)
		self.assertEqual(link.path, '/auth/sso/start')
		self.assertEqual(urllib.parse.parse_qs(link.query), {'next': ['/config/ia']})

	def test_the_sso_button_stays_plain_without_a_destination(self):
		body = self.client.get('/login').get_data(as_text = True)
		self.assertIn('href="/auth/sso/start"', body)


class TheCaseLookupSaysWhatItDoesNotKnow(unittest.TestCase):
	"""GET /api/cases?ref= — lido no texto, porque thephish_app não se importa fora da imagem."""

	def route(self):
		source = read(os.path.join(BASE, 'thephish_app.py'))
		start = source.index("@app.route('/api/cases', methods = ['GET'])")
		return source[start:source.index("@app.route('/api/cases/<case_ref>', methods = ['GET'])")]

	def test_a_reference_is_checked_before_the_window_is_widened(self):
		route = self.route()
		self.assertIn('valid_record_ref(ref)', route)
		self.assertLess(route.index('valid_record_ref(ref)'), route.index("range_key = 'all'"))

	def test_the_ceiling_is_reported_not_swallowed(self):
		route = self.route()
		self.assertNotIn('_truncated', route)
		self.assertIn("'truncated': bool(truncated)", route)

	def test_the_destinations_that_did_not_answer_are_still_reported(self):
		# CLAUDE.md: `partial` e `notice` existem para dizer na tela o que falta
		route = self.route()
		self.assertIn("'partial': bool(failures)", route)
		self.assertIn("'notice': notice", route)


class TheScriptsFollowTheContract(unittest.TestCase):
	"""O que o navegador faz com os caminhos — conferido no texto, como em test_frontend_contract."""

	def setUp(self):
		self.panel = read(os.path.join(BASE, 'static', 'assets', 'js', 'bluephish.js'))
		self.login = read(os.path.join(BASE, 'static', 'assets', 'js', 'login.js'))
		self.login_html = read(os.path.join(BASE, 'templates', 'login.html'))

	def test_no_script_assigns_a_relative_address(self):
		# `location.href = "login"` resolve para /config/login a partir de /config/ia
		for name, script in (('bluephish.js', self.panel), ('login.js', self.login)):
			found = re.findall(r'location\.href\s*=\s*"(?![/#]|https?:)[^"]*"', script)
			self.assertEqual([], found, '{0}: endereço relativo {1}'.format(name, found))

	def test_no_element_is_given_a_relative_address(self):
		# O wrapper do fetch só cobre o fetch. Um <a href="api/whitelist/export"> criado
		# pelo script resolveria para /config/api/whitelist/export — foi o que o
		# download da whitelist fazia, e nenhum teste de texto de location.href o via
		for name, script in (('bluephish.js', self.panel), ('login.js', self.login)):
			found = re.findall(
				r'''\b(?:href|src|action)\s*[:=]\s*["'](?![/#]|https?:|blob:|data:|mailto:)[^"']*["']''', script)
			self.assertEqual([], found, '{0}: endereço relativo {1}'.format(name, found))

	def test_every_fetch_goes_through_the_absolute_address_helper(self):
		self.assertIn('function absolute_url(', self.panel)
		wrapper = self.panel[self.panel.index('window.fetch = function'):]
		wrapper = wrapper[:wrapper.index('handle_unauthorized(response)')]
		self.assertIn('absolute_url(', wrapper)

	def test_the_login_script_also_posts_to_absolute_addresses(self):
		self.assertIn('function absolute_url(', self.login)
		self.assertIn('absolute_url(url)', self.login)

	def test_the_login_forms_post_to_absolute_addresses(self):
		self.assertEqual([], re.findall(r'action="(?!/)[^"]*"', self.login_html))

	def test_the_login_script_goes_where_the_server_said(self):
		self.assertIn('result.data.next', self.login)
		self.assertIn('dataset.next', self.login)

	def test_the_login_script_distrusts_the_address_it_was_given(self):
		self.assertRegex(self.login, r'startsWith\("/"\)')
		self.assertRegex(self.login, r'startsWith\("//"\)')
		# "/\t/host" e "/\n/host": o navegador descarta o controle e lê "//host"
		self.assertIn(r'/[\u0000- \\]/', self.login)

	def test_an_expired_challenge_keeps_the_destination(self):
		leave = self.login[self.login.index('function leave_mfa('):]
		leave = leave[:leave.index('\n}')]
		self.assertIn('dataset.next', leave)

	def test_a_case_that_could_not_be_looked_up_is_not_called_missing(self):
		# Só "não encontrado" quando o servidor leu tudo; uma fonte fora do ar, o teto
		# de casos ou um erro dizem "não foi possível", e o endereço fica como está
		lookup = self.panel[self.panel.index('function open_case_by_ref('):]
		lookup = lookup[:lookup.index('\nfunction router_start(')]
		for flag in ('payload.error', 'payload.partial', 'payload.truncated'):
			self.assertIn(flag, lookup)
		# E uma resposta que chega depois de a pessoa ter ido para outro caso não vale
		self.assertIn('still_wanted()', lookup)

	def test_the_panel_follows_history(self):
		self.assertIn('history.pushState', self.panel)
		self.assertIn('history.replaceState', self.panel)
		self.assertIn('addEventListener("popstate"', self.panel)

	def test_the_router_waits_for_the_identity(self):
		identity = self.panel[self.panel.index('function load_identity('):]
		identity = identity[:identity.index('function do_logout(')]
		self.assertIn('router_start(', identity)
		# E o roteador não pode ter sido ligado antes de o papel ser conhecido
		boot = self.panel[self.panel.index('(function boot()'):]
		self.assertNotIn('router_start(', boot)

	def test_going_to_login_remembers_where_the_user_was(self):
		self.assertIn('function go_to_login(', self.panel)
		self.assertNotIn('location.href = "login"', self.panel)


if __name__ == '__main__':
	unittest.main()
