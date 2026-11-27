"""Os caminhos das telas do painel — `/config/ia`, `/integr/tickets`, `/done/<caso>`, `/queues/<caso>`, `/inbox/<uid>`.

O painel é uma página só (`index.html`) que mostra uma tela por vez; até aqui a
URL não acompanhava a tela, e por isso não dava para mandar o link de uma
configuração nem voltar a ela depois de a sessão cair. Cada tela agora tem um
caminho próprio, e o servidor entrega o mesmo documento para todos eles.

Esta tabela é a única fonte de dois fatos:

* **Qual o papel mínimo de cada tela.** É a rota que decide quem a abre, não o
  JavaScript: esconder o item de menu nunca foi o controle (§3.2). As abas de SSO
  e de armazenamento da auditoria pedem `global_admin`, a mesma régua das rotas de
  dados que elas usam (`/sso-config`, `/audit-log-config`) — uma tela que abre e
  responde 403 em tudo o que mostra é pior do que uma que não abre.
* **Para onde o login pode devolver a pessoa.** `safe_next` só aceita um caminho
  que esteja aqui. Um `next` qualquer é redirecionamento aberto numa tela que
  acabou de pedir a senha.

Os identificadores são os mesmos `data-view`, `data-config-tab` e
`data-integr-tab` do `index.html` — `test_page_routes` confere os dois lados, de
modo que uma tela nova sem caminho (ou um caminho sem tela) falha o CI em vez de
passar despercebida. O JavaScript não repete esta tabela: ele lê as telas do
próprio DOM, e quem recusa um caminho que não existe é o servidor (404).
"""

import re

import flask
import flask_login
import werkzeug.exceptions

from models import ROLE_ADMIN, ROLE_ANALYST, ROLE_GLOBAL_ADMIN

# Papel mínimo de cada tela do painel
VIEW_ROLES = {
	'exec': ROLE_ANALYST,
	'intel': ROLE_ANALYST,
	'tactic': ROLE_ANALYST,
	'inbox': ROLE_ANALYST,
	'done': ROLE_ANALYST,
	'queues': ROLE_ANALYST,
	'account': ROLE_ANALYST,
	'audit': ROLE_ADMIN,
	'integr': ROLE_ADMIN,
	'config': ROLE_ADMIN,
	'users': ROLE_GLOBAL_ADMIN
}

# As abas de Configurações. SSO, o destino da trilha de auditoria e a política de
# segurança (auto logoff, duração da sessão) são de quem gerencia os usuários
# (global_admin), o mesmo critério do botão no painel
CONFIG_TABS = {
	'auto': ROLE_ADMIN,
	'ia': ROLE_ADMIN,
	'email': ROLE_ADMIN,
	'notificacao': ROLE_ADMIN,
	'caso': ROLE_ADMIN,
	'departamentos': ROLE_ADMIN,
	'whitelist': ROLE_ADMIN,
	'sso': ROLE_GLOBAL_ADMIN,
	'auditoria': ROLE_GLOBAL_ADMIN,
	'seguranca': ROLE_GLOBAL_ADMIN,
	# Trocar o certificado é trocar o que o navegador de todo mundo confia
	'certificados': ROLE_GLOBAL_ADMIN
}

# As abas de Integrações
INTEGR_TABS = {
	'analisadores': ROLE_ADMIN,
	'priorizacao': ROLE_ADMIN,
	'bloqueio': ROLE_ADMIN,
	'tickets': ROLE_ADMIN
}

# Um caso aberto no arquivo ou na mesa de trabalho. O parâmetro é o mesmo `ref` de
# /api/cases/<ref>
CASE_RULE = '/done/<case_ref>'
DESK_RULE = '/queues/<case_ref>'
# Um e-mail aberto na caixa monitorada. O parâmetro é o mailUID de /email/<uid>. Não
# existe consulta própria para ele: quem abre o endereço recebe a página, e o painel
# procura o e-mail na listagem que já tem (um que saiu da caixa só gera um aviso)
INBOX_RULE = '/inbox/<mail_uid>'

# Caminhos que já foram tela e deixaram de ser, e a tela que ficou no lugar.
# `/integr/plataforma` era o endereço em que Integrações abria — o que está nos
# favoritos e no histórico de quem administra o painel. A aba saiu (só espelhava
# o nome da exportação MISP, que é um campo do destino TheHive), e um 404 no
# endereço mais guardado da tela seria o jeito ruim de avisar. O destino é
# sempre um caminho fixo desta tabela: quem o abre passa pelo login e pelo papel
# da tela de destino, como qualquer outra navegação.
# `/chat` era a aba "Chat AI", em que o analista digitava o número de um caso para
# conversar sobre ele. A conversa ficou onde o caso está aberto (o botão Assistente
# de /done e /queues), com o contexto carregado sozinho; o destino é a tela dos casos.
RETIRED_PAGES = {
	'/integr/plataforma': '/integr',
	'/chat': '/done'
}

# Um endereço de página cabe folgado nisto. O teto existe para que o `next`, que
# viaja na URL e na sessão, não seja um lugar para guardar texto de quem quiser
MAX_NEXT_LENGTH = 200


def _build_pages():
	pages = []
	for view, role in VIEW_ROLES.items():
		pages.append(('/' + view, role))
		if view == 'config':
			pages.extend(('/config/' + tab, tab_role) for tab, tab_role in CONFIG_TABS.items())
		if view == 'integr':
			pages.extend(('/integr/' + tab, tab_role) for tab, tab_role in INTEGR_TABS.items())
		if view == 'done':
			pages.append((CASE_RULE, role))
		if view == 'queues':
			pages.append((DESK_RULE, role))
		if view == 'inbox':
			pages.append((INBOX_RULE, role))
	return tuple(pages)


# (regra, papel mínimo), na ordem em que o menu as mostra
PAGES = _build_pages()


def sample_path(rule):
	"""Um endereço concreto que casa com a regra, para quem precisa testá-lo."""
	return re.sub(r'<[^>]+>', 'sample', rule)


def _endpoint(rule):
	return 'page_' + re.sub(r'\W+', '_', rule).strip('_')


def _page_view(auth, rule, minimum_role):
	import access_profiles

	# Primeiro a pergunta "tem sessão?", que manda quem não tem para o login levando
	# o caminho em `next`; depois a do papel. Recusar por papel é um 403 de página —
	# o JSON que o `_deny` devolve serve para chamada de API, não para quem digitou
	# um endereço no navegador
	@auth.requires_analyst
	def view(**_values):
		user = flask_login.current_user
		# O perfil de acesso decide, para mais ou para menos que o cargo
		# (access_profiles); sem perfil, vale o cargo de sempre
		if not access_profiles.can_open_page(user, rule):
			auth.audit('authorization_denied', user.username, 'denied',
				'path={0} required={1} item={2}'.format(flask.request.path, minimum_role, access_profiles.page_item(rule)))
			flask.abort(403)
		response = flask.make_response(flask.render_template('index.html'))
		# O documento é o mesmo para todos e só abre para quem tem sessão. Sem
		# isto, o Voltar depois de sair reabriria a tela do cache do navegador
		response.headers['Cache-Control'] = 'no-store'
		return response
	return view


def register(app):
	# Importado aqui e não no topo: o auth.py importa este módulo (safe_next), e um
	# import circular deixaria um dos dois pela metade
	import auth
	for rule, minimum_role in PAGES:
		# strict_slashes desligado: `/config/` abre a mesma tela que `/config`, em
		# vez de dar 404 em quem copiou o endereço com a barra
		app.add_url_rule(rule, endpoint = _endpoint(rule), view_func = _page_view(auth, rule, minimum_role),
			methods = ['GET'], strict_slashes = False)
	for rule, target in RETIRED_PAGES.items():
		# O endpoint não começa por `page_` de propósito: `safe_next` só devolve o
		# login a um caminho de página, e este não é mais um
		app.add_url_rule(rule, endpoint = 'retired_' + re.sub(r'\W+', '_', rule).strip('_'),
			view_func = _retired_view(target), methods = ['GET'], strict_slashes = False)


def no_store_unless_static(response, endpoint):
	"""`Cache-Control: no-store` em toda resposta, menos nos arquivos de `/static`.

	O documento das telas já saía assim (`_page_view`); as respostas de dados não.
	Um `/api/cases` ou um `.eml` sem a ordem ficava disponível ao Voltar depois de
	sair e a qualquer proxy no caminho. Vale também para erro, login e exportação,
	e sobrescreve o `public, max-age` que um `send_file` ponha por conta própria.

	`/static` fica de fora de propósito: a semana de cache dele é o que impede a
	rajada de requisições de cada F5 de derrubar conexões do eventlet, e o que há ali
	é o mesmo arquivo para todo mundo (a versão vai na query string).
	"""
	if endpoint != 'static':
		response.headers['Cache-Control'] = 'no-store'
	return response


def _retired_view(target):
	def view():
		return flask.redirect(target)
	return view


def _is_plain_path(value):
	"""Texto que pode ser um caminho: sem consulta, âncora, barra invertida, espaço ou controle."""
	if not isinstance(value, str) or not value or len(value) > MAX_NEXT_LENGTH:
		return False
	# `//host` é "mesmo esquema, outro servidor", e `/\host` o navegador lê igual
	if not value.startswith('/') or value.startswith('//'):
		return False
	if any(char in '\\?#%' or char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
		return False
	# `%` fica de fora porque o caminho chega aqui já decodificado e um `%2f` ou
	# `%2e%2e` seria visto como letra pelo roteador e como separador por um proxy.
	# Pelo mesmo motivo, nenhum segmento pode ser `.` ou `..`: `/done/<case_ref>`
	# casaria com `/done/..`, que o navegador normaliza para outro caminho
	return not any(part in ('.', '..') for part in value.split('/'))


def safe_next(value):
	"""O caminho de página a que o login pode devolver a pessoa, ou None.

	Só vale o que o servidor reconhece como página deste painel: nada de outro
	site, nada de rota de dados (`/api/...`), nada com consulta ou âncora. O
	valor devolvido é o próprio caminho recebido — nunca um endereço montado a
	partir dele.
	"""
	if not _is_plain_path(value):
		return None
	if value == '/':
		return value
	try:
		endpoint, _values = flask.current_app.url_map.bind('localhost').match(value, method = 'GET')
	except werkzeug.exceptions.HTTPException:
		return None
	return value if endpoint.startswith('page_') else None
