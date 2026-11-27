"""Perfis de acesso: o que cada pessoa vê e usa, além (ou aquém) do cargo.

Dois analistas podem ver telas diferentes: o global_admin cria perfis — "Analista
N1", "Analista de ameaças", "Auditor" — marcando, num catálogo, as telas, as
abas e as ações que cada um libera, e dá um perfil a cada conta. Sem perfil,
vale o que o cargo sempre deu. Com perfil, vale exatamente o que o perfil diz,
para mais ou para menos que o cargo: um analista pode ganhar a aba de IA, um
admin pode perder a de bloqueio.

**O controle é o servidor, em toda rota.** Esconder o item de menu é conveniência
(§3.2). `auth.requires_role` pergunta aqui (`allows`) antes de olhar o cargo:
cada rota protegida declara em ENDPOINT_ITEMS a que tela ou ação pertence, e
quem não tem nenhuma delas recebe 403. As telas (`page_routes`) perguntam
`can_open_page`. test_access_profiles confere que toda rota protegida está nesta
tabela ou, de propósito, em ROLE_ONLY — uma rota nova esquecida aqui seria uma
rota que o perfil não governa, e falha o CI em vez de passar despercebida.

O catálogo vem de page_routes (as telas e abas que existem), com o cargo
padrão de cada uma, mais as ações que moram dentro de telas compartilhadas e
que o cargo sempre separou (desfazer reclassificação, editar a whitelist...).

Três regras que não são óbvias:

1. **Usuários e perfis é do global_admin, e de mais ninguém.** Quem distribui
   acesso precisa ter todo o acesso: a tela de usuários dada a um analista seria
   um global_admin com outro nome — ele criaria uma conta global_admin, ou se
   daria um perfil com tudo, num clique. Ela não aparece no catálogo, nenhum
   perfil a tira de um global_admin (ninguém se tranca fora por um perfil mal
   montado), e as rotas dela ficam em ROLE_ONLY.

2. **Minha conta vale para todos.** Trocar a própria senha e ver o próprio
   segundo fator não depende de perfil.

3. **Uma tela-mãe abre se alguma aba dela abre.** /config e /integr não são itens
   do catálogo: abrem para quem tem ao menos uma aba, e a tela mostra só as que
   o perfil libera.
"""

import json
import logging

import flask

import models
import page_routes
from models import ROLES, ROLE_ADMIN, ROLE_GLOBAL_ADMIN

log = logging.getLogger('access_profiles')

MAX_NAME = 64
MAX_DESCRIPTION = 300

# Telas que não entram no catálogo: a conta é de todos, Usuários é do
# global_admin, e config/integr abrem pelas abas (regras 1 a 3)
ALWAYS = ('account',)
GLOBAL_ADMIN_ONLY = ('users',)
PARENTS = ('config', 'integr')

LABELS = {
	'exec': 'Visão executiva',
	'intel': 'Panorama externo',
	'tactic': 'Painel tático',
	'inbox': 'Caixa de entrada',
	'done': 'Casos analisados',
	'queues': 'Mesa de trabalho',
	'audit': 'Auditoria',
	'config.auto': 'Análise automática',
	'config.ia': 'IA',
	'config.email': 'E-mail',
	'config.notificacao': 'Notificações',
	'config.caso': 'Caso',
	'config.departamentos': 'Departamentos',
	'config.whitelist': 'Whitelist',
	'config.sso': 'SSO',
	'config.auditoria': 'Auditoria (armazenamento)',
	'config.seguranca': 'Segurança',
	'config.certificados': 'Certificados',
	'integr.analisadores': 'Analisadores',
	'integr.priorizacao': 'Priorização',
	'integr.bloqueio': 'Bloqueio',
	'integr.tickets': 'Tickets',
	'action.reclassify_revert': 'Desfazer reclassificação de um caso',
	'action.block': 'Bloquear indicadores de um caso no firewall',
	'action.whitelist_edit': 'Criar, editar e importar regras de whitelist',
	'action.whitelist_permanent': 'Regra de whitelist permanente e migração da whitelist antiga',
	'action.verdict_memory': 'Revogar e dispensar memórias de veredito',
	'action.intel_sources': 'Escolher as fontes e o resumo do Panorama externo'
}

ACTION_ROLES = {
	'action.reclassify_revert': ROLE_ADMIN,
	'action.block': ROLE_ADMIN,
	'action.whitelist_edit': ROLE_ADMIN,
	'action.whitelist_permanent': ROLE_GLOBAL_ADMIN,
	'action.verdict_memory': ROLE_ADMIN,
	'action.intel_sources': ROLE_ADMIN
}


def _catalogue():
	items = []
	for view, role in page_routes.VIEW_ROLES.items():
		if view in ALWAYS or view in GLOBAL_ADMIN_ONLY:
			continue
		if view == 'config':
			items.extend(('config.' + tab, tab_role, 'Configurações') for tab, tab_role in page_routes.CONFIG_TABS.items())
		elif view == 'integr':
			items.extend(('integr.' + tab, tab_role, 'Integrações') for tab, tab_role in page_routes.INTEGR_TABS.items())
		else:
			items.append((view, role, 'Telas'))
	items.extend((item, role, 'Ações') for item, role in ACTION_ROLES.items())
	return tuple({'id': item, 'role': role, 'group': group, 'label': LABELS.get(item, item)} for item, role, group in items)


CATALOGUE = _catalogue()
CATALOGUE_IDS = tuple(entry['id'] for entry in CATALOGUE)
DEFAULT_ROLE = {entry['id']: entry['role'] for entry in CATALOGUE}

# Abas de configuração do global_admin: um perfil pode tirá-las, nunca dá-las a
# um cargo abaixo. Quem tem SSO mapeia o próprio grupo para global_admin no
# próximo login; quem tem Certificados troca o TLS de todo mundo; quem tem
# Auditoria cega a trilha; Segurança afrouxa a política de sessão. Dar qualquer
# uma delas por perfil seria dar o cargo inteiro, que a regra 1 proíbe. As ações
# (a regra de whitelist permanente) seguem o perfil, de propósito
ROLE_BOUND = frozenset(entry['id'] for entry in CATALOGUE
	if entry['role'] == ROLE_GLOBAL_ADMIN and entry['id'].startswith('config.'))

# Qualquer pessoa autenticada: o que o painel inteiro consulta para se montar
PANEL = 'panel'

# A que tela ou ação cada rota protegida pertence. Uma tupla: basta ter uma.
# As leituras que várias telas usam (os casos aparecem na Visão executiva, no
# Painel tático, em Casos analisados e na Mesa de trabalho) abrem para quem
# tem qualquer uma delas
CASES_READ = ('done', 'queues', 'exec', 'tactic')
ENDPOINT_ITEMS = {
	# Caixa de entrada (a Mesa de trabalho abre e analisa os mesmos e-mails)
	'obtain_emails_to_analyze': ('inbox', 'queues'),
	'load_email_body': ('inbox', 'queues'),
	'render_email_as_delivered': ('inbox', 'queues'),
	'analyze_selected_emails': ('inbox', 'queues'),
	'analyze_email': ('inbox', 'queues'),
	# O painel em si (/) e o que ele lê para se montar (status do agendador e da
	# leitura da caixa). O JavaScript leva cada um à primeira tela que abre
	'homepage': PANEL,
	'get_scheduler': PANEL,
	'get_inbox_poll': PANEL,
	# Configurações
	'update_scheduler': ('config.auto',),
	# Só a aba: ligar e desligar a leitura da caixa não é da tela Caixa de entrada
	'update_inbox_poll': ('config.auto',),
	'get_llm_config': ('config.ia',),
	'update_llm_config': ('config.ia',),
	'list_llm_models': ('config.ia',),
	'get_verdict_config': ('config.ia',),
	'update_verdict_config': ('config.ia',),
	'get_email_config': ('config.email',),
	'update_email_config': ('config.email',),
	'get_smtp_config': ('config.email', 'config.notificacao'),
	'update_smtp_config': ('config.email', 'config.notificacao'),
	'test_smtp_config': ('config.email', 'config.notificacao'),
	'get_volume_alerts': ('config.notificacao',),
	'update_volume_alerts': ('config.notificacao',),
	'create_alert_connector': ('config.notificacao',),
	'preview_alert_connector': ('config.notificacao',),
	'update_alert_connector': ('config.notificacao',),
	'delete_alert_connector': ('config.notificacao',),
	'test_alert_connector': ('config.notificacao',),
	'get_case_config': ('config.caso',),
	'update_case_config': ('config.caso',),
	'get_case_evidence_config': ('config.caso',),
	'update_case_evidence_config': ('config.caso',),
	'get_departments_config': ('config.departamentos',),
	'update_departments_config': ('config.departamentos',),
	'test_departments_config': ('config.departamentos',),
	'get_sso_config': ('config.sso',),
	'update_sso_config': ('config.sso',),
	'get_audit_log_config': ('config.auditoria',),
	'update_audit_log_config': ('config.auditoria',),
	'test_audit_log_config': ('config.auditoria',),
	'get_security_config': ('config.seguranca',),
	'update_security_config': ('config.seguranca',),
	'update_protection_config': ('config.seguranca',),
	'update_captcha_config': ('config.seguranca',),
	'unban_address': ('config.seguranca',),
	'get_cert_config': ('config.certificados',),
	'upload_cert_pem': ('config.certificados',),
	'upload_cert_pfx': ('config.certificados',),
	'generate_cert_self_signed': ('config.certificados',),
	'reissue_internal_cert': ('config.certificados',),
	'save_letsencrypt_config': ('config.certificados',),
	'issue_letsencrypt_cert': ('config.certificados',),
	# Whitelist: ler é de quem vê a aba ou os casos; mexer é ação à parte
	'get_whitelist': ('config.whitelist',) + CASES_READ,
	'whitelist_rule_suppressions': ('config.whitelist',) + CASES_READ,
	'whitelist_export': ('config.whitelist',),
	'whitelist_dry_run': ('action.whitelist_edit',),
	'whitelist_url_suggest': ('action.whitelist_edit',),
	'whitelist_url_test': ('action.whitelist_edit',),
	'whitelist_rule_create': ('action.whitelist_edit',),
	'whitelist_rule_update': ('action.whitelist_edit',),
	'whitelist_rule_delete': ('action.whitelist_edit',),
	'whitelist_rule_renew': ('action.whitelist_edit',),
	'whitelist_rule_resume': ('action.whitelist_edit',),
	'whitelist_import': ('action.whitelist_edit',),
	'whitelist_migrate': ('action.whitelist_permanent',),
	'api_verdict_memory': ('config.whitelist',),
	'api_verdict_memory_revoke': ('action.verdict_memory',),
	'api_verdict_memory_dismiss': ('action.verdict_memory',),
	# Auditoria
	'audit_list': ('audit',),
	'audit_export': ('audit',),
	'audit_assistant_context': ('audit',),
	'audit_assistant': ('audit',),
	# Integrações
	'get_analyzers': ('integr.analisadores',),
	'create_custom_analyzer': ('integr.analisadores',),
	'update_custom_analyzer': ('integr.analisadores',),
	'delete_custom_analyzer': ('integr.analisadores',),
	'test_custom_analyzer': ('integr.analisadores',),
	'update_analyzer': ('integr.analisadores',),
	'test_analyzer': ('integr.analisadores',),
	'get_feeds': ('integr.analisadores',),
	'refresh_feed': ('integr.analisadores',),
	'enable_recommended_feeds': ('integr.analisadores',),
	'get_scoring': ('integr.priorizacao',),
	'update_scoring': ('integr.priorizacao',),
	'get_responders': ('integr.bloqueio', 'action.block'),
	'update_responder': ('integr.bloqueio',),
	'test_responder': ('integr.bloqueio',),
	'block_indicators': ('action.block',),
	'get_tickets': ('integr.tickets',),
	'update_ticket_destination': ('integr.tickets',),
	'test_ticket_destination': ('integr.tickets',),
	'get_connectors': ('integr.tickets',),
	'create_connector': ('integr.tickets',),
	'preview_connector': ('integr.tickets',),
	'update_connector': ('integr.tickets',),
	'delete_connector': ('integr.tickets',),
	'test_connector': ('integr.tickets',),
	# Casos
	'api_cases': CASES_READ,
	'api_case_detail': CASES_READ,
	'api_case_scope': CASES_READ,
	'api_case_rendered': CASES_READ,
	'api_case_reanalyze': ('done', 'queues'),
	'api_case_reclassify': ('done', 'queues'),
	'api_case_reclassify_revert': ('action.reclassify_revert',),
	'chat_load': ('done', 'queues'),
	'chat_message': ('done', 'queues'),
	'api_insights': ('exec', 'tactic'),
	'api_insights_windows': ('exec', 'tactic'),
	# Panorama externo
	'api_threat_intel': ('intel', 'exec'),
	'api_threat_intel_sources': ('intel',),
	'api_threat_intel_summary': ('intel',),
	'api_threat_intel_sources_save': ('action.intel_sources',),
	'api_threat_intel_recommended': ('action.intel_sources',),
	'api_threat_intel_summary_config': ('action.intel_sources',),
	'api_threat_intel_summary_config_save': ('action.intel_sources',),
	'api_threat_intel_refresh': ('action.intel_sources',),
}

# Rotas protegidas que, de propósito, seguem só o cargo: a gestão de usuários e
# perfis (regra 1) e a própria senha (regra 2)
ROLE_ONLY = (
	'api_list_users', 'api_create_user', 'api_delete_user', 'api_set_role', 'api_reset_mfa',
	'api_unlock_user', 'api_change_password',
	'api_list_profiles', 'api_create_profile', 'api_update_profile', 'api_delete_profile', 'api_set_profile'
)


def role_items(role):
	"""Os itens que o cargo dá quando a conta não tem perfil."""
	level = ROLES.index(role) if role in ROLES else 0
	return frozenset(item for item, minimum in DEFAULT_ROLE.items() if level >= ROLES.index(minimum))


def parse_items(text):
	"""Os itens válidos gravados num perfil. Item que saiu do catálogo é ignorado."""
	try:
		stored = json.loads(text or '[]')
	except ValueError:
		log.error('perfil com itens ilegíveis; vale nenhum item')
		return frozenset()
	if not isinstance(stored, list):
		return frozenset()
	return frozenset(item for item in stored if item in CATALOGUE_IDS)


def _profile_items(profile_id):
	session = models.get_session()
	try:
		profile = session.query(models.AccessProfile).get(profile_id)
		# Perfil apagado por baixo (a tela recusa apagar perfil em uso) não dá
		# nada — nem cai no cargo, que seria dar mais em silêncio
		return parse_items(profile.items) if profile is not None else frozenset()
	finally:
		session.close()


def effective_items(user):
	"""O que esta conta pode usar agora. Lido uma vez por requisição."""
	key = (user.id, user.profile_id, user.role)
	cache = getattr(flask.g, '_access_items', None) if flask.has_app_context() else None
	if cache is not None and cache[0] == key:
		return cache[1]
	if user.profile_id is None:
		items = role_items(user.role)
	else:
		items = frozenset(item for item in _profile_items(user.profile_id)
			if item not in ROLE_BOUND or user.has_role_at_least(DEFAULT_ROLE[item]))
	if flask.has_app_context():
		flask.g._access_items = (key, items)
	return items


def allows(user, endpoint, minimum_role):
	"""Se a conta pode usar a rota. A regra que auth.requires_role aplica."""
	items = ENDPOINT_ITEMS.get(endpoint)
	if items is None:
		return user.has_role_at_least(minimum_role)
	if items == PANEL:
		return True
	granted = effective_items(user)
	return any(item in granted for item in items)


def can_open_item(user, item):
	if item in ALWAYS:
		return True
	if item in GLOBAL_ADMIN_ONLY:
		return user.has_role_at_least(ROLE_GLOBAL_ADMIN)
	granted = effective_items(user)
	if item in PARENTS:
		return any(entry.startswith(item + '.') for entry in granted)
	return item in granted


def page_item(rule):
	"""O item do catálogo que governa uma rota de tela de page_routes."""
	parts = [part for part in rule.strip('/').split('/') if part]
	if not parts:
		return None
	if parts[0] in PARENTS and len(parts) > 1:
		return parts[0] + '.' + parts[1]
	return parts[0]


def can_open_page(user, rule):
	item = page_item(rule)
	return item is None or can_open_item(user, item)


def visible(user):
	"""O que a tela recebe em /api/auth/me para montar o menu."""
	granted = set(effective_items(user))
	granted.update(ALWAYS)
	if user.has_role_at_least(ROLE_GLOBAL_ADMIN):
		granted.update(GLOBAL_ADMIN_ONLY)
	for parent in PARENTS:
		if any(item.startswith(parent + '.') for item in granted):
			granted.add(parent)
	return sorted(granted)


def validate(payload):
	"""(nome, descrição, itens, erro) a partir do formulário da tela."""
	name = str(payload.get('name') or '').strip()
	description = str(payload.get('description') or '').strip()
	items = payload.get('items')
	if isinstance(items, str):
		try:
			items = json.loads(items)
		except ValueError:
			items = None
	if not name or len(name) > MAX_NAME:
		return None, None, None, 'O nome do perfil vai de 1 a {0} caracteres.'.format(MAX_NAME)
	if len(description) > MAX_DESCRIPTION:
		return None, None, None, 'A descrição vai até {0} caracteres.'.format(MAX_DESCRIPTION)
	if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
		return None, None, None, 'A lista de telas e ações do perfil é inválida.'
	unknown = [item for item in items if item not in CATALOGUE_IDS]
	if unknown:
		return None, None, None, 'Item desconhecido no perfil: {0}.'.format(', '.join(unknown)[:200])
	ordered = [item for item in CATALOGUE_IDS if item in items]
	return name, description, ordered, None


def profile_dict(profile, users = 0):
	return {
		'id': profile.id,
		'name': profile.name,
		'description': profile.description or '',
		'items': [item for item in CATALOGUE_IDS if item in parse_items(profile.items)],
		'users': users
	}
