"""Entrada no painel pelo provedor de identidade da organização.

Até aqui a única porta era usuário e senha guardados aqui dentro: uma senha a
mais para cada analista, fora do MFA e das políticas condicionais que a
organização já aplica em todo o resto, e uma conta que continua funcionando
depois que a pessoa sai da empresa. Este módulo abre a segunda porta.

O protocolo é **OpenID Connect** com *authorization code + PKCE*, que é o que a
Microsoft recomenda para aplicação web que assina usuário no Entra ID — e não
SAML, apesar de o mock falar dele. Dois motivos, nessa ordem: é a recomendação
do próprio provedor para este caso, e a biblioteca já está na imagem (`msal`,
usada pelo acesso à caixa de e-mail), enquanto SAML exigiria `xmlsec1` compilado
sobre uma base Python 3.8. O segredo nunca sai do servidor; o navegador só
carrega o `code`, que sozinho não vale nada sem o `code_verifier` guardado na
sessão.

Quem entra e com qual cargo é decidido pelo **grupo no Entra ID**, não por uma
lista mantida aqui: um mapeamento digitado à mão fica errado no dia em que
alguém muda de time e ninguém atualiza. Um usuário cujos grupos não casam com
nenhum cargo é recusado — a ausência de mapeamento nega, nunca concede.

Formato do módulo:

  load_config()       a seção `sso` de configuration.json, normalizada. Nunca
                      levanta: configuração ilegível deixa o recurso desligado.

  is_configured()     se há tenant, client id, segredo e ao menos um grupo
                      mapeado. O botão na tela de login só aparece com isto.

  begin(redirect_uri) devolve (url_de_autorizacao, flow). O `flow` guarda o
                      state e o code_verifier, e vai para a sessão do usuário.

  complete(flow, args) devolve (claims, erro). Valida o código contra o mesmo
                      flow — um `state` que não bate é tentativa de forjar.

  role_for_claims()   grupo/app role do token → cargo, o mais alto que casar,
                      ou '' quando nenhum casa.

auth.py é quem conhece Flask, sessão e banco; este módulo é a configuração, o
cliente MSAL e a política de cargo em volta dele.
"""

import json

import msal

import models

CONFIG_SECTION = 'sso'

# Caminho fixo do retorno. É registrado no Entra ID como URI de redirecionamento
# e precisa bater byte a byte, então não é editável na tela: um campo livre aqui
# só produziria a diferença de barra final que quebra o login em produção
REDIRECT_PATH = '/auth/sso/callback'

# Nenhum escopo de recurso: só a identidade. A MSAL acrescenta openid, profile e
# offline_access sozinha. Pedir Graph aqui daria ao registro de aplicativo um
# poder que a autenticação não precisa
SCOPES = []

# Claims de onde o cargo pode vir. `roles` são as App Roles do registro de
# aplicativo (recomendado: não estoura, e o nome é legível); `groups` são os
# object ids dos grupos de segurança
ROLE_CLAIMS = ('roles', 'groups')

AUTHORITY_TEMPLATE = 'https://login.microsoftonline.com/{0}'


def default_config():
	"""O formato que a tela de configuração e o login esperam."""
	return {
		'enabled': False,
		'tenantId': '',
		'clientId': '',
		'clientSecret': '',
		# grupo (ou App Role) do Entra ID → cargo no painel. Uma lista por cargo
		'groupRoles': {role: [] for role in models.ROLES}
	}


def _clean_list(raw):
	"""Aceita lista ou texto com uma entrada por linha/vírgula, sem duplicatas."""
	if isinstance(raw, str):
		raw = raw.replace(',', '\n').split('\n')
	if not isinstance(raw, (list, tuple)):
		return []
	cleaned = []
	for item in raw:
		value = str(item or '').strip()
		# Um id de grupo tem 36 caracteres; um nome de App Role é curto. O corte
		# existe para que um paste acidental não vire uma entrada de 4 KB
		value = value[:128]
		if value and value not in cleaned:
			cleaned.append(value)
	return cleaned


def normalize_config(raw):
	"""Coage o que estiver em configuration.json para o formato documentado."""
	raw = raw if isinstance(raw, dict) else {}
	config = default_config()
	config['enabled'] = bool(raw.get('enabled', False))
	config['tenantId'] = str(raw.get('tenantId') or '').strip()
	config['clientId'] = str(raw.get('clientId') or '').strip()
	config['clientSecret'] = str(raw.get('clientSecret') or '')
	group_roles = raw.get('groupRoles') if isinstance(raw.get('groupRoles'), dict) else {}
	config['groupRoles'] = {role: _clean_list(group_roles.get(role)) for role in models.ROLES}
	return config


def load_config(path = 'configuration.json'):
	"""A seção `sso`, normalizada. Nunca levanta.

	Um arquivo ausente ou ilegível deixa o SSO desligado, que é o que todo
	chamador quer quando nem a configuração pode ser lida.
	"""
	try:
		with open(path) as conf_file:
			conf_dict = json.load(conf_file)
	except Exception:
		return default_config()
	return normalize_config(conf_dict.get(CONFIG_SECTION))


def has_mapping(config):
	"""Se algum cargo tem ao menos um grupo mapeado."""
	return any(config['groupRoles'].get(role) for role in models.ROLES)


def is_configured(config):
	"""Se o fluxo tem tudo de que precisa para acontecer.

	Sem mapeamento de grupo o login terminaria sempre em recusa, então isto
	conta como não configurado: um botão que só sabe negar é pior que botão
	nenhum.
	"""
	return bool(config['tenantId'] and config['clientId'] and config['clientSecret']) and has_mapping(config)


def is_available(config):
	"""Se o botão de SSO deve aparecer na tela de login."""
	return bool(config['enabled']) and is_configured(config)


def _client(config):
	# Sem cache de token: o painel usa o id_token uma vez, para saber quem é a
	# pessoa, e daí em diante a sessão é a nossa. Guardar refresh token seria
	# manter uma credencial do usuário que nada aqui consome
	return msal.ConfidentialClientApplication(
		config['clientId'],
		client_credential = config['clientSecret'],
		authority = AUTHORITY_TEMPLATE.format(config['tenantId'])
	)


def begin(config, redirect_uri):
	"""(url de autorização, flow). O flow guarda state e code_verifier."""
	flow = _client(config).initiate_auth_code_flow(scopes = list(SCOPES), redirect_uri = redirect_uri)
	if 'auth_uri' not in flow:
		raise RuntimeError('O Entra ID não devolveu a URL de autorização: {0}'.format(flow.get('error_description') or flow.get('error') or flow))
	return flow['auth_uri'], flow


def complete(config, flow, request_args):
	"""(claims, erro) a partir do retorno do Entra ID.

	A validação inteira — assinatura, emissor, audiência, nonce e o `state` que
	amarra o retorno ao pedido — é da MSAL. Um `state` que não bate levanta
	ValueError lá dentro, e é isso que a segunda cláusula transforma em recusa.
	"""
	try:
		result = _client(config).acquire_token_by_auth_code_flow(flow, request_args, scopes = list(SCOPES))
	except ValueError as e:
		# state ausente/divergente: o retorno não corresponde ao pedido guardado
		return None, 'A resposta do provedor não corresponde a este pedido de login ({0}).'.format(e)
	except Exception as e:
		return None, 'Não foi possível concluir o login com o provedor: {0}'.format(e)
	if 'error' in result:
		return None, '{0}: {1}'.format(result.get('error'), result.get('error_description') or '')
	claims = result.get('id_token_claims')
	if not claims:
		return None, 'O provedor não devolveu um token de identidade.'
	return claims, None


def username_from_claims(claims):
	"""O nome de usuário do painel: o UPN, ou o e-mail quando não houver."""
	for key in ('preferred_username', 'upn', 'email'):
		value = str((claims or {}).get(key) or '').strip()
		if value:
			return value[:64].lower()
	return ''


def groups_from_claims(claims):
	"""Tudo que o token oferece como grupo ou App Role, em uma lista só."""
	found = []
	for key in ROLE_CLAIMS:
		value = (claims or {}).get(key)
		if isinstance(value, str):
			value = [value]
		if isinstance(value, (list, tuple)):
			found.extend(str(item or '').strip() for item in value)
	return [item for item in found if item]


def has_group_overage(claims):
	"""Se o token omitiu os grupos por excesso (mais de ~200 por pessoa).

	Nesse caso o Entra ID manda `_claim_names` no lugar da lista, e decidir cargo
	pelo que sobrou daria o cargo errado — cai fora com erro em vez de conceder.
	"""
	names = (claims or {}).get('_claim_names')
	return isinstance(names, dict) and 'groups' in names


def role_for_claims(config, claims):
	"""O cargo mais alto cujos grupos casam com o token, ou '' se nenhum casa.

	A comparação ignora caixa porque um nome de App Role é digitado por gente nos
	dois lados. O mais alto vence: quem está no grupo de admin e no de analista
	entra como admin.
	"""
	present = {value.lower() for value in groups_from_claims(claims)}
	if not present:
		return ''
	# models.ROLES vai do menos ao mais privilegiado
	for role in reversed(models.ROLES):
		mapped = {value.lower() for value in config['groupRoles'].get(role) or []}
		if present & mapped:
			return role
	return ''
