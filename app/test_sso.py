"""Testes da entrada por SSO corporativo.

O que pode dar errado aqui não é a rede — é a decisão de *quem entra*. Um token
sem grupo mapeado, um token com grupos demais para caber nele, um botão numa
instalação sem provedor: os três terminam em acesso concedido a quem não devia,
se ninguém fixar o contrário. É isso que estes testes prendem. Nenhum toca o
Entra ID; o que se testa é a política em volta dele.

Roda com:  python -m unittest test_sso   (a partir do diretório app/)
"""

import unittest

import models
import sso


def config(**overrides):
	built = sso.default_config()
	built['enabled'] = True
	built['tenantId'] = 'tenant'
	built['clientId'] = 'client'
	built['clientSecret'] = 'secret'
	built['groupRoles'] = {
		models.ROLE_ANALYST: ['grupo-analistas'],
		models.ROLE_ADMIN: ['grupo-admins'],
		models.ROLE_GLOBAL_ADMIN: ['grupo-donos']
	}
	built.update(overrides)
	return sso.normalize_config(built)


class Normalizacao(unittest.TestCase):

	def test_uma_configuracao_vazia_deixa_o_sso_desligado(self):
		empty = sso.normalize_config(None)
		self.assertFalse(empty['enabled'])
		self.assertFalse(sso.is_available(empty))

	def test_grupos_aceitam_texto_em_linhas_e_viram_lista(self):
		built = sso.normalize_config({'groupRoles': {models.ROLE_ADMIN: 'um\ndois, tres\n\n  um  '}})
		# Sem vazios e sem repetição: colar de uma planilha não pode duplicar regra
		self.assertEqual(['um', 'dois', 'tres'], built['groupRoles'][models.ROLE_ADMIN])

	def test_um_paste_gigante_e_cortado(self):
		built = sso.normalize_config({'groupRoles': {models.ROLE_ANALYST: ['x' * 500]}})
		self.assertEqual(128, len(built['groupRoles'][models.ROLE_ANALYST][0]))

	def test_todo_cargo_conhecido_tem_uma_lista(self):
		built = sso.normalize_config({'groupRoles': {'inventado': ['x']}})
		self.assertEqual(sorted(models.ROLES), sorted(built['groupRoles'].keys()))


class Disponibilidade(unittest.TestCase):
	"""O botão na tela de login só existe quando ele pode terminar em entrada."""

	def test_configuracao_completa_e_ligada_oferece_o_botao(self):
		self.assertTrue(sso.is_available(config()))

	def test_sem_segredo_nao_ha_botao(self):
		self.assertFalse(sso.is_available(config(clientSecret = '')))

	def test_sem_tenant_nao_ha_botao(self):
		self.assertFalse(sso.is_available(config(tenantId = '')))

	def test_desligado_nao_ha_botao(self):
		self.assertFalse(sso.is_available(config(enabled = False)))

	def test_sem_nenhum_grupo_mapeado_nao_ha_botao(self):
		"""Um botão que só sabe recusar é pior que botão nenhum."""
		vazio = config(groupRoles = {role: [] for role in models.ROLES})
		self.assertFalse(sso.is_configured(vazio))
		self.assertFalse(sso.is_available(vazio))


class NomeDeUsuario(unittest.TestCase):

	def test_o_upn_e_a_primeira_escolha(self):
		self.assertEqual('ana@acme.com', sso.username_from_claims({
			'preferred_username': 'Ana@ACME.com', 'email': 'outra@acme.com'}))

	def test_o_email_serve_quando_nao_ha_upn(self):
		self.assertEqual('ana@acme.com', sso.username_from_claims({'email': 'ana@acme.com'}))

	def test_um_token_sem_identificador_nao_vira_usuario(self):
		self.assertEqual('', sso.username_from_claims({'name': 'Ana'}))


class CargoPorGrupo(unittest.TestCase):

	def test_o_grupo_mapeado_define_o_cargo(self):
		self.assertEqual(models.ROLE_ADMIN, sso.role_for_claims(config(), {'groups': ['grupo-admins']}))

	def test_app_roles_valem_como_grupo(self):
		self.assertEqual(models.ROLE_ANALYST, sso.role_for_claims(config(), {'roles': ['grupo-analistas']}))

	def test_a_comparacao_ignora_caixa(self):
		"""Nome de App Role é digitado por gente nos dois lados."""
		self.assertEqual(models.ROLE_ADMIN, sso.role_for_claims(config(), {'roles': ['Grupo-Admins']}))

	def test_quem_esta_em_dois_grupos_entra_pelo_mais_alto(self):
		claims = {'groups': ['grupo-analistas', 'grupo-donos', 'grupo-admins']}
		self.assertEqual(models.ROLE_GLOBAL_ADMIN, sso.role_for_claims(config(), claims))

	def test_grupo_nao_mapeado_nao_entra(self):
		self.assertEqual('', sso.role_for_claims(config(), {'groups': ['grupo-do-financeiro']}))

	def test_token_sem_grupo_nenhum_nao_entra(self):
		"""A ausência de mapeamento nega; nunca concede o cargo mais baixo."""
		self.assertEqual('', sso.role_for_claims(config(), {'preferred_username': 'ana@acme.com'}))

	def test_configuracao_sem_mapeamento_nao_entra(self):
		vazio = config(groupRoles = {role: [] for role in models.ROLES})
		self.assertEqual('', sso.role_for_claims(vazio, {'groups': ['grupo-donos']}))


class ExcessoDeGrupos(unittest.TestCase):
	"""Acima de ~200 grupos o Entra ID manda um ponteiro em vez da lista.

	Decidir cargo pelo que sobrou daria o cargo errado — silenciosamente, e para
	baixo ou para cima conforme o que coubesse. Tem de ser recusa.
	"""

	def test_o_ponteiro_de_excesso_e_reconhecido(self):
		self.assertTrue(sso.has_group_overage({'_claim_names': {'groups': 'src1'}}))

	def test_um_token_normal_nao_e_confundido_com_excesso(self):
		self.assertFalse(sso.has_group_overage({'groups': ['grupo-admins']}))
		self.assertFalse(sso.has_group_overage({}))


class MensagensDeRecusa(unittest.TestCase):
	"""A tela de login recebe código, nunca texto de fora.

	Um parâmetro de URL que vira frase deixa qualquer um montar um /login?erro=…
	dizendo o que quiser numa página que pede senha.
	"""

	def test_os_codigos_de_erro_sao_todos_identificadores_simples(self):
		import auth
		for code in auth.SSO_ERRORS:
			self.assertRegex(code, r'^[a-z_]+$')


if __name__ == '__main__':
	unittest.main()
