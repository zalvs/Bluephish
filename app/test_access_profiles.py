"""Testes dos perfis de acesso (access_profiles.py).

O que se prende aqui, e por que cada um falharia em silêncio:

  * **Toda rota protegida pertence a uma tela ou ação, ou está em ROLE_ONLY de
    propósito.** Uma rota nova esquecida no mapa seria uma rota que o perfil
    não governa: o perfil tiraria a tela do menu e a API continuaria aberta.
  * **O perfil dá e tira, no servidor**: um analista com a aba IA lê e grava a
    configuração da IA; um admin sem a aba Bloqueio recebe 403 na rota dela, e
    na página.
  * **Sem perfil, vale o que o cargo sempre deu** — uma instalação que nunca
    criou perfil não muda nada.
  * **Usuários e perfis é do global_admin, e nenhum perfil mexe nisso**: nem dá a
    um analista, nem tira de um global_admin.
  * **Perfil em uso não se apaga**, e um perfil apagado por baixo não cai no cargo.
  * **Minha conta abre para todos.**

Roda com:  python -m unittest test_access_profiles   (a partir do diretório app/)
"""

import json
import unittest

import access_profiles
import models
import page_routes
import test_security_policy
from test_security_policy import AUTOMATIC

thephish_app = test_security_policy.thephish_app


class Catalogo(unittest.TestCase):

	def test_toda_tela_e_aba_do_painel_tem_item_ou_regra(self):
		for view in page_routes.VIEW_ROLES:
			if view in access_profiles.ALWAYS + access_profiles.GLOBAL_ADMIN_ONLY + access_profiles.PARENTS:
				continue
			self.assertIn(view, access_profiles.CATALOGUE_IDS)
		for tab in page_routes.CONFIG_TABS:
			self.assertIn('config.' + tab, access_profiles.CATALOGUE_IDS)
		for tab in page_routes.INTEGR_TABS:
			self.assertIn('integr.' + tab, access_profiles.CATALOGUE_IDS)

	def test_todo_item_tem_nome_para_a_tela(self):
		for entry in access_profiles.CATALOGUE:
			self.assertNotEqual(entry['id'], entry['label'], entry['id'])

	def test_usuarios_nao_esta_no_catalogo(self):
		self.assertNotIn('users', access_profiles.CATALOGUE_IDS)

	def test_o_mapa_so_cita_itens_que_existem(self):
		for endpoint, items in access_profiles.ENDPOINT_ITEMS.items():
			if items == access_profiles.PANEL:
				continue
			for item in items:
				self.assertIn(item, access_profiles.CATALOGUE_IDS, endpoint)

	def test_sem_perfil_o_cargo_da_o_que_sempre_deu(self):
		analyst = access_profiles.role_items(models.ROLE_ANALYST)
		admin = access_profiles.role_items(models.ROLE_ADMIN)
		self.assertIn('inbox', analyst)
		self.assertNotIn('config.ia', analyst)
		self.assertIn('config.ia', admin)
		self.assertNotIn('config.seguranca', admin)
		self.assertNotIn('action.whitelist_permanent', admin)
		self.assertIn('config.seguranca', access_profiles.role_items(models.ROLE_GLOBAL_ADMIN))

	def test_validacao(self):
		self.assertIsNone(access_profiles.validate({'name': 'N1', 'items': ['inbox']})[3])
		self.assertIn('desconhecido', access_profiles.validate({'name': 'N1', 'items': ['users']})[3])
		self.assertIsNotNone(access_profiles.validate({'name': '', 'items': []})[3])
		self.assertIsNotNone(access_profiles.validate({'name': 'x', 'items': 'não é lista'})[3])
		# A ordem gravada é a do catálogo, não a de quem marcou
		self.assertEqual(['inbox', 'config.ia'], access_profiles.validate({'name': 'x', 'items': ['config.ia', 'inbox']})[2])


@unittest.skipIf(thephish_app is None, 'thephish_app precisa da imagem')
class TodaRotaProtegidaPertenceAUmaTela(unittest.TestCase):

	def test_nenhuma_rota_protegida_fora_do_mapa(self):
		missing = []
		for endpoint, view in thephish_app.app.view_functions.items():
			if getattr(view, 'required_role', None) is None or endpoint.startswith('page_'):
				continue
			if endpoint not in access_profiles.ENDPOINT_ITEMS and endpoint not in access_profiles.ROLE_ONLY:
				missing.append(endpoint)
		self.assertEqual([], sorted(missing), 'rotas protegidas sem tela no mapa de access_profiles')

	def test_o_mapa_nao_tem_rota_que_nao_existe(self):
		stale = [endpoint for endpoint in list(access_profiles.ENDPOINT_ITEMS) + list(access_profiles.ROLE_ONLY)
			if endpoint not in thephish_app.app.view_functions]
		self.assertEqual([], stale)


@unittest.skipIf(thephish_app is None, 'thephish_app precisa da imagem')
class PeloServidor(test_security_policy.RotaSoDeGlobalAdmin):
	"""O perfil decidindo na aplicação de verdade, rota e página."""

	def profile(self, name, items):
		session = models.get_session()
		try:
			profile = models.AccessProfile(name = name, items = json.dumps(items))
			session.add(profile)
			session.commit()
			return profile.id
		finally:
			session.close()

	def assign(self, role, profile_id):
		username = 'pessoa-' + role
		session = models.get_session()
		try:
			user = session.query(models.User).filter(models.User.username == username).first()
			user.profile_id = profile_id
			session.commit()
		finally:
			session.close()

	def signed_in_with(self, role, items):
		client = self.signed_in(role)
		self.assign(role, self.profile('perfil-' + role, items))
		return client

	def events(self):
		return [event for event, _ in self.audited]

	def test_perfil_da_a_um_analista_a_aba_de_ia(self):
		client = self.signed_in_with(models.ROLE_ANALYST, ['inbox', 'config.ia'])
		self.assertEqual(200, client.get('/llm-config', headers = AUTOMATIC).status_code)
		self.assertEqual(200, client.get('/config/ia').status_code)
		self.assertEqual(200, client.get('/config').status_code)
		# O que o perfil não deu continua fechado, mesmo sendo da mesma tela-mãe
		self.assertEqual(403, client.get('/email-config', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/config/email').status_code)

	def test_perfil_tira_de_um_admin_a_aba_de_bloqueio(self):
		client = self.signed_in_with(models.ROLE_ADMIN, ['inbox', 'integr.analisadores'])
		self.assertEqual(403, client.get('/api/responders', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/integr/bloqueio').status_code)
		self.assertEqual(200, client.get('/integr/analisadores').status_code)

	def test_perfil_sem_a_caixa_fecha_a_caixa(self):
		client = self.signed_in_with(models.ROLE_ANALYST, ['done'])
		self.assertEqual(403, client.get('/list', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/inbox').status_code)
		self.assertEqual(200, client.get('/api/cases', headers = AUTOMATIC).status_code)

	def test_sem_perfil_nada_muda(self):
		client = self.signed_in(models.ROLE_ANALYST)
		self.assertEqual(200, client.get('/list', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/llm-config', headers = AUTOMATIC).status_code)

	def test_minha_conta_abre_com_perfil_vazio(self):
		client = self.signed_in_with(models.ROLE_ANALYST, [])
		self.assertEqual(200, client.get('/account').status_code)

	def test_nenhum_perfil_tira_usuarios_do_global_admin(self):
		client = self.signed_in_with(models.ROLE_GLOBAL_ADMIN, [])
		self.assertEqual(200, client.get('/api/users', headers = AUTOMATIC).status_code)
		self.assertEqual(200, client.get('/users').status_code)
		self.assertIn('users', client.get('/api/auth/me').get_json()['pages'])

	def test_nenhum_perfil_da_usuarios_a_um_analista(self):
		client = self.signed_in_with(models.ROLE_ANALYST, list(access_profiles.CATALOGUE_IDS))
		self.assertEqual(403, client.get('/api/users', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/api/profiles', headers = AUTOMATIC).status_code)
		self.assertNotIn('users', client.get('/api/auth/me').get_json()['pages'])

	def test_o_menu_recebe_as_telas_do_perfil(self):
		client = self.signed_in_with(models.ROLE_ANALYST, ['done', 'config.ia'])
		pages = client.get('/api/auth/me').get_json()['pages']
		self.assertEqual(['account', 'config', 'config.ia', 'done'], pages)

	def test_perfil_apagado_por_baixo_nao_cai_no_cargo(self):
		client = self.signed_in(models.ROLE_ADMIN)
		self.assign(models.ROLE_ADMIN, 9999)
		self.assertEqual(403, client.get('/llm-config', headers = AUTOMATIC).status_code)

	def test_global_admin_cria_edita_atribui_e_nao_apaga_em_uso(self):
		admin = self.signed_in(models.ROLE_GLOBAL_ADMIN)
		created = admin.post('/api/profiles', json = {'name': 'N1', 'items': ['inbox', 'done']}, headers = AUTOMATIC)
		self.assertEqual(200, created.status_code)
		profile_id = created.get_json()['profiles'][0]['id']
		self.assertEqual(400, admin.post('/api/profiles', json = {'name': 'N1', 'items': []}, headers = AUTOMATIC).status_code)
		self.assertEqual(200, admin.post('/api/profiles/{0}'.format(profile_id),
			json = {'name': 'N1', 'items': ['inbox']}, headers = AUTOMATIC).status_code)
		models.create_user('alvo', test_security_policy.gate.SENHA, models.ROLE_ANALYST)
		session = models.get_session()
		try:
			target = session.query(models.User).filter(models.User.username == 'alvo').first().id
		finally:
			session.close()
		self.assertEqual(200, admin.post('/api/users/{0}/profile'.format(target),
			json = {'profileId': profile_id}, headers = AUTOMATIC).status_code)
		self.assertEqual(400, admin.delete('/api/profiles/{0}'.format(profile_id), headers = AUTOMATIC).status_code)
		admin.post('/api/users/{0}/profile'.format(target), json = {'profileId': None}, headers = AUTOMATIC)
		self.assertEqual(200, admin.delete('/api/profiles/{0}'.format(profile_id), headers = AUTOMATIC).status_code)
		self.assertIn('profile_save', self.events())
		self.assertIn('user_profile_change', self.events())
		self.assertIn('profile_delete', self.events())

	def test_regra_permanente_segue_o_perfil_para_dar_e_para_tirar(self):
		# Dar: um admin com a ação pode criar regra permanente
		admin = self.signed_in_with(models.ROLE_ADMIN, ['config.whitelist', 'action.whitelist_permanent'])
		self.assertTrue(admin.get('/api/whitelist', headers = AUTOMATIC).get_json()['allowPermanent'])
		# Tirar: um global_admin cujo perfil não a tem, não
		chief = self.signed_in_with(models.ROLE_GLOBAL_ADMIN, ['config.whitelist'])
		self.assertFalse(chief.get('/api/whitelist', headers = AUTOMATIC).get_json()['allowPermanent'])

	def test_perfil_nao_da_aba_de_global_admin_a_cargo_abaixo(self):
		# Regressão: um analista com a aba SSO mapeava o próprio grupo para
		# global_admin e virava global_admin no próximo login
		items = ['config.sso', 'config.seguranca', 'config.auditoria', 'config.certificados', 'config.ia']
		client = self.signed_in_with(models.ROLE_ANALYST, items)
		self.assertEqual(403, client.get('/sso-config', headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.post('/sso-config', data = {'enabled': 'false'}, headers = AUTOMATIC).status_code)
		self.assertEqual(403, client.get('/config/sso').status_code)
		self.assertEqual(403, client.get('/config/certificados').status_code)
		pages = client.get('/api/auth/me').get_json()['pages']
		for item in items[:-1]:
			self.assertNotIn(item, pages)
		# O que não é do global_admin o perfil continua dando
		self.assertIn('config.ia', pages)
		# E um global_admin com a aba no perfil segue com ela
		chief = self.signed_in_with(models.ROLE_GLOBAL_ADMIN, ['config.sso'])
		self.assertEqual(200, chief.get('/config/sso').status_code)

	def test_caixa_de_entrada_nao_desliga_a_leitura_da_caixa(self):
		# Regressão: a tela Caixa de entrada abria o POST de /inbox-poll
		client = self.signed_in(models.ROLE_ANALYST)
		self.assertEqual(403, client.post('/inbox-poll', data = {'enabled': 'false'}, headers = AUTOMATIC).status_code)

	def test_admin_nao_gerencia_perfis(self):
		client = self.signed_in(models.ROLE_ADMIN)
		self.assertEqual(403, client.post('/api/profiles', json = {'name': 'x', 'items': ['inbox']}, headers = AUTOMATIC).status_code)


if __name__ == '__main__':
	unittest.main()
