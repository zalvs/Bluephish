"""Testes do cofre de segredos (secret_vault) e da porta única do configuration.json (config_file).

O que se prende aqui, e por que cada um falharia em silêncio:

  * **Nenhum módulo abre o configuration.json direto.** Com os segredos no
    cofre, o arquivo guarda `vault:v1:<id>` no lugar da senha; um módulo que
    lesse o arquivo por conta própria mandaria a referência como senha para o
    servidor de e-mail, e a integração só pararia de autenticar. A varredura
    (`NinguemAbreOArquivoDireto`) é o que pega isso — nenhum teste de unidade
    do módulo pegaria.
  * **O arquivo não guarda segredo em texto**, e cada segredo tem salt e nonce
    próprios (o mesmo valor gravado duas vezes não dá o mesmo texto cifrado).
  * **Linhas trocadas, chave errada ou banco de outro lugar não devolvem lixo**:
    o valor sai vazio, nunca a referência.
  * **Sem a chave certa, nada se grava** — a gravação perderia o segredo.
  * **Sem chave mestra, tudo segue em texto, como antes** — uma atualização não
    tranca ninguém fora.
  * **O conector removido do meio da lista não dá o segredo ao vizinho**, e a
    linha que ficou sem uso sai do cofre.

Roda com:  python -m unittest test_config_file   (a partir do diretório app/)
"""

import ast
import glob
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import config_file
import config_store
import models
import secret_vault

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLE = {
	'imap': {'host': 'imap.exemplo.com', 'user': 'soc@exemplo.com', 'password': 'senha-da-caixa'},
	'llm_analysis': {'api_key': 'sk-teste', 'max_tokens': 800},
	'ticketing': {'jira': {'url': 'https://jira.exemplo.com', 'token': 'tok-jira'}},
	'email_sync': {'m365': {'clientSecret': 'cs-m365', 'tenantId': 'abc'}, 'gmail': {'appPassword': 'app-pw'}},
	'customAnalyzers': [{'id': 'x', 'authType': 'header', 'authName': 'X-Key', 'authValue': 'av-1'}],
	'connectors': [
		{'id': 'a', 'params': [{'name': 'Authorization', 'value': 'Bearer A', 'isSecret': True},
			{'name': 'X-Org', 'value': 'org-a', 'isSecret': False}]},
		{'id': 'b', 'params': [{'name': 'Authorization', 'value': 'Bearer B', 'isSecret': True}]}
	]
}
PLAINTEXTS = ('senha-da-caixa', 'sk-teste', 'tok-jira', 'cs-m365', 'app-pw', 'av-1', 'Bearer A', 'Bearer B')


class Ambiente(unittest.TestCase):
	"""Um banco, uma chave mestra e um configuration.json, todos temporários."""

	def setUp(self):
		self.directory = tempfile.mkdtemp(prefix = 'bluephish-vault-')
		self.previous_db = models.DB_PATH
		models.DB_PATH = os.path.join(self.directory, 'bluephish.db')
		models._engine = None
		models._SessionFactory = None
		self.key_path = os.path.join(self.directory, 'master.key')
		self.keys_written = 0
		self.write_key()
		self.env = mock.patch.dict(os.environ, {secret_vault.KEY_FILE_ENV: self.key_path})
		self.env.start()
		secret_vault.forget_cache()
		self.path = os.path.join(self.directory, 'configuration.json')
		with open(self.path, 'w') as handle:
			json.dump(SAMPLE, handle)

	def tearDown(self):
		self.env.stop()
		secret_vault.forget_cache()
		models.DB_PATH = self.previous_db
		models._engine = None
		models._SessionFactory = None
		shutil.rmtree(self.directory, ignore_errors = True)

	def write_key(self, key = None):
		with open(self.key_path, 'w') as handle:
			handle.write(key or secret_vault.generate_key())
		# O cache da chave decide pelo mtime; duas gravações no mesmo instante
		# teriam o mesmo
		self.keys_written += 1
		stamp = os.stat(self.key_path).st_mtime + self.keys_written
		os.utime(self.key_path, (stamp, stamp))

	def on_disk(self):
		with open(self.path) as handle:
			return handle.read()

	def rows(self):
		session = models.get_session()
		try:
			return session.query(models.VaultSecret).all()
		finally:
			session.close()


class Cifra(Ambiente):

	def test_a_migracao_tira_todo_segredo_do_arquivo(self):
		self.assertEqual(len(PLAINTEXTS), config_file.migrate(self.path))
		text = self.on_disk()
		for plaintext in PLAINTEXTS:
			self.assertNotIn(plaintext, text)
		# O que não é segredo continua legível no arquivo
		self.assertIn('org-a', text)
		self.assertIn('imap.exemplo.com', text)
		self.assertIn('800', text)

	def test_ler_devolve_os_valores(self):
		config_file.migrate(self.path)
		secret_vault.forget_cache()
		self.assertEqual(SAMPLE, config_file.read(self.path))

	def test_o_banco_nao_guarda_texto(self):
		config_file.migrate(self.path)
		for row in self.rows():
			for plaintext in PLAINTEXTS:
				self.assertNotIn(plaintext.encode(), row.ciphertext)
			self.assertEqual(16, len(row.salt))
			self.assertEqual(12, len(row.nonce))

	def test_mesmo_valor_duas_vezes_da_cifras_diferentes(self):
		config_file.write({'a': {'password': 'igual'}, 'b': {'password': 'igual'}}, self.path)
		first, second = self.rows()
		self.assertNotEqual(first.ciphertext, second.ciphertext)
		self.assertNotEqual(first.salt, second.salt)

	def test_linhas_trocadas_nao_abrem(self):
		config_file.migrate(self.path)
		raw = config_file.read_raw(self.path)
		imap = raw['imap']['password'][len(secret_vault.REF_PREFIX):]
		jira = raw['ticketing']['jira']['token'][len(secret_vault.REF_PREFIX):]
		session = models.get_session()
		try:
			# Troca o conteúdo cifrado das duas linhas, mantendo os ids
			a = session.query(models.VaultSecret).get(imap)
			b = session.query(models.VaultSecret).get(jira)
			a.ciphertext, b.ciphertext = b.ciphertext, a.ciphertext
			a.salt, b.salt = b.salt, a.salt
			a.nonce, b.nonce = b.nonce, a.nonce
			session.commit()
		finally:
			session.close()
		secret_vault.forget_cache()
		opened = config_file.read(self.path)
		self.assertEqual('', opened['imap']['password'])
		self.assertEqual('', opened['ticketing']['jira']['token'])

	def test_chave_mestra_errada_devolve_vazio_e_nao_a_referencia(self):
		config_file.migrate(self.path)
		self.write_key()
		secret_vault.forget_cache()
		opened = config_file.read(self.path)
		self.assertEqual('', opened['imap']['password'])
		self.assertNotIn('vault:', json.dumps(opened))

	def test_com_a_chave_errada_nada_se_grava(self):
		config_file.migrate(self.path)
		self.write_key()
		secret_vault.forget_cache()
		before = self.on_disk()
		with self.assertRaises(secret_vault.VaultError):
			config_file.write(config_file.read(self.path), self.path)
		self.assertEqual(before, self.on_disk())
		# E as linhas da chave antiga não foram coletadas
		self.assertEqual(len(PLAINTEXTS), len(self.rows()))

	def test_sem_a_chave_com_segredo_cifrado_nada_se_grava(self):
		config_file.migrate(self.path)
		os.remove(self.key_path)
		secret_vault.forget_cache()
		with self.assertRaises(secret_vault.VaultError):
			config_store.write_section(self.path, 'outra', {'x': 1})

	def test_conector_removido_do_meio_nao_entrega_o_segredo_ao_vizinho(self):
		config_file.migrate(self.path)
		document = config_file.read(self.path)
		del document['connectors'][0]
		config_file.write(document, self.path)
		secret_vault.forget_cache()
		self.assertEqual('Bearer B', config_file.read(self.path)['connectors'][0]['params'][0]['value'])
		# A linha do conector removido saiu do cofre
		self.assertEqual(len(PLAINTEXTS) - 1, len(self.rows()))

	def test_gravar_uma_secao_preserva_os_segredos_das_outras(self):
		config_file.migrate(self.path)
		config_store.write_section(self.path, 'security', {'session': {'idleMinutes': 15}})
		secret_vault.forget_cache()
		opened = config_file.read(self.path)
		self.assertEqual('senha-da-caixa', opened['imap']['password'])
		self.assertEqual(len(PLAINTEXTS), len(self.rows()))

	def test_referencia_de_outro_campo_e_recusada(self):
		# Regressão: colar a referência do IMAP no campo do SMTP fazia o SMTP abrir
		# a senha do IMAP (o AAD amarra a cifra ao id, não ao campo)
		config_file.migrate(self.path)
		raw = config_file.read_raw(self.path)
		forged = config_file.read(self.path)
		forged.setdefault('smtp', {})['password'] = raw['imap']['password']
		with self.assertRaises(secret_vault.ForeignReference):
			config_file.write(forged, self.path)
		# O arquivo ficou como estava
		self.assertEqual(raw, config_file.read_raw(self.path))

	def test_referencia_que_o_arquivo_ja_tinha_continua_valendo(self):
		config_file.migrate(self.path)
		config_file.write(config_file.read_raw(self.path), self.path)
		secret_vault.forget_cache()
		self.assertEqual(SAMPLE, config_file.read(self.path))

	def test_valor_vazio_continua_vazio(self):
		config_file.write({'smtp': {'password': ''}}, self.path)
		self.assertEqual('', config_file.read_raw(self.path)['smtp']['password'])
		self.assertEqual([], self.rows())

	def test_estado_nao_mostra_valor(self):
		config_file.migrate(self.path)
		state = secret_vault.status(config_file.read_raw(self.path))
		self.assertTrue(state['keyPresent'])
		self.assertEqual(len(PLAINTEXTS), state['sealed'])
		self.assertEqual(0, state['plaintext'])
		self.assertEqual(0, state['unreadable'])
		for plaintext in PLAINTEXTS:
			self.assertNotIn(plaintext, json.dumps(state))

	def test_chave_mestra_aceita_hex_e_recusa_curta(self):
		self.write_key('ab' * 32)
		self.assertEqual(32, len(secret_vault.master_key()))
		self.write_key('curta')
		with self.assertRaises(secret_vault.VaultError):
			secret_vault.master_key()

	def test_o_segredo_da_aplicacao_e_estavel_e_sobrevive_a_coleta(self):
		first = secret_vault.app_secret('flask-secret-key', lambda: 'gerado-1')
		config_file.write({'x': {}}, self.path)
		secret_vault.forget_cache()
		self.assertEqual(first, secret_vault.app_secret('flask-secret-key', lambda: 'gerado-2'))


class OsLeitoresDeVerdade(Ambiente):
	"""Com o cofre ligado, os módulos que usam os segredos recebem o valor, não a referência.

	A varredura acima prova que ninguém abre o arquivo direto; isto prova, para
	alguns leitores reais, que o caminho pelo config_file entrega o segredo aberto.
	"""

	def setUp(self):
		super().setUp()
		document = {
			'thehive': {'url': 'https://hive.exemplo.com', 'apikey': 'hive-key'},
			'ticketing': {'jira': {'enabled': True, 'url': 'https://jira.exemplo.com', 'token': 'tok-jira'}},
			'notification': {'smtp': {'enabled': True, 'host': 'smtp.exemplo.com', 'user': 'soc', 'password': 'smtp-pw'}}
		}
		with open(self.path, 'w') as handle:
			json.dump(document, handle)
		config_file.migrate(self.path)
		secret_vault.forget_cache()
		self.assertNotIn('smtp-pw', self.on_disk())

	def test_tickets(self):
		import tickets
		config = tickets.load_config(self.path)
		self.assertEqual('hive-key', config['thehive']['apikey'])
		self.assertEqual('tok-jira', config['jira']['token'])

	def test_mailer(self):
		import mailer
		self.assertEqual('smtp-pw', mailer.load_config(self.path)['password'])

	def test_gravar_pelo_modulo_mantem_cifrado(self):
		import mailer
		entry = mailer.load_config(self.path)
		mailer.save_config(dict(entry, host = 'smtp2.exemplo.com'), self.path)
		self.assertNotIn('smtp-pw', self.on_disk())
		secret_vault.forget_cache()
		self.assertEqual('smtp-pw', mailer.load_config(self.path)['password'])


class SemChaveMestra(Ambiente):

	def setUp(self):
		super().setUp()
		os.remove(self.key_path)
		secret_vault.forget_cache()

	def test_tudo_segue_em_texto_como_antes(self):
		self.assertEqual(0, config_file.migrate(self.path))
		config_file.write(dict(SAMPLE, extra = {'password': 'nova'}), self.path)
		self.assertIn('nova', self.on_disk())
		self.assertEqual('senha-da-caixa', config_file.read(self.path)['imap']['password'])
		self.assertFalse(secret_vault.status(config_file.read_raw(self.path))['keyPresent'])

	def test_o_segredo_da_aplicacao_fica_para_quem_chama(self):
		self.assertIsNone(secret_vault.app_secret('flask-secret-key', lambda: 'x'))


class QuemESegredo(unittest.TestCase):

	def test_nomes(self):
		for name in ('password', 'appPassword', 'clientSecret', 'apiKey', 'api_key', 'apikey', 'apiToken', 'token', 'authValue',
				'hashSecret', 'hasuraAdminSecret', 'issuerToken', 'isvApiKey', 'IsPassword'):
			self.assertTrue(secret_vault.is_secret_name(name), name)
		for name in ('max_tokens', 'tokenUrl', 'user', 'authType', 'authName', 'isSecret', 'hasClientSecret', 'tenantId'):
			self.assertFalse(secret_vault.is_secret_name(name), name)


def _mentions_config(node):
	for child in ast.walk(node):
		if isinstance(child, ast.Constant) and child.value == 'configuration.json':
			return True
		if isinstance(child, ast.Name) and child.id == 'CONFIG_FILE':
			return True
		if isinstance(child, ast.Attribute) and child.attr == 'CONFIG_FILE':
			return True
	return False


class NinguemAbreOArquivoDireto(unittest.TestCase):
	"""Varredura do código: só config_file abre o configuration.json.

	Um `open()` conta como abrir a configuração quando o caminho cita o arquivo
	(o literal, ou CONFIG_FILE), ou quando é um caminho variável dentro de uma
	função que cita a configuração (`def load_config(path = CONFIG_FILE)`, ou
	`path = path or CONFIG_FILE` no corpo). Um caminho literal de outro arquivo
	(`open('logging_conf.json')`) não conta.
	"""

	def test_nenhum_modulo_abre_o_configuration_json(self):
		found = set()
		for path in sorted(glob.glob(os.path.join(BASE, '*.py'))):
			name = os.path.basename(path)
			if name.startswith('test_') or name == 'config_file.py':
				continue
			with open(path) as handle:
				tree = ast.parse(handle.read())
			scopes = [tree] + [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
			for scope in scopes:
				config_scope = isinstance(scope, ast.FunctionDef) and _mentions_config(scope)
				for call in ast.walk(scope):
					if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'open' and call.args):
						continue
					target = call.args[0]
					if _mentions_config(target) or (config_scope and not isinstance(target, ast.Constant)):
						found.add('{0}:{1}'.format(name, call.lineno))
		self.assertEqual([], sorted(found), 'abre o configuration.json sem config_file: {0}'.format(sorted(found)))


if __name__ == '__main__':
	unittest.main()
