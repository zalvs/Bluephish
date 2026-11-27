"""Guarda estática das configurações do nginx e do compose (docker/).

O nginx não roda nos testes; estas armadilhas, se voltassem, só apareceriam no
primeiro deploy — e todas falham em silêncio ou trancam alguém fora:

  * **CSP ou Referrer-Policy no vhost.** Um segundo Content-Security-Policy é
    aplicado junto com o da aplicação e mata a CSP própria da tela de login com o
    reCAPTCHA; um Referrer-Policy no-referrer quebra todo POST (§4.4).
  * **add_header dentro de um location.** No nginx ele apaga os herdados do server:
    o HSTS e os outros sumiriam só naquele caminho.
  * **Host $host.** Perde a porta; fora da 443 o CSRF recusa todo POST.
  * **listen [::].** Num contêiner sem IPv6, o nginx não sobe.
  * **Só o vhost publica porta**, a API não está na rede do vhost e só escuta na
    rede backend, que é interna, e os proxies confiáveis padrão são as duas redes —
    sem elas, o primeiro banimento de IP trancaria todo mundo.
  * **O banco** só na rede `data`, interna, sem porta, só a API nela, a senha
    por arquivo dos dois lados e a imagem presa por digest.
  * **O frontend não serve uma cópia própria de /static**: ela ficaria para trás
    quando só a API fosse reconstruída.

Roda com:  python -m unittest test_docker_configs   (a partir do diretório app/)
"""

import os
import re
import unittest

DOCKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docker')
VHOST = os.path.join(DOCKER, 'vhost', 'default.conf.template')
FRONTEND = os.path.join(DOCKER, 'frontend', 'nginx.conf')
COMPOSE = os.path.join(DOCKER, 'docker-compose.yml')


def read(path):
	with open(path, encoding = 'utf-8') as handle:
		return handle.read()


def directives(text):
	"""O texto sem comentários, para a checagem não tropeçar no que os comentários explicam."""
	return '\n'.join(line.split('#', 1)[0] for line in text.splitlines())


def location_blocks(text):
	blocks, depth, current = [], 0, None
	for line in directives(text).splitlines():
		if re.match(r'\s*location\b', line):
			current, depth = [], 0
		if current is not None:
			current.append(line)
			depth += line.count('{') - line.count('}')
			if depth <= 0 and '}' in line:
				blocks.append('\n'.join(current))
				current = None
	return blocks


@unittest.skipUnless(os.path.isfile(VHOST), 'sem a pasta docker/ ao lado')
class Nginx(unittest.TestCase):

	def test_o_vhost_nao_manda_csp_nem_referrer_policy(self):
		text = directives(read(VHOST)).lower()
		self.assertNotIn('content-security-policy', text)
		self.assertNotIn('referrer-policy', text)

	def test_nenhum_add_header_dentro_de_location(self):
		for path in (VHOST, FRONTEND):
			for block in location_blocks(read(path)):
				self.assertNotIn('add_header', block, path)

	def test_host_leva_a_porta_nos_dois_saltos(self):
		for path in (VHOST, FRONTEND):
			text = directives(read(path))
			self.assertIn('proxy_set_header Host $http_host;', text, path)
			self.assertNotRegex(text, r'proxy_set_header Host \$host;', path)

	def test_sem_listen_ipv6(self):
		for path in (VHOST, FRONTEND):
			self.assertNotIn('[::]', directives(read(path)), path)

	def test_tls_e_hsts_do_vhost(self):
		text = directives(read(VHOST))
		self.assertIn('ssl_protocols TLSv1.2 TLSv1.3;', text)
		self.assertNotRegex(text, r'TLSv1(\.1)?[ ;]')
		self.assertGreaterEqual(int(re.search(r'Strict-Transport-Security "max-age=(\d+)', text).group(1)), 31536000)
		self.assertIn('proxy_hide_header Strict-Transport-Security;', text)

	def test_o_frontend_confere_a_api_pela_ca_interna(self):
		text = directives(read(FRONTEND))
		self.assertIn('proxy_ssl_verify on;', text)
		self.assertIn('proxy_ssl_trusted_certificate /etc/nginx/trust/ca.pem;', text)
		self.assertIn('proxy_ssl_name bluephish;', text)

	def test_o_frontend_nao_serve_static_proprio(self):
		self.assertNotIn('alias', directives(read(FRONTEND)))
		self.assertNotIn('app/static', read(os.path.join(DOCKER, 'frontend', 'Dockerfile')))

	def test_o_frontend_acrescenta_ao_x_forwarded_for(self):
		# O vhost sobrescreve (é a borda, ver Compose); o frontend acrescenta o vhost
		self.assertIn('X-Forwarded-For $proxy_add_x_forwarded_for;', directives(read(FRONTEND)))


@unittest.skipUnless(os.path.isfile(COMPOSE), 'sem a pasta docker/ ao lado')
class Compose(unittest.TestCase):

	def setUp(self):
		try:
			import yaml
		except ImportError:
			self.skipTest('PyYAML não está instalado')
		self.compose = yaml.safe_load(read(COMPOSE))

	def test_so_o_vhost_publica_porta(self):
		services = self.compose['services']
		self.assertTrue(services['vhost'].get('ports'))
		for name in ('frontend', 'bluephish'):
			self.assertFalse(services[name].get('ports'), name)

	def test_redes(self):
		services, networks = self.compose['services'], self.compose['networks']
		self.assertNotIn('backend', services['vhost']['networks'])
		self.assertNotIn('edge', services['bluephish']['networks'])
		self.assertTrue(networks['backend'].get('internal'))

	def test_proxies_confiaveis_padrao_sao_os_dois_saltos(self):
		services = self.compose['services']
		environment = services['bluephish']['environment']
		line = [item for item in environment if item.startswith('BLUEPHISH_TRUSTED_PROXIES=')][0]
		default = line.split(':-', 1)[1].rstrip('}')
		expected = {services['vhost']['networks']['edge']['ipv4_address'] + '/32',
			services['frontend']['networks']['backend']['ipv4_address'] + '/32'}
		self.assertEqual(expected, set(default.split(',')))
		# A rede inteira traria o gateway do Docker (.1) para dentro da confiança
		for name in ('edge', 'backend'):
			for config in self.compose['networks'][name]['ipam']['config']:
				self.assertNotIn(config['subnet'], line)

	def test_o_vhost_sobrescreve_o_x_forwarded_for(self):
		text = directives(read(VHOST))
		self.assertIn('proxy_set_header X-Forwarded-For $remote_addr;', text)
		self.assertNotIn('X-Forwarded-For $proxy_add_x_forwarded_for', text)

	def test_o_frontend_nao_repassa_o_protocolo_do_cliente(self):
		self.assertNotIn('$http_x_forwarded_proto', directives(read(FRONTEND)))

	def test_nenhum_conteiner_ganha_privilegio(self):
		for name, service in self.compose['services'].items():
			self.assertIn('no-new-privileges:true', service.get('security_opt', []), name)

	def test_a_api_escuta_so_na_rede_backend(self):
		# Na egress, o host chegaria na API sem passar pelo vhost
		api = self.compose['services']['bluephish']
		line = [item for item in api['environment'] if item.startswith('BLUEPHISH_LISTEN_ADDRESS=')][0]
		self.assertEqual(api['networks']['backend']['ipv4_address'], line.split('=', 1)[1])

	def test_a_chave_mestra_entra_por_pasta_somente_leitura(self):
		volumes = self.compose['services']['bluephish']['volumes']
		self.assertIn('./secrets:/run/secrets/bluephish:ro', volumes)
		# O único secret do compose é a senha do banco, e só o contêiner db o usa
		self.assertEqual(['db_password'], list(self.compose.get('secrets', {})))
		self.assertNotIn('secrets', self.compose['services']['bluephish'])

	def test_o_banco_so_na_rede_data_interna_e_sem_porta(self):
		db = self.compose['services']['db']
		self.assertFalse(db.get('ports'))
		self.assertEqual(['data'], list(db['networks']))
		self.assertTrue(self.compose['networks']['data'].get('internal'))

	def test_so_a_api_alcanca_o_banco(self):
		services = self.compose['services']
		on_data = sorted(name for name, service in services.items() if 'data' in (service.get('networks') or {}))
		self.assertEqual(['bluephish', 'db'], on_data)

	def test_a_senha_do_banco_vem_de_arquivo_nos_dois_lados(self):
		services = self.compose['services']
		db_env = services['db']['environment']
		api_env = services['bluephish']['environment']
		self.assertIn('POSTGRES_PASSWORD_FILE=/run/secrets/db_password', db_env)
		self.assertEqual('./secrets/db.password', self.compose['secrets']['db_password']['file'])
		self.assertIn('BLUEPHISH_DB_PASSWORD_FILE=/run/secrets/bluephish/db.password', api_env)
		for item in db_env + api_env:
			self.assertFalse(item.startswith(('POSTGRES_PASSWORD=', 'BLUEPHISH_DB_PASSWORD=')), item)

	def test_a_imagem_do_banco_e_presa_por_digest(self):
		self.assertRegex(self.compose['services']['db']['image'], r'^postgres:[\w.-]+@sha256:[0-9a-f]{64}$')

	def test_a_api_espera_o_banco_saudavel(self):
		api = self.compose['services']['bluephish']
		self.assertEqual('service_healthy', api['depends_on']['db']['condition'])
		self.assertIn('healthcheck', self.compose['services']['db'])


if __name__ == '__main__':
	unittest.main()
