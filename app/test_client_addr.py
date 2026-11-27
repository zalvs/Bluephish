"""De onde vem o IP que a trilha de auditoria registra (client_addr.py).

O que estes testes seguram, e por que cada um falharia em silêncio:

* O primeiro X-Forwarded-For é escrito por quem fez a requisição. Honrá-lo de
  qualquer par permitia a quem acessa direto escolher o IP que a auditoria e o
  limitador de tentativas enxergam.
* Atrás de um proxy confiável, o cliente é a entrada mais à direita que não é
  proxy — não a primeira da lista.
* Quem chega pelo gateway da bridge do Docker sem cabeçalho nenhum não tem IP
  conhecido: a trilha diz isso em vez de apresentar 172.18.0.1 como se fosse
  uma pessoa.

Rodar com:  python -m unittest test_client_addr   (a partir de app/)
"""

import unittest

import client_addr


class ParseTrustedTests(unittest.TestCase):
	def test_default_trusts_only_loopback(self):
		nets = client_addr.parse_trusted('')
		self.assertTrue(client_addr.is_trusted('127.0.0.1', nets))
		self.assertTrue(client_addr.is_trusted('::1', nets))
		self.assertFalse(client_addr.is_trusted('172.18.0.1', nets))

	def test_accepts_cidrs_and_single_addresses(self):
		nets = client_addr.parse_trusted('10.0.0.0/8, 192.168.1.5')
		self.assertTrue(client_addr.is_trusted('10.9.8.7', nets))
		self.assertTrue(client_addr.is_trusted('192.168.1.5', nets))
		self.assertFalse(client_addr.is_trusted('192.168.1.6', nets))

	def test_invalid_entries_are_ignored_not_fatal(self):
		nets = client_addr.parse_trusted('lixo, 10.0.0.0/8')
		self.assertTrue(client_addr.is_trusted('10.1.1.1', nets))

	def test_unparseable_address_is_never_trusted(self):
		self.assertFalse(client_addr.is_trusted('nao-e-ip', client_addr.parse_trusted('')))


class ResolveTests(unittest.TestCase):
	def setUp(self):
		self.trusted = client_addr.parse_trusted('10.0.0.0/8')

	def test_forged_header_from_untrusted_peer_is_ignored(self):
		result = client_addr.resolve('45.166.227.2', '1.2.3.4', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')
		self.assertEqual(result.source, 'peer')

	def test_trusted_proxy_hands_over_the_client(self):
		result = client_addr.resolve('10.0.0.2', '45.166.227.2', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')
		self.assertEqual(result.source, 'forwarded')

	def test_client_is_rightmost_entry_that_is_not_a_proxy(self):
		# O cliente tentou se anunciar como 1.2.3.4; o proxy acrescentou o que viu
		result = client_addr.resolve('10.0.0.2', '1.2.3.4, 45.166.227.2, 10.0.0.9', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')

	def test_trusted_peer_without_header_is_the_peer(self):
		result = client_addr.resolve('10.0.0.2', '', self.trusted)
		self.assertEqual(result.ip, '10.0.0.2')
		self.assertEqual(result.source, 'peer')

	def test_garbage_in_header_falls_back_to_peer(self):
		result = client_addr.resolve('10.0.0.2', 'x, y', self.trusted)
		self.assertEqual(result.ip, '10.0.0.2')

	def test_two_hops_of_the_compose_hand_over_the_client(self):
		# vhost (edge) -> frontend (edge + backend) -> API. A API vê o frontend como
		# par; o X-Forwarded-For traz o cliente e, à direita, o vhost. Com as duas
		# saltos do compose em BLUEPHISH_TRUSTED_PROXIES (o padrão), vale o cliente —
		# sem isso, todo mundo seria o frontend e o primeiro banimento trancaria todos
		trusted = client_addr.parse_trusted('172.30.10.10/32,172.30.11.20/32')
		result = client_addr.resolve('172.30.11.20', '198.51.100.7, 172.30.10.10', trusted)
		self.assertEqual(('198.51.100.7', 'forwarded', False), (result.ip, result.source, result.docker_gateway))
		# O cliente que manda um X-Forwarded-For forjado fica à esquerda e é ignorado
		forged = client_addr.resolve('172.30.11.20', '10.9.9.9, 198.51.100.7, 172.30.10.10', trusted)
		self.assertEqual('198.51.100.7', forged.ip)

	def test_gateway_of_the_edge_network_cannot_speak_for_the_client(self):
		# Regressão: com a rede /24 inteira confiável e o vhost acrescentando ao
		# cabeçalho, quem chegava pelo gateway (172.30.10.1) escolhia o próprio IP
		trusted = client_addr.parse_trusted('172.30.10.10/32,172.30.11.20/32')
		forged = client_addr.resolve('172.30.11.20', '1.2.3.4, 172.30.10.1, 172.30.10.10', trusted)
		self.assertEqual('172.30.10.1', forged.ip)
		# E o gateway resolvido não é contável: não vira um banimento de todos
		self.assertTrue(forged.docker_gateway)

	def test_garbage_from_the_edge_never_becomes_the_client(self):
		# O vhost sobrescreve; se algo ainda trouxer lixo, cai no par, nunca no lixo
		trusted = client_addr.parse_trusted('172.30.10.10/32,172.30.11.20/32')
		result = client_addr.resolve('172.30.11.20', '1.2.3.4, lixo, 172.30.10.10', trusted)
		self.assertEqual(('172.30.11.20', 'peer'), (result.ip, result.source))

	def test_missing_peer_is_dash(self):
		self.assertEqual(client_addr.resolve(None, '', self.trusted).ip, '-')

	def test_result_is_clipped_like_the_old_field(self):
		self.assertLessEqual(len(client_addr.resolve('10.0.0.2', 'a' * 100, self.trusted).ip), 45)


class DockerGatewayTests(unittest.TestCase):
	def test_bridge_gateway_without_header_is_flagged(self):
		result = client_addr.resolve('172.18.0.1', '', client_addr.parse_trusted(''))
		self.assertTrue(result.docker_gateway)
		self.assertEqual(result.ip, '172.18.0.1')

	def test_real_client_address_is_not_flagged(self):
		self.assertFalse(client_addr.resolve('45.166.227.2', '', client_addr.parse_trusted('')).docker_gateway)

	def test_other_private_hosts_are_not_flagged_as_gateway(self):
		# Só o .1 da bridge é o gateway; um contêiner vizinho é outra coisa
		self.assertFalse(client_addr.resolve('172.18.0.7', '', client_addr.parse_trusted('')).docker_gateway)

	def test_gateway_resolved_through_a_proxy_is_not_flagged(self):
		trusted = client_addr.parse_trusted('172.18.0.1')
		result = client_addr.resolve('172.18.0.1', '45.166.227.2', trusted)
		self.assertFalse(result.docker_gateway)
		self.assertEqual(result.ip, '45.166.227.2')


class HostileInputTests(unittest.TestCase):
	"""Casos de entrada que o revisor de segurança derrubou na primeira versão."""

	def setUp(self):
		self.trusted = client_addr.parse_trusted('10.0.0.0/8')

	def test_ipv4_mapped_peer_is_matched_against_ipv4_networks(self):
		# Um socket dual-stack entrega o par IPv4 neste formato
		result = client_addr.resolve('::ffff:10.0.0.2', '45.166.227.2', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')

	def test_ipv4_mapped_client_has_the_same_key_as_plain_ipv4(self):
		mapped = client_addr.resolve('45.166.227.2', '', self.trusted).ip
		other = client_addr.resolve('::ffff:45.166.227.2', '', self.trusted).ip
		self.assertEqual(mapped, other)

	def test_ipv4_mapped_forwarded_entry_is_discounted_as_a_proxy(self):
		result = client_addr.resolve('10.0.0.2', '45.166.227.2, ::ffff:10.0.0.9', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')

	def test_scope_id_is_rejected_and_never_reaches_the_log_field(self):
		result = client_addr.resolve('10.0.0.2', '9.9.9.9, fe80::1%a b actor=admin', self.trusted)
		self.assertNotIn(' ', result.ip)
		self.assertNotIn('%', result.ip)
		self.assertEqual(result.ip, '10.0.0.2')

	def test_result_is_always_an_address_or_dash(self):
		import re
		for forwarded in ('fe80::1%x', '1.2.3.4\tx', '1.2.3.4 actor=x', '\u202e1.2.3.4'):
			result = client_addr.resolve('10.0.0.2', forwarded, self.trusted)
			self.assertRegex(result.ip, r'^[0-9a-fA-F:.]+$|^-$')

	def test_port_suffix_is_accepted_on_forwarded_entries(self):
		# Application Gateway e alguns balanceadores mandam "ip:porta"
		result = client_addr.resolve('10.0.0.2', '45.166.227.2:51234', self.trusted)
		self.assertEqual(result.ip, '45.166.227.2')

	def test_bracketed_ipv6_with_port_is_accepted(self):
		result = client_addr.resolve('10.0.0.2', '[2001:db8::7]:443', self.trusted)
		self.assertEqual(result.ip, '2001:db8::7')

	def test_invalid_trusted_entries_are_reported(self):
		problems = []
		client_addr.parse_trusted('10.0.0.0/8, lixo', report = problems.append)
		self.assertEqual(problems, ['lixo'])


if __name__ == '__main__':
	unittest.main()
