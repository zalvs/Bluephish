"""O MSAL, sem `timeout`, espera o Entra ID para sempre.

A MSAL repassa `timeout` ao `requests` e o padrão dela é nenhum. O token do
M365 é pedido no ciclo de polling da caixa e no login por SSO: um Entra ID que
aceita a conexão e não responde pendura o ciclo (ou a requisição de login) sem
erro e sem log. Estes testes prendem que as duas construções passam um prazo.
Nenhum toca a rede: a classe da MSAL é trocada por uma que só guarda os
argumentos.

Roda com:  python -m unittest test_msal_timeout   (a partir do diretório app/)
"""

import sys
import types
import unittest
from unittest import mock

if 'msal' not in sys.modules:
	try:
		import msal  # noqa: F401
	except ImportError:
		# Fora da imagem a MSAL não está instalada; o que se testa é o argumento.
		sys.modules['msal'] = types.SimpleNamespace(ConfidentialClientApplication = None)

import m365_auth

try:
	import sso
except ImportError:
	# sso puxa o SQLAlchemy via models; sem a imagem o teste do SSO é pulado.
	sso = None


class FakeClient:
	calls = []

	def __init__(self, *args, **kwargs):
		FakeClient.calls.append(kwargs)


class PrazoDoEntraId(unittest.TestCase):

	def setUp(self):
		FakeClient.calls = []

	def test_o_token_do_m365_pede_com_prazo(self):
		m365_auth._msal_app = None
		with mock.patch.object(m365_auth.msal, 'ConfidentialClientApplication', FakeClient):
			m365_auth._get_msal_app('tenant', 'client', 'secret')
		m365_auth._msal_app = None
		self.assertEqual(FakeClient.calls[0].get('timeout'), m365_auth.MSAL_TIMEOUT)

	@unittest.skipIf(sso is None, 'sso depende das bibliotecas da imagem')
	def test_o_login_por_sso_pede_com_prazo(self):
		config = {'clientId': 'client', 'clientSecret': 'secret', 'tenantId': 'tenant'}
		with mock.patch.object(sso.msal, 'ConfidentialClientApplication', FakeClient):
			sso._client(config)
		self.assertEqual(FakeClient.calls[0].get('timeout'), m365_auth.MSAL_TIMEOUT)

	def test_o_prazo_e_finito_e_curto(self):
		self.assertTrue(0 < m365_auth.MSAL_TIMEOUT <= 30)


if __name__ == '__main__':
	unittest.main()
