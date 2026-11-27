"""The Exchange Online block path refuses redirects.

`_entra_token` posts the app's client secret in the body of a POST. `requests`
follows a 307/308 by sending the same body to the host the answer names, and
strips only the Authorization header when the host changes — so the secret would
travel with it. `_eop_invoke` carries the blocked indicator the same way. Both go
to fixed Microsoft hosts, which is why nothing guards them; a redirect from there
is a failure to show the admin, never a hop to follow.

Run with:  python -m unittest test_responders_no_redirect   (from the app/ directory)
"""

import unittest
from unittest import mock

import responders as rp


class FakeResponse:

	def __init__(self, status, body = None):
		self.status_code = status
		self.headers = {'Location': 'http://elsewhere.example/steal'}
		self._body = body if body is not None else {}

	def raise_for_status(self):
		if self.status_code >= 400:
			raise RuntimeError('HTTP {0}'.format(self.status_code))

	def json(self):
		return self._body


ENTRY = {'tenantId': 't', 'clientId': 'c', 'clientSecret': 's', 'organization': 'contoso.onmicrosoft.com'}


class TokenRequest(unittest.TestCase):

	def test_does_not_follow_redirects(self):
		with mock.patch.object(rp.requests, 'post', return_value = FakeResponse(200, {'access_token': 'x'})) as post:
			rp._entra_token(ENTRY, 'scope')
		self.assertIs(post.call_args.kwargs.get('allow_redirects'), False)

	def test_a_redirect_answer_is_an_error_not_a_token(self):
		with mock.patch.object(rp.requests, 'post', return_value = FakeResponse(307)):
			with self.assertRaises(rp.ResponderError) as caught:
				rp._entra_token(ENTRY, 'scope')
		self.assertIn('redirecion', str(caught.exception))


class InvokeRequest(unittest.TestCase):

	def test_does_not_follow_redirects(self):
		with mock.patch.object(rp, '_entra_token', return_value = 'tok'), \
				mock.patch.object(rp.requests, 'post', return_value = FakeResponse(200)) as post:
			rp._eop_invoke(ENTRY, 'Get-X', {})
		self.assertIs(post.call_args.kwargs.get('allow_redirects'), False)

	def test_a_redirect_answer_is_an_error_not_a_result(self):
		with mock.patch.object(rp, '_entra_token', return_value = 'tok'), \
				mock.patch.object(rp.requests, 'post', return_value = FakeResponse(308)):
			with self.assertRaises(rp.ResponderError) as caught:
				rp._eop_invoke(ENTRY, 'Get-X', {})
		self.assertIn('redirecion', str(caught.exception))


if __name__ == '__main__':
	unittest.main()
