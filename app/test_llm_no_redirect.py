"""The calls that carry the reported e-mail to the model refuse redirects.

The endpoint is the host the admin typed. A 307/308 from it would make
`requests` send the same body (the attacker's e-mail text and its images) to
whatever host the answer names, and the SSRF guard does not cover this path.
`llm_catalog` already refuses redirects; the three calls that carry the e-mail
must too, and a redirect answer is a failure (`chat` raises, `ask_chat_llm`
returns None), never a silent success.

Run with:  python -m unittest test_llm_no_redirect   (from the app/ directory)
"""

import unittest
from unittest import mock

import llm_analysis

try:
	import thephish_app
except Exception:  # sem as dependências da imagem (eventlet, flask...) o teste do chat fica de fora
	thephish_app = None


class FakeResponse:

	def __init__(self, status):
		self.status_code = status
		self.headers = {'Location': 'http://elsewhere.example/steal'}

	def raise_for_status(self):
		if self.status_code >= 400:
			raise RuntimeError('HTTP {0}'.format(self.status_code))

	def json(self):
		return {}


def refused_redirects(kwargs):
	return kwargs.get('allow_redirects') is False


class AnalysisChatRefusesRedirects(unittest.TestCase):

	def setUp(self):
		patcher = mock.patch.dict(llm_analysis.config, {'llmApiKey': ''})
		patcher.start()
		self.addCleanup(patcher.stop)

	def post_with(self, endpoint, answer_status = 200):
		with mock.patch.dict(llm_analysis.config, {'llmEndpoint': endpoint, 'llmModel': 'm'}), \
				mock.patch.object(llm_analysis.requests, 'post', return_value = FakeResponse(answer_status)) as post:
			try:
				llm_analysis.chat([{'role': 'user', 'content': 'x'}])
			except Exception:
				pass
		return post

	def test_ollama_call_does_not_follow_redirects(self):
		post = self.post_with('http://llm.local:11434/api/chat')
		self.assertTrue(refused_redirects(post.call_args.kwargs))

	def test_openai_compatible_call_does_not_follow_redirects(self):
		post = self.post_with('https://gw.example/v1/chat/completions')
		self.assertTrue(refused_redirects(post.call_args.kwargs))

	def test_a_redirect_answer_is_an_error_not_a_result(self):
		for endpoint in ('http://llm.local:11434/api/chat', 'https://gw.example/v1/chat/completions'):
			with mock.patch.dict(llm_analysis.config, {'llmEndpoint': endpoint, 'llmModel': 'm'}), \
					mock.patch.object(llm_analysis.requests, 'post', return_value = FakeResponse(307)):
				with self.assertRaises(Exception) as caught:
					llm_analysis.chat([{'role': 'user', 'content': 'x'}])
			self.assertIn('redirect', str(caught.exception).lower(), endpoint)


@unittest.skipIf(thephish_app is None, 'thephish_app precisa da imagem')
class ChatCompanionRefusesRedirects(unittest.TestCase):

	def ask(self, endpoint, status = 200):
		conf = {'api_endpoint': endpoint, 'model_name': 'm', 'api_key': ''}
		with mock.patch.object(llm_analysis.requests, 'post', return_value = FakeResponse(status)) as post:
			answer = thephish_app.ask_chat_llm(conf, [{'role': 'user', 'content': 'x'}])
		return answer, post

	def test_neither_transport_follows_redirects(self):
		for endpoint in ('http://llm.local:11434/api/chat', 'https://gw.example/v1/chat/completions'):
			_answer, post = self.ask(endpoint)
			self.assertTrue(refused_redirects(post.call_args.kwargs), endpoint)

	def test_a_redirect_answer_gives_no_answer(self):
		for endpoint in ('http://llm.local:11434/api/chat', 'https://gw.example/v1/chat/completions'):
			answer, _post = self.ask(endpoint, 307)
			self.assertIsNone(answer, endpoint)


if __name__ == '__main__':
	unittest.main()
