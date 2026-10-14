"""Tests for the model catalog behind the LLM model picker.

The invariant that fails silently here is "unknown is not no": a provider that
does not say whether a model reads images must come back as None, never as
False, or the settings screen would state a fact nobody reported.

Run with:  python -m unittest test_llm_catalog   (from the app/ directory)
"""

import unittest

import llm_catalog


class ProviderKind(unittest.TestCase):

	def test_same_decision_as_the_chat_client(self):
		self.assertEqual(llm_catalog.provider_kind('https://openrouter.ai/api/v1/chat/completions'), 'openrouter')
		self.assertEqual(llm_catalog.provider_kind('http://host.docker.internal:11434/api/chat'), 'ollama')
		self.assertEqual(llm_catalog.provider_kind('https://gw.example/v1/chat/completions'), 'openai')

	def test_openrouter_lookalike_host_is_not_openrouter(self):
		self.assertEqual(llm_catalog.provider_kind('https://openrouter.ai.evil.example/v1/chat/completions'), 'openai')

	def test_openai_base(self):
		self.assertEqual(llm_catalog.openai_base('https://gw.example/v1/chat/completions'), 'https://gw.example/v1')
		self.assertEqual(llm_catalog.openai_base('https://gw.example/v1/'), 'https://gw.example/v1')


class OwnerInference(unittest.TestCase):

	def test_names_without_prefix(self):
		self.assertEqual(llm_catalog.infer_owner('claude-sonnet-4-6-eu', 'openai'), 'anthropic')
		self.assertEqual(llm_catalog.infer_owner('gpt-oss-120b'), 'openai')
		self.assertEqual(llm_catalog.infer_owner('text-embedding-3-small'), 'openai')
		self.assertEqual(llm_catalog.infer_owner('gemma-3-27b-it'), 'google')
		self.assertEqual(llm_catalog.infer_owner('qwen2.5:7b'), 'qwen')
		self.assertEqual(llm_catalog.infer_owner('glm-4.6'), 'z-ai')

	def test_prefix_wins(self):
		self.assertEqual(llm_catalog.infer_owner('moonshotai/kimi-k2'), 'moonshotai')

	def test_unknown_is_other(self):
		self.assertEqual(llm_catalog.infer_owner('my-finetune'), 'other')


class OpenRouter(unittest.TestCase):

	payload = {'data': [
		{'id': 'anthropic/claude-sonnet-4.5', 'architecture': {'input_modalities': ['text', 'image', 'file'], 'output_modalities': ['text']}},
		{'id': 'deepseek/deepseek-chat', 'architecture': {'input_modalities': ['text'], 'output_modalities': ['text']}},
		{'id': 'openai/gpt-image-1', 'architecture': {'input_modalities': ['text'], 'output_modalities': ['image']}},
		{'id': 'meta-llama/llama-4-maverick', 'architecture': {'input_modalities': ['text', 'image']}},
		{'id': 'qwen/qwen3-max'},
	]}

	def test_only_requested_owners_and_text_output(self):
		ids = [m['id'] for m in llm_catalog.parse_openrouter(self.payload)]
		self.assertEqual(ids, ['anthropic/claude-sonnet-4.5', 'deepseek/deepseek-chat', 'qwen/qwen3-max'])

	def test_modalities(self):
		models = {m['id']: m for m in llm_catalog.parse_openrouter(self.payload)}
		self.assertEqual((models['anthropic/claude-sonnet-4.5']['image'], models['anthropic/claude-sonnet-4.5']['file']), (True, True))
		self.assertEqual((models['deepseek/deepseek-chat']['image'], models['deepseek/deepseek-chat']['file']), (False, False))
		self.assertEqual(models['anthropic/claude-sonnet-4.5']['name'], 'claude-sonnet-4.5')

	def test_missing_architecture_is_unknown_not_false(self):
		model = [m for m in llm_catalog.parse_openrouter(self.payload) if m['id'] == 'qwen/qwen3-max'][0]
		self.assertIsNone(model['image'])
		self.assertIsNone(model['file'])


class Ollama(unittest.TestCase):

	def test_vision_capability(self):
		tags = {'models': [{'name': 'qwen2.5vl:7b'}, {'name': 'llama3.1:8b'}, {'name': 'old:1b'}]}
		caps = {'qwen2.5vl:7b': ['completion', 'vision'], 'llama3.1:8b': ['completion', 'tools'], 'old:1b': None}
		models = {m['id']: m for m in llm_catalog.parse_ollama(tags, caps)}
		self.assertTrue(models['qwen2.5vl:7b']['image'])
		self.assertFalse(models['llama3.1:8b']['image'])
		self.assertIsNone(models['old:1b']['image'])

	def test_fetch_uses_show_per_model(self):
		calls = []
		def get(url, headers = None):
			calls.append(url)
			return {'models': [{'name': 'gemma3:4b'}]}
		def post(url, payload):
			calls.append((url, payload['model']))
			return {'capabilities': ['completion', 'vision']}
		kind, models = llm_catalog.fetch('http://ollama:11434/api/chat', get = get, post = post)
		self.assertEqual(kind, 'ollama')
		self.assertEqual(calls, ['http://ollama:11434/api/tags', ('http://ollama:11434/api/show', 'gemma3:4b')])
		self.assertTrue(models[0]['image'])


class OpenAICompatible(unittest.TestCase):

	def test_litellm_info_fills_capabilities(self):
		payload = {'data': [{'id': 'claude-opus-4-8-eu', 'owned_by': 'openai'}, {'id': 'gpt-5-nano', 'owned_by': 'openai'}]}
		info = {'data': [{'model_name': 'claude-opus-4-8-eu', 'model_info': {'supports_vision': True, 'supports_pdf_input': True}}]}
		models = {m['id']: m for m in llm_catalog.parse_openai_models(payload, info)}
		self.assertEqual(models['claude-opus-4-8-eu']['owner'], 'anthropic')
		self.assertTrue(models['claude-opus-4-8-eu']['image'])
		self.assertIsNone(models['gpt-5-nano']['image'])

	def test_key_goes_only_to_the_typed_host(self):
		seen = []
		def get(url, headers = None):
			seen.append((url, (headers or {}).get('Authorization')))
			if url.endswith('/models'):
				return {'data': [{'id': 'gpt-5-mini'}]}
			raise ValueError('no litellm here')
		llm_catalog.fetch('https://gw.example/v1/chat/completions', 'sk-test', get = get)
		for url, auth in seen:
			self.assertTrue(url.startswith('https://gw.example/'))
			self.assertEqual(auth, 'Bearer sk-test')

	def test_openrouter_never_receives_the_key(self):
		seen = []
		def get(url, headers = None):
			seen.append(headers)
			return {'data': []}
		llm_catalog.fetch('https://openrouter.ai/api/v1/chat/completions', 'sk-or', get = get)
		self.assertEqual(seen, [None])


class ListModels(unittest.TestCase):

	def test_rejects_non_http_endpoint(self):
		self.assertIn('error', llm_catalog.list_models('file:///etc/passwd'))
		self.assertIn('error', llm_catalog.list_models(''))


class ImagesHeldBackOnlyOnExplicitNo(unittest.TestCase):
	"""Sending an image to a text-only model can cost the whole assessment
	(OpenRouter refuses the request). Holding images back from a model that can
	read them costs the visual analysis. Only the provider's explicit False may
	decide the second."""

	ENDPOINT = 'https://gw.example/v1/chat/completions'

	def setUp(self):
		import llm_analysis
		self.llm_analysis = llm_analysis
		self.saved_fetch = llm_catalog.fetch
		self.saved_config = dict(llm_analysis.config)
		llm_catalog._cache.clear()
		llm_catalog.fetch = lambda endpoint, api_key = '': ('openai', [
			llm_catalog.entry('text-only', False, False),
			llm_catalog.entry('sees', True, False),
			llm_catalog.entry('silent', None, None)])
		llm_analysis.config.update({'llmEndpoint': self.ENDPOINT, 'llmApiKey': '', 'llmModel': 'text-only'})

	def tearDown(self):
		llm_catalog.fetch = self.saved_fetch
		llm_catalog._cache.clear()
		self.llm_analysis.config.clear()
		self.llm_analysis.config.update(self.saved_config)

	def test_accepts_image(self):
		self.assertFalse(llm_catalog.accepts_image(self.ENDPOINT, '', 'text-only'))
		self.assertTrue(llm_catalog.accepts_image(self.ENDPOINT, '', 'sees'))
		self.assertIsNone(llm_catalog.accepts_image(self.ENDPOINT, '', 'silent'))
		self.assertIsNone(llm_catalog.accepts_image(self.ENDPOINT, '', 'not-listed'))

	def test_images_for_model(self):
		images = [{'name': 'a.png', 'mimetype': 'image/png', 'base64': 'AA=='}]
		self.assertIsNone(self.llm_analysis.images_for_model(images))
		self.assertEqual(self.llm_analysis.images_for_model(images, 'sees'), images)
		self.assertEqual(self.llm_analysis.images_for_model(images, 'silent'), images)
		self.assertEqual(self.llm_analysis.images_for_model(images, 'not-listed'), images)

	def test_provider_that_does_not_list_keeps_images(self):
		def broken(endpoint, api_key = ''):
			raise ValueError('down')
		llm_catalog.fetch = broken
		images = [{'name': 'a.png', 'mimetype': 'image/png', 'base64': 'AA=='}]
		self.assertEqual(self.llm_analysis.images_for_model(images), images)

	def test_query_llm_sends_no_image_to_a_text_only_model(self):
		sent = {}
		saved_chat = self.llm_analysis.chat
		def fake_chat(messages, model = None, images = None, force_json = True):
			sent['images'] = images
			sent['prompt'] = messages[-1]['content']
			return '{}'
		self.llm_analysis.chat = fake_chat
		try:
			self.llm_analysis.query_llm('s', 'corpo', images = [{'name': 'a.png', 'mimetype': 'image/png', 'base64': 'AA=='}])
		finally:
			self.llm_analysis.chat = saved_chat
		self.assertIsNone(sent['images'])
		# The prompt must not tell the model about images it did not receive
		self.assertNotIn('a.png', sent['prompt'])


if __name__ == '__main__':
	unittest.main()
