"""Catálogo de modelos do provedor de LLM configurado, para o seletor da tela de IA.

Três formatos de provedor, os mesmos que `llm_analysis.chat()` sabe chamar:

* **OpenRouter** — `GET /api/v1/models` é público e diz, por modelo, o que ele
  aceita de entrada (`architecture.input_modalities`). A lista é cortada nos
  fabricantes que interessam: Anthropic, OpenAI e os chineses mais usados.
* **Ollama** — `GET /api/tags` lista o que está baixado e `POST /api/show`
  devolve `capabilities` por modelo (`vision` quando lê imagem).
* **Qualquer outro compatível com OpenAI** (LiteLLM, vLLM, gateways) —
  `GET {base}/models`. O que o modelo aceita vem do próprio item quando o
  gateway informa, ou do `/model/info` do LiteLLM.

Duas regras que falham em silêncio se forem quebradas:

1. **Capacidade desconhecida é `None`, nunca `False`.** Um gateway que não diz
   se o modelo lê imagem não disse que ele não lê. A tela mostra "o provedor não
   informa" — não inventa dado (ver ROADMAP.md).
2. **A chave de API nunca volta para o navegador**, e a chave salva só é usada
   quando o host pedido é o mesmo host salvo — a mesma regra de
   `update_llm_config`, para que ninguém aponte o endpoint para um servidor seu e
   receba a chave como bearer token.

Este módulo não usa `logging`: um logger novo teria de entrar em
`logging_conf.json` (THEPHISH_ARCHITECTURE.md, armadilhas silenciosas).
"""

import hashlib
import re
import time
from urllib.parse import urlparse, urlunparse

import requests


REQUEST_TIMEOUT = (5, 20)
# A lista do OpenRouter tem centenas de modelos e passa de 1 MB; acima disto
# a resposta não é um catálogo
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
# Cada modelo do Ollama custa um POST /api/show; uma instalação com mais do que
# isto lista os nomes sem capacidade em vez de travar a tela
MAX_OLLAMA_SHOW = 60
CACHE_SECONDS = 300
ERROR_CACHE_SECONDS = 60

OPENROUTER_MODELS_URL = 'https://openrouter.ai/api/v1/models'

# Fabricantes, na ordem em que aparecem no seletor. `patterns` reconhece o
# fabricante pelo nome do modelo quando o provedor não diz (Ollama, gateways
# que declaram `owned_by: openai` para tudo)
OWNERS = [
	('anthropic', 'Anthropic', r'claude'),
	('openai', 'OpenAI', r'^(gpt|o[1-9]\b|o[1-9]-|chatgpt|text-embedding|dall-e|whisper|tts-|davinci|babbage|codex)'),
	('google', 'Google', r'gemini|gemma|palm'),
	('deepseek', 'DeepSeek', r'deepseek'),
	('qwen', 'Qwen', r'qwen|qwq'),
	('moonshotai', 'Moonshot AI', r'kimi|moonshot'),
	('z-ai', 'Z.ai', r'glm'),
	('minimax', 'MiniMax', r'minimax'),
	('meta-llama', 'Meta', r'llama'),
	('mistralai', 'Mistral', r'mistral|mixtral|codestral|ministral|pixtral|magistral|devstral'),
	('microsoft', 'Microsoft', r'^phi'),
]
OWNER_LABELS = {key: label for key, label, _ in OWNERS}
OWNER_ORDER = {key: index for index, (key, _, _) in enumerate(OWNERS)}
# Aliases com que provedores escrevem o mesmo fabricante
OWNER_ALIASES = {
	'meta': 'meta-llama', 'mistral': 'mistralai', 'alibaba': 'qwen', 'zhipuai': 'z-ai',
	'thudm': 'z-ai', 'moonshot': 'moonshotai', 'google-ai': 'google', 'vertex_ai': 'google',
}

# No OpenRouter o seletor mostra só estes: o pedido é Anthropic, OpenAI e os
# chineses populares — não as centenas de ids da lista completa
OPENROUTER_OWNERS = ('anthropic', 'openai', 'deepseek', 'qwen', 'moonshotai', 'z-ai', 'minimax')

_cache = {}


def provider_kind(endpoint):
	"""Mesma decisão de `llm_analysis.chat()`: o formato segue a URL."""
	host = urlparse(endpoint).netloc.lower()
	if host == 'openrouter.ai' or host.endswith('.openrouter.ai'):
		return 'openrouter'
	if '/api/chat' in endpoint:
		return 'ollama'
	return 'openai'


def infer_owner(model_id, owned_by = None):
	"""Chave do fabricante: prefixo `dono/` do id, depois o nome, depois `owned_by`."""
	lowered = (model_id or '').lower()
	if '/' in lowered:
		prefix = lowered.split('/', 1)[0]
		prefix = OWNER_ALIASES.get(prefix, prefix)
		if prefix in OWNER_LABELS:
			return prefix
	name = lowered.rsplit('/', 1)[-1]
	for key, _, pattern in OWNERS:
		if re.search(pattern, name):
			return key
	declared = OWNER_ALIASES.get((owned_by or '').lower(), (owned_by or '').lower())
	if declared in OWNER_LABELS:
		return declared
	return 'other'


def owner_label(key, owned_by = None):
	if key in OWNER_LABELS:
		return OWNER_LABELS[key]
	return 'Outros'


def entry(model_id, image, file, owned_by = None, display = None):
	owner = infer_owner(model_id, owned_by)
	return {
		'id': model_id,
		# No OpenRouter o prefixo já é o grupo; o valor salvo continua o id inteiro
		'name': display or model_id,
		'owner': owner,
		'ownerLabel': owner_label(owner, owned_by),
		'image': image,
		'file': file,
	}


def sort_models(models):
	return sorted(models, key = lambda m: (OWNER_ORDER.get(m['owner'], len(OWNERS)), m['name'].lower()))


def modalities_flags(modalities):
	"""(imagem, arquivo) de uma lista de modalidades; `None` quando não há lista."""
	if not isinstance(modalities, list):
		return None, None
	lowered = [str(m).lower() for m in modalities]
	return 'image' in lowered, 'file' in lowered


# --- parsing (puro, testado sem rede) ------------------------------------------

def parse_openrouter(payload):
	models = []
	for item in (payload or {}).get('data') or []:
		model_id = item.get('id') or ''
		owner = model_id.split('/', 1)[0] if '/' in model_id else ''
		if owner not in OPENROUTER_OWNERS:
			continue
		architecture = item.get('architecture') or {}
		output = architecture.get('output_modalities')
		# Modelos que só geram imagem ou áudio não servem para a análise
		if isinstance(output, list) and 'text' not in output:
			continue
		image, file = modalities_flags(architecture.get('input_modalities'))
		models.append(entry(model_id, image, file, display = model_id.split('/', 1)[1]))
	return sort_models(models)


def parse_ollama(tags, capabilities_by_name):
	models = []
	for item in (tags or {}).get('models') or []:
		name = item.get('name') or item.get('model') or ''
		if not name:
			continue
		capabilities = capabilities_by_name.get(name)
		if isinstance(capabilities, list):
			image = 'vision' in capabilities
		else:
			image = None
		# O Ollama não recebe arquivo pela API de chat: não há o que informar
		models.append(entry(name, image, None))
	return sort_models(models)


def item_capabilities(item):
	"""O que um item de `/models` diz sobre entrada, nos formatos que já existem."""
	architecture = item.get('architecture') or {}
	for modalities in (item.get('input_modalities'), architecture.get('input_modalities'),
			(item.get('modalities') or {}).get('input') if isinstance(item.get('modalities'), dict) else None):
		image, file = modalities_flags(modalities)
		if image is not None:
			return image, file
	capabilities = item.get('capabilities')
	if isinstance(capabilities, dict):
		image = capabilities.get('vision', capabilities.get('image_input'))
		file = capabilities.get('pdf_input', capabilities.get('file_input'))
		return (bool(image) if image is not None else None), (bool(file) if file is not None else None)
	if isinstance(capabilities, list):
		lowered = [str(c).lower() for c in capabilities]
		return ('vision' in lowered or 'image' in lowered), ('file' in lowered or 'pdf' in lowered or None)
	return None, None


def parse_openai_models(payload, litellm_info = None):
	info_by_name = {}
	for item in (litellm_info or {}).get('data') or []:
		info = item.get('model_info') or {}
		name = item.get('model_name')
		if name:
			info_by_name[name] = info
	models = []
	seen = set()
	for item in (payload or {}).get('data') or []:
		model_id = item.get('id') or ''
		if not model_id or model_id in seen:
			continue
		seen.add(model_id)
		image, file = item_capabilities(item)
		info = info_by_name.get(model_id)
		if info:
			if image is None and info.get('supports_vision') is not None:
				image = bool(info.get('supports_vision'))
			if file is None and info.get('supports_pdf_input') is not None:
				file = bool(info.get('supports_pdf_input'))
		models.append(entry(model_id, image, file, owned_by = item.get('owned_by')))
	return sort_models(models)


def openai_base(endpoint):
	"""`https://gw/v1/chat/completions` -> `https://gw/v1`."""
	parsed = urlparse(endpoint)
	path = parsed.path.rstrip('/')
	for suffix in ('/chat/completions', '/completions', '/responses'):
		if path.endswith(suffix):
			path = path[:-len(suffix)]
			break
	return urlunparse((parsed.scheme, parsed.netloc, path, '', '', ''))


def root_of(endpoint):
	parsed = urlparse(endpoint)
	return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))


# --- rede ----------------------------------------------------------------------

def _check(response):
	response.raise_for_status()
	if len(response.content) > MAX_RESPONSE_BYTES:
		raise ValueError('resposta grande demais para um catálogo de modelos')
	return response.json()


def http_get(url, headers = None):
	# Sem redirect: o destino é o host que o admin digitou, não outro que ele indique
	return _check(requests.get(url, headers = headers or {}, timeout = REQUEST_TIMEOUT, allow_redirects = False))


def http_post(url, payload):
	return _check(requests.post(url, json = payload, timeout = REQUEST_TIMEOUT, allow_redirects = False))


def bearer(api_key):
	return {'Authorization': 'Bearer ' + api_key} if api_key else {}


def fetch(endpoint, api_key = '', get = http_get, post = http_post):
	kind = provider_kind(endpoint)
	if kind == 'openrouter':
		# Lista pública: a chave não precisa sair daqui
		return kind, parse_openrouter(get(OPENROUTER_MODELS_URL))
	if kind == 'ollama':
		root = root_of(endpoint)
		tags = get(root + '/api/tags')
		capabilities = {}
		for item in ((tags or {}).get('models') or [])[:MAX_OLLAMA_SHOW]:
			name = item.get('name') or item.get('model')
			try:
				capabilities[name] = (post(root + '/api/show', {'model': name}) or {}).get('capabilities')
			except Exception:
				# Um modelo que não responde fica com capacidade desconhecida
				capabilities[name] = None
		return kind, parse_ollama(tags, capabilities)
	base = openai_base(endpoint)
	payload = get(base + '/models', bearer(api_key))
	litellm_info = None
	for url in (base + '/model/info', root_of(endpoint) + '/model/info'):
		try:
			litellm_info = get(url, bearer(api_key))
			break
		except Exception:
			continue
	return kind, parse_openai_models(payload, litellm_info)


def list_models(endpoint, api_key = ''):
	"""{'provider', 'models'} ou {'error'}; nunca levanta exceção."""
	if not (endpoint.startswith('http://') or endpoint.startswith('https://')) or not urlparse(endpoint).netloc:
		return {'error': 'Preencha o HOST / ENDPOINT com uma URL http:// ou https:// antes de escolher o modelo.'}
	key_digest = hashlib.sha256((api_key or '').encode('utf-8')).hexdigest()[:16]
	cache_key = (endpoint, key_digest)
	cached = _cache.get(cache_key)
	if cached and time.time() - cached[0] < CACHE_SECONDS:
		return cached[1]
	try:
		kind, models = fetch(endpoint, api_key)
	except requests.HTTPError as e:
		status = e.response.status_code if e.response is not None else None
		if status in (401, 403):
			result = {'error': 'O provedor recusou a chave de API ao listar os modelos (HTTP {0}).'.format(status)}
		else:
			result = {'error': 'O provedor respondeu HTTP {0} ao listar os modelos.'.format(status)}
	except Exception:
		result = {'error': 'Não foi possível listar os modelos em {0}.'.format(urlparse(endpoint).netloc)}
	else:
		result = {'provider': kind, 'models': models}
	# An error is remembered too, for less time: the analysis asks this before
	# every e-mail, and a provider that does not list models must not add a
	# timeout to each one of them
	_cache[cache_key] = (time.time() - (CACHE_SECONDS - ERROR_CACHE_SECONDS if 'error' in result else 0), result)
	return result


def accepts_image(endpoint, api_key, model):
	"""True/False as the provider reports it; None when it does not say.

	Only False lets the analysis hold images back. None — the provider did not
	list models, did not list this one, or does not report capabilities — keeps
	sending them, which is what the analysis always did.
	"""
	catalog = list_models(endpoint or '', api_key or '')
	for item in catalog.get('models') or []:
		if item['id'] == model:
			return item['image']
	return None
