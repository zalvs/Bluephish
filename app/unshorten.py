"""Resolução de encurtadores — o que o UnshortenLink do Cortex fazia.

Uma URL encurtada esconde o destino de todo analisador de reputação: bit.ly não
está em blocklist nenhuma, e o domínio de phishing atrás dela nunca chega a ser
consultado. O pipeline resolvia isso com o analisador UnshortenLink do Cortex,
que seguia os redirecionamentos e devolvia o destino final. Este módulo faz o
mesmo sem o Cortex no meio.

A diferença que importa: **a URL vem do e-mail de um atacante**. Seguir
redirecionamento cegamente transformaria o servidor num proxy para a rede
interna — exatamente o SSRF que `custom_analyzers.validate_destination()` existe
para barrar. Então cada salto é validado antes de ser seguido, com a mesma trava
e sem liberar a rede interna, e o serviço de metadados da nuvem continua barrado
mesmo que o redirecionamento aponte direto para ele.

Nada é baixado: só o cabeçalho `Location` de cada resposta é lido. O corpo da
página de phishing não interessa e não é buscado.
"""

import traceback

from urllib.parse import urljoin

import requests

import custom_analyzers
import pinned_http

# Um encurtador responde na hora; um destino que demora é um destino que não vale
# a espera dentro do pipeline
HTTP_TIMEOUT = (5, 10)

# Cadeias mais longas que isso são armadilha de laço ou tentativa de estourar o
# tempo da análise, não um encurtador legítimo
MAX_HOPS = 10

REDIRECT_CODES = (301, 302, 303, 307, 308)

# Só o suficiente para o encurtador não devolver uma página de bloqueio de bot
USER_AGENT = 'Mozilla/5.0 (compatible; BluePhish/1.0; +unshortener)'


def _next_hop(response, current):
	"""A próxima URL absoluta da cadeia, ou '' quando a resposta não redireciona."""
	if response.status_code not in REDIRECT_CODES:
		return ''
	location = response.headers.get('Location') or response.headers.get('location') or ''
	location = location.strip()
	if not location:
		return ''
	# Um Location relativo é legítimo e comum; resolvê-lo contra a URL atual é o
	# que o navegador faria
	return urljoin(current, location)


def resolve(url):
	"""Segue a cadeia de redirecionamentos. Devolve {found, url, chain, error}.

	`found` é True só quando a URL final é diferente da original — é esse o
	contrato que o pipeline usa para decidir se cria um observável novo.
	Nunca levanta: um encurtador fora do ar não pode derrubar a análise.
	"""
	original = str(url or '').strip()
	result = {'found': False, 'url': original, 'chain': [], 'error': ''}
	if not original:
		result['error'] = 'URL vazia.'
		return result

	# `require_https = False`: um encurtador em http é comum, e aqui nada sai na
	# requisição — nem credencial nem observável, só um HEAD numa URL que já estava
	# no e-mail. A trava de *endereço* continua inteira, e é a que importa.
	ok, error = custom_analyzers.validate_destination(original, require_https = False)
	if not ok:
		result['error'] = 'Destino recusado: {0}'.format(error)
		return result

	current = original
	# Fixada no endereço aprovado: é o encadeamento inteiro que quem escreveu o
	# e-mail escolhe, e um nome dele pode responder diferente à trava e à conexão.
	# Sessão própria, e não a compartilhada, porque um encurtador pode depender do
	# cookie que o salto anterior pôs
	session = pinned_http.session()
	try:
		for _hop in range(MAX_HOPS):
			try:
				response = session.head(current, allow_redirects = False, timeout = HTTP_TIMEOUT,
					headers = {'User-Agent': USER_AGENT})
				# Nem todo encurtador responde a HEAD; quando ele recusa o método,
				# um GET resolve — e o corpo continua sem ser lido
				if response.status_code in (400, 403, 405, 501):
					response = session.get(current, allow_redirects = False, timeout = HTTP_TIMEOUT,
						headers = {'User-Agent': USER_AGENT}, stream = True)
					response.close()
			except pinned_http.DestinationRefused as refused:
				result['error'] = 'Destino recusado: {0}'.format(refused)
				break
			except requests.exceptions.Timeout:
				result['error'] = '{0} não respondeu dentro do tempo limite.'.format(current)
				break
			except requests.exceptions.RequestException as request_error:
				result['error'] = 'Não foi possível alcançar {0}: {1}'.format(
					current, type(request_error).__name__)
				break

			following = _next_hop(response, current)
			if not following:
				break

			# A trava roda em cada salto, não só no primeiro: a cadeia inteira é
			# escolhida por quem escreveu o e-mail
			ok, error = custom_analyzers.validate_destination(following, require_https = False)
			if not ok:
				result['error'] = 'Redirecionamento recusado para {0}: {1}'.format(following, error)
				break

			current = following
			result['chain'].append(current)
		else:
			result['error'] = 'A cadeia de redirecionamentos passou de {0} saltos.'.format(MAX_HOPS)
	except Exception:
		print("[ERROR]_[unshorten]: failed to resolve {0}: {1}".format(original, traceback.format_exc()))
		result['error'] = 'Falha inesperada ao resolver a URL.'
	finally:
		session.close()

	result['url'] = current
	result['found'] = current != original
	return result
