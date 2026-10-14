"""Observáveis que o extrator encontra e que não são o que parecem.

`ioc_finder` acha domínios por forma, e há textos com forma de domínio que não
são domínio de ninguém. O caso que motivou este módulo: todo e-mail do LinkedIn
traz o selo "Disponível no Google Play", com o link
`play.google.com/store/apps/details?id=com.linkedin.android`. O identificador do
pacote Android é um nome reverso (`com.linkedin.android`), `.android` é um TLD
real do Google, e o extrator o entregou como domínio ao VirusTotal — que teve
um motor chamando de suspeito o domínio que não existe, e um aviso de vaga no
LinkedIn fechou como Suspicious (2026-09-09).

O filtro é estreito de propósito. Um domínio dentro de parâmetro de URL é, na
maioria das vezes, exatamente o que interessa (`?url=golpe.example` num link de
redirecionamento), então só o `id=` das lojas de aplicativo é reconhecido, e só
é descartado o candidato que **não aparece em nenhum outro lugar** do texto.

Puro, sem rede e sem `emoji`, para ser testado fora da imagem.
"""

import re


# O identificador de pacote no link de uma loja de aplicativos: Google Play e o
# esquema market:// que o Android abre direto. A App Store usa id numérico, que
# não tem forma de domínio e não precisa de filtro
APP_STORE_PACKAGE = re.compile(
	r'(?:play\.google\.com/store/apps/details|market://details)\?'
	r'(?:[^\s"\'<>]*?(?:&amp;|&))?id=([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)',
	re.IGNORECASE)


def app_package_ids(buffer):
	"""{identificador em minúsculas: quantas vezes aparece como id= de loja}."""
	counts = {}
	for match in APP_STORE_PACKAGE.finditer(str(buffer or '')):
		key = match.group(1).lower()
		counts[key] = counts.get(key, 0) + 1
	return counts


def is_app_package_only(domain, buffer, packages = None):
	"""Se este candidato a domínio só existe no texto como id de loja de aplicativo."""
	key = str(domain or '').strip().lower()
	if not key:
		return False
	packages = app_package_ids(buffer) if packages is None else packages
	as_package = packages.get(key, 0)
	if not as_package:
		return False
	anywhere = len(re.findall(r'(?<![A-Za-z0-9.-])' + re.escape(key) + r'(?![A-Za-z0-9-])',
		str(buffer or ''), re.IGNORECASE))
	return anywhere <= as_package
