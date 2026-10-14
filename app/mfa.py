"""Segundo fator por aplicativo autenticador (TOTP, RFC 6238).

Este módulo é só a mecânica do código de seis dígitos: gerar o segredo, montar
o `otpauth://` que o aplicativo lê no QR, e conferir um código apresentado. A
*política* — quem precisa, quando é cobrado, o que acontece quando falha — mora
em auth.py, e o estado por conta mora em models.py.

Três escolhas ficam fixas aqui de propósito:

  * **SHA-1, 6 dígitos, 30 segundos.** Não é a combinação mais forte que o RFC
    permite, é a única que os aplicativos exigidos pelo requisito (Google
    Authenticator, Microsoft Authenticator, Authy) leem sem falhar. Um segredo
    SHA-256 entra no Microsoft Authenticator sem reclamar e passa a gerar
    códigos que nunca batem — a pessoa fica trancada fora sem nenhuma mensagem
    de erro dizendo por quê. A força real está nos 160 bits do segredo, não no
    hash de seis dígitos derivado dele.

  * **Nenhum canal além do aplicativo.** Não existe aqui envio por e-mail nem
    por SMS, e não é omissão a ser preenchida depois: SMS cai com um SIM swap e
    e-mail cai junto com a caixa postal que esta própria plataforma existe para
    vigiar. Um segundo fator que chega pelo mesmo lugar que o phishing não é um
    segundo fator.

  * **Janela de ±1 passo.** Relógio de celular erra, e uma janela de um passo
    (30 s para cada lado) cobre isso. Cada passo a mais é um código a mais
    válido por tentativa, então a janela para em um — quem tem o relógio muito
    fora sincroniza o telefone, que é o conserto certo.

Contra repetição, quem chama guarda o contador que passou (`verify` devolve) e
o apresenta na conferência seguinte: um código já usado não entra de novo
enquanto ainda estiver dentro da janela. Sem isso, um código lido por cima do
ombro (ou colhido numa página de phishing) vale por até 90 segundos, que é
tempo de sobra para alguém digitá-lo em outro navegador.
"""

import os
import io
import re
import time
import base64
import hmac

import pyotp
import qrcode
import qrcode.constants
import qrcode.image.svg

DIGITS = 6
PERIOD_SECONDS = 30
# Passos aceitos para cada lado do atual (ver o cabeçalho)
VALID_WINDOW = 1

# Nome que o aplicativo autenticador mostra na lista. Configurável porque quem
# opera mais de uma instalação (homologação e produção, por exemplo) precisa
# distinguir as duas contas no telefone
ISSUER = os.environ.get('BLUEPHISH_MFA_ISSUER', '').strip() or 'bluephish'

# Só dígitos, e exatamente DIGITS deles. Espaço e hífen são retirados antes
# porque alguns aplicativos mostram o código como "123 456" e quem copia leva o
# espaço junto
_SEPARATORS = re.compile(r'[\s\-]')


def new_secret():
	"""Um segredo novo, em base32 (160 bits, o tamanho recomendado pelo RFC 4226)."""
	return pyotp.random_base32()


def normalize_code(code):
	"""O código como o algoritmo o espera, ou None se não for um código.

	Devolver None em vez de levantar mantém a conferência com uma saída só: um
	código malformado e um código errado terminam no mesmo lugar, e quem chama
	não precisa distinguir os dois para responder a mesma coisa.
	"""
	if code is None:
		return None
	cleaned = _SEPARATORS.sub('', str(code))
	if len(cleaned) != DIGITS or not cleaned.isdigit():
		return None
	return cleaned


def provisioning_uri(username, secret):
	"""O `otpauth://` que vira o QR e que o aplicativo lê."""
	return pyotp.TOTP(secret, digits = DIGITS, interval = PERIOD_SECONDS).provisioning_uri(
		name = username, issuer_name = ISSUER)


def qr_data_uri(uri):
	"""O QR como `data:` de um SVG, pronto para o `src` de uma <img>.

	SVG e não PNG porque não depende de Pillow (que não está na imagem) e
	escala sem borrar. `data:` porque a Content-Security-Policy da aplicação
	permite `img-src 'self' data:` — servir o QR num endereço próprio deixaria
	o segredo numa URL, que é exatamente onde ele não pode ficar (histórico do
	navegador, log de acesso, Referer).

	`SvgPathFillImage` e não `SvgPathImage`: o segundo desenha os módulos sem
	fundo, e sobre o tema escuro do painel o preto no transparente vira um
	quadrado invisível que nenhuma câmera lê.
	"""
	image = qrcode.make(uri,
		image_factory = qrcode.image.svg.SvgPathFillImage,
		error_correction = qrcode.constants.ERROR_CORRECT_M,
		box_size = 10, border = 2)
	buffer = io.BytesIO()
	image.save(buffer)
	return 'data:image/svg+xml;base64,' + base64.b64encode(buffer.getvalue()).decode('ascii')


def current_counter(now = None):
	return int((now if now is not None else time.time()) // PERIOD_SECONDS)


def verify(secret, code, last_counter = None, now = None):
	"""Confere um código e devolve `(ok, contador)`.

	O contador é o passo de tempo que casou. Quem chama o guarda e o devolve em
	`last_counter` na próxima conferência: passo menor ou igual ao último usado
	é recusado sem sequer ser comparado, e é isso que impede a repetição de um
	código ainda dentro da janela.

	A comparação é feita com `hmac.compare_digest` — em tempo constante. Um `==`
	comum sai no primeiro dígito diferente, e a diferença de tempo entre "errou
	no primeiro" e "errou no último" é medível pela rede; com seis dígitos e um
	oráculo desses, o código sai dígito a dígito em algumas centenas de
	tentativas em vez do milhão que ele deveria custar.
	"""
	normalized = normalize_code(code)
	if not secret or normalized is None:
		return False, None
	totp = pyotp.TOTP(secret, digits = DIGITS, interval = PERIOD_SECONDS)
	now = now if now is not None else time.time()
	current = current_counter(now)
	for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
		counter = current + offset
		if last_counter is not None and counter <= last_counter:
			continue
		if hmac.compare_digest(totp.at(counter * PERIOD_SECONDS), normalized):
			return True, counter
	return False, None
