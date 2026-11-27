"""O cookie de sessão sobrevive a um relógio que anda para trás.

A aplicação hoje usa jwt_session (o cookie é um JWT), que importa daqui a
tolerância (MAX_BACKWARD_SECONDS) e o ritmo do aviso; a interface abaixo é a do
cookie no formato do itsdangerous, e test_session_clock segue reproduzindo nela
o defeito original.

O cookie de sessão do Flask é assinado com um carimbo de tempo, e o itsdangerous
recusa o carimbo "do futuro": idade negativa é `SignatureExpired`. O Flask trata
isso como cookie inválido e abre uma sessão vazia, sem log e sem auditoria — a
pessoa é mandada para o login no meio do que estava fazendo.

E o relógio anda para trás. A VM do Docker Desktop corrige a hora aos saltos:
medido em 30/10/2026, 4,3 s para trás enquanto o painel coletava os feeds do
panorama. Todo cookie assinado nesses segundos passou a valer "daqui a 4 s", e as
requisições seguintes caíram como se a sessão tivesse acabado. Num servidor com
NTP o salto é raro, mas uma VM que volta de suspensão faz o mesmo.

A assinatura continua sendo conferida inteira pelo itsdangerous; muda só a regra
da idade. Um carimbo até MAX_BACKWARD_SECONDS no futuro é aceito — ele só pode ter
sido gerado por esta aplicação, com esta chave, quando o relógio estava adiantado.
Acima disso continua recusado, e o limite de 12 h segue igual. As regras de
inatividade e de duração absoluta da sessão (auth.py) leem os horários gravados
dentro da sessão e não são afetadas: um recuo só faz a sessão parecer mais nova.
"""

import logging
import time

import itsdangerous
from flask.sessions import SecureCookieSessionInterface

log = logging.getLogger('session_clock')

# Quanto o relógio pode ter recuado. Os saltos medidos no Docker Desktop foram de
# segundos; cinco minutos cobrem uma VM que volta de suspensão sem abrir margem
# que importe — o carimbo continua assinado com a chave da aplicação
MAX_BACKWARD_SECONDS = 300

# Um aviso por minuto basta: durante o salto, toda requisição passaria por aqui
WARN_EVERY_SECONDS = 60
_last_warning = [0.0]


class SkewTolerantSigner(itsdangerous.TimestampSigner):
	"""TimestampSigner que aceita idade negativa até MAX_BACKWARD_SECONDS."""

	def unsign(self, signed_value, max_age = None, return_timestamp = False):
		# Assinatura e carimbo conferidos pelo itsdangerous; só a idade fica aqui
		value, signed_at = super().unsign(signed_value, max_age = None, return_timestamp = True)
		if max_age is not None:
			age = self.get_timestamp() - int(signed_at.timestamp())
			if age > max_age:
				raise itsdangerous.SignatureExpired('Signature age {0} > {1} seconds'.format(age, max_age),
					payload = value, date_signed = signed_at)
			if age < -MAX_BACKWARD_SECONDS:
				raise itsdangerous.SignatureExpired('Signature age {0} < -{1} seconds'.format(age, MAX_BACKWARD_SECONDS),
					payload = value, date_signed = signed_at)
			if age < 0:
				_warn_backward(-age)
		if return_timestamp:
			return value, signed_at
		return value


def _warn_backward(seconds):
	now = time.monotonic()
	if now - _last_warning[0] >= WARN_EVERY_SECONDS:
		_last_warning[0] = now
		log.warning('the clock went back about %s s; session cookies signed before the jump are still accepted', seconds)


class SkewTolerantSessionInterface(SecureCookieSessionInterface):
	"""A sessão em cookie do Flask, assinada com o SkewTolerantSigner."""

	def get_signing_serializer(self, app):
		if not app.secret_key:
			return None
		return itsdangerous.URLSafeTimedSerializer(
			app.secret_key,
			salt = self.salt,
			serializer = self.serializer,
			signer = SkewTolerantSigner,
			signer_kwargs = dict(key_derivation = self.key_derivation, digest_method = self.digest_method)
		)
