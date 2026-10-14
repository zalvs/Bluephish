"""A errata ao denunciante: "aquele e-mail que você denunciou era legítimo".

Existe porque o aviso de veredito já saiu. Quem denunciou recebeu "classificado
como malicioso" — e provavelmente apagou a mensagem, avisou o colega, deixou de
pagar a fatura. Quando uma pessoa do SOC conclui que era um falso positivo, a
correção precisa chegar a quem agiu com base no erro. Sem ela, a plataforma
treina os funcionários a desconfiar de correio legítimo, que é o oposto do que
um programa de conscientização quer.

Três regras:

  * **Só sai de um falso positivo corrigido** (`reclassification.is_false_positive`):
    de malicioso ou suspeito para legítimo. Confirmar malicioso não manda nada, e
    desfazer uma reclassificação também não — mandar "desconsidere a errata"
    sobre um e-mail é pior do que o silêncio.
  * **Duas travas, as duas precisam estar abertas.** O interruptor `errata` em
    Configurações › Notificações — que nasce desligado e não herda o `enabled`
    antigo (`mailer.notification_flags`) —, e a caixa marcada no formulário da
    decisão. A
    caixa existe porque a analista sabe coisas que a configuração não sabe: que
    o denunciante já foi avisado por telefone, ou que são quarenta denúncias da
    mesma campanha e ela vai avisar a empresa inteira de outro jeito.
  * **Nunca desfaz a decisão.** A reclassificação já está gravada quando isto
    roda. Um SMTP fora do ar vira um `outcome` com `ok: false` que a tela mostra,
    e não um erro que faz a analista achar que a decisão não valeu.

Sem Flask: `compose` é puro e testado em `test_errata.py`; `send` chama o
`mailer`, que já nunca levanta.
"""

import mailer

DEFAULT_MESSAGE = (
	'Errata: após análise humana, confirmamos que o e-mail com assunto [{subject}] que você '
	'denunciou é legítimo. A classificação anterior foi um falso positivo, e não é preciso '
	'tomar nenhuma providência sobre ele.\n\n'
	'Obrigado por denunciar — continue enviando o que parecer suspeito.'
)

SUBJECT_PREFIX = 'Errata: '

DESTINATION = 'Errata ao denunciante'


def compose(subject, message = None):
	"""(assunto, corpo) da errata para um e-mail com este assunto."""
	body = (message or DEFAULT_MESSAGE).replace('{subject}', subject or '(sem assunto)')
	return SUBJECT_PREFIX + (subject or '(sem assunto)'), body


def enabled(notif_conf):
	return mailer.notification_flags(notif_conf).get('errata', False)


def send(reporter, subject, notif_conf, send_mail = None):
	"""Manda a errata. Devolve um `outcome` no formato das reclassificações.

	`send_mail` existe para os testes; em produção é `mailer.send`.
	"""
	send_mail = send_mail or mailer.send
	notif_conf = notif_conf if isinstance(notif_conf, dict) else {}
	if not enabled(notif_conf):
		return {'destination': DESTINATION, 'ok': False,
			'detail': 'não enviada: a errata está desligada em Configurações › Notificações'}
	reporter = str(reporter or '').strip()
	if not reporter:
		# Uma análise anterior à impressão digital não guardou quem denunciou. Dito
		# por extenso, porque "enviada" sem destinatário seria mentira e "falhou"
		# faria a analista procurar um problema de SMTP que não existe
		return {'destination': DESTINATION, 'ok': False,
			'detail': 'não enviada: este registro não guardou quem denunciou'}
	mail_subject, body = compose(subject, notif_conf.get('errataMessage'))
	result = send_mail(reporter, mail_subject, body)
	if result.get('ok'):
		return {'destination': DESTINATION, 'ok': True, 'detail': 'enviada para {0}'.format(reporter)}
	return {'destination': DESTINATION, 'ok': False,
		'detail': 'não enviada para {0}: {1}'.format(reporter, result.get('error') or 'falha no envio')}
