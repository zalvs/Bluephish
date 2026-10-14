#!/usr/bin/env python3
# Command line administration for bluephish.
#
# The application never ships a default account with a known password: the very
# first global_admin is created here, interactively, by whoever installs it.
#
# The service name is `thephish` and not `bluephish` because renaming it would
# recreate the container and lose the bind mounts; the name is an identifier the
# stack answers to, not the name of the product.
#
#   docker compose exec thephish python3 manage.py create-admin
#   docker compose exec thephish python3 manage.py list-users
#   docker compose exec thephish python3 manage.py reset-password <username>
#   docker compose exec thephish python3 manage.py reset-mfa <username>
#
# The password is read with getpass (never echoed, never taken from argv, so it
# does not end up in the shell history or in the process list).
#
# E duas leituras da metodologia de score, que nao tocam usuario nenhum:
#
#   docker compose exec thephish python3 manage.py weights
#   docker compose exec thephish python3 manage.py score /tmp/amostra.eml
import sys
import getpass
import argparse

import models
from models import ROLES, ROLE_GLOBAL_ADMIN, MIN_PASSWORD_LENGTH


def _read_password(prompt = 'Password: '):
	password = getpass.getpass(prompt)
	confirmation = getpass.getpass('Confirm password: ')
	if password != confirmation:
		print('The two passwords do not match.')
		return None
	policy_error = models.validate_password(password)
	if policy_error:
		print(policy_error)
		return None
	return password


def cmd_create_admin(args):
	models.init_db()
	username = args.username or input('Username for the new global_admin: ').strip()
	if not username:
		print('The username cannot be empty.')
		return 1
	print('The password must be at least {0} characters long and is not echoed.'.format(MIN_PASSWORD_LENGTH))
	password = _read_password()
	if password is None:
		return 1
	try:
		user_id = models.create_user(username, password, ROLE_GLOBAL_ADMIN)
	except ValueError as e:
		print('Error: {0}'.format(e))
		return 1
	print('Created global_admin "{0}" (id {1}). Sign in through the web interface.'.format(username, user_id))
	return 0


def cmd_create_user(args):
	models.init_db()
	if args.role not in ROLES:
		print('Unknown role {0}. Valid roles: {1}'.format(args.role, ', '.join(ROLES)))
		return 1
	password = _read_password()
	if password is None:
		return 1
	try:
		user_id = models.create_user(args.username, password, args.role)
	except ValueError as e:
		print('Error: {0}'.format(e))
		return 1
	print('Created {0} "{1}" (id {2}).'.format(args.role, args.username, user_id))
	return 0


def cmd_list_users(args):
	models.init_db()
	session = models.get_session()
	try:
		users = session.query(models.User).order_by(models.User.username).all()
		if not users:
			print('No user exists yet. Create the first one with: python3 manage.py create-admin')
			return 0
		print('{0:<5} {1:<24} {2:<14} {3:<10} {4:<7} {5}'.format('ID', 'USERNAME', 'ROLE', 'LOCKED', 'MFA', 'LAST LOGIN'))
		for user in users:
			print('{0:<5} {1:<24} {2:<14} {3:<10} {4:<7} {5}'.format(
				user.id, user.username, user.role,
				'yes' if user.is_locked() else 'no',
				'yes' if user.mfa_is_enrolled() else 'PENDING',
				user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else '-'))
		return 0
	finally:
		session.close()


def cmd_reset_password(args):
	models.init_db()
	session = models.get_session()
	try:
		user = session.query(models.User).filter(models.User.username == args.username).first()
		if user is None:
			print('User {0} not found.'.format(args.username))
			return 1
		password = _read_password('New password for {0}: '.format(args.username))
		if password is None:
			return 1
		user.set_password(password)
		# Resetting also clears an active lockout
		user.failed_logins = 0
		user.locked_until = None
		session.commit()
		print('Password updated for {0}. Every active session of this user has been revoked.'.format(args.username))
		return 0
	finally:
		session.close()


# O caminho de recuperação de última instância. A tela de Usuários faz o mesmo,
# mas ela exige um global_admin capaz de entrar — e quem tem exatamente um
# global_admin, que perdeu o telefone, não tem esse alguém. Daqui se sai de
# dentro do container, o que é uma prova de acesso mais forte que qualquer
# sessão
def cmd_reset_mfa(args):
	models.init_db()
	session = models.get_session()
	try:
		user = session.query(models.User).filter(models.User.username == args.username).first()
		if user is None:
			print('User {0} not found.'.format(args.username))
			return 1
		if not user.mfa_secret:
			print('{0} has no MFA configured; the next sign-in will ask for it.'.format(args.username))
			return 0
		user.reset_mfa()
		session.commit()
		print('MFA cleared for {0}. The next sign-in will require configuring an authenticator app again.'.format(args.username))
		return 0
	finally:
		session.close()


def cmd_unlock(args):
	models.init_db()
	session = models.get_session()
	try:
		user = session.query(models.User).filter(models.User.username == args.username).first()
		if user is None:
			print('User {0} not found.'.format(args.username))
			return 1
		user.failed_logins = 0
		user.locked_until = None
		session.commit()
		print('Account {0} unlocked.'.format(args.username))
		return 0
	finally:
		session.close()


# --------------------------------------------------------------------------- #
# Metodologia de score — inspecao offline                                      #
# --------------------------------------------------------------------------- #
#
# Estes dois comandos existem por um problema concreto de operacao: a unica
# forma de ver um score ate agora era rodar uma analise inteira, o que exige
# caixa monitorada, chave de fornecedor com cota e TheHive de pe. Calibrar peso
# assim custa uma analise real por tentativa — e queima cota para produzir um
# numero, nao um veredito.
#
# Aqui nao ha rede: `score` le um .eml do disco, extrai autenticacao e
# cabecalhos de massa de verdade, e recebe os niveis dos analisadores como
# argumento. E a configuracao viva que responde, a mesma que o pipeline le, de
# modo que o que sai daqui e o que sairia de la.


def cmd_weights(args):
	"""O ranking de fatores como a tela de Priorizacao o mostra."""
	import analyzers
	import custom_analyzers
	import scoring

	config = scoring.load_config()
	rows = scoring.factor_rows(analyzers.load_config(), custom_analyzers.load_all(), config)

	print('Modo: {0}  ·  faixas: phishing >= {1}, suspeito/spam >= {2}, legitimo >= {3}'.format(
		config['mode'], config['tiers']['phishing'], config['tiers']['suspicious'],
		config['tiers']['legitimate']))
	print('Triagem de spam: {0}  ·  pular analisadores nela: {1}'.format(
		'ligada' if config['spamTriage'] else 'desligada',
		'sim' if config['spamSkipAnalysis'] else 'nao'))
	print('')
	# 38 e 30 nao sao arbitrarios: cabem o nome e a fonte mais longos do registro
	# ('Microsoft Defender Threat Intelligence'). A tesoura fica para nome que a
	# analista deu a um analisador dela — truncar um nome do registro tornaria
	# ambigua justamente a coluna pela qual se escolhe o peso a mexer
	print('{0:>6}  {1:>5}  {2:<38} {3:<30} {4}'.format('SCORE', 'PESO', 'PRIO', 'FONTE', 'SITUACAO'))
	for row in rows:
		print('{0:>6.1f}  {1:>5.2f}  {2:<38} {3:<30} {4}'.format(
			row['weightShare'], row['weight'], row['name'][:38], row['source'][:30],
			'sinal' if row['kind'] == 'signal' else ('ativo' if row['enabled'] else 'desativado')))
	print('')
	# Sem fator de conviccao o teto entra em acao e o score nunca alcanca a faixa
	# de phishing. Quem esta calibrando peso precisa saber disso antes de concluir
	# que a metodologia "nao marca nada"
	conviction = [row for row in rows if row['enabled'] and row['conviction'] and row['weight'] > 0]
	if not conviction:
		print('AVISO: nenhum fator de conviccao habilitado com peso > 0. Cabecalho de massa e')
		print('falha de autenticacao nao condenam sozinhos, entao o score fica limitado a um')
		print('ponto abaixo da faixa de phishing ate um analisador ou o LLM participar.')
	else:
		print('{0} fator(es) capaz(es) de levar o score a faixa de phishing.'.format(len(conviction)))
	return 0


def _parse_analyzer_levels(pairs):
	"""`--analisador virustotal=malicious` -> relatorios sinteticos.

	Recusa um id que nao existe em vez de ignora-lo: um peso digitado errado que
	e silenciosamente descartado produz um score que a pessoa atribui ao
	analisador que ela pensou ter informado.
	"""
	import analyzers
	import custom_analyzers
	import scoring

	known = set(analyzers.BY_ID)
	known.update(d['id'] for d in custom_analyzers.load_all())
	reports = []
	for index, pair in enumerate(pairs or []):
		if '=' not in pair:
			return None, 'Use a forma id=nivel, por exemplo virustotal=malicious. Recebido: {0}'.format(pair)
		analyzer_id, level = pair.split('=', 1)
		analyzer_id = analyzer_id.strip()
		level = level.strip().lower()
		if analyzer_id not in known:
			return None, 'Analisador desconhecido: {0}. Conhecidos: {1}'.format(
				analyzer_id, ', '.join(sorted(known)))
		if level not in scoring.LEVEL_FACTOR:
			return None, 'Nivel invalido: {0}. Use um de: {1}'.format(
				level, ', '.join(scoring.LEVEL_FACTOR))
		reports.append({
			'observable_id': 'obs-{0}'.format(index), 'observable_name': '(simulado)',
			'observable_type': 'url', 'analyzer_id': analyzer_id, 'analyzer_name': analyzer_id,
			'analyzer_result': level, 'analyzer_detail': '', 'analyzer_error': ''
		})
	return reports, None


def _baseline_verdict(reports):
	"""O veredito dos analisadores, pela mesma regra de terminate_analysis."""
	levels = [r['analyzer_result'] for r in reports]
	if 'malicious' in levels:
		return 'Malicious'
	if 'suspicious' in levels:
		return 'Suspicious'
	return 'Safe'


def cmd_score(args):
	import email
	import json

	import case_from_email
	import custom_analyzers
	import scoring
	import spam_headers

	try:
		with open(args.eml, 'rb') as handle:
			message = email.message_from_binary_file(handle)
	except Exception as e:
		print('Nao foi possivel ler {0}: {1}'.format(args.eml, e))
		return 1

	reports, error = _parse_analyzer_levels(args.analyzer)
	if error:
		print(error)
		return 1

	llm = None
	if args.llm:
		risk = args.llm.capitalize()
		if risk not in scoring.RISK_FACTOR:
			print('Risco invalido: {0}. Use um de: {1}'.format(
				args.llm, ', '.join(scoring.RISK_FACTOR)))
			return 1
		llm = {'social_engineering_detected': not args.llm_clean, 'risk_level': risk,
			'tactics': [], 'justification': '(simulado)'}

	auth = case_from_email.extract_authentication_results(message)
	subject = str(message.get('Subject', '') or '')
	bulk = spam_headers.scan(message, subject)

	config = scoring.load_config()
	verdict = _baseline_verdict(reports)
	result = scoring.compute(verdict, reports, llm, auth, bulk, config,
		custom_definitions = custom_analyzers.load_all())
	final, reason = scoring.verdict_after(verdict, result, auth)

	if args.json:
		print(json.dumps({'authentication': auth, 'bulk': bulk, 'score': result,
			'verdictBefore': verdict, 'verdictAfter': final, 'reason': reason},
			indent = '\t', ensure_ascii = False))
		return 0

	print('ARQUIVO      {0}'.format(args.eml))
	print('ASSUNTO      {0}'.format(subject[:70] or '(sem assunto)'))
	print('DE           {0}'.format(auth['fromAddress'] or '(nao identificado)'))
	print('AUTENTICACAO spf={0} dkim={1} dmarc={2}  ->  {3}'.format(
		auth['spf'], auth['dkim'], auth['dmarc'],
		'dominio autenticado' if auth['authenticated'] else 'dominio NAO autenticado'))
	print('')
	print('CABECALHOS DE MASSA  sinal {0:.2f}'.format(bulk['value']))
	if bulk['markers']:
		for marker in bulk['markers']:
			print('  + {0:<44} {1:>5.2f}  {2}'.format(
				marker['label'][:44], marker['weight'], marker['rfc']))
	else:
		print('  nenhum marcador')
	print('')
	print('MEMORIA DE CALCULO')
	print('  {0:<34} {1:>5} {2:>7} {3:>7}  {4}'.format(
		'FATOR', 'PESO', 'FATOR', 'CONTRIB', 'POR QUE'))
	for factor in result['factors']:
		print('  {0:<34} {1:>5.2f} {2:>7} {3:>7.3f}  {4}'.format(
			factor['label'][:34], factor['weight'],
			'--' if factor['factor'] is None else '{0:.2f}'.format(factor['factor']),
			factor['contribution'], factor['reason'][:44]))
	print('')
	print('SCORE        {0}/100   (media {1}, piso do veredito {2}{3})'.format(
		result['score'], result['raw'], result['floor'],
		', limitado: nenhum analisador nem o LLM encontrou evidencia' if result['capped'] else ''))
	print('FAIXA        {0}'.format(scoring.TIER_LABEL.get(result['label'], result['tier'])))
	print('VEREDITO     {0}{1}'.format(final, '' if final == verdict else
		'  (era {0})'.format(verdict)))
	if reason:
		print('             {0}'.format(reason))
	if result['label'] == 'spam':
		print('             Rotulado spam: gramatica de lista + dominio autenticado. Sai da fila.')
	if config['mode'] != 'escalate':
		print('             Modo {0}: a faixa nao altera veredito nesta instalacao.'.format(config['mode']))
	return 0


def main():
	parser = argparse.ArgumentParser(description = 'bluephish administration')
	sub = parser.add_subparsers(dest = 'command')

	p = sub.add_parser('create-admin', help = 'create the first global_admin (interactive)')
	p.add_argument('--username', help = 'username (prompted when omitted)')
	p.set_defaults(func = cmd_create_admin)

	p = sub.add_parser('create-user', help = 'create a user with a given role')
	p.add_argument('username')
	p.add_argument('--role', default = 'analyst', help = 'analyst | admin | global_admin')
	p.set_defaults(func = cmd_create_user)

	p = sub.add_parser('list-users', help = 'list the existing users')
	p.set_defaults(func = cmd_list_users)

	p = sub.add_parser('reset-password', help = 'reset the password of a user')
	p.add_argument('username')
	p.set_defaults(func = cmd_reset_password)

	p = sub.add_parser('reset-mfa', help = 'clear the TOTP second factor of a user (lost or replaced phone)')
	p.add_argument('username')
	p.set_defaults(func = cmd_reset_mfa)

	p = sub.add_parser('unlock', help = 'clear the lockout of a user')
	p.add_argument('username')
	p.set_defaults(func = cmd_unlock)

	p = sub.add_parser('weights', help = 'mostra o ranking de fatores do score (Priorizacao)')
	p.set_defaults(func = cmd_weights)

	p = sub.add_parser('score', help = 'pontua um .eml do disco, sem rede e sem cota de fornecedor')
	p.add_argument('eml', help = 'caminho do arquivo .eml')
	p.add_argument('--analyzer', action = 'append', metavar = 'ID=NIVEL',
		help = 'nivel a simular para um analisador (info|safe|suspicious|malicious). '
			'Repetivel: --analyzer virustotal=malicious --analyzer otx=safe')
	p.add_argument('--llm', metavar = 'RISCO',
		help = 'simula a avaliacao do LLM: Low | Medium | High | Critical')
	p.add_argument('--llm-clean', action = 'store_true',
		help = 'o LLM rodou e NAO detectou engenharia social (com --llm)')
	p.add_argument('--json', action = 'store_true', help = 'saida em JSON')
	p.set_defaults(func = cmd_score)

	args = parser.parse_args()
	if not getattr(args, 'func', None):
		parser.print_help()
		return 1
	return args.func(args)


if __name__ == '__main__':
	sys.exit(main())
