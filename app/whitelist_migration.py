"""Migração do whitelist v1 para o v2.

O v1 guardava sete tipos (mail, ip, domain, url, filename, filetype, hash) em
duas formas (exata e regex) mais três listas de domínio. O v2 guarda quatro
tipos e nenhum casamento por texto cru. Nem tudo tem para onde ir, e a migração
prefere relatar o que não cabe a inventar um destino parecido.

Três destinos possíveis para cada entrada do v1:

- **migrada** — existe equivalente exato no v2 e a semântica não muda.
- **reescrever à mão** — a entrada expressa algo que o v2 não representa da
  mesma forma. Fica no backup e no relatório, não vira regra.
- **descartada** — o tipo saiu do modelo.

As duas decisões que merecem atenção:

**Endereços de `exactMatching.mail` entram desabilitados.** No v1 a entrada
significava "não extraia este endereço como observable" — conveniência, redução
de ruído. No v2, `sender` significa "confie neste remetente e rebaixe o veredito
dele". Ligar sozinho converteria uma entrada de conveniência em concessão de
confiança: escalada silenciosa de privilégio sobre dados que já estavam lá.
Quem administra liga uma a uma, sabendo o que está ligando.

**Nenhuma regex do v1 vira regra.** Elas rodavam com `re.search` sem âncora; no
v2 tudo é `fullmatch` sobre host e caminho já desmontados. O mesmo texto passa a
significar outra coisa. Criar a regra desabilitada com o padrão antigo dentro
guardaria um valor que não quer dizer o que aparenta — pior do que a lista no
relatório, que é o que a pessoa precisa para reescrever.
"""

import copy
import datetime
import json
import os
import re

import whitelist


# Motivo das regras que vêm da lista que acompanha o produto. Elas descrevem
# marcas conhecidas, não um acordo com prazo, e dar 180 dias a centenas delas só
# produziria uma avalanche de expirações que ninguém revisa de verdade
SHIPPED_REASON = 'lista padrão BluePhish (migração v1→v2)'
OPERATOR_REASON = 'migrado do whitelist v1 — revisar'
SENDER_REASON = 'migrado do whitelist v1 — habilitar só se este remetente deve ser confiável'

# O template que acompanha a imagem. O que estiver nele veio de fábrica; o que
# não estiver, alguém desta instalação acrescentou — e é isso que merece revisão
SHIPPED_TEMPLATE = os.path.join(
	os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
	'docker', 'thephish_conf_files', 'whitelist.json')


def _shipped_values(template_path = None):
	"""Junta num conjunto tudo que a lista de fábrica traz, para comparação.

	Lê o template nos dois formatos de propósito: instalações novas já recebem o
	arquivo no v2, enquanto uma que está subindo agora compara contra o v1 que
	ainda tem em disco. Ler só um dos dois faria a lista de fábrica inteira ser
	tratada como acréscimo do operador e ganhar 180 dias — centenas de
	expirações que ninguém pediu.
	"""
	path = template_path or SHIPPED_TEMPLATE
	try:
		with open(path, encoding = 'utf-8') as template_file:
			document = json.load(template_file)
	except Exception:
		return set()
	if document.get('version') == whitelist.SCHEMA_VERSION:
		values = set()
		for rule in document.get('rules') or []:
			if isinstance(rule, dict) and rule.get('value'):
				values.add(str(rule['value']).strip().lower().lstrip('*.'))
		return values
	values = set()
	for list_name in ('domainsInSubdomains', 'domainsInURLs', 'domainsInEmails'):
		for value in document.get(list_name, []) or []:
			values.add(str(value).strip().lower())
	exact = document.get('exactMatching', {}) or {}
	for obs_type in ('domain', 'url', 'hash', 'mail', 'ip', 'filename', 'filetype'):
		for value in exact.get(obs_type, []) or []:
			values.add(str(value).strip().lower())
	return values


class Report:
	"""O que aconteceu com cada entrada, para virar texto no fim."""

	def __init__(self):
		self.migrated = []
		self.needs_rewrite = []
		self.dropped = []
		self.backup_path = ''

	def add_migrated(self, source, value, rule, note = ''):
		self.migrated.append({'source': source, 'value': value, 'type': rule['type'],
			'enabled': rule['enabled'], 'note': note})

	def add_rewrite(self, source, value, why):
		self.needs_rewrite.append({'source': source, 'value': value, 'why': why})

	def add_dropped(self, source, value, why):
		self.dropped.append({'source': source, 'value': value, 'why': why})

	def to_dict(self):
		return {'migrated': self.migrated, 'needsRewrite': self.needs_rewrite,
			'dropped': self.dropped, 'backupPath': self.backup_path}

	def format(self):
		lines = []
		lines.append('Migração do whitelist v1 → v2')
		lines.append('=' * 60)
		enabled = sum(1 for item in self.migrated if item['enabled'])
		lines.append('{0} regras criadas ({1} ativas, {2} desabilitadas para revisão)'.format(
			len(self.migrated), enabled, len(self.migrated) - enabled))
		lines.append('{0} entradas precisam ser reescritas à mão'.format(len(self.needs_rewrite)))
		lines.append('{0} entradas descartadas'.format(len(self.dropped)))
		if self.backup_path:
			lines.append('Backup do v1: {0}'.format(self.backup_path))

		disabled = [item for item in self.migrated if not item['enabled']]
		if disabled:
			lines.append('')
			lines.append('Criadas DESABILITADAS — ligar uma a uma:')
			for item in disabled:
				lines.append('  [{0}] {1}'.format(item['type'], item['value']))

		if self.needs_rewrite:
			lines.append('')
			lines.append('Reescrever à mão (preservadas no backup):')
			for item in self.needs_rewrite:
				lines.append('  {0}: {1}'.format(item['source'], item['value']))
				lines.append('      {0}'.format(item['why']))

		if self.dropped:
			lines.append('')
			lines.append('Descartadas:')
			by_reason = {}
			for item in self.dropped:
				by_reason.setdefault(item['why'], []).append(item['value'])
			for why, values in sorted(by_reason.items()):
				shown = ', '.join(values[:6])
				extra = '' if len(values) <= 6 else ' (+{0})'.format(len(values) - 6)
				lines.append('  {0}: {1}{2}'.format(why, shown, extra))
		return '\n'.join(lines)


def _expiry_for(value, shipped, now):
	"""Lista de fábrica nasce permanente; o que o operador acrescentou, 180 dias."""
	if value.strip().lower() in shipped:
		return None, SHIPPED_REASON
	return whitelist.default_expiry(now), OPERATOR_REASON


def _build(rule_type, value, shipped, now, enabled = True, reason = None, **extra):
	expires_at, default_reason = _expiry_for(value, shipped, now)
	payload = {
		'type': rule_type,
		'value': value,
		'enabled': enabled,
		'reason': reason or default_reason,
		'expires_at': expires_at,
		'permanent_reason': SHIPPED_REASON if expires_at is None else None,
		'created_by': 'migração v1→v2',
		'created_at': whitelist._format_timestamp(now),
	}
	payload.update(extra)
	return whitelist.normalize_rule(payload, now)


def migrate_document(v1_document, shipped = None, now = None):
	"""Converte o dicionário do v1 e devolve (regras, relatório)."""
	now = now or datetime.datetime.utcnow()
	shipped = shipped if shipped is not None else _shipped_values()
	report = Report()
	rules = []
	seen = set()

	def keep(rule, source, original, note = ''):
		# Três listas do v1 podem trazer o mesmo domínio; uma regra basta
		key = (rule['type'], rule['value'])
		if not rule.get('value') or key in seen:
			return
		seen.add(key)
		rules.append(rule)
		report.add_migrated(source, original, rule, note)

	exact = v1_document.get('exactMatching', {}) or {}
	regex = v1_document.get('regexMatching', {}) or {}

	# --- domínios: as três listas do v1 viram o mesmo tipo ---
	# `domainsInSubdomains` casava com `^(.+\.|)dominio$` — o próprio domínio e
	# tudo abaixo. É exatamente o que a forma sem curinga significa no v2, então
	# a semântica não muda
	for list_name in ('domainsInSubdomains', 'domainsInURLs'):
		for raw in v1_document.get(list_name, []) or []:
			value = whitelist.normalize_domain(str(raw))
			if not value or '.' not in value:
				report.add_dropped(list_name, str(raw), 'não é um domínio válido')
				continue
			keep(_build(whitelist.TYPE_DOMAIN, value, shipped, now), list_name, str(raw))

	for raw in exact.get('domain', []) or []:
		value = whitelist.normalize_domain(str(raw))
		if not value or '.' not in value:
			# `tinyurl` e `rebrandly` estão assim no arquivo de fábrica: sem TLD,
			# e como o v1 casava exato eles nunca casaram com nada
			report.add_dropped('exactMatching.domain', str(raw), 'não é um domínio válido (nunca casou no v1)')
			continue
		keep(_build(whitelist.TYPE_DOMAIN, value, shipped, now), 'exactMatching.domain', str(raw))

	# --- URLs exatas ---
	for raw in exact.get('url', []) or []:
		host, target = whitelist.normalize_url(str(raw))
		if not host:
			report.add_dropped('exactMatching.url', str(raw), 'não é uma URL legível')
			continue
		if target in ('', '/'):
			# Sem caminho, a entrada libera o host inteiro: isso é uma regra de
			# domínio, e é lá que ela ganha as travas de sufixo público
			keep(_build(whitelist.TYPE_DOMAIN, host, shipped, now), 'exactMatching.url', str(raw),
				note='sem caminho: virou regra de domínio')
			continue
		# Regex escapada, não prefixo: o modo prefixo saiu da interface, e deixar a
		# migração como último produtor dele criaria regra que ninguém consegue
		# editar na tela. `re.escape` preserva o sentido literal da entrada do v1
		keep(_build(whitelist.TYPE_URL, '', shipped, now, mode = whitelist.URL_MODE_REGEX,
			host_pattern = re.escape(host), path_pattern = re.escape(target) + '.*'),
			'exactMatching.url', str(raw))

	# --- hashes ---
	for raw in exact.get('hash', []) or []:
		value = whitelist.normalize_hash(str(raw))
		if not value:
			report.add_dropped('exactMatching.hash', str(raw),
				'não é SHA-256 (MD5 e SHA-1 têm colisão prática e saíram do modelo)')
			continue
		keep(_build(whitelist.TYPE_HASH, value, shipped, now), 'exactMatching.hash', str(raw))

	# --- endereços: viram remetente confiável, DESABILITADO ---
	for raw in exact.get('mail', []) or []:
		value = whitelist.normalize_address(str(raw))
		if not value:
			report.add_dropped('exactMatching.mail', str(raw), 'não é um endereço válido')
			continue
		keep(_build(whitelist.TYPE_SENDER, value, shipped, now, enabled = False, reason = SENDER_REASON),
			'exactMatching.mail', str(raw))

	# `domainsInEmails` liberava qualquer endereço de um domínio. O v2 não tem
	# "confie no domínio remetente" — confiança é por endereço, justamente para
	# que uma caixa comprometida em algum canto do domínio não venha junto
	for raw in v1_document.get('domainsInEmails', []) or []:
		report.add_rewrite('domainsInEmails', str(raw),
			'liberava todo endereço do domínio. No v2 a confiança é por endereço: '
			'crie uma regra de remetente para cada caixa que deve ser confiável.')

	# --- regex: nenhuma vira regra ---
	for obs_type, values in sorted(regex.items()):
		for raw in values or []:
			report.add_rewrite('regexMatching.{0}'.format(obs_type), str(raw),
				'rodava com re.search sem âncora; no v2 é fullmatch sobre host e caminho '
				'desmontados. O mesmo texto passa a significar outra coisa.')

	# --- IPs ---
	# Só endereço roteável vira regra. Os privados que o v1 listava (127.0.0.1,
	# 8.8.8.8 e as três regex RFC1918) não precisam mais de entrada nenhuma:
	# endereço não roteável é descartado na extração, sempre
	for raw in exact.get('ip', []) or []:
		value = whitelist.normalize_ip(str(raw))
		if not value:
			report.add_dropped('exactMatching.ip', str(raw), 'não é um IP nem uma faixa CIDR válida')
			continue
		if not whitelist.is_public_ip_value(value):
			report.add_dropped('exactMatching.ip', str(raw),
				'endereço não roteável: já é ignorado em toda análise, sem precisar de regra')
			continue
		keep(_build(whitelist.TYPE_IP, value, shipped, now), 'exactMatching.ip', str(raw))

	# --- tipos que saíram do modelo ---
	for obs_type, why in (
		('filename', 'o tipo filename saiu do modelo: libere o anexo por SHA-256'),
		('filetype', 'o tipo filetype saiu do modelo: liberar um MIME inteiro libera todo anexo daquele formato'),
	):
		for raw in exact.get(obs_type, []) or []:
			report.add_dropped('exactMatching.{0}'.format(obs_type), str(raw), why)

	return rules, report


def migrate_file(path = None, template_path = None, now = None, backup = True):
	"""Migra o arquivo no disco. Devolve o relatório.

	Idempotente: um arquivo já no v2 não é tocado.
	"""
	path = path or whitelist.WHITELIST_PATH
	now = now or datetime.datetime.utcnow()

	with open(path, encoding = 'utf-8') as whitelist_file:
		document = json.load(whitelist_file)

	if document.get('version') == whitelist.SCHEMA_VERSION:
		report = Report()
		report.backup_path = ''
		return report

	shipped = _shipped_values(template_path)
	rules, report = migrate_document(document, shipped, now)

	if backup:
		backup_path = path.replace('.json', '') + '.v1.backup.json'
		with open(backup_path, 'w', encoding = 'utf-8') as backup_file:
			json.dump(copy.deepcopy(document), backup_file, indent = '\t', ensure_ascii = False)
		report.backup_path = backup_path

	whitelist.save(rules, path)
	return report


if __name__ == '__main__':
	print(migrate_file().format())
