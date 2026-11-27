"""Uma seção do `configuration.json`, lida e gravada pelos módulos de configuração.

O que `audit_store` e `security_policy` faziam cada um à sua maneira — limitar um
número a um intervalo, regravar uma chave preservando o resto do arquivo — mora
aqui, para que uma correção numa cópia não deixe a outra para trás.

**A gravação é no lugar, não por troca de arquivo.** O jeito atômico de sempre
(escrever ao lado e `os.replace`) não funciona aqui: no compose,
`configuration.json` é montado no contêiner como *arquivo* (bind mount), e
renomear outro arquivo por cima de um ponto de montagem falha. Então quem lê
precisa tolerar um arquivo pela metade — `read_section` levanta
`ConfigUnreadable`, e cada módulo decide o que vale enquanto isso (em
`security_policy`, a última configuração boa, para que uma leitura no meio de
uma gravação não afrouxe a sessão de ninguém).
"""

import json
import config_file
import os


class ConfigUnreadable(Exception):
	"""O arquivo existe mas não é um JSON com um objeto no topo."""


def clamp(value, low, high, default):
	"""`value` como inteiro dentro de [low, high]; `default` se não for número."""
	try:
		return min(max(int(value), low), high)
	except (TypeError, ValueError):
		return default


def as_dict(value):
	"""O valor se for um objeto JSON; senão, um dicionário vazio."""
	return value if isinstance(value, dict) else {}


def read_section(path, key):
	"""A seção `key` do arquivo (None se ausente). Levanta ConfigUnreadable."""
	try:
		whole = config_file.read(path)
	except ValueError as error:
		raise ConfigUnreadable(str(error))
	if not isinstance(whole, dict):
		raise ConfigUnreadable('o topo do arquivo não é um objeto')
	return whole.get(key)


def write_section(path, key, value):
	"""Regrava só a seção `key`, preservando o resto do arquivo."""
	whole = config_file.read(path)
	whole[key] = value
	config_file.write(whole, path)
