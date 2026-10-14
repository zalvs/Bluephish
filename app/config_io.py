"""Leitura do configuration.json, num lugar só.

Mais de vinte pontos da aplicação abriam e liam este arquivo cada um por conta
própria, sempre pelo mesmo par de linhas. Quem precisa de uma seção chama
`read_configuration()` e fica com o dicionário inteiro: o que fazer quando o
arquivo falta ou está quebrado continua sendo decisão de quem chama (cada rota
responde a seu modo), então nada é capturado aqui.
"""

import json

# Relativo ao diretório de trabalho do processo, como sempre foi: no container é
# /root/thephish, onde o docker-compose monta o arquivo vivo
CONFIGURATION_PATH = 'configuration.json'


def read_configuration():
	with open(CONFIGURATION_PATH) as conf_file:
		return json.load(conf_file)
