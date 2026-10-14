# Imagem do Bluephish.
#
# Parte de um Ubuntu 20.04 limpo e instala por conta própria tudo de que a
# aplicação precisa: o Python 3.8 do sistema, o libmagic e as bibliotecas fixadas
# em requirements.txt (Flask 2.0.1, eventlet, msal, a pilha de autenticação...).
# A base é a 20.04 de propósito: é o ambiente em que estas versões foram
# validadas, e trocar de sistema junto com a origem da imagem esconderia qual
# das duas mudanças quebrou algo. Subir para um Python mais novo é uma decisão à
# parte, que começa por reavaliar cada versão fixada.
FROM ubuntu:20.04

# Python buffers stdout when it is not a tty, so every print() the application
# makes — including the error paths that log a traceback — sat in a buffer and
# never reached `docker logs`. An analyzer failing was invisible from outside
# the container, which is precisely when the log is needed.
ENV PYTHONUNBUFFERED=1 \
	DEBIAN_FRONTEND=noninteractive

# O que roda em produção, e só isso:
# - python3 / python3-pip   o interpretador e o instalador das bibliotecas
# - libmagic1               o python-magic reconhece o tipo real dos anexos
# - openssl                 gera o certificado autoassinado na primeira subida: o
#                           cookie de sessão sai com a flag Secure, então a
#                           interface precisa de HTTPS para a autenticação existir
# - ca-certificates         as chamadas HTTPS de saída (LLM, Graph, analisadores)
# - netbase                 dono de /etc/protocols; sem ele
#                           socket.getprotobyname('tcp') levanta e o eventlet nem
#                           importa — a aplicação ficava em crash loop
RUN apt-get update \
	&& apt-get install -y --no-install-recommends python3 python3-pip libmagic1 openssl ca-certificates netbase \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /root/thephish

# As bibliotecas, antes do código: mudar uma linha da aplicação não refaz esta camada.
#
# O yara-python (o analisador YARA local, analyzers.py) não tem wheel para este
# Python, então é compilado: precisa de compilador e dos cabeçalhos do OpenSSL e
# do Python, nenhum dos quais deve ir para a imagem final. Instalar e remover
# numa camada só deixa o .so, que liga com a libssl que o openssl acima já traz.
#
# `--auto-remove` é o que torna isto delicado: ele leva junto pacotes que o
# compilador puxou. O netbase está marcado como manual (veio de `apt-get install`
# acima), então sobrevive, e o teste de fumaça no fim transforma uma regressão
# disso em build quebrado, e não em deploy quebrado.
COPY requirements.txt /root/thephish/requirements.txt
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential libssl-dev python3-dev \
	&& pip3 install --no-cache-dir -r requirements.txt \
	&& apt-get purge -y --auto-remove build-essential libssl-dev python3-dev \
	&& rm -rf /var/lib/apt/lists/* \
	&& python3 -c "import yara, eventlet, socket; socket.getprotobyname('tcp')"

# O código da aplicação: módulos Python, templates e arquivos estáticos
COPY . /root/thephish/

# O banco de usuários, a trilha de auditoria e o par de chaves TLS ficam aqui; o
# diretório é montado do host no docker-compose para sobreviver a um rebuild
RUN mkdir -p /root/thephish/data

CMD ["python3", "thephish_app.py"]
