"""Guias da tela de bloqueio — prosa, nunca lógica.

Mesma divisão de `analyzer_guides.py`, e pelo mesmo motivo: `responders.py`
guarda o registro e as chamadas, e o que um admin precisa para *decidir* — o que
o destino faz de fato, o que ele exige do outro lado, e o que continua sendo
responsabilidade dele — é texto.

Há uma diferença de tom em relação aos guias de analisador, deliberada. Um
analisador errado devolve um veredito errado; um destino de bloqueio mal
configurado derruba tráfego legítimo, ou deixa alguém achando que bloqueou algo
que segue passando. Os guias abaixo dizem isso explicitamente em vez de deixar
para a documentação do fabricante.
"""

FAMILIES = {
	'email_gateway': {
		'label': 'Gateway de e-mail',
		'summary': 'Age antes da entrega: a mensagem seguinte com aquele indicador não chega à caixa.',
		'body': 'É o bloqueio mais direto para phishing, porque atua no mesmo lugar em que o e-mail '
			'entra. Bloquear um remetente vale para toda a organização, não só para quem denunciou, '
			'e é por isso que a decisão é de admin e vai para o log de auditoria com o valor. '
			'Um bloqueio de domínio de remetente é mais amplo do que parece: derruba também o que '
			'aquele domínio manda de legítimo. Prefira o endereço quando ele bastar.'
	},
	'firewall': {
		'label': 'Firewall de perímetro',
		'summary': 'Preenche o objeto que a sua regra de negação usa. O objeto não é a regra.',
		'body': 'Este é o ponto que faz alguém achar que bloqueou e não ter bloqueado nada: colocar '
			'um IP num grupo dinâmico, num address group ou num network group só derruba tráfego se '
			'existir uma regra negando aquele grupo. Crie a regra primeiro, confirme que ela está '
			'ativa, e só então habilite o destino aqui. O mesmo vale para categoria de URL e filtro '
			'web — o objeto precisa estar referenciado por um perfil que esteja aplicado a uma '
			'política. Vale lembrar também o alcance: firewall barra a saída de quem já clicou, não '
			'a entrada do e-mail. Os dois se complementam; nenhum substitui o outro.'
	}
}


def _sections(what, requires, reading):
	return [
		{'title': 'O que ele faz', 'body': what},
		{'title': 'O que precisa existir do outro lado', 'body': requires},
		{'title': 'Depois de bloquear', 'body': reading}
	]


GUIDES = {
	'eop': _sections(
		'Grava o indicador na Tenant Allow/Block List do Microsoft 365, a mesma lista do Centro de '
		'Segurança em Políticas → Listas de permissão/bloqueio do locatário. Endereço de e-mail e '
		'domínio entram como bloqueio de remetente; URL entra como padrão de URL, sem esquema; hash '
		'entra como SHA-256 e barra o anexo. MD5 e SHA-1 são recusados aqui em vez de serem enviados '
		'para tomar erro do outro lado — a lista só aceita SHA-256.',
		'Um registro de aplicativo no Entra ID com a permissão de aplicação Exchange.ManageAsApp '
		'(Office 365 Exchange Online) e consentimento do administrador. Só isso não basta, e é o '
		'erro mais comum: o próprio aplicativo também precisa receber o papel de diretório '
		'Administrador do Exchange ou Administrador de Segurança. Sem o papel, a autenticação passa '
		'e o comando volta 403. O campo Organização é o domínio inicial do tenant '
		'(contoso.onmicrosoft.com), que entra no caminho do endpoint de administração.',
		'A propagação pelo serviço leva alguns minutos; a mensagem seguinte pode ainda passar. '
		'A expiração padrão é de 30 dias, e o máximo que a Microsoft aceita é 90. Zero grava sem '
		'expiração — pense duas vezes: uma entrada permanente sobrevive à campanha que a motivou, e '
		'a lista tem limite de tamanho. Remover é feito no Centro de Segurança; esta tela só '
		'acrescenta.'
	),
	'panos': _sections(
		'Para IP, registra o endereço numa tag pela API de User-ID. Esse caminho foi escolhido '
		'porque o registro vale no mesmo instante e não entra na configuração candidata, então não '
		'exige commit nem interfere numa mudança que outro administrador esteja preparando. Para '
		'domínio e URL, acrescenta o padrão à lista de uma categoria de URL personalizada, o que é '
		'mudança de configuração e só passa a valer com commit.',
		'Uma chave de API de um usuário cujo perfil de acesso tenha XML API com User-ID e '
		'Configuration habilitados. Um Dynamic Address Group cujo critério case com a tag '
		'configurada aqui. A categoria de URL personalizada precisa existir antes — este destino '
		'acrescenta itens a ela, não a cria. E, acima de tudo, as regras de segurança negando o '
		'grupo dinâmico e a categoria: sem elas nada é barrado.',
		'O registro de IP aparece em Monitor → registered IP e não sobrevive a um reboot do '
		'firewall, o que é característica do mecanismo, não defeito — bloqueio dinâmico é para '
		'campanha em andamento. Domínio e URL ficam gravados. Com o commit ligado, a tela mostra o '
		'número do job; acompanhe em Tasks. Com ele desligado, o indicador fica na configuração '
		'candidata e a tela diz "aguardando commit" — nesse estado ele ainda não bloqueia nada.'
	),
	'fortigate': _sections(
		'Cria o objeto de endereço — subnet /32 para IP, tipo FQDN para domínio — com nome prefixado '
		'por bp-, e o acrescenta ao address group configurado. URL vai por outro caminho: uma '
		'entrada de bloqueio do tipo simple num filtro de URL do web filter, identificado pelo id '
		'numérico da tabela.',
		'Um token de REST API Admin com escrita em Firewall Objects, e também em Security Profiles '
		'se você for bloquear URL. Confira o trusted host do token: ele é a causa mais frequente de '
		'403 numa configuração que está correta em todo o resto. O address group precisa existir e '
		'estar referenciado por uma política de negação. Para URL, o id do filtro é o da tabela '
		'webfilter urlfilter, e o perfil que a usa precisa estar aplicado a uma política.',
		'Objeto já existente não é erro: o FortiOS responde -5 e a tela mostra "já constava". Deixar '
		'o id do filtro de URL em branco é uma escolha válida — o destino passa a recusar URL e '
		'continua aceitando IP e domínio, em vez de falhar na hora do bloqueio. Nada aqui é '
		'removido automaticamente; a limpeza dos objetos bp- é sua.'
	),
	'checkpoint': _sections(
		'Abre sessão na Management API, e então: para IP, cria o host e o acrescenta ao network '
		'group; para domínio e URL, acrescenta o valor à lista de URLs de um Application/Site '
		'personalizado. Publica ao final, e encerra a sessão mesmo quando algo falha no meio.',
		'Um usuário com leitura e escrita na Management API, e a API aceitando conexões de fora do '
		'servidor de gerência (api fwm set-accessibility). O network group e, se for usar URL, o '
		'objeto Application/Site precisam existir antes. Em Multi-Domain Security Management, '
		'informe o domínio. E a regra de drop referenciando o grupo precisa estar na política.',
		'Publicar grava o objeto no banco de gerência; ele só chega ao gateway na instalação de '
		'política. Por isso o pacote de política é um campo opcional: preenchido, a instalação é '
		'disparada e a tela diz que a regra está valendo; em branco, a tela diz "valendo na próxima '
		'instalação" — que é a verdade, e é diferente de estar bloqueado. Instalar política é '
		'operação pesada e algumas operações preferem fazê-la em janela; por isso o padrão é não '
		'instalar.'
	)
}


def guide_for(responder_id):
	"""Seções do guia de um destino, ou lista vazia quando ele não tem."""
	return GUIDES.get(responder_id, [])
