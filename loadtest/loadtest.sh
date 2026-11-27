#!/usr/bin/env bash
# Teste de carga e de estresse do BluePhish, só com bash, curl e openssl.
#
# Rode de OUTRA máquina (ou de outro contêiner) contra uma instância de
# HOMOLOGAÇÃO. O gerador usa um processo curl por requisição, então a partir de
# algumas centenas de requisições por segundo o gargalo passa a ser o próprio
# gerador, e não a aplicação.
#
# O que ele mede, em ordem:
#   1. Entrada anônima: GET /login (sem sessão, sem banco).
#   2. Rampa autenticada: GET só de leitura, em degraus de concorrência. Para no
#      primeiro degrau com erro ou p95 acima do limite e informa onde cedeu.
#   3. Leitura da caixa (opcional): GET /list, que abre IMAP/Graph.
#   4. Análise (opcional): POST /analysis, que roda os analisadores de verdade.
#   5. Sustentação (opcional): carga fixa por mais tempo, para ver vazamento.
#   6. Limite de tentativas de login: confere que o 429 chega.
#
# Nenhuma resposta é guardada: o corpo vai para /dev/null e só código HTTP e
# tempo são anotados. Senha e segredo TOTP vêm do ambiente e nunca da linha de
# comando.
#
# Uso:
#   export LOADTEST_TARGET=https://homolog.exemplo.local:8080
#   export LOADTEST_CONFIRM=homologacao
#   export LOADTEST_USER=loadtest          # conta analyst criada só para isto
#   export LOADTEST_PASSWORD='...'
#   export LOADTEST_TOTP_SECRET='JBSWY3DPEHPK3PXP'   # segredo base32 da conta
#   export LOADTEST_INSECURE=1             # certificado autoassinado
#   ./loadtest.sh
#
# Veja loadtest/README.md para o preparo da conta e a leitura do resultado.

set -u -o pipefail

TARGET="${LOADTEST_TARGET:-}"
CONFIRM="${LOADTEST_CONFIRM:-}"
USERNAME="${LOADTEST_USER:-}"
TOTP_SECRET="${LOADTEST_TOTP_SECRET:-}"
LEVELS="${LOADTEST_LEVELS:-1 5 10 25 50 100}"
STEP_SECONDS="${LOADTEST_STEP_SECONDS:-30}"
REQ_TIMEOUT="${LOADTEST_REQ_TIMEOUT:-30}"
# Acima disto, em porcentagem, o degrau conta como quebrado e a rampa para
ERROR_LIMIT="${LOADTEST_ERROR_LIMIT:-5}"
# Acima disto, em segundos, o p95 também conta como quebra
P95_LIMIT="${LOADTEST_P95_LIMIT:-5}"
ADMIN_ENDPOINTS="${LOADTEST_ADMIN:-0}"
ALLOW_MAILBOX="${LOADTEST_ALLOW_MAILBOX:-0}"
ALLOW_ANALYSIS="${LOADTEST_ALLOW_ANALYSIS:-}"
ANALYSIS_UID="${LOADTEST_ANALYSIS_UID:-}"
ANALYSIS_CONCURRENCY="${LOADTEST_ANALYSIS_CONCURRENCY:-2}"
SOAK_SECONDS="${LOADTEST_SOAK_SECONDS:-0}"
SOAK_CONCURRENCY="${LOADTEST_SOAK_CONCURRENCY:-10}"
LOGIN_PROBE="${LOADTEST_LOGIN_PROBE:-1}"
HEARTBEAT_SECONDS=60

WORK=""
HEARTBEAT_PID=""
TAB_TOKEN=""
STEP_ERRORS=0
STEP_P95=0

die() { printf 'ERRO: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

# --------------------------------------------------------------------------- #
# TOTP (RFC 6238: SHA-1, 6 dígitos, 30 s), o mesmo que o app valida em mfa.py   #
# --------------------------------------------------------------------------- #

# base32 -> hexadecimal. Falha em caractere fora do alfabeto
base32_to_hex() {
	printf '%s' "$1" | tr -d ' =' | tr 'a-z' 'A-Z' | awk '
		BEGIN { alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" }
		{
			bits = ""
			for (i = 1; i <= length($0); i++) {
				v = index(alphabet, substr($0, i, 1)) - 1
				if (v < 0) { exit 1 }
				for (b = 4; b >= 0; b--) { bits = bits (int(v / (2 ^ b)) % 2) }
			}
			hex = ""
			for (i = 1; i + 7 <= length(bits); i += 8) {
				byte = 0
				for (j = 0; j < 8; j++) { byte = byte * 2 + substr(bits, i + j, 1) }
				hex = hex sprintf("%02x", byte)
			}
			print hex
		}'
}

# totp_code SEGREDO [EPOCH]
totp_code() {
	local key counter message mac offset binary
	key=$(base32_to_hex "$1") || return 1
	[ -n "$key" ] || return 1
	counter=$(( ${2:-$(date +%s)} / 30 ))
	message=$(printf '%016x' "$counter" | sed 's/../\\x&/g')
	mac=$(printf "$message" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -binary \
		| od -An -v -tx1 | tr -d ' \n') || return 1
	[ "${#mac}" -eq 40 ] || return 1
	offset=$(( 0x${mac:38:2} & 0xf ))
	binary=$(( 0x${mac:$((offset * 2)):8} & 0x7fffffff ))
	printf '%06d' $(( binary % 1000000 ))
}

# --------------------------------------------------------------------------- #
# curl                                                                         #
# --------------------------------------------------------------------------- #

curl_args() {
	CURL=(curl -sS --max-time "$REQ_TIMEOUT")
	if [ "${LOADTEST_INSECURE:-0}" = "1" ]; then
		CURL+=(-k)
	elif [ -n "${LOADTEST_CACERT:-}" ]; then
		CURL+=(--cacert "$LOADTEST_CACERT")
	fi
}

# cookie_value JAR NOME: o valor de um cookie do jar do curl
cookie_value() {
	awk -v name="$2" '$6 == name { value = $7 } END { print value }' "$1"
}

# --------------------------------------------------------------------------- #
# Estatística                                                                  #
# --------------------------------------------------------------------------- #

# summarize ARQUIVO SEGUNDOS: o arquivo tem uma linha "codigo tempo" por
# requisição. Imprime o resumo e grava "erros% p95" em ARQUIVO.stat
summarize() {
	local file="$1" seconds="$2"
	if [ ! -s "$file" ]; then
		say "  nenhuma requisição registrada"
		echo "100 0" > "$file.stat"
		return
	fi
	sort -k2,2g "$file" | awk -v seconds="$seconds" -v statfile="$file.stat" '
		{ time[NR] = $2; code[NR] = $1 + 0; total += $2 }
		END {
			n = NR
			for (i = 1; i <= n; i++) {
				if (code[i] >= 200 && code[i] < 400) { ok++ }
				else if (code[i] == 429) { limited++ }
				else { failed++ }
			}
			p50 = time[int((n * 50 + 99) / 100)]
			p95 = time[int((n * 95 + 99) / 100)]
			p99 = time[int((n * 99 + 99) / 100)]
			errors = (failed + limited) * 100 / n
			printf "  req=%d rps=%.1f ok=%d 429=%d falhas=%d (%.1f%%) media=%.3fs p50=%.3fs p95=%.3fs p99=%.3fs max=%.3fs\n",
				n, n / seconds, ok, limited, failed, errors, total / n, p50, p95, p99, time[n]
			printf "%.2f %.3f\n", errors, p95 > statfile
		}'
}

# --------------------------------------------------------------------------- #
# Trabalhadores                                                                #
# --------------------------------------------------------------------------- #

# worker METODO SAIDA FIM JAR_ORIGEM URL...: cada trabalhador tem a própria cópia
# do jar. A aplicação renova o cookie de sessão a cada resposta, e vários
# processos escrevendo o mesmo arquivo o corromperiam
worker() {
	local method="$1" out="$2" deadline="$3" source_jar="$4"; shift 4
	local jar="$out.jar" index=0 url count=$#
	local urls=("$@") args=() result token
	if [ -n "$source_jar" ]; then
		cp "$source_jar" "$jar"
		args=(-b "$jar" -c "$jar")
	fi
	while [ "$(date +%s)" -lt "$deadline" ]; do
		url="${urls[$((index % count))]}"
		index=$((index + 1))
		if [ "$method" = "POST" ]; then
			token=$(cookie_value "$jar" csrf_token)
			result=$("${CURL[@]}" "${args[@]}" -X POST -H "X-CSRFToken: $token" -e "$TARGET/" \
				--data-urlencode "mailUID=$ANALYSIS_UID" --data-urlencode "sid=loadtest" \
				-o /dev/null -w '%{http_code} %{time_total}\n' "$url" 2>/dev/null) || result="000 $REQ_TIMEOUT"
		else
			result=$("${CURL[@]}" "${args[@]}" -o /dev/null -w '%{http_code} %{time_total}\n' "$url" 2>/dev/null) \
				|| result="000 $REQ_TIMEOUT"
		fi
		printf '%s\n' "$result" >> "$out"
	done
}

# run_step ROTULO METODO CONCORRENCIA SEGUNDOS JAR URL...
# Deixa o resultado em STEP_ERRORS (porcentagem) e STEP_P95 (segundos)
run_step() {
	local label="$1" method="$2" concurrency="$3" seconds="$4" jar="$5"; shift 5
	local dir deadline i pids=()
	dir=$(mktemp -d "$WORK/step.XXXXXX")
	deadline=$(( $(date +%s) + seconds ))
	for ((i = 0; i < concurrency; i++)); do
		worker "$method" "$dir/w$i" "$deadline" "$jar" "$@" &
		pids+=($!)
	done
	wait "${pids[@]}" 2>/dev/null
	cat "$dir"/w[0-9]* > "$dir/all" 2>/dev/null
	printf '%s, %s conexões\n' "$label" "$concurrency"
	summarize "$dir/all" "$seconds"
	read -r STEP_ERRORS STEP_P95 < "$dir/all.stat"
	rm -rf "$dir"
}

# broken ERROS P95: verdadeiro quando o degrau passou dos limites
broken() {
	awk -v e="$1" -v p="$2" -v el="$ERROR_LIMIT" -v pl="$P95_LIMIT" 'BEGIN { exit !(e > el || p > pl) }'
}

# ramp ROTULO METODO JAR URL...
ramp() {
	local label="$1" method="$2" jar="$3"; shift 3
	local level last_good="nenhum"
	for level in $LEVELS; do
		run_step "$label" "$method" "$level" "$STEP_SECONDS" "$jar" "$@"
		if broken "$STEP_ERRORS" "$STEP_P95"; then
			say "  >> QUEBRA com $level conexões (erros ${STEP_ERRORS}%, p95 ${STEP_P95}s). Último degrau bom: $last_good."
			return 1
		fi
		last_good="$level"
	done
	say "  >> Sem quebra até $last_good conexões simultâneas."
}

# --------------------------------------------------------------------------- #
# Sessão                                                                       #
# --------------------------------------------------------------------------- #

login() {
	local jar="$1" csrf code response status
	printf '%s' "$LOADTEST_PASSWORD" > "$WORK/pw"
	"${CURL[@]}" -c "$jar" -b "$jar" -o /dev/null "$TARGET/login" || die "não alcancei $TARGET/login"
	csrf=$(cookie_value "$jar" csrf_token)
	[ -n "$csrf" ] || die "a aplicação não entregou o cookie csrf_token em /login"
	response=$("${CURL[@]}" -c "$jar" -b "$jar" -X POST -H "X-CSRFToken: $csrf" -e "$TARGET/login" \
		--data-urlencode "username=$USERNAME" --data-urlencode "password@$WORK/pw" \
		-w '\n%{http_code}' "$TARGET/api/auth/login") || die "falha de rede no login"
	rm -f "$WORK/pw"
	status="${response##*$'\n'}"
	[ "$status" = "200" ] || die "login recusado (HTTP $status). Conta bloqueada, senha errada ou limite de 5 por minuto."
	case "$response" in
		*'"mfaEnrolled":false'*|*'"mfaEnrolled": false'*)
			die "a conta ainda não configurou o segundo fator. Entre uma vez pelo navegador e guarde o segredo do QR." ;;
	esac
	csrf=$(cookie_value "$jar" csrf_token)
	code=$(totp_code "$TOTP_SECRET") || die "segredo TOTP inválido (esperado base32)"
	response=$("${CURL[@]}" -c "$jar" -b "$jar" -X POST -H "X-CSRFToken: $csrf" -e "$TARGET/login" \
		--data-urlencode "code=$code" -w '\n%{http_code}' "$TARGET/api/auth/mfa/verify") || die "falha de rede no MFA"
	status="${response##*$'\n'}"
	[ "$status" = "200" ] || die "código TOTP recusado (HTTP $status). Confira o relógio desta máquina (NTP)."
	TAB_TOKEN=$(cookie_value "$jar" bluephish_tab)
	[ -n "$TAB_TOKEN" ] || die "a aplicação não entregou o cookie de aba"
	status=$("${CURL[@]}" -b "$jar" -o /dev/null -w '%{http_code}' "$TARGET/api/auth/me")
	[ "$status" = "200" ] || die "a sessão não ficou autenticada (HTTP $status)"
}

# A sessão é amarrada à aba: sem sinal de vida o servidor a revoga. Uma cópia
# própria do jar, para não disputar o arquivo com os trabalhadores
start_heartbeat() {
	cp "$1" "$WORK/heartbeat.jar"
	(
		while sleep "$HEARTBEAT_SECONDS"; do
			"${CURL[@]}" -b "$WORK/heartbeat.jar" -c "$WORK/heartbeat.jar" -X POST \
				-H "X-Session-Tab: $TAB_TOKEN" -H "X-CSRFToken: $(cookie_value "$WORK/heartbeat.jar" csrf_token)" \
				-e "$TARGET/" -o /dev/null "$TARGET/api/auth/heartbeat" 2>/dev/null
		done
	) &
	HEARTBEAT_PID=$!
}

cleanup() {
	[ -n "$HEARTBEAT_PID" ] && kill "$HEARTBEAT_PID" 2>/dev/null
	[ -n "$WORK" ] && rm -rf "$WORK"
}

# --------------------------------------------------------------------------- #
# Fases                                                                        #
# --------------------------------------------------------------------------- #

phase_login_page() {
	say ""; say "== 1. Entrada anônima: GET /login"
	ramp "login-page" GET "" "$TARGET/login"
}

phase_read_ramp() {
	say ""; say "== 2. Rampa autenticada, só leitura"
	local urls=("$TARGET/api/auth/me" "$TARGET/api/whitelist" "$TARGET/")
	if [ "$ADMIN_ENDPOINTS" = "1" ]; then
		urls+=("$TARGET/api/analyzers" "$TARGET/api/scoring" "$TARGET/api/tickets")
	fi
	ramp "leitura" GET "$1" "${urls[@]}"
}

phase_mailbox() {
	if [ "$ALLOW_MAILBOX" != "1" ]; then
		say ""; say "== 3. Leitura da caixa: pulada (LOADTEST_ALLOW_MAILBOX=1 liga)"
		return 0
	fi
	say ""; say "== 3. Leitura da caixa: GET /list (abre IMAP/Graph; respeita o teto diário do provedor)"
	LEVELS="1 2 5" STEP_SECONDS=20 ramp "lista" GET "$1" "$TARGET/list"
}

phase_analysis() {
	if [ "$ALLOW_ANALYSIS" != "sim-consome-cota" ]; then
		say ""; say "== 4. Análise: pulada (exige LOADTEST_ALLOW_ANALYSIS=sim-consome-cota)"
		return 0
	fi
	[ -n "$ANALYSIS_UID" ] || die "defina LOADTEST_ANALYSIS_UID com o UID de um e-mail de teste da fila"
	say ""; say "== 4. Análise: POST /analysis (consome cota de analisadores e de IA, grava nos destinos)"
	say "   O e-mail $ANALYSIS_UID é marcado como lido na primeira análise; as seguintes devolvem 404 da fila."
	run_step "analise" POST "$ANALYSIS_CONCURRENCY" "$STEP_SECONDS" "$1" "$TARGET/analysis"
}

phase_soak() {
	[ "$SOAK_SECONDS" -gt 0 ] 2>/dev/null || return 0
	say ""; say "== 5. Sustentação: $SOAK_CONCURRENCY conexões por $SOAK_SECONDS s"
	say "   Em paralelo, no servidor: docker stats bluephish  (a memória não deve subir sem parar)"
	run_step "sustentacao" GET "$SOAK_CONCURRENCY" "$SOAK_SECONDS" "$1" "$TARGET/api/auth/me" "$TARGET/api/whitelist"
}

phase_login_probe() {
	[ "$LOGIN_PROBE" = "1" ] || return 0
	say ""; say "== 6. Limite de tentativas: 8 logins com usuário inexistente (esperado: 401 até a quinta, depois 429)"
	local jar="$WORK/probe.jar" csrf i code codes=""
	"${CURL[@]}" -c "$jar" -b "$jar" -o /dev/null "$TARGET/login"
	csrf=$(cookie_value "$jar" csrf_token)
	for i in 1 2 3 4 5 6 7 8; do
		code=$("${CURL[@]}" -c "$jar" -b "$jar" -X POST -H "X-CSRFToken: $csrf" -e "$TARGET/login" \
			--data-urlencode "username=loadtest-inexistente-$$" --data-urlencode "password=incorreta" \
			-o /dev/null -w '%{http_code}' "$TARGET/api/auth/login")
		codes="$codes $code"
	done
	say "  códigos:$codes"
	case "$codes" in
		*429*) say "  >> O limite de tentativas respondeu 429." ;;
		*)     say "  >> ATENÇÃO: nenhum 429. Atrás de proxy, confira BLUEPHISH_TRUSTED_PROXIES: o limite conta por IP do cliente." ;;
	esac
	say "  Estas tentativas ficam na trilha de auditoria (usuário inexistente, não bloqueia nenhuma conta)."
}

# --------------------------------------------------------------------------- #
# Principal                                                                    #
# --------------------------------------------------------------------------- #

main() {
	local tool jar
	for tool in curl openssl awk sed od tr sort mktemp date; do
		command -v "$tool" > /dev/null || die "falta o comando $tool"
	done
	[ -n "$TARGET" ] || die "defina LOADTEST_TARGET (ex.: https://homolog.exemplo.local:8080)"
	case "$TARGET" in https://*) ;; *) die "LOADTEST_TARGET precisa começar com https:// (o cookie de sessão é Secure)" ;; esac
	TARGET="${TARGET%/}"
	[ "$CONFIRM" = "homologacao" ] || die "defina LOADTEST_CONFIRM=homologacao para confirmar que o alvo NÃO é produção"
	if [ -z "$USERNAME" ] || [ -z "${LOADTEST_PASSWORD:-}" ] || [ -z "$TOTP_SECRET" ]; then
		die "defina LOADTEST_USER, LOADTEST_PASSWORD e LOADTEST_TOTP_SECRET"
	fi

	umask 077
	WORK=$(mktemp -d)
	trap cleanup EXIT INT TERM
	curl_args

	say "Alvo: $TARGET   degraus: $LEVELS   por degrau: ${STEP_SECONDS}s   início: $(date '+%F %T')"
	jar="$WORK/session.jar"

	phase_login_page
	login "$jar"
	say ""; say "Sessão autenticada como $USERNAME."
	start_heartbeat "$jar"
	phase_read_ramp "$jar"
	phase_mailbox "$jar"
	phase_analysis "$jar"
	phase_soak "$jar"
	phase_login_probe

	"${CURL[@]}" -b "$jar" -X POST -H "X-CSRFToken: $(cookie_value "$jar" csrf_token)" -e "$TARGET/" \
		-o /dev/null "$TARGET/api/auth/logout" 2>/dev/null
	say ""; say "Fim: $(date '+%F %T')"
}

# Permite carregar as funções (para testá-las) sem executar nada
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
