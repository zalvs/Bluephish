// Login page script.
//
// It lives in its own file on purpose: the Content-Security-Policy sent by the
// application allows scripts only from 'self', so an inline <script> block is
// blocked by the browser. When that happened the submit handler below was never
// registered, the form fell back to a native submit and — with no method
// attribute — sent the username and the password as a GET query string, leaking
// the credentials into the URL, the browser history and any access log.
// The form now also carries method="post" as a second line of defence.

// The server issues the CSRF token as a readable cookie and validates it in the
// X-CSRFToken header
function csrf_token(){
	let match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
	return match ? decodeURIComponent(match[1]) : "";
}

// Todo endereço desta tela parte da raiz. Um relativo ("api/auth/login") resolve
// contra a pasta da página, e é só por acaso que /login fica na raiz: quem abre o
// login a partir de outro caminho não pode acabar postando em /algo/api/auth/login
function absolute_url(url){
	return /^(?:[a-z][a-z0-9+.-]*:|\/)/i.test(url) ? url : "/" + url;
}

// Para onde ir depois do segundo fator. O servidor já devolve só um caminho de
// página deste painel, mas quem manda o navegador para um endereço confere de
// novo: um "//host" ou "\host" aqui seria uma saída do painel para outro site
function destination_after_login(next){
	// Any control character or space, too: "/\t/host" reaches the address parser
	// as "//host", because it drops the tab before it looks at the slashes
	if (typeof next === "string" && next.startsWith("/") && !next.startsWith("//") && !/[\u0000- \\]/.test(next)){
		return next;
	}
	return "/";
}

let form = document.getElementById("loginForm");
let error_box = document.getElementById("loginError");
let login_btn = document.getElementById("loginBtn");

let mfa_form = document.getElementById("mfaForm");
let mfa_error = document.getElementById("mfaError");
let mfa_btn = document.getElementById("mfaBtn");
let mfa_code = document.getElementById("mfaCode");

// The error box is hidden with the shared .hidden utility class from bluephish.css
function show_error(message){
	error_box.textContent = message;
	error_box.classList.remove("hidden");
}

function show_mfa_error(message){
	mfa_error.textContent = message;
	mfa_error.classList.remove("hidden");
}

// Um envelope só para as duas chamadas: tolera corpo não-JSON (uma página de
// erro do proxy, por exemplo) para que um erro HTTP real apareça como tal em
// vez de virar uma falha de rede genérica
function post(url, body){
	return fetch(absolute_url(url), {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-CSRFToken": csrf_token(),
			"X-Requested-With": "XMLHttpRequest"
		},
		credentials: "same-origin",
		body: JSON.stringify(body || {})
	}).then(function(response){
		return response.text().then(function(text){
			let data = {};
			try { data = JSON.parse(text); } catch (e) { data = {}; }
			return {ok: response.ok, status: response.status, data: data};
		});
	});
}

/* ========================================================================== */
/* Segundo fator                                                              */
/* ========================================================================== */

/* Este bloco não decide nada: quem decide é o servidor. Ele só desenha o passo
 * que a resposta do login (ou o data-mfa-stage que o servidor renderizou, no
 * caminho de volta do SSO) mandou desenhar, e devolve o código digitado. Não
 * existe estado aqui que, mexido pelo console, libere alguma coisa — o que abre
 * a sessão é o código conferido do outro lado. */

// 'enroll' quando ainda falta parear o aplicativo, 'verify' quando já foi
let mfa_stage = "";

// Prazo do desafio, como o servidor o mediu. A contagem é só um aviso: o
// servidor recusa o código vencido de qualquer jeito, e é ele que conta as
// tentativas. Quando chega a zero, a tela volta para a senha em vez de deixar
// a pessoa digitar um código que já não pode ser aceito
let mfa_deadline = 0;
let mfa_timer = null;
const MFA_URGENT_SECONDS = 10;

function show_attempts(left){
	if (typeof left !== "number"){ return; }
	let box = document.getElementById("mfaAttempts");
	box.textContent = String(left);
	box.classList.toggle("urgent", left <= 1);
}

function tick_mfa(){
	let left = Math.max(0, Math.ceil((mfa_deadline - Date.now()) / 1000));
	let box = document.getElementById("mfaTimer");
	box.textContent = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
	box.classList.toggle("urgent", left <= MFA_URGENT_SECONDS);
	if (left === 0){
		window.clearInterval(mfa_timer);
		leave_mfa("mfa_expired");
	}
}

function start_mfa_clock(status){
	window.clearInterval(mfa_timer);
	let seconds = status && typeof status.expiresIn === "number" ? status.expiresIn : 0;
	mfa_deadline = Date.now() + seconds * 1000;
	show_attempts(status && status.attemptsLeft);
	tick_mfa();
	mfa_timer = window.setInterval(tick_mfa, 250);
}

function enter_mfa(stage, status){
	mfa_stage = stage;
	form.classList.add("hidden");
	mfa_form.classList.remove("hidden");
	mfa_error.classList.add("hidden");
	mfa_code.value = "";
	let enrolling = stage === "enroll";
	document.getElementById("mfaEnroll").classList.toggle("hidden", !enrolling);
	document.getElementById("mfaTitle").textContent = enrolling
		? "Configure a verificação em duas etapas"
		: "Verificação em duas etapas";
	document.getElementById("mfaLead").textContent = enrolling
		? "O acesso ao painel exige um aplicativo autenticador. Isto é feito uma vez."
		: "Digite o código de 6 dígitos do seu aplicativo autenticador.";
	if (enrolling){ load_enrollment(); }
	start_mfa_clock(status);
	window.setTimeout(function(){ mfa_code.focus(); }, 30);
}

// De volta ao começo: o desafio no servidor continua de pé até vencer sozinho,
// mas quem cancelou não deve ficar olhando para um formulário que não vai
// responder — a senha é pedida de novo, e um login novo troca o desafio.
// `reason` é o código fechado que o servidor mandou (auth.MFA_END_*); a tela de
// login o transforma na frase que explica por que a pessoa voltou para cá
function leave_mfa(reason){
	window.clearInterval(mfa_timer);
	let params = [];
	if (reason === "mfa_expired" || reason === "mfa_attempts" || reason === "mfa_cancel"){
		params.push("reason=" + reason);
	}
	// The screen the person was heading to is still theirs to return to; the
	// server checks it again before using it
	let next = form.dataset.next;
	if (next){ params.push("next=" + encodeURIComponent(next)); }
	window.location.href = "/login" + (params.length ? "?" + params.join("&") : "");
}

function load_enrollment(){
	let qr = document.getElementById("mfaQr");
	let secret_box = document.getElementById("mfaSecret");
	mfa_btn.disabled = true;
	post("api/auth/mfa/setup", {}).then(function(result){
		mfa_btn.disabled = false;
		if (!result.ok){
			// Desafio vencido: a senha tem de ser apresentada de novo
			if (result.data && result.data.restart){ leave_mfa(result.data.reason); return; }
			show_mfa_error((result.data && result.data.error) || "Não foi possível preparar a verificação em duas etapas.");
			return;
		}
		qr.src = result.data.qr;
		// Em grupos de quatro: a chave é lida da tela e digitada num telefone,
		// e 32 caracteres corridos é onde se perde o lugar
		secret_box.textContent = String(result.data.secret || "").replace(/(.{4})/g, "$1 ").trim();
	}).catch(function(){
		mfa_btn.disabled = false;
		show_mfa_error("Não foi possível falar com o servidor.");
	});
}

// Só dígitos, e o envio sai sozinho no sexto: o código tem prazo de validade e
// cada segundo procurando o botão é um segundo a menos
mfa_code.addEventListener("input", function(){
	let digits = mfa_code.value.replace(/\D/g, "").substring(0, 6);
	if (digits !== mfa_code.value){ mfa_code.value = digits; }
	if (digits.length === 6 && !mfa_btn.disabled){ submit_mfa(); }
});

function submit_mfa(){
	let code = mfa_code.value.replace(/\D/g, "");
	if (code.length !== 6){
		show_mfa_error("O código tem 6 dígitos.");
		return;
	}
	mfa_error.classList.add("hidden");
	mfa_btn.disabled = true;
	post(mfa_stage === "enroll" ? "api/auth/mfa/activate" : "api/auth/mfa/verify", {code: code})
		.then(function(result){
			mfa_btn.disabled = false;
			if (result.ok){
				// Navegação nova para o painel carregar com a sessão recém-aberta, na
				// tela que a pessoa queria abrir antes de o login interrompê-la
				window.location.href = destination_after_login(result.data.next);
				return;
			}
			mfa_code.value = "";
			mfa_code.focus();
			if (result.data && result.data.restart){ leave_mfa(result.data.reason); return; }
			show_attempts(result.data && result.data.attemptsLeft);
			let message = (result.data && result.data.error) || "Código inválido.";
			if (result.status === 429){
				message = "Tentativas demais. Aguarde um minuto e tente de novo.";
			}
			show_mfa_error(message);
		}).catch(function(){
			mfa_btn.disabled = false;
			show_mfa_error("Não foi possível falar com o servidor.");
		});
}

mfa_form.addEventListener("submit", function(event){
	event.preventDefault();
	submit_mfa();
});

document.getElementById("mfaCancelBtn").addEventListener("click", function(){ leave_mfa("mfa_cancel"); });

// reCAPTCHA v3: um token novo a cada envio, pedido na hora (ele vale dois
// minutos). Sem o captcha ligado, ou com o script do Google bloqueado, sai
// vazio — e quem decide o que fazer com isso é o servidor (captcha.py)
// O nome da ação que o servidor confere na resposta do Google (captcha.ACTION)
const CAPTCHA_ACTION = "login";

function captcha_token(){
	let key = form.dataset.captchaKey;
	if (!key || !window.grecaptcha || typeof window.grecaptcha.ready !== "function"){
		return Promise.resolve("");
	}
	return new Promise(function(resolve){
		window.grecaptcha.ready(function(){
			window.grecaptcha.execute(key, {action: CAPTCHA_ACTION}).then(resolve, function(){ resolve(""); });
		});
	});
}

form.addEventListener("submit", function(event){
	// Stop the native submit: the credentials must travel in a POST body, never
	// in the URL
	event.preventDefault();
	error_box.classList.add("hidden");
	login_btn.disabled = true;
	captcha_token().then(function(token){
		return post("api/auth/login", {
			username: document.getElementById("username").value,
			password: document.getElementById("password").value,
			// Só uma sugestão: o servidor a valida e é ele que a devolve no fim
			next: form.dataset.next || "",
			captchaToken: token
		});
	}).then(function(result){
		login_btn.disabled = false;
		if (result.ok){
			// A senha certa não abre sessão nenhuma: ela abre o segundo passo.
			// A senha some da tela junto com o formulário
			document.getElementById("password").value = "";
			enter_mfa(result.data && result.data.mfaEnrolled ? "verify" : "enroll", result.data);
			return;
		}
		// The server always answers with the same generic message, so the
		// interface cannot leak whether the account exists or is locked
		let message = (result.data && result.data.error) || "Usuário ou senha inválidos.";
		if (result.status === 429){
			message = "Tentativas demais. Aguarde um minuto e tente de novo.";
		}
		show_error(message);
		document.getElementById("password").value = "";
	}).catch(function(){
		login_btn.disabled = false;
		show_error("Não foi possível falar com o servidor.");
	});
});

// O retorno do SSO cai nesta tela já com um desafio de segundo fator aberto, e
// é o servidor que diz em qual dos dois passos ela abre
let auth_main = document.querySelector(".auth-main");
let initial_stage = auth_main.dataset.mfaStage || "";
if (initial_stage){
	enter_mfa(initial_stage, {
		expiresIn: parseInt(auth_main.dataset.mfaExpiresIn, 10) || 0,
		attemptsLeft: parseInt(auth_main.dataset.mfaAttemptsLeft, 10) || 0
	});
}
