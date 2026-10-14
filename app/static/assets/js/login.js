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
	return fetch(url, {
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

function enter_mfa(stage){
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
	window.setTimeout(function(){ mfa_code.focus(); }, 30);
}

// De volta ao começo: o desafio no servidor continua de pé até vencer sozinho,
// mas quem cancelou não deve ficar olhando para um formulário que não vai
// responder — a senha é pedida de novo, e um login novo troca o desafio
function leave_mfa(){
	window.location.href = "login";
}

function load_enrollment(){
	let qr = document.getElementById("mfaQr");
	let secret_box = document.getElementById("mfaSecret");
	mfa_btn.disabled = true;
	post("api/auth/mfa/setup", {}).then(function(result){
		mfa_btn.disabled = false;
		if (!result.ok){
			// Desafio vencido: a senha tem de ser apresentada de novo
			if (result.data && result.data.restart){ leave_mfa(); return; }
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
				// Navegação nova para o painel carregar com a sessão recém-aberta
				window.location.href = "/";
				return;
			}
			mfa_code.value = "";
			mfa_code.focus();
			if (result.data && result.data.restart){ leave_mfa(); return; }
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

document.getElementById("mfaCancelBtn").addEventListener("click", leave_mfa);

form.addEventListener("submit", function(event){
	// Stop the native submit: the credentials must travel in a POST body, never
	// in the URL
	event.preventDefault();
	error_box.classList.add("hidden");
	login_btn.disabled = true;
	post("api/auth/login", {
		username: document.getElementById("username").value,
		password: document.getElementById("password").value
	}).then(function(result){
		login_btn.disabled = false;
		if (result.ok){
			// A senha certa não abre sessão nenhuma: ela abre o segundo passo.
			// A senha some da tela junto com o formulário
			document.getElementById("password").value = "";
			enter_mfa(result.data && result.data.mfaEnrolled ? "verify" : "enroll");
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
let initial_stage = document.querySelector(".auth-main").dataset.mfaStage || "";
if (initial_stage){ enter_mfa(initial_stage); }
