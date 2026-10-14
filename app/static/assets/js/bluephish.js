/* bluephish — application layer
 *
 * Replaces the former thephish.js. The server contract is unchanged: every
 * endpoint, form field name and socket event is exactly the one the Flask app
 * already exposes. What changed is the DOM it drives and the fact that all
 * rendering now goes through small helpers instead of Bootstrap classes.
 *
 * The Content-Security-Policy forbids inline event handlers, so controls declare
 * their handler in a data-* attribute and a single set of delegated listeners at
 * the bottom of this file wires them up (this also covers rows added later):
 *   data-click / data-change / data-input : name of a function in HANDLERS
 *   data-arg                              : value passed to it, otherwise the
 *                                           element itself is passed
 *   data-enter                            : called when Enter is pressed
 */

/* ========================================================================== */
/* Transport                                                                  */
/* ========================================================================== */

// The server issues the CSRF token as a readable (non-HttpOnly) cookie and
// validates it in the X-CSRFToken header. fetch is wrapped once here so every
// state-changing request made by this page carries the header automatically.
function csrf_token(){
	let match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
	return match ? decodeURIComponent(match[1]) : "";
}

function csrf_needed(method){
	return ["POST", "PUT", "PATCH", "DELETE"].indexOf((method || "GET").toUpperCase()) !== -1;
}

// A 401 means the session expired (idle/absolute timeout) or was revoked after a
// password change: send the analyst back to the login page
function handle_unauthorized(status){
	if (status === 401){
		window.location.href = "login";
		return true;
	}
	return false;
}

(function(){
	let original_fetch = window.fetch;
	window.fetch = function(resource, options){
		options = options || {};
		let method = options.method || "GET";
		let headers = new Headers(options.headers || {});
		headers.set("X-Requested-With", "XMLHttpRequest");
		if (csrf_needed(method)){ headers.set("X-CSRFToken", csrf_token()); }
		options.headers = headers;
		options.credentials = options.credentials || "same-origin";
		return original_fetch(resource, options).then(function(response){
			handle_unauthorized(response.status);
			return response;
		});
	};
})();

// GET a JSON endpoint. Resolves to null on any transport or server error, which
// is the same shape the old XHR code handled.
function get_json(url){
	return fetch(url).then(function(r){
		if (!r.ok){ return null; }
		return r.json();
	}).catch(function(){ return null; });
}

// POST a form-encoded body and parse the JSON answer. The Flask routes all
// consume request.form, so the encoding is not negotiable.
function post_form(url, params){
	let body = Object.keys(params).map(function(key){
		return encodeURIComponent(key) + "=" + encodeURIComponent(params[key] == null ? "" : params[key]);
	}).join("&");
	return fetch(url, {
		method: "POST",
		headers: {"Content-Type": "application/x-www-form-urlencoded"},
		body: body
	}).then(function(r){
		return r.json().then(function(data){ return {ok: r.ok, status: r.status, data: data}; })
			.catch(function(){ return {ok: r.ok, status: r.status, data: null}; });
	}).catch(function(){ return {ok: false, status: 0, data: null}; });
}

// POST a JSON body (the user-management routes consume request.json)
function post_json(url, payload, method){
	return fetch(url, {
		method: method || "POST",
		headers: {"Content-Type": "application/json"},
		body: JSON.stringify(payload || {})
	}).then(function(r){
		return r.json().then(function(data){ return {ok: r.ok, status: r.status, data: data}; })
			.catch(function(){ return {ok: r.ok, status: r.status, data: null}; });
	}).catch(function(){ return {ok: false, status: 0, data: null}; });
}

/* ========================================================================== */
/* Sessão presa à aba                                                         */
/* ========================================================================== */

/* Fechar a aba tem de encerrar a sessão. O navegador não avisa quando isso
 * acontece — `pagehide` dispara igual num F5, então tratá-lo como logout
 * deslogaria a cada recarga —, mas ele destrói o `sessionStorage` da aba junto
 * com ela, e preserva no F5. É essa diferença que este bloco explora: um token
 * entregue no login, guardado ali, devolvido ao servidor a cada sinal de vida.
 *
 * Sem token, a sessão acabou: o painel se desloga e volta para a tela de login.
 * Com token, ele bate ponto a cada TAB_HEARTBEAT_MS; quando os sinais param, o
 * servidor revoga a sessão sozinho (ver o bloco "Sessão presa à aba" em
 * auth.py). O lado servidor é o que vale — este aqui é quem sabe, na hora, que
 * a aba é outra.
 *
 * O aperto de mão entre abas existe para o caso legítimo de abrir o painel numa
 * segunda aba: ela nasce sem sessionStorage e, sem perguntar a ninguém,
 * derrubaria a sessão da primeira. A pergunta viaja pelo `storage` do
 * localStorage, que só dispara nas *outras* abas, e a resposta é apagada logo
 * em seguida — o token não fica guardado onde sobreviveria ao fechamento. */

const TAB_COOKIE = "bluephish_tab";
const TAB_KEY = "bluephish.tab";
const TAB_ASK_KEY = "bluephish.tab.ask";
const TAB_TELL_KEY = "bluephish.tab.tell";
const TAB_HEARTBEAT_MS = 30000;
// Quanto se espera por uma aba viva antes de concluir que não há nenhuma
const TAB_ANSWER_MS = 500;
// Resposta mais velha que isto é sobra de uma aba que já morreu, não resposta
const TAB_ANSWER_MAX_AGE_MS = 3000;

let tab_token = null;

function read_tab_cookie(){
	let match = document.cookie.match(new RegExp("(?:^|;\\s*)" + TAB_COOKIE + "=([^;]+)"));
	return match ? decodeURIComponent(match[1]) : "";
}

function clear_tab_cookie(){
	document.cookie = TAB_COOKIE + "=; Max-Age=0; path=/; Secure; SameSite=Strict";
}

function adopt_tab_token(token){
	tab_token = token;
	try { window.sessionStorage.setItem(TAB_KEY, token); } catch (e) { /* private mode */ }
}

// Responde à aba que acabou de abrir, se esta aqui tem o token
window.addEventListener("storage", function(event){
	if (event.key !== TAB_ASK_KEY || !event.newValue || !tab_token){ return; }
	try {
		window.localStorage.setItem(TAB_TELL_KEY, JSON.stringify({token: tab_token, at: Date.now()}));
		window.setTimeout(function(){
			try { window.localStorage.removeItem(TAB_TELL_KEY); } catch (e) { /* private mode */ }
		}, TAB_ANSWER_MAX_AGE_MS);
	} catch (e) { /* private mode */ }
});

function ask_other_tabs(){
	return new Promise(function(resolve){
		let settled = false;
		function finish(token){
			if (settled){ return; }
			settled = true;
			window.removeEventListener("storage", on_answer);
			try { window.localStorage.removeItem(TAB_TELL_KEY); } catch (e) { /* private mode */ }
			resolve(token);
		}
		function on_answer(event){
			if (event.key !== TAB_TELL_KEY || !event.newValue){ return; }
			let payload = null;
			try { payload = JSON.parse(event.newValue); } catch (e) { return; }
			if (payload && payload.token && (Date.now() - payload.at) < TAB_ANSWER_MAX_AGE_MS){
				finish(payload.token);
			}
		}
		window.addEventListener("storage", on_answer);
		try {
			window.localStorage.setItem(TAB_ASK_KEY, String(Date.now()));
			window.localStorage.removeItem(TAB_ASK_KEY);
		} catch (e) {
			finish(null);
			return;
		}
		window.setTimeout(function(){ finish(null); }, TAB_ANSWER_MS);
	});
}

/* De onde sai o token desta aba, em ordem: o cookie entregue pelo login (usado
 * uma vez e apagado), o sessionStorage desta aba, ou uma aba irmã já aberta. */
function claim_tab_token(){
	let handed_over = read_tab_cookie();
	if (handed_over){
		adopt_tab_token(handed_over);
		clear_tab_cookie();
		return Promise.resolve(true);
	}
	let stored = null;
	try { stored = window.sessionStorage.getItem(TAB_KEY); } catch (e) { /* private mode */ }
	if (stored){
		tab_token = stored;
		return Promise.resolve(true);
	}
	return ask_other_tabs().then(function(token){
		if (!token){ return false; }
		adopt_tab_token(token);
		return true;
	});
}

// Nenhuma aba é dona desta sessão: a que abriu foi fechada e o cookie ficou
function end_orphan_session(){
	fetch("api/auth/logout", {method: "POST"}).then(function(){
		window.location.href = "login?reason=tab";
	}).catch(function(){
		window.location.href = "login?reason=tab";
	});
}

function tab_heartbeat(){
	if (!tab_token){ return; }
	// Um 401 aqui já é tratado pelo envelope do fetch, que devolve para o login
	fetch("api/auth/heartbeat", {method: "POST", headers: {"X-Session-Tab": tab_token}})
		.catch(function(){ /* rede fora: o próximo sinal resolve */ });
}

/* ========================================================================== */
/* DOM helpers                                                                */
/* ========================================================================== */

function $(id){ return document.getElementById(id); }
function $$(selector){ return Array.prototype.slice.call(document.querySelectorAll(selector)); }

function show(el, visible){
	if (!el){ return; }
	el.classList.toggle("hidden", !visible);
}

// Build an element. Text always goes through textContent — never innerHTML —
// because most of what this UI renders (email subjects, senders, LLM answers,
// whitelist values) is attacker-influenced content.
function el(tag, options, children){
	let node = document.createElement(tag);
	options = options || {};
	if (options.className){ node.className = options.className; }
	if (options.text != null){ node.textContent = options.text; }
	if (options.title){ node.title = options.title; }
	if (options.style){ node.setAttribute("style", options.style); }
	if (options.dataset){
		for (let key of Object.keys(options.dataset)){ node.dataset[key] = options.dataset[key]; }
	}
	if (options.attrs){
		for (let key of Object.keys(options.attrs)){ node.setAttribute(key, options.attrs[key]); }
	}
	if (options.onClick){ node.onclick = options.onClick; }
	for (let child of (children || [])){
		if (child){ node.appendChild(child); }
	}
	return node;
}

// Inline SVG icons are trusted, static markup authored here, so innerHTML is
// safe for them specifically. Never pass user data to this function.
function icon(paths, size){
	let svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
	svg.setAttribute("width", size || 14);
	svg.setAttribute("height", size || 14);
	svg.setAttribute("viewBox", "0 0 16 16");
	svg.setAttribute("fill", "none");
	svg.setAttribute("stroke", "currentColor");
	svg.setAttribute("stroke-width", "1.5");
	svg.setAttribute("stroke-linecap", "round");
	svg.setAttribute("stroke-linejoin", "round");
	svg.innerHTML = paths;
	return svg;
}

const CHECK_ICON = '<path d="M2.6 8.3l3.4 3.4 7.4-7.4"></path>';
const CROSS_ICON = '<path d="M4 4l8 8M12 4l-8 8"></path>';
const SHIELD_ICON = '<path d="M8 1.6l5.2 2v4c0 3.1-2.2 5.8-5.2 7.2-3-1.4-5.2-4.1-5.2-7.2v-4z"></path>';

/* Put a value on the clipboard.
 *
 * The Clipboard API needs a secure context, which this deployment has — it is
 * HTTPS-only. The fallback is there for a bare-HTTP development run, because a
 * copy button that silently does nothing is worse than no copy button: the
 * analyst walks away believing the hash is pasted. Either way the toast is the
 * confirmation, and it only fires on success. */
function copy_to_clipboard(value, message){
	function done(){ toast(message || "Copiado."); }
	function failed(){ toast("Não foi possível copiar. Selecione o valor e copie manualmente.", "bad"); }

	if (navigator.clipboard && window.isSecureContext){
		navigator.clipboard.writeText(value).then(done, failed);
		return;
	}
	let holder = document.createElement("textarea");
	holder.value = value;
	holder.setAttribute("readonly", "");
	holder.style.position = "fixed";
	holder.style.opacity = "0";
	document.body.appendChild(holder);
	holder.select();
	try {
		if (document.execCommand("copy")){ done(); } else { failed(); }
	} catch (e){
		failed();
	}
	document.body.removeChild(holder);
}

// Set a status line, optionally with a tone. Text only — no markup.
function set_status(id, text, tone){
	let node = $(id);
	if (!node){ return; }
	node.textContent = text || "";
	node.classList.remove("ok", "bad");
	if (tone){ node.classList.add(tone); }
}

let toast_timers = [];
function toast(text, tone){
	let dock = $("toastDock");
	let node = el("div", {className: "toast" + (tone ? " " + tone : ""), text: text});
	dock.appendChild(node);
	toast_timers.push(window.setTimeout(function(){ node.remove(); }, 5000));
}

/* ========================================================================== */
/* Theme                                                                      */
/* ========================================================================== */

const SUN = '<circle cx="8" cy="8" r="3.2"></circle><path d="M8 1.2v1.6M8 13.2v1.6M1.2 8h1.6M13.2 8h1.6M3.2 3.2l1.1 1.1M11.7 11.7l1.1 1.1M12.8 3.2l-1.1 1.1M4.3 11.7l-1.1 1.1"></path>';
const MOON = '<path d="M13.4 9.6A5.8 5.8 0 116.4 2.6a4.6 4.6 0 007 7z"></path>';

// Brand prefixes for the localStorage preference keys, newest first. Writes go
// to PREF_BRANDS[0]; boot() reads down the list so a rename never resets an
// analyst's theme. Append a new name to the FRONT, never drop the tail.
const PREF_BRANDS = ["bluephish", "bluephising", "redphish"];

function apply_theme(theme){
	document.documentElement.setAttribute("data-theme", theme);
	let button = $("themeToggle");
	button.replaceChildren(icon(theme === "dark" ? SUN : MOON, 15));
	button.title = theme === "dark" ? "Mudar para o tema claro" : "Mudar para o tema escuro";
	try { window.localStorage.setItem(PREF_BRANDS[0] + ".theme", theme); } catch (e) { /* private mode */ }
}

function toggle_theme(){
	apply_theme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
}

function toggle_sidebar(){
	let collapsed = !$("sidebar").classList.contains("hidden");
	show($("sidebar"), !collapsed);
	show($("rail"), collapsed);
	try { window.localStorage.setItem(PREF_BRANDS[0] + ".sidebar", collapsed ? "closed" : "open"); } catch (e) { /* private mode */ }
}

function toggle_profile_menu(element, event){
	// A click inside the popup must not re-toggle it
	if (event && event.target.closest("#profileMenu")){ return; }
	$("profileMenu").classList.toggle("hidden");
}

/* ========================================================================== */
/* Tamanho da interface                                                       */
/* ========================================================================== */

/* O valor vive em `font-size` no <html>, e toda a folha de estilo mede em rem —
 * então mexer aqui move texto, campo, botão e espaçamento juntos, em vez de
 * inchar a letra dentro de uma caixa que não cresce.
 *
 * Por que existe, se o navegador já tem Ctrl+ +/-: o zoom do navegador é por
 * origem e some quando a pessoa entra de outra máquina, e boa parte de quem
 * precisa dele não sabe que existe. Num painel que o analista encara por turnos
 * inteiros, com texto de 10,5px, o controle na tela é a diferença entre
 * conseguir ler e trocar de ferramenta. A preferência do navegador continua
 * valendo e se multiplica com esta — as duas usam a mesma base. */

const SCALE_KEY = PREF_BRANDS[0] + ".scale";
const SCALE_BASE = 16;

/* Três tamanhos, e não um contínuo. O controle antigo era mais e menos: para
 * chegar no maior a pessoa clicava cinco vezes, e nenhum clique dizia onde ia
 * parar. Com três opções nomeadas, um clique chega em qualquer uma, e o botão
 * mostra a letra no tamanho que aplica — quem olha já sabe o que vai acontecer.
 *
 * Os valores: 87,5% para quem quer mais densidade num monitor grande, 100% como
 * veio, e 125% para quem lê o dia inteiro. Não vai além disso porque a partir
 * daí a barra lateral e a lista deixam de caber lado a lado num notebook, que é
 * a segunda tela deste produto. Quem precisa de mais tem o zoom do navegador, e
 * ele agora funciona de verdade: com a folha medindo em rem, a preferência de
 * fonte do navegador se multiplica com esta escolha em vez de ser ignorada. */
const SCALES = { small: 0.875, normal: 1, large: 1.25 };
const SCALE_ORDER = ["small", "normal", "large"];
const SCALE_NAMES = { small: "pequeno", normal: "normal", large: "grande" };

let ui_scale_name = "normal";

/* Um botão que avança a cada clique, em vez de três alvos. A escolha não precisa
 * de três botões porque o resultado aparece na hora: a tela inteira muda de
 * tamanho, e essa é a confirmação mais direta que existe. O que o controle
 * precisa dizer, e diz pelo título e pelo nome acessível, é para onde o próximo
 * clique vai — senão ele promete um caminho sem dizer onde termina.
 *
 * Volta ao pequeno depois do grande. Sem a volta, quem chega no maior fica preso
 * e precisa procurar outro caminho para voltar; com ela, três cliques dão a
 * volta completa e qualquer tamanho está a no máximo dois cliques de distância. */
function set_scale(name, announce){
	if (!SCALES[name]){ name = "normal"; }
	ui_scale_name = name;
	document.documentElement.style.fontSize = (SCALE_BASE * SCALES[name]) + "px";

	let button = $("scaleToggle");
	if (button){
		let proximo = SCALE_ORDER[(SCALE_ORDER.indexOf(name) + 1) % SCALE_ORDER.length];
		button.dataset.size = name;
		let descricao = "Tamanho do texto: " + SCALE_NAMES[name]
			+ ". Clique para " + SCALE_NAMES[proximo] + ".";
		button.title = descricao;
		button.setAttribute("aria-label", descricao);
	}

	try { window.localStorage.setItem(SCALE_KEY, name); } catch (e) { /* private mode */ }
	// Só anuncia quando alguém escolheu; na carga inicial calaria em cima da
	// leitura do título da página
	if (announce !== false){ announce_live("Texto " + SCALE_NAMES[name]); }
}

function cycle_scale(){
	set_scale(SCALE_ORDER[(SCALE_ORDER.indexOf(ui_scale_name) + 1) % SCALE_ORDER.length], true);
}

function load_scale(){
	let saved = null;
	try { saved = window.localStorage.getItem(SCALE_KEY); } catch (e) { /* private mode */ }
	// A primeira versão deste controle guardava um número (1.125, 1.375…). Um
	// valor desses vira o nome mais próximo em vez de ser descartado: quem já
	// tinha escolhido um tamanho não volta ao padrão porque o controle mudou de
	// forma
	if (saved && !SCALES[saved]){
		let numero = parseFloat(saved);
		if (numero){
			saved = SCALE_ORDER.reduce(function(melhor, nome){
				return Math.abs(SCALES[nome] - numero) < Math.abs(SCALES[melhor] - numero) ? nome : melhor;
			}, "normal");
		}
	}
	set_scale(SCALES[saved] ? saved : "normal", false);
}



/* Uma região viva só, reaproveitada por tudo que muda sem o foco se mover. Sem
 * ela, quem usa leitor de tela não fica sabendo que o veredito chegou, que a
 * regra foi salva ou que o tamanho mudou — a tela avisa só quem está olhando. */
function announce_live(message){
	let region = $("liveRegion");
	if (!region){ return; }
	// Limpar antes força o leitor a anunciar de novo quando a mensagem se repete
	region.textContent = "";
	window.setTimeout(function(){ region.textContent = message; }, 60);
}
/* Um `div` com onclick não recebe Tab, não responde a Espaço nem Enter e não se
 * anuncia como controle. Eram 21 nesta interface, incluindo TODAS as chaves de
 * ligar/desligar das configurações — quem navega por teclado não conseguia ligar
 * o agendador nem a IA. Aqui cada um ganha papel, foco e as teclas que o papel
 * implica, sem virar <button>: trocar a tag mexeria no layout de todos eles. */
function make_operable(element, role){
	if (!element || element.dataset.a11yReady === "1"){ return; }
	element.dataset.a11yReady = "1";
	element.setAttribute("role", role);
	element.setAttribute("tabindex", "0");
	element.addEventListener("keydown", function(event){
		if (event.key === "Enter" || event.key === " " || event.key === "Spacebar"){
			event.preventDefault();
			element.click();
		}
	});
}

/* `aria-checked` precisa acompanhar a classe que já pinta o estado, senão o
 * leitor de tela anuncia o contrário do que a tela mostra. */
function sync_checked(element, on){
	if (element && element.hasAttribute("role")){ element.setAttribute("aria-checked", on ? "true" : "false"); }
}

function wire_a11y_controls(){
	for (let node of document.querySelectorAll(".toggle")){
		make_operable(node, "switch");
		sync_checked(node, node.classList.contains("on"));
	}
	for (let node of document.querySelectorAll(".check")){
		make_operable(node, "checkbox");
		sync_checked(node, node.classList.contains("on"));
	}
	let profile = document.querySelector(".profile");
	if (profile){
		make_operable(profile, "button");
		profile.setAttribute("aria-haspopup", "menu");
		profile.setAttribute("aria-expanded", "false");
	}
}

/* ========================================================================== */
/* Generic controls                                                           */
/* ========================================================================== */

// Toggle switches carry their state in the "on" class; the save handlers read it
function toggle_switch(element){
	element.classList.toggle("on");
	sync_checked(element, element.classList.contains("on"));
}
function switch_on(id){ return $(id).classList.contains("on"); }
function set_switch(id, on){ $(id).classList.toggle("on", !!on); sync_checked($(id), !!on); }

// Keep a range input and its number twin in sync. Each declares the other's id
// in data-arg, so the dispatcher hands over that id and the edited field is the
// event target.
function sync_range(target_id, event){
	let target = $(target_id);
	if (target && event){ target.value = event.target.value; }
}
function set_paired(number_id, range_id, value){
	if (document.activeElement !== $(number_id)){ $(number_id).value = value; }
	$(range_id).value = value;
}

/* ========================================================================== */
/* Modals                                                                     */
/* ========================================================================== */

let open_modal_id = null;

function open_modal(id){
	close_modal();
	open_modal_id = id;
	show($("modalScrim"), true);
	show($(id), true);
}

function close_modal(){
	if (open_modal_id){ show($(open_modal_id), false); }
	open_modal_id = null;
	show($("modalScrim"), false);
}

// Replacement for window.prompt / window.confirm, so the dialogs match the shell.
// on_confirm receives the typed value (or null when there is no input field).
function ask(options, on_confirm){
	$("promptTitle").textContent = options.title;
	$("promptSub").textContent = options.sub || "";
	$("promptBody").textContent = options.body || "";
	show($("promptBody"), !!options.body);
	let field = $("promptField");
	let input = $("promptInput");
	show(field, !!options.label);
	if (options.label){
		$("promptLabel").textContent = options.label;
		input.type = options.type || "text";
		input.value = "";
		input.placeholder = options.placeholder || "";
	}
	let confirm_btn = $("promptConfirm");
	confirm_btn.textContent = options.confirmLabel || "Confirmar";
	confirm_btn.classList.toggle("danger", !!options.danger);
	confirm_btn.onclick = function(){
		let value = options.label ? input.value : null;
		if (options.label && !value){ return; }
		close_modal();
		on_confirm(value);
	};
	open_modal("promptModal");
	if (options.label){ window.setTimeout(function(){ input.focus(); }, 30); }
}

/* ========================================================================== */
/* View routing                                                               */
/* ========================================================================== */

// Identity of the signed-in user, filled by load_identity() at page load and
// used to decide which views this user may open. The privileged views are also
// guarded server-side: hiding them here is usability, not access control.
let current_identity = null;
let current_view = "inbox";

function show_view(view){
	if (view === "config" && !(current_identity && current_identity.canChangeSettings)){ return; }
	if (view === "integr" && !(current_identity && current_identity.canChangeSettings)){ return; }
	if (view === "users" && !(current_identity && current_identity.canManageUsers)){ return; }
	if (view === "audit" && !(current_identity && current_identity.canChangeSettings)){ return; }
	current_view = view;
	// A section may belong to several views ("done queues"): the case detail is
	// one component on the archive and on the work desk
	for (let section of $$("[data-view]")){
		show(section, section.dataset.view.split(" ").indexOf(view) !== -1);
	}
	for (let item of $$(".nav-item")){
		item.classList.toggle("active", item.dataset.arg === view);
	}
	show($("profileMenu"), false);
	if (view === "users"){ load_users(); }
	// Os analisadores são carregados junto com a aba Plataforma, e não só quando a
	// aba Analisadores abre: o card da Plataforma resume quantos estão habilitados,
	// e um resumo que só aparece depois de visitar outra aba não é resumo.
	if (view === "integr"){
		load_email_config();
		if (analyzer_registry.length === 0){ load_analyzers(); }
		if (ticket_registry.length === 0){ load_tickets(); }
		// Os destinos são carregados uma vez só; nas aberturas seguintes o
		// registro já está em memória e não há render para atualizar a linha
		update_integr_summary();
	}
	// The TheHive-backed screens are fetched on first open and then reused; the
	// refresh button on each header forces a new read
	if (view === "exec" && insights_payload == null){ load_insights(); }
	if (view === "done" && case_rows.length === 0){ load_cases(); }
	// A fila é recarregada a cada abertura, e não só na primeira: ela responde
	// "o que ainda espera decisão", e essa resposta muda com o trabalho de
	// qualquer pessoa da equipe — inclusive com o que esta acabou de decidir
	if (view === "queues"){ load_desk_queue(); }
	if (view === "tactic"){
		if (insights_payload == null){ load_insights(); }
		if (phish_rows.length === 0){ load_phish(); }
		if (phish_windows == null){ load_phish_windows(); }
		render_phish_inbox_subjects();
		start_phish_live();
	} else {
		stop_phish_live();
	}
	// A trilha é relida a cada abertura: ela é o registro do que acabou de
	// acontecer, e uma tabela de auditoria parada no passado engana
	if (view === "audit"){ load_audit(); }
	sync_case_assistant();
	sync_audit_assistant();
}

function show_config_tab(tab){
	if (current_view !== "config"){ show_view("config"); }
	for (let panel of $$("[data-config-tab]")){
		show(panel, panel.dataset.configTab === tab);
	}
	for (let button of $$("#configTabs .tab")){
		button.classList.toggle("active", button.dataset.arg === tab);
	}
}

// Fetch the identity of the caller and reveal only the controls the role allows
function load_identity(){
	get_json("api/auth/me").then(function(identity){
		if (!identity){
			window.location.href = "login";
			return;
		}
		current_identity = identity;
		$("profileName").textContent = identity.username;
		$("profileRole").textContent = identity.role;
		$("profileInitials").textContent = identity.username.substring(0, 2).toUpperCase();
		$("accountIdentity").textContent = identity.username + " · " + identity.role;
		// Quem chegou até aqui atravessou o segundo fator — a sessão não existe
		// sem ele. O painel diz desde quando, que é o que dá para conferir
		$("accountMfaSince").textContent = identity.mfaConfirmedAt
			? "configurada em " + identity.mfaConfirmedAt : "";
		show($("navConfig"), identity.canChangeSettings);
		show($("navIntegr"), identity.canChangeSettings);
		show($("navUsers"), identity.canManageUsers);
		show($("navAudit"), identity.canChangeSettings);
		// Quem entra no painel é decisão de global_admin: a aba de SSO segue a
		// mesma régua da tela de Usuários, não a das outras configurações
		show($("configTabSso"), identity.canManageUsers);
		show($("configTabAudit"), identity.canManageUsers);
		show($("navAdminGroup"), identity.canChangeSettings || identity.canManageUsers);
		// Bloquear altera um sistema de terceiro, então segue a mesma régua da
		// whitelist e das Integrações: só admin. Um botão visível que responde 403
		// é pior do que botão nenhum — ele sugere que a ação existe para quem olha.
		show($("caseBlockBtn"), identity.canChangeSettings);
		show($("phishBlockBtn"), identity.canChangeSettings);
		// Only load the configuration the user is allowed to read
		if (identity.canChangeSettings){
			load_scheduler_config();
			load_llm_config();
			load_email_config();
			// Os destinos de registro não são pedidos aqui: a aba Integrações os
			// carrega quando abre, e é de lá que sai a linha de resumo do painel
			load_verdict_config();
			load_smtp_config();
			load_case_config();
			load_evidence_config();
			load_departments_config();
			load_inbox_poll_config();
			load_whitelist();
			window.setInterval(load_scheduler_config, 30000);
		}
		// /sso-config exige global_admin: só quem pode lê-lo é que o pede
		if (identity.canManageUsers){ load_sso_config(); load_audit_log_config(); }
	});
}

function do_logout(){
	fetch("api/auth/logout", {method: "POST"}).then(function(){
		window.location.href = "login";
	}).catch(function(){
		window.location.href = "login";
	});
}

/* ========================================================================== */
/* Socket / analysis log                                                      */
/* ========================================================================== */

const socket = io();

/* "Listar e-mails" lives inside the empty state, so it leaves the document as
 * soon as the queue has rows — and the queue now fills on its own, from the
 * mailbox poll. Every caller goes through here rather than assuming the button
 * is on screen. */
function set_list_button(disabled){
	let button = $("listMailsBtn");
	if (button){ button.disabled = disabled; }
}

socket.on("connect", function(){
	set_list_button(false);
});

function append_log(level, text){
	let console_box = $("logConsole");
	show(console_box, true);
	let line = el("span", {className: "lvl-" + level, text: "[" + level.toUpperCase() + "] " + text + "\n"});
	$("logText").appendChild(line);
	console_box.scrollTop = console_box.scrollHeight;
}

socket.on("logInfo", function(data){ append_log("info", data); });
socket.on("logWarning", function(data){ append_log("warning", data); });
socket.on("logError", function(data){ append_log("error", data); });

// Refresh the scheduler status when an automatic analysis cycle starts or ends
socket.on("autoAnalysis", function(data){
	if (data.event === "cycle_start"){
		show($("runCard"), true);
		$("runTitle").textContent = "Ciclo automático em andamento";
	}
	if (current_identity && current_identity.canChangeSettings){ load_scheduler_config(); }
});

/* ========================================================================== */
/* Inbox — listing, selection and analysis                                    */
/* ========================================================================== */

let queue = [];            // emails returned by GET /list or pushed by the poll
let queue_selected = null; // mailUID currently open in the preview
let queue_checked = [];    // mailUIDs ticked for the batch scan
let queue_listed = false;  // whether a listing has landed at all, so an empty
                           // mailbox does not read like a screen nobody loaded

/* Which end of the mailbox the analyst wants at the top.
 *
 * This is a view preference, not a query: the server sends the whole mailbox
 * with BOTH ends already downloaded, so switching is a reversal of a list the
 * browser is already holding. It used to be a query parameter, which meant a
 * click waited out a running poll cycle — a minute or more — before anything
 * changed on screen. It is kept per browser rather than on the server because
 * two analysts looking at the same queue should not be able to reorder it
 * under each other. */
const INBOX_ORDER_KEY = "bluephish.inboxOrder";
let inbox_order = "newest";

/* The direction the listing currently in `queue` was built in, as the server
 * reported it. The displayed list is `queue` when the two agree and its reverse
 * when they do not — which is the whole of the filter. Keeping the two apart is
 * what stopped a push arriving mid-click from flipping the chips: the server
 * says what it sent, the analyst says what they want to see, and neither
 * overwrites the other. */
let queue_order = "newest";

/* mailUID whose body is being fetched right now, so that a slow answer for an
 * email the analyst has already navigated away from is dropped instead of
 * overwriting whatever they are looking at now. */
let inbox_loading_uid = null;

/* What the analyst typed in the queue search box.
 *
 * Filtering happens here rather than on the server, and that is the whole point:
 * the listing already holds every unread email, so narrowing it costs nothing
 * and cannot go stale between the keystroke and the answer. Asking the server
 * would mean rereading the mailbox — the same mistake the order filter used to
 * make, which cost a click a full polling cycle before anything moved.
 *
 * The queue is not a place anyone scrolls: a real mailbox arrives with hundreds
 * of unread reports, and the one being asked about is always identified by
 * sender, subject or UID. */
let queue_query = "";

/* The queue is read a page at a time.
 *
 * A mailbox arrives with thousands of unread reports, and a list that long is not
 * scrolled — it is searched or paged. A page is a slice of queue_display(), the
 * analyst's order and then their search, so page 1 of "Mais recentes" and page 1
 * of "Mais antigos" are the two ends of the mailbox, which are exactly the pages
 * the server loads first (inbox_pages.page_plan).
 *
 * The size is the admin's (`pageSize` in the push). The page number is this
 * browser's, and a polling tick does not reset it: a refresh that throws the
 * analyst back to page 1 while they are working page 12 makes paging useless at
 * the moment it is needed. Changing the order or the search does reset it, because
 * page 12 of a different list is not where anybody was. */
let inbox_page = 1;
let inbox_page_size = 30;
const INBOX_PAGE_SIZES = [20, 30, 40, 50];

/* How far the server's background loader has got, as it last reported. */
let inbox_loader_state = null;

/* Full bodies fetched with GET /email/<uid>, by mailUID.
 *
 * The push carries a snippet of each body, not the body — thousands of full
 * bodies on every tick would be megabytes per minute per tab. When an analyst
 * opens an email its whole text is fetched once and kept here, so the next tick,
 * which replaces the queue with snippets, cannot shorten the text they are
 * reading. Dropped when the email leaves the listing or its arrival time changes
 * (a recycled IMAP id is another message). */
let queue_full = {};

/* What POST /analysis-selected accepts in one call. Mirrored here because the
 * queue is no longer bounded by what fits in a download: "select all" on a
 * mailbox with a real backlog would otherwise tick two thousand emails and
 * build a request the server refuses, which reads to the analyst as the scan
 * being broken rather than as a batch being too large. */
const BATCH_SCAN_MAX = 50;

// "Other" is a case an analyst closed under a resolution this application does
// not interpret (Indeterminate, Duplicated); it is reported as-is rather than
// folded into one of the real verdicts
const VERDICT_TONE = {Safe: "ok", Suspicious: "warn", Malicious: "bad", Other: ""};
const VERDICT_LABEL = {Safe: "SEGURO", Suspicious: "SUSPEITO", Malicious: "MALICIOSO", Other: "OUTRO"};

// Analyzers speak in taxonomy levels; the interface speaks in verdicts. 'info'
// has no verdict of its own — it means the analyzer had nothing to say.
const LEVEL_TO_VERDICT = {safe: "Safe", suspicious: "Suspicious", malicious: "Malicious", info: "Other"};

/* The two empty states of the queue, held rather than looked up.
 *
 * They are declared in the template, and render_queue() clears the container on
 * every pass — which detaches them from the document, and getElementById cannot
 * find a node that is not in the document. So the lookup has to happen before
 * the first clear, once, and the references are what put them back.
 *
 * Without this the list breaks the *second* time the queue is empty: rows are
 * rendered, the node is detached, and the next appendChild gets null. Analyzing
 * the last report in the queue is enough to reach it. */
let queue_empty_node = null;
let queue_nomatch_node = null;

function render_queue(){
	let container = $("queueRows");
	queue_empty_node = queue_empty_node || $("queueEmpty");
	queue_nomatch_node = queue_nomatch_node || $("queueNoMatch");
	container.replaceChildren();

	if (queue.length === 0){
		container.appendChild(queue_empty_node);
		show(queue_empty_node, true);
		show(queue_nomatch_node, false);
		$("inboxCount").textContent = queue_listed
			? "nenhum e-mail pendente na caixa monitorada"
			: "nenhuma listagem ainda";
		render_inbox_pager(0);
		render_selection_state();
		return;
	}

	let visible = queue_display();

	// A queue with reports in it and a search that matches none of them is not
	// an empty mailbox, and the way out of the two is different: one waits for
	// an email to arrive, the other waits for the analyst to type something
	// else. Saying "nenhum e-mail pendente" here would be a lie about the queue.
	if (visible.length === 0){
		queue_nomatch_node.querySelector("#queueNoMatchTerm").textContent = queue_query;
		container.appendChild(queue_nomatch_node);
		show(queue_nomatch_node, true);
		show(queue_empty_node, false);
		$("inboxCount").textContent = queue_count_label();
		render_inbox_pager(0);
		render_selection_state();
		return;
	}

	for (let mail of queue_page_rows(visible)){
		let checked = queue_checked.indexOf(mail.mailUID) !== -1;
		let selected = queue_selected === mail.mailUID;
		let loaded = mail.bodyLoaded !== false;

		let box = el("div", {className: "check" + (checked ? " on" : "")}, [icon(CHECK_ICON, 9)]);
		box.onclick = function(event){
			event.stopPropagation();
			toggle_check(mail.mailUID);
		};

		// A row the background loader has not reached yet says so, rather than
		// showing an email type it does not know. "Attached .eml" vs "Raw Email"
		// is read out of the message structure, so guessing one here would be a
		// label the analyst could act on and that could be wrong. It still opens:
		// the click fetches that one email ahead of the loader.
		let meta = "UID " + mail.mailUID + " · "
			+ (loaded ? (mail.email_type || "Raw Email") : "aguardando carregamento");

		let row = el("div", {
			className: "mail-row" + (selected ? " selected" : "") + (checked && !selected ? " checked" : "")
				+ (loaded ? "" : " deferred")
		}, [
			el("div", {className: "rail-mark"}),
			el("div", {className: "row", style: "gap:8px;width:100%"}, [
				box,
				el("span", {className: "mail-from truncate grow", text: mail.from || "(remetente desconhecido)"}),
				el("span", {className: "mail-time", text: short_date(mail), title: full_date(mail)})
			]),
			el("div", {className: "mail-subject truncate", text: mail.subject || "(sem assunto)"}),
			el("div", {className: "mail-meta truncate", text: meta})
		]);
		row.onclick = function(){ open_queue_item(mail.mailUID); };
		container.appendChild(row);
	}

	$("inboxCount").textContent = queue_count_label();
	render_inbox_pager(visible.length);
	render_selection_state();
}

/* The line under the title.
 *
 * It has to carry two numbers, not one: how many reports are waiting, and how
 * many of them are already downloaded. An analyst who sees only the first has
 * no way to tell a queue that is slow to open from one that is broken. */
function queue_count_label(){
	let loaded = queue.filter(function(m){ return m.bodyLoaded !== false; }).length;

	// With a search running, the first number has to be what is on screen and
	// the second what the mailbox holds. Reporting only the filtered count would
	// read as a queue that shrank; reporting only the total would describe a
	// list nobody is looking at.
	if (queue_query){
		return queue_display().length + " de " + queue.length + " e-mail(s) não analisado(s)";
	}

	let label = queue.length + " e-mail(s) não analisado(s)";
	if (loaded < queue.length){
		label += " · " + loaded + " com conteúdo carregado";
	}
	return label;
}

/* The queue as the analyst asked to see it: their order, then their search.
 *
 * The server downloads both ends of the mailbox, so the first rows of either
 * direction already carry their bodies — reversing here never lands anybody on
 * a screenful of rows that all have to be fetched one by one. */
function queue_display(){
	let rows = inbox_order === queue_order ? queue : queue.slice().reverse();
	return queue_query ? rows.filter(queue_matches) : rows;
}

function page_count(rows){
	return Math.max(1, Math.ceil(rows / inbox_page_size));
}

/* The rows of the current page. The page is clamped here, on every read, rather
 * than when the queue changes: an analysis that removes the last row of the last
 * page, a search that narrows the list, a smaller page size — all of them can
 * leave the number past the end, and each would otherwise need its own fix. */
function queue_page_rows(visible){
	visible = visible || queue_display();
	inbox_page = Math.min(Math.max(1, inbox_page), page_count(visible.length));
	let start = (inbox_page - 1) * inbox_page_size;
	return visible.slice(start, start + inbox_page_size);
}

function go_inbox_page(where){
	let pages = page_count(queue_display().length);
	let target = {first: 1, prev: inbox_page - 1, next: inbox_page + 1, last: pages}[where];
	if (!target){ return; }
	target = Math.min(Math.max(1, target), pages);
	if (target === inbox_page){ return; }
	inbox_page = target;
	render_queue();
	$("queueRows").scrollTop = 0;
}

function render_inbox_pager(rows){
	let pager = $("inboxPager");
	if (!pager){ return; }
	show(pager, queue.length > 0);
	let pages = page_count(rows);
	let first = rows === 0 ? 0 : (inbox_page - 1) * inbox_page_size + 1;
	let last = Math.min(rows, inbox_page * inbox_page_size);
	$("inboxPageLabel").textContent = rows === 0
		? "nenhuma página"
		: "Página " + inbox_page + " de " + pages + " · " + first + "–" + last + " de " + rows;
	let at_start = rows === 0 || inbox_page <= 1;
	let at_end = rows === 0 || inbox_page >= pages;
	$("inboxPageFirst").disabled = at_start;
	$("inboxPagePrev").disabled = at_start;
	$("inboxPageNext").disabled = at_end;
	$("inboxPageLast").disabled = at_end;
	render_inbox_loader();
}

/* What the server's background loader is doing, in the analyst's terms.
 *
 * The server speaks of the front and the back of its listing; the analyst sees
 * "Mais recentes" and "Mais antigos", and which one is the front depends on the
 * direction the listing was built in. Messages it could not load are counted
 * rather than hidden, so a total that never reaches the end explains itself —
 * those still open on the click, like every email did before the loader. */
function render_inbox_loader(){
	let node = $("inboxLoader");
	if (!node){ return; }
	let state = inbox_loader_state;
	if (!state || !state.total){
		node.textContent = "";
		return;
	}
	if (state.available === false){
		node.textContent = "carregamento em segundo plano indisponível — cada e-mail carrega ao abrir";
		return;
	}
	let skipped = state.skipped || 0;
	if (state.ready + skipped >= state.total){
		node.textContent = skipped > 0
			? state.ready + " de " + state.total + " prontos · " + skipped + " carregam ao abrir"
			: "texto e diagramação de todas as páginas prontos";
		return;
	}
	let text = state.ready + " de " + state.total + " e-mails prontos";
	if (state.running && state.page){
		let newest_first = queue_order === "newest";
		let end_label = (state.end === "front") === newest_first ? "mais recentes" : "mais antigos";
		text += " · carregando a página " + state.page + " dos " + end_label;
	}
	node.textContent = text;
}

/* Does one queue entry match what was typed?
 *
 * Every term has to match somewhere, in any field — so "boleto itau" finds the
 * email whose subject says boleto and whose sender is at itau, which is how
 * somebody describes an email out loud. Substring rather than whole word: half a
 * domain or the first digits of a UID is usually all anybody remembers.
 *
 * The body is searched only when it is here. Past the download limit the listing
 * carries the envelope alone, and a row that cannot be searched by content must
 * not be dropped for not matching it — the sender and the subject came from the
 * envelope and are as solid as any other row's. */
function queue_matches(mail){
	let haystack = [
		mail.from, mail.subject, mail.attachedMail, mail.mailUID,
		mail.email_type, mail.bodyLoaded !== false ? mail.body : ""
	].join(" ").toLowerCase();
	return queue_query.toLowerCase().split(/\s+/).every(function(term){
		return term === "" || haystack.indexOf(term) !== -1;
	});
}

// Client-side, so the delay is only there to coalesce keystrokes into one
// render rather than to spare a request
let queue_query_timer = null;
function filter_queue_debounced(){
	show($("queueQueryClear"), $("queueQuery").value.trim() !== "");
	window.clearTimeout(queue_query_timer);
	queue_query_timer = window.setTimeout(function(){
		queue_query = $("queueQuery").value.trim();
		inbox_page = 1;
		render_queue();
	}, 120);
}

function clear_queue_query(){
	window.clearTimeout(queue_query_timer);
	$("queueQuery").value = "";
	queue_query = "";
	inbox_page = 1;
	show($("queueQueryClear"), false);
	render_queue();
	$("queueQuery").focus();
}

/* The order filter. Newest-first is the default (a report that just came in is
 * the one worth looking at); oldest-first is how a backlog gets worked down
 * without the newest arrivals pushing it out of reach forever.
 *
 * It asks the server for nothing: the rows are already here and both ends are
 * already downloaded, so the switch is immediate. */
function set_inbox_order(order){
	order = order === "oldest" ? "oldest" : "newest";
	if (order === inbox_order){ return; }
	inbox_order = order;
	try { window.localStorage.setItem(INBOX_ORDER_KEY, order); } catch (e){ /* private mode */ }
	inbox_page = 1;
	render_inbox_order();
	render_queue();
}

function load_inbox_order(){
	let saved = null;
	try { saved = window.localStorage.getItem(INBOX_ORDER_KEY); } catch (e){ /* private mode */ }
	inbox_order = saved === "oldest" ? "oldest" : "newest";
	render_inbox_order();
}

function render_inbox_order(){
	for (let chip of $$("#inboxOrder .chip")){
		chip.classList.toggle("active", chip.dataset.arg === inbox_order);
	}
}

/* When the report came in.
 *
 * The listing carries `receivedAt`, the Date header already parsed into epoch
 * milliseconds, so the hour can be shown in the analyst's own timezone — the
 * raw header arrives in whatever format and offset the reporter's mail client
 * wrote, which is why this used to show a day and nothing more. `date` is the
 * fallback for a message whose header could not be parsed at all. */
function short_date(mail){
	if (mail && mail.receivedAt){
		let moment = new Date(mail.receivedAt);
		let today = new Date();
		let same_day = moment.toDateString() === today.toDateString();
		let clock = moment.toLocaleTimeString("pt-BR", {hour: "2-digit", minute: "2-digit"});
		return same_day ? clock : moment.toLocaleDateString("pt-BR", {day: "2-digit", month: "2-digit"}) + " " + clock;
	}
	let value = mail && mail.date;
	if (!value){ return ""; }
	let text = String(value);
	let match = text.match(/\d{1,2}\s+\w{3}\s+\d{4}/);
	return match ? match[0] : text.substring(0, 16);
}

// The same instant spelled out, for the header of the open preview
function full_date(mail){
	if (mail && mail.receivedAt){ return format_date(mail.receivedAt); }
	return (mail && mail.date) || "";
}

function render_selection_state(){
	let count = queue_checked.length;
	let visible = queue_display();
	let page_rows = queue_page_rows(visible).map(function(m){ return m.mailUID; });

	// A tick survives the page turn and the search that hide its row — the analyst
	// built that selection on purpose, and neither is unticking it. But the scan
	// would then run on emails nobody can see, so the count says how many are off
	// screen, and whether another page or the search is hiding them. Silence here
	// is how somebody analyzes forty reports believing they analyzed four.
	let off_page = 0;
	let off_search = 0;
	if (count > 0){
		let in_search = {};
		for (let m of visible){ in_search[m.mailUID] = true; }
		for (let uid of queue_checked){
			if (!in_search[uid]){ off_search += 1; }
			else if (page_rows.indexOf(uid) === -1){ off_page += 1; }
		}
	}

	let label = count > 0 ? count + " selecionado(s)" : "";
	if (off_page > 0){ label += " · " + off_page + " em outras páginas"; }
	if (off_search > 0){ label += " · " + off_search + " fora da busca"; }
	$("queueCheckedLabel").textContent = label;

	show($("queueBulkBar"), count > 0);
	let page_ticked = page_rows.filter(function(uid){ return queue_checked.indexOf(uid) !== -1; }).length;
	$("queueCheckAll").classList.toggle("on", page_rows.length > 0 && page_ticked === page_rows.length);
	$("navInboxBadge").textContent = queue.length > 0 ? String(queue.length) : "";
}

function toggle_check(uid){
	let index = queue_checked.indexOf(uid);
	if (index === -1){ queue_checked.push(uid); } else { queue_checked.splice(index, 1); }
	render_queue();
}

function toggle_select_all(){
	// "Todos" means the rows on this page — with a search running, the page of the
	// filtered list. A page is at most 50 rows, which is what one scan accepts, so
	// the control never offers a batch the server would refuse; ticks from other
	// pages are kept, and only refused when they would push the batch past it
	let page_rows = queue_page_rows().map(function(m){ return m.mailUID; });
	let all_ticked = page_rows.length > 0 && page_rows.every(function(uid){
		return queue_checked.indexOf(uid) !== -1;
	});
	if (all_ticked){
		queue_checked = queue_checked.filter(function(uid){ return page_rows.indexOf(uid) === -1; });
		render_queue();
		return;
	}
	let merged = queue_checked.slice();
	for (let uid of page_rows){
		if (merged.indexOf(uid) === -1){ merged.push(uid); }
	}
	if (merged.length > BATCH_SCAN_MAX){
		toast("Um scan roda no máximo " + BATCH_SCAN_MAX + " e-mails por vez. "
			+ "Limpe a seleção das outras páginas antes de marcar esta.");
		return;
	}
	queue_checked = merged;
	render_queue();
}

function clear_selection(){
	queue_checked = [];
	render_queue();
}

/* ---------------------------------------------------------------------------
 * "Como entregue"
 *
 * The default preview is text pulled out of the message, and it stays the
 * default: nothing in it can pretend to be something else. What it cannot show
 * is the half of a phishing email that does the persuading — the forged
 * letterhead, the button whose label and destination disagree, the layout that
 * convinced somebody enough to report it.
 *
 * That view is rendered by the server (email_render.py) into markup that cannot
 * act, and shown here inside an iframe with an empty `sandbox` attribute: no
 * scripts, no same-origin, no forms, no navigation. The frame is `srcdoc`, so it
 * also inherits this page's CSP — `script-src 'self'` and `img-src 'self' data:`
 * — which happens to be exactly the right policy for hostile mail: inline images
 * that arrived with the message render, anything that would touch the network
 * does not. Three layers, none of them load-bearing alone.
 *
 * It is fetched on the click that asks for it. Carrying it on the listing would
 * mean base64 logos and attachment hashes for every unread email in the mailbox,
 * every polling cycle, for the ones nobody opens.
 * ------------------------------------------------------------------------- */

let preview_mode = "text";
let preview_rendered = null;      // payload for the email currently open
let preview_rendering_uid = null; // in flight, so a slow answer for an email the
                                  // analyst left is dropped, not shown
let preview_images_uid = null;    // remote images being fetched for this email
let preview_frame_expanded = false;

// Base stylesheet injected into the sandboxed document. The email is drawn on
// white whatever theme the console is in, because "as delivered" means as the
// recipient saw it and every mail client on earth is white here. The rest gives
// the sanitizer's marks something to look like.
const PREVIEW_FRAME_CSS = [
	"html{background:#fff}",
	"body{margin:0;padding:18px;background:#fff;color:#16181d;",
	"font:14px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;",
	"word-break:break-word;overflow-wrap:anywhere}",
	"img{max-width:100%;height:auto}",
	"table{max-width:100%}",
	/* Links do not navigate, so they must not look like they would */
	"a{color:#0b57d0;text-decoration:underline;cursor:default}",
	/* The destination, printed next to the text.
	 *
	 * It carries its own background and its own colour rather than inheriting:
	 * the sender chose what is behind it, and the first version of this put dark
	 * red text on a red call-to-action button, which is the one place in the
	 * message where reading the real URL matters most. inline-block also keeps
	 * the parent's underline and weight from bleeding into it. */
	".bp-link::after{content:attr(data-url);display:inline-block;margin-left:5px;",
	"padding:1px 5px;border-radius:3px;background:#fff;border:1px solid #d7dae0;",
	"font:400 11px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#3c4043;",
	"text-decoration:none;word-break:break-all;max-width:100%;vertical-align:middle}",
	/* The text names one site and the destination is another */
	".bp-mismatch{background:#fdecea;box-shadow:0 0 0 1px #e8a5a0;border-radius:3px}",
	".bp-mismatch::after{background:#fff;border-color:#dd8e86;color:#a8342a;font-weight:600}",
	/* O que fica no lugar de uma imagem que não pôde ser trazida. Diz o host e o
	 * motivo em vez de deixar um buraco: um retângulo vazio não se distingue de
	 * um e-mail que não tinha imagem nenhuma ali */
	".bp-blocked,.bp-missing{display:inline-block;padding:5px 9px;border-radius:5px;",
	"border:1px dashed #b9bec7;background:#f3f4f6;color:#5f6368;",
	"font:11px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;max-width:100%}",
	".bp-blocked::before{content:'imagem remota não carregada · '}",
	".bp-missing{border-style:dotted}"
].join("");

function open_queue_item(uid){
	queue_selected = uid;
	let mail = queue.filter(function(m){ return m.mailUID === uid; })[0];
	render_queue();
	if (!mail){ return; }

	// Opening another email starts on text again. Carrying the previous choice
	// over would open the next report already showing an attacker's layout,
	// which is a thing to ask for, not a thing to land in
	reset_preview_visual();
	render_preview(mail);

	// Two reasons to ask the server for the body. The loader has not reached this
	// email yet, so the row is an envelope — the click fetches it ahead of the
	// loader. Or the push carried a snippet, which is what every row carries —
	// the whole text is served from the server's cache, so this one is instant.
	// Either way the preview says it is working rather than showing an empty or
	// shortened body that looks like the email itself.
	if (mail.bodyLoaded === false || mail.bodyTruncated){
		load_queue_item_body(uid);
	}
}

/* Fetch the body of one listed email.
 *
 * GET /email/<uid> peeks: the message stays unread and stays in the queue, so
 * reading an email is not the same act as analyzing it. The answer is folded
 * back into the queue so a second click is free, and dropped outright if the
 * analyst has moved on in the meantime. */
function load_queue_item_body(uid){
	inbox_loading_uid = uid;
	set_preview_loading(true);

	get_json("email/" + encodeURIComponent(uid)).then(function(entry){
		if (inbox_loading_uid !== uid){ return; }
		inbox_loading_uid = null;
		set_preview_loading(false);

		if (entry == null){
			// Either the mailbox could not be read or the email is no longer
			// there — analyzed by somebody else, or moved out of the folder
			$("previewBody").textContent =
				"Não foi possível carregar o conteúdo deste e-mail. Ele pode já ter sido analisado por outra pessoa, "
				+ "ou saído da caixa monitorada. Clique em Atualizar para reler a caixa.";
			toast("Não foi possível carregar o conteúdo deste e-mail.", "bad");
			return;
		}

		let index = queue.findIndex(function(m){ return m.mailUID === uid; });
		if (index !== -1){
			entry.layout = queue[index].layout;
			queue[index] = entry;
		}
		queue_full[uid] = entry;
		render_queue();
		if (queue_selected === uid){ render_preview(entry); }
	});
}

function set_preview_loading(loading){
	show($("previewBodyProgress"), loading);
	if (loading){
		$("previewBody").textContent = "Carregando o conteúdo do e-mail…";
	}
}

function reset_preview_visual(){
	preview_mode = "text";
	preview_rendered = null;
	preview_rendering_uid = null;
	preview_images_uid = null;
	preview_frame_expanded = false;
	$("previewFrame").removeAttribute("srcdoc");
	$("previewFrameShell").classList.remove("expanded");
	$("previewExpandBtn").textContent = "Expandir";
	render_preview_mode();
}

function set_preview_mode(mode){
	preview_mode = mode === "visual" ? "visual" : "text";
	render_preview_mode();
	if (preview_mode === "visual" && preview_rendered === null && queue_selected !== null){
		load_preview_rendered(queue_selected);
	}
}

function render_preview_mode(){
	let visual = preview_mode === "visual";
	for (let tab of $$("#previewModes .tab")){
		let on = tab.dataset.arg === preview_mode;
		tab.classList.toggle("active", on);
		tab.setAttribute("aria-selected", on ? "true" : "false");
	}
	show($("previewBody"), !visual);
	show($("previewVisual"), visual);
}

/* Fetch the "as delivered" view of one email.
 *
 * Costs a peek, like loading a body does, and for the same reason leaves the
 * message unread: looking at how an email was laid out is still not analyzing
 * it. Dropped outright if the analyst has moved on — a render arriving for an
 * email nobody is looking at must never land on top of the one they are. */
function load_preview_rendered(uid){
	preview_rendering_uid = uid;
	show($("previewVisualProgress"), true);
	show($("previewFrameShell"), false);
	show($("previewInert"), false);
	show($("previewVisualSource"), false);
	show($("previewAttachments"), false);
	show($("previewVisualEmpty"), false);

	get_json("email-rendered/" + encodeURIComponent(uid)).then(function(payload){
		if (preview_rendering_uid !== uid || queue_selected !== uid){ return; }
		preview_rendering_uid = null;
		show($("previewVisualProgress"), false);

		if (payload == null){
			show($("previewVisualEmpty"), true);
			$("previewVisualEmpty").textContent =
				"Não foi possível montar esta visualização. O e-mail pode já ter sido analisado por outra pessoa, "
				+ "ou saído da caixa monitorada. O conteúdo em texto continua acima, na aba Texto.";
			return;
		}
		preview_rendered = payload;
		render_preview_visual(payload);
		// Laid out in the background, where nothing is fetched on the email's
		// behalf. The layout is on screen already; the remote images are fetched
		// now, because somebody actually opened this view
		if (payload.imagesDeferred){ load_preview_images(uid); }
	});
}

/* The remote images of a layout that is already on screen.
 *
 * The background loader lays every email out without them: a tracking pixel
 * fetched for an email nobody opened tells its sender the mailbox is read, for
 * every message in it. So the images cost the click, and the analyst reads the
 * layout while the server fetches them — under the same guard chain and the same
 * deadline as always (§7.11). */
function load_preview_images(uid){
	preview_images_uid = uid;
	get_json("email-rendered/" + encodeURIComponent(uid) + "?images=1").then(function(payload){
		if (preview_images_uid !== uid || queue_selected !== uid){ return; }
		preview_images_uid = null;
		if (payload == null){
			if (preview_rendered){
				preview_rendered.imagesDeferred = false;
				preview_rendered.imagesFailed = true;
				render_preview_inert(preview_rendered);
			}
			return;
		}
		preview_rendered = payload;
		render_preview_visual(payload);
		let index = queue.findIndex(function(m){ return m.mailUID === uid; });
		if (index !== -1){ queue[index].layout = "full"; }
	});
}

function render_preview_visual(payload){
	// Which of the two messages this is. On a forwarded report there is the note
	// somebody wrote and the email they were reporting, and reading the wrong
	// one looks exactly like reading the right one
	let note = $("previewVisualSource");
	note.textContent = payload.source === "attachment"
		? "Este é o e-mail denunciado, anexado à mensagem — não o bilhete de quem denunciou."
		: "Esta é a própria mensagem recebida na caixa monitorada.";
	show(note, true);

	render_preview_inert(payload);

	if (payload.html){
		let frame = $("previewFrame");
		// srcdoc rather than a src: the document has no origin of its own to be
		// fetched from, inherits this page's CSP, and never touches the network.
		// Assigned as a property — an attribute would be markup an attacker's
		// content is being written into
		frame.srcdoc = "<!doctype html><html><head><meta charset=\"utf-8\">"
			+ "<style>" + PREVIEW_FRAME_CSS + "</style></head><body>"
			+ payload.html + "</body></html>";
		show($("previewFrameShell"), true);
		show($("previewVisualEmpty"), false);
	} else {
		show($("previewFrameShell"), false);
		show($("previewVisualEmpty"), true);
		// No HTML part is a fact about the message, not a failure of this screen
		$("previewVisualEmpty").textContent = payload.error
			? "Não foi possível interpretar a estrutura deste e-mail. O conteúdo em texto continua na aba Texto."
			: "Este e-mail não traz uma versão formatada — foi enviado só em texto. É exatamente o que a aba Texto mostra.";
	}

	render_preview_attachments(payload.attachments || []);
}

/* De onde veio o que está sendo exibido, e o que continua desligado.
 *
 * Não é alerta: este é o estado normal de todo e-mail desta tela, e uma tarja
 * vermelha em todos eles vira ruído antes do fim do primeiro turno. É uma
 * afirmação de fato, no mesmo registro do resto da tela — e não é opcional,
 * porque quem decide olhando para uma diagramação precisa saber quem a montou.
 *
 * As duas coisas que essa linha tem de deixar claras:
 *
 *   1. **Quem buscou.** A imagem foi baixada pelo servidor, não pelo navegador
 *      do analista. A diferença é a estação de trabalho não aparecer no log de
 *      quem mandou o phishing.
 *   2. **De onde.** O host de uma imagem costuma ser a única infraestrutura do
 *      remetente que aparece na mensagem inteira — é anotação de caso, não
 *      detalhe técnico.
 */
function render_preview_inert(payload, strip){
	strip = strip || $("previewInert");
	strip.replaceChildren();

	let facts = [];

	if (payload.fetchedCount > 0){
		facts.push(payload.fetchedCount + " imagem(ns) baixada(s) pelo servidor — não pelo seu navegador — de "
			+ host_list(payload.fetchedHosts));
	}
	if (payload.inlineCount > 0){
		facts.push(payload.inlineCount + " imagem(ns) embutida(s) na própria mensagem");
	}
	// Aqui "não carregada" cobre três coisas diferentes, e o motivo de cada uma
	// fica no lugar da imagem: a trava recusou o endereço, o host não respondeu,
	// ou o arquivo passou do limite
	if (payload.blockedCount > 0 && payload.imagesDeferred){
		// Not a refusal: this layout was built in the background, where nothing is
		// fetched, and the fetch has started because the view was opened
		facts.push(payload.blockedCount + " imagem(ns) remota(s) de " + host_list(payload.blockedHosts)
			+ " — sendo buscada(s) pelo servidor agora");
	} else if (payload.blockedCount > 0 && payload.imagesFailed){
		facts.push(payload.blockedCount + " imagem(ns) remota(s) de " + host_list(payload.blockedHosts)
			+ " não puderam ser buscadas agora — abra o e-mail de novo para tentar");
	} else if (payload.blockedCount > 0){
		facts.push(payload.blockedCount + " não carregada(s) de " + host_list(payload.blockedHosts)
			+ " — o motivo aparece no lugar de cada uma");
	}
	facts.push("links desativados — o destino de cada um aparece ao lado do texto");
	if ((payload.truncated || []).length > 0){
		facts.push("conteúdo cortado por limite de tamanho (" + payload.truncated.join(", ") + ")");
	}

	strip.appendChild(icon(SHIELD_ICON, 13));
	strip.appendChild(el("span", {className: "grow", text: facts.join(" · ")}));
	show(strip, true);
}

// Os primeiros hosts de uma lista, com o resto contado. Quatro cabem numa linha;
// uma newsletter com quinze CDNs não vira um parágrafo por causa disso.
function host_list(hosts){
	let names = (hosts || []).slice(0, 4).map(function(h){ return h.host; });
	let extra = (hosts || []).length - names.length;
	return names.join(", ") + (extra > 0 ? " e mais " + extra : "");
}

function render_preview_attachments(list, box){
	box = box || $("previewAttachments");
	box.replaceChildren();
	if (list.length === 0){
		show(box, false);
		return;
	}

	box.appendChild(el("span", {className: "field-label", text: "ANEXOS (" + list.length + ")"}));
	for (let item of list){
		// Declared type next to the type read off the content. A .pdf that is
		// really a DOS executable is not a detail, it is the finding — and it
		// only shows up when the two sit side by side
		let mismatch = item.realType && item.declaredType
			&& item.realType !== item.declaredType;

		let rows = [
			el("div", {className: "row", style: "gap:8px"}, [
				el("span", {className: "att-name truncate grow", title: item.name, text: item.name}),
				el("span", {className: "att-size mono", text: format_bytes(item.size)})
			]),
			el("div", {className: "att-type mono" + (mismatch ? " mismatch" : "")}, [
				el("span", {text: item.realType || "tipo desconhecido"}),
				el("span", {className: "att-declared", text: mismatch
					? " · declarado como " + item.declaredType
					: ""})
			])
		];
		if (item.sha256){
			// The artifact. Copyable, because it is going straight into another
			// tool — and the file itself never leaves the container for exactly
			// the same reason this line is enough
			let hash = el("span", {className: "att-hash mono truncate grow", title: item.sha256, text: item.sha256});
			let copy = el("button", {className: "btn xs secondary", type: "button", text: "Copiar"});
			copy.onclick = function(){ copy_to_clipboard(item.sha256, "SHA-256 copiado."); };
			rows.push(el("div", {className: "row", style: "gap:8px"}, [hash, copy]));
		} else {
			rows.push(el("span", {className: "absent", text: "SHA-256 não calculado — anexo acima do limite de tamanho"}));
		}
		box.appendChild(el("div", {className: "att-row"}, rows));
	}
	show(box, true);
}

/* The frame opens at a height that shows the top of the email and leaves the
 * rest of the screen usable; a long newsletter needs the whole pane. The height
 * is fixed rather than fitted to the content because the document is sandboxed
 * without same-origin, so nothing here can measure it — and asking for
 * `allow-same-origin` to save a click would hand the attacker's markup this
 * page's origin. */
function toggle_preview_frame(){
	preview_frame_expanded = !preview_frame_expanded;
	$("previewFrameShell").classList.toggle("expanded", preview_frame_expanded);
	$("previewExpandBtn").textContent = preview_frame_expanded ? "Recolher" : "Expandir";
}

function format_bytes(size){
	if (!size && size !== 0){ return "—"; }
	if (size < 1024){ return size + " B"; }
	if (size < 1024 * 1024){ return (size / 1024).toFixed(1) + " KB"; }
	return (size / (1024 * 1024)).toFixed(1) + " MB";
}

/* Fill the preview from a queue entry, downloaded or not.
 *
 * The fields that are only known once the message has been read (its type and
 * the subject of the report attached to it) say they are still coming instead
 * of showing a dash: "not yet" and "empty" must never look the same. */
function render_preview(mail){
	let loaded = mail.bodyLoaded !== false;
	let pending = "carregando…";

	$("detailTitle").textContent = mail.subject || "(sem assunto)";
	$("detailSub").textContent = "não analisado · denunciado em " + (full_date(mail) || "data desconhecida")
		+ " · UID " + mail.mailUID;
	show($("inboxIntro"), false);
	show($("analyzeOneBtn"), true);

	/* Two shapes of field, because these are two shapes of data.
	 *
	 * An address and a subject are long, and they are what the triage decision
	 * is actually made on — a domain cut off at the ellipsis is the difference
	 * between bradesco.com.br and bradesco.com.br.seguro.tk. They take the whole
	 * row and wrap. A timestamp, a type and a UID are short and fixed, and they
	 * share one. Giving all five the same column was giving "UID 4127" the same
	 * space as the sender, and truncating the sender to afford it. */
	let fields = [
		["DE", mail.from, true],
		["ASSUNTO DO E-MAIL A ANALISAR", loaded ? mail.attachedMail : pending, true],
		["HORÁRIO DA DENÚNCIA", full_date(mail), false],
		["TIPO", loaded ? (mail.email_type || "Raw Email") : pending, false],
		["UID", mail.mailUID, false]
	];
	let grid = $("previewFields");
	grid.replaceChildren();
	for (let [label, value, wide] of fields){
		grid.appendChild(el("div", {className: wide ? "kv wide" : "kv"}, [
			el("span", {className: "kv-key", text: label}),
			el("span", {
				className: wide ? "kv-val" : "kv-val truncate",
				title: value || "",
				text: value || "—"
			})
		]));
	}
	render_preview_auth(mail);
	show($("previewHeaderCard"), true);

	show($("previewBodyCard"), true);
	if (loaded){
		show($("previewBodyProgress"), false);
		$("previewBody").textContent = mail.body || "(sem corpo)";
	}
}

/* SPF / DKIM / DMARC strip on the unanalyzed preview.
 *
 * GET /list returns the envelope only; the authentication results are parsed
 * from the attached .eml by case_from_email during the run. So the strip is
 * built when the listing happens to carry them and otherwise says why it is
 * empty — "not yet" and "all passed" must never look the same. */
const AUTH_TONE = {pass: "pass", fail: "fail", softfail: "warn", none: "warn", neutral: "warn"};

function render_preview_auth(mail){
	let strip = $("previewAuth");
	strip.replaceChildren();
	let results = mail.authentication || null;

	if (!results){
		strip.appendChild(el("span", {
			className: "empty-note",
			text: "SPF, DKIM e DMARC são lidos do .eml durante a análise. Rode o scan para vê-los."
		}));
		return;
	}

	for (let key of ["spf", "dkim", "dmarc"]){
		let raw = String(results[key] || "").toLowerCase();
		strip.appendChild(el("div", {className: "pair"}, [
			el("span", {text: key.toUpperCase()}),
			el("span", {
				className: "auth-pill " + (AUTH_TONE[raw] || ""),
				text: (results[key] || "—").toUpperCase()
			})
		]));
	}
}

function reset_run_panel(title){
	show($("runCard"), true);
	$("runTitle").textContent = title;
	$("runVerdict").textContent = "";
	$("runVerdict").className = "pill";
	$("runSummary").textContent = "";
	$("logText").replaceChildren();
	show($("logConsole"), true);
	show($("runProgress"), true);
}

function finish_run_panel(title, summary, tone, verdict_label){
	$("runTitle").textContent = title;
	$("runSummary").textContent = summary;
	show($("runProgress"), false);
	if (verdict_label){
		$("runVerdict").textContent = verdict_label;
		$("runVerdict").className = "pill " + (tone || "");
	}
}

/* Live mailbox — the server rereads the monitored mailbox on a fixed interval
 * and pushes the listing here, so a report that arrived a minute ago is on the
 * screen without anybody pressing "Atualizar".
 *
 * The push replaces the queue but never the analyst's place in it: what is
 * ticked and what is open survive, minus anything that has since left the
 * mailbox. Losing a selection to a background refresh would make the screen
 * unusable exactly when it is busiest. */
function apply_inbox_snapshot(state){
	let emails = state.emails || [];
	let present = {};
	for (let mail of emails){ present[mail.mailUID] = mail; }

	// A full body fetched for an email outlives the snippet the push carries in
	// its place — as long as the arrival time still says it is the same message
	for (let uid of Object.keys(queue_full)){
		let listed = present[uid];
		if (!listed || listed.receivedAt !== queue_full[uid].receivedAt){ delete queue_full[uid]; }
	}
	queue = emails.map(function(mail){
		let full = queue_full[mail.mailUID];
		return full ? Object.assign({}, full, {layout: mail.layout}) : mail;
	});
	queue_listed = true;
	queue_checked = queue_checked.filter(function(uid){ return present[uid]; });
	if (queue_selected && !present[queue_selected]){ queue_selected = null; }
	// The order the SERVER built this listing in — not what the analyst asked to
	// see. render_queue() reconciles the two. Overwriting the preference here is
	// what used to make a click on the filter snap back when a poll tick landed
	queue_order = state.order === "oldest" ? "oldest" : "newest";

	// A new page size keeps the analyst on the page holding the first row they
	// were looking at, rather than on the same page number of a different slicing
	let size = parseInt(state.pageSize, 10);
	if (INBOX_PAGE_SIZES.indexOf(size) !== -1 && size !== inbox_page_size){
		inbox_page = Math.floor(((inbox_page - 1) * inbox_page_size) / size) + 1;
		inbox_page_size = size;
	}
	if (state.loader){ inbox_loader_state = state.loader; }
	render_queue();
	render_phish_inbox_subjects();

	// The open preview follows the refreshed entry: a tick that arrives while an
	// email is open must not leave the panel showing a body the list no longer
	// carries — and it is also how a body loaded server-side lands on screen
	if (queue_selected){
		let open_mail = queue.filter(function(m){ return m.mailUID === queue_selected; })[0];
		if (open_mail && inbox_loading_uid !== queue_selected && !open_mail.bodyTruncated){
			render_preview(open_mail);
		}
	}
}

function update_inbox_poll_status(state){
	let node = $("inboxPollStatus");
	if (!node){ return; }
	let clock = state.at ? new Date(state.at).toLocaleTimeString("pt-BR", {hour: "2-digit", minute: "2-digit", second: "2-digit"}) : "—";
	if (!state.enabled){
		node.textContent = "consulta automática desligada · última leitura às " + clock;
	} else if (state.result){
		node.textContent = "última consulta " + clock + " · " + state.result;
	} else {
		node.textContent = "consultando a cada " + state.intervalSeconds + "s · última às " + clock;
	}
	render_inbox_limit(state);
}

/* The mailbox holds more than one listing can enumerate.
 *
 * The queue is no longer capped at what fits in a download — every unread email
 * is listed, and the background loader fills the bodies in. What is left to
 * warn about is the far rarer case of a mailbox so large that even the envelopes
 * did not fit. Said under the list rather than in a toast because it is a
 * statement about what the list is showing, and about what it is not: a toast
 * would scroll away and leave a truncated queue looking like the whole mailbox,
 * which is how a report sits unseen for a week. */
function render_inbox_limit(state){
	let box = $("inboxLimit");
	if (!box){ return; }
	let behind = Math.max(0, (state.total || 0) - (state.count || 0));
	show(box, behind > 0);
	if (behind === 0){ return; }

	$("inboxLimitTitle").textContent = "A caixa tem mais denúncias do que esta lista";
	$("inboxLimitText").textContent =
		(state.totalExact ? behind + " denúncia(s) não aparecem nesta lista. " : "Há mais denúncias fora desta lista. ")
		+ "Analise as que estão na fila para que as próximas entrem, ou troque a ordem para começar pelo outro extremo da caixa.";
}

socket.on("inbox", function(state){
	if (!state){ return; }
	// A failed cycle keeps the last good listing on screen and says so in the
	// status line: blanking the queue because one IMAP call timed out would throw
	// away work the analyst can still act on
	if (state.emails){ apply_inbox_snapshot(state); }
	update_inbox_poll_status(state);
});

/* The background loader finished a batch.
 *
 * The event carries only the emails that just became ready, not the queue: the
 * loader works through a mailbox ten messages at a time, and resending thousands
 * of envelopes after every batch would cost more than the work it reports. A row
 * is only replaced while its arrival time still matches — the listing may have
 * moved on while the batch was being read. */
socket.on("inboxProgress", function(update){
	if (!update){ return; }
	if (update.loader){ inbox_loader_state = update.loader; }
	let changed = false;
	for (let entry of (update.emails || [])){
		let index = queue.findIndex(function(m){ return m.mailUID === entry.mailUID; });
		if (index === -1 || queue[index].receivedAt !== entry.receivedAt){ continue; }
		let full = queue_full[entry.mailUID];
		queue[index] = full ? Object.assign({}, full, {layout: entry.layout}) : entry;
		changed = true;
	}
	if (changed){ render_queue(); render_phish_inbox_subjects(); } else { render_inbox_loader(); }
});

/* GET /list — read the mailbox now, whatever the poll is doing.
 *
 * It answers the same envelope the poll pushes, and re-decides the ceiling
 * server-side, so this button is also the way out of a queue that paused while
 * the backlog was cleared somewhere else. */
function list_emails(){
	set_list_button(true);
	inbox_loading_uid = null;
	$("inboxCount").textContent = "buscando e-mails…";
	get_json("list").then(function(state){
		set_list_button(false);
		if (state == null){
			$("inboxCount").textContent = "falha ao buscar os e-mails";
			toast("Não foi possível buscar os e-mails. Verifique as configurações da caixa monitorada.", "bad");
			return;
		}
		queue_checked = [];
		queue_selected = null;
		apply_inbox_snapshot(state);
		update_inbox_poll_status(state);
		if ((state.emails || []).length === 0){
			toast("Nenhum e-mail novo para analisar.");
		}
	});
}

// POST /analysis — analyze the email currently open in the preview
function analyze_current(){
	if (!queue_selected){ return; }
	let uid = queue_selected;
	reset_run_panel("Analisando o e-mail UID " + uid + "…");
	$("analyzeOneBtn").disabled = true;

	post_form("analysis", {sid: socket.id, mailUID: uid}).then(function(result){
		$("analyzeOneBtn").disabled = false;
		let response = result.ok ? result.data : null;
		if (response == null){
			// The server says why when it refuses before analyzing: no UID, or an
			// email that already left the queue
			let reason = (result.data && result.data.error) || "Ocorreu um erro durante a análise. Consulte o log acima.";
			finish_run_panel("Falha na análise", reason, "bad");
			toast("A análise falhou.", "bad");
			if (result.status === 404){ drop_from_queue([uid]); }
			return;
		}
		let verdict = response.verdict;
		let summary = verdict_summary(verdict);
		if (response.llmAnalysis){
			summary += "\n\nEngenharia social (LLM) — risco "
				+ response.llmAnalysis.risk_level.toUpperCase() + ": "
				+ response.llmAnalysis.justification;
		}
		finish_run_panel("Análise concluída", summary, VERDICT_TONE[verdict], VERDICT_LABEL[verdict] || verdict);
		drop_from_queue([uid]);
	});
}

function verdict_summary(verdict){
	if (verdict === "Safe"){
		return "O e-mail foi classificado como SEGURO. O caso foi encerrado e a resposta ao denunciante foi enviada.";
	}
	if (verdict === "Malicious"){
		return "O e-mail foi classificado como MALICIOSO. O caso foi encerrado, exportado para o MISP e a resposta ao denunciante foi enviada.";
	}
	if (verdict === "Suspicious"){
		return "O e-mail foi classificado como SUSPEITO. O caso ficou aberto para investigação — revise o resultado registrado antes de dar o veredito final.";
	}
	return "Veredito não reconhecido: " + verdict;
}

// POST /analysis-selected — batch scan of every ticked email
function analyze_selected(){
	if (queue_checked.length === 0){ return; }
	if (queue_checked.length > BATCH_SCAN_MAX){
		toast("Um scan roda no máximo " + BATCH_SCAN_MAX + " e-mails por vez. Desmarque alguns e rode de novo.", "bad");
		return;
	}
	let uids = queue_checked.slice();
	reset_run_panel("Analisando " + uids.length + " e-mail(s)…");
	$("runScanBtn").disabled = true;
	show($("inboxIntro"), false);

	post_form("analysis-selected", {sid: socket.id, mailUIDs: JSON.stringify(uids)}).then(function(result){
		$("runScanBtn").disabled = false;
		let response = result.ok ? result.data : null;
		if (response == null){
			finish_run_panel("Falha no scan", "Ocorreu um erro durante o lote. Consulte o log acima.", "bad");
			toast("O scan falhou.", "bad");
			return;
		}
		let lines = [response.analyzed + " analisado(s), " + response.failed + " erro(s)."];
		for (let item of response.results){
			lines.push("UID " + item.mailUID + ": " + (VERDICT_LABEL[item.verdict] || item.verdict || item.error || "ERRO"));
		}
		finish_run_panel("Scan concluído", lines.join("\n"),
			response.failed === 0 ? "ok" : "warn",
			response.failed === 0 ? "OK" : "PARCIAL");
		drop_from_queue(uids);
	});
}

// An analyzed email is no longer pending, so it leaves the queue
function drop_from_queue(uids){
	queue = queue.filter(function(m){ return uids.indexOf(m.mailUID) === -1; });
	queue_checked = queue_checked.filter(function(uid){ return uids.indexOf(uid) === -1; });
	if (uids.indexOf(queue_selected) !== -1){
		queue_selected = null;
		// An in-flight body for an email that has just been analyzed has nowhere
		// left to land, and its answer must not reopen the panel
		inbox_loading_uid = null;
		show($("previewBodyProgress"), false);
		show($("previewHeaderCard"), false);
		show($("previewBodyCard"), false);
		show($("analyzeOneBtn"), false);
		// Drops the rendered document with it: leaving an analyzed email's
		// markup loaded in the frame would keep it on screen behind a hidden
		// card, and it is the one thing here nobody wrote
		reset_preview_visual();
		$("detailTitle").textContent = "Nenhum e-mail aberto";
		$("detailSub").textContent = "selecione um item da lista";
	}
	render_queue();
}

/* ========================================================================== */
/* Settings — automatic analysis                                              */
/* ========================================================================== */

function update_scheduler_status(state){
	if (state == null){
		set_status("schedulerStatus", "Não foi possível carregar a configuração da análise automática.", "bad");
		return;
	}
	set_paired("schedulerInterval", "schedulerIntervalRange", state.intervalMinutes);
	set_paired("schedulerMaxPerCycle", "schedulerMaxRange", state.maxPerCycle || 10);
	set_switch("schedulerEnabled", state.enabled);

	let text;
	if (state.running){
		text = "Análise automática em andamento…";
	} else if (state.enabled){
		text = state.nextRunInSeconds != null
			? "Habilitada. Próxima execução em cerca de " + Math.max(1, Math.ceil(state.nextRunInSeconds / 60)) + " minuto(s)."
			: "Habilitada.";
	} else {
		text = "Análise automática desabilitada.";
	}
	if (state.lastRun){
		text += " Última execução: " + state.lastRun + " (" + state.lastResult + ").";
	}
	set_status("schedulerStatus", text, state.enabled ? "ok" : null);
}

function load_scheduler_config(){
	get_json("scheduler").then(update_scheduler_status);
}

function save_scheduler_config(){
	let interval_minutes = parseInt($("schedulerInterval").value, 10);
	if (isNaN(interval_minutes) || interval_minutes < 1 || interval_minutes > 1440){
		set_status("schedulerStatus", "O intervalo deve ser um número de minutos entre 1 e 1440.", "bad");
		return;
	}
	let max_per_cycle = parseInt($("schedulerMaxPerCycle").value, 10);
	if (isNaN(max_per_cycle) || max_per_cycle < 1 || max_per_cycle > 100){
		set_status("schedulerStatus", "O máximo de e-mails por ciclo deve estar entre 1 e 100.", "bad");
		return;
	}
	$("schedulerSaveBtn").disabled = true;
	post_form("scheduler", {
		intervalMinutes: interval_minutes,
		enabled: switch_on("schedulerEnabled"),
		maxPerCycle: max_per_cycle
	}).then(function(result){
		$("schedulerSaveBtn").disabled = false;
		update_scheduler_status(result.ok ? result.data : null);
		if (result.ok && result.data){ toast("Configuração salva.", "ok"); }
	});
}

/* ========================================================================== */
/* Settings — LLM                                                             */
/* ========================================================================== */

function update_prompt_chars(){
	$("promptChars").textContent = $("llmSystemPrompt").value.length + " caracteres";
}

// Infer the provider preset from a stored endpoint URL
function detect_llm_provider(endpoint){
	if (!endpoint){ return "ollama"; }
	if (endpoint.indexOf("openrouter.ai") !== -1){ return "openrouter"; }
	if (endpoint.indexOf("/api/chat") !== -1){ return "ollama"; }
	return "custom";
}

// Fill the endpoint/model fields with sensible defaults when a preset is chosen,
// so switching to OpenRouter does not require typing the URL by hand
function apply_llm_provider_preset(){
	let preset = $("llmProviderPreset").value;
	if (preset === "ollama"){
		$("llmEndpoint").value = "http://host.docker.internal:11434/api/chat";
		if ($("llmModel").value === "" || $("llmModel").value.indexOf("/") !== -1){
			$("llmModel").value = "qwen2.5:7b";
		}
	} else if (preset === "openrouter"){
		$("llmEndpoint").value = "https://openrouter.ai/api/v1/chat/completions";
		if ($("llmModel").value === "" || $("llmModel").value.indexOf("/") === -1){
			$("llmModel").value = "anthropic/claude-3.5-sonnet";
		}
	}
	// "custom" leaves the fields untouched
	refresh_llm_model_catalog();
}

function update_llm_status(state){
	if (state == null){
		set_status("llmStatus", "Não foi possível carregar a configuração da IA.", "bad");
		return;
	}
	if (document.activeElement !== $("llmEndpoint")){ $("llmEndpoint").value = state.api_endpoint; }
	if (document.activeElement !== $("llmModel")){ $("llmModel").value = state.model_name; }
	if (document.activeElement !== $("llmEscalation")){ $("llmEscalation").value = state.escalation_threshold || "Medium"; }
	if (document.activeElement !== $("llmMaliciousEscalation")){ $("llmMaliciousEscalation").value = state.malicious_escalation || "off"; }
	if (document.activeElement !== $("llmSystemPrompt")){
		$("llmSystemPrompt").value = state.system_prompt || "";
		update_prompt_chars();
	}
	if (document.activeElement !== $("llmProviderPreset")){
		$("llmProviderPreset").value = detect_llm_provider(state.api_endpoint);
	}
	if (document.activeElement !== $("llmPipelineMode")){ $("llmPipelineMode").value = state.pipeline_mode || "single"; }
	let agents = state.agents || {};
	if (document.activeElement !== $("llmAgentAnalystB")){
		$("llmAgentAnalystB").value = (agents.analyst_b || {}).model || "";
	}
	if (document.activeElement !== $("llmAgentReviewer")){
		$("llmAgentReviewer").value = (agents.reviewer || {}).model || "";
	}
	update_pipeline_note();
	load_llm_model_catalog();
	// The API key is never sent back by the server: an empty field means "keep the saved one"
	$("llmApiKey").placeholder = state.hasApiKey ? "•••••••• (salva — deixe vazio para manter)" : "não exigida em host local";
	set_switch("llmEnabled", state.enabled);

	if (state.enabled){
		let text = "Análise de engenharia social habilitada com o modelo " + state.model_name
			+ ". Vereditos seguros escalam para suspeito a partir do risco " + (state.escalation_threshold || "Medium") + ".";
		if (state.malicious_escalation && state.malicious_escalation !== "off"){
			text += " A IA sozinha marca malicioso a partir do risco " + state.malicious_escalation + ".";
		}
		text += " Se o endpoint estiver inacessível, a análise de links e anexos continua normalmente.";
		set_status("llmStatus", text, "ok");
	} else {
		set_status("llmStatus", "Análise de engenharia social desabilitada.");
	}
}

/* What each pipeline costs and what it buys, said on the screen rather than only
 * in the docs. The cost is the part that surprises people: on a local GPU every
 * extra agent is another full model round trip per e-mail. */
const PIPELINE_NOTE = {
	single: "Uma chamada de modelo por e-mail. Nenhuma revisão: a avaliação vai direto para o veredito.",
	review: "Duas chamadas por e-mail. O revisor só pode reter confiança, nunca concedê-la — "
		+ "\u0022seguir\u0022 não muda nada, e reter bloqueia o escalonamento autônomo para malicioso.",
	debate: "Até três chamadas por e-mail (os dois analistas rodam em paralelo). Uma rodada de "
		+ "réplica, limitada a subir o risco: um modelo pode ser convencido de que o e-mail é pior "
		+ "do que julgou, nunca de que é melhor. Discordância manda o caso para revisão humana."
};

function update_pipeline_note(){
	let mode = $("llmPipelineMode").value;
	$("llmPipelineNote").textContent = PIPELINE_NOTE[mode] || "";
	let uses_agents = mode === "debate";
	$("llmAgentAnalystB").disabled = !uses_agents;
	$("llmAgentReviewer").disabled = mode === "single";
}

function load_llm_config(){
	get_json("llm-config").then(update_llm_status);
}

function save_llm_config(){
	let api_endpoint = $("llmEndpoint").value.trim();
	let model_name = $("llmModel").value.trim();
	let enabled = switch_on("llmEnabled");
	if (enabled && !(api_endpoint.startsWith("http://") || api_endpoint.startsWith("https://"))){
		set_status("llmStatus", "O endpoint deve ser uma URL http:// ou https://.", "bad");
		return;
	}
	if (enabled && model_name.length === 0){
		set_status("llmStatus", "O nome do modelo não pode ficar vazio.", "bad");
		return;
	}
	// A hosted provider (OpenRouter) needs an API key: warn if none is set and none is stored
	if (enabled && $("llmProviderPreset").value === "openrouter"
		&& $("llmApiKey").value.length === 0 && $("llmApiKey").placeholder.indexOf("salva") === -1){
		set_status("llmStatus", "O OpenRouter exige uma chave de API.", "bad");
		return;
	}
	$("llmSaveBtn").disabled = true;
	post_form("llm-config", {
		api_endpoint: api_endpoint,
		model_name: model_name,
		api_key: $("llmApiKey").value,
		enabled: enabled,
		escalation_threshold: $("llmEscalation").value,
		malicious_escalation: $("llmMaliciousEscalation").value,
		system_prompt: $("llmSystemPrompt").value.trim(),
		pipeline_mode: $("llmPipelineMode").value,
		agent_analyst_b: $("llmAgentAnalystB").value.trim(),
		agent_reviewer: $("llmAgentReviewer").value.trim()
	}).then(function(result){
		$("llmSaveBtn").disabled = false;
		if (result.ok && result.data){
			// Clear the key field: the saved key is now represented by the placeholder
			$("llmApiKey").value = "";
			update_llm_status(result.data);
			toast("Configuração salva.", "ok");
		} else {
			update_llm_status(null);
		}
	});
}

/* ========================================================================== */
/* Settings — LLM model picker                                                */
/* ========================================================================== */

/* The model fields open a picker instead of taking a typed name. The catalog
 * comes from POST /llm-models, which asks the provider on the server — the API
 * key never passes through here — and says per model whether it accepts an
 * image or a file. `null` there means the provider did not say, and the screen
 * says exactly that instead of guessing. A name the provider does not list can
 * still be used: type it in the search and press Enter. */

const MODEL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:\/-]*$/;

let llm_model_catalog = {endpoint: null, key_typed: false, data: null, pending: null};
let llm_model_target = null;

// Trusted, static brand marks (24x24). Owners without one get a monogram.
const MODEL_OWNER_MARKS = {
	anthropic: {color: "#D97757", path: "M17.304 3.541h-3.672l6.696 16.918H24Zm-10.608 0L0 20.459h3.744l1.37-3.553h7.005l1.369 3.553h3.744L10.536 3.541Zm-.371 10.223 2.291-5.945 2.292 5.945Z"},
	openai: {color: "#10A37F", path: "M22.282 9.821a5.985 5.985 0 0 0-.516-4.911 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.182a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073zM13.26 22.43a4.476 4.476 0 0 1-2.876-1.041l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.169a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494zM3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.5 4.5 0 0 1-6.14-1.646zM2.34 7.896a4.485 4.485 0 0 1 2.366-1.973V11.6a.766.766 0 0 0 .388.677l5.815 3.354-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786A4.504 4.504 0 0 1 2.34 7.872zm16.597 3.855-5.833-3.387L15.119 7.2a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.407-.667zm2.01-3.023-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.5 4.5 0 0 1 6.68 4.66zm-12.64 4.135-2.02-1.164a.08.08 0 0 1-.038-.057V6.075a4.5 4.5 0 0 1 7.375-3.453l-.142.08L8.704 5.46a.795.795 0 0 0-.393.681zm1.097-2.365 2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5Z"},
	google: {color: "#8E6FD8", path: "M12 24A14.3 14.3 0 0 0 0 12 14.3 14.3 0 0 0 12 0a14.3 14.3 0 0 0 12 12 14.3 14.3 0 0 0-12 12"}
};
const MODEL_OWNER_MONOGRAMS = {
	deepseek: {color: "#4D6BFE", letter: "D"},
	qwen: {color: "#615CED", letter: "Q"},
	moonshotai: {color: "#16191E", letter: "K"},
	"z-ai": {color: "#2D2D2D", letter: "Z"},
	minimax: {color: "#E2167E", letter: "M"},
	"meta-llama": {color: "#0668E1", letter: "M"},
	mistralai: {color: "#FA520F", letter: "M"},
	microsoft: {color: "#0078D4", letter: "M"},
	other: {color: "#71717A", letter: "?"}
};

const MODEL_IMAGE_ICON = '<rect x="2.2" y="3" width="11.6" height="10" rx="1.6"></rect><circle cx="5.8" cy="6.4" r="1.1"></circle><path d="M13.8 10.6l-3.3-3.2-6.6 5.6"></path>';
const MODEL_FILE_ICON = '<path d="M9.4 1.8H4.6a1.4 1.4 0 0 0-1.4 1.4v9.6a1.4 1.4 0 0 0 1.4 1.4h6.8a1.4 1.4 0 0 0 1.4-1.4V5.2z"></path><path d="M9.4 1.8v3.4h3.4"></path>';

function model_owner_logo(owner){
	let mark = MODEL_OWNER_MARKS[owner];
	if (mark){
		let svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
		svg.setAttribute("width", 14);
		svg.setAttribute("height", 14);
		svg.setAttribute("viewBox", "0 0 24 24");
		svg.setAttribute("fill", mark.color);
		svg.setAttribute("aria-hidden", "true");
		svg.innerHTML = '<path d="' + mark.path + '"></path>';
		return el("span", {className: "model-logo"}, [svg]);
	}
	let mono = MODEL_OWNER_MONOGRAMS[owner] || MODEL_OWNER_MONOGRAMS.other;
	return el("span", {className: "model-logo model-logo-mono", text: mono.letter,
		style: "background:" + mono.color, attrs: {"aria-hidden": "true"}});
}

function llm_model_request_params(){
	return {api_endpoint: $("llmEndpoint").value.trim(), api_key: $("llmApiKey").value};
}

// Fetch the catalog once per endpoint (and again when a key was typed, since a
// gateway may list nothing without it). Resolves to the catalog data.
function load_llm_model_catalog(force){
	let params = llm_model_request_params();
	let key_typed = params.api_key.length > 0;
	let same = llm_model_catalog.endpoint === params.api_endpoint && llm_model_catalog.key_typed === key_typed;
	if (!force && same && llm_model_catalog.pending){ return llm_model_catalog.pending; }
	if (!force && same && llm_model_catalog.data){ return Promise.resolve(llm_model_catalog.data); }
	if (!params.api_endpoint){
		llm_model_catalog = {endpoint: "", key_typed: key_typed, data: null, pending: null};
		update_llm_model_caps();
		return Promise.resolve(null);
	}
	let request = post_form("llm-models", params).then(function(result){
		let data = result.ok && result.data ? result.data
			: {error: "Não foi possível consultar a lista de modelos."};
		// A newer request (endpoint changed meanwhile) owns the state
		if (llm_model_catalog.pending === request){
			llm_model_catalog.data = data;
			llm_model_catalog.pending = null;
			update_llm_model_caps();
		}
		return data;
	});
	llm_model_catalog = {endpoint: params.api_endpoint, key_typed: key_typed, data: null, pending: request};
	return request;
}

function refresh_llm_model_catalog(){
	load_llm_model_catalog();
}

function find_llm_model(id){
	let data = llm_model_catalog.data;
	if (!data || !data.models || !id){ return null; }
	return data.models.find(function(model){ return model.id === id; }) || null;
}

// What the chosen model accepts, as the provider reported it
function describe_llm_model_caps(id){
	let data = llm_model_catalog.data;
	if (!id || !data || !data.models){ return ""; }
	let model = find_llm_model(id);
	if (!model){ return "fora da lista do provedor — o que ele aceita não é informado"; }
	if (model.image === null && model.file === null){
		return "o provedor não informa se este modelo aceita imagem ou arquivo";
	}
	let parts = [];
	if (model.image !== null){
		parts.push(model.image ? "aceita imagem" : "não aceita imagem — as do e-mail não são enviadas a ele");
	}
	if (model.file !== null){ parts.push(model.file ? "aceita arquivo" : "não aceita arquivo"); }
	return parts.join(" · ");
}

function update_llm_model_caps(){
	for (let id of ["llmModel", "llmAgentAnalystB", "llmAgentReviewer"]){
		let hint = $(id + "Caps");
		if (hint){ hint.textContent = describe_llm_model_caps($(id).value.trim()); }
	}
}

function open_llm_model_picker(target){
	let target_id = typeof target === "string" ? target : target.getAttribute("data-arg");
	if (!$(target_id) || $(target_id).disabled){ return; }
	llm_model_target = target_id;
	$("llmModelSearch").value = "";
	open_modal("llmModelModal");
	$("llmModelSearch").focus();
	render_llm_models();
	load_llm_model_catalog().then(function(){
		if (open_modal_id === "llmModelModal"){ render_llm_models(); }
	});
}

function choose_llm_model(id){
	if (!llm_model_target){ return; }
	$(llm_model_target).value = id;
	update_llm_model_caps();
	close_modal();
	$(llm_model_target).focus();
}

function filter_llm_models(){
	render_llm_models();
}

// Enter in the search: the only match, or the typed name as-is
function use_llm_model_search(){
	let query = $("llmModelSearch").value.trim();
	if (!query){ return; }
	let data = llm_model_catalog.data;
	let matches = data && data.models ? data.models.filter(function(model){ return llm_model_matches(model, query); }) : [];
	if (matches.length === 1){ choose_llm_model(matches[0].id); return; }
	if (MODEL_NAME_RE.test(query)){ choose_llm_model(query); }
}

function llm_model_matches(model, query){
	let q = query.toLowerCase();
	return model.id.toLowerCase().indexOf(q) !== -1 || model.ownerLabel.toLowerCase().indexOf(q) !== -1;
}

function llm_model_chip(model, selected){
	let children = [model_owner_logo(model.owner), el("span", {className: "model-chip-name", text: model.name})];
	let caps = [];
	if (model.image){ caps.push(el("span", {title: "aceita imagem"}, [icon(MODEL_IMAGE_ICON, 12)])); }
	if (model.file){ caps.push(el("span", {title: "aceita arquivo"}, [icon(MODEL_FILE_ICON, 12)])); }
	if (caps.length){ children.push(el("span", {className: "model-chip-caps"}, caps)); }
	if (selected){ children.push(el("span", {className: "model-chip-check"}, [icon(CHECK_ICON, 14)])); }
	return el("button", {
		className: "model-chip" + (selected ? " selected" : ""),
		title: model.id + " — " + describe_caps_inline(model),
		attrs: {type: "button", "aria-pressed": selected ? "true" : "false"},
		onClick: function(){ choose_llm_model(model.id); }
	}, children);
}

function describe_caps_inline(model){
	if (model.image === null && model.file === null){ return "entrada além de texto não informada"; }
	return [model.image === null ? "imagem: não informado" : (model.image ? "aceita imagem" : "sem imagem"),
		model.file === null ? "arquivo: não informado" : (model.file ? "aceita arquivo" : "sem arquivo")].join(", ");
}

function llm_model_group(title, logo_owner, count, chips){
	let head = [];
	if (logo_owner){ head.push(model_owner_logo(logo_owner)); }
	head.push(el("span", {text: title}));
	if (count != null){ head.push(el("span", {className: "model-group-count", text: "· " + count})); }
	return el("div", {className: "model-group"}, [
		el("div", {className: "model-group-head"}, head),
		el("div", {className: "model-grid"}, chips)
	]);
}

function render_llm_models(){
	let box = $("llmModelGroups");
	box.textContent = "";
	let query = $("llmModelSearch").value.trim();
	let current = llm_model_target ? $(llm_model_target).value.trim() : "";
	let data = llm_model_catalog.data;
	let is_agent = llm_model_target && llm_model_target !== "llmModel";

	if (!data){
		$("llmModelSub").textContent = llm_model_catalog.pending ? "consultando o provedor…"
			: "Preencha o HOST / ENDPOINT para listar os modelos.";
		if (llm_model_catalog.pending){ return; }
	} else if (data.error){
		$("llmModelSub").textContent = "não foi possível listar os modelos";
		box.appendChild(el("p", {className: "model-empty", text: data.error + " Digite o nome exato do modelo na busca e pressione Enter."}));
	}

	if (is_agent && !query){
		box.appendChild(llm_model_group("Padrão", null, null, [el("button", {
			className: "model-chip" + (current === "" ? " selected" : ""),
			attrs: {type: "button"},
			onClick: function(){ choose_llm_model(""); }
		}, [el("span", {className: "model-chip-name", text: "mesmo modelo do analista"})].concat(
			current === "" ? [el("span", {className: "model-chip-check"}, [icon(CHECK_ICON, 14)])] : []))]));
	}

	let models = data && data.models ? data.models : [];
	if (data && data.models){
		$("llmModelSub").textContent = models.length + " modelos disponíveis, agrupados por provedor.";
	}
	let groups = [];
	let by_owner = {};
	for (let model of models){
		if (query && !llm_model_matches(model, query)){ continue; }
		if (!by_owner[model.owner]){
			by_owner[model.owner] = {label: model.ownerLabel, owner: model.owner, items: []};
			groups.push(by_owner[model.owner]);
		}
		by_owner[model.owner].items.push(model);
	}
	for (let group of groups){
		box.appendChild(llm_model_group(group.label, group.owner, group.items.length,
			group.items.map(function(model){ return llm_model_chip(model, model.id === current); })));
	}

	let exact = models.some(function(model){ return model.id === query; });
	if (query && !exact && MODEL_NAME_RE.test(query)){
		box.appendChild(llm_model_group("Nome digitado", null, null, [el("button", {
			className: "model-chip", attrs: {type: "button"},
			onClick: function(){ choose_llm_model(query); }
		}, [el("span", {className: "model-chip-name", text: "usar “" + query + "”"})])]));
	} else if (query && groups.length === 0){
		box.appendChild(el("p", {className: "model-empty", text: "Nenhum modelo corresponde à busca."}));
	}
}

/* ========================================================================== */
/* Settings — mailbox provider                                                */
/* ========================================================================== */

function select_email_tab(provider){
	let gmail = (provider === "gmail");
	$("gmailTabBtn").classList.toggle("active", gmail);
	$("m365TabBtn").classList.toggle("active", !gmail);
	show($("gmailTab"), gmail);
	show($("m365Tab"), !gmail);
}

function update_email_sync_status(state){
	if (state == null){
		set_status("emailSyncStatus", "Não foi possível carregar a configuração da caixa monitorada.", "bad");
		return;
	}
	if (document.activeElement !== $("m365TenantId")){ $("m365TenantId").value = state.m365.tenantId; }
	if (document.activeElement !== $("m365ClientId")){ $("m365ClientId").value = state.m365.clientId; }
	if (document.activeElement !== $("m365Mailbox")){ $("m365Mailbox").value = state.m365.mailbox; }
	if (document.activeElement !== $("gmailUser")){ $("gmailUser").value = state.gmail.user; }
	// The secrets are never sent back by the server: an empty field means "keep the saved one"
	$("m365ClientSecret").placeholder = state.m365.hasClientSecret ? "•••••••• (salvo — deixe vazio para manter)" : "";
	$("gmailAppPassword").placeholder = state.gmail.hasAppPassword ? "•••••••• (salva — deixe vazio para manter)" : "16 caracteres, sem espaços";
	if (document.activeElement !== $("analysisModeSelect")){
		$("analysisModeSelect").value = state.analysisMode || "attachment";
	}

	let mode_label = (state.analysisMode === "raw") ? "e-mail bruto" : ".eml anexado";
	let gmail = (state.provider === "gmail");
	select_email_tab(gmail ? "gmail" : "m365");

	let mailbox = gmail ? state.gmail.user : state.m365.mailbox;
	let provider_label = gmail ? "Gmail (IMAP)" : "Microsoft 365 (Graph API)";
	set_status("emailSyncStatus", "Provedor ativo: " + provider_label + (mailbox ? " — " + mailbox : "") + " · modo: " + mode_label);
}

function load_email_config(){
	get_json("email-config").then(update_email_sync_status);
}

// The provider that gets saved is the one of the currently selected tab
function save_email_config(){
	let provider = $("gmailTabBtn").classList.contains("active") ? "gmail" : "m365";
	let params = {provider: provider, analysisMode: $("analysisModeSelect").value};

	if (provider === "m365"){
		let tenant_id = $("m365TenantId").value.trim();
		let client_id = $("m365ClientId").value.trim();
		let mailbox = $("m365Mailbox").value.trim();
		if (!tenant_id || !client_id || !mailbox){
			set_status("emailSyncStatus", "Tenant ID, Client ID e caixa são obrigatórios.", "bad");
			return;
		}
		if ($("m365ClientSecret").value.length === 0 && $("m365ClientSecret").placeholder === ""){
			set_status("emailSyncStatus", "O Client Secret é obrigatório.", "bad");
			return;
		}
		params.tenantId = tenant_id;
		params.clientId = client_id;
		params.clientSecret = $("m365ClientSecret").value;
		params.mailbox = mailbox;
	} else {
		let gmail_user = $("gmailUser").value.trim();
		if (!gmail_user){
			set_status("emailSyncStatus", "O endereço do Gmail é obrigatório.", "bad");
			return;
		}
		if ($("gmailAppPassword").value.length === 0 && $("gmailAppPassword").placeholder.indexOf("salva") === -1){
			set_status("emailSyncStatus", "A senha de app é obrigatória.", "bad");
			return;
		}
		params.gmailUser = gmail_user;
		params.gmailAppPassword = $("gmailAppPassword").value;
	}

	$("emailSyncSaveBtn").disabled = true;
	post_form("email-config", params).then(function(result){
		$("emailSyncSaveBtn").disabled = false;
		if (result.ok && result.data){
			// Clear the secret fields: the saved secret is now the placeholder
			$("m365ClientSecret").value = "";
			$("gmailAppPassword").value = "";
			update_email_sync_status(result.data);
			toast("Configuração salva.", "ok");
		} else {
			set_status("emailSyncStatus", "Configuração inválida: revise os campos e tente de novo.", "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — helpers compartilhados                                          */
/* ========================================================================== */

function set_pill(id, text, tone){
	let pill = $(id);
	pill.textContent = text;
	pill.className = "pill" + (tone ? " " + tone : "");
}

/* ========================================================================== */
/* Settings — verdict notification                                            */
/* ========================================================================== */

function update_verdict_status(state){
	if (state == null){
		set_status("verdictStatus", "Não foi possível carregar a configuração de notificação.", "bad");
		return;
	}
	set_switch("verdictStartEnabled", state.startEnabled);
	set_switch("verdictSafeEnabled", state.safeEnabled);
	set_switch("verdictMaliciousEnabled", state.maliciousEnabled);
	set_switch("verdictErrataEnabled", state.errataEnabled);
	if (document.activeElement !== $("verdictStartMessage")){ $("verdictStartMessage").value = state.startMessage; }
	if (document.activeElement !== $("verdictSafeMessage")){ $("verdictSafeMessage").value = state.safeMessage; }
	if (document.activeElement !== $("verdictMaliciousMessage")){ $("verdictMaliciousMessage").value = state.maliciousMessage; }
	if (document.activeElement !== $("verdictErrataMessage")){ $("verdictErrataMessage").value = state.errataMessage || ""; }
	sync_event_rows();
	let on = [state.startEnabled, state.safeEnabled, state.maliciousEnabled, state.errataEnabled].filter(Boolean).length;
	set_status("verdictStatus",
		on === 0 ? "Nenhum aviso ao denunciante está ligado."
			: on + " de 4 avisos ligados. Eles saem pelo servidor SMTP configurado em E-mail.",
		on > 0 ? "ok" : null);
}

function load_verdict_config(){
	get_json("verdict-config").then(update_verdict_status);
}

function save_verdict_config(){
	$("verdictSaveBtn").disabled = true;
	post_form("verdict-config", {
		startEnabled: switch_on("verdictStartEnabled") ? "true" : "false",
		safeEnabled: switch_on("verdictSafeEnabled") ? "true" : "false",
		maliciousEnabled: switch_on("verdictMaliciousEnabled") ? "true" : "false",
		errataEnabled: switch_on("verdictErrataEnabled") ? "true" : "false",
		errataMessage: $("verdictErrataMessage").value.trim(),
		startMessage: $("verdictStartMessage").value.trim(),
		safeMessage: $("verdictSafeMessage").value.trim(),
		maliciousMessage: $("verdictMaliciousMessage").value.trim()
	}).then(function(result){
		$("verdictSaveBtn").disabled = false;
		if (result.ok && result.data){
			update_verdict_status(result.data);
			toast("Configuração salva.", "ok");
		} else {
			set_status("verdictStatus", "Configuração inválida: revise os campos e tente de novo.", "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — Notificações: as duas guias e o alerta de volume                */
/* ========================================================================== */

function show_notif_tab(tab){
	for (let panel of $$("[data-notif-tab]")){ show(panel, panel.dataset.notifTab === tab); }
	for (let button of $$("#notifTabs .tab")){ button.classList.toggle("active", button.dataset.arg === tab); }
	if (tab === "team" && !volume_loaded){ load_volume_alerts(); }
}

// Um aviso desligado mostra a mensagem apagada, ainda editável
function sync_event_rows(){
	for (let key of ["Start", "Safe", "Malicious", "Errata"]){
		let row = $("verdict" + key + "Row");
		if (row){ row.classList.toggle("off", !switch_on("verdict" + key + "Enabled")); }
	}
}

// Os interruptores são genéricos (toggle_switch); o que depende do estado deles
// relê depois que o despacho terminou de alternar a classe
document.addEventListener("click", function(event){
	let toggle = event.target.closest && event.target.closest(".toggle");
	if (!toggle){ return; }
	if (/^verdict/.test(toggle.id)){ window.setTimeout(sync_event_rows, 0); }
	if (/^volumeBy/.test(toggle.id)){ window.setTimeout(render_volume_rule, 0); }
});

let volume_loaded = false;
let alert_connector_defs = [];
let alert_connector_variables = [];
let alert_connector_limit = 10;

// Minutos para número + unidade: mostra em horas quando fecha em hora cheia
function set_duration(prefix, minutes){
	let hours = minutes >= 60 && minutes % 60 === 0;
	if (document.activeElement !== $(prefix)){ $(prefix).value = hours ? minutes / 60 : minutes; }
	$(prefix + "Unit").value = hours ? "60" : "1";
}

function read_duration(prefix){
	let value = parseInt($(prefix).value, 10);
	return isFinite(value) ? value * parseInt($(prefix + "Unit").value, 10) : NaN;
}

function duration_text(minutes){
	if (!isFinite(minutes) || minutes <= 0){ return "—"; }
	if (minutes % 1440 === 0){ return (minutes / 1440) + (minutes === 1440 ? " dia" : " dias"); }
	if (minutes % 60 === 0){ return (minutes / 60) + " h"; }
	return minutes + " min";
}

// A regra em uma frase, a partir do que está digitado — não do que está salvo
function render_volume_rule(){
	let threshold = parseInt($("volumeThreshold").value, 10);
	let window_minutes = read_duration("volumeWindow");
	let cooldown = read_duration("volumeCooldown");
	let patterns = [];
	if (switch_on("volumeBySubject")){ patterns.push("o mesmo assunto"); }
	if (switch_on("volumeBySender")){ patterns.push("o mesmo remetente"); }
	if (patterns.length === 0){
		$("volumeRule").textContent = "Escolha ao menos um padrão para agrupar.";
		return;
	}
	if (!isFinite(threshold) || !isFinite(window_minutes)){
		$("volumeRule").textContent = "";
		return;
	}
	$("volumeRule").textContent = "Dispara quando " + threshold + " e-mails da fila tiverem "
		+ patterns.join(" ou ") + " em " + duration_text(window_minutes)
		+ "; o mesmo padrão volta a avisar depois de " + duration_text(cooldown) + ".";
}

function load_volume_alerts(){
	get_json("api/volume-alerts").then(function(payload){
		if (payload == null || payload.error){
			set_status("volumeStatus", (payload && payload.error) || "Não foi possível carregar o alerta de volume.", "bad");
			$("alertConnectorCards").replaceChildren(el("div", {className: "tbl-empty",
				text: "Não foi possível carregar os webhooks."}));
			render_pending("volumeRecent", "Não foi possível carregar os últimos alertas.");
			return;
		}
		volume_loaded = true;
		let config = payload.config;
		set_switch("volumeEnabled", config.enabled);
		set_switch("volumeBySubject", config.bySubject);
		set_switch("volumeBySender", config.bySender);
		if (document.activeElement !== $("volumeThreshold")){ $("volumeThreshold").value = config.threshold; }
		set_duration("volumeWindow", config.windowMinutes);
		set_duration("volumeCooldown", config.cooldownMinutes);
		if (document.activeElement !== $("volumeRecipients")){ $("volumeRecipients").value = (config.recipients || []).join("\n"); }
		render_volume_rule();

		// O que impede o alerta de funcionar, dito onde ele é configurado
		let notes = [];
		if (!payload.pollEnabled){
			notes.push("A consulta automática da caixa está desligada (Análise automática). Sem ela a fila não é relida e nenhum alerta é avaliado.");
		}
		if (!payload.smtpEnabled && (config.recipients || []).length){
			notes.push("O servidor SMTP está desligado (aba E-mail): os e-mails da equipe não saem até ele ser ligado.");
		}
		$("volumePollNote").textContent = notes.join(" ");
		show($("volumePollNote"), notes.length > 0);

		set_status("volumeStatus", config.enabled
			? "Ligado · " + payload.queued + " e-mail(s) na fila"
				+ (payload.pending ? ", " + payload.pending + " ainda carregando e fora da contagem" : "") + "."
			: "Desligado: nenhum alerta é avaliado.", config.enabled ? "ok" : null);

		alert_connector_defs = payload.connectors || [];
		alert_connector_variables = payload.variables || [];
		alert_connector_limit = payload.connectorLimit || alert_connector_limit;
		render_alert_connector_cards();
		render_volume_recent(payload.recent || []);
	});
}

function save_volume_alerts(){
	let window_minutes = read_duration("volumeWindow");
	let cooldown = read_duration("volumeCooldown");
	$("volumeSaveBtn").disabled = true;
	post_json("api/volume-alerts", {
		enabled: switch_on("volumeEnabled"),
		bySubject: switch_on("volumeBySubject"),
		bySender: switch_on("volumeBySender"),
		threshold: $("volumeThreshold").value,
		windowMinutes: isFinite(window_minutes) ? window_minutes : "",
		cooldownMinutes: isFinite(cooldown) ? cooldown : "",
		recipients: $("volumeRecipients").value
	}).then(function(result){
		$("volumeSaveBtn").disabled = false;
		if (!result.ok || !result.data || result.data.error){
			set_status("volumeStatus", (result.data && result.data.error) || "Não foi possível salvar.", "bad");
			return;
		}
		toast("Alerta de volume salvo.", "ok");
		load_volume_alerts();
	});
}

function render_alert_connector_cards(){
	let enabled = alert_connector_defs.filter(function(d){ return d.enabled; }).length;
	$("alertConnectorsNote").textContent = alert_connector_defs.length === 0
		? "Nenhum webhook. O limite é de " + alert_connector_limit + "."
		: enabled + " de " + alert_connector_defs.length + " habilitado" + (enabled === 1 ? "" : "s");
	let cards = alert_connector_defs.map(function(def){
		return connector_card(def, "recebe os alertas de volume", function(){ open_alert_connector_modal(def.id); });
	});
	if (cards.length === 0){
		cards.push(el("div", {className: "tbl-empty",
			text: "Nenhum webhook ainda. Use \"Novo webhook\" para avisar a equipe no Teams, Slack ou outra ferramenta."}));
	}
	$("alertConnectorCards").replaceChildren.apply($("alertConnectorCards"), cards);
}

function render_volume_recent(entries){
	let box = $("volumeRecent");
	if (entries.length === 0){
		render_pending("volumeRecent", "Nenhum alerta disparado ainda.");
		return;
	}
	box.replaceChildren.apply(box, entries.map(function(entry){
		let when = new Date(entry.detectedAt);
		let channels = (entry.results || []).map(function(result){
			return el("span", {className: "pill " + (result.ok ? "ok" : "bad"),
				text: (result.channel === "email" ? "e-mail " : "webhook ") + result.target,
				title: result.ok ? "enviado" : result.error});
		});
		if (channels.length === 0){
			channels.push(el("span", {className: "pill warn", text: "nenhum canal configurado"}));
		}
		return el("div", {className: "alert-entry"}, [
			el("div", {className: "alert-entry-head"}, [
				el("span", {className: "pill", text: entry.patternType === "sender" ? "remetente" : "assunto"}),
				el("span", {className: "alert-entry-pattern", text: entry.pattern}),
				el("span", {className: "card-code", style: "flex:0 0 auto",
					text: entry.count + " em " + duration_text(entry.windowMinutes)
						+ (isNaN(when) ? "" : " · " + when.toLocaleString("pt-BR", {day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"}))})
			]),
			el("div", {className: "alert-entry-channels"}, channels)
		]);
	}));
}

/* ========================================================================== */
/* Settings — SMTP, how the notifications actually leave                      */
/* ========================================================================== */

// Every field except the password, which the server never sends back
let SMTP_TEXT_FIELDS = ["host", "port", "security", "user", "sender", "senderName", "subjectPrefix"];

function smtp_input(key){
	return $("smtp" + key.charAt(0).toUpperCase() + key.slice(1));
}

function update_smtp_status(state){
	if (state == null){
		set_status("smtpStatus", "Não foi possível carregar a configuração do servidor de envio.", "bad");
		return;
	}
	let config = state.config || state;
	set_switch("smtpEnabledSwitch", config.enabled);
	SMTP_TEXT_FIELDS.forEach(function(key){
		let input = smtp_input(key);
		if (input && document.activeElement !== input){ input.value = config[key] == null ? "" : config[key]; }
	});
	// An empty password field means "keep the stored one", so the placeholder is
	// the only thing that says a password exists
	$("smtpPassword").placeholder = config.hasPassword ? "•••••••• (salva — deixe vazio para manter)" : "";

	if (!config.enabled){
		set_status("smtpStatus", "Envio desabilitado: nenhuma notificação sai desta aplicação.");
	} else if (!config.host || !config.sender){
		set_status("smtpStatus", "Servidor ou remetente ainda não configurado.", "bad");
	} else {
		set_status("smtpStatus", "Enviando por " + config.host + ":" + config.port + " como " + config.sender + ".");
	}
}

function load_smtp_config(){
	get_json("smtp-config").then(update_smtp_status);
}

function smtp_form_params(){
	let params = {enabled: switch_on("smtpEnabledSwitch") ? "true" : "false"};
	SMTP_TEXT_FIELDS.forEach(function(key){
		let input = smtp_input(key);
		params[key] = input ? input.value.trim() : "";
	});
	params.password = $("smtpPassword").value;
	return params;
}

function save_smtp_config(){
	$("smtpSaveBtn").disabled = true;
	post_form("smtp-config", smtp_form_params()).then(function(result){
		$("smtpSaveBtn").disabled = false;
		if (result.ok && result.data && result.data.ok){
			// Clear the password field: the saved one is now the placeholder
			$("smtpPassword").value = "";
			update_smtp_status(result.data.config);
			toast("Servidor de envio salvo.", "ok");
		} else {
			let error = (result.data && result.data.error) || "Configuração inválida: revise os campos.";
			set_status("smtpStatus", error, "bad");
		}
	});
}

// Deliberately does not send a message: it opens the session, negotiates TLS and
// authenticates. A test button that emailed somebody for real would be a trap.
function test_smtp_config(){
	$("smtpTestBtn").disabled = true;
	set_status("smtpStatus", "Testando a conexão com o servidor…");
	post_form("smtp-config/test", smtp_form_params()).then(function(result){
		$("smtpTestBtn").disabled = false;
		if (result.ok && result.data && result.data.ok){
			set_status("smtpStatus", "Conexão OK — " + result.data.detail + ". Nenhuma mensagem foi enviada.", "ok");
		} else {
			let error = (result.data && result.data.error) || "Não foi possível falar com o servidor.";
			set_status("smtpStatus", error, "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — case parameters                                                 */
/* ========================================================================== */

function update_case_status(state){
	if (state == null){
		set_status("caseStatus", "Não foi possível carregar a configuração do caso.", "bad");
		return;
	}
	if (document.activeElement !== $("caseTlpSelect")){ $("caseTlpSelect").value = state.tlp; }
	if (document.activeElement !== $("casePapSelect")){ $("casePapSelect").value = state.pap; }
	if (document.activeElement !== $("caseTagsInput")){ $("caseTagsInput").value = state.tags.join(", "); }
	if (document.activeElement !== $("caseMispIdInput")){ $("caseMispIdInput").value = state.mispId; }
	// The Integrações card shows the same value read-only
	$("mispIdInput").value = state.mispId;
	set_status("caseStatus", "Casos criados com TLP " + state.tlp + ", PAP " + state.pap + " e tags: " + state.tags.join(", ") + ".");
	set_pill("mispPill", state.mispId ? "configurado" : "não usado", state.mispId ? "ok" : "");
}

function load_case_config(){
	get_json("case-config").then(update_case_status);
}

function save_case_config(){
	let tags = $("caseTagsInput").value.trim();
	if (tags.length === 0){
		set_status("caseStatus", "Pelo menos uma tag é obrigatória.", "bad");
		return;
	}
	$("caseSaveBtn").disabled = true;
	post_form("case-config", {
		tlp: $("caseTlpSelect").value,
		pap: $("casePapSelect").value,
		tags: tags,
		mispId: $("caseMispIdInput").value.trim()
	}).then(function(result){
		$("caseSaveBtn").disabled = false;
		if (result.ok && result.data){
			update_case_status(result.data);
			toast("Configuração salva.", "ok");
		} else {
			set_status("caseStatus", "Configuração inválida: revise os campos e tente de novo.", "bad");
		}
	});
}

/* --- Settings — original message archive ---------------------------------- */

function update_evidence_status(state){
	if (state == null || state.error){
		set_status("evidenceStatus", (state && state.error) || "Não foi possível carregar a guarda da mensagem original.", "bad");
		return;
	}
	set_switch("evidenceEnabled", state.storeOriginal);
	if (document.activeElement !== $("evidenceRetention")){ $("evidenceRetention").value = state.retentionDays; }
	if (document.activeElement !== $("evidenceMaxGb")){ $("evidenceMaxGb").value = state.maxGigabytes; }
	// O uso só existe quando o acervo abriu; sem ele a linha diz isso, não "0 B"
	$("evidenceUsage").textContent = state.usedBytes == null
		? "acervo indisponível neste servidor"
		: format_bytes(state.usedBytes) + " em uso · " + state.messages + " registro(s)";
	set_status("evidenceStatus", state.storeOriginal
		? "Guardando por " + (state.retentionDays ? state.retentionDays + " dias" : "tempo indeterminado") + ", até " + state.maxGigabytes + " GB."
		: "Desligado: nenhuma mensagem nova é guardada.", state.storeOriginal ? "ok" : null);
}

function load_evidence_config(){
	get_json("case-evidence-config").then(update_evidence_status);
}

function save_evidence_config(){
	$("evidenceSaveBtn").disabled = true;
	post_form("case-evidence-config", {
		storeOriginal: switch_on("evidenceEnabled") ? "true" : "false",
		retentionDays: $("evidenceRetention").value.trim(),
		maxGigabytes: $("evidenceMaxGb").value.trim()
	}).then(function(result){
		$("evidenceSaveBtn").disabled = false;
		if (result.ok && result.data && !result.data.error){
			update_evidence_status(result.data);
			toast("Configuração salva.", "ok");
		} else {
			set_status("evidenceStatus", (result.data && result.data.error) || "Configuração inválida: revise os campos e tente de novo.", "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — audit trail storage                                             */
/*                                                                            */
/* Where the trail lives, how long it stays, how much it may take, and the    */
/* syslog copy. global_admin only: shortening retention deletes history. The  */
/* floors come from the server and are enforced there.                        */
/* ========================================================================== */

// O que está aplicado no servidor, para saber se o que foi digitado encurta
let audit_log_current = null;

function format_megabytes(bytes){
	let mb = bytes / (1024 * 1024);
	return (mb < 10 ? mb.toFixed(1) : String(Math.round(mb))).replace(".", ",") + " MB";
}

function update_audit_log_config(state){
	if (state == null || state.error){
		set_status("auditLogStatus", (state && state.error) || "Não foi possível carregar a configuração da trilha.", "bad");
		return;
	}
	audit_log_current = state;
	let limits = state.limits || {};
	for (let [id, value] of [["auditLogFolder", state.folder], ["auditLogDays", state.retentionDays],
		["auditLogMb", state.maxMegabytes], ["auditSyslogHost", state.syslog.host], ["auditSyslogPort", state.syslog.port]]){
		if (document.activeElement !== $(id)){ $(id).value = value == null ? "" : value; }
	}
	$("auditSyslogProtocol").value = state.syslog.protocol || "udp";
	set_switch("auditSyslogEnabled", state.syslog.enabled);
	$("auditLogDays").min = limits.minRetentionDays;
	$("auditLogDays").max = limits.maxRetentionDays;
	$("auditLogMb").min = limits.minMegabytes;
	$("auditLogMb").max = limits.maxMegabytes;
	$("auditLogDaysHint").textContent = "de " + limits.minRetentionDays + " a " + limits.maxRetentionDays + " dias";
	$("auditLogMbHint").textContent = "de " + limits.minMegabytes + " a " + limits.maxMegabytes.toLocaleString("pt-BR") + " MB";
	$("auditLogFolderHint").textContent = "não pode ser " + (state.reservedFolders || []).join(", ");

	// O uso de agora, e se a promessa de retenção está sendo cumprida
	let box = $("auditLogUsage");
	box.replaceChildren();
	let usage = state.usage;
	if (usage){
		box.appendChild(el("p", {className: "audit-usage-line"}, [
			el("strong", {text: format_megabytes(usage.bytes)}),
			document.createTextNode(" de " + state.maxMegabytes.toLocaleString("pt-BR") + " MB em "
				+ usage.files + (usage.files === 1 ? " arquivo" : " arquivos")
				+ " · registro mais antigo: " + (usage.oldest ? audit_short_date(usage.oldest) : "—"))
		]));
		let fill = Math.min(100, Math.round(usage.bytes / (state.maxMegabytes * 1024 * 1024) * 100));
		let bar = el("div", {className: "audit-usage-bar", attrs: {role: "meter", "aria-valuemin": "0",
			"aria-valuemax": "100", "aria-valuenow": String(fill), "aria-label": "Espaço usado pela trilha"}}, [el("span", {})]);
		bar.firstChild.style.width = fill + "%";
		box.appendChild(bar);
	}
	if (state.path){
		box.appendChild(el("p", {className: "field-hint mono", text: state.path}));
	}

	if (state.capCut){
		set_status("auditLogStatus", "O teto está cortando a trilha antes do prazo: os dias mais antigos foram apagados para caber em "
			+ state.maxMegabytes + " MB. Aumente o teto para cumprir " + state.retentionDays + " dias.", "bad");
	} else if (state.syslog.enabled && state.syslogError){
		set_status("auditLogStatus", "Syslog fora: " + state.syslogError + " A trilha local continua sendo gravada.", "bad");
	} else if (state.syslog.enabled && state.syslogActive){
		set_status("auditLogStatus", "Copiando para " + state.syslog.protocol.toUpperCase() + " " + state.syslog.host + ":"
			+ state.syslog.port + " · " + state.syslogSent + " registro(s) enviado(s) desde a última aplicação.", "ok");
	} else {
		set_status("auditLogStatus", "Guardando " + state.retentionDays + " dias, até " + state.maxMegabytes + " MB. Sem cópia externa.");
	}
	$("auditSyslogTestBtn").disabled = !(state.syslog.enabled && state.syslogActive);
}

function load_audit_log_config(){
	get_json("audit-log-config").then(update_audit_log_config);
}

function audit_log_form(){
	return {
		folder: $("auditLogFolder").value.trim(),
		retentionDays: $("auditLogDays").value.trim(),
		maxMegabytes: $("auditLogMb").value.trim(),
		syslogEnabled: switch_on("auditSyslogEnabled") ? "true" : "false",
		syslogHost: $("auditSyslogHost").value.trim(),
		syslogPort: $("auditSyslogPort").value.trim(),
		syslogProtocol: $("auditSyslogProtocol").value
	};
}

function save_audit_log_config(){
	let submit = function(){
		$("auditLogSaveBtn").disabled = true;
		post_form("audit-log-config", audit_log_form()).then(function(result){
			$("auditLogSaveBtn").disabled = false;
			if (result.ok && result.data && !result.data.error){
				update_audit_log_config(result.data);
				toast("Configuração da trilha salva.", "ok");
			} else {
				set_status("auditLogStatus", (result.data && result.data.error) || "Configuração inválida: revise os campos e tente de novo.", "bad");
			}
		});
	};
	// Encurtar apaga na hora. Confirmar é o mínimo quando o que some é
	// justamente o registro do que foi feito
	let days = parseInt($("auditLogDays").value, 10);
	let mb = parseInt($("auditLogMb").value, 10);
	let current = audit_log_current;
	if (current && (days < current.retentionDays || mb < current.maxMegabytes)){
		ask({
			title: "Encurtar a trilha de auditoria?",
			body: "Com " + days + " dias e " + mb + " MB, o que ficar de fora é apagado agora e não volta. "
				+ "A mudança fica registrada na trilha com o seu usuário.",
			confirmLabel: "Encurtar e apagar",
			danger: true
		}, submit);
		return;
	}
	submit();
}

function test_audit_log_config(){
	$("auditSyslogTestBtn").disabled = true;
	post_form("audit-log-config/test", {}).then(function(result){
		let state = result.ok ? result.data : null;
		update_audit_log_config(state);
		if (state && !state.error && !state.syslogError){
			toast(state.syslog.protocol === "udp"
				? "Registro de teste enviado. UDP não confirma entrega: confira no SIEM."
				: "Registro de teste entregue ao servidor syslog.", "ok");
		}
	});
}

/* ========================================================================== */
/* Settings — departments                                                     */
/* ========================================================================== */

/* Where the "Departamentos mais visados" card gets its data: Entra ID, asked
 * once per reporter and cached. The screen's whole job is to make the one thing
 * that realistically goes wrong — User.Read.All never granted or never consented
 * — visible before it turns into an empty card that looks like an organization
 * with no departments. Hence a Testar that reports the error verbatim. */
function update_departments_status(state){
	if (state == null){
		set_status("deptStatus", "Não foi possível carregar a configuração de departamentos.", "bad");
		return;
	}
	set_switch("deptEnabled", state.enabled);
	set_switch("deptUseEmailCreds", state.useEmailCredentials);
	show($("deptOwnCreds"), !state.useEmailCredentials);
	if (document.activeElement !== $("deptAttribute")){ $("deptAttribute").value = state.attribute; }
	if (document.activeElement !== $("deptCacheHours")){ $("deptCacheHours").value = state.cacheHours; }
	if (document.activeElement !== $("deptTenantId")){ $("deptTenantId").value = state.tenantId; }
	if (document.activeElement !== $("deptClientId")){ $("deptClientId").value = state.clientId; }

	$("deptCredStatus").textContent = state.useEmailCredentials
		? "Usando o registro de aplicativo do Microsoft 365 configurado em E-mail."
		: (state.hasClientSecret ? "Registro próprio, com client secret guardado." : "Registro próprio, sem client secret guardado.");

	if (!state.credentialsComplete){
		set_status("deptStatus", "Credenciais incompletas: o Entra ID não pode ser consultado e nenhuma denúncia será atribuída.", "bad");
	} else if (!state.enabled){
		set_status("deptStatus", "Desligado: as análises não gravam departamento e o card da Visão Executiva fica vazio.", "warn");
	} else {
		set_status("deptStatus", "Cada análise consulta o " + state.attribute + " de quem denunciou no Entra ID.", "ok");
	}
}

function load_departments_config(){
	get_json("departments-config").then(update_departments_status);
}

// Toggling where the credentials come from also reveals the fields for them, so
// the switch and what it controls are never out of step
function toggle_dept_credentials(element){
	toggle_switch(element);
	show($("deptOwnCreds"), !switch_on("deptUseEmailCreds"));
}

function departments_form_params(){
	return {
		enabled: switch_on("deptEnabled") ? "true" : "false",
		attribute: $("deptAttribute").value,
		useEmailCredentials: switch_on("deptUseEmailCreds") ? "true" : "false",
		tenantId: $("deptTenantId").value.trim(),
		clientId: $("deptClientId").value.trim(),
		// Empty means "keep the stored one"; the server never sends it back
		clientSecret: $("deptClientSecret").value,
		cacheHours: $("deptCacheHours").value
	};
}

function save_departments_config(){
	$("deptSaveBtn").disabled = true;
	post_form("departments-config", departments_form_params()).then(function(result){
		$("deptSaveBtn").disabled = false;
		if (result.ok && result.data){
			$("deptClientSecret").value = "";
			update_departments_status(result.data);
			toast("Configuração de departamentos salva.", "ok");
		} else {
			set_status("deptStatus", "Para ligar a consulta é preciso tenant, client id e client secret — próprios ou os do Microsoft 365.", "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — SSO corporativo                                                 */
/* ========================================================================== */

/* Quem entra pelo Entra ID e com qual cargo. Duas coisas a tela precisa deixar
 * óbvias, porque errar qualquer uma delas produz um botão que só sabe recusar:
 * o URI de redirecionamento tem de estar colado no registro de aplicativo tal
 * como aparece aqui, e sem nenhum grupo mapeado ninguém entra. Daí o estado
 * dizer, em uma frase, em qual dos dois pés a configuração está. */

const SSO_GROUP_FIELD = {
	analyst: "ssoGroupAnalyst",
	admin: "ssoGroupAdmin",
	global_admin: "ssoGroupGlobalAdmin"
};

function update_sso_status(state){
	if (state == null){
		set_status("ssoStatus", "Não foi possível carregar a configuração de SSO.", "bad");
		return;
	}
	set_switch("ssoEnabled", state.enabled);
	if (document.activeElement !== $("ssoTenantId")){ $("ssoTenantId").value = state.tenantId; }
	if (document.activeElement !== $("ssoClientId")){ $("ssoClientId").value = state.clientId; }
	$("ssoRedirectUri").value = state.redirectUri;
	for (let role of Object.keys(SSO_GROUP_FIELD)){
		let field = $(SSO_GROUP_FIELD[role]);
		if (document.activeElement !== field){
			field.value = (state.groupRoles[role] || []).join("\n");
		}
	}

	$("ssoCredStatus").textContent = state.hasClientSecret
		? "Client secret guardado no servidor."
		: "Nenhum client secret guardado.";

	let mapped = Object.keys(SSO_GROUP_FIELD).reduce(function(total, role){
		return total + (state.groupRoles[role] || []).length;
	}, 0);
	if (!state.configured){
		let missing = mapped === 0
			? "nenhum grupo está mapeado a um cargo"
			: "faltam tenant, client id ou client secret";
		set_status("ssoStatus", "Incompleto: " + missing + ". O botão não aparece na tela de login.", "bad");
	} else if (!state.enabled){
		set_status("ssoStatus", "Configurado, mas desligado: a tela de login só oferece usuário e senha.", "warn");
	} else {
		set_status("ssoStatus", "Ligado: " + mapped + " grupo(s) mapeado(s). Quem não está em nenhum deles não entra.", "ok");
	}
}

function load_sso_config(){
	get_json("sso-config").then(update_sso_status);
}

function save_sso_config(){
	let params = {
		enabled: switch_on("ssoEnabled") ? "true" : "false",
		tenantId: $("ssoTenantId").value.trim(),
		clientId: $("ssoClientId").value.trim(),
		// Vazio significa "mantenha o que já está guardado"; o servidor nunca o devolve
		clientSecret: $("ssoClientSecret").value
	};
	for (let role of Object.keys(SSO_GROUP_FIELD)){
		params["groupRoles." + role] = $(SSO_GROUP_FIELD[role]).value;
	}
	$("ssoSaveBtn").disabled = true;
	post_form("sso-config", params).then(function(result){
		$("ssoSaveBtn").disabled = false;
		if (result.ok && result.data){
			$("ssoClientSecret").value = "";
			update_sso_status(result.data);
			toast("Configuração de SSO salva.", "ok");
		} else {
			set_status("ssoStatus", "Para ligar o SSO é preciso tenant, client id, client secret e ao menos um grupo mapeado a um cargo.", "bad");
		}
	});
}

/* Resolves one address live, with whatever is on screen. An empty address tests
 * only the permission, which is the question an admin actually has before
 * trusting the card. */
function test_departments_config(){
	let params = departments_form_params();
	params.address = $("deptTestAddress").value.trim();
	set_status("deptTestStatus", "consultando o Entra ID…");
	post_form("departments-config/test", params).then(function(result){
		let data = result.data;
		if (!result.ok || !data){
			set_status("deptTestStatus", "Não foi possível testar a consulta.", "bad");
			return;
		}
		if (!data.ok){
			set_status("deptTestStatus", data.error, "bad");
			return;
		}
		if (!data.address){
			set_status("deptTestStatus", data.detail, "ok");
			return;
		}
		if (data.department){
			set_status("deptTestStatus", data.address + " → " + data.department, "ok");
		} else {
			set_status("deptTestStatus", data.address + " → sem departamento. " + data.detail, "warn");
		}
	});
}

/* ========================================================================== */
/* Settings — mailbox polling                                                 */
/* ========================================================================== */

/* Reading the mailbox on a timer is what keeps the analyst from clicking
 * Atualizar. The number that needs saying out loud is no longer a ceiling on
 * the queue — every unread email is listed — but how many of them arrive with
 * their content already downloaded. The rest are fetched one at a time, when
 * somebody opens them, which is what keeps a full mailbox from costing a full
 * mailbox on every cycle. */
function update_inbox_poll_config(state){
	if (state == null){
		set_status("pollStatus", "Não foi possível carregar a configuração da consulta automática.", "bad");
		return;
	}
	set_switch("pollEnabled", state.enabled);
	set_paired("pollInterval", "pollIntervalRange", state.intervalSeconds);
	if (state.pageSize){ $("pollPageSize").value = String(state.pageSize); }
	if (!state.enabled){
		set_status("pollStatus", "Desligada: a tela Caixa de e-mail só atualiza no botão Atualizar.", "warn");
	} else {
		set_status("pollStatus", "A caixa é relida a cada " + state.intervalSeconds
			+ "s e paginada de " + state.pageSize + " em " + state.pageSize
			+ ". O servidor carrega texto e diagramação página por página, alternando as duas pontas.", "ok");
	}
}

function load_inbox_poll_config(){
	get_json("inbox-poll").then(update_inbox_poll_config);
}

function save_inbox_poll_config(){
	$("pollSaveBtn").disabled = true;
	post_form("inbox-poll", {
		enabled: switch_on("pollEnabled") ? "true" : "false",
		intervalSeconds: $("pollInterval").value,
		pageSize: $("pollPageSize").value
	}).then(function(result){
		$("pollSaveBtn").disabled = false;
		if (result.ok && result.data){
			update_inbox_poll_config(result.data);
			toast("Consulta automática salva.", "ok");
		} else {
			set_status("pollStatus", "Valores fora da faixa: intervalo 15–3600s e página de 20, 30, 40 ou 50 e-mails.", "bad");
		}
	});
}

/* ========================================================================== */
/* Settings — whitelist v2                                                    */
/* ========================================================================== */

// Cópia local da whitelist, atualizada a cada resposta do servidor. Cada regra
// vem com `stats` (contadores e suspensão) grudados pela API, porque contador
// mora no banco e declaração mora no arquivo.
let wl_data = null;
let wl_type = "sender";
let wl_editing = null;

const WL_TYPE_LABEL = {
	sender: "Remetente",
	domain: "Domínio",
	url: "URL",
	hash: "Hash",
	ip: "IP"
};

// O que cada aba faz com o que casa. Está escrito na tela porque é a distinção
// que a whitelist antiga não tinha: suprimir observável e rebaixar veredito são
// coisas de risco muito diferente.
const WL_TYPE_NOTE = {
	sender: "Rebaixa o veredito para Safe, e só quando o servidor autenticou o domínio "
		+ "(DMARC, ou DKIM alinhado). A análise roda inteira e todo rebaixamento fica registrado: "
		+ "se a regra passar a esconder vereditos ruins, ela é suspensa sozinha.",
	domain: "O domínio deixa de virar observável. empresa.com cobre o domínio e todos os "
		+ "subdomínios; *.empresa.com cobre só os subdomínios.",
	url: "A URL deixa de virar observável. Host e caminho são casados por expressão regular, "
		+ "cada um sobre o endereço já desmontado — nunca sobre o texto cru da URL, que é onde "
		+ "moram as evasões. Cole endereços no testador antes de salvar: ele roda o mesmo "
		+ "casamento da análise e mostra o que a regra libera de verdade.",
	hash: "O anexo com esse SHA-256 deixa de ser analisado. É como se libera um logotipo de "
		+ "assinatura que aparece em todo e-mail.",
	ip: "O endereço deixa de virar observável. Aceita IP solto (203.0.113.7) ou faixa em CIDR "
		+ "(203.0.113.0/24). Só endereço roteável na internet: privado, loopback e reservado já são "
		+ "ignorados em toda análise, sem precisar de regra."
};

// Ids marcados na aba atual. Zera ao trocar de aba, porque selecionar em uma
// aba e apagar em outra é a forma mais fácil de apagar o que não se queria.
let wl_selected = [];

function wl_rules_of_type(){
	if (wl_data == null || !Array.isArray(wl_data.rules)){ return []; }
	let filter = ($("whitelistSearch").value || "").trim().toLowerCase();
	return wl_data.rules.filter(function(rule){
		if (rule.type !== wl_type){ return false; }
		if (filter === ""){ return true; }
		return (rule.value || "").toLowerCase().indexOf(filter) !== -1
			|| (rule.reason || "").toLowerCase().indexOf(filter) !== -1;
	});
}

function wl_expiry_label(rule){
	if (rule.expires_at == null){ return "permanente"; }
	let when = new Date(rule.expires_at);
	if (isNaN(when.getTime())){ return rule.expires_at; }
	let days = Math.ceil((when.getTime() - Date.now()) / 86400000);
	if (days < 0){ return "expirada"; }
	if (days === 0){ return "expira hoje"; }
	return "expira em " + days + "d";
}

function wl_expiry_tone(rule){
	if (rule.expires_at == null){ return ""; }
	let when = new Date(rule.expires_at);
	if (isNaN(when.getTime())){ return "bad"; }
	let days = Math.ceil((when.getTime() - Date.now()) / 86400000);
	if (days < 0){ return "bad"; }
	if (days <= 14){ return "warn"; }
	return "";
}

function wl_toggle_selected(rule_id){
	let at = wl_selected.indexOf(rule_id);
	if (at === -1){ wl_selected.push(rule_id); } else { wl_selected.splice(at, 1); }
	render_whitelist();
}

// Marca ou desmarca tudo que está VISÍVEL — o filtro de busca faz parte da
// seleção. Marcar 460 regras enquanto a tela mostra 3 é como se apaga o que não
// se queria apagar.
function whitelist_toggle_all(){
	let visible = wl_rules_of_type().map(function(rule){ return rule.id; });
	let all_on = visible.length > 0 && visible.every(function(id){ return wl_selected.indexOf(id) !== -1; });
	wl_selected = all_on ? [] : visible.slice();
	render_whitelist();
}

function whitelist_delete_selected(){
	if (wl_selected.length === 0){
		set_status("whitelistStatus", "Marque as regras que quer remover.", "bad");
		return;
	}
	let rules = wl_data.rules.filter(function(rule){ return wl_selected.indexOf(rule.id) !== -1; });
	let sample = rules.slice(0, 8).map(function(rule){ return rule.value; }).join(", ");
	if (rules.length > 8){ sample += " e mais " + (rules.length - 8); }
	ask({
		title: "Remover " + rules.length + " regra(s)",
		sub: "a mudança vale a partir da próxima análise",
		body: "Serão removidas: " + sample,
		confirmLabel: "Remover " + rules.length,
		danger: true
	}, function(){
		wl_mutation("api/whitelist/rule/delete", {ids: wl_selected.join(",")},
			rules.length + " regra(s) removida(s).").then(function(ok){
			if (ok){ wl_selected = []; render_whitelist(); }
		});
	});
}

function render_whitelist(){
	let container = $("whitelistRows");
	container.replaceChildren();

	// Com a aba Aprendido aberta, uma releitura da whitelist não pode devolver o
	// destaque a um tipo de regra que não está na tela
	if ($("wlMemoryPanel").classList.contains("hidden")){
		for (let node of document.querySelectorAll("[data-wl-tab]")){
			node.classList.toggle("active", node.dataset.wlTab === wl_type);
		}
	}
	$("whitelistTypeNote").textContent = WL_TYPE_NOTE[wl_type];
	wl_render_form();

	if (wl_data == null){
		$("whitelistCount").textContent = "";
		return;
	}

	// O arquivo não carregou: nada está sendo liberado, e isso precisa estar na
	// tela e não só no log — senão a analista lê "nenhuma regra" como "tudo certo"
	if (wl_data.loadError){
		container.appendChild(el("div", {
			className: "empty-note bad",
			text: "A whitelist não pôde ser carregada, então nada está sendo liberado nas análises: "
				+ wl_data.loadError
		}));
	}

	let rules = wl_rules_of_type();
	// Suspensa primeiro: é o alarme, não pode ficar na terceira página
	rules.sort(function(a, b){
		let sa = (a.stats && a.stats.suspended) ? 0 : 1;
		let sb = (b.stats && b.stats.suspended) ? 0 : 1;
		if (sa !== sb){ return sa - sb; }
		return (a.value || "").localeCompare(b.value || "");
	});

	$("whitelistCount").textContent = rules.length + " regra(s) de " + WL_TYPE_LABEL[wl_type].toLowerCase()
		+ (wl_selected.length > 0 ? " · " + wl_selected.length + " marcada(s)" : "");

	let all_on = rules.length > 0 && rules.every(function(rule){ return wl_selected.indexOf(rule.id) !== -1; });
	$("whitelistCheckAll").classList.toggle("on", all_on);
	show($("whitelistDeleteSelected"), wl_selected.length > 0);
	$("whitelistDeleteSelected").textContent = "Remover " + wl_selected.length + " marcada(s)";
	wl_render_composer_state();

	if (rules.length === 0 && !wl_data.loadError){
		container.appendChild(el("span", {className: "empty-note", text: "Nenhuma regra deste tipo."}));
		return;
	}

	for (let rule of rules){
		container.appendChild(wl_row(rule));
	}
}

// Simular compara a regra que está sendo escrita com os e-mails já analisados.
// Numa instalação nova esse histórico está vazio, e aí o botão só pode responder
// "não tenho com o que comparar" — que na tela se lê como defeito.
//
// Desabilitado com o motivo à vista, e não escondido: a régua deste projeto é
// esconder o que a pessoa nunca vai poder fazer (ação sem permissão), porque
// botão que responde 403 sugere um caminho que não existe. Aqui é o contrário —
// é um "ainda não", que se resolve sozinho na próxima análise. Escondido, a
// analista nunca descobriria que a simulação existe.
function wl_render_composer_state(){
	let history = (wl_data && wl_data.historyCount) || 0;
	let button = $("whitelistSimulateBtn");
	let hint = $("whitelistComposerHint");
	if (button == null || hint == null){ return; }

	button.disabled = history === 0;
	if (history === 0){
		button.title = "A simulação precisa de e-mails já analisados para comparar";
		hint.textContent = "Simular compara a regra com os e-mails já analisados. O histórico ainda "
			+ "está vazio, e começa a se encher na próxima análise. Ele guarda 90 dias.";
	} else {
		button.title = "Roda a regra contra os últimos 30 dias antes de salvar";
		hint.textContent = "Simular roda a regra contra " + history
			+ " análise(s) dos últimos 90 dias e mostra quantos alertas ela teria calado.";
	}
}

function wl_row(rule){
	let stats = rule.stats || {};
	let suspended = !!stats.suspended;

	let badges = [];
	if (suspended){
		badges.push(el("span", {className: "pill bad", text: "suspensa"}));
	} else if (!rule.enabled){
		badges.push(el("span", {className: "pill", text: "desligada"}));
	}
	if (rule.type === "sender" && rule.require_reply_to_alignment === false){
		badges.push(el("span", {className: "pill warn", text: "sem checar Reply-To"}));
	}
	if (rule.expires_at == null){
		badges.push(el("span", {className: "pill", text: "permanente"}));
	}

	let actions = [];
	if (suspended){
		actions.push(el("button", {className: "btn sm", text: "Religar", attrs: {type: "button"},
			onClick: function(){ wl_resume(rule); }}));
	}
	if (rule.expires_at != null){
		actions.push(el("button", {className: "btn quiet", text: "Renovar", attrs: {type: "button"},
			onClick: function(){ wl_renew(rule); }}));
	}
	if (stats.suppressionCount > 0){
		actions.push(el("button", {className: "btn quiet", text: "O que escondeu", attrs: {type: "button"},
			onClick: function(){ wl_show_suppressions(rule); }}));
	}
	actions.push(el("button", {className: "btn quiet", text: "Editar", attrs: {type: "button"},
		onClick: function(){ wl_start_edit(rule); }}));
	actions.push(el("button", {className: "btn danger", text: "Remover", attrs: {type: "button"},
		onClick: function(){ wl_confirm_delete(rule); }}));

	let counters = stats.suppressionsInWindow > 0
		? stats.suppressionsInWindow + " veredito(s) escondido(s) em " + (wl_data.windowDays || 30) + "d"
		: (stats.matchCount || 0) + " uso(s)";

	let checked = wl_selected.indexOf(rule.id) !== -1;
	let box = el("div", {className: "check" + (checked ? " on" : ""),
		style: "cursor:pointer;flex:0 0 auto"}, [icon(CHECK_ICON, 9)]);
	box.onclick = function(){ wl_toggle_selected(rule.id); };

	return el("div", {
		className: "tbl-row cols-wl",
		style: suspended ? "background:var(--danger-tint)" : ""
	}, [
		el("div", {className: "row", style: "gap:9px;min-width:0"}, [box,
		el("div", {className: "col", style: "gap:3px;min-width:0"}, [
			el("div", {className: "row", style: "gap:6px;flex-wrap:wrap;min-width:0"}, [
				el("span", {className: "mono truncate", text: rule.value, title: rule.value,
					style: "font-size:var(--fs-body);color:var(--t0)"})
			].concat(badges)),
			el("span", {
				className: "truncate",
				text: rule.reason || "sem motivo registrado",
				title: rule.reason || "",
				style: "font-size:var(--fs-micro);color:var(--t4)"
			}),
			suspended ? el("span", {
				className: "truncate",
				text: "Suspensa automaticamente: " + (stats.suspendedReason || "")
					+ ". Verifique se a caixa do remetente foi comprometida antes de religar.",
				style: "font-size:var(--fs-micro);color:var(--danger)"
			}) : null
		].filter(Boolean))]),
		el("span", {className: "pill " + wl_expiry_tone(rule), text: wl_expiry_label(rule)}),
		el("span", {className: "mono truncate", text: counters,
			style: "font-size:var(--fs-micro);color:" + (stats.suppressionsInWindow > 0 ? "var(--danger)" : "var(--t3)")}),
		el("span", {className: "mono truncate", text: rule.created_by || "-",
			style: "font-size:var(--fs-micro);color:var(--t3)"}),
		el("div", {className: "row", style: "gap:6px;justify-content:flex-end;flex-wrap:wrap"}, actions)
	]);
}

/* --- formulário ----------------------------------------------------------- */

function wl_render_form(){
	let host = $("whitelistFormFields");
	host.replaceChildren();

	if (wl_type === "url"){
		// Sem seletor de modo: regex é o único. O modo prefixo saiu da interface
		// porque dava duas formas de escrever a mesma coisa, e a que testava mal
		// era justamente a que parecia mais simples.
		host.appendChild(el("input", {className: "input mono", style: "flex:1 1 200px",
			attrs: {id: "wlHost", type: "text",
				placeholder: "regex do host — ex.: (nf|rh)\\.empresa\\.com\\.br"}}));
		host.appendChild(el("input", {className: "input mono", style: "flex:1 1 200px",
			attrs: {id: "wlPath", type: "text",
				placeholder: "regex do caminho — vazio = qualquer caminho"}}));
	} else {
		let placeholder = {
			sender: "faturamento@empresa.com.br",
			domain: "empresa.com.br ou *.empresa.com.br",
			hash: "SHA-256 do anexo (64 caracteres)",
			ip: "203.0.113.7 ou faixa 203.0.113.0/24"
		}[wl_type];
		host.appendChild(el("input", {className: "input mono", style: "flex:1 1 260px",
			attrs: {id: "wlValue", type: "text", placeholder: placeholder}}));
	}

	host.appendChild(el("input", {className: "input", style: "flex:1 1 200px",
		attrs: {id: "wlReason", type: "text", placeholder: "motivo (ex.: contrato AgenciaX #4711)"}}));

	// As três camadas de prazo. O padrão fica selecionado porque é o que impede
	// que a pressa do dia a dia produza regra eterna por acidente.
	let expiry = el("select", {className: "select", attrs: {id: "wlExpiryMode"}});
	for (let pair of [["", "Padrão (" + ((wl_data && wl_data.defaultTtlDays) || 180) + " dias)"],
			["date", "Escolher data"], ["never", "Permanente"]]){
		if (pair[0] === "never" && !(wl_data && wl_data.allowPermanent)){ continue; }
		let option = el("option", {text: pair[1]});
		option.value = pair[0];
		expiry.appendChild(option);
	}
	expiry.onchange = wl_toggle_expiry_fields;
	host.appendChild(el("span", {className: "select-wrap", style: "flex:0 0 170px"}, [expiry]));
	host.appendChild(el("input", {className: "input hidden", style: "flex:0 0 150px",
		attrs: {id: "wlExpiryDate", type: "date"}}));
	host.appendChild(el("input", {className: "input hidden", style: "flex:1 1 200px",
		attrs: {id: "wlPermanentReason", type: "text",
			placeholder: "justificativa da regra permanente (obrigatória)"}}));

	if (wl_type === "url"){ wl_render_tester(host); }
}

// Testador de padrão de URL. A avaliação é do servidor, não daqui: ele usa o
// mesmo normalizador e o mesmo fullmatch da análise, então o resultado na tela é
// o que vai acontecer na próxima mensagem. Um testador que diverge da produção
// dá uma confiança que não se sustenta, que é pior do que não ter testador.
function wl_render_tester(host){
	let box = el("div", {className: "col", style: "gap:8px;flex:1 1 100%;min-width:0"}, [
		el("div", {className: "row", style: "gap:8px;flex-wrap:wrap"}, [
			el("span", {text: "Testador", style: "font-size:var(--fs-body);font-weight:600;color:var(--t2)"}),
			el("span", {className: "grow"}),
			// Duas ações sobre a mesma caixa, e nessa ordem de propósito: cola-se
			// o endereço a liberar, pede-se a sugestão, e só então testa. Escrever
			// a regex à mão é onde nascem o ponto sem escapar e o `.*` frouxo
			el("button", {className: "btn quiet", text: "Sugerir regex", attrs: {type: "button"},
				title: "Deriva o padrão das URLs coladas e explica cada escolha",
				onClick: wl_suggest_url_pattern}),
			el("button", {className: "btn quiet", text: "Testar", attrs: {type: "button"},
				onClick: wl_test_url_pattern})
		]),
		el("textarea", {className: "input mono", style: "flex:1 1 100%;min-height:64px;resize:vertical",
			attrs: {id: "wlTestUrls", rows: "3",
				placeholder: "cole uma URL por linha — as que você quer liberar\nhttps://nf.empresa.com.br/relatorios/2026\nhttps://rh.empresa.com.br/relatorios/agosto"}}),
		el("div", {className: "col", style: "gap:4px", attrs: {id: "wlTestResults"}})
	]);
	host.appendChild(box);
}

// Pede o padrão ao servidor a partir das URLs coladas. Cada sugestão já volta
// testada contra as próprias URLs e contra as variantes de evasão, então a
// escolha é entre opções que já se sabe o que fazem.
function wl_suggest_url_pattern(){
	let results = $("wlTestResults");
	results.replaceChildren();
	results.appendChild(el("span", {text: "derivando o padrão…", style: "font-size:var(--fs-micro);color:var(--t4)"}));
	post_form("api/whitelist/url-suggest", {urls: $("wlTestUrls").value || ""}).then(function(result){
		wl_render_suggestions(result.ok ? result.data : null);
	});
}

function wl_apply_suggestion(suggestion){
	$("wlHost").value = suggestion.host_pattern;
	$("wlPath").value = suggestion.path_pattern;
	set_status("whitelistStatus", "Padrão " + suggestion.label.toLowerCase()
		+ " aplicado. Confira no testador antes de incluir.", "ok");
	wl_test_url_pattern();
}

function wl_render_suggestions(data){
	let results = $("wlTestResults");
	results.replaceChildren();
	if (data == null){
		results.appendChild(el("span", {className: "status bad", text: "Não foi possível sugerir o padrão."}));
		return;
	}
	if (data.error){
		results.appendChild(el("span", {className: "status bad", text: data.error}));
		return;
	}

	for (let problem of (data.problems || [])){
		results.appendChild(el("span", {className: "status bad", text: problem, style: "font-size:var(--fs-body)"}));
	}
	results.appendChild(el("span", {
		text: "Host(s) reconhecido(s): " + data.hosts.join(", "),
		style: "font-size:var(--fs-micro);color:var(--t3)"
	}));

	for (let suggestion of data.suggestions){
		let leaked = (suggestion.leaked || []).length > 0;
		let head = el("div", {className: "row", style: "gap:8px;flex-wrap:wrap;align-items:baseline"}, [
			el("span", {text: suggestion.label,
				style: "font-size:var(--fs-body);font-weight:600;color:var(--t0)"}),
			el("span", {text: suggestion.scope, style: "font-size:var(--fs-micro);color:var(--t4)"}),
			el("span", {className: "grow"}),
			suggestion.blocked ? null : el("button", {className: "btn quiet", text: "Usar este",
				attrs: {type: "button"}, onClick: function(){ wl_apply_suggestion(suggestion); }})
		].filter(Boolean));

		let body = [head,
			el("div", {className: "mono", style: "font-size:var(--fs-body);color:var(--t1);word-break:break-all"}, [
				el("span", {text: "host: " + suggestion.host_pattern}),
				el("br"),
				el("span", {text: "caminho: " + (suggestion.path_pattern || "(qualquer)")})
			])];

		if (suggestion.blocked){
			body.push(el("span", {className: "status bad", text: "Recusada: " + suggestion.blocked,
				style: "font-size:var(--fs-micro)"}));
		} else {
			body.push(el("span", {
				text: leaked
					? "Cobre " + suggestion.covered + "/" + suggestion.total
						+ " · VAZA: " + suggestion.leaked.join("; ")
					: "Cobre " + suggestion.covered + "/" + suggestion.total
						+ " · nenhuma variante de evasão passou",
				style: "font-size:var(--fs-body);font-weight:600;color:var(--" + (leaked ? "danger" : "ok") + ")"
			}));
		}

		for (let warning of (suggestion.warnings || [])){
			body.push(el("span", {className: "status bad", text: warning, style: "font-size:var(--fs-body)"}));
		}
		// O porquê fica visível, não atrás de um "saiba mais": é onde a pessoa
		// aprende por que o ponto vai escapado, e é isso que faz a próxima regra
		// escrita à mão sair certa
		for (let why of (suggestion.why || [])){
			body.push(el("span", {text: "· " + why,
				style: "font-size:var(--fs-micro);color:var(--t4);line-height:1.45"}));
		}

		results.appendChild(el("div", {className: "col",
			style: "gap:5px;padding:9px 10px;border:1px solid var(--b1);border-radius:8px;background:var(--s3)"},
			body));
	}
}

function wl_test_url_pattern(){
	let results = $("wlTestResults");
	results.replaceChildren();
	results.appendChild(el("span", {text: "testando…", style: "font-size:var(--fs-micro);color:var(--t4)"}));
	post_form("api/whitelist/url-test", {
		hostPattern: ($("wlHost").value || "").trim(),
		pathPattern: ($("wlPath").value || "").trim(),
		urls: $("wlTestUrls").value || ""
	}).then(function(result){
		wl_render_test_results(result.ok ? result.data : null);
	});
}

function wl_test_line(ok, text, detail, tone){
	let mark = icon(ok ? CHECK_ICON : CROSS_ICON, 11);
	mark.setAttribute("style", "flex:0 0 11px;color:var(--" + (tone || (ok ? "ok" : "t4")) + ")");
	return el("div", {className: "row", style: "gap:8px;align-items:center;min-width:0"}, [
		mark,
		el("span", {className: "mono truncate", text: text, title: text,
			style: "font-size:var(--fs-body);color:var(--t1);min-width:0"}),
		el("span", {className: "mono", text: detail || "",
			style: "font-size:var(--fs-micro);color:var(--t4);white-space:nowrap"})
	]);
}

function wl_render_test_results(data){
	let results = $("wlTestResults");
	results.replaceChildren();
	if (data == null){
		results.appendChild(el("span", {className: "status bad", text: "Não foi possível testar o padrão."}));
		return;
	}
	if (data.error){
		results.appendChild(el("span", {className: "status bad", text: data.error}));
		return;
	}

	for (let item of data.results){
		if (!item.readable){
			results.appendChild(wl_test_line(false, item.url, item.note, "danger"));
			continue;
		}
		// O host normalizado aparece sempre: é o que revela que
		// `empresa.com@evil.com` na verdade visita evil.com
		results.appendChild(wl_test_line(item.matched, item.url,
			"→ " + item.host + " " + item.target));
	}

	if (data.evasions && data.evasions.length > 0){
		let leaked = data.leaked > 0;
		results.appendChild(el("span", {
			text: leaked
				? "Este padrão vaza: " + data.leaked + " variante(s) de evasão também casaram."
				: "Nenhuma variante de evasão casou — o padrão está fechado.",
			style: "font-size:var(--fs-body);margin-top:6px;font-weight:600;color:var(--"
				+ (leaked ? "danger" : "ok") + ")"
		}));
		for (let item of data.evasions){
			if (!leaked && !item.matched){ continue; }
			results.appendChild(wl_test_line(!item.matched,
				item.url, item.matched ? "CASOU — " + item.label : "", item.matched ? "danger" : "ok"));
		}
	}

	for (let warning of (data.warnings || [])){
		results.appendChild(el("span", {className: "status bad", text: warning,
			style: "font-size:var(--fs-micro)"}));
	}
}

function wl_toggle_expiry_fields(){
	let mode = $("wlExpiryMode").value;
	$("wlExpiryDate").classList.toggle("hidden", mode !== "date");
	$("wlPermanentReason").classList.toggle("hidden", mode !== "never");
}

function wl_form_params(){
	let params = {
		type: wl_type,
		reason: ($("wlReason").value || "").trim(),
		expiresAt: ""
	};
	let mode = $("wlExpiryMode").value;
	if (mode === "never"){
		params.expiresAt = "never";
		params.permanentReason = ($("wlPermanentReason").value || "").trim();
	} else if (mode === "date"){
		params.expiresAt = $("wlExpiryDate").value;
	}
	if (wl_type === "url"){
		params.mode = "regex";
		params.hostPattern = ($("wlHost").value || "").trim();
		params.pathPattern = ($("wlPath").value || "").trim();
		params.value = "";
	} else {
		params.value = ($("wlValue").value || "").trim();
	}
	return params;
}

function wl_clear_form(){
	for (let id of ["wlValue", "wlHost", "wlPath", "wlReason", "wlPermanentReason", "wlExpiryDate", "wlTestUrls"]){
		let node = $(id);
		if (node){ node.value = ""; }
	}
	wl_editing = null;
	wl_memory_proposal = null;
	$("whitelistSaveBtn").textContent = "Incluir";
	$("whitelistCancelEdit").classList.add("hidden");
	wl_render_composer_state();
}

function wl_start_edit(rule){
	wl_type = rule.type;
	render_whitelist();
	wl_editing = rule.id;
	if (rule.type === "url"){
		$("wlHost").value = rule.host_pattern || "";
		$("wlPath").value = rule.path_pattern || "";
	} else {
		$("wlValue").value = rule.value || "";
	}
	$("wlReason").value = rule.reason || "";
	if (rule.expires_at == null){
		$("wlExpiryMode").value = "never";
		$("wlPermanentReason").value = rule.permanent_reason || "";
	} else {
		$("wlExpiryMode").value = "date";
		$("wlExpiryDate").value = String(rule.expires_at).substring(0, 10);
	}
	wl_toggle_expiry_fields();
	$("whitelistSaveBtn").textContent = "Salvar";
	$("whitelistCancelEdit").classList.remove("hidden");
	set_status("whitelistStatus", "Editando a regra " + rule.value + ".");
	// O compositor está acima da lista; sem isto, clicar em Editar numa regra da
	// terceira tela preencheria um formulário fora do campo de visão
	let composer = document.querySelector(".wl-composer");
	if (composer){ composer.scrollIntoView({behavior: "smooth", block: "nearest"}); }
}

/* --- chamadas ------------------------------------------------------------- */

function handle_whitelist_response(response, success_message){
	if (response == null){
		set_status("whitelistStatus", "Erro no servidor ao atualizar a whitelist.", "bad");
		return false;
	}
	if (response.error){
		set_status("whitelistStatus", response.error, "bad");
		return false;
	}
	// Aviso não impede, exige leitura: `google.com` cobre `sites.google.com`, e
	// recusar seria exagero enquanto deixar passar calado seria pior
	if (Array.isArray(response.warnings) && response.warnings.length > 0){
		ask({
			title: "Confirmar a regra",
			sub: "esta liberação é mais ampla do que parece",
			body: response.warnings.join(" "),
			confirmLabel: "Cadastrar assim mesmo",
			danger: true
		}, function(){
			wl_submit(true);
		});
		set_status("whitelistStatus", "");
		return false;
	}
	wl_data = response;
	render_whitelist();
	if (response.importSummary){
		let summary = response.importSummary;
		let text = success_message + " " + summary.added + " regra(s) incluída(s)";
		if (summary.refusedCount > 0){ text += ", " + summary.refusedCount + " recusada(s)"; }
		set_status("whitelistStatus", text + ".", summary.refusedCount > 0 ? "bad" : "ok");
	} else if (response.migrationReport){
		set_status("whitelistStatus", success_message, "ok");
		ask({
			title: "Migração concluída",
			sub: "whitelist v1 → v2",
			body: response.migrationReport,
			confirmLabel: "Entendi"
		}, function(){});
	} else if (success_message){
		set_status("whitelistStatus", success_message, "ok");
	}
	return true;
}

function load_whitelist(){
	get_json("api/whitelist").then(function(response){
		if (response == null){
			set_status("whitelistStatus", "Não foi possível carregar a whitelist.", "bad");
			return;
		}
		wl_data = response;
		render_whitelist();
	});
	// O contador de propostas pendentes aparece na aba antes de ela ser aberta
	if (current_identity && current_identity.canChangeSettings){ load_verdict_memory(); }
}

function whitelist_show_type(type){
	let memory = type === "memory";
	for (let node of document.querySelectorAll("[data-wl-tab]")){
		node.classList.toggle("active", node.dataset.wlTab === type);
	}
	// A aba Aprendido não é um tipo de regra: não tem compositor nem tabela
	show($("wlMemoryPanel"), memory);
	for (let node of document.querySelectorAll('[data-config-tab="whitelist"] .wl-composer, [data-config-tab="whitelist"] .wl-listbar, [data-config-tab="whitelist"] .tbl-scroll')){
		show(node, !memory);
	}
	if (memory){
		load_verdict_memory();
		return;
	}
	wl_type = type;
	wl_selected = [];
	wl_clear_form();
	set_status("whitelistStatus", "");
	render_whitelist();
}

/* --- memória de vereditos -------------------------------------------------- */

let wl_memory_proposal = null;
let memory_show_inactive = false;
let memory_rows = [];

function toggle_memory_inactive(){
	memory_show_inactive = !memory_show_inactive;
	$("wlMemoryAll").classList.toggle("on", memory_show_inactive);
	$("wlMemoryAll").setAttribute("aria-checked", memory_show_inactive ? "true" : "false");
	load_verdict_memory();
}

function load_verdict_memory(){
	set_status("wlMemoryStatus", "carregando…");
	get_json("api/verdict-memory" + (memory_show_inactive ? "?all=1" : "")).then(function(response){
		if (response == null || response.error){
			set_status("wlMemoryStatus", (response && response.error) || "Não foi possível ler a memória de vereditos.", "bad");
			return;
		}
		memory_rows = response.memories || [];
		render_verdict_memory();
	});
}

function memory_state(memory){
	if (memory.scope === "sender"){
		return {pending: ["proposta pendente", "warn"], accepted: ["virou regra", "ok"], dismissed: ["recusada", ""]}[memory.proposalStatus]
			|| [memory.proposalStatus, ""];
	}
	if (memory.revokedAt){ return ["revogada por " + (memory.revokedBy || "—"), ""]; }
	if (!memory.active){ return ["expirada", ""]; }
	if (memory.suspended){ return ["suspensa", "bad"]; }
	return ["ativa", "ok"];
}

function render_verdict_memory(){
	let box = $("wlMemoryRows");
	box.replaceChildren();
	let pending = memory_rows.filter(function(m){ return m.scope === "sender" && m.proposalStatus === "pending"; }).length;
	$("wlMemoryPending").textContent = pending ? String(pending) : "";
	set_status("wlMemoryStatus", memory_rows.length === 0
		? "Nenhuma liberação aprendida" + (memory_show_inactive ? "." : " em vigor.")
		: memory_rows.length + " liberação(ões)" + (pending ? " · " + pending + " proposta(s) de remetente aguardando decisão" : ""),
		pending ? "bad" : null);
	for (let memory of memory_rows){
		let state = memory_state(memory);
		let sender = memory.scope === "sender";
		let inactive = sender ? memory.proposalStatus !== "pending" : (!memory.active || memory.suspended);
		let actions = el("div", {className: "memory-actions"});
		if (sender && memory.proposalStatus === "pending"){
			let create = el("button", {className: "btn xs", type: "button", text: "Criar regra"});
			create.onclick = function(){ memory_create_rule(memory); };
			let dismiss = el("button", {className: "btn xs secondary", type: "button", text: "Recusar"});
			dismiss.onclick = function(){ memory_mutation(memory, "dismiss", "Recusar a proposta de " + memory.key); };
			actions.appendChild(create);
			actions.appendChild(dismiss);
		} else if (!sender && memory.active){
			let revoke = el("button", {className: "btn xs danger", type: "button", text: "Revogar"});
			revoke.onclick = function(){ memory_mutation(memory, "revoke", "Revogar a liberação da mensagem de " + (memory.recordRef || "um caso")); };
			actions.appendChild(revoke);
		}
		box.appendChild(el("div", {className: "memory-row" + (inactive ? " inactive" : "")}, [
			el("div", {className: "col", style: "gap:4px;min-width:0"}, [
				el("div", {className: "row", style: "gap:8px;flex-wrap:wrap"}, [
					el("span", {className: "pill", text: sender ? "REMETENTE" : "MENSAGEM IDÊNTICA"}),
					el("span", {className: "pill " + state[1], text: state[0]})
				]),
				// A chave de conteúdo é um resumo: mostrá-lo não diz nada a ninguém.
				// O que identifica a mensagem é o caso de onde a lição saiu
				el("span", {className: "memory-key" + (sender ? " mono" : ""),
					text: sender ? memory.key : "Cópias exatas da mensagem do caso " + (memory.recordRef || "(registro não guardado)")}),
				el("span", {className: "memory-meta", text: "por " + memory.by + " · " + format_iso(memory.at)
					+ (sender ? "" : " · " + memory.hits + " análise(s) rebaixada(s)"
						+ (memory.lastHitAt ? ", a última em " + format_iso(memory.lastHitAt) : "")
						+ (memory.expiresAt ? " · expira em " + format_iso(memory.expiresAt).split(" ")[0] : ""))})
			]),
			actions,
			el("p", {className: "memory-reason", text: memory.reason})
		]));
	}
}

function memory_mutation(memory, action, title){
	ask({
		title: title,
		sub: action === "revoke" ? "a próxima cópia desta mensagem volta a passar pelo pipeline sem desconto" : "o remetente não vira regra",
		body: "Motivo registrado na decisão original: " + (memory.reason || "—"),
		confirmLabel: action === "revoke" ? "Revogar" : "Recusar",
		danger: action === "revoke"
	}, function(){
		post_form("api/verdict-memory/" + memory.id + "/" + action, {}).then(function(result){
			let data = result && result.data;
			if (!result || !result.ok || !data || data.error){
				set_status("wlMemoryStatus", (data && data.error) || "Não foi possível concluir.", "bad");
				return;
			}
			toast(action === "revoke" ? "Liberação revogada." : "Proposta recusada.", "ok");
			load_verdict_memory();
		});
	});
}

// A proposta vira regra pelo compositor de sempre, com Simular à mão: o servidor
// só fecha a proposta se a regra salva for exatamente o remetente proposto
function memory_create_rule(memory){
	whitelist_show_type("sender");
	$("wlValue").value = memory.key;
	$("wlReason").value = "Proposta a partir do falso positivo corrigido por " + memory.by
		+ " (caso " + (memory.recordRef || "—") + "): " + (memory.reason || "");
	wl_memory_proposal = memory.id;
	wl_render_composer_state();
	set_status("whitelistStatus", "Proposta da memória de vereditos carregada. Simule antes de incluir.");
}

function wl_mutation(endpoint, params, success_message){
	return post_form(endpoint, params).then(function(result){
		let ok = handle_whitelist_response(result.ok ? result.data : null, success_message);
		if (ok){ wl_clear_form(); }
		return ok;
	});
}

function wl_submit(accept_warnings){
	let params = wl_form_params();
	if (accept_warnings){ params.acceptWarnings = "true"; }
	if (wl_memory_proposal != null && !wl_editing){ params.memoryProposalId = String(wl_memory_proposal); }
	if (wl_editing){
		params.id = wl_editing;
		let editing = wl_editing;
		wl_mutation("api/whitelist/rule/update", params, "Regra atualizada.").then(function(ok){
			if (!ok){ wl_editing = editing; }
		});
		return;
	}
	wl_mutation("api/whitelist/rule", params, "Regra cadastrada.");
}

function whitelist_add(){
	wl_submit(false);
}

function whitelist_cancel_edit(){
	wl_clear_form();
	set_status("whitelistStatus", "");
	render_whitelist();
}

// Roda a regra contra o histórico antes de ela existir. Uma regra que teria
// escondido quatro vereditos Malicious não deveria chegar a ser salva.
function whitelist_dry_run(){
	let params = wl_form_params();
	params.days = 30;
	set_status("whitelistStatus", "simulando…");
	post_form("api/whitelist/dry-run", params).then(function(result){
		let data = result.ok ? result.data : null;
		if (data == null){
			set_status("whitelistStatus", "Não foi possível simular a regra.", "bad");
			return;
		}
		if (data.error){
			set_status("whitelistStatus", data.error, "bad");
			return;
		}
		if (data.analyzed === 0){
			set_status("whitelistStatus", "Ainda não há histórico suficiente para simular.", "bad");
			return;
		}
		let text = "Nos últimos 30 dias: " + data.matched + " de " + data.analyzed
			+ " e-mail(s) teriam casado com esta regra";
		if (data.notSafe > 0){
			text += ", e " + data.notSafe + " deles NÃO eram Safe";
			ask({
				title: "Esta regra esconderia alertas",
				sub: data.notSafe + " veredito(s) não-Safe nos últimos 30 dias",
				body: text + ". Exemplos: " + data.samples.map(function(s){
					return s.verdict + " — " + (s.subject || s.from);
				}).join(" | "),
				confirmLabel: "Entendi"
			}, function(){});
		}
		set_status("whitelistStatus", text + ".", data.notSafe > 0 ? "bad" : "ok");
	});
}

function wl_renew(rule){
	wl_mutation("api/whitelist/rule/renew", {id: rule.id}, "Regra " + rule.value + " renovada.");
}

function wl_resume(rule){
	ask({
		title: "Religar a regra suspensa",
		sub: rule.value,
		body: "Esta regra foi suspensa porque escondeu vereditos que não eram Safe. "
			+ "Religue apenas depois de confirmar que a caixa do remetente não foi comprometida. "
			+ "A contagem recomeça do zero.",
		confirmLabel: "Religar",
		danger: true
	}, function(){
		wl_mutation("api/whitelist/rule/resume", {id: rule.id}, "Regra " + rule.value + " religada.");
	});
}

function wl_confirm_delete(rule){
	ask({
		title: "Remover a regra",
		sub: "a mudança vale a partir da próxima análise",
		body: "Remover a regra " + rule.value + "?",
		confirmLabel: "Remover",
		danger: true
	}, function(){
		wl_mutation("api/whitelist/rule/delete", {id: rule.id}, "Regra " + rule.value + " removida.");
	});
}

function wl_show_suppressions(rule){
	get_json("api/whitelist/rule/suppressions?id=" + encodeURIComponent(rule.id)).then(function(data){
		let rows = (data && data.suppressions) || [];
		ask({
			title: "O que esta regra escondeu",
			sub: rule.value,
			body: rows.length === 0 ? "Nenhum veredito escondido." : rows.map(function(row){
				return (row.occurredAt || "").substring(0, 16).replace("T", " ")
					+ " — " + row.originalVerdict + " — " + (row.subject || row.from);
			}).join("\n"),
			confirmLabel: "Fechar"
		}, function(){});
	});
}

function whitelist_export(){
	let link = el("a", {attrs: {href: "api/whitelist/export", download: "whitelist.json"}});
	document.body.appendChild(link);
	link.click();
	link.remove();
}

function whitelist_import(file_input){
	if (file_input.files.length === 0){ return; }
	let form_data = new FormData();
	form_data.append("file", file_input.files[0]);
	form_data.append("mode", $("whitelistImportMode").value);
	file_input.value = "";
	set_status("whitelistStatus", "Importando…");
	fetch("api/whitelist/import", {method: "POST", body: form_data})
		.then(function(r){ return r.ok ? r.json() : null; })
		.catch(function(){ return null; })
		.then(function(response){ handle_whitelist_response(response, "Importação concluída."); });
}

// Converte o whitelist.json antigo. Fica atrás de uma confirmação porque
// reescreve a base de liberações inteira.
function whitelist_migrate(){
	ask({
		title: "Migrar a whitelist do formato antigo",
		sub: "v1 → v2",
		body: "O arquivo atual é salvo como backup e as regras são convertidas. "
			+ "Endereços e expressões regulares do formato antigo NÃO são ligados sozinhos: "
			+ "eles aparecem no relatório para você revisar um a um.",
		confirmLabel: "Migrar",
		danger: true
	}, function(){
		set_status("whitelistStatus", "migrando…");
		wl_mutation("api/whitelist/migrate", {}, "Migração concluída.");
	});
}

/* ========================================================================== */
/* User management (global_admin only)                                        */
/* ========================================================================== */

const ROLE_LABEL = {analyst: "analyst", admin: "admin", global_admin: "global_admin"};

function load_users(){
	get_json("api/users").then(function(users){
		let container = $("usersRows");
		container.replaceChildren();
		if (!Array.isArray(users)){
			set_status("usersStatus", "Não foi possível carregar os usuários.", "bad");
			return;
		}

		for (let user of users){
			let select = el("select", {className: "select"});
			for (let role of ["analyst", "admin", "global_admin"]){
				let option = el("option", {text: ROLE_LABEL[role]});
				option.value = role;
				if (user.role === role){ option.selected = true; }
				select.appendChild(option);
			}
			select.onchange = function(){ set_user_role(user.id, select.value); };

			let actions = [];
			if (user.locked){
				actions.push(el("button", {className: "btn quiet", text: "Desbloquear", attrs: {type: "button"},
					onClick: function(){ unlock_user(user.id); }}));
			}
			// Conta que entra pelo Entra ID não tem senha para resetar: o botão
			// gravaria um hash que nada consome, e sugeriria uma recuperação que
			// não existe aqui — quem resolve isso é o provedor de identidade
			if (user.authSource !== "sso"){
				actions.push(el("button", {className: "btn quiet", text: "Resetar senha", attrs: {type: "button"},
					onClick: function(){ reset_user_password(user.id, user.username); }}));
			}
			// Telefone perdido ou trocado: este é o único caminho de volta. Só
			// aparece quando há o que zerar — numa conta que nunca configurou o
			// botão não faria nada, e sugeriria que faria
			if (user.mfaEnrolled){
				actions.push(el("button", {className: "btn quiet", text: "Resetar MFA", attrs: {type: "button"},
					onClick: function(){ reset_user_mfa(user.id, user.username); }}));
			}
			actions.push(el("button", {className: "btn danger", text: "Excluir", attrs: {type: "button"},
				onClick: function(){ delete_user(user.id, user.username); }}));

			container.appendChild(el("div", {className: "tbl-row cols-users"}, [
				el("div", {className: "row", style: "gap:10px;min-width:0"}, [
					el("div", {className: "avatar mono", text: user.username.substring(0, 2).toUpperCase()}),
					el("span", {className: "truncate", text: user.username, style: "font-size:var(--fs-body);font-weight:500"}),
					// De onde a conta se autentica muda o que dá para fazer com ela
					// nesta tela, então fica dito na própria linha
					user.authSource === "sso" ? el("span", {className: "pill", text: "SSO"}) : null
				].filter(Boolean)),
				el("span", {className: "select-wrap"}, [select]),
				// Bloqueio e segundo fator dividem a coluna: as duas coisas são
				// "em que estado esta conta está". O MFA pendente é dito em voz
				// alta porque uma conta sem ele é uma conta que ainda não
				// atravessou o login uma vez — quem administra precisa
				// distinguir isso de uma conta em uso
				el("div", {className: "row", style: "gap:6px;flex-wrap:wrap"}, [
					el("span", {
						className: "pill " + (user.locked ? "bad" : "ok"),
						text: user.locked ? "bloqueado até " + user.lockedUntil : "ativo"
					}),
					user.mfaEnrolled ? null : el("span", {className: "pill warn", text: "MFA pendente"})
				].filter(Boolean)),
				el("span", {className: "mono truncate", text: user.lastLogin || "nunca acessou",
					style: "font-size:var(--fs-micro);color:var(--t3)"}),
				el("div", {className: "row", style: "gap:7px;justify-content:flex-end"}, actions)
			]));
		}

		$("userCount").textContent = users.length + " usuário(s)";
		$("navUsersBadge").textContent = String(users.length);
		set_status("usersStatus", "");
	});
}

function users_mutation(promise, success_message){
	promise.then(function(result){
		if (!result.ok){
			set_status("usersStatus", (result.data && result.data.error) || "A operação falhou.", "bad");
			return;
		}
		set_status("usersStatus", success_message, "ok");
		toast(success_message, "ok");
		load_users();
	});
}

function open_user_modal(){
	$("newUserName").value = "";
	$("newUserPassword").value = "";
	$("newUserRole").value = "analyst";
	open_modal("userModal");
	window.setTimeout(function(){ $("newUserName").focus(); }, 30);
}

function create_user(){
	let username = $("newUserName").value.trim();
	let password = $("newUserPassword").value;
	let role = $("newUserRole").value;
	if (!username || password.length < 12){
		toast("Informe o usuário e uma senha de no mínimo 12 caracteres.", "bad");
		return;
	}
	close_modal();
	users_mutation(post_json("api/users", {username: username, password: password, role: role}),
		"Usuário " + username + " criado.");
}

function set_user_role(user_id, role){
	users_mutation(post_json("api/users/" + user_id + "/role", {role: role}), "Cargo atualizado.");
}

function unlock_user(user_id){
	users_mutation(post_json("api/users/" + user_id + "/unlock", {}), "Conta desbloqueada.");
}

// Zerar o segundo fator é a reposição de uma credencial, e a confirmação existe
// porque o efeito é irreversível dos dois lados: o segredo antigo não volta, e
// a pessoa fica sem entrar até parear um aplicativo de novo
function reset_user_mfa(user_id, username){
	ask({
		title: "Resetar MFA",
		sub: "o usuário terá de configurar o aplicativo autenticador de novo",
		body: "Zerar a verificação em duas etapas de " + username + "? Faça isto apenas quando tiver confirmado, por um canal que não seja esta plataforma, que foi essa pessoa que pediu.",
		confirmLabel: "Resetar MFA",
		danger: true
	}, function(){
		users_mutation(post_json("api/users/" + user_id + "/mfa/reset", {}),
			"MFA de " + username + " zerado.");
	});
}

// A global_admin resets somebody else's password without knowing the current one
function reset_user_password(user_id, username){
	ask({
		title: "Resetar senha",
		sub: "as sessões ativas do usuário são revogadas",
		label: "NOVA SENHA PARA " + username.toUpperCase(),
		type: "password",
		placeholder: "mínimo 12 caracteres",
		confirmLabel: "Resetar"
	}, function(new_password){
		users_mutation(post_json("api/users/change_password", {userId: user_id, newPassword: new_password}),
			"Senha de " + username + " redefinida.");
	});
}

function delete_user(user_id, username){
	ask({
		title: "Excluir usuário",
		sub: "esta ação não pode ser desfeita",
		body: "Excluir o usuário " + username + "?",
		confirmLabel: "Excluir",
		danger: true
	}, function(){
		users_mutation(
			fetch("api/users/" + user_id, {method: "DELETE"}).then(function(r){
				return r.json().then(function(d){ return {ok: r.ok, data: d}; })
					.catch(function(){ return {ok: r.ok, data: null}; });
			}).catch(function(){ return {ok: false, data: null}; }),
			"Usuário " + username + " excluído.");
	});
}

// Changing your own password always requires the current one, and revokes every
// active session (the server signs this one out too)
function change_own_password(){
	let current_password = $("currentPassword").value;
	let new_password = $("newPassword").value;
	let confirm_password = $("confirmPassword").value;
	if (new_password !== confirm_password){
		set_status("accountStatus", "As duas senhas novas não conferem.", "bad");
		return;
	}
	if (new_password.length < 12){
		set_status("accountStatus", "A nova senha precisa ter no mínimo 12 caracteres.", "bad");
		return;
	}
	$("changePasswordBtn").disabled = true;
	post_json("api/users/change_password", {currentPassword: current_password, newPassword: new_password})
		.then(function(result){
			$("changePasswordBtn").disabled = false;
			if (!result.ok){
				if (result.status === 429){
					set_status("accountStatus", "Tentativas demais em pouco tempo. Espere um minuto e tente de novo.", "bad");
					return;
				}
				set_status("accountStatus", (result.data && result.data.error) || "A operação falhou.", "bad");
				// Errar a senha atual vezes demais trava a conta e encerra a sessão
				if (result.data && result.data.reauthenticate){
					window.setTimeout(function(){ window.location.href = "login"; }, 2500);
				}
				return;
			}
			set_status("accountStatus", "Senha alterada. Encerrando a sessão…", "ok");
			window.setTimeout(function(){ window.location.href = "login"; }, 1200);
		});
}

/* ========================================================================== */
/* AI chat                                                                    */
/* ========================================================================== */

// State of the AI chat: the loaded case reference and the conversation history
// (sent back to the server so the LLM keeps the conversational context)
let chat_case_ref = null;
let chat_history = [];
// Whether this conversation has already told the analyst that the case carries
// prompt injection markers. Once per loaded case: repeated on every turn, the
// warning turns into furniture and stops being read
let chat_injection_warned = false;

const CHAT_ROLE_LABEL = {user: "ANALISTA", assistant: "IA", warn: "ALERTA", info: "CONTEXTO"};

const CHAT_SUGGESTIONS = [
	"Quais links parecem suspeitos?",
	"Resuma as táticas de engenharia social.",
	"Que ações de remediação você recomenda?"
];

function chat_append(role, text){
	let bubble = el("div", {className: "bubble"}, [
		el("span", {className: "bubble-role", text: CHAT_ROLE_LABEL[role] || "CONTEXTO"}),
		el("p", {className: "bubble-text", text: text})
	]);
	$("chatThread").appendChild(el("div", {className: "chat-row " + role}, [bubble]));
	$("chatMessages").scrollTop = $("chatMessages").scrollHeight;
	return bubble.lastChild;
}

function chat_set_busy(busy){
	$("chatLoadBtn").disabled = busy;
	$("chatSendBtn").disabled = busy || chat_case_ref == null;
	$("chatQuestionInput").disabled = busy || chat_case_ref == null;
}

function render_chat_suggestions(){
	let dock = $("chatSuggestions");
	dock.replaceChildren();
	if (chat_case_ref == null){ return; }
	for (let text of CHAT_SUGGESTIONS){
		dock.appendChild(el("button", {className: "chip", text: text, attrs: {type: "button"},
			onClick: function(){ $("chatQuestionInput").value = text; chat_send(); }}));
	}
}

function chat_scope_rows(rows){
	let container = $("chatScopeRows");
	container.replaceChildren();
	for (let [label, value] of rows){
		container.appendChild(el("div", {className: "row baseline", style: "gap:10px"}, [
			el("span", {text: label, style: "font-size:var(--fs-micro);color:var(--t4);flex:0 0 auto"}),
			el("span", {className: "mono truncate push", text: value, style: "font-size:var(--fs-micro);color:var(--t1);text-align:right"})
		]));
	}
}

// GET api/chat/load/<ref> — loads the analyzed email (body, IOCs, verdict) of the
// case on the server so the following questions are answered with that context
function chat_load_context(){
	let case_ref = $("chatCaseInput").value.trim();
	if (case_ref === ""){
		set_status("chatContextStatus", "Informe o número ou o id do caso.", "bad");
		return;
	}
	chat_set_busy(true);
	set_status("chatContextStatus", "Carregando o contexto do caso…");

	get_json("api/chat/load/" + encodeURIComponent(case_ref)).then(function(response){
		chat_set_busy(false);
		if (response == null || response.error){
			chat_case_ref = null;
			chat_set_busy(false);
			$("chatScopeRows").replaceChildren();
			set_status("chatContextStatus", (response && response.error) || "Não foi possível carregar o contexto do caso.", "bad");
			return;
		}
		chat_case_ref = case_ref;
		chat_history = [];
		$("chatThread").replaceChildren();
		chat_set_busy(false);

		$("chatTitle").textContent = "Chat AI · " + response.label;
		$("chatSubtitle").textContent = response.title;
		show($("chatLockPill"), true);
		show($("chatClearBtn"), true);
		$("chatScopeDot").className = "dot ok";
		let verdict = VERDICT_LABEL[response.verdict] || response.verdict;
		chat_scope_rows([
			["Registro", response.label],
			["Veredito", verdict],
			["Observáveis", String(response.observableCount)],
			["Corpo do e-mail", response.hasBody ? "disponível" : "indisponível"]
		]);
		set_status("chatContextStatus", response.label + " carregado.", "ok");
		chat_append("info", "Contexto carregado: " + response.label + " — \"" + response.title
			+ "\" (" + verdict + ", " + response.observableCount + " observáveis). Pergunte o que quiser sobre este e-mail.");
		render_chat_suggestions();
		$("chatQuestionInput").focus();
	});
}

function chat_clear_context(){
	chat_case_ref = null;
	chat_history = [];
	chat_injection_warned = false;
	$("chatThread").replaceChildren();
	$("chatScopeRows").replaceChildren();
	$("chatScopeDot").className = "dot";
	$("chatTitle").textContent = "Chat AI";
	$("chatSubtitle").textContent = "carregue um caso para começar";
	show($("chatLockPill"), false);
	show($("chatClearBtn"), false);
	set_status("chatContextStatus", "Nenhum caso carregado.");
	render_chat_suggestions();
	chat_set_busy(false);
}

// POST api/chat/message
function chat_send(){
	let question = $("chatQuestionInput").value.trim();
	if (question === "" || chat_case_ref == null || $("chatSendBtn").disabled){ return; }
	$("chatQuestionInput").value = "";
	chat_append("user", question);
	let thinking = chat_append("assistant", "Pensando…");
	chat_set_busy(true);

	post_form("api/chat/message", {
		caseRef: chat_case_ref,
		question: question,
		history: JSON.stringify(chat_history)
	}).then(function(result){
		chat_set_busy(false);
		let response = result.ok ? result.data : null;
		if (response == null || response.error){
			thinking.textContent = "Erro: " + ((response && response.error)
				|| "a IA não respondeu. Verifique as configurações do modelo e tente de novo.");
		} else {
			thinking.textContent = response.answer;
			/* The case tried to steer the model. The analyst is reading an answer
			 * about an e-mail written to manipulate whoever analyses it, so the
			 * warning belongs next to the answer and not only in the server log.
			 * Said once per conversation: a banner on every turn stops being read. */
			if ((response.injectionDetected || []).length && !chat_injection_warned){
				chat_injection_warned = true;
				chat_append("warn", "Atenção: este caso contém marcadores de prompt injection ("
					+ response.injectionDetected.join(", ") + "). O e-mail tenta manipular a análise; "
					+ "leia as respostas da IA com esse contexto.");
			}
			chat_history.push({role: "user", content: question});
			chat_history.push({role: "assistant", content: response.answer});
			// Keep only the most recent exchanges to bound the context size
			if (chat_history.length > 12){ chat_history = chat_history.slice(-12); }
		}
		$("chatMessages").scrollTop = $("chatMessages").scrollHeight;
		$("chatQuestionInput").focus();
	});
}

/* ========================================================================== */
/* Auditoria                                                                  */
/*                                                                            */
/* A trilha de data/auth.log, lida de volta. O estado da tela vive em dois     */
/* objetos: audit_state (filtros, página, o que o servidor devolveu) e          */
/* audit_ai (a conversa com o assistente). Toda mudança de filtro passa por     */
/* audit_state.filters e termina em load_audit(), que é o único que pede dados; */
/* os renders só leem o estado. Os filtros são aplicados no servidor — o        */
/* navegador nunca recebe a trilha inteira, só a página que vai mostrar.        */
/* ========================================================================== */

const AUDIT_PAGE_SIZE = 50;
// A janela que o servidor injeta no assistente (audit_trail.ASSISTANT_WINDOW_DAYS)
const AUDIT_AI_DAYS = 7;

const AUDIT_DEFAULT_FILTERS = {user: "", email: "", event: "", outcome: "", q: "", range: "7d", from: "", to: ""};

let audit_state = {
	filters: Object.assign({}, AUDIT_DEFAULT_FILTERS),
	offset: 0,
	total: 0,
	window_total: 0,
	rows: [],
	facets: {events: [], users: []},
	malformed: 0,
	has_log: true,
	oldest: null,
	loading: false,
	loaded: false,
	error: null,
	expanded: null,
	// Número da requisição em voo. Digitar rápido dispara várias; só a última
	// pode pintar a tabela, senão uma resposta lenta sobrescreve a mais nova
	seq: 0
};

let audit_ai = {
	open: null,          // null = ainda não decidido (decide pela largura na 1ª abertura)
	history: [],
	busy: false,
	context: null,
	context_loading: false,
	injection_warned: false,
	asked: false
};

// O nome que a tela mostra para cada evento que auth.audit() grava. Um evento
// que não está aqui aparece com o nome cru — nunca some da tabela por falta de
// tradução
const AUDIT_EVENT_LABEL = {
	login: "Login",
	logout: "Saída",
	session_expired: "Sessão expirada",
	session_revoked: "Sessão revogada",
	authorization_denied: "Acesso negado",
	mfa_gate: "Barreira do MFA",
	mfa_setup: "MFA: cadastro",
	mfa_activate: "MFA: ativação",
	mfa_verify: "MFA: verificação",
	mfa_reset: "MFA zerado",
	sso_login: "Login SSO",
	user_create: "Usuário criado",
	user_delete: "Usuário excluído",
	user_role_change: "Cargo alterado",
	user_unlock: "Conta desbloqueada",
	password_change: "Troca de senha",
	config_change: "Requisição de alteração",
	smtp_update: "SMTP alterado",
	case_evidence_update: "Guarda de originais",
	departments_update: "Departamentos",
	sso_config_update: "SSO alterado",
	scoring_update: "Score alterado",
	whitelist_rule_create: "Whitelist: regra criada",
	whitelist_rule_update: "Whitelist: regra editada",
	whitelist_rule_delete: "Whitelist: regra excluída",
	whitelist_rule_renew: "Whitelist: regra renovada",
	whitelist_rule_resume: "Whitelist: regra retomada",
	whitelist_import: "Whitelist importada",
	whitelist_migrate: "Whitelist migrada",
	custom_analyzer_create: "Analisador criado",
	custom_analyzer_update: "Analisador editado",
	custom_analyzer_delete: "Analisador excluído",
	custom_analyzer_test: "Analisador testado",
	responder_update: "Destino de bloqueio",
	responder_test: "Destino de bloqueio testado",
	ticket_destination_update: "Destino de registro",
	ticket_destination_test: "Destino de registro testado",
	connector_create: "Conector criado",
	connector_update: "Conector editado",
	connector_delete: "Conector excluído",
	connector_test: "Conector testado",
	volume_alerts_update: "Alerta de volume",
	alert_connector_create: "Webhook de alerta criado",
	alert_connector_update: "Webhook de alerta editado",
	alert_connector_delete: "Webhook de alerta excluído",
	alert_connector_test: "Webhook de alerta testado",
	indicator_block: "Indicador bloqueado",
	case_reanalyze: "Caso reanalisado",
	case_reclassify: "Caso reclassificado",
	case_reclassify_revert: "Reclassificação desfeita",
	verdict_memory_learn: "Memória: lição aprendida",
	verdict_memory_revoke: "Memória: lição revogada",
	verdict_memory_dismiss: "Memória: proposta recusada",
	audit_export: "Trilha exportada",
	audit_assistant: "Assistente de auditoria"
};

const AUDIT_OUTCOME = {
	ok: {label: "sucesso", tone: "ok"},
	fail: {label: "falha", tone: "bad"},
	denied: {label: "recusado", tone: "bad"},
	other: {label: "", tone: "muted"}
};

// Os status que não são sucesso nem falha — a razão de uma sessão acabar, um
// passo do login — ditos em português em vez do identificador cru
const AUDIT_STATUS_LABEL = {
	idle: "inatividade",
	absolute: "tempo máximo",
	tab_closed: "aba fechada",
	password_changed: "senha trocada",
	mfa_required: "pediu MFA",
	pending: "pendente",
	already: "já estava"
};

const AUDIT_RANGE_LABEL = {"1d": "últimas 24h", "7d": "últimos 7 dias", "30d": "últimos 30 dias", "90d": "últimos 90 dias", all: "toda a trilha"};

const AUDIT_AI_SUGGESTIONS = [
	"Houve logins com falha nesta semana? De quais contas e IPs?",
	"O que cada administrador alterou nos últimos 7 dias?",
	"Alguma ação fora do horário comercial?",
	"Algum IP novo para uma conta que já existia?"
];

function audit_event_label(name){
	return AUDIT_EVENT_LABEL[name] || name || "—";
}

function audit_status_text(row){
	let outcome = AUDIT_OUTCOME[row.outcome] || AUDIT_OUTCOME.other;
	return outcome.label || AUDIT_STATUS_LABEL[row.status] || row.status || "—";
}

// "2026-09-24 14:02:11" -> Date local. O servidor escreve no horário local
// dele, sem fuso; a tela mostra o mesmo relógio, sem converter
function audit_parse_at(text){
	let match = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(text || "");
	if (!match){ return null; }
	return new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5], +match[6]);
}

function audit_day_label(date){
	let today = new Date();
	let yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
	let same = function(a, b){ return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate(); };
	let full = date.toLocaleDateString("pt-BR", {weekday: "long", day: "2-digit", month: "long", year: "numeric"});
	if (same(date, today)){ return "Hoje · " + full; }
	if (same(date, yesterday)){ return "Ontem · " + full; }
	return full.charAt(0).toUpperCase() + full.slice(1);
}

function audit_short_date(text){
	let date = audit_parse_at(text);
	return date ? date.toLocaleString("pt-BR", {day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"}) : (text || "—");
}

function audit_params(include_page){
	let filters = audit_state.filters;
	let params = new URLSearchParams();
	for (let key of ["user", "email", "event", "outcome", "q"]){
		if (filters[key]){ params.set(key, filters[key]); }
	}
	if (filters.from || filters.to){
		if (filters.from){ params.set("from", filters.from); }
		if (filters.to){ params.set("to", filters.to); }
	} else if (filters.range && filters.range !== "all"){
		params.set("range", filters.range);
	}
	if (include_page){
		params.set("limit", String(AUDIT_PAGE_SIZE));
		params.set("offset", String(audit_state.offset));
	}
	return params.toString();
}

function audit_filters_active(){
	let filters = audit_state.filters;
	return !!(filters.user || filters.email || filters.event || filters.outcome || filters.q
		|| filters.from || filters.to || filters.range !== AUDIT_DEFAULT_FILTERS.range);
}

// GET api/audit — a única função desta tela que busca a trilha
function load_audit(){
	let seq = ++audit_state.seq;
	audit_state.loading = true;
	audit_state.error = null;
	render_audit_rows();
	get_json("api/audit?" + audit_params(true)).then(function(response){
		if (seq !== audit_state.seq){ return; }
		audit_state.loading = false;
		audit_state.loaded = true;
		if (response == null || response.error){
			audit_state.error = (response && response.error) || "Não foi possível ler a trilha de auditoria.";
			audit_state.rows = [];
			audit_state.total = 0;
		} else {
			audit_state.rows = response.entries || [];
			audit_state.total = response.total || 0;
			audit_state.window_total = response.windowTotal || 0;
			audit_state.facets = response.facets || {events: [], users: []};
			audit_state.malformed = response.malformed || 0;
			audit_state.has_log = response.hasLog !== false;
			audit_state.oldest = response.oldest || null;
			// Uma página além do fim (o filtro encolheu o resultado) volta ao início
			if (audit_state.rows.length === 0 && audit_state.offset > 0 && audit_state.total > 0){
				audit_state.offset = 0;
				load_audit();
				return;
			}
		}
		audit_state.expanded = null;
		render_audit();
	});
}

function reload_audit(){
	load_audit();
	if (audit_ai.open){ load_audit_ai_context(); }
}

function render_audit(){
	render_audit_filters();
	render_audit_summary();
	render_audit_rows();
	render_audit_pager();
}

// Os controles refletem o estado — nunca o contrário. É o que deixa "Filtrar
// por este usuário", vindo de uma linha, aparecer no campo de cima
function render_audit_filters(){
	let filters = audit_state.filters;
	for (let [id, key] of [["auditUser", "user"], ["auditEmail", "email"], ["auditQuery", "q"], ["auditFrom", "from"], ["auditTo", "to"]]){
		let input = $(id);
		if (input && input.value !== filters[key] && document.activeElement !== input){ input.value = filters[key]; }
	}
	$("auditOutcome").value = filters.outcome;

	let select = $("auditEvent");
	let events = (audit_state.facets.events || []).slice().sort(function(a, b){
		return audit_event_label(a.event).localeCompare(audit_event_label(b.event), "pt-BR");
	});
	select.replaceChildren(el("option", {text: "Todos os eventos", attrs: {value: ""}}));
	let present = false;
	for (let item of events){
		let option = el("option", {text: audit_event_label(item.event) + " (" + item.count + ")", attrs: {value: item.event}});
		select.appendChild(option);
		if (item.event === filters.event){ present = true; }
	}
	// Um evento escolhido que não acontece no período continua selecionado — some
	// da lista só o que ninguém escolheu
	if (filters.event && !present){
		select.appendChild(el("option", {text: audit_event_label(filters.event) + " (0)", attrs: {value: filters.event}}));
	}
	select.value = filters.event;

	let list = $("auditUserList");
	list.replaceChildren();
	for (let name of audit_state.facets.users || []){
		list.appendChild(el("option", {attrs: {value: name}}));
	}

	let custom = !!(filters.from || filters.to);
	for (let chip of $$("#auditRanges .chip")){
		let on = !custom && chip.dataset.arg === filters.range;
		chip.classList.toggle("active", on);
		chip.setAttribute("aria-pressed", on ? "true" : "false");
	}
	show($("auditClearBtn"), audit_filters_active());
}

function audit_period_text(){
	let filters = audit_state.filters;
	let day = function(value){ let date = audit_parse_at(value + " 00:00:00"); return date ? date.toLocaleDateString("pt-BR") : value; };
	if (filters.from && filters.to){ return "de " + day(filters.from) + " a " + day(filters.to); }
	if (filters.from){ return "desde " + day(filters.from); }
	if (filters.to){ return "até " + day(filters.to); }
	return AUDIT_RANGE_LABEL[filters.range] || "toda a trilha";
}

// A frase de cima diz o que a tabela está mostrando, com os filtros por
// extenso: com cinco filtros combináveis, "143 registros" sozinho não diz de quê
function render_audit_summary(){
	let box = $("auditSummary");
	box.replaceChildren();
	let filters = audit_state.filters;
	let period = audit_period_text();
	$("auditSub").textContent = audit_state.loaded
		? (audit_state.has_log
			? audit_state.window_total.toLocaleString("pt-BR") + " registros · " + period
				+ (audit_state.oldest ? " · trilha desde " + audit_short_date(audit_state.oldest) : "")
			: "a trilha ainda está vazia")
		: "carregando…";
	if (!audit_state.loaded || audit_state.error || !audit_state.has_log){ return; }

	let parts = [];
	if (filters.user){ parts.push(["usuário", filters.user]); }
	if (filters.email){ parts.push(["e-mail", filters.email]); }
	if (filters.event){ parts.push(["evento", audit_event_label(filters.event)]); }
	if (filters.outcome){ parts.push(["resultado", (AUDIT_OUTCOME[filters.outcome].label || "outro")]); }
	if (filters.q){ parts.push(["contém", filters.q]); }

	let line = el("p", {className: "audit-summary-line"});
	line.appendChild(el("strong", {text: audit_state.total.toLocaleString("pt-BR")}));
	line.appendChild(document.createTextNode(audit_state.total === 1 ? " registro" : " registros"));
	if (parts.length){
		line.appendChild(document.createTextNode(" de " + audit_state.window_total.toLocaleString("pt-BR") + " no período, com "));
		parts.forEach(function(part, index){
			if (index > 0){ line.appendChild(document.createTextNode(index === parts.length - 1 ? " e " : ", ")); }
			line.appendChild(document.createTextNode(part[0] + " "));
			line.appendChild(el("span", {className: "audit-token", text: part[1]}));
		});
	} else {
		line.appendChild(document.createTextNode(" · " + period));
	}
	box.appendChild(line);

	// Uma linha que não se deixa ler não é escondida: a trilha pode ter sido
	// corrompida, ou alguém tentou escrever um registro falso nela
	if (audit_state.malformed > 0){
		box.appendChild(el("p", {className: "audit-summary-warn",
			text: audit_state.malformed + (audit_state.malformed === 1
				? " linha da trilha está fora do formato e não aparece na tabela."
				: " linhas da trilha estão fora do formato e não aparecem na tabela.")
				+ " Pode ser corrupção do arquivo ou tentativa de forjar um registro — confira data/auth.log no servidor."}));
	}
}

function render_audit_rows(){
	let container = $("auditRows");
	container.replaceChildren();
	container.setAttribute("aria-busy", audit_state.loading ? "true" : "false");

	if (audit_state.loading && audit_state.rows.length === 0){
		for (let i = 0; i < 8; i++){
			container.appendChild(el("div", {className: "tbl-row cols-audit audit-skeleton", attrs: {"aria-hidden": "true"}},
				[1, 2, 3, 4, 5, 6, 7].map(function(){ return el("span", {className: "skel"}); })));
		}
		return;
	}
	container.classList.toggle("audit-stale", audit_state.loading);

	if (audit_state.error){
		container.appendChild(el("div", {className: "tbl-empty"}, [
			el("p", {className: "audit-empty-title", text: audit_state.error}),
			el("button", {className: "btn quiet sm", text: "Tentar de novo", attrs: {type: "button"}, onClick: load_audit})
		]));
		return;
	}
	if (!audit_state.has_log){
		container.appendChild(el("div", {className: "tbl-empty"}, [
			el("p", {className: "audit-empty-title", text: "A trilha de auditoria ainda não tem registros."}),
			el("p", {className: "audit-empty-note", text: "Ela começa no primeiro login e registra cada entrada, cada falha e cada alteração de configuração, em data/auth.log."})
		]));
		return;
	}
	if (audit_state.rows.length === 0){
		container.appendChild(el("div", {className: "tbl-empty"}, [
			el("p", {className: "audit-empty-title", text: "Nenhum registro com estes filtros."}),
			el("p", {className: "audit-empty-note", text: "Os filtros se somam: cada um estreita o resultado dos outros. Amplie o período ou tire um filtro."}),
			audit_filters_active() ? el("button", {className: "btn quiet sm", text: "Limpar filtros", attrs: {type: "button"}, onClick: audit_clear_filters}) : null
		].filter(Boolean)));
		return;
	}

	let last_day = null;
	audit_state.rows.forEach(function(row, index){
		let date = audit_parse_at(row.at);
		let day = date ? row.at.slice(0, 10) : "";
		if (day !== last_day){
			last_day = day;
			container.appendChild(el("div", {className: "audit-day", attrs: {role: "presentation"}, text: date ? audit_day_label(date) : "Data ilegível"}));
		}
		container.appendChild(audit_row(row, index));
		if (audit_state.expanded === index){ container.appendChild(audit_row_detail(row)); }
	});
}

function audit_row(row, index){
	let outcome = AUDIT_OUTCOME[row.outcome] || AUDIT_OUTCOME.other;
	let expanded = audit_state.expanded === index;

	let who;
	if (row.actor){
		who = el("span", {className: "audit-who"}, [
			el("button", {className: "audit-link truncate", text: row.actor, title: "Filtrar por " + row.actor,
				attrs: {type: "button"}, onClick: function(event){ event.stopPropagation(); audit_filter_user(row.actor); }}),
			row.actorRole ? el("span", {className: "audit-role mono", text: row.actorRole}) : null
		].filter(Boolean));
	} else {
		who = el("span", {className: "audit-anon", text: "anônimo", title: "Ninguém autenticado — um login que falhou, por exemplo"});
	}

	let node = el("div", {
		className: "tbl-row cols-audit audit-row" + (expanded ? " open" : "") + (row.outcome === "fail" || row.outcome === "denied" ? " flagged" : ""),
		attrs: {role: "row", tabindex: "0", "aria-expanded": expanded ? "true" : "false"},
		onClick: function(){ audit_toggle_row(index); }
	}, [
		el("span", {className: "mono audit-time", text: row.at ? row.at.slice(11) : "—", title: row.at}),
		el("span", {className: "audit-event truncate", text: audit_event_label(row.event), title: row.event}),
		el("span", {}, [el("span", {className: "pill " + outcome.tone, text: audit_status_text(row), title: "status=" + row.status})]),
		who,
		el("span", {className: "mono truncate audit-dim", text: row.target || "—", title: row.target}),
		el("span", {className: "mono truncate audit-dim", text: row.ip || "—"}),
		el("span", {className: "mono truncate audit-dim", text: row.detail || "—", title: row.detail})
	]);
	node.addEventListener("keydown", function(event){
		if (event.target !== node){ return; }
		if (event.key === "Enter" || event.key === " "){
			event.preventDefault();
			audit_toggle_row(index);
		}
	});
	return node;
}

// O registro inteiro, sem corte, e o que dá para fazer a partir dele
function audit_row_detail(row){
	let pairs = [
		["Quando", row.at || "—"],
		["Evento", audit_event_label(row.event) + (AUDIT_EVENT_LABEL[row.event] ? "  ·  " + row.event : "")],
		["Status", row.status || "—"],
		["Quem", row.actor ? row.actor + (row.actorRole ? " (" + row.actorRole + ")" : "") : "anônimo"],
		["IP", row.ip || "—"],
		["Alvo", row.target || "—"],
		["Detalhe", row.detail || "—"]
	];
	if (row.emails && row.emails.length){ pairs.push(["E-mails", row.emails.join(", ")]); }

	let grid = el("dl", {className: "audit-kv"});
	for (let [key, value] of pairs){
		grid.appendChild(el("dt", {text: key}));
		grid.appendChild(el("dd", {className: key === "Evento" || key === "Quem" ? "" : "mono", text: value}));
	}

	let actions = [];
	if (row.actor){
		actions.push(el("button", {className: "btn quiet xs", text: "Só registros de " + row.actor, attrs: {type: "button"},
			onClick: function(){ audit_filter_user(row.actor); }}));
	}
	if (row.ip){
		actions.push(el("button", {className: "btn quiet xs", text: "Só deste IP", attrs: {type: "button"},
			onClick: function(){ audit_set_filter("q", row.ip); }}));
	}
	if (row.event){
		actions.push(el("button", {className: "btn quiet xs", text: "Só este evento", attrs: {type: "button"},
			onClick: function(){ audit_set_filter("event", row.event); }}));
	}
	let date = audit_parse_at(row.at);
	let in_window = date && (Date.now() - date.getTime()) <= AUDIT_AI_DAYS * 86400000;
	actions.push(el("button", {
		className: "btn secondary xs",
		text: "Perguntar ao assistente",
		title: in_window ? "" : "O assistente só lê os últimos " + AUDIT_AI_DAYS + " dias",
		attrs: in_window ? {type: "button"} : {type: "button", disabled: "disabled"},
		onClick: function(){ audit_ai_ask_about(row); }
	}));
	actions.push(el("button", {className: "btn quiet xs", text: "Copiar linha", attrs: {type: "button"},
		onClick: function(){
			copy_to_clipboard([row.at, "event=" + row.event, "status=" + row.status, "ip=" + (row.ip || "-"),
				"actor=" + (row.actor ? row.actor + "(" + row.actorRole + ")" : "-"), "target=" + (row.target || "-"),
				"detail=" + row.detail].join(" "), "Registro copiado.");
		}}));

	return el("div", {className: "audit-expand", attrs: {role: "region", "aria-label": "Registro completo"}}, [
		grid,
		el("div", {className: "row audit-expand-actions"}, actions)
	]);
}

function audit_toggle_row(index){
	audit_state.expanded = audit_state.expanded === index ? null : index;
	render_audit_rows();
	let rows = $$("#auditRows .audit-row");
	let target = rows[index];
	if (target){ target.focus({preventScroll: true}); }
}

function render_audit_pager(){
	let total = audit_state.total;
	let first = total ? audit_state.offset + 1 : 0;
	let last = Math.min(audit_state.offset + AUDIT_PAGE_SIZE, total);
	$("auditPagerLabel").textContent = total
		? first.toLocaleString("pt-BR") + "–" + last.toLocaleString("pt-BR") + " de " + total.toLocaleString("pt-BR") + " · mais novos primeiro"
		: "";
	$("auditPrevBtn").disabled = audit_state.offset === 0;
	$("auditNextBtn").disabled = audit_state.offset + AUDIT_PAGE_SIZE >= total;
}

function audit_page(direction){
	let next = audit_state.offset + (direction === "next" ? AUDIT_PAGE_SIZE : -AUDIT_PAGE_SIZE);
	if (next < 0 || next >= audit_state.total){ return; }
	audit_state.offset = next;
	$("auditScroll").scrollTop = 0;
	load_audit();
}

// --- Mudanças de filtro -------------------------------------------------------
// Todas terminam no mesmo lugar: estado atualizado, página zerada, nova leitura

function audit_set_filter(key, value){
	audit_state.filters[key] = value;
	audit_state.offset = 0;
	render_audit_filters();
	load_audit();
}

let audit_text_timer = null;
function audit_filter_text(element){
	let key = element.dataset.filter;
	audit_state.filters[key] = element.value.trim();
	audit_state.offset = 0;
	show($("auditClearBtn"), audit_filters_active());
	window.clearTimeout(audit_text_timer);
	audit_text_timer = window.setTimeout(load_audit, 280);
}

function audit_filter_select(element){
	audit_set_filter(element.dataset.filter, element.value);
}

// Uma data digitada substitui o atalho de período; as duas coisas juntas seriam
// dois períodos, e o intervalo é sempre o mais específico
function audit_filter_date(element){
	audit_state.filters[element.dataset.filter] = element.value;
	audit_state.offset = 0;
	render_audit_filters();
	load_audit();
}

function audit_set_range(range){
	audit_state.filters.range = range;
	audit_state.filters.from = "";
	audit_state.filters.to = "";
	$("auditFrom").value = "";
	$("auditTo").value = "";
	audit_state.offset = 0;
	render_audit_filters();
	load_audit();
}

function audit_filter_user(name){
	audit_set_filter("user", name);
	$("auditUser").value = name;
}

function audit_clear_filters(){
	audit_state.filters = Object.assign({}, AUDIT_DEFAULT_FILTERS);
	audit_state.offset = 0;
	for (let id of ["auditUser", "auditEmail", "auditQuery", "auditFrom", "auditTo"]){ $(id).value = ""; }
	render_audit_filters();
	load_audit();
	announce_live("Filtros da auditoria limpos.");
}

// A exportação leva exatamente o que está filtrado na tela, todas as páginas.
// O servidor registra quem exportou e com que filtro
function audit_export(){
	let button = $("auditExportBtn");
	button.disabled = true;
	window.location.href = "api/audit/export?" + audit_params(false);
	window.setTimeout(function(){ button.disabled = false; }, 1500);
	toast("Exportando " + audit_state.total.toLocaleString("pt-BR") + " registros em CSV.");
}

// --- Assistente -----------------------------------------------------------------

function sync_audit_assistant(){
	if (audit_ai.open === null){
		// Abre sozinho só onde cabe ao lado da tabela; abaixo disso ele a cobriria
		audit_ai.open = window.matchMedia("(min-width: 1281px)").matches;
	}
	let visible = audit_ai.open && current_view === "audit";
	show($("auditAssistant"), visible);
	$("auditAssistantBtn").setAttribute("aria-pressed", audit_ai.open ? "true" : "false");
	if (visible && audit_ai.context == null && !audit_ai.context_loading){ load_audit_ai_context(); }
}

function toggle_audit_assistant(){
	audit_ai.open = !audit_ai.open;
	sync_audit_assistant();
	if (audit_ai.open){ $("auditAiInput").focus(); }
	else { $("auditAssistantBtn").focus(); }
}

function audit_ai_append(role, text){
	let bubble = el("div", {className: "bubble"}, [
		el("span", {className: "bubble-role", text: role === "user" ? "VOCÊ" : (CHAT_ROLE_LABEL[role] || "CONTEXTO")}),
		el("p", {className: "bubble-text", text: text})
	]);
	$("auditAiThread").appendChild(el("div", {className: "chat-row " + role}, [bubble]));
	$("auditAiMessages").scrollTop = $("auditAiMessages").scrollHeight;
	return bubble.lastChild;
}

function audit_ai_set_busy(busy){
	audit_ai.busy = busy;
	let ready = !!(audit_ai.context && audit_ai.context.llmReady);
	$("auditAiSendBtn").disabled = busy || !ready;
	$("auditAiInput").disabled = busy || !ready;
	$("auditAiSendBtn").textContent = busy ? "Lendo…" : "Enviar";
}

function render_audit_ai_suggestions(){
	let dock = $("auditAiSuggestions");
	dock.replaceChildren();
	if (audit_ai.asked || !(audit_ai.context && audit_ai.context.llmReady)){ return; }
	for (let text of AUDIT_AI_SUGGESTIONS){
		dock.appendChild(el("button", {className: "chip", text: text, attrs: {type: "button"},
			onClick: function(){ $("auditAiInput").value = text; audit_ai_send(); }}));
	}
}

// O que o assistente está lendo, dito antes da primeira pergunta
function render_audit_ai_scope(){
	let box = $("auditAiScope");
	box.replaceChildren();
	let context = audit_ai.context;
	if (!context){ return; }
	let window_text = audit_short_date(context.since + ":00") + " → " + audit_short_date(context.until + ":00");
	$("auditAiSub").textContent = "últimos " + context.days + " dias · " + context.total.toLocaleString("pt-BR") + " registros";
	box.appendChild(el("div", {className: "audit-ai-facts"}, [
		el("span", {className: "mono", text: window_text}),
		context.model ? el("span", {className: "mono truncate", text: context.model, title: "Modelo configurado em Configurações → IA"}) : null
	].filter(Boolean)));
	if (context.included < context.total){
		box.appendChild(el("p", {className: "audit-ai-note",
			text: "A semana não cabe inteira no modelo: ele lê " + context.included.toLocaleString("pt-BR") + " dos "
				+ context.total.toLocaleString("pt-BR") + " registros — todas as falhas e recusas primeiro, depois os mais recentes. As contagens que ele usa valem para a semana inteira."}));
	}
	if (audit_ai.history.length){
		box.appendChild(el("button", {className: "btn quiet xs", text: "Nova conversa", attrs: {type: "button"}, onClick: audit_ai_reset}));
	}
}

function load_audit_ai_context(){
	audit_ai.context_loading = true;
	audit_ai_set_busy(true);
	$("auditAiSub").textContent = "lendo a trilha…";
	get_json("api/audit/assistant/context").then(function(context){
		audit_ai.context_loading = false;
		if (context == null || context.error){
			audit_ai.context = null;
			$("auditAiSub").textContent = "trilha indisponível";
			audit_ai_set_busy(false);
			$("auditAiSendBtn").disabled = true;
			$("auditAiInput").disabled = true;
			if (!$("auditAiThread").childElementCount){
				audit_ai_append("warn", (context && context.error) || "Não foi possível ler a trilha de auditoria.");
			}
			return;
		}
		let first = audit_ai.context == null;
		audit_ai.context = context;
		audit_ai_set_busy(false);
		render_audit_ai_scope();
		if (first && !$("auditAiThread").childElementCount){
			if (!context.llmReady){
				audit_ai_append("warn", "Nenhum modelo configurado. Defina o endpoint e o modelo em Configurações → IA para conversar sobre a trilha.");
			} else if (context.total === 0){
				audit_ai_append("info", "Não há registros nos últimos " + context.days + " dias. Posso responder assim que a trilha tiver movimento.");
			} else {
				audit_ai_append("info", "Estou lendo " + context.total.toLocaleString("pt-BR") + " registros dos últimos "
					+ context.days + " dias. Pergunte sobre logins, falhas, alterações de configuração, bloqueios ou quem fez o quê.");
			}
		}
		render_audit_ai_suggestions();
	});
}

function audit_ai_reset(){
	audit_ai.history = [];
	audit_ai.asked = false;
	audit_ai.injection_warned = false;
	$("auditAiThread").replaceChildren();
	audit_ai.context = null;
	load_audit_ai_context();
}

function audit_ai_ask_about(row){
	let question = "Explique este registro e o que aconteceu em volta dele (mesma pessoa, mesmo IP, minutos antes e depois): "
		+ row.at + " event=" + row.event + " status=" + row.status + " actor=" + (row.actor || "-")
		+ " ip=" + (row.ip || "-") + " target=" + (row.target || "-");
	audit_ai.open = true;
	sync_audit_assistant();
	$("auditAiInput").value = question.slice(0, 2000);
	if (audit_ai.context && audit_ai.context.llmReady && !audit_ai.busy){ audit_ai_send(); }
	else { $("auditAiInput").focus(); }
}

// POST api/audit/assistant — o navegador manda a pergunta e a conversa; a
// trilha da semana é o servidor quem injeta, a cada pergunta
function audit_ai_send(){
	let question = $("auditAiInput").value.trim();
	if (question === "" || audit_ai.busy || !(audit_ai.context && audit_ai.context.llmReady)){ return; }
	$("auditAiInput").value = "";
	audit_ai.asked = true;
	render_audit_ai_suggestions();
	audit_ai_append("user", question);
	let thinking = audit_ai_append("assistant", "Lendo a trilha da semana…");
	thinking.parentNode.classList.add("pending");
	audit_ai_set_busy(true);

	post_form("api/audit/assistant", {question: question, history: JSON.stringify(audit_ai.history)}).then(function(result){
		audit_ai_set_busy(false);
		thinking.parentNode.classList.remove("pending");
		let response = result.ok ? result.data : null;
		if (result.status === 403){
			thinking.textContent = "Sem permissão: o assistente de auditoria é só para administradores.";
		} else if (response == null || response.error){
			thinking.parentNode.parentNode.className = "chat-row warn";
			thinking.previousSibling.textContent = CHAT_ROLE_LABEL.warn;
			thinking.textContent = (response && response.error) || "O assistente não respondeu. Tente de novo.";
		} else {
			thinking.textContent = response.answer;
			if (response.context){
				audit_ai.context = Object.assign({}, audit_ai.context, response.context);
			}
			// Um registro da trilha tentou dar ordens ao modelo. Dito uma vez por
			// conversa, ao lado da resposta — repetido a cada turno, vira mobília
			if ((response.injectionDetected || []).length && !audit_ai.injection_warned){
				audit_ai.injection_warned = true;
				audit_ai_append("warn", "Atenção: há registros na trilha com texto que tenta instruir o modelo ("
					+ response.injectionDetected.join(", ") + "). Isso costuma vir de um nome digitado num login que falhou. "
					+ "Leia a resposta com esse contexto e procure o registro na tabela.");
			}
			audit_ai.history.push({role: "user", content: question});
			audit_ai.history.push({role: "assistant", content: response.answer});
			if (audit_ai.history.length > 12){ audit_ai.history = audit_ai.history.slice(-12); }
		}
		render_audit_ai_scope();
		$("auditAiMessages").scrollTop = $("auditAiMessages").scrollHeight;
		$("auditAiInput").focus();
	});
}

/* ========================================================================== */
/* Native analyzers                                                           */
/*                                                                            */
/* The cards and the whole configuration form are built from the registry the  */
/* server sends, so adding an analyzer is a registry entry in analyzers.py —   */
/* never new markup here.                                                      */
/* ========================================================================== */

let analyzer_registry = [];
let analyzer_config = {};
let analyzer_open = null;
let analyzer_families = {};
let analyzer_query = "";
let observable_hint = "";

// Como cada tipo de observável é chamado na tela. O valor cru continua visível
// ao lado porque é ele que aparece no log da análise e nos relatórios
const OBSERVABLE_LABEL = {
	ip: "endereços IP",
	domain: "domínios",
	url: "URLs",
	hash: "hashes de anexo",
	file: "arquivos anexados",
	mail: "endereços de e-mail"
};

function show_integr_tab(tab){
	for (let panel of $$("[data-integr-tab]")){
		show(panel, panel.dataset.integrTab === tab);
	}
	for (let button of $$("#integrTabs .tab")){
		button.classList.toggle("active", button.dataset.arg === tab);
	}
	if (tab === "analisadores" && analyzer_registry.length === 0){ load_analyzers(); }
	// A priorização lista os analisadores customizados junto dos nativos, então
	// ela busca o próprio recorte em vez de reaproveitar o registro dos cards:
	// abrir esta aba primeiro é um caminho normal
	if (tab === "priorizacao" && scoring_factors.length === 0){ load_scoring(); }
	if (tab === "bloqueio" && responder_registry.length === 0){ load_responders(); }
	if (tab === "tickets" && ticket_registry.length === 0){ load_tickets(); }
	// Os conectores dividem a aba com os destinos nativos. Sem registro estático
	// para comparar: a lista é toda do usuário, e uma lista vazia é
	// indistinguível de "ainda não carreguei"
	if (tab === "tickets"){ load_connectors(); }
}

function load_analyzers(){
	get_json("api/analyzers").then(function(payload){
		if (payload == null || payload.error){
			$("analyzerCards").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível carregar os analisadores."
			}));
			return;
		}
		analyzer_registry = payload.registry || [];
		analyzer_config = payload.config || {};
		analyzer_families = payload.families || {};
		custom_defs = payload.custom || [];
		custom_limit = payload.customLimit || custom_limit;
		custom_levels = payload.levels || custom_levels;
		custom_observables = payload.customObservables || custom_observables;
		observable_hint = payload.observableHint || observable_hint;
		render_analyzer_cards();
	});
}

// Typing must narrow the list, never hide an analyzer the analyst is looking at
// under a term they did not type: name, kind, family and observable all count,
// because "sandbox" is a family, "url" is an observable and "virustotal" is a name.
function analyzer_matches(spec, needle){
	if (!needle){ return true; }
	let family = analyzer_families[spec.family] || {};
	let haystack = [spec.name, spec.kind, spec.id, family.label || "", (spec.observables || []).join(" ")]
		.join(" ").toLowerCase();
	return haystack.indexOf(needle) !== -1;
}

let analyzer_query_timer = null;
function filter_analyzers_debounced(){
	show($("analyzerQueryClear"), $("analyzerQuery").value.trim() !== "");
	window.clearTimeout(analyzer_query_timer);
	analyzer_query_timer = window.setTimeout(function(){
		analyzer_query = $("analyzerQuery").value.trim().toLowerCase();
		render_analyzer_cards();
	}, 120);
}

function clear_analyzer_filter(){
	$("analyzerQuery").value = "";
	analyzer_query = "";
	show($("analyzerQueryClear"), false);
	render_analyzer_cards();
}

function render_analyzer_cards(){
	let container = $("analyzerCards");
	container.replaceChildren();

	let enabled = 0;
	let shown = 0;
	for (let spec of analyzer_registry){
		let entry = analyzer_config[spec.id] || {};
		if (entry.enabled){ enabled++; }
		// The enabled count above stays over the whole registry: a filter narrows
		// what you see, it does not change how many analyzers are actually on
		if (!analyzer_matches(spec, analyzer_query)){ continue; }
		shown++;

		// A configured-but-off analyzer reads differently from one never touched
		let configured = spec.credentials.every(function(field){
			return !field.required || (field.secret ? entry["has" + field.key[0].toUpperCase() + field.key.slice(1)] : entry[field.key]);
		});
		let tone = entry.enabled ? "ok" : (configured ? "warn" : "");
		let label = entry.enabled ? "ativo" : (configured ? "configurado, desligado" : "não configurado");

		container.appendChild(el("div", {className: "card"}, [
			el("div", {className: "row top"}, [
				el("div", {className: "grow col", style: "gap:2px"}, [
					// A descrição mora no "i" ao lado do nome: numa grade de cards,
					// um parágrafo por card era o que mais pesava na tela
					el("div", {className: "title-line"}, [
						el("span", {className: "card-title", text: spec.name}),
						info_tip(spec.description)
					]),
					el("span", {className: "card-code", text: spec.kind})
				]),
				el("span", {className: "pill " + tone, text: label})
			]),
			el("div", {className: "row", style: "gap:5px;flex-wrap:wrap"},
				[(analyzer_families[spec.family]
					? el("span", {className: "pill", text: analyzer_families[spec.family].label,
						attrs: {title: analyzer_families[spec.family].summary}})
					: null)].concat(spec.observables.map(function(type){
						// Tracejado e apagado quando o tipo foi desmarcado: o card continua
						// dizendo o que o fornecedor sabe avaliar, e mostra de relance o que
						// esta instalação de fato manda para ele
						let sent = (entry.observables || spec.observables).indexOf(type) !== -1;
						return el("span", {className: sent ? "pill" : "pill muted", text: type,
							title: sent ? null : "não é enviado a este analisador"});
					}))),
			el("div", {className: "card-foot"}, [
				el("span", {className: "status grow mono",
					text: spec.custom ? "veredito pelo mapa de valores" : threshold_summary(spec, entry)}),
				el("button", {className: "btn sm", text: "Configurar", attrs: {type: "button"},
					onClick: spec.custom
						? function(){ open_custom_modal(spec.id); }
						: function(){ open_analyzer_modal(spec.id); }})
			])
		]));
	}

	// A filter that matches nothing must say so, not leave an empty grid that
	// reads as "there are no analyzers"
	if (shown === 0){
		container.appendChild(el("div", {className: "tbl-empty",
			text: "Nenhum analisador corresponde a “" + analyzer_query + "”."}));
	}

	// Quantos analisadores o analista definiu, no callout que os oferece — o
	// mesmo par de números que a lista de conectores mostra logo abaixo
	$("customAnalyzersNote").textContent = custom_defs.length === 0
		? "Nenhum analisador definido por você. O limite é de " + custom_limit + "."
		: custom_defs.length + " definido(s) por você, de um limite de " + custom_limit + ".";

	// Sem nenhum analisador habilitado o pipeline não deixa de rodar: ele passa a
	// julgar cada e-mail só pela avaliação do LLM, o que é bem menos do que se
	// espera de uma triagem. Dizer isso aqui é o que evita a surpresa.
	$("analyzersPipelineNote").textContent = enabled === 0
		? "Nenhum analisador habilitado. Sem nenhum, o veredito sai apenas da avaliação de engenharia social do LLM."
		: enabled + " habilitado(s) — é o que o pipeline roda em cada análise.";
}

/* ========================================================================== */
/* Priorização — os pesos da metodologia de score                             */
/* ========================================================================== */
/*
 * A tabela é o ponto: cada linha é um fator, e o que se faz aqui é compará-los.
 * Um modal por fator daria mais espaço para cada um e destruiria a única coisa
 * que essa tela precisa entregar — ver os pesos lado a lado enquanto se mexe num
 * deles. Por isso o peso é editável na linha e o ranking reordena ao vivo.
 *
 * A ordenação é por peso, e a nota da primeira coluna é a participação relativa
 * (peso ÷ soma dos pesos). É ela que responde "e se eu subir este?", que o peso
 * absoluto sozinho não responde: 0,90 num conjunto de doze fatores e 0,90 num
 * conjunto de três são coisas diferentes.
 */

let scoring_factors = [];
let scoring_config = null;
let scoring_dirty = {};
let scoring_query = "";

function load_scoring(){
	get_json("api/scoring").then(function(payload){
		if (payload == null || payload.error){
			$("scoringRows").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível carregar a priorização."
			}));
			return;
		}
		scoring_config = payload.config;
		scoring_factors = payload.factors || [];
		scoring_dirty = {};
		apply_scoring_config();
		render_scoring_rows();
	});
}

function apply_scoring_config(){
	if (!scoring_config){ return; }
	$("scoringMode").value = scoring_config.mode;
	$("scoringTierPhishing").value = scoring_config.tiers.phishing;
	$("scoringTierSuspicious").value = scoring_config.tiers.suspicious;
	$("scoringTierLegitimate").value = scoring_config.tiers.legitimate;
	$("scoringSpamTriage").classList.toggle("on", !!scoring_config.spamTriage);
	$("scoringSpamSkip").classList.toggle("on", !!scoring_config.spamSkipAnalysis);
}

let scoring_query_timer = null;
function filter_scoring_debounced(){
	window.clearTimeout(scoring_query_timer);
	scoring_query_timer = window.setTimeout(function(){
		scoring_query = $("scoringQuery").value.trim().toLowerCase();
		render_scoring_rows();
	}, 120);
}

function scoring_matches(row, needle){
	if (!needle){ return true; }
	return [row.name, row.source, row.description, row.detail, row.id]
		.join(" ").toLowerCase().indexOf(needle) !== -1;
}

// A participação relativa é recalculada a cada movimento de peso, sobre o
// conjunto inteiro — inclusive as linhas que o filtro escondeu. Recalcular só
// sobre o visível faria o mesmo fator mostrar duas notas diferentes conforme o
// que estivesse digitado na busca.
function scoring_shares(){
	let total = scoring_factors.reduce(function(sum, row){ return sum + row.weight; }, 0) || 1;
	let shares = {};
	for (let row of scoring_factors){ shares[row.id] = row.weight * 100 / total; }
	return shares;
}

function render_scoring_rows(){
	let container = $("scoringRows");
	container.replaceChildren();
	let shares = scoring_shares();
	let ordered = scoring_factors.slice().sort(function(a, b){
		if (b.weight !== a.weight){ return b.weight - a.weight; }
		return a.name.localeCompare(b.name);
	});

	let shown = 0;
	for (let row of ordered){
		if (!scoring_matches(row, scoring_query)){ continue; }
		shown++;
		container.appendChild(scoring_row(row, shares[row.id]));
	}
	if (shown === 0){
		container.appendChild(el("div", {className: "tbl-empty",
			text: "Nenhum fator corresponde a “" + scoring_query + "”."}));
	}

	let enabled = scoring_factors.filter(function(row){ return row.enabled; }).length;
	let conviction = scoring_factors.filter(function(row){
		return row.enabled && row.conviction && row.weight > 0;
	}).length;
	$("scoringNote").textContent = conviction === 0
		? "Nenhum fator de convicção está habilitado com peso maior que zero. Sem analisador nem "
			+ "avaliação de conteúdo participando, o score não alcança a faixa de phishing — cabeçalho "
			+ "de massa e falha de autenticação sozinhos nunca condenam."
		: enabled + " fator(es) habilitado(s), " + conviction + " deles capaz(es) de levar o score à faixa de phishing.";
	render_scoring_dirty();
}

function scoring_row(row, share){
	let node = el("div", {className: "tbl-row cols-prio"}, [
		el("span", {className: "prio-score" + (row.enabled ? "" : " off"),
			text: share.toFixed(1),
			title: "participação relativa deste fator no total dos pesos"}),
		el("div", {className: "col", style: "gap:2px;min-width:0"}, [
			el("span", {className: "truncate", text: row.name, title: row.name,
				style: "font-size:var(--fs-body);color:var(--t1)"}),
			el("span", {className: "mono truncate", text: row.id, title: row.id,
				style: "font-size:var(--fs-micro);color:var(--t5)"})
		]),
		el("span", {className: "truncate", text: row.source, title: row.source,
			style: "font-size:var(--fs-body);color:var(--t3)"}),
		el("span", {className: "truncate", text: row.detail || row.description,
			title: row.detail || row.description,
			style: "font-size:var(--fs-body);color:var(--t3)"}),
		scoring_weight_control(row),
		scoring_status_pill(row)
	]);
	node.classList.toggle("dirty", Object.prototype.hasOwnProperty.call(scoring_dirty, row.id));
	return node;
}

function scoring_weight_control(row){
	let value = el("span", {className: "prio-weight-value", text: row.weight.toFixed(2)});
	let slider = el("input", {attrs: {type: "range", min: "0", max: "1", step: "0.05",
		value: String(row.weight), "aria-label": "peso de " + row.name}});
	// oninput como propriedade, nunca como atributo: a CSP proíbe manipulador
	// embutido, e um atributo aqui deixaria o controle mudo sem nenhum erro
	slider.oninput = function(){
		let weight = parseFloat(slider.value);
		row.weight = weight;
		scoring_dirty[row.id] = weight;
		value.textContent = weight.toFixed(2);
		render_scoring_dirty();
	};
	// O reordenamento espera o mouse soltar. Reordenar durante o arrasto tiraria
	// a linha de baixo do cursor no meio do gesto
	slider.onchange = function(){ render_scoring_rows(); };
	return el("div", {className: "prio-weight"}, [slider, value]);
}

function scoring_status_pill(row){
	if (row.kind === "signal"){
		return el("span", {className: "pill", text: "sinal",
			attrs: {title: "sinal do próprio e-mail: existe sempre que o dado que o alimenta existe"}});
	}
	return el("span", {className: "pill " + (row.enabled ? "ok" : ""),
		text: row.enabled ? "ativo" : "desativado",
		attrs: {title: row.enabled
			? "habilitado em Integrações → Analisadores"
			: "desabilitado: o peso fica gravado e volta a valer quando ele for habilitado"}});
}

function render_scoring_dirty(){
	let count = Object.keys(scoring_dirty).length;
	$("scoringDirty").textContent = count === 0 ? "" : count + " peso(s) alterado(s), não gravado(s)";
	$("scoringDirty").classList.toggle("bad", count > 0);
}

function reset_scoring_weights(){
	ask({
		title: "Restaurar os pesos padrão?",
		sub: "os limiares de faixa e o modo não mudam",
		body: "Cada fator volta ao peso documentado no registro. Os pesos que você ajustou são "
			+ "perdidos — inclusive os que já estavam gravados.",
		confirmLabel: "Restaurar",
		danger: true
	}, function(){
		// Mandar `weights: {}` não restauraria nada: a validação mescla sobre o
		// gravado, então um mapa vazio mantém tudo. O padrão vem do servidor,
		// que é quem conhece o registro — reconstruí-lo aqui duplicaria a tabela
		// de pesos em dois lugares que envelheceriam separados
		post_json("api/scoring", {resetWeights: true}).then(function(payload){
			if (payload && payload.error){ toast(payload.error, "bad"); return; }
			scoring_config = payload.config;
			scoring_factors = payload.factors || [];
			scoring_dirty = {};
			apply_scoring_config();
			render_scoring_rows();
			toast("Pesos restaurados.");
		});
	});
}

function save_scoring(){
	let weights = {};
	for (let row of scoring_factors){ weights[row.id] = row.weight; }
	let payload = {
		mode: $("scoringMode").value,
		weights: weights,
		tiers: {
			phishing: parseInt($("scoringTierPhishing").value, 10),
			suspicious: parseInt($("scoringTierSuspicious").value, 10),
			legitimate: parseInt($("scoringTierLegitimate").value, 10)
		},
		spamTriage: $("scoringSpamTriage").classList.contains("on"),
		spamSkipAnalysis: $("scoringSpamSkip").classList.contains("on")
	};
	post_json("api/scoring", payload).then(function(response){
		if (response == null){ toast("Não foi possível gravar a priorização.", "bad"); return; }
		if (response.error){ toast(response.error, "bad"); return; }
		scoring_config = response.config;
		scoring_factors = response.factors || scoring_factors;
		scoring_dirty = {};
		apply_scoring_config();
		render_scoring_rows();
		// A janela de insights foi calculada com os pesos anteriores; ela precisa
		// ser refeita, ou o painel tático continua ordenando por um critério que
		// não existe mais
		insights_payload = null;
		toast("Priorização gravada. Vale a partir da próxima análise.");
	});
}

// A metodologia inteira num diálogo, a partir do painel tático: quem está
// olhando o ranking é quem pergunta de onde saiu o número, e mandá-lo procurar
// a resposta em Integrações é onde a explicação deixa de ser lida
function open_scoring_method(){
	let tiers = (scoring_config && scoring_config.tiers) || {phishing: 50, suspicious: 40, legitimate: 20};
	ask({
		title: "Como o score é calculado",
		sub: "score = 100 × Σ ( peso × fator )",
		body: "Cada analisador e cada sinal do e-mail é um fator normalizado em [0,1]: malicioso 1,0, "
			+ "suspeito 0,5, limpo 0. Um analisador que não conseguiu olhar (info) fica fora da média "
			+ "em vez de diluí-la, e evidência de inocência participa com peso reduzido. "
			+ "Faixas: phishing ≥ " + tiers.phishing + " · suspeito/spam ≥ " + tiers.suspicious
			+ " · legítimo ≥ " + tiers.legitimate + ". "
			+ "O veredito é piso do score, então a faixa só eleva um veredito — nunca o rebaixa. "
			+ "Os pesos são ajustáveis em Integrações → Priorização.",
		confirmLabel: "Entendi"
	}, function(){});
}

// The one-line "malicious from N, suspicious from M" a card shows at a glance.
// A blocklist has nothing to tune — it either holds the indicator or it does
// not — so it says that instead of showing an empty line.
function threshold_summary(spec, entry){
	let malicious = spec.thresholds.filter(function(t){ return t.key === "maliciousMin"; })[0];
	let suspicious = spec.thresholds.filter(function(t){ return t.key === "suspiciousMin"; })[0];
	if (!malicious){ return "sem limiar: resposta binária do fornecedor"; }
	let unit = malicious.unit ? " " + malicious.unit : "";
	let text = "malicioso ≥ " + (entry.maliciousMin != null ? entry.maliciousMin : malicious.default) + unit;
	if (suspicious){
		text += " · suspeito ≥ " + (entry.suspiciousMin != null ? entry.suspiciousMin : suspicious.default);
	}
	return text;
}

function analyzer_spec(id){
	return analyzer_registry.filter(function(s){ return s.id === id; })[0] || null;
}

// The guide opens closed. Someone reconfiguring a threshold they set last month
// should not have to scroll past three paragraphs to reach the field.
function render_analyzer_guide(spec){
	let box = $("analyzerGuide");
	box.replaceChildren();

	let family = analyzer_families[spec.family];
	let sections = spec.guide || [];
	if (!family && sections.length === 0){
		show($("analyzerGuideBox"), false);
		return;
	}
	show($("analyzerGuideBox"), true);

	if (family){
		box.appendChild(el("div", {className: "col", style: "gap:4px"}, [
			el("span", {className: "field-label", text: "FAMÍLIA · " + family.label.toUpperCase()}),
			el("p", {className: "card-note", text: family.body})
		]));
	}
	for (let section of sections){
		box.appendChild(el("div", {className: "col", style: "gap:4px"}, [
			el("span", {className: "field-label", text: section.title.toUpperCase()}),
			el("p", {className: "card-note", text: section.body})
		]));
	}
	if (spec.docs){
		let link = el("a", {className: "card-note", text: "Documentação do fornecedor ↗"});
		link.href = spec.docs;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		box.appendChild(link);
	}

	show(box, false);
	$("analyzerGuideToggle").textContent = "Como usar este analisador";
}

/* ========================================================================== */
/* Analisador definido pelo analista.                                         */
/*                                                                            */
/* O card e o filtro são os mesmos dos nativos — o back end devolve a          */
/* definição já na forma do registro. O que muda é o formulário: aqui não se   */
/* preenche a credencial de um fornecedor conhecido, se decide para onde o     */
/* servidor vai chamar. Por isso ele tem modal próprio.                        */
/* ========================================================================== */

let custom_defs = [];
let custom_open = null;
let custom_limit = 20;
let custom_levels = ["info", "safe", "suspicious", "malicious"];
let custom_observables = ["ip", "domain", "url", "hash", "mail"];

const LEVEL_LABEL = {info: "info", safe: "safe", suspicious: "suspeito", malicious: "malicioso"};

function custom_def(id){
	return custom_defs.filter(function(d){ return d.id === id; })[0] || null;
}

function open_custom_modal(id){
	// Chamado de dois lugares: pelo card, com o id, e pelo botão "Novo
	// analisador", pelo dispatch — que entrega o elemento quando não há
	// data-arg. Só string é id; qualquer outra coisa significa "criar".
	if (typeof id !== "string" || !id){ id = null; }
	custom_open = id;
	let def = id ? custom_def(id) : null;

	$("customModalTitle").textContent = def ? def.name : "Novo analisador";
	$("customModalNote").textContent = def
		? "Editando um analisador que você definiu."
		: "O servidor vai consultar o endereço que você informar aqui. Só HTTPS, e destino na rede interna é recusado — na hora de salvar e de novo a cada chamada.";
	show($("customDeleteBtn"), !!def);
	set_status("customModalStatus", "");
	show($("customTestResult"), false);
	$("customTestValue").value = "";

	$("customEnabled").classList.toggle("on", !!(def && def.enabled));
	$("customAllowInternal").classList.toggle("on", !!(def && def.allowInternal));
	$("customName").value = def ? def.name : "";
	$("customDescription").value = def ? (def.description || "") : "";
	$("customUrl").value = def ? def.url : "";
	$("customMethod").value = def ? def.method : "GET";
	$("customAuthType").value = def ? def.authType : "none";
	$("customAuthName").value = def ? (def.authName || "") : "";
	$("customAuthValue").value = "";
	$("customAuthValue").placeholder = def && def.hasAuthValue
		? "•••••••• (salva — deixe vazio para manter)"
		: "";
	$("customValuePath").value = def ? def.valuePath : "";

	// Observáveis
	let box = $("customObservables");
	box.replaceChildren();
	for (let type of custom_observables){
		let input = el("input", {attrs: {id: "cob_" + type}});
		input.type = "checkbox";
		input.checked = !!(def && (def.observables || []).indexOf(type) !== -1);
		box.appendChild(el("label", {className: "row", style: "gap:5px;align-items:center"},
			[input, el("span", {className: "mono", text: type})]));
	}

	// Nível de reserva
	let fallback = $("customFallback");
	fallback.replaceChildren();
	for (let level of custom_levels){
		let option = el("option", {text: LEVEL_LABEL[level] || level});
		option.value = level;
		if ((def ? def.fallbackLevel : "info") === level){ option.selected = true; }
		fallback.appendChild(option);
	}

	$("customLevelMap").replaceChildren();
	let rules = def ? (def.levelMap || []) : [];
	if (rules.length === 0){ rules = [{value: "", level: "malicious"}]; }
	for (let rule of rules){ add_custom_rule(rule); }

	render_custom_auth();
	open_modal("customModal");
}

function add_custom_rule(rule){
	// Idem: o botão "Adicionar regra" chega aqui pelo dispatch com o elemento.
	// Um elemento também tem .value, então o teste precisa ser mais específico.
	if (!rule || typeof rule !== "object" || rule.nodeType || typeof rule.level !== "string"){
		rule = {value: "", level: "malicious"};
	}
	let container = $("customLevelMap");

	let value = el("input", {className: "input mono grow"});
	value.type = "text";
	value.placeholder = "valor devolvido pelo fornecedor";
	value.value = rule.value || "";

	let select = el("select", {className: "select"});
	for (let level of custom_levels){
		let option = el("option", {text: LEVEL_LABEL[level] || level});
		option.value = level;
		if (rule.level === level){ option.selected = true; }
		select.appendChild(option);
	}

	let row = el("div", {className: "row", style: "gap:6px"}, [
		value,
		el("span", {className: "select-wrap"}, [select]),
		el("button", {className: "btn sm secondary", text: "×", attrs: {type: "button"},
			onClick: function(){ row.remove(); }})
	]);
	row.dataset.rule = "1";
	container.appendChild(row);
}

function collect_custom_rules(){
	let rules = [];
	for (let row of $("customLevelMap").children){
		let value = row.querySelector("input").value.trim();
		let level = row.querySelector("select").value;
		if (value){ rules.push({value: value, level: level}); }
	}
	return rules;
}

// Bearer não pede nome de campo; "nenhuma" não pede nem nome nem credencial
function render_custom_auth(){
	let type = $("customAuthType").value;
	show($("customAuthNameField"), type === "header" || type === "query");
	show($("customAuthValueField"), type !== "none");
}

function custom_payload(){
	let observables = [];
	for (let type of custom_observables){
		if ($("cob_" + type).checked){ observables.push(type); }
	}
	return {
		id: custom_open,
		enabled: $("customEnabled").classList.contains("on"),
		allowInternal: $("customAllowInternal").classList.contains("on"),
		name: $("customName").value.trim(),
		description: $("customDescription").value.trim(),
		url: $("customUrl").value.trim(),
		method: $("customMethod").value,
		authType: $("customAuthType").value,
		authName: $("customAuthName").value.trim(),
		authValue: $("customAuthValue").value,
		observables: observables,
		valuePath: $("customValuePath").value.trim(),
		levelMap: collect_custom_rules(),
		fallbackLevel: $("customFallback").value
	};
}

function save_custom(){
	set_status("customModalStatus", "salvando…");
	let url = custom_open ? "api/custom-analyzers/" + encodeURIComponent(custom_open) : "api/custom-analyzers";
	post_json(url, custom_payload()).then(function(result){
		if (!result.ok){
			set_status("customModalStatus", (result.data && result.data.error) || "Não foi possível salvar.", "bad");
			return;
		}
		close_modal();
		toast("Analisador salvo.", "ok");
		load_analyzers();
	});
}

function delete_custom(){
	if (!custom_open){ return; }
	set_status("customModalStatus", "removendo…");
	post_json("api/custom-analyzers/" + encodeURIComponent(custom_open), {}, "DELETE").then(function(result){
		if (!result.ok){
			set_status("customModalStatus", (result.data && result.data.error) || "Não foi possível remover.", "bad");
			return;
		}
		close_modal();
		toast("Analisador removido.", "ok");
		load_analyzers();
	});
}

function test_custom(){
	let value = $("customTestValue").value.trim();
	if (!value){ set_status("customModalStatus", "Informe um observável para testar.", "warn"); return; }
	set_status("customModalStatus", "consultando…");
	show($("customTestResult"), false);

	let payload = custom_payload();
	payload.value = value;
	post_json("api/custom-analyzers/test", payload).then(function(result){
		if (!result.ok){
			set_status("customModalStatus", (result.data && result.data.error) || "Falha na consulta.", "bad");
			return;
		}
		set_status("customModalStatus", "");
		show($("customTestResult"), true);
		let level = result.data.level;
		$("customTestLevel").textContent = LEVEL_LABEL[level] || level;
		$("customTestLevel").className = "pill " + level_tone(level);
		$("customTestDetail").textContent = result.data.error || result.data.detail || "";
	});
}

// O nível do analisador traduzido para o tom visual. Distinto de verdict_tone(),
// que mapeia o veredito do caso — são vocabulários diferentes.
function level_tone(level){
	if (level === "malicious"){ return "bad"; }
	if (level === "suspicious"){ return "warn"; }
	if (level === "safe"){ return "ok"; }
	return "";
}

// --------------------------------------------------------------------------- //
// Conectores genéricos                                                         //
// --------------------------------------------------------------------------- //

let connector_defs = [];
let connector_limit = 20;
let connector_variables = [];
let connector_locations = ["header", "query", "body"];
let connector_value_types = ["string", "number", "boolean", "json"];
let connector_open = null;
// "report" para os conectores de Integrações, "alert" para os webhooks da
// equipe em Notificações. O modal e o caminho de disparo são os mesmos
let connector_kind = "report";

const CONNECTOR_VERDICT_LABEL = {
	all: "todo e-mail analisado",
	Suspicious: "suspeito ou malicioso",
	Malicious: "somente malicioso"
};

function load_connectors(){
	get_json("api/connectors").then(function(payload){
		if (payload == null || payload.error){
			$("connectorCards").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível carregar os conectores."
			}));
			return;
		}
		connector_defs = payload.connectors || [];
		connector_limit = payload.limit || connector_limit;
		connector_variables = payload.variables || [];
		connector_locations = payload.locations || connector_locations;
		connector_value_types = payload.valueTypes || connector_value_types;
		render_connector_cards();
	});
}

function connector_def(id){
	let defs = connector_kind === "alert" ? alert_connector_defs : connector_defs;
	return defs.filter(function(d){ return d.id === id; })[0] || null;
}

function connector_base(){
	return connector_kind === "alert" ? "api/alert-connectors" : "api/connectors";
}

function reload_connectors(){
	if (connector_kind === "alert"){ load_volume_alerts(); } else { load_connectors(); }
}

// Um card de conector, o mesmo para Integrações e para os webhooks da equipe
function connector_card(def, detail, on_edit){
	return el("div", {className: "card"}, [
		el("div", {className: "row top"}, [
			el("div", {className: "grow col", style: "gap:2px"}, [
				el("div", {className: "title-line"}, [
					el("span", {className: "card-title", text: def.name}),
					info_tip(def.description)
				]),
				el("span", {className: "card-code", text: def.method + " " + connector_host(def.url)})
			]),
			el("span", {className: "pill " + (def.enabled ? "ok" : ""),
				text: def.enabled ? "habilitado" : "desligado"})
		]),
		el("div", {className: "card-foot"}, [
			el("span", {className: "status grow", text: detail}),
			el("button", {className: "btn sm", text: "Editar", attrs: {type: "button"}, onClick: on_edit})
		])
	]);
}

function connector_host(url){
	// Só o host, porque é o que identifica o destino num card estreito. Um
	// endereço com variável não é URL válida ainda, e aí o texto cru serve mais
	// do que um "inválido" que assustaria sem motivo.
	try { return new URL(url).host; } catch (e) { return url || "—"; }
}

function render_connector_cards(){
	let enabled = connector_defs.filter(function(d){ return d.enabled; }).length;
	$("connectorsNote").textContent = connector_defs.length === 0
		? "Nenhum conector definido. O limite é de " + connector_limit + "."
		: enabled + " de " + connector_defs.length + " habilitado" + (enabled === 1 ? "" : "s")
			+ " — os desabilitados não recebem nada.";

	let cards = [];
	for (let def of connector_defs){
		cards.push(connector_card(def, CONNECTOR_VERDICT_LABEL[def.minVerdict] || def.minVerdict,
			function(){ open_connector_modal(def.id); }));
	}
	if (cards.length === 0){
		cards.push(el("div", {className: "tbl-empty",
			text: "Nenhum conector ainda. Use \"Novo conector\" para integrar com qualquer ferramenta que aceite uma API REST."}));
	}
	$("connectorCards").replaceChildren.apply($("connectorCards"), cards);
}

function open_connector_modal(id){
	connector_kind = "report";
	fill_connector_modal(id);
}

// Os webhooks da equipe (Notificações → Equipe de SI) são o mesmo formulário: muda
// para onde grava, que variáveis oferece, e que não há veredito para filtrar
function open_alert_connector_modal(id){
	connector_kind = "alert";
	fill_connector_modal(id);
}

function fill_connector_modal(id){
	// Como em open_custom_modal: só string é id, qualquer outra coisa (o próprio
	// elemento, vindo do dispatch) significa "criar".
	if (typeof id !== "string" || !id){ id = null; }
	connector_open = id;
	let alert = connector_kind === "alert";
	let def = id ? connector_def(id) : null;

	$("connectorModalTitle").textContent = def ? def.name : (alert ? "Novo webhook" : "Novo conector");
	$("connectorModalNote").textContent = def
		? "Editando um " + (alert ? "webhook" : "conector") + " que você definiu."
		: alert
			? "O servidor vai enviar cada alerta de volume para o endereço que você informar aqui. Só HTTPS público, e o destino é revalidado a cada disparo."
			: "O servidor vai enviar o relatório da análise para o endereço que você informar aqui. Só HTTPS público, e o destino é revalidado a cada disparo.";
	show($("connectorMinVerdictField"), !alert);
	// O formulário é o mesmo; o vocabulário não. Um webhook da equipe não
	// "registra a análise", ele avisa gente — e não filtra veredito nenhum
	$("connectorEnabledTitle").textContent = alert ? "Habilitar webhook" : "Habilitar conector";
	$("connectorEnabledHint").textContent = alert
		? "desligado, nenhum alerta é enviado a este destino"
		: "desligado, nenhuma análise é enviada ao destino";
	$("connectorName").placeholder = alert ? "Teams — canal do SOC" : "Conector Jira";
	$("connectorNameHint").textContent = alert
		? "Use algo que o próximo analista entenda — \"Teams — canal do SOC\"."
		: "Use algo que o próximo analista entenda — \"Conector Jira — fila SEC\".";
	$("connectorDescription").placeholder = alert
		? "Quem é avisado por este webhook, e onde."
		: "O que este conector registra, e onde.";
	$("connectorPayload").placeholder = alert
		? '{\n  "text": "{{message}}"\n}'
		: '{\n  "fields": {\n    "project": { "key": "SEC" },\n    "summary": "[{{verdict}}] {{subject}}",\n    "description": "{{report_markdown}}"\n  }\n}';
	show($("connectorDeleteBtn"), !!def);
	set_status("connectorModalStatus", "");
	set_status("connectorPayloadStatus", "");
	show($("connectorPreviewBox"), false);

	$("connectorEnabled").classList.toggle("on", !!(def && def.enabled));
	$("connectorAllowInternal").classList.toggle("on", !!(def && def.allowInternal));
	$("connectorName").value = def ? def.name : "";
	$("connectorDescription").value = def ? (def.description || "") : "";
	$("connectorUrl").value = def ? def.url : "";
	$("connectorMethod").value = def ? def.method : "POST";
	$("connectorTimeout").value = def ? def.timeout : 30;
	$("connectorAuthType").value = def ? def.authType : "none";
	$("connectorAuthUser").value = def ? (def.authUser || "") : "";
	$("connectorAuthName").value = def ? (def.authName || "") : "";
	$("connectorAuthValue").value = "";
	$("connectorAuthValue").placeholder = def && def.hasAuthValue
		? "•••••••• (salva — deixe vazio para manter)"
		: "";
	$("connectorMinVerdict").value = def ? def.minVerdict : "all";
	$("connectorResultRef").value = def ? (def.resultRefPath || "") : "";
	$("connectorSuccessStatus").value = def
		? (def.successStatus || []).join(", ")
		: "200, 201, 202, 204";
	$("connectorPayload").value = def && def.payloadTemplate
		? JSON.stringify(def.payloadTemplate, null, 2)
		: "";

	$("connectorParams").replaceChildren();
	for (let param of (def ? def.params || [] : [])){ add_connector_param(param); }

	render_connector_variables();
	render_connector_auth();
	open_modal("connectorModal");
}

function render_connector_variables(){
	let chips = [];
	for (let variable of (connector_kind === "alert" ? alert_connector_variables : connector_variables)){
		let token = "{{" + variable.name + "}}";
		chips.push(el("button", {
			className: "btn sm secondary mono",
			text: variable.name,
			title: variable.help + " (" + variable.type + ")",
			attrs: {type: "button"},
			onClick: function(){ insert_connector_variable(token); }
		}));
	}
	$("connectorVariables").replaceChildren.apply($("connectorVariables"), chips);
}

function insert_connector_variable(token){
	let box = $("connectorPayload");
	let start = box.selectionStart == null ? box.value.length : box.selectionStart;
	let end = box.selectionEnd == null ? start : box.selectionEnd;
	box.value = box.value.slice(0, start) + token + box.value.slice(end);
	box.focus();
	box.selectionStart = box.selectionEnd = start + token.length;
}

function add_connector_param(param){
	// Idem add_custom_rule: o botão chega aqui pelo dispatch com o elemento, e um
	// elemento também tem .key — daí o teste pelo nodeType.
	if (!param || typeof param !== "object" || param.nodeType){
		param = {location: "body", key: "", value: "", valueType: "string", isSecret: false};
	}
	let container = $("connectorParams");

	let location = el("select", {className: "select"});
	for (let where of connector_locations){
		let option = el("option", {text: where});
		option.value = where;
		if (param.location === where){ option.selected = true; }
		location.appendChild(option);
	}

	let key = el("input", {className: "input mono grow"});
	key.type = "text";
	key.placeholder = "fields.customfield_10010";
	key.value = param.key || "";

	let value = el("input", {className: "input mono grow"});
	value.type = "text";
	value.placeholder = param.isSecret && param.hasValue ? "•••••••• (salvo)" : "valor ou {{variavel}}";
	value.value = param.value || "";

	let type = el("select", {className: "select"});
	for (let kind of connector_value_types){
		let option = el("option", {text: kind});
		option.value = kind;
		if (param.valueType === kind){ option.selected = true; }
		type.appendChild(option);
	}

	let secret = el("input");
	secret.type = "checkbox";
	secret.checked = !!param.isSecret;

	let row = el("div", {className: "row", style: "gap:6px;align-items:center"}, [
		el("span", {className: "select-wrap", style: "width:92px"}, [location]),
		key,
		value,
		el("span", {className: "select-wrap", style: "width:96px"}, [type]),
		el("label", {className: "row", style: "gap:4px;align-items:center", title: "Cifra o valor e o oculta do histórico"},
			[secret, el("span", {className: "field-hint", text: "segredo"})]),
		el("button", {className: "btn sm secondary", text: "×", attrs: {type: "button"},
			onClick: function(){ row.remove(); }})
	]);
	row.dataset.param = "1";
	container.appendChild(row);
}

function collect_connector_params(){
	let params = [];
	for (let row of $("connectorParams").children){
		let inputs = row.querySelectorAll("input");
		let selects = row.querySelectorAll("select");
		let key = inputs[0].value.trim();
		if (!key){ continue; }
		params.push({
			location: selects[0].value,
			key: key,
			value: inputs[1].value,
			valueType: selects[1].value,
			isSecret: inputs[2].checked
		});
	}
	return params;
}

// basic pede usuário; header e query pedem o nome do campo; nenhuma não pede nada
function render_connector_auth(){
	let type = $("connectorAuthType").value;
	show($("connectorAuthUserField"), type === "basic");
	show($("connectorAuthNameField"), type === "header" || type === "query");
	show($("connectorAuthValueField"), type !== "none");
}

function connector_status_list(){
	let list = [];
	for (let piece of $("connectorSuccessStatus").value.split(",")){
		let text = piece.trim();
		if (text){ list.push(text); }
	}
	return list.length ? list : [200, 201, 202, 204];
}

function connector_payload_body(){
	// O texto vai cru para o servidor, que é quem valida. Validar aqui também
	// serve para dizer *onde* está o erro antes de uma ida e volta.
	let text = $("connectorPayload").value.trim();
	if (!text){ return {}; }
	try {
		JSON.parse(text);
		set_status("connectorPayloadStatus", "");
	} catch (error){
		set_status("connectorPayloadStatus", "JSON inválido: " + error.message, "bad");
	}
	return text;
}

function connector_form(){
	return {
		id: connector_open,
		enabled: $("connectorEnabled").classList.contains("on"),
		allowInternal: $("connectorAllowInternal").classList.contains("on"),
		name: $("connectorName").value.trim(),
		description: $("connectorDescription").value.trim(),
		url: $("connectorUrl").value.trim(),
		method: $("connectorMethod").value,
		timeout: $("connectorTimeout").value,
		authType: $("connectorAuthType").value,
		authUser: $("connectorAuthUser").value.trim(),
		authName: $("connectorAuthName").value.trim(),
		authValue: $("connectorAuthValue").value,
		params: collect_connector_params(),
		payloadTemplate: connector_payload_body(),
		minVerdict: connector_kind === "alert" ? "all" : $("connectorMinVerdict").value,
		resultRefPath: $("connectorResultRef").value.trim(),
		successStatus: connector_status_list()
	};
}

function save_connector(){
	set_status("connectorModalStatus", "salvando…");
	let url = connector_open
		? connector_base() + "/" + encodeURIComponent(connector_open)
		: connector_base();
	post_json(url, connector_form()).then(function(result){
		if (!result.ok){
			set_status("connectorModalStatus", (result.data && result.data.error) || "Não foi possível salvar.", "bad");
			return;
		}
		close_modal();
		toast(connector_kind === "alert" ? "Webhook salvo." : "Conector salvo.", "ok");
		reload_connectors();
	});
}

function delete_connector(){
	if (!connector_open){ return; }
	set_status("connectorModalStatus", "removendo…");
	post_json(connector_base() + "/" + encodeURIComponent(connector_open), {}, "DELETE").then(function(result){
		if (!result.ok){
			set_status("connectorModalStatus", (result.data && result.data.error) || "Não foi possível remover.", "bad");
			return;
		}
		close_modal();
		toast(connector_kind === "alert" ? "Webhook removido." : "Conector removido.", "ok");
		reload_connectors();
	});
}

// Monta a requisição sem enviá-la. É o que separa "colei um JSON e torço" de
// "vejo o que vai sair" — e o motivo de existir separado do botão de teste.
function preview_connector(){
	set_status("connectorModalStatus", "montando…");
	show($("connectorPreviewBox"), false);
	post_json(connector_base() + "/preview", connector_form()).then(function(result){
		if (!result.ok){
			set_status("connectorModalStatus", (result.data && result.data.error) || "Não foi possível montar.", "bad");
			return;
		}
		set_status("connectorModalStatus", "");
		let data = result.data;
		show($("connectorPreviewBox"), true);
		$("connectorPreviewPill").textContent = data.method + " · " + data.bytes + " B";
		$("connectorPreviewPill").className = "pill";
		$("connectorPreviewDetail").textContent = data.missing.length
			? "Não resolveram: " + data.missing.join(", ")
			: "Todas as variáveis resolveram.";
		$("connectorPreviewDetail").className = "status grow" + (data.missing.length ? " warn" : "");
		$("connectorPreviewBody").textContent = data.url + "\n\n"
			+ JSON.stringify(data.headers, null, 2) + "\n\n"
			+ JSON.stringify(data.body, null, 2);
	});
}

// Diferente de todo outro botão Testar desta aplicação: este dispara de verdade.
// Num conector genérico quem escolheu o endpoint foi o usuário, e não há como
// saber se ele é de leitura — então o aviso vem antes, e é explícito.
function test_connector(){
	if (!window.confirm("Este teste envia a requisição de verdade e vai criar um registro real na ferramenta de destino. Continuar?")){
		return;
	}
	set_status("connectorModalStatus", "disparando…");
	show($("connectorPreviewBox"), false);
	let id = connector_open || "novo";
	post_json(connector_base() + "/" + encodeURIComponent(id) + "/test", connector_form()).then(function(result){
		let data = result.data || {};
		if (!result.ok && data.error == null){
			set_status("connectorModalStatus", "Não foi possível disparar.", "bad");
			return;
		}
		set_status("connectorModalStatus", "");
		show($("connectorPreviewBox"), true);
		$("connectorPreviewPill").textContent = data.ok
			? "HTTP " + data.status + " · " + data.latencyMs + " ms"
			: "falhou";
		$("connectorPreviewPill").className = "pill " + (data.ok ? "ok" : "bad");
		$("connectorPreviewDetail").textContent = data.ok ? data.detail : data.error;
		$("connectorPreviewDetail").className = "status grow" + (data.ok ? "" : " bad");
		$("connectorPreviewBody").textContent = data.response || "";
	});
}

function toggle_analyzer_guide(){
	let box = $("analyzerGuide");
	let open = box.classList.contains("hidden");
	show(box, open);
	$("analyzerGuideToggle").textContent = open ? "Ocultar guia" : "Como usar este analisador";
}

function open_analyzer_modal(id){
	let spec = analyzer_spec(id);
	if (!spec){ return; }
	analyzer_open = id;
	let entry = analyzer_config[id] || {};

	$("analyzerModalTitle").textContent = spec.name;
	$("analyzerModalKind").textContent = spec.kind;
	$("analyzerModalDesc").textContent = spec.description;
	$("analyzerTestValue").placeholder = spec.testPlaceholder || "";
	$("analyzerTestValue").value = "";
	show($("analyzerTestResult"), false);
	set_status("analyzerModalStatus", "");
	render_analyzer_guide(spec);

	// Credentials, plus the enable switch
	let creds = $("analyzerCreds");
	creds.replaceChildren();
	let toggle = el("div", {className: "toggle" + (entry.enabled ? " on" : ""), attrs: {id: "analyzerEnabled"}},
		[el("span", {className: "knob"})]);
	toggle.onclick = function(){ toggle.classList.toggle("on"); };
	creds.appendChild(el("div", {className: "row top"}, [
		el("div", {className: "grow col", style: "gap:4px"}, [
			el("span", {className: "card-title", text: "Habilitar analisador"}),
			el("span", {className: "field-hint", text: "desligado, nada é enviado ao fornecedor"})
		]),
		toggle
	]));

	for (let field of spec.credentials){
		let control;
		if (field.options){
			let select = el("select", {className: "select", attrs: {id: "af_" + field.key}});
			for (let option of field.options){
				let node = el("option", {text: option});
				node.value = option;
				if ((entry[field.key] || field.default) === option){ node.selected = true; }
				select.appendChild(node);
			}
			control = el("span", {className: "select-wrap"}, [select]);
		} else {
			let input = el("input", {className: "input" + (field.secret ? "" : " mono"), attrs: {id: "af_" + field.key}});
			input.type = field.secret ? "password" : "text";
			input.autocomplete = "new-password";
			// A stored secret is never sent back: an empty field means "keep it"
			let stored = entry["has" + field.key[0].toUpperCase() + field.key.slice(1)];
			input.placeholder = field.secret && stored
				? "•••••••• (salva — deixe vazio para manter)"
				: (field.placeholder || "");
			if (!field.secret){ input.value = entry[field.key] || field.default || ""; }
			control = input;
		}
		creds.appendChild(el("label", {className: "field"}, [
			el("span", {className: "field-label", text: field.label}),
			control,
			field.help ? el("span", {className: "field-hint", text: field.help}) : null
		]));
	}

	// O que este fornecedor vai receber. Todo analisador tem a seção, inclusive o
	// de um tipo só: quem administra abre qualquer card e lê ali o que sai daqui
	// para lá, sem precisar deduzir do nome nem lembrar do registro.
	let observables = $("analyzerObservables");
	observables.replaceChildren();
	let chosen = entry.observables || spec.observables;
	observables.appendChild(el("div", {className: "col", style: "gap:4px"}, [
		el("span", {className: "field-label", text: "O QUE ENVIAR A ESTE ANALISADOR"}),
		el("p", {className: "card-note", text: observable_hint})
	]));
	let boxes = el("div", {className: "col", style: "gap:6px"});
	for (let type of spec.observables){
		let input = el("input", {attrs: {id: "ao_" + type}});
		input.type = "checkbox";
		input.checked = chosen.indexOf(type) !== -1;
		boxes.appendChild(el("label", {className: "row", style: "gap:7px;align-items:center"}, [
			input,
			el("span", {text: OBSERVABLE_LABEL[type] || type}),
			el("span", {className: "card-code", text: type})
		]));
	}
	observables.appendChild(boxes);
	// Num analisador de tipo único a caixa e o botão de habilitar dizem a mesma
	// coisa, e desmarcá-la com ele ligado é recusado no salvamento. Dizer isso
	// aqui evita que o analista descubra pela mensagem de erro
	if (spec.observables.length === 1){
		observables.appendChild(el("span", {className: "field-hint",
			text: "Este analisador avalia um tipo só, então desmarcá-lo equivale a desabilitá-lo — "
				+ "use o botão acima para isso."}));
	}
	if (spec.observablesHelp){
		observables.appendChild(el("span", {className: "field-hint", text: spec.observablesHelp}));
	}

	// Thresholds: a range and a number bound to each other. A blocklist has none,
	// and an empty section with a divider above it just looks broken.
	let thresholds = $("analyzerThresholds");
	thresholds.replaceChildren();
	show($("analyzerThresholdsSep"), spec.thresholds.length > 0);
	if (spec.thresholds.length === 0){
		thresholds.appendChild(el("span", {className: "field-hint",
			text: "Este fornecedor responde de forma binária — o indicador consta na base ou não consta — então não há limiar a ajustar."}));
	}
	for (let field of spec.thresholds){
		let value = entry[field.key] != null ? entry[field.key] : field.default;
		let range = el("input", {className: "grow", attrs: {id: "at_r_" + field.key}});
		range.type = "range"; range.min = field.min; range.max = field.max; range.step = 1; range.value = value;
		let number = el("input", {className: "input mono", style: "flex:0 0 84px;width:84px",
			attrs: {id: "at_" + field.key}});
		number.type = "number"; number.min = field.min; number.max = field.max; number.value = value;
		range.oninput = function(){ number.value = range.value; };
		number.oninput = function(){ range.value = number.value; };

		thresholds.appendChild(el("div", {className: "col", style: "gap:8px"}, [
			el("div", {className: "row baseline", style: "gap:10px"}, [
				el("span", {className: "grow", text: field.label, style: "font-size:var(--fs-body);color:var(--t1)"}),
				el("span", {className: "card-code", text: "faixa " + field.min + "–" + field.max})
			]),
			el("div", {className: "row"}, [
				range, number,
				el("span", {className: "card-code", style: "flex:0 0 auto", text: field.unit || ""})
			]),
			field.help ? el("span", {className: "field-hint", text: field.help}) : null
		]));
	}

	open_modal("analyzerModal");
}

// Collect the modal into the payload the server validates
function analyzer_form_payload(){
	let spec = analyzer_spec(analyzer_open);
	let payload = {enabled: $("analyzerEnabled").classList.contains("on")};
	for (let field of spec.credentials){
		payload[field.key] = $("af_" + field.key).value;
	}
	for (let field of spec.thresholds){
		payload[field.key] = $("at_" + field.key).value;
	}
	payload.observables = spec.observables.filter(function(type){
		return $("ao_" + type).checked;
	});
	return payload;
}

function save_analyzer(){
	if (!analyzer_open){ return; }
	let spec = analyzer_spec(analyzer_open);
	$("analyzerSaveBtn").disabled = true;
	post_json("api/analyzers/" + encodeURIComponent(analyzer_open), analyzer_form_payload())
		.then(function(result){
			$("analyzerSaveBtn").disabled = false;
			if (!result.ok){
				set_status("analyzerModalStatus", (result.data && result.data.error) || "Não foi possível salvar.", "bad");
				return;
			}
			analyzer_config = result.data.config || analyzer_config;
			render_analyzer_cards();
			toast(spec.name + ": configuração salva.", "ok");
			// Rebuild against the saved state so the secret placeholders refresh,
			// then write the confirmation — the rebuild clears the status line
			open_analyzer_modal(analyzer_open);
			set_status("analyzerModalStatus", "Configuração salva.", "ok");
		});
}

function test_analyzer(){
	if (!analyzer_open){ return; }
	let value = $("analyzerTestValue").value.trim();
	if (!value){
		set_status("analyzerModalStatus", "Informe um observável para testar.", "bad");
		return;
	}
	$("analyzerTestBtn").disabled = true;
	set_status("analyzerModalStatus", "Consultando o fornecedor…");
	show($("analyzerTestResult"), false);

	// The settings on screen are what gets tested, so a key can be verified
	// before it is committed. Nothing is written to disk by this call.
	let payload = analyzer_form_payload();
	payload.observable = value;
	post_json("api/analyzers/" + encodeURIComponent(analyzer_open) + "/test", payload)
		.then(function(result){
			$("analyzerTestBtn").disabled = false;
			let data = result.data || {};
			if (!result.ok){
				set_status("analyzerModalStatus", data.error || "A consulta falhou.", "bad");
				return;
			}
			set_status("analyzerModalStatus", "");
			show($("analyzerTestResult"), true);
			if (data.error){
				$("analyzerTestLevel").textContent = "ERRO";
				$("analyzerTestLevel").className = "pill bad";
				$("analyzerTestDetail").textContent = data.error;
				return;
			}
			$("analyzerTestLevel").textContent = VERDICT_LABEL[LEVEL_TO_VERDICT[data.level]] || data.level.toUpperCase();
			$("analyzerTestLevel").className = "pill " + (VERDICT_TONE[LEVEL_TO_VERDICT[data.level]] || "");
			let verdict = data.level === "info"
				? "nenhum sinal"
				: (VERDICT_LABEL[LEVEL_TO_VERDICT[data.level]] || data.level).toLowerCase();
			$("analyzerTestDetail").textContent = data.detail
				+ " · reconhecido como " + data.observableType
				+ " · com os limiares atuais isso vira " + verdict + ".";
		});
}

/* ========================================================================== */
/* Destinos de bloqueio                                                       */
/*                                                                            */
/* Cards e formulário saem do registro que o servidor manda, como nos          */
/* analisadores. O que muda é o que está do outro lado: um analisador lê, um   */
/* destino destes escreve na lista de bloqueio de um tenant do Microsoft 365   */
/* ou nos objetos de um firewall. Por isso o botão de teste aqui só faz uma    */
/* chamada de leitura, e o texto diz isso — um "Testar" que bloqueasse de      */
/* verdade seria uma armadilha para quem só queria conferir a credencial.      */
/* ========================================================================== */

let responder_registry = [];
let responder_config = {};
let responder_families = {};
let responder_labels = {};
let responder_open = null;

function load_responders(){
	return get_json("api/responders").then(function(payload){
		if (payload == null || payload.error){
			$("responderCards").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível carregar os destinos de bloqueio."
			}));
			return false;
		}
		responder_registry = payload.registry || [];
		responder_config = payload.config || {};
		responder_families = payload.families || {};
		responder_labels = payload.targetLabels || {};
		render_responder_cards();
		return true;
	});
}

function responder_spec(id){
	return responder_registry.filter(function(s){ return s.id === id; })[0] || null;
}

function render_responder_cards(){
	let container = $("responderCards");
	container.replaceChildren();

	let enabled = 0;
	for (let spec of responder_registry){
		let entry = responder_config[spec.id] || {};
		if (entry.enabled){ enabled++; }

		let configured = spec.credentials.every(function(field){
			return !field.required || (field.secret
				? entry["has" + field.key[0].toUpperCase() + field.key.slice(1)]
				: entry[field.key]);
		});
		let tone = entry.enabled ? "ok" : (configured ? "warn" : "");
		let label = entry.enabled ? "ativo" : (configured ? "configurado, desligado" : "não configurado");

		// Os tipos mostrados são os efetivos, não os declarados: um FortiGate sem
		// id de filtro de URL sabe bloquear URL e não tem para onde mandá-la, e um
		// card que prometesse url ali levaria a um erro na hora do bloqueio
		let available = spec.availableTargets || spec.targets;

		container.appendChild(el("div", {className: "card"}, [
			el("div", {className: "row top"}, [
				el("div", {className: "grow col", style: "gap:2px"}, [
					// A descrição mora no "i" ao lado do nome: numa grade de cards,
					// um parágrafo por card era o que mais pesava na tela
					el("div", {className: "title-line"}, [
						el("span", {className: "card-title", text: spec.name}),
						info_tip(spec.description)
					]),
					el("span", {className: "card-code", text: spec.kind})
				]),
				el("span", {className: "pill " + tone, text: label})
			]),
			el("div", {className: "row", style: "gap:5px;flex-wrap:wrap"},
				[(responder_families[spec.family]
					? el("span", {className: "pill", text: responder_families[spec.family].label,
						attrs: {title: responder_families[spec.family].summary}})
					: null)].concat(spec.targets.map(function(type){
						let off = available.indexOf(type) === -1;
						return el("span", {
							className: "pill" + (off ? " muted" : ""),
							text: type,
							attrs: off ? {title: "este destino sabe bloquear " + type
								+ ", mas falta configurar o objeto que recebe esse tipo"} : {}
						});
					}))),
			el("div", {className: "card-foot"}, [
				el("span", {className: "status grow mono",
					text: available.length + " de " + spec.targets.length + " tipos prontos"}),
				el("button", {className: "btn sm", text: "Configurar", attrs: {type: "button"},
					onClick: function(){ open_responder_modal(spec.id); }})
			])
		]));
	}

	$("respondersNote").textContent = enabled === 0
		? "Nenhum destino habilitado. O botão Bloquear indicadores no detalhe do caso não tem para onde mandar nada."
		: enabled + " destino(s) habilitado(s). Confirme que a regra de negação que usa esses objetos existe e está ativa — preencher o objeto não cria a regra.";
}

function render_responder_guide(spec){
	let box = $("responderGuide");
	box.replaceChildren();

	let family = responder_families[spec.family];
	let sections = spec.guide || [];
	if (!family && sections.length === 0){
		show($("responderGuideBox"), false);
		return;
	}
	show($("responderGuideBox"), true);

	if (family){
		box.appendChild(el("div", {className: "col", style: "gap:4px"}, [
			el("span", {className: "field-label", text: "FAMÍLIA · " + family.label.toUpperCase()}),
			el("p", {className: "card-note", text: family.body})
		]));
	}
	for (let section of sections){
		box.appendChild(el("div", {className: "col", style: "gap:4px"}, [
			el("span", {className: "field-label", text: section.title.toUpperCase()}),
			el("p", {className: "card-note", text: section.body})
		]));
	}
	if (spec.docs){
		let link = el("a", {className: "card-note", text: "Documentação do fabricante ↗"});
		link.href = spec.docs;
		link.target = "_blank";
		link.rel = "noopener noreferrer";
		box.appendChild(link);
	}

	show(box, false);
	$("responderGuideToggle").textContent = "Como configurar este destino";
}

function toggle_responder_guide(){
	let box = $("responderGuide");
	let open = box.classList.contains("hidden");
	show(box, open);
	$("responderGuideToggle").textContent = open ? "Ocultar guia" : "Como configurar este destino";
}

function open_responder_modal(id){
	let spec = responder_spec(id);
	if (!spec){ return; }
	responder_open = id;
	let entry = responder_config[id] || {};

	$("responderModalTitle").textContent = spec.name;
	$("responderModalKind").textContent = spec.kind;
	$("responderModalDesc").textContent = spec.description;
	$("responderTestNote").textContent = "Não bloqueia nada: " + (spec.testHint || "faz apenas uma chamada de leitura")
		+ ". Usa o que está nesta tela, então dá para conferir a credencial antes de salvar.";
	$("responderTestDetail").textContent = "";
	set_status("responderModalStatus", "");
	render_responder_guide(spec);

	let creds = $("responderCreds");
	creds.replaceChildren();
	let toggle = el("div", {className: "toggle" + (entry.enabled ? " on" : ""), attrs: {id: "responderEnabled"}},
		[el("span", {className: "knob"})]);
	toggle.onclick = function(){ toggle.classList.toggle("on"); };
	creds.appendChild(el("div", {className: "row top"}, [
		el("div", {className: "grow col", style: "gap:4px"}, [
			el("span", {className: "card-title", text: "Habilitar destino"}),
			el("span", {className: "field-hint", text: "desligado, ele não aparece na hora de bloquear"})
		]),
		toggle
	]));

	for (let field of spec.credentials){
		let control;
		if (field.options){
			let select = el("select", {className: "select", attrs: {id: "rf_" + field.key}});
			for (let option of field.options){
				let node = el("option", {text: option});
				node.value = option;
				if ((entry[field.key] || field.default) === option){ node.selected = true; }
				select.appendChild(node);
			}
			control = el("span", {className: "select-wrap"}, [select]);
		} else {
			let input = el("input", {className: "input" + (field.secret ? "" : " mono"), attrs: {id: "rf_" + field.key}});
			input.type = field.secret ? "password" : "text";
			input.autocomplete = "new-password";
			let stored = entry["has" + field.key[0].toUpperCase() + field.key.slice(1)];
			input.placeholder = field.secret && stored
				? "•••••••• (salva — deixe vazio para manter)"
				: (field.placeholder || "");
			if (!field.secret){ input.value = entry[field.key] || field.default || ""; }
			control = input;
		}
		creds.appendChild(el("label", {className: "field"}, [
			el("span", {className: "field-label", text: field.label}),
			control,
			field.help ? el("span", {className: "field-hint", text: field.help}) : null
		]));
	}

	let settings = $("responderSettings");
	settings.replaceChildren();
	show($("responderSettingsSep"), spec.settings.length > 0);
	for (let field of spec.settings){
		let value = entry[field.key] != null ? entry[field.key] : field.default;
		let range = el("input", {className: "grow", attrs: {id: "rs_r_" + field.key}});
		range.type = "range"; range.min = field.min; range.max = field.max; range.step = 1; range.value = value;
		let number = el("input", {className: "input mono", style: "flex:0 0 84px;width:84px",
			attrs: {id: "rs_" + field.key}});
		number.type = "number"; number.min = field.min; number.max = field.max; number.value = value;
		range.oninput = function(){ number.value = range.value; };
		number.oninput = function(){ range.value = number.value; };

		settings.appendChild(el("div", {className: "col", style: "gap:8px"}, [
			el("div", {className: "row baseline", style: "gap:10px"}, [
				el("span", {className: "grow", text: field.label, style: "font-size:var(--fs-body);color:var(--t1)"}),
				el("span", {className: "card-code", text: "faixa " + field.min + "–" + field.max})
			]),
			el("div", {className: "row"}, [
				range, number,
				el("span", {className: "card-code", style: "flex:0 0 auto", text: field.unit || ""})
			]),
			field.help ? el("span", {className: "field-hint", text: field.help}) : null
		]));
	}

	open_modal("responderModal");
}

function responder_form_payload(){
	let spec = responder_spec(responder_open);
	let payload = {enabled: $("responderEnabled").classList.contains("on")};
	for (let field of spec.credentials){
		payload[field.key] = $("rf_" + field.key).value;
	}
	for (let field of spec.settings){
		payload[field.key] = $("rs_" + field.key).value;
	}
	return payload;
}

function save_responder(){
	if (!responder_open){ return; }
	let spec = responder_spec(responder_open);
	$("responderSaveBtn").disabled = true;
	post_json("api/responders/" + encodeURIComponent(responder_open), responder_form_payload())
		.then(function(result){
			$("responderSaveBtn").disabled = false;
			if (!result.ok){
				set_status("responderModalStatus", (result.data && result.data.error) || "Não foi possível salvar.", "bad");
				return;
			}
			responder_config = result.data.config || responder_config;
			spec.availableTargets = result.data.availableTargets || spec.availableTargets;
			render_responder_cards();
			toast(spec.name + ": configuração salva.", "ok");
			open_responder_modal(responder_open);
			set_status("responderModalStatus", "Configuração salva.", "ok");
		});
}

function test_responder(){
	if (!responder_open){ return; }
	$("responderTestBtn").disabled = true;
	$("responderTestDetail").textContent = "";
	set_status("responderModalStatus", "verificando credencial e alcance…");

	post_json("api/responders/" + encodeURIComponent(responder_open) + "/test", responder_form_payload())
		.then(function(result){
			$("responderTestBtn").disabled = false;
			let data = result.data || {};
			if (!result.ok){
				set_status("responderModalStatus", data.error || "A verificação falhou.", "bad");
				return;
			}
			if (!data.ok){
				set_status("responderModalStatus", data.error, "bad");
				return;
			}
			set_status("responderModalStatus", "Conexão verificada.", "ok");
			$("responderTestDetail").textContent = data.detail;
		});
}

/* ========================================================================== */
/* Bloquear indicadores                                                       */
/*                                                                            */
/* É a whitelist ao contrário, e o modal foi desenhado igual de propósito: a   */
/* escolha é a mesma, o efeito é oposto. A diferença que se vê na tela é que   */
/* aqui se marca também o destino, e que o resultado volta linha por linha —   */
/* um firewall inalcançável não impede o gateway de e-mail de ser acionado, e  */
/* o analista precisa ver os dois desfechos no mesmo lugar.                    */
/* ========================================================================== */

// Os tipos que qualquer destino sabe bloquear. Filename e filetype não estão
// aqui porque nenhum destino bloqueia por nome de arquivo.
const BLOCKABLE_TYPES = ["mail", "domain", "url", "ip", "hash"];

const BLOCK_STATUS = {
	blocked: {label: "bloqueado", tone: "ok"},
	already: {label: "já constava", tone: ""},
	pending: {label: "aguardando", tone: "warn"},
	error: {label: "falhou", tone: "bad"}
};

let block_values = [];
let block_checked = [];
let block_responders = [];
let block_case_ref = "";

// Os destinos que aceitam ao menos um dos tipos selecionados. Oferecer um
// destino que não bloqueia nada do que está marcado só produz um resultado vazio.
function block_responder_options(){
	return responder_registry.filter(function(spec){
		let entry = responder_config[spec.id] || {};
		if (!entry.enabled){ return false; }
		let available = spec.availableTargets || spec.targets;
		return block_values.some(function(target){
			return available.indexOf(target.type) !== -1;
		});
	});
}

function open_block_modal(targets, subtitle, case_ref){
	block_values = targets.filter(function(target){
		return target.value && BLOCKABLE_TYPES.indexOf(target.type) !== -1;
	});
	block_checked = [];
	block_responders = [];
	block_case_ref = case_ref || "";
	$("blockSub").textContent = subtitle;
	set_status("blockStatus", "");
	$("blockResults").replaceChildren();
	show($("blockResults"), false);
	show($("blockSaveBtn"), true);
	render_block();
	open_modal("blockModal");
}

function open_case_block(){
	if (!selected_case){ return; }
	let case_ref = String(selected_case.ref);
	// O registro precisa estar carregado para saber quais destinos existem; quem
	// abre isto pela primeira vez veio da lista de casos, não das Integrações
	let ready = responder_registry.length > 0 ? Promise.resolve(true) : load_responders();
	ready.then(function(){
		get_json("api/cases/" + encodeURIComponent(case_ref)).then(function(detail){
			let observables = (detail && detail.observables) || [];
			open_block_modal(observables, "observáveis de " + selected_case.label, case_ref);
		});
	});
}

function open_campaign_block(){
	if (!insights_payload || !insights_payload.recurringIoc || !insights_payload.recurringIoc.value){
		toast("Nenhum IOC recorrente no período.", "bad");
		return;
	}
	let ioc = insights_payload.recurringIoc;
	let ready = responder_registry.length > 0 ? Promise.resolve(true) : load_responders();
	ready.then(function(){
		open_block_modal([{type: ioc.type, value: ioc.value, ioc: true}],
			"IOC mais recorrente do período", "");
	});
}

function render_block(){
	// Destinos
	let rows = $("blockResponderRows");
	rows.replaceChildren();
	let options = block_responder_options();

	if (options.length === 0){
		rows.appendChild(el("span", {
			className: "empty-note",
			text: responder_registry.length === 0
				? "Não foi possível carregar os destinos de bloqueio."
				: "Nenhum destino habilitado bloqueia os tipos deste caso. Configure um em Integrações → Bloqueio."
		}));
	}

	for (let spec of options){
		let on = block_responders.indexOf(spec.id) !== -1;
		let available = spec.availableTargets || spec.targets;
		let node = el("div", {
			className: "row",
			style: "gap:9px;padding:9px 10px;border-radius:8px;border:1px solid "
				+ (on ? "var(--accent)" : "var(--b1)") + ";background:" + (on ? "var(--accent-soft)" : "var(--s3)") + ";cursor:pointer"
		}, [
			el("div", {className: "check" + (on ? " on" : "")}, [icon(CHECK_ICON, 9)]),
			el("div", {className: "grow col", style: "gap:2px"}, [
				el("span", {text: spec.name, style: "font-size:var(--fs-body);color:var(--t0)"}),
				el("span", {className: "mono", text: available.join(" · "), style: "font-size:var(--fs-micro);color:var(--t4)"})
			])
		]);
		node.onclick = function(){ toggle_block_responder(spec.id); };
		rows.appendChild(node);
	}

	// Indicadores
	let list = $("blockRows");
	list.replaceChildren();
	if (block_values.length === 0){
		list.appendChild(el("span", {
			className: "empty-note",
			text: "Nenhum observável bloqueável neste caso. Só remetente, domínio, URL, IP e hash SHA-256 podem ser bloqueados."
		}));
	}

	for (let target of block_values){
		let on = block_checked.indexOf(target.value) !== -1;
		let node = el("div", {
			className: "row",
			style: "gap:9px;padding:9px 10px;border-radius:8px;border:1px solid "
				+ (on ? "var(--danger2)" : "var(--b1)") + ";background:" + (on ? "var(--danger-soft)" : "var(--s3)") + ";cursor:pointer"
		}, [
			el("div", {className: "check" + (on ? " on" : "")}, [icon(CHECK_ICON, 9)]),
			el("div", {className: "grow col", style: "gap:2px"}, [
				el("span", {className: "mono truncate", title: target.value, text: target.value, style: "font-size:var(--fs-body);color:var(--t0)"}),
				el("span", {className: "mono", text: responder_labels[target.type] || target.type, style: "font-size:var(--fs-micro);color:var(--t4)"})
			]),
			target.ioc ? el("span", {className: "pill bad", text: "IOC"}) : null
		]);
		node.onclick = function(){ toggle_block(target.value); };
		list.appendChild(node);
	}

	$("blockCount").textContent = block_checked.length > 0
		? block_checked.length + " de " + block_values.length + " selecionados"
		: "";
	$("blockAll").classList.toggle("on",
		block_values.length > 0 && block_checked.length === block_values.length);
	$("blockSaveBtn").disabled = block_checked.length === 0 || block_responders.length === 0;
}

function toggle_block(value){
	let at = block_checked.indexOf(value);
	if (at === -1){ block_checked.push(value); } else { block_checked.splice(at, 1); }
	render_block();
}

function toggle_block_all(){
	block_checked = block_checked.length === block_values.length
		? []
		: block_values.map(function(target){ return target.value; });
	render_block();
}

function toggle_block_responder(id){
	let at = block_responders.indexOf(id);
	if (at === -1){ block_responders.push(id); } else { block_responders.splice(at, 1); }
	render_block();
}

function submit_block(){
	let picked = block_values.filter(function(target){
		return block_checked.indexOf(target.value) !== -1;
	});
	if (picked.length === 0 || block_responders.length === 0){ return; }

	$("blockSaveBtn").disabled = true;
	set_status("blockStatus", "bloqueando…");

	post_json("api/block", {
		targets: picked.map(function(target){ return {type: target.type, value: target.value}; }),
		responders: block_responders,
		caseRef: block_case_ref
	}).then(function(result){
		let data = result.data || {};
		if (!result.ok){
			set_status("blockStatus", data.error || "O bloqueio falhou.", "bad");
			$("blockSaveBtn").disabled = false;
			return;
		}

		let results = data.results || [];
		let failed = results.filter(function(row){ return !row.ok; }).length;
		render_block_results(results);

		// O botão some depois de rodar: reenviar a mesma lista não desfaz nada e
		// não acrescenta nada, e um botão ainda ativo convida a isso
		show($("blockSaveBtn"), false);
		if (failed === 0){
			set_status("blockStatus", results.length + " operação(ões) concluída(s).", "ok");
			toast(picked.length + " indicador(es) enviado(s) para bloqueio.", "ok");
		} else {
			set_status("blockStatus", failed + " de " + results.length + " não puderam ser bloqueados.", "bad");
		}
	});
}

// Uma linha por par indicador × destino. O status é o do destino, não um
// resumo: "aguardando commit" é diferente de "bloqueado", e achatar os dois num
// ✓ verde faria alguém sair da tela achando que a regra já está valendo.
function render_block_results(results){
	let box = $("blockResults");
	box.replaceChildren();
	show(box, true);
	box.appendChild(el("span", {className: "field-label", text: "RESULTADO"}));

	for (let row of results){
		let status = BLOCK_STATUS[row.status] || BLOCK_STATUS.error;
		box.appendChild(el("div", {className: "col", style: "gap:3px;padding:8px 10px;border-radius:8px;background:var(--s3)"}, [
			el("div", {className: "row", style: "gap:8px"}, [
				el("span", {className: "pill " + status.tone, text: status.label}),
				el("span", {className: "mono truncate grow", title: row.value, text: row.value, style: "font-size:var(--fs-body);color:var(--t1)"})
			]),
			el("span", {className: "field-hint", text: row.responderName + " · " + (row.detail || row.error)})
		]));
	}
}

/* ========================================================================== */
/* Destinos de ticket                                                         */
/*                                                                            */
/* Só dois destinos, e os campos cabem no card: por isso não há modal aqui,    */
/* diferente dos analisadores e dos destinos de bloqueio. Um modal para dois   */
/* formulários seria marcação a mais para esconder o que já cabia na tela.     */
/* ========================================================================== */

let ticket_registry = [];
let ticket_config = {};
let ticket_verdict_labels = {};

function load_tickets(){
	get_json("api/tickets").then(function(payload){
		if (payload == null){
			$("ticketCards").replaceChildren(el("div", {className: "tbl-empty",
				text: "Não foi possível carregar os destinos de ticket."}));
			return;
		}
		ticket_registry = payload.registry || [];
		ticket_config = payload.config || {};
		ticket_verdict_labels = payload.verdictLabels || {};
		render_ticket_cards();
	});
}

function ticket_field_id(destination_id, key){
	return "tk_" + destination_id + "_" + key;
}

function ticket_field_control(destination_id, field, entry){
	if (field.options){
		let select = el("select", {className: "select", attrs: {id: ticket_field_id(destination_id, field.key)}});
		for (let option of field.options){
			let node = el("option", {text: ticket_verdict_labels[option] || option});
			node.value = option;
			if ((entry[field.key] || field.default) === option){ node.selected = true; }
			select.appendChild(node);
		}
		return el("span", {className: "select-wrap"}, [select]);
	}
	let input = el("input", {className: "input" + (field.secret ? "" : " mono"),
		attrs: {id: ticket_field_id(destination_id, field.key)}});
	input.type = field.secret ? "password" : (field.type === "number" ? "number" : "text");
	input.autocomplete = "new-password";
	// O segredo nunca volta do servidor: o placeholder é a única coisa que diz
	// que existe um gravado, e o campo vazio significa "mantenha o que está lá"
	let stored = entry["has" + field.key[0].toUpperCase() + field.key.slice(1)];
	input.placeholder = field.secret && stored
		? "•••••••• (salvo — deixe vazio para manter)"
		: (field.placeholder || "");
	if (!field.secret){
		let value = entry[field.key];
		input.value = (value === undefined || value === null) ? (field.default || "") : value;
	}
	return input;
}

function render_ticket_cards(){
	let container = $("ticketCards");
	container.replaceChildren();
	let enabled = 0;

	for (let spec of ticket_registry){
		let entry = ticket_config[spec.id] || {};
		if (entry.enabled){ enabled++; }

		let configured = spec.credentials.every(function(field){
			return !field.required || (field.secret
				? entry["has" + field.key[0].toUpperCase() + field.key.slice(1)]
				: entry[field.key]);
		});
		let tone = entry.enabled ? "ok" : (configured ? "warn" : "");
		let label = entry.enabled ? "ativo" : (configured ? "configurado, desligado" : "não configurado");

		// O card é o resumo; o formulário mora no modal. Com os campos inline, os
		// três destinos empilhavam uma dúzia de inputs na primeira coisa que se vê
		// ao abrir a aba, e a pergunta que ela responde — quem está recebendo a
		// análise — ficava soterrada. É a mesma forma dos analisadores.
		container.appendChild(el("div", {className: "card"}, [
			el("div", {className: "row top"}, [
				el("div", {className: "grow col", style: "gap:2px"}, [
					// A descrição mora no "i" ao lado do nome: numa grade de cards,
					// um parágrafo por card era o que mais pesava na tela
					el("div", {className: "title-line"}, [
						el("span", {className: "card-title", text: spec.name}),
						info_tip(spec.description)
					]),
					el("span", {className: "card-code", text: spec.kind})
				]),
				el("span", {className: "pill " + tone, text: label})
			]),
			el("div", {className: "card-foot"}, [
				el("span", {className: "status grow",
					text: ticket_verdict_labels[entry.minVerdict] || ""}),
				el("button", {className: "btn sm", text: "Configurar", attrs: {type: "button"},
					onClick: function(){ open_ticket_modal(spec.id); }})
			])
		]));
	}

	// Nem TheHive, nem Jira, nem disco significa que a análise roda e não fica
	// registrada em lugar nenhum além do log — vale dizer, não deixar descobrir
	$("ticketsNote").textContent = enabled === 0
		? "Nenhum destino habilitado: a análise roda e não fica registrada em lugar nenhum além do log."
		: enabled + " de " + ticket_registry.length + " destino(s) recebendo cada análise.";
	update_integr_summary();
}


/* A linha sob o título de Integrações.
 *
 * Ela dizia "TheHive conectado" / "TheHive ainda sem chave de API", lendo a
 * chave de um destino como se fosse a conexão da plataforma. Desde que o
 * registro do caso virou combinável isso passou a mentir nos dois sentidos:
 * quem grava só em Jira ou em disco via um aviso de falha que não existia, e
 * quem tinha a chave do TheHive guardada mas o destino desligado via "conectado"
 * enquanto nada era registrado ali.
 *
 * Agora ela responde a pergunta que o cabeçalho faz — onde a análise fica
 * registrada — e responde a partir da mesma configuração que desenha os cards,
 * de modo que não há um segundo lugar para ficar defasado. Diz *quais*, e não
 * quantos: quantos já está no card da aba Tickets, e o cabeçalho tem espaço
 * para a informação que o operador não consegue deduzir de outro jeito.
 */
function update_integr_summary(){
	let node = $("integrSummary");
	if (!node){ return; }
	// Antes da primeira carga não se sabe nada, e um resumo chutado é pior que
	// um travessão: ele seria lido como resposta
	if (ticket_registry.length === 0){
		node.textContent = "—";
		return;
	}
	let active = ticket_registry.filter(function(spec){
		return (ticket_config[spec.id] || {}).enabled;
	}).map(function(spec){ return spec.name; });
	node.textContent = active.length === 0
		? "nenhum destino de registro ativo"
		: "registrando em " + active.join(" · ");
}

// Qual destino o modal está editando. Só um por vez, então os ids dos campos
// continuam sendo tk_<destino>_<campo> — eles existem enquanto o modal existe.
let ticket_open = null;

function ticket_spec(destination_id){
	return ticket_registry.filter(function(s){ return s.id === destination_id; })[0] || null;
}

function open_ticket_modal(destination_id){
	let spec = ticket_spec(destination_id);
	if (!spec){ return; }
	ticket_open = destination_id;
	let entry = ticket_config[destination_id] || {};

	$("ticketModalTitle").textContent = spec.name;
	$("ticketModalKind").textContent = spec.kind;
	$("ticketModalDesc").textContent = spec.description;
	set_status("ticketModalStatus", "");
	$("ticketTestHint").textContent = spec.testHint || "";

	let toggle = el("div", {className: "toggle" + (entry.enabled ? " on" : ""),
		attrs: {id: "tk_" + destination_id + "_enabled"}}, [el("span", {className: "knob"})]);
	toggle.onclick = function(){ toggle.classList.toggle("on"); };

	let fields = spec.credentials.concat(spec.settings || []).map(function(field){
		return el("label", {className: "field"}, [
			el("span", {className: "field-label",
				text: field.label + (field.unit ? " (" + field.unit + ")" : "")}),
			ticket_field_control(destination_id, field, entry),
			field.help ? el("span", {className: "field-hint", text: field.help}) : null
		]);
	});

	$("ticketFields").replaceChildren(
		el("div", {className: "row top"}, [
			el("div", {className: "grow col", style: "gap:4px"}, [
				el("span", {className: "card-title", text: "Habilitar destino"}),
				el("span", {className: "field-hint", text: "desligado, ele não recebe nenhuma análise"})
			]),
			toggle
		]),
		el("div", {className: "grid-auto"}, fields)
	);

	let docs = $("ticketDocs");
	docs.replaceChildren();
	if (spec.docs){
		docs.appendChild(el("a", {text: "documentação da API",
			attrs: {href: spec.docs, target: "_blank", rel: "noopener noreferrer"}}));
	}
	show(docs, !!spec.docs);

	open_modal("ticketModal");
}

function ticket_form_payload(destination_id){
	let spec = null;
	for (let candidate of ticket_registry){
		if (candidate.id === destination_id){ spec = candidate; }
	}
	if (!spec){ return null; }
	let payload = {enabled: switch_on("tk_" + destination_id + "_enabled")};
	for (let field of spec.credentials.concat(spec.settings || [])){
		let node = $(ticket_field_id(destination_id, field.key));
		payload[field.key] = node ? node.value : "";
	}
	return payload;
}

function save_ticket_destination(){
	if (!ticket_open){ return; }
	let payload = ticket_form_payload(ticket_open);
	if (!payload){ return; }
	set_status("ticketModalStatus", "salvando…");
	post_json("api/tickets/" + encodeURIComponent(ticket_open), payload).then(function(result){
		if (result.ok && result.data && result.data.ok){
			ticket_config = result.data.config || ticket_config;
			close_modal();
			render_ticket_cards();
			toast("Destino salvo.", "ok");
		} else {
			let error = (result.data && result.data.error) || "Configuração inválida: revise os campos.";
			set_status("ticketModalStatus", error, "bad");
		}
	});
}

// Estritamente leitura: o Jira consulta o projeto, o disco escreve e apaga um
// arquivo vazio. Um Testar que abrisse chamado de verdade seria armadilha.
// É o oposto do botão Testar de um conector, e a diferença está dita nas duas
// telas: lá o endpoint é escolhido pelo usuário e não há como saber se é inócuo.
function test_ticket_destination(){
	if (!ticket_open){ return; }
	let payload = ticket_form_payload(ticket_open);
	if (!payload){ return; }
	set_status("ticketModalStatus", "testando…");
	post_json("api/tickets/" + encodeURIComponent(ticket_open) + "/test", payload).then(function(result){
		if (result.ok && result.data && result.data.ok){
			set_status("ticketModalStatus",
				result.data.detail + ". Nenhum ticket foi criado.", "ok");
		} else {
			let error = (result.data && result.data.error) || "Não foi possível alcançar o destino.";
			set_status("ticketModalStatus", error, "bad");
		}
	});
}

/* ========================================================================== */
/* Case history — analyzed emails, confirmed phishing, executive insights     */
/*                                                                            */
/* TheHive is the system of record for everything already analyzed, so these   */
/* three screens are views over /api/insights and /api/cases. None of them     */
/* fabricates a figure: an empty window renders an empty state.                */
/* ========================================================================== */

let insights_range = "30d";
let insights_payload = null;
let cases_range = "30d";
let cases_verdict = "all";
let cases_query = "";
let cases_ioc = "";
// Fatia clicada num gráfico da aba Phishing: {tier} ou {auth: "dmarc:fail"}, com o rótulo do chip
let cases_signal = null;
let case_rows = [];
let selected_case = null;
let phish_rows = [];
let phish_windows = null;

function verdict_tone(verdict){
	return VERDICT_TONE[verdict] || "";
}

function verdict_label(verdict){
	return VERDICT_LABEL[verdict] || (verdict || "").toUpperCase();
}

// TheHive timestamps are epoch milliseconds
function format_date(ms){
	if (!ms){ return "—"; }
	let date = new Date(ms);
	return date.toLocaleDateString("pt-BR") + " " + date.toLocaleTimeString("pt-BR", {hour: "2-digit", minute: "2-digit"});
}

function format_day(iso){
	let parts = String(iso).split("-");
	return parts.length === 3 ? parts[2] + "/" + parts[1] : iso;
}

/* --- executive dashboard -------------------------------------------------- */

/* The LLM answers with a closed vocabulary (llm_analysis.TACTICS) precisely so
 * the tactics can be counted; the keys are the contract, and this is where they
 * become Portuguese. An unknown key is shown raw rather than dropped: a model
 * answering something new should be visible, not silently discarded. */
const TACTIC_LABEL = {
	urgency: "Urgência",
	authority: "Autoridade",
	impersonation: "Falsidade ideológica",
	credential_harvesting: "Roubo de credenciais",
	payment_fraud: "Fraude de pagamento",
	fear: "Medo",
	reward: "Recompensa",
	curiosity: "Curiosidade",
	malicious_link: "Link malicioso",
	malicious_attachment: "Anexo malicioso",
	filter_evasion: "Evasão de filtro",
	pretexting: "Pretexto"
};

function tactic_label(key){
	return TACTIC_LABEL[key] || key;
}

const RISK_LABEL = {Critical: "Crítico", High: "Alto", Medium: "Médio", Low: "Baixo"};
const RISK_TONE = {Critical: "bad", High: "bad", Medium: "warn", Low: "ok"};

function percent(part, total){
	return total > 0 ? Math.round(part * 100 / total) : 0;
}

const RANGE_LABEL = {"1d": "24 horas", "7d": "7 dias", "15d": "15 dias", "30d": "30 dias",
	"60d": "60 dias", "90d": "90 dias", "180d": "180 dias"};

function range_window_label(key){
	if (key === "all"){ return "todo o histórico"; }
	if (key === "1d"){ return "últimas 24 horas"; }
	return "últimos " + (RANGE_LABEL[key] || key);
}

// Os dois seletores de período — os chips da Visão Executiva e os blocos do
// Phishing — mostram a mesma escolha, porque é uma variável só por trás deles
function sync_range_controls(range){
	for (let chip of $$("#execRanges .chip")){
		chip.classList.toggle("active", chip.dataset.arg === range);
	}
	for (let tile of $$("#phishWindows .window-tile")){
		tile.classList.toggle("active", tile.dataset.arg === range);
		tile.setAttribute("aria-pressed", tile.dataset.arg === range ? "true" : "false");
	}
}

function set_insights_range(range){
	insights_range = range;
	sync_range_controls(range);
	load_insights();
}

function reload_insights(){
	insights_payload = null;
	load_insights();
}

function load_insights(){
	$("execSub").textContent = "consultando informações…";
	get_json("api/insights?range=" + encodeURIComponent(insights_range)).then(function(payload){
		if (payload == null || payload.error){
			insights_payload = null;
			show($("execError"), true);
			$("execErrorText").textContent = (payload && payload.error)
				|| "Não foi possível consultar os registros. Confira o destino em Integrações.";
			$("execSub").textContent = "sem dados";
			render_exec(null);
			render_phish_insights(null);
			return;
		}
		show($("execError"), false);
		insights_payload = payload;
		render_exec(payload);
		render_phish_insights(payload);
	});
}

function render_exec(payload){
	let kpis = $("execKpis");
	let volume = $("execVolume");
	let verdicts = $("execVerdicts");
	let senders = $("execSenders");
	let subjects = $("execSubjects");

	if (payload == null){
		for (let node of [kpis, verdicts, senders, subjects]){ node.replaceChildren(); }
		volume.replaceChildren(el("div", {className: "chart-empty", text: "sem dados no período"}));
		show($("execCampaign"), false);
		$("execTotalCases").textContent = "—";
		render_exec_extras(payload);
		return;
	}

	let window_label = range_window_label(payload.range);
	$("execSub").textContent = window_label + " · atualizado " + format_date(payload.generatedAt)
		+ (payload.truncated ? " · janela truncada em " + payload.kpis.analyzed + " casos" : "");
	$("navDoneBadge").textContent = payload.kpis.analyzed > 0 ? String(payload.kpis.analyzed) : "";
	$("navTacticBadge").textContent = payload.kpis.malicious > 0 ? String(payload.kpis.malicious) : "";
	$("execTotalCases").textContent = payload.kpis.analyzed + " casos";

	// KPI tiles
	kpis.replaceChildren();
	let tiles = [
		{label: "E-MAILS ANALISADOS", value: payload.kpis.analyzed, note: window_label},
		{label: "MALICIOSOS", value: payload.kpis.malicious, tone: "bad", note: payload.kpis.maliciousRate + "% do total"},
		{label: "AGUARDANDO ANÁLISE", value: payload.kpis.pending, tone: "warn", note: "casos ainda abertos"},
		{label: "LEGÍTIMOS", value: payload.kpis.safe, tone: "ok", note: "encerrados como falso positivo"}
	];
	for (let tile of tiles){
		kpis.appendChild(el("div", {className: "kpi"}, [
			el("span", {className: "kpi-label mono", text: tile.label}),
			el("span", {className: "kpi-value" + (tile.tone ? " " + tile.tone : ""), text: String(tile.value)}),
			el("span", {className: "kpi-note", text: tile.note})
		]));
	}

	// Daily volume — each column scaled against the busiest day.
	//
	// The column carries its own total and date; the tooltip only adds the
	// threat/legit split, so the chart still reads with the mouse away from it.
	// Ticks thin out on long windows: 30 or 90 labels in a 320px card is noise.
	volume.replaceChildren();
	let peak = payload.daily.reduce(function(max, day){ return Math.max(max, day.threat + day.safe); }, 0);
	if (peak === 0){
		volume.replaceChildren(el("div", {className: "chart-empty", text: "nenhum e-mail analisado no período"}));
	} else {
		let every = Math.ceil(payload.daily.length / 10);
		payload.daily.forEach(function(day, index){
			let total = day.threat + day.safe;
			let labelled = index % every === 0 || index === payload.daily.length - 1;
			volume.appendChild(el("div", {className: "chart-col"}, [
				el("span", {className: "chart-num", text: total > 0 ? String(total) : ""}),
				el("div", {className: "chart-stack"}, [
					day.threat > 0 ? el("div", {className: "chart-seg threat", style: "height:" + (day.threat / peak * 100) + "%"}) : null,
					day.safe > 0 ? el("div", {className: "chart-seg safe", style: "height:" + (day.safe / peak * 100) + "%"}) : null
				]),
				el("span", {className: "chart-tick", text: labelled ? format_day(day.date) : ""}),
				el("div", {className: "chart-tip"}, [
					el("span", {className: "chart-tip-day", text: format_day(day.date)}),
					el("span", {text: day.threat + " com ameaça"}),
					el("span", {className: "muted", text: day.safe + " legítimos"})
				])
			]));
		});
	}
	$("execVolumeRange").textContent = payload.daily.length + " dia(s) · UTC";

	// Verdict distribution
	verdicts.replaceChildren();
	let total = payload.verdicts.reduce(function(sum, entry){ return sum + entry.count; }, 0) || 1;
	let bar_tone = {Malicious: "", Suspicious: "warn", Safe: "ok", Other: "muted"};
	for (let entry of payload.verdicts){
		verdicts.appendChild(el("div", {className: "col", style: "gap:6px"}, [
			el("div", {className: "row baseline", style: "gap:8px"}, [
				el("span", {className: "grow", text: verdict_label(entry.key), style: "font-size:var(--fs-body);color:var(--t2)"}),
				el("span", {className: "mono", text: String(entry.count), style: "font-size:var(--fs-micro);color:var(--t3)"})
			]),
			el("div", {className: "meter"}, [
				el("span", {className: bar_tone[entry.key] || "", style: "width:" + (entry.count / total * 100) + "%"})
			])
		]));
	}

	// Top senders
	senders.replaceChildren();
	if (payload.topSenders.length === 0){
		senders.appendChild(el("div", {className: "tbl-empty", text: "nenhum remetente com veredito de ameaça no período"}));
	}
	for (let sender of payload.topSenders){
		senders.appendChild(el("div", {className: "rank-row"}, [
			el("span", {className: "mono truncate", text: sender.value, title: sender.value, style: "font-size:var(--fs-body);color:var(--t1)"}),
			el("span", {className: "mono", text: String(sender.count), style: "font-size:var(--fs-micro);color:var(--t3);text-align:right"}),
			el("span", {
				className: "pill " + (sender.malicious > 0 ? "bad" : "warn"),
				text: sender.malicious > 0 ? sender.malicious + " malic." : "suspeito"
			})
		]));
	}

	// Top subjects
	subjects.replaceChildren();
	render_ranked_bars(subjects, payload.topSubjects, "label", "count", "nenhum assunto no período");

	render_exec_extras(payload);
}

/* A panel with nothing to show says what is missing, never a zero or an empty
 * bar. In a tool whose only job is to tell an analyst what is true about an
 * email, a placeholder that reads like a measurement is worse than no panel. */
function render_pending(id, text){
	let node = $(id);
	if (!node){ return; }
	node.replaceChildren(el("span", {className: "empty-note", text: text}));
}

/* Insights da IA — what the model concluded across the window.
 *
 * Every figure is over `assessed`, the number of cases the model actually
 * judged, and the card says so out loud. An instance whose LLM is off, or was
 * unreachable for half the window, must not read as "the model found nothing":
 * that is the one misreading that would send an executive the wrong way. */
function render_exec_insights(payload){
	let container = $("execInsights");
	let insights = payload && payload.llmInsights;
	let code = $("execInsightsCode");

	if (!insights || insights.assessed === 0){
		if (code){ code.textContent = ""; }
		render_pending("execInsights", payload && payload.kpis.analyzed > 0
			? "Nenhum dos " + payload.kpis.analyzed + " casos do período traz avaliação do LLM. Habilite a análise de engenharia social em Configurações › IA."
			: "Sem casos no período.");
		return;
	}

	if (code){ code.textContent = insights.assessed + " de " + payload.kpis.analyzed + " avaliados"; }
	container.replaceChildren();

	let se_rate = percent(insights.socialEngineering, insights.assessed);
	let lines = [
		{
			title: "Engenharia social em " + se_rate + "% do que foi avaliado",
			body: insights.socialEngineering + " de " + insights.assessed
				+ " e-mails avaliados pelo modelo trazem sinais de engenharia social.",
			tone: se_rate >= 50 ? "bad" : (se_rate > 0 ? "warn" : "ok")
		},
		{
			title: insights.highRisk > 0
				? insights.highRisk + " avaliação(ões) de risco alto ou crítico"
				: "Nenhum risco alto ou crítico no período",
			body: insights.highRisk > 0
				? "São as que o modelo julgou mais graves — comece a revisão por elas."
				: "O modelo não classificou nenhum e-mail avaliado acima de risco médio.",
			tone: insights.highRisk > 0 ? "bad" : "ok"
		}
	];
	if (payload.topTactics && payload.topTactics.length > 0){
		let top = payload.topTactics[0];
		lines.push({
			title: "Tática mais reconhecida: " + tactic_label(top.key),
			body: "Aparece em " + top.count + " e-mail(s) do período.",
			tone: "warn"
		});
	}
	if (insights.notAssessed > 0){
		lines.push({
			title: insights.notAssessed + " caso(s) sem avaliação do modelo",
			body: "Ficaram de fora das contas acima: o LLM estava desligado ou inalcançável quando foram analisados.",
			tone: ""
		});
	}

	for (let line of lines){
		container.appendChild(el("div", {className: "insight"}, [
			el("span", {className: "dot " + (line.tone || "")}),
			el("div", {className: "col grow", style: "gap:3px"}, [
				el("span", {className: "insight-title", text: line.title}),
				el("span", {className: "insight-body", text: line.body})
			])
		]));
	}

	// Risk distribution, only for the levels that actually occurred
	let present = insights.risk.filter(function(level){ return level.count > 0; });
	if (present.length > 0){
		container.appendChild(el("div", {className: "row", style: "gap:6px;flex-wrap:wrap;margin-top:2px"},
			present.map(function(level){
				return el("span", {
					className: "pill " + (RISK_TONE[level.key] || ""),
					text: (RISK_LABEL[level.key] || level.key) + " · " + level.count
				});
			})));
	}
}

/* Táticas mais frequentes — counted from the tactic: tags of the window */
function render_exec_tactics(payload){
	let assessed = payload && payload.llmInsights ? payload.llmInsights.assessed : 0;
	if (!payload || !payload.topTactics || payload.topTactics.length === 0){
		render_pending("execTactics", assessed > 0
			? "O LLM avaliou " + assessed + " e-mail(s) no período sem reconhecer nenhuma das táticas do vocabulário."
			: "Nenhuma avaliação do LLM no período — as táticas vêm dela.");
		return;
	}
	render_ranked_bars($("execTactics"),
		payload.topTactics.map(function(tactic){
			return {label: tactic_label(tactic.key), count: tactic.count};
		}), "label", "count", "");
}

/* Departamentos mais visados — resolved from the reporter's address.
 *
 * The card counts every report, not only the malicious ones: the question is
 * which desks the attempts are reaching. Reports no rule claimed are reported
 * as such under the card instead of being folded into a bucket. */
function render_exec_departments(payload){
	let code = $("execDeptsCode");
	let unattributed = payload ? (payload.departmentsUnattributed || 0) : 0;

	if (!payload || !payload.topDepartments || payload.topDepartments.length === 0){
		if (code){ code.textContent = "quem denunciou"; }
		render_pending("execDepts", payload && payload.kpis.analyzed > 0
			? "Nenhuma das " + payload.kpis.analyzed + " denúncias do período foi atribuída a um departamento. Declare as regras em Configurações › Departamentos."
			: "Sem denúncias no período.");
		return;
	}

	if (code){ code.textContent = payload.departmentsTotal + " departamento(s)"; }
	render_ranked_bars($("execDepts"), payload.topDepartments, "label", "count", "");
	if (unattributed > 0){
		$("execDepts").appendChild(el("span", {
			className: "field-hint",
			text: unattributed + " denúncia(s) sem departamento: nenhuma regra casou com o endereço."
		}));
	}
}

function render_exec_extras(payload){
	render_exec_insights(payload);
	render_exec_tactics(payload);
	render_exec_departments(payload);
}

// Shared renderer for the "label + bar + count" lists
function render_ranked_bars(container, items, label_key, count_key, empty_text){
	container.replaceChildren();
	if (!items || items.length === 0){
		container.appendChild(el("span", {className: "field-hint", text: empty_text}));
		return;
	}
	let peak = items.reduce(function(max, item){ return Math.max(max, item[count_key]); }, 0) || 1;
	for (let item of items){
		container.appendChild(el("div", {className: "col", style: "gap:5px"}, [
			el("div", {className: "row baseline", style: "gap:8px"}, [
				el("span", {className: "grow truncate", text: item[label_key], title: item[label_key], style: "font-size:var(--fs-body);color:var(--t2)"}),
				el("span", {className: "mono", text: String(item[count_key]), style: "font-size:var(--fs-micro);color:var(--t3);flex:0 0 auto"})
			]),
			el("div", {className: "meter", style: "height:5px"}, [
				el("span", {style: "width:" + (item[count_key] / peak * 100) + "%"})
			])
		]));
	}
}

/* --- phishing insights panel ---------------------------------------------- */

function render_phish_insights(payload){
	if (payload == null){
		// Sem dado nenhum, cada painel diz o que falta. Um zero aqui seria lido
		// como medição, e medir "zero phishing" quando na verdade a consulta não
		// respondeu é o pior erro que esta tela pode cometer
		show($("phishCampaign"), false);
		render_pending("phishSubjects", "Não foi possível consultar os registros do período.");
		render_pending("phishAuthStats", "Não foi possível consultar os registros do período.");
		render_pending("phishTiers", "Não foi possível consultar os registros do período.");
		render_pending("phishActions", "Não foi possível consultar os registros do período.");
		render_pending("phishSenders", "Não foi possível consultar os registros do período.");
		$("phishIocTable").replaceChildren(el("div", {className: "tbl-empty",
			text: "Não foi possível consultar os registros do período."}));
		$("phishAuthScope").textContent = "—";
		$("phishTierScope").textContent = "—";
		$("phishSendersMode").textContent = "—";
		$("phishIocMode").textContent = "—";
		$("phishSendersNote").textContent = "";
		$("phishHeadlineTitle").textContent = "Sem dados no período";
		$("phishHeadlineText").textContent = "A consulta aos casos não respondeu. Nada nesta tela "
			+ "está sendo estimado — os painéis ficam vazios até haver registro.";
		return;
	}

	// The campaign card only appears when an IOC actually recurs across cases
	let campaign = payload.recurringIoc;
	show($("phishCampaign"), !!campaign);
	show($("execCampaign"), !!campaign);
	if (campaign){
		$("phishCampaignValue").textContent = campaign.value;
		$("phishCampaignText").textContent = "Presente em " + campaign.cases
			+ " casos distintos no período. Bloquear esse " + (campaign.type || "indicador") + " atinge a campanha inteira.";
		$("execCampaignCount").textContent = campaign.cases + " casos";
		$("execCampaignText").textContent = "O indicador " + campaign.value + " (" + (campaign.type || "IOC")
			+ ") aparece em " + campaign.cases + " casos distintos do período — a mesma infraestrutura sendo reaproveitada contra a organização.";
	}

	render_ranked_bars($("phishSubjects"), payload.topSubjects, "label", "count", "nenhum assunto no período");
	phish_live_at = new Date();
	phish_live_failed = false;
	render_phish_live_stamp();

	render_phish_auth(payload);
	render_phish_tiers(payload);
	render_phish_actions(payload);
	render_phish_tactical(payload);
}

/* --- assuntos predominantes, ao vivo ---------------------------------------
 *
 * Duas fontes, mostradas separadas de propósito:
 *
 * - os casos já analisados no período, de /api/insights, relidos a cada 30 s
 *   enquanto a tela Phishing está aberta e a aba do navegador está visível;
 * - o que está na fila da caixa agora, sem veredito, do push `inbox` do socket —
 *   que já chega em tempo real e não custa requisição nenhuma.
 *
 * Somar as duas numa lista só faria um e-mail que ninguém julgou contar como
 * assunto de phishing. A releitura é silenciosa: não troca o texto por
 * "consultando…" e, se falhar, mantém a última leitura boa na tela e diz de
 * quando ela é, em vez de esvaziar o painel. */

const PHISH_LIVE_MS = 30000;
let phish_live_timer = null;
let phish_live_at = null;      // quando chegou a leitura que está na tela
let phish_live_failed = false; // a última releitura falhou

function start_phish_live(){
	if (phish_live_timer){ return; }
	phish_live_timer = window.setInterval(refresh_phish_live, PHISH_LIVE_MS);
}

function stop_phish_live(){
	window.clearInterval(phish_live_timer);
	phish_live_timer = null;
}

// Tudo menos o carimbo de geração: sem isso, toda releitura pareceria mudança
function insights_fingerprint(payload){
	return payload ? JSON.stringify(Object.assign({}, payload, {generatedAt: null})) : "";
}

function refresh_phish_live(){
	if (current_view !== "tactic"){ stop_phish_live(); return; }
	if (document.hidden){ return; }
	let range = insights_range;
	get_json("api/insights?range=" + encodeURIComponent(range)).then(function(payload){
		// O período mudou enquanto a consulta andava: quem responde pela troca é
		// o load_insights que ela disparou, não esta releitura
		if (range !== insights_range){ return; }
		if (payload == null || payload.error){
			phish_live_failed = true;
			render_phish_live_stamp();
			return;
		}
		if (insights_fingerprint(payload) === insights_fingerprint(insights_payload)){
			phish_live_at = new Date();
			phish_live_failed = false;
			render_phish_live_stamp();
			return;
		}
		insights_payload = payload;
		render_exec(payload);
		render_phish_insights(payload);
	});
}

document.addEventListener("visibilitychange", function(){
	if (!document.hidden && current_view === "tactic" && insights_payload != null){ refresh_phish_live(); }
});

function render_phish_live_stamp(){
	let stamp = $("phishSubjectsStamp");
	if (!stamp){ return; }
	if (!phish_live_at){ stamp.textContent = ""; return; }
	let time = phish_live_at.toLocaleTimeString("pt-BR", {hour: "2-digit", minute: "2-digit", second: "2-digit"});
	stamp.classList.toggle("stale", phish_live_failed);
	stamp.textContent = phish_live_failed
		? "releitura falhou · dados de " + time
		: "atualizado às " + time;
}

/* Mesma normalização de case_insights.normalize_subject, para que um assunto da
 * fila e o mesmo assunto já analisado sejam agrupados pelo mesmo critério */
function normalize_subject(title){
	let subject = String(title || "").trim();
	subject = subject.replace(/^(?:\s*(?:re|res|fw|fwd|enc|encaminhando)\s*:\s*)+/i, "");
	subject = subject.replace(/[#nN]?\s*\d[\d.,/-]{3,}\b/g, "…");
	subject = subject.replace(/\s+/g, " ").trim();
	return subject.slice(0, 80);
}

function render_phish_inbox_subjects(){
	let container = $("phishInboxSubjects");
	if (!container){ return; }
	let count = $("phishInboxSubjectsCount");
	if (!queue_listed){
		count.textContent = "";
		render_pending("phishInboxSubjects", "A caixa ainda não foi lida nesta sessão.");
		return;
	}
	let counts = {};
	let loading = 0;
	for (let mail of queue){
		// O assunto do e-mail denunciado só existe depois que a mensagem foi
		// lida; antes disso ele não é "sem assunto", é "ainda não sabemos"
		if (mail.bodyLoaded === false){ loading++; continue; }
		let subject = normalize_subject(mail.attachedMail);
		if (subject){ counts[subject] = (counts[subject] || 0) + 1; }
	}
	count.textContent = queue.length + " na fila" + (loading ? " · " + loading + " carregando" : "");
	let items = Object.keys(counts).map(function(label){ return {label: label, count: counts[label]}; })
		.sort(function(a, b){ return b.count - a.count || (a.label < b.label ? 1 : a.label > b.label ? -1 : 0); })
		.slice(0, 5);
	if (queue.length === 0){
		render_pending("phishInboxSubjects", "Nenhum e-mail aguardando análise.");
	} else if (items.length === 0){
		render_pending("phishInboxSubjects", loading
			? "Os assuntos aparecem conforme os e-mails terminam de carregar."
			: "Nenhum assunto legível nos e-mails da fila.");
	} else {
		render_ranked_bars(container, items, "label", "count", "");
	}
}

/* --- sinais de autenticação somados na janela ------------------------------
 *
 * A regra que governa este bloco: um caso sem registro de SPF/DKIM/DMARC não é
 * um caso que falhou. Ele é contado à parte e fica fora do percentual, porque
 * somá-lo a `fail` inventaria falha que ninguém observou — e é sobre esse
 * número que alguém decide endurecer uma política de DMARC. */
const AUTH_LABEL = {spf: "SPF", dkim: "DKIM", dmarc: "DMARC"};

/* --- gráfico de pizza (rosca) ------------------------------------------------
 *
 * SVG montado por createElementNS no próprio bundle — a CSP não aceita script
 * inline, e uma biblioteca de gráficos inteira para duas roscas é peso sem
 * retorno. O raio dá circunferência 100, então cada fatia é a sua própria
 * porcentagem no dasharray.
 *
 * A pizza nunca é a única forma de ler o número: o rótulo acessível traz as
 * contagens por extenso e a legenda ao lado as repete com a porcentagem. Cor
 * sozinha não distingue fail de outro para quem não enxerga a diferença. */
const SVG_NS = "http://www.w3.org/2000/svg";

function svg_node(tag, attrs){
	let node = document.createElementNS(SVG_NS, tag);
	for (let key of Object.keys(attrs || {})){ node.setAttribute(key, attrs[key]); }
	return node;
}

// slices: [{label, count, tone}] — tone é bad | warn | ok | muted
function donut_chart(slices, value, unit, size_class){
	let total = slices.reduce(function(sum, slice){ return sum + slice.count; }, 0);
	// Com fatia clicável o gráfico vira um grupo de botões; sem, é uma imagem só
	let interactive = slices.some(function(slice){ return slice.pick && slice.count > 0; });
	let svg = svg_node("svg", interactive ? {viewBox: "0 0 42 42"} : {viewBox: "0 0 42 42", "aria-hidden": "true"});
	svg.appendChild(svg_node("circle", {class: "donut-track", cx: 21, cy: 21, r: 15.9155}));

	let drawn = slices.filter(function(slice){ return slice.count > 0; });
	// Um respiro entre fatias vizinhas; uma fatia sozinha fecha o anel inteiro
	let gap = drawn.length > 1 ? 0.8 : 0;
	let offset = 0;
	for (let slice of drawn){
		let share = slice.count * 100 / total;
		let seg = svg_node("circle", {
			class: "donut-seg " + (slice.tone || ""),
			cx: 21, cy: 21, r: 15.9155,
			"stroke-dasharray": Math.max(share - gap, 0.4) + " " + (100 - Math.max(share - gap, 0.4)),
			"stroke-dashoffset": String(-offset)
		});
		let tip = svg_node("title", {});
		tip.textContent = slice.label + ": " + slice.count + " (" + percent(slice.count, total) + "%)";
		if (slice.pick){
			tip.textContent += " — clique para ver os casos";
			seg.classList.add("pickable");
			seg.setAttribute("tabindex", "0");
			seg.setAttribute("role", "button");
			seg.setAttribute("aria-label", slice.label + ": " + slice.count + " caso(s). Ver os casos");
			seg.addEventListener("click", slice.pick);
			seg.addEventListener("keydown", function(event){
				if (event.key === "Enter" || event.key === " "){
					event.preventDefault();
					slice.pick();
				}
			});
		}
		seg.appendChild(tip);
		svg.appendChild(seg);
		offset += share;
	}

	let summary = total === 0 ? "sem registro"
		: slices.map(function(slice){ return slice.label + " " + slice.count; }).join(", ");
	return el("div", {className: "donut" + (size_class ? " " + size_class : ""),
		attrs: {role: interactive ? "group" : "img", "aria-label": unit + " — " + summary}}, [
		svg,
		el("div", {className: "donut-center"}, [
			el("span", {className: "donut-value", text: value}),
			unit ? el("span", {className: "donut-unit", text: unit}) : null
		])
	]);
}

function chart_legend(slices, inline){
	let total = slices.reduce(function(sum, slice){ return sum + slice.count; }, 0);
	return el("div", {className: "chart-legend" + (inline ? " inline" : "")},
		slices.map(function(slice){
			let pickable = !inline && slice.pick && slice.count > 0;
			return el(pickable ? "button" : "div", {
				className: "legend-row" + (pickable ? " pickable" : ""),
				attrs: pickable ? {type: "button", title: "Ver os casos: " + slice.label} : null,
				onClick: pickable ? slice.pick : null}, [
				el("span", {className: "swatch " + (slice.tone || "")}),
				el("span", {className: "legend-name", text: slice.label}),
				inline ? null : el("span", {className: "legend-count", text: String(slice.count)}),
				inline ? null : el("span", {className: "legend-pct", text: percent(slice.count, total) + "%"})
			]);
		}));
}

/* --- sinais de autenticação somados na janela ------------------------------
 *
 * A regra que governa este bloco: um caso sem registro de SPF/DKIM/DMARC não é
 * um caso que falhou. Ele é contado à parte e fica fora da pizza e do
 * percentual, porque somá-lo a `fail` inventaria falha que ninguém observou — e
 * é sobre esse número que alguém decide endurecer uma política de DMARC. */
function render_phish_auth(payload){
	let box = $("phishAuthStats");
	box.replaceChildren();
	let stats = payload.authStats || [];
	let recorded = stats.reduce(function(max, row){ return Math.max(max, row.recorded); }, 0);

	if (recorded === 0){
		$("phishAuthScope").textContent = "—";
		box.appendChild(el("span", {className: "empty-note",
			text: "Nenhum caso do período traz os cabeçalhos de autenticação registrados. "
				+ "Casos analisados antes desta versão não os gravaram como tag; os novos passam a gravar."}));
		return;
	}
	$("phishAuthScope").textContent = recorded + " de " + payload.kpis.analyzed + " casos com registro";

	let legend_slices = [
		{label: "pass", count: 0, tone: "ok"},
		{label: "fail", count: 0, tone: "bad"},
		{label: "outro", count: 0, tone: "warn"}
	];
	let donuts = el("div", {className: "auth-donuts"});
	for (let row of stats){
		let name = AUTH_LABEL[row.method] || row.method;
		let pick = function(kind, label){
			return function(){ open_signal({auth: row.method + ":" + kind, label: name + ": " + label}); };
		};
		let slices = [
			{label: "pass", count: row.pass, tone: "ok", pick: pick("pass", "pass")},
			{label: "fail", count: row.fail, tone: "bad", pick: pick("fail", "fail")},
			{label: "outro", count: row.other, tone: "warn", pick: pick("other", "outro")}
		];
		let failed = row.fail + row.other;
		let detail = row.recorded === 0 ? "sem registro"
			: row.pass + " de " + row.recorded + " passaram";
		donuts.appendChild(el("div", {className: "auth-donut" + (failed > row.pass ? " failing" : "")}, [
			donut_chart(slices, row.recorded === 0 ? "—" : percent(row.pass, row.recorded) + "%", name + " pass"),
			el("span", {className: "auth-donut-name", text: name}),
			el("span", {className: "auth-donut-detail", text: detail}),
			row.unrecorded > 0 && row.recorded > 0
				? el("span", {className: "auth-donut-detail", text: row.unrecorded + " sem registro"})
				: null
		]));
	}
	box.appendChild(donuts);
	box.appendChild(chart_legend(legend_slices, true));
}

/* --- distribuição por faixa do score --------------------------------------- */

const TIER_LABEL_PT = {phishing: "phishing", spam: "spam", suspicious: "suspeito",
	legitimate: "legítimo"};
const TIER_TONE = {phishing: "bad", spam: "muted", suspicious: "warn", legitimate: "ok"};

function render_phish_tiers(payload){
	let box = $("phishTiers");
	box.replaceChildren();
	let tiers = payload.tiers || {};
	let scored = payload.scored || 0;

	if (scored === 0){
		$("phishTierScope").textContent = "—";
		box.appendChild(el("span", {className: "empty-note",
			text: "Nenhum caso do período foi pontuado. A nota é gravada como tag do caso a partir "
				+ "desta versão — casos anteriores não têm score, e não são contados como zero."}));
		return;
	}
	$("phishTierScope").textContent = scored + " de " + payload.kpis.analyzed + " casos pontuados";

	let slices = ["phishing", "suspicious", "spam", "legitimate"].map(function(key){
		return {label: TIER_LABEL_PT[key], count: tiers[key] || 0, tone: TIER_TONE[key],
			pick: function(){ open_signal({tier: key, label: "Faixa do score: " + TIER_LABEL_PT[key]}); }};
	});
	box.appendChild(el("div", {className: "tier-chart"}, [
		donut_chart(slices, String(scored), "pontuados", "lg"),
		chart_legend(slices, false)
	]));
	if (tiers.unscored > 0){
		box.appendChild(el("span", {className: "field-hint tier-note",
			text: tiers.unscored + " caso(s) sem score — anteriores à metodologia, fora da pizza."}));
	}
}

/* --- ações recomendadas sobre a coletânea ----------------------------------
 *
 * Recomendação a partir de playbook, não de modelo: a ação que se toma sobre um
 * IOC é função do que ele é. É o que separa "ação recomendada" de palpite
 * apresentado como conclusão — e o que permite dizer, para cada linha, se algum
 * destino de bloqueio habilitado consegue executá-la. */
function render_phish_actions(payload){
	let box = $("phishActions");
	box.replaceChildren();
	let iocs = (payload.topIocs || []).filter(function(ioc){ return ioc.remediation; });

	if (iocs.length === 0){
		box.appendChild(el("span", {className: "empty-note",
			text: "Nenhum IOC marcado no período. A recomendação sai dos indicadores que os "
				+ "analisadores confirmaram — sem eles não há sobre o que recomendar."}));
		return;
	}

	// Uma ação por tipo, e não uma por indicador: quarenta URLs da mesma campanha
	// produzem uma recomendação, não quarenta
	let by_type = {};
	for (let ioc of iocs){
		let entry = by_type[ioc.type] || {type: ioc.type, count: 0, remediation: ioc.remediation};
		entry.count++;
		by_type[ioc.type] = entry;
	}
	let ordered = Object.keys(by_type).map(function(key){ return by_type[key]; })
		.sort(function(a, b){ return b.count - a.count; });

	for (let entry of ordered){
		let blockable = entry.remediation.blockable;
		box.appendChild(el("div", {className: "col", style: "gap:5px"}, [
			el("div", {className: "row", style: "gap:7px"}, [
				el("span", {className: "pill", text: entry.type}),
				el("span", {className: "grow", text: entry.remediation.action,
					style: "font-size:var(--fs-body);color:var(--t1);line-height:1.45"})
			]),
			el("span", {className: "card-note", text: entry.remediation.detail}),
			el("span", {className: "field-hint",
				text: blockable === true
					? entry.count + " indicador(es) — há destino de bloqueio habilitado que executa isto daqui."
					: (blockable === false
						? entry.count + " indicador(es) — nenhum destino de bloqueio habilitado aceita este tipo; a ação é manual."
						: entry.count + " indicador(es).")})
		]));
	}
}

/* --- a faixa tática acima da lista de casos --------------------------------
 *
 * Duas perguntas, lado a lado: quem está mandando, e o que fazer com o que
 * chegou. O ranking de remetentes é por risco agregado — a soma das notas, não a
 * contagem — porque um remetente com uma denúncia de 90 e um com dez de 45 não
 * são o mesmo problema para quem decide o que bloquear primeiro. Quando nenhum
 * caso da janela tem nota, ele cai para contagem e *diz* que caiu: um ranking que
 * troca de critério em silêncio é um ranking em que ninguém confia na segunda
 * vez que olha. */
function render_phish_tactical(payload){
	let by_risk = (payload.sendersScored || 0) > 0;
	let senders = payload.topSenders || [];

	$("phishSendersMode").textContent = senders.length === 0 ? "—"
		: (by_risk ? "soma das notas dos casos" : "contagem de casos — nenhum caso pontuado ainda");

	let box = $("phishSenders");
	box.replaceChildren();
	if (senders.length === 0){
		box.appendChild(el("span", {className: "empty-note",
			text: "Nenhum remetente identificado nos casos de ameaça do período."}));
		$("phishSendersNote").textContent = "";
	} else {
		let key = by_risk ? "risk" : "count";
		let peak = senders.reduce(function(max, s){ return Math.max(max, s[key] || 0); }, 0) || 1;
		for (let sender of senders){
			let value = sender[key] || 0;
			box.appendChild(el("div", {className: "rank-bar"}, [
				el("div", {className: "rank-head"}, [
					el("span", {className: "grow truncate mono", text: sender.value, title: sender.value,
						style: "font-size:var(--fs-body);color:var(--t2)"}),
					el("span", {className: "mono",
						text: by_risk ? value.toFixed(0) : String(value),
						title: by_risk
							? "risco agregado: soma das notas dos " + sender.count + " caso(s)"
							: sender.count + " caso(s)",
						style: "font-size:var(--fs-micro);color:var(--t3);flex:0 0 auto"})
				]),
				el("div", {className: "meter", style: "height:5px"}, [
					el("span", {className: sender.malicious > 0 ? "" : "warn",
						style: "width:" + (value * 100 / peak) + "%"})
				]),
				el("span", {className: "field-hint",
					text: sender.count + " caso(s) · " + sender.malicious + " malicioso(s)"
						+ (by_risk && sender.topScore != null ? " · pior nota " + sender.topScore : "")})
			]));
		}
		$("phishSendersNote").textContent = by_risk
			? "Ordenado pela soma das notas. " + payload.sendersScored + " de " + payload.sendersTotal
				+ " remetentes têm ao menos um caso pontuado."
			: "Nenhum caso do período foi pontuado, então o ranking é por contagem. A nota passa a "
				+ "ser gravada nas análises feitas a partir desta versão.";
	}

	render_phish_ioc_table(payload);
	render_phish_headline(payload);
}

function render_phish_ioc_table(payload){
	let table = $("phishIocTable");
	table.replaceChildren();
	let iocs = payload.topIocs || [];
	$("phishIocMode").textContent = iocs.length === 0 ? "—"
		: iocs.length + " indicador(es) mais reutilizado(s)";

	if (iocs.length === 0){
		table.appendChild(el("div", {className: "tbl-empty",
			text: "Nenhum indicador foi marcado como IOC no período."}));
		return;
	}
	for (let ioc of iocs){
		let remediation = ioc.remediation;
		table.appendChild(el("div", {className: "tbl-row cols-ioc"}, [
			el("span", {className: "pill", text: ioc.type || "ioc"}),
			el("span", {className: "mono truncate", text: ioc.value, title: ioc.value,
				style: "font-size:var(--fs-body);color:var(--t1)"}),
			el("span", {className: "mono", text: String(ioc.cases),
				style: "font-size:var(--fs-micro);color:var(--danger2)"}),
			el("span", {className: "mono",
				text: ioc.risk == null ? "—" : String(Math.round(ioc.risk)),
				title: ioc.risk == null
					? "nenhum dos casos deste indicador foi pontuado"
					: "soma das notas dos " + ioc.scored + " caso(s) pontuado(s)",
				style: "font-size:var(--fs-micro);color:" + (ioc.risk == null ? "var(--t5)" : "var(--t2)")}),
			remediation
				? el("div", {className: "col", style: "gap:2px;min-width:0"}, [
					el("span", {className: "truncate", text: remediation.action, title: remediation.detail,
						style: "font-size:var(--fs-body);color:var(--t2)"}),
					el("span", {className: "field-hint",
						text: remediation.blockable === true ? "há destino habilitado"
							: (remediation.blockable === false ? "sem destino habilitado" : "")})
				])
				: el("span", {className: "field-hint", text: "sem remediação mapeada"})
		]));
	}
}

// A frase de abertura da tela, no formato da pergunta que ela responde. Cada
// número dela é contado, nunca estimado — e o que não foi contado é dito como
// tal em vez de virar zero
function render_phish_headline(payload){
	let malicious = payload.kpis.malicious;
	let unauthenticated = 0;
	let recorded = 0;
	for (let row of payload.authStats || []){
		if (row.method !== "dmarc"){ continue; }
		unauthenticated = row.fail + row.other;
		recorded = row.recorded;
	}
	$("phishHeadlineTitle").textContent = "O que já foi confirmado como phishing? "
		+ malicious + " caso(s)";
	let text = "Ranking de remetentes por risco agregado e fila de indicadores priorizada abaixo. ";
	if (recorded === 0){
		text += "Os cabeçalhos de autenticação não foram somados nesta janela: nenhum caso dela os "
			+ "traz registrados como tag.";
	} else {
		text += unauthenticated + " de " + recorded + " caso(s) com registro de DMARC não passaram na "
			+ "verificação — o domínio exibido no From não foi comprovado.";
	}
	$("phishHeadlineText").textContent = text;
}

/* --- phishing confirmado por janela fixa -----------------------------------
 *
 * Seis números que não dependem do período selecionado: 24 horas a 90 dias,
 * cada um contra a janela de mesmo tamanho logo antes. Um número que o servidor
 * não conseguiu medir inteiro aparece como piso ("≥ 12"), e uma comparação sem
 * a janela anterior lida some — "+12" sobre um anterior que ninguém contou é
 * tendência inventada. */
function load_phish_windows(){
	get_json("api/insights/windows").then(function(payload){
		phish_windows = payload && !payload.error ? payload : null;
		render_phish_windows(phish_windows);
	});
}

function render_phish_windows(payload){
	for (let tile of $$("#phishWindows .window-tile")){
		let key = tile.dataset.arg;
		let value = tile.querySelector(".window-value");
		let delta = tile.querySelector(".window-delta");
		let label = range_window_label(key);
		let entry = payload ? (payload.windows || []).filter(function(w){ return w.key === key; })[0] : null;
		delta.className = "window-delta";

		if (!entry){
			value.textContent = "—";
			delta.textContent = "sem dados";
			tile.title = "";
			continue;
		}

		let floor = !entry.complete || payload.partial;
		value.textContent = (floor ? "≥ " : "") + entry.malicious;
		let tip = (floor ? "Pelo menos " : "") + entry.malicious + " phishing confirmado(s) "
			+ (key === "1d" ? "nas " : "nos ") + label;

		if (entry.previous == null || payload.partial){
			delta.textContent = "sem base anterior";
			tip += ". O período anterior não foi lido por inteiro, então não há comparação.";
		} else {
			let diff = entry.malicious - entry.previous;
			if (diff === 0){
				delta.textContent = "igual ao anterior";
			} else {
				// Mais phishing é o sentido ruim; a cor segue o risco, não o sinal
				delta.textContent = (diff > 0 ? "+" : "−") + Math.abs(diff) + " vs. anterior";
				delta.classList.add(diff > 0 ? "up" : "down");
			}
			tip += "; " + entry.previous + " no período anterior de mesmo tamanho.";
		}
		tile.title = tip;
	}

	let note = $("phishWindowsNote");
	let parts = [];
	if (payload == null){
		parts.push("Não foi possível contar o phishing por período.");
	} else {
		if (payload.partial){
			parts.push("Contagem parcial: " + (payload.unread || []).join(", ") + " não respondeu.");
		}
		if (payload.truncated){
			parts.push("O histórico passou de " + payload.limit + " casos; os períodos com ≥ contam só os mais recentes.");
		}
		if (payload.undated > 0){
			parts.push(payload.undated + " caso(s) sem data de criação ficaram fora dos períodos.");
		}
	}
	note.textContent = parts.join(" ");
	show(note, parts.length > 0);
}

// Jump to the analyzed-emails list filtered by the recurring IOC. The indicator
// lives in the observables, not in the subject, so it travels as its own filter
// rather than as text in the search box.
function open_campaign(){
	if (!insights_payload || !insights_payload.recurringIoc){ return; }
	show_view("done");
	cases_verdict = "all";
	cases_range = insights_range;
	cases_query = "";
	cases_ioc = insights_payload.recurringIoc.value;
	cases_signal = null;
	$("doneQuery").value = "";
	sync_case_chips();
	load_cases();
}

function clear_ioc_filter(){
	cases_ioc = "";
	sync_case_chips();
	load_cases();
}

// Abre os casos de uma fatia no mesmo período do painel e com todos os vereditos:
// é sobre esse conjunto que a pizza foi contada, então é ele que a lista mostra
function open_signal(signal){
	show_view("done");
	cases_verdict = "all";
	cases_range = insights_range;
	cases_query = "";
	cases_ioc = "";
	cases_signal = signal;
	$("doneQuery").value = "";
	sync_case_chips();
	load_cases();
}

function clear_signal_filter(){
	cases_signal = null;
	sync_case_chips();
	load_cases();
}

// Download the IOCs of the current window as JSON, straight from the insights
// payload the screen is already showing
function export_iocs(){
	if (!insights_payload || insights_payload.topIocs.length === 0){
		toast("Nenhum IOC para exportar no período.", "bad");
		return;
	}
	let blob = new Blob([JSON.stringify({
		range: insights_payload.range,
		generatedAt: insights_payload.generatedAt,
		iocs: insights_payload.topIocs
	}, null, "\t")], {type: "application/json"});
	let url = URL.createObjectURL(blob);
	let link = el("a", {attrs: {href: url, download: "bluephish-iocs-" + insights_payload.range + ".json"}});
	document.body.appendChild(link);
	link.click();
	link.remove();
	URL.revokeObjectURL(url);
}

/* --- analyzed emails list ------------------------------------------------- */

function sync_case_chips(){
	for (let chip of $$("#doneFilters .chip")){
		chip.classList.toggle("active", chip.dataset.arg === cases_verdict);
	}
	for (let chip of $$("#doneRanges .chip")){
		chip.classList.toggle("active", chip.dataset.arg === cases_range);
	}
	show($("doneIocChip"), !!cases_ioc);
	$("doneIocLabel").textContent = cases_ioc ? "IOC: " + cases_ioc : "";
	show($("doneSignalChip"), !!cases_signal);
	$("doneSignalLabel").textContent = cases_signal ? cases_signal.label : "";
}

function set_case_verdict(verdict){
	cases_verdict = verdict;
	sync_case_chips();
	load_cases();
}

function set_case_range(range){
	cases_range = range;
	sync_case_chips();
	load_cases();
}

function reload_cases(){
	load_cases();
}

// Typing in the search box must not fire a TheHive query per keystroke
let cases_query_timer = null;
function filter_cases_debounced(){
	show($("doneQueryClear"), $("doneQuery").value.trim() !== "");
	window.clearTimeout(cases_query_timer);
	cases_query_timer = window.setTimeout(function(){
		cases_query = $("doneQuery").value.trim();
		load_cases();
	}, 350);
}

// The handoff shows a clear affordance inside the field once it has text —
// emptying a filter should not require selecting and deleting.
function clear_done_query(){
	window.clearTimeout(cases_query_timer);
	$("doneQuery").value = "";
	cases_query = "";
	show($("doneQueryClear"), false);
	load_cases();
}

function load_cases(){
	$("doneCount").textContent = "consultando informações…";
	let url = "api/cases?range=" + encodeURIComponent(cases_range)
		+ "&verdict=" + encodeURIComponent(cases_verdict)
		+ "&q=" + encodeURIComponent(cases_query)
		+ "&ioc=" + encodeURIComponent(cases_ioc)
		+ "&tier=" + encodeURIComponent((cases_signal && cases_signal.tier) || "")
		+ "&auth=" + encodeURIComponent((cases_signal && cases_signal.auth) || "")
		+ "&limit=60";
	get_json(url).then(function(payload){
		if (payload == null || payload.error){
			case_rows = [];
			$("doneRows").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível consultar os registros."
			}));
			$("doneCount").textContent = "sem dados";
			return;
		}
		case_rows = payload.cases;
		let shown = payload.shown === payload.total
			? payload.total + " caso(s)"
			: payload.shown + " de " + payload.total + " caso(s)";
		$("doneCount").textContent = shown;
		render_case_list($("doneRows"), case_rows, open_case, payload.notice,
			selected_case ? selected_case.ref : null);
	});
}

// "0 observáveis" and "we cannot say" are different statements, and only one of
// them is a fact. A Jira record keeps its report as prose written for a human, so
// its observables come back as null rather than as an empty list — printing a
// zero there would be a count nobody took.
function observable_summary(row){
	if (row.observableCount == null){ return "observáveis não registrados nesta fonte"; }
	return row.observableCount + " observáveis";
}

// `selected_ref` is the row this surface should mark, or null when it marks none.
// Passed in rather than read off a global: the same list renders on three screens
// and the highlight belongs to the screen the analyst is on, not to the case
function render_case_list(container, rows, on_click, notice, selected_ref){
	container.replaceChildren();
	if (rows.length === 0){
		// The server sends a notice only when it established why the window is
		// empty. "Nenhum caso corresponde aos filtros" under a mailbox that just
		// finished an analysis reads as a broken pipeline, and the analyst goes
		// hunting through the log of an analysis that ran perfectly well
		container.appendChild(el("div", {className: "tbl-empty",
			text: notice || "Nenhum caso corresponde aos filtros."}));
		return;
	}
	for (let row of rows){
		let selected = selected_ref != null && String(selected_ref) === String(row.ref);
		let ioc_line = row.iocs.map(function(ioc){ return ioc.value; }).join(" · ");
		let node = el("div", {className: "mail-row" + (selected ? " selected" : "")}, [
			el("div", {className: "rail-mark"}),
			el("div", {className: "row", style: "gap:8px;width:100%"}, [
				el("span", {className: "dot " + verdict_tone(row.verdict)}),
				el("span", {className: "mail-from truncate grow", text: row.sender || "(remetente não registrado)"}),
				el("span", {className: "pill " + verdict_tone(row.verdict), text: verdict_label(row.verdict),
					title: row.originalVerdict ? "A análise classificou como " + verdict_label(row.originalVerdict)
						+ "; reclassificado por " + (row.reclassification ? row.reclassification.by : "uma pessoa") : ""}),
				el("span", {className: "mail-time", text: format_date(row.startDate).split(" ")[0]})
			]),
			el("div", {className: "mail-subject truncate", text: row.title || "(sem assunto)"}),
			el("div", {className: "mail-meta truncate", text: ioc_line || observable_summary(row)}),
			el("div", {className: "row", style: "gap:5px;margin-top:1px;flex-wrap:wrap"}, [
				el("span", {className: "pill", text: row.label}),
				row.reclassification ? el("span", {className: "pill muted", text: "RECLASSIFICADO"}) : null,
				row.iocCount > 0 ? el("span", {className: "pill", text: row.iocCount + " IOC"}) : null
			].concat((row.tags || []).slice(0, 2).map(function(tag){
				return el("span", {className: "pill", text: tag});
			})))
		]);
		node.onclick = function(){ on_click(row); };
		container.appendChild(node);
	}
}

/* --- work queues ---------------------------------------------------------- */

/* A mesa de trabalho. Duas filas sobre o mesmo /api/cases, com `pending=1`: só o
 * que ainda espera decisão humana. O arquivo continua sendo "E-mails analisados",
 * e é de propósito que as duas telas existam — uma é onde se trabalha, a outra é
 * onde se procura.
 *
 * As contagens das abas vêm do mesmo payload que a lista, e não de uma chamada
 * própria: duas consultas separadas divergem exatamente no instante em que
 * alguém acabou de decidir um caso, que é quando a analista está olhando. */

const DESK_QUEUES = ["Suspicious", "Malicious"];

let desk_verdict = "Suspicious";
let desk_range = "30d";
let desk_query = "";
let desk_rows = [];
let desk_counts = {};
let selected_desk_case = null;

function sync_desk_tabs(){
	for (let tab of $$("#deskTabs .tab")){
		tab.classList.toggle("active", tab.dataset.arg === desk_verdict);
	}
	for (let chip of $$("#deskRanges .chip")){
		chip.classList.toggle("active", chip.dataset.arg === desk_range);
	}
	// Vazio, e não zero, enquanto a contagem não chegou: um "0" antes da resposta
	// diz que a fila está limpa, que é a informação oposta de "ainda não sei"
	for (let verdict of DESK_QUEUES){
		let count = desk_counts[verdict];
		$("deskTab" + verdict + "Count").textContent = count == null ? "" : String(count);
	}
}

function show_desk_queue(verdict){
	if (DESK_QUEUES.indexOf(verdict) === -1){ return; }
	desk_verdict = verdict;
	sync_desk_tabs();
	load_desk_queue();
}

function set_desk_range(range){
	desk_range = range;
	sync_desk_tabs();
	load_desk_queue();
}

function reload_desk(){
	load_desk_queue();
}

let desk_query_timer = null;
function filter_desk_debounced(){
	show($("deskQueryClear"), $("deskQuery").value.trim() !== "");
	window.clearTimeout(desk_query_timer);
	desk_query_timer = window.setTimeout(function(){
		desk_query = $("deskQuery").value.trim();
		load_desk_queue();
	}, 350);
}

function clear_desk_search(){
	window.clearTimeout(desk_query_timer);
	$("deskQuery").value = "";
	desk_query = "";
	show($("deskQueryClear"), false);
	load_desk_queue();
}

// O contador do menu é o da fila que espera decisão, somadas as duas. Vazio
// enquanto não houver resposta, pelo mesmo motivo das abas
function sync_desk_badge(){
	let total = 0;
	let known = false;
	for (let verdict of DESK_QUEUES){
		if (desk_counts[verdict] != null){ total += desk_counts[verdict]; known = true; }
	}
	$("navDeskBadge").textContent = known && total > 0 ? String(total) : "";
}

function load_desk_queue(){
	$("deskCount").textContent = "consultando informações…";
	let url = "api/cases?pending=1&range=" + encodeURIComponent(desk_range)
		+ "&verdict=" + encodeURIComponent(desk_verdict)
		+ "&q=" + encodeURIComponent(desk_query)
		+ "&limit=60";
	get_json(url).then(function(payload){
		if (payload == null || payload.error){
			desk_rows = [];
			desk_counts = {};
			sync_desk_tabs();
			sync_desk_badge();
			$("deskRows").replaceChildren(el("div", {
				className: "tbl-empty",
				text: (payload && payload.error) || "Não foi possível consultar os registros."
			}));
			$("deskCount").textContent = "sem dados";
			return;
		}
		desk_rows = payload.cases;
		desk_counts = payload.counts || {};
		sync_desk_tabs();
		sync_desk_badge();
		// `partial` significa que um destino não respondeu: a fila que a analista
		// vê está incompleta e ela precisa saber disso antes de concluir que a
		// caixa está limpa
		let shown = payload.shown === payload.total
			? payload.total + " caso(s) aguardando decisão"
			: payload.shown + " de " + payload.total + " caso(s) aguardando decisão";
		$("deskCount").textContent = payload.partial ? shown + " · leitura parcial" : shown;
		render_case_list($("deskRows"), desk_rows, open_desk, payload.notice,
			selected_desk_case ? selected_desk_case.ref : null);
	});
}

// Abre um caso na mesa. O cabeçalho é montado do que a linha já traz, antes de
// qualquer requisição: a analista clicou num caso e precisa ver que clicou nele,
// não uma tela em branco enquanto o detalhe viaja
function open_desk(row){
	case_surface = "queues";
	selected_desk_case = row;
	render_case_list($("deskRows"), desk_rows, open_desk, "", row.ref);
	open_case(row, true);
}

/* --- case detail ---------------------------------------------------------- */

// Write one section of the case detail. `muted` marks a statement about the data
// (absent, still loading, failed) rather than the data itself, so the analyst can
// tell "there is none" from "it did not arrive".
function set_case_section(id, text, muted){
	let node = $(id);
	node.textContent = "";
	if (id === "caseObsRows"){
		node.appendChild(el("div", {className: "tbl-empty", text: text}));
		return;
	}
	node.textContent = text;
	node.classList.toggle("absent", !!muted);
}

// How many observables the detail lists before the analyst asks for the rest.
// They arrive IOCs first (case_insights.flagged_by), so the first screen holds
// what an analyst acts on and the long tail of benign links waits behind a click.
const CASE_OBS_PREVIEW = 5;
let case_obs_expanded = false;
// The detail payload of the open case, once it landed. The reclassification form
// and the observable toggle read it instead of fetching the case again
let case_detail = null;

const FLAG_LEVEL_LABEL = {malicious: "malicioso", suspicious: "suspeito"};
const FLAG_LEVEL_TONE = {malicious: "bad", suspicious: "warn"};
const TRAIL_STAGE_LABEL = {
	analyzers: "ANALISADORES",
	llm: "IA",
	council: "CONSELHO DE IA",
	injection: "PROMPT INJECTION",
	score: "SCORE",
	whitelist: "WHITELIST",
	memory: "MEMÓRIA DE VEREDITO",
	coverage: "COBERTURA"
};
const COUNCIL_ROLE_LABEL = {analyst: "analista", skeptic: "cético", reviewer: "revisor"};

function format_iso(iso){
	let ms = Date.parse(iso || "");
	return isNaN(ms) ? "—" : format_date(ms);
}

// Which screen the open case belongs to: "done" (the archive) or "queues" (the
// work desk). The detail is shared; what a decision reloads afterwards is not
let case_surface = "done";

function open_case(row, from_desk){
	if (!from_desk){
		case_surface = "done";
		render_case_list($("doneRows"), case_rows, open_case, "", row.ref);
	}
	selected_case = row;
	case_detail = null;
	case_obs_expanded = false;
	close_case_reclassify();

	$("caseTitle").textContent = row.title || "(sem assunto)";
	$("caseSub").textContent = row.label + " · " + format_date(row.startDate)
		+ (row.department ? " · denunciado por " + row.department : "");
	$("caseVerdictPill").textContent = verdict_label(row.verdict);
	$("caseVerdictPill").className = "pill " + verdict_tone(row.verdict);
	show($("caseVerdictPill"), true);
	$("caseWasPill").textContent = row.originalVerdict ? "ERA " + verdict_label(row.originalVerdict) : "";
	show($("caseWasPill"), !!row.originalVerdict);
	show($("caseChatBtn"), true);
	show($("caseIntro"), false);
	show($("caseReanalyzeBtn"), false);
	show($("caseReanalyzed"), false);
	show($("caseDecisionBar"), false);
	load_case_scope(row);
	reset_case_mail("carregando…");
	if (assistant_open){ assistant_load(row); } else { assistant_ref = null; }
	sync_case_assistant();

	// The three cards stay visible through the whole fetch. Hiding them and
	// revealing them one by one made a slow or partial answer look like a section
	// that had silently failed to load.
	set_case_section("caseObsRows", "carregando observáveis…");
	set_case_section("caseLlmText", "carregando…");
	set_case_section("caseBody", "carregando…");
	$("caseWhyTitle").textContent = "Por que a análise classificou como "
		+ verdict_label(row.originalVerdict || row.verdict).toLowerCase();
	$("caseWhyCode").textContent = "";
	$("caseTrail").replaceChildren(el("li", {className: "empty-note", text: "carregando…"}));
	$("caseLlmRisk").textContent = "LLM";
	$("caseLlmRisk").className = "pill";
	$("caseLlmDetected").textContent = "";
	show($("caseEvidenceBlock"), false);
	show($("caseCouncil"), false);
	show($("caseScoreBlock"), false);
	$("caseObsCount").textContent = row.observableCount != null ? row.observableCount + " observáveis" : "";
	show($("caseObsMore"), false);
	show($("caseObsCard"), true);
	show($("caseLlmCard"), true);
	show($("caseBodyCard"), true);
	show($("caseActions"), true);
	// Only offered once the server said so: the verdict the list shows may be
	// stale, and the detail is where the decision in force is read
	show($("caseReclassUnavailable"), false);
	render_case_reclassification(row.reclassification, false);
	render_case_metrics(row, null);
	// The listing already carries the tactics (they are case tags), so the pills
	// are on screen before the detail request lands
	render_case_tactics(row.tactics);

	get_json("api/cases/" + encodeURIComponent(row.ref)).then(function(detail){
		// A different row may have been clicked while this was in flight
		if (!selected_case || selected_case.ref !== row.ref){ return; }
		if (detail == null || detail.error){
			let message = (detail && detail.error) || "Não foi possível carregar o caso.";
			// O cartão do e-mail estava em "carregando…"; sem isto ficava assim para sempre
			reset_case_mail(message);
			$("caseObsCount").textContent = "erro";
			set_case_section("caseObsRows", message);
			set_case_section("caseLlmText", message);
			set_case_section("caseBody", message);
			$("caseTrail").replaceChildren(el("li", {className: "empty-note", text: message}));
			return;
		}

		case_detail = detail;
		render_case_metrics(row, detail);
		render_case_tactics(detail.tactics);
		render_case_observables();
		render_case_reasoning(row, detail);
		render_case_reclassification(detail.reclassification, true);
		show($("caseReclassUnavailable"), !!detail.reclassificationUnavailable);
		render_case_decisions(detail);
		show($("caseReanalyzeBtn"), !!detail.originalHeld);
		load_case_mail(row, detail);

		if (detail.body){
			set_case_section("caseBody", detail.body);
		} else {
			set_case_section("caseBody",
				"Corpo indisponível: o .eml original não pôde ser recuperado dos observáveis deste caso.",
				true);
		}
	});
}

/* --- observables of the open case ----------------------------------------- */

function render_case_observables(){
	let observables = (case_detail && case_detail.observables) || [];
	let container = $("caseObsRows");
	container.replaceChildren();

	let iocs = observables.filter(function(obs){ return obs.level === "malicious"; }).length;
	let suspicious = observables.filter(function(obs){ return obs.level === "suspicious"; }).length;
	$("caseObsCount").textContent = observables.length + " observáveis · " + iocs + " IOC"
		+ (suspicious ? " · " + suspicious + " suspeito(s)" : "");

	if (observables.length === 0){
		container.appendChild(el("div", {className: "tbl-empty", text: "Nenhum observável extraído neste caso."}));
		show($("caseObsMore"), false);
		return;
	}

	let visible = case_obs_expanded ? observables : observables.slice(0, CASE_OBS_PREVIEW);
	visible.forEach(function(obs, index){
		container.appendChild(observable_row(obs, case_obs_expanded && index >= CASE_OBS_PREVIEW));
	});

	let more = $("caseObsMore");
	let hidden = observables.length - CASE_OBS_PREVIEW;
	show(more, hidden > 0);
	if (hidden <= 0){ return; }
	// Past the preview everything is unflagged, unless more than five were
	// flagged — and then the button has to say so, or "show more" reads as
	// "nothing else of interest"
	let hidden_flagged = observables.slice(CASE_OBS_PREVIEW).filter(function(obs){ return obs.level; }).length;
	$("caseObsMoreLabel").textContent = case_obs_expanded
		? "Mostrar só os " + CASE_OBS_PREVIEW + " primeiros"
		: "Mostrar todos os " + observables.length + " observáveis"
			+ (hidden_flagged ? " · mais " + hidden_flagged + " marcado(s)" : "");
	more.setAttribute("aria-expanded", case_obs_expanded ? "true" : "false");
	more.classList.toggle("open", case_obs_expanded);
}

function toggle_case_observables(){
	if (!case_detail){ return; }
	case_obs_expanded = !case_obs_expanded;
	render_case_observables();
	// Collapsing a long list from its bottom would leave the analyst staring at
	// the body card; bring the list's head back into view
	if (!case_obs_expanded){ $("caseObsCard").scrollIntoView({block: "nearest"}); }
}

function observable_row(obs, revealed){
	let flags = null;
	if (obs.flaggedBy && obs.flaggedBy.length > 0){
		let parts = [el("span", {text: "marcado por "})];
		obs.flaggedBy.forEach(function(flag, index){
			if (index > 0){ parts.push(el("span", {text: " · "})); }
			parts.push(el("strong", {text: flag.analyzer || "analisador sem nome"}));
			parts.push(el("span", {className: FLAG_LEVEL_TONE[flag.level] || "", text: " " + (FLAG_LEVEL_LABEL[flag.level] || flag.level)}));
			if (flag.detail){ parts.push(el("span", {text: " — " + flag.detail})); }
		});
		flags = el("div", {className: "obs-flags"}, parts);
	} else if (obs.level && obs.flaggedBy == null){
		// A TheHive case older than the report format, or a record whose log could
		// not be read: the IOC flag is real, who raised it is not on record
		flags = el("div", {className: "obs-flags absent", text: "o analisador que marcou não está registrado nesta fonte"});
	}
	return el("div", {className: "obs-row" + (revealed ? " revealed" : "")}, [
		el("span", {className: "pill", text: obs.type || "—", title: obs.type || ""}),
		el("span", {className: "obs-value mono", text: obs.value, title: obs.value}),
		obs.level
			? el("span", {className: "pill " + FLAG_LEVEL_TONE[obs.level], text: obs.level === "malicious" ? "IOC" : "SUSPEITO"})
			: el("span", {className: "field-hint", text: "—"}),
		flags
	]);
}

/* --- why the analysis reached its verdict --------------------------------- */

function render_case_reasoning(row, detail){
	let analysis = detail.analysis;
	let trail = $("caseTrail");
	trail.replaceChildren();
	let original = detail.recordVerdict || row.originalVerdict || row.verdict;
	$("caseWhyTitle").textContent = "Por que a análise classificou como " + verdict_label(original).toLowerCase();

	if (!analysis){
		$("caseWhyCode").textContent = "";
		trail.appendChild(el("li", {className: "empty-note",
			text: "O registro deste caso não traz o detalhamento da análise: ele foi gravado antes deste formato, ou o log da análise não pôde ser lido no destino."}));
	} else if (analysis.verdictTrail && analysis.verdictTrail.length > 0){
		$("caseWhyCode").textContent = analysis.verdictTrail.length + " etapas";
		let previous = null;
		for (let step of analysis.verdictTrail){
			let changed = previous !== null && step.verdict !== previous;
			trail.appendChild(trail_step(TRAIL_STAGE_LABEL[step.stage] || String(step.stage || "").toUpperCase(),
				step.reason, step.verdict, changed));
			previous = step.verdict;
		}
	} else {
		// Listing the recorded facts is honest; naming the rule that fired from
		// them would be a reconstruction presented as a record
		$("caseWhyCode").textContent = "fatos gravados";
		trail.appendChild(el("li", {className: "empty-note",
			text: "Esta análise é anterior ao registro do passo a passo. Abaixo, os fatos que ela gravou — não qual regra disparou."}));
		for (let fact of recorded_facts(analysis)){
			trail.appendChild(trail_step(fact.stage, fact.text, null, false));
		}
	}

	render_case_llm(analysis ? analysis.llm : null, detail.llmSummary);
	render_case_score(analysis ? analysis.score : null);
}

function trail_step(stage, reason, verdict, changed){
	let tone = verdict ? verdict_tone(verdict) : "";
	return el("li", {className: "trail-step" + (changed ? " changed" : "")}, [
		el("span", {className: "trail-node " + tone}),
		el("div", {className: "col", style: "gap:3px"}, [
			el("span", {className: "trail-stage", text: stage + (changed ? " · MUDOU O VEREDITO" : "")}),
			el("span", {className: "trail-reason", text: reason || "—"})
		]),
		verdict ? el("span", {className: "pill " + tone, text: verdict_label(verdict)}) : el("span")
	]);
}

function recorded_facts(analysis){
	let facts = [];
	if (analysis.findings){
		let flagged = analysis.findings.filter(function(f){ return FLAG_LEVEL_LABEL[f.level]; });
		if (flagged.length === 0){
			facts.push({stage: "ANALISADORES", text: "Nenhum analisador apontou um observável."});
		} else {
			let by_analyzer = {};
			for (let finding of flagged){
				by_analyzer[finding.analyzer] = (by_analyzer[finding.analyzer] || 0) + 1;
			}
			facts.push({stage: "ANALISADORES", text: flagged.length + " apontamento(s): "
				+ Object.keys(by_analyzer).map(function(name){ return name + " (" + by_analyzer[name] + ")"; }).join(", ")});
		}
	}
	if (analysis.llm){
		facts.push({stage: "IA", text: "Risco " + (RISK_LABEL[analysis.llm.riskLevel] || analysis.llm.riskLevel)
			+ (analysis.llm.detected ? ", engenharia social detectada." : ", sem engenharia social detectada.")});
	}
	if (analysis.injection && analysis.injection.length){
		facts.push({stage: "PROMPT INJECTION", text: "Marcadores encontrados: "
			+ analysis.injection.map(function(f){ return f.rule; }).join(", ")});
	}
	if (analysis.authentication){
		let auth = analysis.authentication;
		facts.push({stage: "AUTENTICAÇÃO", text: "SPF " + (auth.spf || "?") + " · DKIM " + (auth.dkim || "?")
			+ " · DMARC " + (auth.dmarc || "?") + (auth.authenticated ? " — domínio autenticado" : " — domínio não autenticado")});
	}
	if (analysis.score){
		facts.push({stage: "SCORE", text: "Score " + analysis.score.score + "/100, faixa " + analysis.score.tier});
	}
	return facts;
}

function render_case_llm(llm, summary){
	let risk = $("caseLlmRisk");
	let evidence_block = $("caseEvidenceBlock");
	let council = $("caseCouncil");

	if (!llm){
		risk.textContent = "LLM";
		risk.className = "pill";
		$("caseLlmDetected").textContent = "";
		show(evidence_block, false);
		show(council, false);
		// An absent assessment is stated rather than hidden: "the IA was off during
		// this analysis" and "the section failed to load" must not look alike
		if (summary){
			set_case_section("caseLlmText", summary);
		} else {
			set_case_section("caseLlmText",
				"Nenhuma avaliação registrada neste caso. A análise de engenharia social estava desativada quando ele foi processado, ou o modelo não respondeu.",
				true);
		}
		return;
	}

	risk.textContent = "RISCO " + (RISK_LABEL[llm.riskLevel] || llm.riskLevel || "?").toUpperCase();
	risk.className = "pill " + (RISK_TONE[llm.riskLevel] || "");
	$("caseLlmDetected").textContent = llm.detected ? "engenharia social detectada" : "sem engenharia social detectada";
	if (llm.justification){
		set_case_section("caseLlmText", llm.justification);
	} else {
		set_case_section("caseLlmText", "O modelo não escreveu justificativa.", true);
	}

	let list = $("caseEvidence");
	list.replaceChildren();
	show(evidence_block, true);
	if (llm.evidence == null){
		list.appendChild(el("li", {className: "absent", text: "Esta análise é anterior a este campo: o modelo registrou só a justificativa acima."}));
	} else if (llm.evidence.length === 0){
		list.appendChild(el("li", {className: "absent", text: "O modelo não apontou nenhum elemento específico do e-mail."}));
	} else {
		for (let item of llm.evidence){ list.appendChild(el("li", {text: item})); }
	}

	council.replaceChildren();
	show(council, !!llm.council);
	if (!llm.council){ return; }
	let c = llm.council;
	let review = c.review || {};
	let summary_line = "Pipeline " + c.mode + " · " + (c.consensus ? "agentes em consenso" : "sem consenso: " + (c.divergence || "divergência"))
		+ " · revisor " + (review.status === "ok" ? (review.action === "proceed" ? "validou" : "pediu revisão humana") : "não respondeu")
		+ (review.manipulationDetected ? " · manipulação suspeita" : "");
	council.appendChild(el("span", {className: "field-label", text: "CONSELHO DE IA"}));
	council.appendChild(el("span", {className: "trail-reason", text: summary_line}));
	if (review.reason){
		council.appendChild(el("span", {className: "trail-reason", text: "Revisor: " + review.reason}));
	}
	for (let agent of c.agents || []){
		let children = [
			el("div", {className: "row", style: "gap:8px;flex-wrap:wrap"}, [
				el("strong", {className: "grow", style: "font-size:var(--fs-body);font-weight:500;color:var(--t1)",
					text: (COUNCIL_ROLE_LABEL[agent.role] || agent.role) + (agent.revised ? " · revisou após o debate" : "")}),
				el("span", {className: "field-hint", text: agent.model}),
				el("span", {className: "pill " + (RISK_TONE[agent.riskLevel] || ""), text: (RISK_LABEL[agent.riskLevel] || agent.riskLevel || "?").toUpperCase()})
			]),
			el("span", {className: "trail-reason", text: agent.justification || "sem justificativa"})
		];
		if (agent.evidence && agent.evidence.length){
			children.push(el("ul", {className: "evidence"}, agent.evidence.map(function(item){ return el("li", {text: item}); })));
		}
		council.appendChild(el("div", {className: "agent"}, children));
	}
}

function render_case_score(score){
	show($("caseScoreBlock"), !!score);
	if (!score){ return; }
	$("caseScoreValue").textContent = score.score + "/100 · faixa " + score.tier + (score.capped ? " · limitado" : "");
	let factors = $("caseScoreFactors");
	factors.replaceChildren();
	for (let factor of score.factors || []){
		factors.appendChild(el("div", {className: "score-factor"}, [
			el("span", {}, [el("strong", {text: factor.label}), el("span", {text: factor.reason ? " — " + factor.reason : ""})]),
			el("span", {className: "mono", text: factor.contribution.toFixed(2),
				title: "Contribuição deste fator para a média ponderada (peso × fator × participação)"})
		]));
	}
}

/* --- reclassification ------------------------------------------------------
 *
 * Marking an analyzed email as legitimate. The reason is mandatory and the
 * server re-reads the verdict before accepting it — the button being visible is
 * not the permission. The decision is written to the destination the record
 * lives in, and each destination's answer is shown: a TheHive that refused the
 * update must not look like one that took it. */

let case_reclass_mode = null;
const RECLASS_MIN_REASON = 15;
const RECLASS_MAX_REASON = 1000;

function render_case_reclassification(decision, loaded){
	show($("caseReclassBanner"), !!decision);
	if (!decision){ return; }
	// A confirmação de um malicioso não pode aparecer como liberação: o título e
	// o tom saem do veredito decidido, e não de "houve uma decisão"
	let confirmed = decision.verdict === decision.previousVerdict;
	let safe = decision.verdict === "Safe";
	$("caseReclassBanner").className = "callout " + (safe ? "ok" : "warn");
	$("caseReclassTitle").textContent = safe ? "Reclassificado como legítimo"
		: confirmed ? "Confirmado como " + verdict_label(decision.verdict).toLowerCase()
		: "Reclassificado como " + verdict_label(decision.verdict).toLowerCase();
	$("caseReclassMeta").textContent = "por " + decision.by + " · " + format_iso(decision.at)
		+ (confirmed ? " · a análise já classificava assim"
			: " · a análise havia classificado como " + verdict_label(decision.previousVerdict));
	$("caseReclassQuote").textContent = decision.reason;
	let outcomes = $("caseReclassOutcomes");
	outcomes.replaceChildren();
	for (let outcome of decision.outcomes || []){
		outcomes.appendChild(el("span", {className: "status " + (outcome.ok ? "ok" : "bad"),
			text: outcome.destination + ": " + (outcome.ok ? outcome.detail : "não atualizado — " + outcome.detail)}));
	}
	// O que a decisão ensinou às análises seguintes, quando ensinou
	for (let memory of (loaded && case_detail && case_detail.learned) || []){
		let text = memory.scope === "sender"
			? "Remetente " + memory.key + ": proposta de whitelist " + ({pending: "aguardando um admin", accepted: "aceita", dismissed: "recusada"}[memory.proposalStatus] || memory.proposalStatus)
			: "Mensagem idêntica liberada" + (memory.active ? "" : " (revogada)") + " · " + memory.hits + " análise(s) rebaixada(s) desde então";
		outcomes.appendChild(el("span", {className: "status " + (memory.active ? "ok" : ""), text: text}));
	}
	// Undoing is an admin decision; the route refuses anybody else regardless
	show($("caseRevertBtn"), loaded && !!(current_identity && current_identity.canChangeSettings));
}

// The decisions the server offers for this record. Offered, not granted: the
// route re-reads the verdict and checks the transition when the decision arrives
function render_case_decisions(detail){
	let targets = (detail && detail.decisionTargets) || [];
	let decision = detail && detail.reclassification;
	// Confirmar de novo o que uma pessoa já confirmou não decide nada
	let already = decision && decision.verdict === detail.effectiveVerdict && decision.verdict !== "Safe";
	let safe = targets.indexOf("Safe") !== -1;
	let malicious = targets.indexOf("Malicious") !== -1 && !already;
	show($("caseDecideSafeBtn"), safe);
	show($("caseDecideMaliciousBtn"), malicious);
	let none = "";
	if (detail && detail.reclassificationUnavailable){
		none = "Decisões bloqueadas até o banco de reclassificações responder.";
	} else if (!safe && !malicious){
		none = decision ? "Este caso já foi decidido — veja acima." : "Nenhuma decisão se aplica a um e-mail "
			+ verdict_label(detail ? detail.effectiveVerdict : "").toLowerCase() + ".";
	}
	$("caseDecisionNone").textContent = none;
	show($("caseDecisionNone"), none !== "");
	show($("caseDecisionBar"), true);
}

let case_reclass_target = "Safe";
let case_errata_on = false;
let case_memory_scope = "case";

function open_case_reclassify(){ start_case_reclassify("reclassify", "Safe"); }
function open_case_confirm_malicious(){ start_case_reclassify("reclassify", "Malicious"); }
function open_case_revert(){ start_case_reclassify("revert"); }

function start_case_reclassify(mode, target){
	if (!selected_case || !case_detail){ return; }
	let revert = mode === "revert";
	let decision = case_detail.reclassification;
	if (revert && !decision){ return; }
	case_reclass_mode = mode;
	case_reclass_target = revert ? "" : (target || "Safe");
	let to_safe = !revert && case_reclass_target === "Safe";
	let effective = case_detail.effectiveVerdict;
	let confirming = !to_safe && !revert && effective === "Malicious";

	$("caseReclassFormTitle").textContent = revert ? "Desfazer reclassificação"
		: to_safe ? "Marcar como legítimo" : "Confirmar malicioso";
	$("caseReclassFrom").textContent = revert
		? verdict_label(decision.verdict).toUpperCase() + " → " + verdict_label(decision.previousVerdict)
		: verdict_label(effective) + " → " + verdict_label(case_reclass_target).toUpperCase();
	$("caseReclassNote").textContent = revert
		? "O e-mail volta a " + verdict_label(decision.previousVerdict).toLowerCase() + " em todas as telas e contagens, e "
			+ selected_case.label + " é atualizado. A reclassificação anterior continua no histórico do caso, e o que ela ensinou às análises seguintes é revogado."
		: to_safe
			? "O e-mail passa a seguro em todas as telas e contagens. O veredito da análise continua registrado, e a decisão é escrita em "
				+ selected_case.label + " com o seu usuário e o motivo abaixo."
			: confirming
				? "O veredito continua malicioso; o que muda é que uma pessoa o confirmou. O caso sai da fila, e a confirmação é escrita em "
					+ selected_case.label + " com o seu usuário e o motivo abaixo."
				: "O e-mail passa a malicioso em todas as telas e contagens, e sai da fila de suspeitos. A decisão é escrita em "
					+ selected_case.label + " com o seu usuário e o motivo abaixo. Nada é enviado a quem denunciou.";
	$("caseReclassReason").value = "";
	$("caseReclassSave").textContent = revert ? "Desfazer reclassificação"
		: to_safe ? "Reclassificar como legítimo" : "Confirmar malicioso";
	$("caseReclassSave").className = revert ? "btn danger" : "btn";
	set_status("caseReclassStatus", "");

	// Errata: só num falso positivo corrigido. Marcada quando pode sair — a
	// configuração ligada e um denunciante conhecido —, e dizendo por que não
	// pode quando não pode, em vez de sumir
	show($("caseErrataRow"), to_safe);
	let errata_possible = !!case_detail.errataEnabled && !!case_detail.reporterKnown;
	set_case_errata(to_safe && errata_possible);
	$("caseErrataCheck").classList.toggle("disabled", !errata_possible);
	$("caseErrataHint").textContent = !case_detail.errataEnabled
		? "A errata está desligada em Configurações › Notificações."
		: !case_detail.reporterKnown
			? "Este registro não guardou quem denunciou: a errata não tem para quem ir."
			: "Quem denunciou recebe a correção pelo SMTP configurado.";

	show($("caseMemoryRow"), to_safe);
	set_case_memory_scope("case");

	sync_reclass_reason();
	show($("caseDecisionBar"), false);
	show($("caseActions"), false);
	show($("caseReclassForm"), true);
	$("caseReclassForm").scrollIntoView({block: "nearest", behavior: "smooth"});
	$("caseReclassReason").focus({preventScroll: true});
}

function close_case_reclassify(){
	case_reclass_mode = null;
	show($("caseReclassForm"), false);
	if (selected_case){ show($("caseActions"), true); }
	if (selected_case && case_detail){ render_case_decisions(case_detail); }
}

function set_case_errata(on){
	case_errata_on = !!on;
	$("caseErrataCheck").classList.toggle("on", case_errata_on);
	$("caseErrataCheck").setAttribute("aria-checked", case_errata_on ? "true" : "false");
}

function toggle_case_errata(){
	if (!case_detail || !case_detail.errataEnabled || !case_detail.reporterKnown){ return; }
	set_case_errata(!case_errata_on);
}

const MEMORY_SCOPE_HINT = {
	"case": "Só este registro muda. A próxima cópia desta mensagem passa pelo pipeline como qualquer outra.",
	content: "A próxima cópia desta mesma mensagem — mesmo remetente, assunto, corpo e links — sai como segura, com a sua decisão no passo a passo. Expira em 180 dias, e é suspensa sozinha se passar a esconder vereditos maliciosos.",
	sender: "Faz o que \"Mensagem idêntica\" faz, e propõe uma regra de whitelist para o remetente. A regra só vale depois que um admin a aprova em Configurações › Whitelist, com a exigência de domínio autenticado."
};

function set_case_memory_scope(scope){
	if (MEMORY_SCOPE_HINT[scope] === undefined){ return; }
	let can_teach = !!(case_detail && case_detail.canTeach);
	// A escolha que exige admin continua visível para quem não é: esconder a
	// opção faria a analista achar que a plataforma não aprende
	if (scope !== "case" && !can_teach){ scope = "case"; }
	case_memory_scope = scope;
	for (let tab of $$("#caseMemoryScope .tab")){
		let on = tab.dataset.arg === scope;
		tab.classList.toggle("active", on);
		tab.setAttribute("aria-checked", on ? "true" : "false");
		tab.disabled = tab.dataset.arg !== "case" && !can_teach;
	}
	$("caseMemoryHint").textContent = MEMORY_SCOPE_HINT[scope]
		+ (can_teach ? "" : " Liberar mensagens futuras exige perfil de admin.");
}

// The server collapses whitespace before counting, so the counter does too: a
// reason padded with spaces must not look accepted and then be refused
function sync_reclass_reason(){
	let length = $("caseReclassReason").value.replace(/\s+/g, " ").trim().length;
	$("caseReclassCount").textContent = length < RECLASS_MIN_REASON
		? "faltam " + (RECLASS_MIN_REASON - length) + " caracteres para o mínimo"
		: length + " / " + RECLASS_MAX_REASON;
	$("caseReclassSave").disabled = length < RECLASS_MIN_REASON || length > RECLASS_MAX_REASON;
}

function submit_case_reclassify(){
	if (!selected_case || !case_reclass_mode){ return; }
	let row = selected_case;
	let mode = case_reclass_mode;
	let url = "api/cases/" + encodeURIComponent(row.ref) + "/reclassify" + (mode === "revert" ? "/revert" : "");

	$("caseReclassSave").disabled = true;
	set_status("caseReclassStatus", "gravando e atualizando " + row.label + "…");
	let params = {reason: $("caseReclassReason").value};
	if (mode !== "revert"){
		params.verdict = case_reclass_target;
		if (case_reclass_target === "Safe"){
			params.notifyReporter = case_errata_on ? "1" : "";
			params.memoryScope = case_memory_scope;
		}
	}
	post_form(url, params).then(function(result){
		let data = result && result.data;
		if (!result || !result.ok || !data || data.error){
			set_status("caseReclassStatus", (data && data.error) || "Não foi possível gravar a decisão.", "bad");
			sync_reclass_reason();
			return;
		}
		let decision = data.decision;
		if (decision.action === "revert"){
			row.verdict = decision.verdict;
			row.originalVerdict = null;
			row.reclassification = null;
		} else {
			row.verdict = decision.verdict;
			row.originalVerdict = decision.previousVerdict;
			row.reclassification = decision;
		}
		let failed = (decision.outcomes || []).filter(function(outcome){ return !outcome.ok; });
		let done = decision.action === "revert" ? "Reclassificação desfeita."
			: decision.verdict === "Safe" ? "Reclassificado como legítimo."
			: decision.verdict === decision.previousVerdict ? "Confirmado como malicioso."
			: "Reclassificado como malicioso.";
		toast(failed.length
			? done + " Mas " + failed.map(function(o){ return o.destination + " não foi atualizado: " + o.detail; }).join("; ")
			: done + " Registrado em " + (decision.outcomes || []).map(function(o){ return o.destination; }).join(", ") + ".",
			failed.length ? "bad" : "ok");
		let from_desk = case_surface === "queues";
		open_case(row, from_desk);
		if (case_rows.length > 0 || !from_desk){ load_cases(); }
		// Decidido, o caso sai da fila: a lista é relida e não editada na mão,
		// porque outra pessoa pode ter decidido outros enquanto isto estava aberto
		if (from_desk){ load_desk_queue(); }
	});
}

/* --- scope of the open case ------------------------------------------------
 *
 * Quantas pessoas denunciaram esta mesma mensagem. Rota própria, e não parte do
 * detalhe: é uma consulta local, e o número aparece sem esperar o TheHive. */

let case_scope_payload = null;
let case_scope_open = false;

function load_case_scope(row){
	case_scope_payload = null;
	case_scope_open = false;
	$("caseScopeCount").textContent = "…";
	$("caseScopeCount").classList.add("absent");
	$("caseScopeNote").textContent = "medindo o escopo…";
	$("caseScopeMatch").textContent = "";
	show($("caseScopeRows"), false);
	show($("caseScopeMore"), false);
	show($("caseScopeCard"), true);
	get_json("api/cases/" + encodeURIComponent(row.ref) + "/scope").then(function(scope){
		if (!selected_case || selected_case.ref !== row.ref){ return; }
		case_scope_payload = scope;
		render_case_scope(row);
	});
}

function render_case_scope(row){
	let scope = case_scope_payload;
	let count = $("caseScopeCount");
	let note = $("caseScopeNote");
	if (!scope || !scope.known){
		// "—" e não 1: esta análise não foi medida, e "só você denunciou" seria
		// uma afirmação sobre uma contagem que ninguém fez
		count.textContent = "—";
		count.classList.add("absent");
		note.textContent = "Escopo não medido: esta análise é anterior ao registro da impressão digital da mensagem.";
		$("caseScopeMatch").textContent = "";
		show($("caseScopeMore"), false);
		show($("caseScopeRows"), false);
		return;
	}
	count.classList.remove("absent");
	let text;
	if (scope.reporters == null){
		count.textContent = String(scope.reports);
		text = (scope.reports === 1 ? "denúncia" : "denúncias") + " desta mensagem — quem denunciou não foi registrado";
	} else {
		count.textContent = String(scope.reporters);
		text = (scope.reporters === 1 ? "pessoa denunciou esta mensagem" : "pessoas denunciaram esta mensagem")
			+ (scope.reports > scope.reporters ? " · " + scope.reports + " denúncias" : "");
	}
	if (scope.reports > 1 && scope.firstSeen){
		text += " · primeira em " + format_iso(scope.firstSeen) + ", última em " + format_iso(scope.lastSeen);
	}
	note.textContent = text;
	$("caseScopeMatch").textContent = scope.reports > 1
		? (scope.match === "body" ? "mesmo corpo" : "mensagem idêntica") : "";

	let records = scope.records || [];
	show($("caseScopeMore"), records.length > 1);
	$("caseScopeMoreLabel").textContent = case_scope_open ? "Ocultar as denúncias" : "Ver as " + records.length + " denúncias";
	$("caseScopeMore").setAttribute("aria-expanded", case_scope_open ? "true" : "false");
	$("caseScopeMore").classList.toggle("open", case_scope_open);
	let box = $("caseScopeRows");
	box.replaceChildren();
	show(box, case_scope_open && records.length > 1);
	if (!case_scope_open){ return; }
	for (let record of records){
		box.appendChild(el("div", {className: "scope-row" + (String(record.recordRef) === String(row.ref) ? " current" : "")}, [
			el("span", {className: "truncate", text: record.reporter || "(denunciante não registrado)", title: record.subject}),
			el("span", {className: "pill " + verdict_tone(record.verdict), text: verdict_label(record.verdict)}),
			el("span", {className: "mono", text: format_iso(record.at)})
		]));
	}
}

function toggle_case_scope(){
	if (!selected_case || !case_scope_payload){ return; }
	case_scope_open = !case_scope_open;
	render_case_scope(selected_case);
}

/* --- the reported email, as delivered --------------------------------------
 *
 * A partir da mensagem original guardada pela aplicação. O layout chega primeiro,
 * com as imagens remotas bloqueadas; se houver alguma, o servidor as busca numa
 * segunda chamada enquanto a analista já lê — o mesmo desenho da caixa. */

let case_mail_mode = "visual";
let case_mail_payload = null;
let case_mail_expanded = false;

function set_case_mail_mode(mode){
	case_mail_mode = mode === "text" ? "text" : "visual";
	let visual = case_mail_mode === "visual";
	$("caseMailTabVisual").classList.toggle("active", visual);
	$("caseMailTabVisual").setAttribute("aria-selected", visual ? "true" : "false");
	$("caseMailTabText").classList.toggle("active", !visual);
	$("caseMailTabText").setAttribute("aria-selected", visual ? "false" : "true");
	show($("caseMailVisual"), visual);
	show($("caseMailText"), !visual);
}

function reset_case_mail(message){
	case_mail_payload = null;
	$("caseMailFrame").removeAttribute("srcdoc");
	show($("caseMailFrameShell"), false);
	show($("caseMailInert"), false);
	show($("caseMailAttachments"), false);
	show($("caseMailProgress"), false);
	$("caseMailEmpty").textContent = message || "";
	show($("caseMailEmpty"), !!message);
	set_case_mail_mode("visual");
}

function load_case_mail(row, detail){
	if (!detail.originalHeld){
		reset_case_mail("A mensagem original deste caso não está guardada — a análise é anterior à guarda, "
			+ "passou da retenção ou não coube no espaço reservado. O texto extraído na análise continua na aba Texto.");
		set_case_mail_mode("text");
		return;
	}
	reset_case_mail("");
	show($("caseMailProgress"), true);
	fetch_case_mail(row, false);
}

function fetch_case_mail(row, images){
	get_json("api/cases/" + encodeURIComponent(row.ref) + "/rendered" + (images ? "?images=1" : "")).then(function(payload){
		if (!selected_case || selected_case.ref !== row.ref){ return; }
		show($("caseMailProgress"), false);
		if (!payload || !payload.available){
			if (images && case_mail_payload){
				// O layout já está na tela; só as imagens não vieram
				case_mail_payload.imagesDeferred = false;
				case_mail_payload.imagesFailed = true;
				render_preview_inert(case_mail_payload, $("caseMailInert"));
				return;
			}
			reset_case_mail((payload && payload.reason) || "Não foi possível renderizar a mensagem original.");
			return;
		}
		case_mail_payload = payload;
		render_case_mail(payload);
		if (!images && payload.imagesDeferred){ fetch_case_mail(row, true); }
	});
}

function render_case_mail(payload){
	render_preview_inert(payload, $("caseMailInert"));
	if (payload.html){
		// srcdoc atribuído como propriedade, num iframe sandbox sem allow-*: o
		// documento não tem origem, não roda script e herda a CSP desta página
		$("caseMailFrame").srcdoc = "<!doctype html><html><head><meta charset=\"utf-8\">"
			+ "<style>" + PREVIEW_FRAME_CSS + "</style></head><body>"
			+ payload.html + "</body></html>";
		show($("caseMailFrameShell"), true);
		show($("caseMailEmpty"), false);
	} else {
		show($("caseMailFrameShell"), false);
		$("caseMailEmpty").textContent = payload.error
			? "Não foi possível interpretar a estrutura deste e-mail. O conteúdo em texto continua na aba Texto."
			: "Este e-mail não traz uma versão formatada — foi enviado só em texto. É exatamente o que a aba Texto mostra.";
		show($("caseMailEmpty"), true);
	}
	render_preview_attachments(payload.attachments || [], $("caseMailAttachments"));
}

function toggle_case_mail_frame(){
	case_mail_expanded = !case_mail_expanded;
	$("caseMailFrameShell").classList.toggle("expanded", case_mail_expanded);
	$("caseMailExpandBtn").textContent = case_mail_expanded ? "Recolher" : "Expandir";
}

/* --- reanalysis -------------------------------------------------------------
 *
 * O pipeline de novo, sobre o original guardado. Grava um registro novo e não
 * mexe neste: a analista decide este caso à luz do resultado. */

function reanalyze_case(){
	if (!selected_case || !case_detail || !case_detail.originalHeld){ return; }
	let row = selected_case;
	let button = $("caseReanalyzeBtn");
	button.disabled = true;
	button.textContent = "Reanalisando…";
	$("caseReanalyzed").className = "callout neutral";
	$("caseReanalyzedTitle").textContent = "Reanalisando";
	$("caseReanalyzedNote").textContent = "O pipeline está rodando de novo sobre a mensagem original — analisadores, IA e score. "
		+ "Pode levar alguns minutos se algum fornecedor limitar consultas. Quem denunciou não é avisado.";
	show($("caseReanalyzed"), true);

	post_form("api/cases/" + encodeURIComponent(row.ref) + "/reanalyze", {sid: socket.id}).then(function(result){
		button.disabled = false;
		button.textContent = "Reanalisar";
		if (!selected_case || selected_case.ref !== row.ref){ return; }
		let data = result && result.data;
		if (!result || !result.ok || !data || data.error){
			$("caseReanalyzed").className = "callout warn";
			$("caseReanalyzedTitle").textContent = "A reanálise não terminou";
			$("caseReanalyzedNote").textContent = (data && data.error) || "O servidor não respondeu à reanálise.";
			return;
		}
		let refs = data.recordRefs || [];
		let label = verdict_label(data.verdict);
		$("caseReanalyzed").className = "callout " + (data.verdict === "Safe" ? "ok" : data.verdict === "Malicious" ? "warn" : "neutral");
		$("caseReanalyzedTitle").textContent = "Reanálise: " + label.toLowerCase();
		$("caseReanalyzedNote").textContent = (refs.length
			? "Gravada como novo registro (" + refs.join(", ") + ") com veredito " + label.toLowerCase()
			: "Concluída com veredito " + label.toLowerCase() + ", mas nenhum destino devolveu referência para o novo registro")
			+ (data.score ? ", score " + data.score.score + "/100" : "")
			+ ". Este caso não foi alterado — decida-o à luz do resultado.";
		toast("Reanálise concluída: " + label.toLowerCase() + ".", "ok");
		if (case_surface === "queues"){ load_desk_queue(); }
		if (case_rows.length > 0){ load_cases(); }
	});
}

/* --- assistant beside the case ----------------------------------------------
 *
 * O Chat AI, com o contexto do caso aberto carregado sozinho. Mesmas rotas e
 * mesmas proteções de prompt do Chat AI; uma conversa por caso, zerada quando
 * outro caso é aberto — a resposta sobre um caso lida ao lado de outro é o erro
 * que este painel não pode cometer. */

let assistant_open = false;
let assistant_ref = null;
let assistant_history = [];
let assistant_warned = false;

function sync_case_assistant(){
	let visible = assistant_open && (current_view === "done" || current_view === "queues") && !!selected_case;
	show($("caseAssistant"), visible);
	$("conteudo").classList.toggle("assistant-open", visible);
	$("caseChatBtn").setAttribute("aria-pressed", assistant_open ? "true" : "false");
}

function toggle_case_assistant(){
	assistant_open = !assistant_open;
	if (assistant_open && selected_case && assistant_ref !== String(selected_case.ref)){
		assistant_load(selected_case);
	}
	sync_case_assistant();
	if (assistant_open && !$("assistantInput").disabled){ $("assistantInput").focus(); }
}

function assistant_append(role, text){
	let bubble = el("div", {className: "bubble"}, [
		el("span", {className: "bubble-role", text: CHAT_ROLE_LABEL[role] || "CONTEXTO"}),
		el("p", {className: "bubble-text", text: text})
	]);
	$("assistantThread").appendChild(el("div", {className: "chat-row " + role}, [bubble]));
	$("assistantMessages").scrollTop = $("assistantMessages").scrollHeight;
	return bubble.lastChild;
}

function assistant_set_busy(busy){
	$("assistantSendBtn").disabled = busy || assistant_ref == null;
	$("assistantInput").disabled = busy || assistant_ref == null;
}

function assistant_load(row){
	let ref = String(row.ref);
	assistant_ref = null;
	assistant_history = [];
	assistant_warned = false;
	$("assistantThread").replaceChildren();
	$("assistantSuggestions").replaceChildren();
	$("assistantSub").textContent = "carregando o contexto de " + row.label + "…";
	assistant_set_busy(true);
	get_json("api/chat/load/" + encodeURIComponent(ref)).then(function(response){
		if (!selected_case || String(selected_case.ref) !== ref){ return; }
		if (response == null || response.error){
			$("assistantSub").textContent = "contexto indisponível";
			assistant_append("warn", (response && response.error) || "Não foi possível carregar o contexto deste caso.");
			assistant_set_busy(false);
			return;
		}
		assistant_ref = ref;
		let verdict = VERDICT_LABEL[response.verdict] || response.verdict;
		$("assistantSub").textContent = response.label + " · " + verdict;
		assistant_append("info", "Contexto carregado: " + response.label + " — \"" + response.title + "\" ("
			+ verdict + ", " + response.observableCount + " observáveis"
			+ (response.hasBody ? "" : ", sem o corpo do e-mail") + ").");
		for (let text of CHAT_SUGGESTIONS){
			$("assistantSuggestions").appendChild(el("button", {className: "chip", text: text, attrs: {type: "button"},
				onClick: function(){ $("assistantInput").value = text; assistant_send(); }}));
		}
		assistant_set_busy(false);
	});
}

function assistant_send(){
	let question = $("assistantInput").value.trim();
	if (question === "" || assistant_ref == null || $("assistantSendBtn").disabled){ return; }
	let ref = assistant_ref;
	$("assistantInput").value = "";
	assistant_append("user", question);
	let thinking = assistant_append("assistant", "Pensando…");
	assistant_set_busy(true);
	post_form("api/chat/message", {
		caseRef: ref,
		question: question,
		history: JSON.stringify(assistant_history)
	}).then(function(result){
		// Outro caso aberto enquanto a pergunta viajava: a resposta é sobre o
		// anterior e não pode aparecer ao lado deste
		if (assistant_ref !== ref){ return; }
		assistant_set_busy(false);
		let response = result.ok ? result.data : null;
		if (response == null || response.error){
			thinking.textContent = "Erro: " + ((response && response.error)
				|| "a IA não respondeu. Verifique as configurações do modelo e tente de novo.");
			return;
		}
		thinking.textContent = response.answer;
		if ((response.injectionDetected || []).length && !assistant_warned){
			assistant_warned = true;
			assistant_append("warn", "Atenção: este caso contém marcadores de prompt injection ("
				+ response.injectionDetected.join(", ") + "). O e-mail tenta manipular a análise; "
				+ "leia as respostas da IA com esse contexto.");
		}
		assistant_history.push({role: "user", content: question});
		assistant_history.push({role: "assistant", content: response.answer});
		if (assistant_history.length > 12){ assistant_history = assistant_history.slice(-12); }
		$("assistantInput").focus();
	});
}

/* Social engineering tactics recognized by the LLM for one case.
 *
 * They are pills and not prose because they came back as a closed vocabulary:
 * the same words here, on the dashboard and in the case tag. An assessment that
 * named none is said so, never left as an empty row. */
function render_case_tactics(tactics){
	let container = $("caseTactics");
	if (!container){ return; }
	if (!tactics || tactics.length === 0){
		render_pending("caseTactics", "O modelo não reconheceu nenhuma tática do vocabulário neste e-mail.");
		return;
	}
	container.replaceChildren();
	for (let key of tactics){
		container.appendChild(el("span", {className: "pill warn", text: tactic_label(key)}));
	}
}

/* The handoff's metric strip above the case body.
 *
 * The risk tile shows the level of the LLM assessment, recorded as a case tag
 * during the analysis; it reads "—" marked absent when the model did not run,
 * never a zero — a 0/100 risk on a malicious email would be a lie the analyst
 * has no way to catch. VirusTotal ratio and domain age still have no field
 * behind them. `detail` is null on the first paint and carries the observables
 * once the fetch lands. */
function render_case_metrics(row, detail){
	let container = $("caseMetrics");
	let observables = detail && detail.observables;
	let iocs = observables ? observables.filter(function(o){ return o.ioc; }).length : null;
	let tone = verdict_tone(row.verdict);

	let tiles = [
		{label: "VEREDITO", value: verdict_label(row.verdict), tone: tone},
		{
			label: "OBSERVÁVEIS",
			value: observables ? String(observables.length)
				: (row.observableCount != null ? String(row.observableCount) : "…")
		},
		{label: "IOCS", value: iocs == null ? "…" : String(iocs), tone: iocs > 0 ? "bad" : ""},
		{
			label: "RISCO (LLM)",
			value: row.risk ? (RISK_LABEL[row.risk] || row.risk) : "—",
			tone: row.risk ? (RISK_TONE[row.risk] || "") : "",
			absent: !row.risk,
			title: row.risk
				? "Nível de risco da avaliação de engenharia social feita durante a análise."
				: "O LLM não avaliou este caso: estava desativado ou não respondeu."
		}
	];

	container.replaceChildren();
	for (let tile of tiles){
		container.appendChild(el("div", {className: "metric", attrs: tile.title ? {title: tile.title} : null}, [
			el("span", {className: "metric-label", text: tile.label}),
			el("span", {
				className: "metric-value" + (tile.absent ? " absent" : tile.tone ? " " + tile.tone : ""),
				text: tile.value
			})
		]));
	}
	show(container, true);
}

/* --- whitelist from an open case ------------------------------------------ */

// The handoff's "Adicionar à whitelist" on the case detail. Unlike the other
// panels it adds, this one is real: the whitelist API already exists, only the
// path from a case to it was missing. Whitelisting is destructive to future
// analysis — an entry silences the observable everywhere — so the modal makes
// the analyst tick each value rather than accepting the case wholesale.
let case_wl_values = [];
let case_wl_checked = [];

function open_case_whitelist(){
	if (!selected_case){ return; }
	get_json("api/cases/" + encodeURIComponent(selected_case.ref)).then(function(detail){
		let observables = (detail && detail.observables) || [];
		// Só os tipos que SUPRIMEM observável. Endereço de remetente não aparece
		// aqui de propósito: no v2 ele não é conveniência, é confiança — rebaixa o
		// veredito do e-mail inteiro. Uma concessão dessas não sai de um clique
		// num modal de falso positivo; ela é escrita na aba Whitelist, com motivo
		// e prazo. IP saiu do modelo.
		case_wl_values = observables.filter(function(obs){
			return obs.value && ["domain", "url", "hash"].indexOf(obs.type) !== -1;
		});
		case_wl_checked = [];
		$("caseWhitelistSub").textContent = "observáveis de " + selected_case.label;
		set_status("caseWlStatus", "");
		render_case_wl();
		open_modal("caseWhitelistModal");
	});
}

function render_case_wl(){
	let rows = $("caseWlRows");
	rows.replaceChildren();

	if (case_wl_values.length === 0){
		rows.appendChild(el("span", {
			className: "empty-note",
			text: "Este caso não tem domínio, URL ou hash entre os observáveis. Remetente confiável é cadastrado na aba Whitelist, com motivo e prazo."
		}));
	}

	for (let obs of case_wl_values){
		let on = case_wl_checked.indexOf(obs.value) !== -1;
		let node = el("div", {
			className: "row",
			style: "gap:9px;padding:9px 10px;border-radius:8px;border:1px solid "
				+ (on ? "var(--accent)" : "var(--b1)") + ";background:" + (on ? "var(--accent-soft)" : "var(--s3)") + ";cursor:pointer"
		}, [
			el("div", {className: "check" + (on ? " on" : "")}, [icon(CHECK_ICON, 9)]),
			el("div", {className: "grow col", style: "gap:2px"}, [
				el("span", {className: "mono truncate", title: obs.value, text: obs.value, style: "font-size:var(--fs-body);color:var(--t0)"}),
				el("span", {className: "mono", text: obs.type, style: "font-size:var(--fs-micro);color:var(--t4)"})
			]),
			obs.ioc ? el("span", {className: "pill bad", text: "IOC"}) : null
		]);
		node.onclick = function(){ toggle_case_wl(obs.value); };
		rows.appendChild(node);
	}

	$("caseWlCount").textContent = case_wl_checked.length > 0
		? case_wl_checked.length + " de " + case_wl_values.length + " selecionados"
		: "";
	$("caseWlAll").classList.toggle("on",
		case_wl_values.length > 0 && case_wl_checked.length === case_wl_values.length);
	$("caseWlSaveBtn").disabled = case_wl_checked.length === 0;
}

function toggle_case_wl(value){
	let at = case_wl_checked.indexOf(value);
	if (at === -1){ case_wl_checked.push(value); } else { case_wl_checked.splice(at, 1); }
	render_case_wl();
}

function toggle_case_wl_all(){
	case_wl_checked = case_wl_checked.length === case_wl_values.length
		? []
		: case_wl_values.map(function(obs){ return obs.value; });
	render_case_wl();
}

// Cada valor vira uma regra do seu próprio tipo, como se tivesse sido digitado
// na aba Whitelist — com o prazo padrão do servidor.
//
// Os posts rodam em fila, e não por Promise.all: cada um reescreve o
// whitelist.json inteiro a partir da cópia que acabou de ler, então seis em
// paralelo fariam o último apagar os cinco anteriores.
// Separa host e caminho de uma URL do caso, para o cadastro por prefixo. O
// servidor normaliza de novo — isto é só para montar o formulário.
function wl_split_url(value){
	try {
		let parsed = new URL(value.indexOf("://") === -1 ? "http://" + value : value);
		let path = parsed.pathname || "";
		if (path === "/"){ path = ""; }
		return {host: parsed.hostname, path: path};
	} catch (error){
		return null;
	}
}

function save_case_whitelist(){
	let picked = case_wl_values.filter(function(obs){ return case_wl_checked.indexOf(obs.value) !== -1; });
	if (picked.length === 0){ return; }

	$("caseWlSaveBtn").disabled = true;
	set_status("caseWlStatus", "cadastrando…");

	let failed = [];
	let chain = picked.reduce(function(previous, obs){
		return previous.then(function(){
			// O prazo padrão do servidor vale aqui também: exceção nascida de um
			// falso positivo é a que mais merece voltar para revisão em 180 dias
			let params = {type: obs.type, reason: "falso positivo confirmado em " + selected_case.label,
				expiresAt: "", acceptWarnings: "true"};
			if (obs.type === "url"){
				let split = wl_split_url(obs.value);
				if (split == null){ failed.push(obs.value); return Promise.resolve(); }
				params.mode = split.path ? "prefix" : "prefix";
				params.hostPattern = split.host;
				params.pathPattern = split.path;
				params.value = "";
				// URL sem caminho é liberação do host inteiro: isso é regra de
				// domínio, e é lá que estão as travas de sufixo público
				if (!split.path){ params.type = "domain"; params.value = split.host; }
			} else {
				params.value = obs.value;
			}
			return post_form("api/whitelist/rule", params)
				.then(function(result){
					if (!result.ok || result.data == null || result.data.error){ failed.push(obs.value); }
					else { wl_data = result.data; }
				});
		});
	}, Promise.resolve());

	chain.then(function(){
		if (wl_data){ render_whitelist(); }
		if (failed.length > 0){
			set_status("caseWlStatus",
				failed.length + " de " + picked.length + " não puderam ser cadastrados: " + failed.join(", "), "bad");
			$("caseWlSaveBtn").disabled = false;
			return;
		}
		close_modal();
		toast(picked.length + " observável(is) adicionado(s) à whitelist.", "ok");
	});
}

/* --- confirmed phishing --------------------------------------------------- */

function set_phish_range(range){
	insights_range = range;
	sync_range_controls(range);
	load_insights();
	load_phish();
}

function load_phish(){
	$("phishCount").textContent = "consultando informações…";
	get_json("api/cases?range=" + encodeURIComponent(insights_range) + "&verdict=Malicious&limit=60")
		.then(function(payload){
			if (payload == null || payload.error){
				phish_rows = [];
				$("phishRows").replaceChildren(el("div", {
					className: "tbl-empty",
					text: (payload && payload.error) || "Não foi possível consultar os registros."
				}));
				$("phishCount").textContent = "sem dados";
				return;
			}
			phish_rows = payload.cases;
			$("phishCount").textContent = payload.total + " e-mail(s) malicioso(s) · "
				+ (payload.counts.Suspicious || 0) + " aguardando ação";
			// Clicking a confirmed phishing row opens it in the analyzed-emails
			// screen, which already owns the detail panel
			render_case_list($("phishRows"), phish_rows, function(row){
				show_view("done");
				cases_verdict = "Malicious";
				cases_range = insights_range;
				sync_case_chips();
				load_cases();
				open_case(row);
			}, payload.notice);
		});
}

/* ========================================================================== */
/* Info tips — o texto explicativo atrás do ícone "i"                         */
/* ========================================================================== */
/*
 * Cada `.info` carrega o botão e, ao lado, o texto em `.info-tip-text`, escondido
 * pelo CSS. O balão é um só, `position: fixed` no <body>: os painéis rolam com
 * `overflow: auto`, e um balão posicionado dentro deles seria cortado na borda.
 *
 * O texto é clonado da marcação autorada no template, ou montado com
 * `textContent` em info_tip() — nunca innerHTML com dado vindo de fora.
 *
 * Passar o mouse mostra; clicar fixa (é o único jeito num toque); Esc, clique
 * fora, rolagem e redimensionamento fecham. Foco de teclado também mostra.
 */

let info_tip_open = null;    // o botão cujo balão está visível
let info_tip_pinned = false; // aberto por clique, e não só por hover/foco

function info_tip_layer(){
	let layer = $("infoTipLayer");
	if (!layer){
		layer = el("div", {className: "info-tip-layer hidden", attrs: {id: "infoTipLayer", role: "tooltip"}});
		document.body.appendChild(layer);
	}
	return layer;
}

function info_tip(text){
	if (!text){ return null; }
	return el("span", {className: "info"}, [
		el("button", {className: "info-tip", attrs: {type: "button", "aria-label": "Mais informações",
			"aria-expanded": "false", "data-click": "toggle_info_tip"}}, [
			icon('<circle cx="8" cy="8" r="6.2"></circle><path d="M8 7.2v4"></path><path d="M8 4.9h.01"></path>', 14)
		]),
		el("span", {className: "info-tip-text", text: text})
	]);
}

function show_info_tip(button, pinned){
	let source = button.parentElement && button.parentElement.querySelector(".info-tip-text");
	if (!source){ return; }
	if (info_tip_open && info_tip_open !== button){ hide_info_tip(); }
	let layer = info_tip_layer();
	layer.replaceChildren.apply(layer, Array.from(source.childNodes).map(function(node){ return node.cloneNode(true); }));
	show(layer, true);
	info_tip_open = button;
	info_tip_pinned = !!pinned;
	button.setAttribute("aria-expanded", "true");
	button.setAttribute("aria-describedby", "infoTipLayer");
	place_info_tip(button, layer);
}

// Abaixo do ícone, alinhado à esquerda dele; sobe quando não cabe embaixo e
// nunca sai da janela pela lateral
function place_info_tip(button, layer){
	let margin = 8;
	let rect = button.getBoundingClientRect();
	layer.style.left = "0px";
	layer.style.top = "0px";
	let box = layer.getBoundingClientRect();
	let left = Math.min(Math.max(margin, rect.left - 10), window.innerWidth - box.width - margin);
	let top = rect.bottom + 6;
	if (top + box.height > window.innerHeight - margin && rect.top - box.height - 6 > margin){
		top = rect.top - box.height - 6;
	}
	layer.style.left = Math.max(margin, left) + "px";
	layer.style.top = Math.max(margin, top) + "px";
}

function hide_info_tip(){
	if (!info_tip_open){ return; }
	info_tip_open.setAttribute("aria-expanded", "false");
	info_tip_open.removeAttribute("aria-describedby");
	info_tip_open = null;
	info_tip_pinned = false;
	show(info_tip_layer(), false);
}

function toggle_info_tip(button, event){
	if (event){ event.stopPropagation(); }
	if (info_tip_open === button && info_tip_pinned){ hide_info_tip(); return; }
	show_info_tip(button, true);
}

document.addEventListener("mouseover", function(event){
	let button = event.target.closest && event.target.closest(".info-tip");
	if (button && info_tip_open !== button && !info_tip_pinned){ show_info_tip(button, false); }
});
document.addEventListener("mouseout", function(event){
	let button = event.target.closest && event.target.closest(".info-tip");
	if (button && button === info_tip_open && !info_tip_pinned
		&& !(event.relatedTarget && button.contains(event.relatedTarget))){ hide_info_tip(); }
});
document.addEventListener("focusin", function(event){
	let button = event.target.closest && event.target.closest(".info-tip");
	if (button && info_tip_open !== button){ show_info_tip(button, false); }
});
document.addEventListener("focusout", function(event){
	if (info_tip_open && event.target === info_tip_open && !info_tip_pinned){ hide_info_tip(); }
});
document.addEventListener("click", function(event){
	if (info_tip_open && !event.target.closest(".info-tip") && !event.target.closest("#infoTipLayer")){ hide_info_tip(); }
});
window.addEventListener("scroll", hide_info_tip, true);
window.addEventListener("resize", hide_info_tip);

/* ========================================================================== */
/* Event wiring                                                               */
/* ========================================================================== */

const HANDLERS = {
	toggle_info_tip: toggle_info_tip,
	show_notif_tab: show_notif_tab,
	save_volume_alerts: save_volume_alerts,
	render_volume_rule: render_volume_rule,
	open_alert_connector_modal: open_alert_connector_modal,
	toggle_theme: toggle_theme,
	toggle_case_observables: toggle_case_observables,
	open_case_reclassify: open_case_reclassify,
	open_case_revert: open_case_revert,
	close_case_reclassify: close_case_reclassify,
	sync_reclass_reason: sync_reclass_reason,
	submit_case_reclassify: submit_case_reclassify,
	cycle_scale: cycle_scale,
	toggle_sidebar: toggle_sidebar,
	toggle_profile_menu: toggle_profile_menu,
	toggle_switch: toggle_switch,
	sync_range: sync_range,
	show_view: show_view,
	show_config_tab: show_config_tab,
	close_modal: close_modal,
	do_logout: do_logout,
	list_emails: list_emails,
	set_inbox_order: set_inbox_order,
	go_inbox_page: go_inbox_page,
	filter_queue_debounced: filter_queue_debounced,
	clear_queue_query: clear_queue_query,
	set_preview_mode: set_preview_mode,
	toggle_preview_frame: toggle_preview_frame,
	toggle_select_all: toggle_select_all,
	clear_selection: clear_selection,
	analyze_current: analyze_current,
	analyze_selected: analyze_selected,
	save_scheduler_config: save_scheduler_config,
	apply_llm_provider_preset: apply_llm_provider_preset,
	update_pipeline_note: update_pipeline_note,
	update_prompt_chars: update_prompt_chars,
	save_llm_config: save_llm_config,
	open_llm_model_picker: open_llm_model_picker,
	filter_llm_models: filter_llm_models,
	use_llm_model_search: use_llm_model_search,
	refresh_llm_model_catalog: refresh_llm_model_catalog,
	select_email_tab: select_email_tab,
	save_email_config: save_email_config,
	save_verdict_config: save_verdict_config,
	open_ticket_modal: open_ticket_modal,
	save_ticket_destination: save_ticket_destination,
	test_ticket_destination: test_ticket_destination,
	save_smtp_config: save_smtp_config,
	test_smtp_config: test_smtp_config,
	save_case_config: save_case_config,
	save_departments_config: save_departments_config,
	test_departments_config: test_departments_config,
	save_sso_config: save_sso_config,
	toggle_dept_credentials: toggle_dept_credentials,
	save_inbox_poll_config: save_inbox_poll_config,
	render_whitelist: render_whitelist,
	whitelist_add: whitelist_add,
	whitelist_show_type: whitelist_show_type,
	whitelist_toggle_all: whitelist_toggle_all,
	whitelist_delete_selected: whitelist_delete_selected,
	whitelist_dry_run: whitelist_dry_run,
	whitelist_cancel_edit: whitelist_cancel_edit,
	whitelist_migrate: whitelist_migrate,
	whitelist_export: whitelist_export,
	whitelist_import: whitelist_import,
	open_user_modal: open_user_modal,
	create_user: create_user,
	change_own_password: change_own_password,
	chat_load_context: chat_load_context,
	chat_clear_context: chat_clear_context,
	chat_send: chat_send,
	set_insights_range: set_insights_range,
	reload_insights: reload_insights,
	set_case_verdict: set_case_verdict,
	set_case_range: set_case_range,
	filter_cases_debounced: filter_cases_debounced,
	filter_analyzers_debounced: filter_analyzers_debounced,
	clear_analyzer_filter: clear_analyzer_filter,
	filter_scoring_debounced: filter_scoring_debounced,
	save_scoring: save_scoring,
	reset_scoring_weights: reset_scoring_weights,
	open_scoring_method: open_scoring_method,
	toggle_analyzer_guide: toggle_analyzer_guide,
	open_custom_modal: open_custom_modal,
	add_custom_rule: add_custom_rule,
	render_custom_auth: render_custom_auth,
	save_custom: save_custom,
	delete_custom: delete_custom,
	test_custom: test_custom,
	open_connector_modal: open_connector_modal,
	add_connector_param: add_connector_param,
	render_connector_auth: render_connector_auth,
	save_connector: save_connector,
	delete_connector: delete_connector,
	preview_connector: preview_connector,
	test_connector: test_connector,
	reload_cases: reload_cases,
	show_desk_queue: show_desk_queue,
	reanalyze_case: reanalyze_case,
	toggle_memory_inactive: toggle_memory_inactive,
	save_evidence_config: save_evidence_config,
	toggle_case_assistant: toggle_case_assistant,
	assistant_send: assistant_send,
	open_case_confirm_malicious: open_case_confirm_malicious,
	toggle_case_errata: toggle_case_errata,
	set_case_memory_scope: set_case_memory_scope,
	set_case_mail_mode: set_case_mail_mode,
	toggle_case_mail_frame: toggle_case_mail_frame,
	toggle_case_scope: toggle_case_scope,
	set_desk_range: set_desk_range,
	filter_desk_debounced: filter_desk_debounced,
	clear_desk_search: clear_desk_search,
	reload_desk: reload_desk,
	set_phish_range: set_phish_range,
	open_campaign: open_campaign,
	clear_ioc_filter: clear_ioc_filter,
	clear_signal_filter: clear_signal_filter,
	export_iocs: export_iocs,
	open_case_whitelist: open_case_whitelist,
	toggle_case_wl_all: toggle_case_wl_all,
	save_case_whitelist: save_case_whitelist,
	clear_done_query: clear_done_query,
	show_integr_tab: show_integr_tab,
	save_analyzer: save_analyzer,
	test_analyzer: test_analyzer,
	toggle_responder_guide: toggle_responder_guide,
	save_responder: save_responder,
	test_responder: test_responder,
	open_case_block: open_case_block,
	open_campaign_block: open_campaign_block,
	toggle_block_all: toggle_block_all,
	submit_block: submit_block,
	reload_audit: reload_audit,
	audit_export: audit_export,
	toggle_audit_assistant: toggle_audit_assistant,
	audit_filter_text: audit_filter_text,
	audit_filter_select: audit_filter_select,
	audit_filter_date: audit_filter_date,
	audit_set_range: audit_set_range,
	audit_clear_filters: audit_clear_filters,
	audit_page: audit_page,
	audit_ai_send: audit_ai_send,
	save_audit_log_config: save_audit_log_config,
	test_audit_log_config: test_audit_log_config
};

function dispatch(element, action, event){
	let handler = HANDLERS[action];
	if (typeof handler !== "function"){ return; }
	if (element.hasAttribute("data-arg")){
		handler(element.getAttribute("data-arg"), event);
	} else {
		handler(element, event);
	}
}

document.addEventListener("click", function(event){
	let element = event.target.closest("[data-click]");
	if (!element){
		// Clicking anywhere else closes the profile popup
		if (!event.target.closest(".profile")){ show($("profileMenu"), false); }
		return;
	}
	if (element.tagName === "A"){ event.preventDefault(); }
	dispatch(element, element.getAttribute("data-click"), event);
});

document.addEventListener("change", function(event){
	let element = event.target.closest("[data-change]");
	if (element){ dispatch(element, element.getAttribute("data-change"), event); }
});

document.addEventListener("input", function(event){
	let element = event.target.closest("[data-input]");
	if (element){ dispatch(element, element.getAttribute("data-input"), event); }
});

document.addEventListener("keydown", function(event){
	if (event.key === "Escape"){
		// O balão fecha antes do modal: dentro de um modal, o primeiro Esc é
		// para a dica, não para descartar o formulário
		if (info_tip_open){ hide_info_tip(); return; }
		if (open_modal_id){ close_modal(); return; }
		show($("profileMenu"), false);
		return;
	}
	if (event.key !== "Enter"){ return; }
	let element = event.target.closest("[data-enter]");
	if (element){ dispatch(element, element.getAttribute("data-enter"), event); }
});

/* ========================================================================== */
/* Boot                                                                       */
/* ========================================================================== */

(function boot(){
	let stored_theme = null;
	let stored_sidebar = null;
	try {
		// The preference keys carry the brand, and the brand moved twice:
		// redphish -> bluephising -> bluephish. Only the first entry is ever
		// written; the older two are read so nobody's theme and sidebar snap
		// back to the defaults just because the product was renamed.
		let stored = function(suffix){
			for (let brand of PREF_BRANDS){
				let value = window.localStorage.getItem(brand + "." + suffix);
				if (value){ return value; }
			}
			return null;
		};
		stored_theme = stored("theme");
		stored_sidebar = stored("sidebar");
	} catch (e) { /* private mode */ }
	apply_theme(stored_theme === "light" ? "light" : "dark");
	if (stored_sidebar === "closed"){ toggle_sidebar(); }
	// O tamanho vem antes de qualquer medida de layout: aplicar depois faria a
	// tela montar num tamanho e saltar para outro na frente de quem olha
	load_scale();
	wire_a11y_controls();

	// The MISP name is edited under Configurações → Caso; the Integrações card
	// only mirrors it
	$("mispIdInput").readOnly = true;

	show_config_tab("auto");
	show_integr_tab("plataforma");
	// The saved preference has to be applied before the first listing lands,
	// otherwise the queue renders in the server's direction and jumps once the
	// chips catch up
	load_inbox_order();
	// The executive dashboard is the landing screen: it answers "what happened"
	// before the analyst decides what to work on
	show_view("exec");
	chat_clear_context();
	// O contador da mesa aparece no menu desde o início: quantos casos esperam
	// decisão é a informação que faz alguém abrir a fila, não a que ela mostra
	// depois de aberta
	load_desk_queue();

	// Antes de qualquer requisição de dado: se nenhuma aba é dona desta sessão,
	// a aba original foi fechada e só o cookie sobreviveu. Nesse caso o painel
	// não chega a carregar — desloga e volta para a tela de login
	claim_tab_token().then(function(owned){
		if (!owned){
			end_orphan_session();
			return;
		}
		window.setInterval(tab_heartbeat, TAB_HEARTBEAT_MS);
		// The configuration is only fetched for users allowed to see it, so an
		// analyst never issues a request that would be rejected
		load_identity();
	});
})();
