// Idioma da interface: português (padrão) e inglês.
//
// O texto da interface nasce em português, escrito direto nos templates e no
// JavaScript. Em vez de trocar cada um por uma chave — milhares de pontos, e um
// esquecido vira texto em branco —, o português continua sendo a fonte e este
// arquivo troca o que está na tela quando o idioma é inglês:
//
// * o texto exato é procurado no dicionário (i18n-en.js);
// * o que não casa por inteiro — frases montadas com números e nomes — tem os
//   trechos conhecidos trocados, e o resto fica como está;
// * o que o dicionário não conhece continua em português. É a falha segura:
//   uma tela meio traduzida se lê; uma tela sem texto, não.
//
// O DOM é percorrido uma vez e depois observado, então o que o aplicativo
// escreve depois (toasts, listas, mensagens do servidor) também é traduzido. O
// original em português é guardado ao lado de cada nó: voltar ao português
// restaura o texto exato, e uma mensagem nova escrita pela aplicação não é
// confundida com uma já traduzida.
//
// Mora num arquivo próprio porque a CSP só aceita script de 'self'. Nada aqui
// roda texto de e-mail como código: só lê e escreve nodeValue e atributos.
(function(){
	"use strict";

	const STORAGE_KEY = "bluephish.lang";
	const LANGS = {"pt-BR": "pt-BR", "en": "en"};
	const ATTRIBUTES = ["title", "placeholder", "aria-label", "alt"];
	// Conteúdo que não é texto da interface: código e o que a pessoa digitou numa
	// caixa de texto. Placeholder, title e <option> SÃO interface e são traduzidos;
	// o iframe do e-mail é outro documento e nem entra no DOM daqui
	const SKIP_TAGS = {SCRIPT: 1, STYLE: 1, TEXTAREA: 1, NOSCRIPT: 1};
	// Acima disto um texto é conteúdo (um resumo do LLM, um corpo de e-mail), não
	// uma mensagem da interface — nem se tenta casar trechos nele
	const MAX_PHRASE_CHARS = 400;
	// Palavras de ligação que podem ficar entre trechos conhecidos ("60 de 120
	// caso(s)"). Conjunto fechado: qualquer outra palavra solta desfaz a tradução
	const CONNECTORS = {de: "of", e: "and", em: "in", ou: "or", do: "of the", da: "of the",
		dos: "of the", das: "of the", no: "in the", na: "in the", por: "by", para: "to", com: "with"};
	const LETTER = /\p{L}/u;
	const WORD_RUN = /^\p{L}+/u;
	const WORD_CHAR = /[\p{L}\p{N}]/u;

	let lang = "pt-BR";
	let dictionary = {exact: {}, patterns: [], after: []};
	let observer = null;
	const cache = new Map();

	// Texto de origem de cada nó, e o que este módulo escreveu por último nele
	const text_state = new WeakMap();
	const attr_state = new WeakMap();
	let title_state = null;

	function normalize(text){
		return text.replace(/\s+/g, " ").trim();
	}

	// Os trechos conhecidos, agrupados pelo primeiro caractere e do mais longo ao
	// mais curto. Procurar por índice custa microssegundos; uma alternação de mil
	// expressões regulares custava dezenas de milissegundos por texto
	let phrase_index = null;

	function build_phrases(){
		phrase_index = new Map();
		let keys = Object.keys(dictionary.exact).filter(function(key){ return key.length >= 6; });
		keys.sort(function(a, b){ return b.length - a.length; });
		for (let key of keys){
			let bucket = phrase_index.get(key[0]);
			if (!bucket){ bucket = []; phrase_index.set(key[0], bucket); }
			bucket.push(key);
		}
	}

	// Só traduz o que os trechos conhecidos cobrem por inteiro. Um assunto de
	// e-mail, um IOC ou um resumo do modelo que apenas CONTÉM uma palavra do
	// dicionário ("Fatura em aberto - Confirmar pagamento") não pode ter essa
	// palavra trocada: quem lê a tela estaria lendo o que o remetente não escreveu.
	// Sobrou uma letra fora dos trechos, o texto fica exatamente como veio
	function translate_by_phrases(key){
		if (!phrase_index || key.length > MAX_PHRASE_CHARS){ return null; }
		let out = "";
		let matched = 0;
		let i = 0;
		let n = key.length;
		while (i < n){
			let hit = null;
			let bucket = phrase_index.get(key[i]);
			if (bucket){
				for (let candidate of bucket){
					if (!key.startsWith(candidate, i)){ continue; }
					if (WORD_CHAR.test(candidate[0]) && i > 0 && WORD_CHAR.test(key[i - 1])){ continue; }
					let end = i + candidate.length;
					if (WORD_CHAR.test(candidate[candidate.length - 1]) && end < n && WORD_CHAR.test(key[end])){ continue; }
					hit = candidate;
					break;
				}
			}
			if (hit){
				out += dictionary.exact[hit];
				i += hit.length;
				matched += 1;
			} else {
				if (LETTER.test(key[i])){
					let run = i === 0 || !LETTER.test(key[i - 1]) ? key.slice(i).match(WORD_RUN) : null;
					let word = run && CONNECTORS[run[0].toLowerCase()];
					if (!word){ return null; }
					out += word;
					i += run[0].length;
					continue;
				}
				out += key[i];
				i += 1;
			}
		}
		if (!matched){ return null; }
		for (let pair of dictionary.after){ out = out.replace(pair[0], pair[1]); }
		return out;
	}

	// A fronteira de espaço do original é preservada, para " caso(s)" não ficar
	// colado no número que vem antes
	function apply_edges(source, out){
		let lead = source.match(/^\s*/)[0];
		let trail = source.match(/\s*$/)[0];
		return lead + out + trail;
	}

	function translate_key(key){
		let out = dictionary.exact[key];
		if (out !== undefined){ return out; }
		for (let pair of dictionary.patterns){
			if (pair[0].test(key)){ return key.replace(pair[0], pair[1]); }
		}
		let by_phrases = translate_by_phrases(key);
		return by_phrases === null ? key : by_phrases;
	}

	function translate(source){
		if (lang === "pt-BR"){ return source; }
		let key = normalize(source);
		if (!key){ return source; }
		if (!cache.has(key)){
			if (cache.size > 5000){ cache.clear(); }
			cache.set(key, translate_key(key));
		}
		return apply_edges(source, cache.get(key));
	}

	// Marcado pela página como "não traduza": o botão de idioma
	function in_skip_region(node){
		for (let el = node.nodeType === 1 ? node : node.parentElement; el; el = el.parentElement){
			if (el.hasAttribute && el.hasAttribute("data-i18n-skip")){ return true; }
		}
		return false;
	}

	// Texto dentro de código ou de uma caixa de texto não é interface
	function text_skipped(node){
		for (let el = node.nodeType === 1 ? node : node.parentElement; el; el = el.parentElement){
			if (SKIP_TAGS[el.tagName]){ return true; }
		}
		return in_skip_region(node);
	}

	function apply_text(node){
		let current = node.nodeValue;
		let state = text_state.get(node);
		// O que está no nó não é o que escrevemos: a aplicação trocou o texto
		if (!state || state.rendered !== current){
			state = {source: current, rendered: current};
		}
		let wanted = lang === "pt-BR" ? state.source : translate(state.source);
		if (wanted !== current){ node.nodeValue = wanted; }
		state.rendered = wanted;
		text_state.set(node, state);
	}

	function apply_attribute(element, name){
		let current = element.getAttribute(name);
		if (current === null){ return; }
		let states = attr_state.get(element) || {};
		let state = states[name];
		if (!state || state.rendered !== current){
			state = {source: current, rendered: current};
		}
		let wanted = lang === "pt-BR" ? state.source : translate(state.source);
		if (wanted !== current){ element.setAttribute(name, wanted); }
		state.rendered = wanted;
		states[name] = state;
		attr_state.set(element, states);
	}

	function walk(root){
		if (!root || in_skip_region(root)){ return; }
		if (root.nodeType === 3){
			if (root.nodeValue.trim() && !text_skipped(root)){ apply_text(root); }
			return;
		}
		if (root.nodeType !== 1){ return; }
		for (let name of ATTRIBUTES){
			if (root.hasAttribute(name)){ apply_attribute(root, name); }
		}
		if (SKIP_TAGS[root.tagName]){ return; }
		for (let child = root.firstChild; child; child = child.nextSibling){
			walk(child);
		}
	}

	function on_mutations(records){
		for (let record of records){
			if (record.type === "characterData"){
				if (!text_skipped(record.target) && record.target.nodeValue.trim()){ apply_text(record.target); }
			} else if (record.type === "attributes"){
				if (!in_skip_region(record.target)){ apply_attribute(record.target, record.attributeName); }
			} else {
				for (let added of record.addedNodes){ walk(added); }
			}
		}
	}

	function start_observing(){
		if (observer || !window.MutationObserver){ return; }
		observer = new MutationObserver(on_mutations);
		observer.observe(document.body, {
			childList: true, subtree: true, characterData: true,
			attributes: true, attributeFilter: ATTRIBUTES
		});
	}

	function stop_observing(){
		if (observer){ observer.disconnect(); observer = null; }
	}

	function sync_title(){
		if (!title_state || title_state.rendered !== document.title){
			title_state = {source: document.title, rendered: document.title};
		}
		let wanted = lang === "pt-BR" ? title_state.source : translate(title_state.source);
		document.title = wanted;
		title_state.rendered = wanted;
	}

	// O botão mostra para onde vai, e não onde está. Fica de fora da tradução
	// (data-i18n-skip no markup): o texto dele já é escrito no idioma certo
	function sync_toggles(){
		for (let button of document.querySelectorAll("[data-lang-toggle]")){
			let to_english = lang !== "en";
			button.textContent = to_english ? "EN" : "PT";
			let label = to_english ? "Switch to English" : "Mudar para português";
			button.setAttribute("title", label);
			button.setAttribute("aria-label", label);
		}
	}

	function set_language(next){
		next = LANGS[next] || "pt-BR";
		stop_observing();
		lang = next;
		cache.clear();
		document.documentElement.setAttribute("lang", lang);
		walk(document.body);
		sync_title();
		sync_toggles();
		if (lang !== "pt-BR"){ start_observing(); }
		document.dispatchEvent(new CustomEvent("bluephish:language", {detail: {lang: lang}}));
	}

	function choose_language(next){
		set_language(next);
		try { window.localStorage.setItem(STORAGE_KEY, lang); } catch (e) { /* modo privado */ }
	}

	function stored_language(){
		try { return window.localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
	}

	// Texto montado em JavaScript e que não passa pelo DOM (confirm, srcdoc): o
	// português entra, o idioma atual sai
	function t(text){
		return translate(String(text));
	}

	function locale(){
		return lang === "en" ? "en-US" : "pt-BR";
	}

	function init(){
		let source = window.BLUEPHISH_I18N_EN || {};
		dictionary = {
			exact: source.exact || {},
			patterns: (source.patterns || []).map(function(pair){ return [new RegExp(pair[0]), pair[1]]; }),
			after: (source.after || []).map(function(pair){ return [new RegExp(pair[0], "g"), pair[1]]; })
		};
		build_phrases();

		document.addEventListener("click", function(event){
			let button = event.target.closest && event.target.closest("[data-lang-toggle]");
			if (button){ choose_language(lang === "en" ? "pt-BR" : "en"); }
		});

		// Português é o padrão e não precisa percorrer nada: a página já nasce nele.
		// Só uma escolha guardada por inglês põe o tradutor para trabalhar
		if (stored_language() === "en"){
			set_language("en");
		} else {
			sync_toggles();
		}
	}

	window.BluePhishI18n = {t: t, locale: locale, set: choose_language, current: function(){ return lang; }};
	window.t = t;
	window.ui_locale = locale;

	if (document.readyState === "loading"){
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
