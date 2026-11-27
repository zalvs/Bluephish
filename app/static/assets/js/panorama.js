/* Panorama externo — o que a comunidade de segurança publicou sobre phishing.
 *
 * Carregado antes de bluephish.js, que registra as ações daqui no mapa HANDLERS
 * e chama load_intel() ao abrir a tela. As funções auxiliares ($, el, get_json,
 * post_json, show, set_status) são as de bluephish.js: só são chamadas depois que
 * ele carregou.
 *
 * Regras que a tela segura (BLUEPHISH_ARCHITECTURE.md §4.8.2):
 *  - Todo texto vindo de fonte externa entra por textContent (el()). Link só
 *    http(s), em nova aba, sem referrer.
 *  - Número na tela vem da contagem do servidor, nunca do resumo por IA.
 *  - Tema sem sinal medível diz "sem como medir aqui", nunca zero; período antes
 *    do começo da coleta é dito incompleto, nunca tranquilo.
 */

let intel_period = "30d";
let intel_payload = null;
let intel_sources = null;
let intel_filter = null;
let intel_by_id = {};

const INTEL_KIND_LABEL = {research: "pesquisa", press: "imprensa", cert: "centro de resposta", brazil: "Brasil"};
const INTEL_STATUS = {
	fresh: {tone: "ok", text: "em dia"},
	failing: {tone: "warn", text: "última tentativa falhou"},
	stale: {tone: "bad", text: "parada"},
	failed: {tone: "bad", text: "falhou"},
	never: {tone: "", text: "ainda não coletada"}
};

function intel_is_admin(){
	return !!(current_identity && current_identity.canChangeSettings);
}

function intel_plural(count, one, many){
	return count + " " + (count === 1 ? one : many);
}

function intel_day(seconds){
	if (!seconds){ return "—"; }
	return new Date(seconds * 1000).toLocaleDateString(ui_locale(), {day: "2-digit", month: "2-digit", year: "numeric"});
}

// O link de uma publicação. O servidor só guarda http(s); conferir de novo aqui
// custa uma linha e fecha a porta para um javascript: que um dia escape de lá.
function intel_link(item, text, className){
	let href = String(item.link || "");
	if (!/^https?:\/\//i.test(href)){
		return el("span", {className: className || "", text: text});
	}
	return el("a", {className: (className || "") + " intel-link", text: text,
		attrs: {href: href, target: "_blank", rel: "noopener noreferrer"}});
}

function intel_theme_label(key){
	let theme = (intel_payload && intel_payload.themes || []).find(function(t){ return t.key === key; });
	return theme ? theme.label : key;
}

function intel_sector_label(key){
	let sector = (intel_payload && intel_payload.sectors || []).find(function(s){ return s.key === key; });
	return sector ? sector.label : key;
}

/* --- abrir, recarregar, período ------------------------------------------- */

// O card da Visão Executiva abre o panorama no período que a executiva mostrava
function open_intel(){
	if (["7d", "30d", "90d"].indexOf(insights_range) !== -1){ intel_period = insights_range; }
	intel_payload = null;
	show_view("intel");
}

function set_intel_period(period){
	intel_period = period;
	intel_filter = null;
	load_intel();
}

function reload_intel(){
	load_intel();
	load_intel_sources();
}

function load_intel(){
	$("intelSub").textContent = "consultando as fontes…";
	get_json("api/threat-intel?period=" + encodeURIComponent(intel_period)).then(function(payload){
		if (payload == null || payload.error){
			intel_payload = null;
			show($("intelError"), true);
			$("intelErrorText").textContent = (payload && payload.error) || "O servidor não respondeu.";
			$("intelSub").textContent = "sem dados";
			return;
		}
		show($("intelError"), false);
		intel_payload = payload;
		intel_by_id = {};
		for (let item of payload.items || []){ intel_by_id[item.id] = item; }
		render_intel();
	});
}

function load_intel_sources(){
	get_json("api/threat-intel/sources").then(function(payload){
		if (payload == null || payload.error){ return; }
		intel_sources = payload;
		render_intel_sources();
		// A chamada de tela vazia depende de saber se alguma fonte está ligada
		if (intel_payload){ render_intel_notices(); }
	});
}

/* --- a tela --------------------------------------------------------------- */

function render_intel(){
	let payload = intel_payload;
	$("intelSub").textContent = payload.period.label + " · "
		+ intel_plural(payload.totals.relevant, "publicação sobre phishing", "publicações sobre phishing")
		+ " · " + intel_plural(payload.totals.sources, "fonte", "fontes");
	render_intel_periods();
	render_intel_notices();
	render_intel_highlights();
	render_intel_summary();
	render_intel_themes();
	render_intel_side();
	render_intel_items();
}

function render_intel_periods(){
	let chips = $("intelPeriods");
	chips.replaceChildren();
	for (let period of intel_payload.periods || []){
		let chip = el("button", {className: "chip" + (period.key === intel_payload.period.key ? " active" : ""),
			text: period.label, attrs: {type: "button"}});
		chip.onclick = function(){ set_intel_period(period.key); };
		chips.appendChild(chip);
	}
}

function intel_enabled_count(){
	if (intel_sources){
		return intel_sources.sources.filter(function(source){ return source.enabled; }).length;
	}
	return intel_payload ? intel_payload.totals.enabledSources : 0;
}

function render_intel_notices(){
	let payload = intel_payload;
	let none = intel_enabled_count() === 0;
	show($("intelEmpty"), none);
	show($("intelEmptyActions"), none && intel_is_admin());
	if (none && !intel_is_admin()){
		$("intelEmptyText").textContent = "Nada é baixado até um administrador ligar as fontes de inteligência nesta tela.";
	}

	let reasons = [];
	if (!none && payload.partial){
		reasons.push(payload.collectingSince
			? "A coleta começou em " + intel_day(payload.collectingSince) + ". Antes disso só entram as publicações que ainda estavam nos feeds, então o período não está completo e a comparação com o período anterior fica de fora."
			: "Nenhuma fonte foi coletada ainda.");
	}
	if ((payload.sourcesFailing || []).length > 0){
		let names = payload.sourcesFailing.map(function(id){
			let source = intel_sources && intel_sources.sources.find(function(s){ return s.id === id; });
			return source ? source.name : id;
		});
		reasons.push("Sem coleta recente de: " + names.join(", ") + ". O que elas publicaram desde a última coleta não está aqui.");
	}
	if (payload.localError){
		reasons.push("Os casos do período não puderam ser lidos: o cruzamento com o ambiente ficou de fora.");
	} else if ((payload.localUnread || []).length > 0){
		reasons.push("Um destino de registro não respondeu; o cruzamento com o ambiente conta só o que foi lido.");
	}
	show($("intelPartial"), reasons.length > 0);
	$("intelPartialText").textContent = reasons.join(" ");
}

// A frase do cruzamento de um tema com os casos. Três estados, nunca confundidos:
// medido (com o número), medível mas não lido, e sem sinal no ambiente.
function intel_local_sentence(theme){
	if (theme.local){
		let local = theme.local;
		if (local.cases > 0){
			return "Aqui: " + intel_plural(local.cases, "caso de ameaça", "casos de ameaça") + " " + local.label
				+ (local.malicious > 0 ? ", " + local.malicious + " confirmado(s) malicioso(s)" : "") + ".";
		}
		return "Aqui: nenhum dos " + local.threatCases + " casos de ameaça do período " + local.label + ".";
	}
	if (theme.measurable){ return "Aqui: os casos do período não puderam ser lidos."; }
	return "Sem como medir aqui: a análise não registra esse sinal.";
}

function intel_trend_text(theme){
	if (theme.previous == null){ return ""; }
	if (theme.count > theme.previous){ return "subiu de " + theme.previous + " no período anterior"; }
	if (theme.count < theme.previous){ return "eram " + theme.previous + " no período anterior"; }
	return "igual ao período anterior";
}

function intel_sources_line(ids, limit){
	let names = [];
	let line = el("span", {className: "intel-cites"});
	for (let id of ids){
		let item = intel_by_id[id];
		if (!item || names.indexOf(item.sourceName) !== -1){ continue; }
		names.push(item.sourceName);
		if (line.childNodes.length > 0){ line.appendChild(document.createTextNode(" · ")); }
		line.appendChild(intel_link(item, item.sourceName));
		if (names.length >= (limit || 3)){ break; }
	}
	return line;
}

/* Os destaques: o que as fontes alegaram no período, em frases montadas aqui a
 * partir das contagens — o "em outubro, as fontes relataram..." sem IA. */
function render_intel_highlights(){
	let payload = intel_payload;
	let box = $("intelHighlights");
	box.replaceChildren();
	$("intelHeadlineTitle").textContent = "O que as fontes relataram — " + payload.period.label;
	$("intelHeadlineCode").textContent = intel_plural(payload.totals.relevant, "publicação", "publicações");

	if (payload.totals.relevant === 0){
		box.appendChild(el("span", {className: "empty-note", text: intel_enabled_count() === 0
			? "Ligue as fontes para ver o que está sendo publicado."
			: "Nenhuma publicação sobre phishing coletada neste período."}));
		return;
	}

	// Os quatro temas mais citados, mais qualquer outro que já chegou à caixa: um
	// tema com poucas publicações lá fora e casos aqui é o que mais importa ler
	let featured = payload.themes.filter(function(theme, index){
		return index < 4 || (theme.local && theme.local.cases > 0);
	});
	let lines = [];
	for (let theme of featured){
		let trend = intel_trend_text(theme);
		lines.push({
			tone: theme.trending ? "warn" : "",
			title: theme.label,
			body: intel_plural(theme.count, "publicação", "publicações") + " de "
				+ intel_plural(theme.sources, "fonte", "fontes") + (trend ? " — " + trend : "") + ". "
				+ intel_local_sentence(theme),
			cites: theme.items
		});
	}
	let actor = (payload.actors || [])[0];
	if (actor){
		lines.push({tone: "", title: "Grupo mais citado: " + actor.name,
			body: "Aparece em " + intel_plural(actor.count, "publicação", "publicações") + " do período.",
			cites: actor.items});
	}
	if (payload.brazil && payload.brazil.count > 0){
		lines.push({tone: "warn", title: "Brasil e América Latina",
			body: intel_plural(payload.brazil.count, "publicação trata", "publicações tratam")
				+ " de golpes no Brasil ou na região.", cites: payload.brazil.items});
	}

	for (let line of lines){
		box.appendChild(el("div", {className: "insight"}, [
			el("span", {className: "dot " + line.tone}),
			el("div", {className: "col grow", style: "gap:3px"}, [
				el("span", {className: "insight-title", text: line.title}),
				el("span", {className: "insight-body", text: line.body}),
				intel_sources_line(line.cites || [], 4)
			])
		]));
	}
}

/* --- resumo por IA -------------------------------------------------------- */

function render_intel_summary(){
	let payload = intel_payload;
	let box = $("intelSummaryBox");
	show(box, !!payload.summaryEnabled);
	if (!payload.summaryEnabled){ return; }
	let container = $("intelSummary");
	container.replaceChildren();
	let summary = payload.summary;
	let has_items = payload.totals.relevant > 0;
	let button = $("intelSummaryBtn");
	show(button, has_items);
	button.textContent = summary ? "Atualizar resumo" : "Gerar resumo";
	button.disabled = false;
	set_status("intelSummaryStatus", "");

	if (!summary){
		$("intelSummaryCode").textContent = "";
		container.appendChild(el("span", {className: "empty-note", text: has_items
			? "Ainda não há resumo para este período."
			: "Sem publicações no período para resumir."}));
		return;
	}
	$("intelSummaryCode").textContent = (summary.model ? summary.model + " · " : "")
		+ "gerado em " + format_date(summary.generatedAt * 1000) + (summary.stale ? " · desatualizado" : "");
	for (let sentence of summary.sentences){
		let line = el("p", {className: "intel-summary-text"});
		line.appendChild(document.createTextNode(sentence.text + " "));
		sentence.cites.forEach(function(id, index){
			let item = intel_by_id[id];
			if (!item){ return; }
			let ref = intel_link(item, "[" + (index + 1) + "]", "intel-ref");
			ref.title = item.sourceName + " — " + item.title;
			line.appendChild(ref);
		});
		container.appendChild(line);
	}
	if (summary.stale){
		set_status("intelSummaryStatus", "Chegaram publicações depois deste resumo.");
	}
}

function generate_intel_summary(){
	let button = $("intelSummaryBtn");
	button.disabled = true;
	set_status("intelSummaryStatus", "Pedindo o resumo ao modelo…");
	post_json("api/threat-intel/summary", {period: intel_period}).then(function(result){
		button.disabled = false;
		if (!result.ok){
			let message = result.status === 429
				? "Limite de resumos por hora atingido; tente mais tarde."
				: (result.data && result.data.error) || "O resumo não pôde ser gerado.";
			set_status("intelSummaryStatus", message, "bad");
			return;
		}
		intel_payload.summary = result.data.summary;
		render_intel_summary();
	});
}

/* --- temas ---------------------------------------------------------------- */

// O feed é da fonte, mas o link pode apontar para qualquer lugar. Quando sai do
// domínio dela, o endereço aparece ao lado, para ninguém clicar achando que vai
// para o site do fornecedor
function intel_offsite_note(item){
	return item.offsite ? el("span", {className: "pill warn", text: "link fora do site da fonte: " + item.host}) : null;
}

function intel_claim(item){
	return el("li", {className: "intel-claim"}, [
		intel_link(item, item.title, "intel-claim-title"),
		el("span", {className: "intel-meta mono", text: item.sourceName + " · " + intel_day(item.published)}),
		intel_offsite_note(item)
	]);
}

function render_intel_themes(){
	let box = $("intelThemes");
	box.replaceChildren();
	let themes = intel_payload.themes || [];
	if (themes.length === 0){
		box.appendChild(el("span", {className: "empty-note", text: "Nenhum tema do vocabulário apareceu no período."}));
		return;
	}
	for (let theme of themes){
		let pills = [el("span", {className: "pill", text: intel_plural(theme.count, "publicação", "publicações")}),
			el("span", {className: "pill", text: intel_plural(theme.sources, "fonte", "fontes")})];
		if (theme.trending){ pills.push(el("span", {className: "pill warn", text: "em alta"})); }
		let local_tone = theme.local && theme.local.cases > 0 ? " bad" : "";
		let claims = el("ul", {className: "intel-claims"},
			theme.items.map(function(id){ return intel_by_id[id]; }).filter(Boolean).map(intel_claim));
		let filter = el("button", {className: "btn secondary sm", text: "Ver todas", attrs: {type: "button"}});
		filter.onclick = function(){ set_intel_filter({type: "theme", key: theme.key, label: theme.label}); };
		box.appendChild(el("article", {className: "card intel-theme" + (theme.trending ? " trending" : "")}, [
			el("div", {className: "row", style: "gap:8px;flex-wrap:wrap"}, [
				el("span", {className: "intel-theme-title grow", text: theme.label})
			].concat(pills)),
			el("p", {className: "intel-here" + local_tone, text: intel_local_sentence(theme)}),
			claims,
			theme.count > theme.items.length ? el("div", {className: "row"}, [filter]) : null
		]));
	}
}

/* --- coluna lateral: grupos, setores, Brasil ------------------------------ */

function intel_rank_row(label, count, onclick){
	let row = el("button", {className: "intel-rank", attrs: {type: "button"}}, [
		el("span", {className: "grow truncate", text: label}),
		el("span", {className: "mono intel-rank-count", text: String(count)})
	]);
	row.onclick = onclick;
	return row;
}

function render_intel_side(){
	let payload = intel_payload;
	let actors = $("intelActors");
	actors.replaceChildren();
	if ((payload.actors || []).length === 0){
		actors.appendChild(el("span", {className: "empty-note", text: "Nenhum grupo nomeado nas publicações do período."}));
	}
	for (let actor of payload.actors || []){
		actors.appendChild(intel_rank_row(actor.name, actor.count, function(){
			set_intel_filter({type: "actor", key: actor.name, label: actor.name});
		}));
	}

	let sectors = $("intelSectors");
	sectors.replaceChildren();
	if ((payload.sectors || []).length === 0){
		sectors.appendChild(el("span", {className: "empty-note", text: "Nenhum setor citado nas publicações do período."}));
	}
	for (let sector of payload.sectors || []){
		sectors.appendChild(intel_rank_row(sector.label, sector.count, function(){
			set_intel_filter({type: "sector", key: sector.key, label: sector.label});
		}));
	}

	let brazil = $("intelBrazil");
	brazil.replaceChildren();
	if (!payload.brazil || payload.brazil.count === 0){
		brazil.appendChild(el("span", {className: "empty-note", text: "Nenhuma publicação do período trata do Brasil ou da América Latina."}));
		return;
	}
	let list = el("ul", {className: "intel-claims"},
		payload.brazil.items.map(function(id){ return intel_by_id[id]; }).filter(Boolean).map(intel_claim));
	brazil.appendChild(list);
	if (payload.brazil.count > payload.brazil.items.length){
		let more = el("button", {className: "btn secondary sm", text: "Ver todas", attrs: {type: "button"}});
		more.onclick = function(){ set_intel_filter({type: "brazil", key: "brazil", label: "Brasil e América Latina"}); };
		brazil.appendChild(el("div", {className: "row"}, [more]));
	}
}

/* --- lista de publicações ------------------------------------------------- */

function set_intel_filter(filter){
	intel_filter = filter;
	render_intel_items();
	let list = $("intelItems");
	if (list && list.scrollIntoView){ list.scrollIntoView({behavior: "smooth", block: "start"}); }
}

function clear_intel_filter(){
	intel_filter = null;
	render_intel_items();
}

function intel_matches(item){
	if (!intel_filter){ return true; }
	if (intel_filter.type === "theme"){ return item.themes.indexOf(intel_filter.key) !== -1; }
	if (intel_filter.type === "actor"){ return item.actors.indexOf(intel_filter.key) !== -1; }
	if (intel_filter.type === "sector"){ return item.sectors.indexOf(intel_filter.key) !== -1; }
	if (intel_filter.type === "brazil"){ return item.brazil; }
	return true;
}

function render_intel_items(){
	let box = $("intelItems");
	box.replaceChildren();
	let items = (intel_payload && intel_payload.items || []).filter(intel_matches);
	show($("intelFilter"), !!intel_filter);
	if (intel_filter){ $("intelFilterLabel").textContent = "Filtrado por: " + intel_filter.label; }
	$("intelItemsCode").textContent = intel_plural(items.length, "publicação", "publicações");
	if (items.length === 0){
		box.appendChild(el("div", {className: "intel-row"}, [
			el("span", {className: "empty-note", text: "Nenhuma publicação para mostrar."})]));
		return;
	}
	for (let item of items){
		let tags = item.themes.map(function(key){ return el("span", {className: "pill", text: intel_theme_label(key)}); })
			.concat(item.sectors.map(function(key){ return el("span", {className: "pill muted", text: intel_sector_label(key)}); }))
			.concat(item.actors.map(function(name){ return el("span", {className: "pill solid", text: name}); }));
		if (item.brazil){ tags.push(el("span", {className: "pill warn", text: "Brasil"})); }
		box.appendChild(el("article", {className: "intel-row"}, [
			el("div", {className: "row", style: "gap:8px"}, [
				intel_link(item, item.title, "intel-row-title grow"),
				el("span", {className: "intel-meta mono", text: intel_day(item.published)})
			]),
			el("span", {className: "intel-meta", text: item.sourceName}),
			intel_offsite_note(item),
			item.excerpt ? el("p", {className: "intel-excerpt", text: item.excerpt}) : null,
			tags.length ? el("div", {className: "row intel-tags", style: "gap:5px;flex-wrap:wrap"}, tags) : null
		]));
	}
}

/* --- fontes --------------------------------------------------------------- */

function render_intel_sources(){
	let box = $("intelSources");
	box.replaceChildren();
	let admin = intel_is_admin();
	let enabled = 0;
	for (let source of intel_sources.sources){
		if (source.enabled){ enabled++; }
		// Para quem não é admin, só as fontes ligadas: são as que explicam a tela
		if (!admin && !source.enabled){ continue; }
		let state = source.enabled ? (INTEL_STATUS[source.status] || INTEL_STATUS.never) : {tone: "", text: "desligada"};
		let detail = state.text + (source.fetchedAt ? " · " + format_date(source.fetchedAt * 1000) : "")
			+ (source.error ? " · " + source.error : "");
		let row = el("div", {className: "intel-source" + (source.enabled ? "" : " off")}, [
			el("span", {className: "dot " + state.tone}),
			el("div", {className: "col grow", style: "gap:1px;min-width:0"}, [
				el("a", {className: "intel-source-name truncate", text: source.name,
					attrs: {href: source.site, target: "_blank", rel: "noopener noreferrer"}}),
				el("span", {className: "intel-meta", text: INTEL_KIND_LABEL[source.kind] + " · " + detail})
			])
		]);
		if (admin){
			if (source.enabled){
				let refresh = el("button", {className: "icon-btn ghost", title: "Coletar agora", attrs: {type: "button"}},
					[icon('<path d="M13.5 8a5.5 5.5 0 11-1.7-4"></path><path d="M12.4 1.4v2.8h-2.8"></path>', 12)]);
				refresh.disabled = !!source.refreshing;
				refresh.onclick = function(){ refresh_intel_source(source.id, refresh); };
				row.appendChild(refresh);
			}
			let toggle = el("div", {className: "toggle" + (source.enabled ? " on" : ""), title: source.enabled ? "Desligar" : "Ligar",
				attrs: {role: "switch", tabindex: "0", "aria-checked": source.enabled ? "true" : "false",
					"aria-label": "Coletar " + source.name}}, [el("span", {className: "knob"})]);
			toggle.onclick = function(){ save_intel_source(source.id, !source.enabled); };
			row.appendChild(toggle);
		}
		box.appendChild(row);
	}
	$("intelSourcesCode").textContent = enabled + " de " + intel_sources.sources.length + " ligadas";
	show($("intelSourcesFoot"), admin);
	if (admin){
		set_status("intelSourcesStatus", "Coleta a cada " + Math.round(intel_sources.intervalMinutes / 60) + " h.");
	}
}

function intel_after_change(result){
	if (!result.ok){
		set_status("intelSourcesStatus", (result.data && result.data.error) || "Não foi possível gravar.", "bad");
		return;
	}
	intel_sources = result.data;
	render_intel_sources();
	// A primeira coleta roda em segundo plano; a tela relê quando ela deve ter acabado
	setTimeout(reload_intel, 6000);
	set_status("intelSourcesStatus", "Gravado. Coletando em segundo plano…", "ok");
}

function save_intel_source(id, enabled){
	let sources = {};
	sources[id] = enabled;
	post_json("api/threat-intel/sources", {sources: sources}).then(intel_after_change);
}

function enable_intel_recommended(){
	post_json("api/threat-intel/recommended", {}).then(intel_after_change);
}

function refresh_intel_source(id, button){
	button.disabled = true;
	post_json("api/threat-intel/sources/" + encodeURIComponent(id) + "/refresh", {}).then(function(result){
		if (!result.ok){
			button.disabled = false;
			set_status("intelSourcesStatus", (result.data && result.data.error) || "Não foi possível coletar.", "bad");
			return;
		}
		set_status("intelSourcesStatus", "Coletando em segundo plano…", "ok");
		setTimeout(reload_intel, 5000);
	});
}

/* --- card da Visão Executiva ---------------------------------------------- */

function load_exec_intel(){
	let period = ["7d", "30d", "90d"].indexOf(insights_range) !== -1 ? insights_range : "30d";
	get_json("api/threat-intel?period=" + encodeURIComponent(period)).then(render_exec_intel);
}

function render_exec_intel(payload){
	let body = $("execIntelBody");
	if (!body){ return; }
	body.replaceChildren();
	if (payload == null || payload.error){
		$("execIntelFoot").textContent = "";
		body.appendChild(el("span", {className: "empty-note", text: (payload && payload.error) || "O panorama externo não respondeu."}));
		return;
	}
	$("execIntelCode").textContent = payload.period.label;
	if (payload.totals.enabledSources === 0){
		$("execIntelFoot").textContent = "";
		body.appendChild(el("span", {className: "empty-note", text: "Nenhuma fonte de inteligência ligada. Abra o panorama para ver as fontes disponíveis."}));
		return;
	}
	$("execIntelFoot").textContent = intel_plural(payload.totals.relevant, "publicação", "publicações") + " de "
		+ intel_plural(payload.totals.sources, "fonte", "fontes") + (payload.partial ? " · coleta incompleta no período" : "");
	if (payload.themes.length === 0){
		body.appendChild(el("span", {className: "empty-note", text: "Nenhum tema de phishing nas publicações coletadas no período."}));
		return;
	}
	// Primeiro o que o mundo relata e já chegou à caixa; depois o mais citado
	let ranked = payload.themes.slice().sort(function(a, b){
		let a_here = a.local && a.local.cases > 0 ? 1 : 0;
		let b_here = b.local && b.local.cases > 0 ? 1 : 0;
		return (b_here - a_here) || (b.count - a.count);
	});
	for (let theme of ranked.slice(0, 3)){
		body.appendChild(el("div", {className: "intel-teaser-item" + (theme.trending ? " trending" : "")}, [
			el("div", {className: "row", style: "gap:6px"}, [
				el("span", {className: "intel-teaser-label grow", text: theme.label}),
				theme.trending ? el("span", {className: "pill warn", text: "em alta"}) : null
			]),
			el("span", {className: "intel-teaser-count mono", text: intel_plural(theme.count, "publicação", "publicações")
				+ " · " + intel_plural(theme.sources, "fonte", "fontes")}),
			el("span", {className: "intel-here" + (theme.local && theme.local.cases > 0 ? " bad" : ""),
				text: intel_local_sentence(theme)})
		]));
	}
}

/* --- Configurações › IA: o resumo ----------------------------------------- */

function load_intel_summary_config(){
	get_json("api/threat-intel/summary-config").then(function(config){
		if (config == null || config.error){ return; }
		set_switch("intelSummaryEnabled", config.enabled);
		$("intelSummaryModel").value = config.model || "";
		$("intelSummaryMode").value = config.mode || "manual";
		$("intelSummaryLength").value = config.length || "short";
	});
}

function save_intel_summary_config(){
	let button = $("intelSummarySaveBtn");
	button.disabled = true;
	post_json("api/threat-intel/summary-config", {
		enabled: switch_on("intelSummaryEnabled"),
		model: $("intelSummaryModel").value.trim(),
		mode: $("intelSummaryMode").value,
		length: $("intelSummaryLength").value
	}).then(function(result){
		button.disabled = false;
		if (!result.ok){
			set_status("intelSummaryConfigStatus", (result.data && result.data.error) || "Não foi possível gravar.", "bad");
			return;
		}
		set_status("intelSummaryConfigStatus", "Gravado.", "ok");
		intel_payload = null;
	});
}
