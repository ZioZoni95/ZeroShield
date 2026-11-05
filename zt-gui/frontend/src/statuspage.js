// Homepage «Stato»: una frase, una sola azione consigliata e il resto in poche tessere.
//
// Per chi non conosce il progetto contano tre cose: sono protetto?, cosa devo fare adesso?, cosa e'
// successo? I numeri tecnici (hook LSM, XDP, binari autorizzati) restano disponibili ma ripiegati.
import {friendlyRule} from './names.js';

const base = p => String(p || '').replace(/ \(deleted\)$/, '').split('/').pop();

// Programmi visti in audit che NON sono nella lista della regola. E' una stima fatta con quello che il
// demone espone (nome del programma): la scheda Regole fa il controllo vero, programma per programma.
export function unauthorizedSeen(status, events) {
    const rules = {};
    (status.rules || []).forEach(r => { rules[r.name] = r; });
    const seen = new Map();
    (events || []).forEach(e => {
        if (e.canary || !e.exe || !e.rule || e.action === 'blocked') return;
        const r = rules[e.rule];
        if (!r) return;
        const ok = (r.allow || []).some(a => a === e.exe || base(a) === base(e.exe));
        if (!ok) seen.set(e.rule + '\x00' + base(e.exe), {rule: e.rule, exe: base(e.exe)});
    });
    return [...seen.values()];
}

export function modeSummary(status) {
    const rules = status.rules || [];
    let enf = 0, aud = 0;
    rules.forEach(r => { ((r.mode || status.mode) === 'enforce') ? enf++ : aud++; });
    return {enf, aud, total: rules.length, all: enf > 0 && aud === 0, none: enf === 0};
}

// Cosa dire e cosa proporre di fare, in ordine di gravita'.
export function hero(status, events) {
    const ms = modeSummary(status);
    const un = unauthorizedSeen(status, events);
    if (!status.hook_lsm) {
        return {level: 'bad', title: 'I tuoi file non sono protetti', text: 'Il blocco dei file segreti non è attivo su questo computer: ZeroShield non può difenderli.',
            action: {label: 'Cosa fare', go: 'guide'}};
    }
    if (!(status.xdp && status.xdp.length)) {
        return {level: 'bad', title: 'La rete non è filtrata', text: 'Nessuna interfaccia di rete è coperta: il poisoning di rete non viene scartato.', action: {label: 'Guarda la rete', go: 'net'}};
    }
    if (ms.all) {
        return {level: 'ok', title: 'Sei protetto', text: 'Ogni protezione sta bloccando i programmi non autorizzati. Se uno dei tuoi programmi smette di funzionare, autorizzalo dalle Regole.',
            action: {label: 'Vedi le regole', go: 'rules', secondary: true}};
    }
    if (ms.enf > 0) {
        return {level: 'warn', title: 'Protetto in parte', text: `${ms.enf} protezion${ms.enf === 1 ? 'e blocca' : 'i bloccano'}, ${ms.aud} ${ms.aud === 1 ? 'osserva' : 'osservano'} soltanto. Metti in Blocca anche le altre quando sei pronto.`,
            action: {label: 'Apri le Regole', go: 'rules'}};
    }
    if (un.length) {
        return {level: 'warn', title: 'Stai osservando, non bloccando', text: `${un.length} programm${un.length === 1 ? 'a ha letto' : 'i hanno letto'} i tuoi segreti senza essere nella lista. Autorizza quelli tuoi, poi potrai passare a Blocca.`,
            action: {label: `Rivedi ${un.length} programm${un.length === 1 ? 'a' : 'i'}`, go: 'rules'}};
    }
    if ((events || []).some(e => !e.canary && e.rule)) {
        return {level: 'warn', title: 'Stai osservando, non bloccando', text: 'Tutto ciò che hai usato finora è autorizzato. Se lo usi da qualche giorno, puoi passare a Blocca.',
            action: {label: 'Passa a Blocca', act: 'enforce'}, link: {label: 'Prima rivedi le Regole', go: 'rules'}};
    }
    return {level: 'warn', title: 'Stai osservando, non bloccando', text: 'ZeroShield registra chi legge i tuoi segreti ma non blocca niente. Usa il computer come al solito: i programmi compariranno nelle Regole.',
        action: {label: 'Apri le Regole', go: 'rules'}};
}

// Lista «Da fare»: ogni voce ha un esito e, se manca, dove andare.
export function todo(status, events, svcOk = true) {
    const ms = modeSummary(status), un = unauthorizedSeen(status, events), v = status.vpn || {};
    const items = [
        {ok: svcOk, t: 'Servizio attivo', d: 'Il demone sta girando.'},
        {ok: !!status.hook_lsm, t: 'Blocco dei file attivo', d: status.hook_lsm ? 'Gli hook del kernel sono agganciati.' : 'Gli hook del kernel non sono agganciati.', go: 'guide'},
        {ok: (status.xdp || []).length > 0, t: 'Rete filtrata', d: (status.xdp || []).length ? `Su ${status.xdp.join(', ')}.` : 'Nessuna interfaccia coperta.', go: 'net'},
        {ok: un.length === 0, t: 'Programmi controllati', d: un.length ? `${un.length} da rivedere nelle Regole.` : 'Nessun programma sconosciuto ha letto i segreti.', go: 'rules'},
        {ok: ms.all, t: 'Protezioni in Blocca', d: ms.all ? 'Tutte.' : (ms.enf ? `${ms.enf} su ${ms.total}.` : 'Ancora in sola osservazione.'), go: 'rules'},
    ];
    if (!v.enabled) items.push({ok: null, t: 'VPN', d: 'Non monitorata (facoltativa).', go: 'net'});
    return items;
}

const sentence = (e, esc, fmtTime) => {
    const what = e.canary ? `esca canary toccata (${e.kind || e.action})` : `${esc(base(e.exe || e.comm || '?'))} ha letto «${esc(friendlyRule(e.rule))}»`;
    const how = e.canary ? '' : (e.action === 'blocked' ? ' · <b class="ev-bl">bloccato</b>' : ' · solo osservato');
    return `<li><span class="rl-d mono">${esc(fmtTime(e.time))}</span> ${e.canary ? '🐤 ' : ''}${what}${how}</li>`;
};

export function statusHtml({status, events, esc, fmtTime, icons, appVersion, daemonMismatch, svcOk}) {
    const h = hero(status, events), ms = modeSummary(status);
    let nB = 0, nA = 0, nC = 0;
    (events || []).forEach(e => { if (e.canary) nC++; else if (e.action === 'blocked') nB++; else nA++; });
    const drops = (status.top_sources || []).reduce((a, s) => a + (s.total || 0), 0);
    const items = todo(status, events, svcOk), doneN = items.filter(i => i.ok === true).length, countN = items.filter(i => i.ok !== null).length;
    const recent = (events || []).slice(-5).reverse();
    const heroBtn = h.action ? (h.action.act === 'enforce'
        ? `<button class="hero-btn" id="hero-act">${esc(h.action.label)}</button>`
        : `<button class="hero-btn${h.action.secondary ? ' ghost' : ''}" data-go="${h.action.go}">${esc(h.action.label)}</button>`) : '';
    const heroLink = h.link ? `<button class="linklike" data-go="${h.link.go}">${esc(h.link.label)} →</button>` : '';
    const mism = daemonMismatch ? `<div class="warn">${icons.warn}<div>${esc(daemonMismatch)}</div></div>` : '';
    return `<h2>${icons.gauge}Stato</h2>
    <p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}${appVersion ? ` · ZeroShield ${esc(appVersion)}` : ''}</p>
    ${mism}
    <div class="hero ${h.level}" role="status"><div class="hero-t">${esc(h.title)}</div><div class="hero-d">${esc(h.text)}</div>
      <div class="hero-a">${heroBtn}${heroLink}</div></div>
    <div class="tiles">
      <div class="tile"><div class="tile-k">Segreti</div>
        <div class="tile-v"><span data-count="${status.protected}">0</span> file protetti</div>
        <div class="tile-d">${ms.total} protezion${ms.total === 1 ? 'e' : 'i'} · ${ms.enf} in Blocca · ${ms.aud} in sola osservazione. ${status.allowed} programmi autorizzati.</div>
        <button class="linklike" data-go="rules">Gestisci le regole →</button></div>
      <div class="tile"><div class="tile-k">Rete</div>
        <div class="tile-v"><span data-count="${drops}">0</span> pacchetti scartati</div>
        <div class="tile-d">${(status.xdp || []).length ? `Filtro su ${esc(status.xdp.join(', '))}.` : 'Nessuna interfaccia filtrata.'} Sono richieste di rete sospette (LLMNR, mDNS, NetBIOS), spesso rumore normale.</div>
        <button class="linklike" data-go="radar">Apri il radar →</button></div>
      <div class="tile"><div class="tile-k">Attività</div>
        <div class="tile-v"><span data-count="${nA + nB}">0</span> letture di segreti</div>
        <div class="tile-d">Da quando hai aperto la finestra: ${nB} bloccate, ${nA} solo osservate${nC ? `, ${nC} allarmi canary` : ''}.</div>
        <button class="linklike" data-go="events">Vedi gli eventi →</button></div>
    </div>
    <h3 class="sec">Da fare <span class="rl-d">· ${doneN} su ${countN}</span></h3>
    <ul class="todo">${items.map(i => `<li class="${i.ok === true ? 'ok' : i.ok === false ? 'no' : 'na'}"><span class="todo-i" aria-hidden="true">${i.ok === true ? '✓' : i.ok === false ? '!' : '–'}</span>
      <span><b>${esc(i.t)}</b> <span class="rl-d">${esc(i.d)}</span>${i.ok === false && i.go ? ` <button class="linklike" data-go="${i.go}">vai →</button>` : ''}</span></li>`).join('')}</ul>
    <h3 class="sec">Ultimi eventi</h3>
    ${recent.length ? `<ul class="recent">${recent.map(e => sentence(e, esc, fmtTime)).join('')}</ul><button class="linklike" data-go="events">Tutti gli eventi →</button>`
        : '<div class="rl-empty">Nessun evento da quando hai aperto la finestra.</div>'}
    <details class="rl-det tech"><summary>Dettagli tecnici</summary>
      <div class="cards">
        <div class="card"><div class="k">Modalità generale</div><div class="v" style="font-size:17px">${esc(status.mode)}</div></div>
        <div class="card"><div class="k">Hook LSM</div><div class="v" style="font-size:17px">${status.hook_lsm ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento'}</div></div>
        <div class="card"><div class="k">XDP su</div><div class="v small">${esc((status.xdp || []).join(', ') || '(spento)')}</div></div>
        <div class="card"><div class="k">File protetti</div><div class="v">${status.protected}</div></div>
        <div class="card"><div class="k">Binari autorizzati</div><div class="v">${status.allowed}</div></div>
        ${status.version ? `<div class="card"><div class="k">Versione del demone</div><div class="v small">${esc(status.version)}</div></div>` : ''}
      </div></details>
    <h3 class="sec">Controlli</h3>
    <div class="panel">
      <div class="kv"><div class="kv-k">Servizio</div><div class="kv-v"><b id="svc-state">…</b> <button class="chip danger" id="svc-stop">■ Ferma</button></div><div class="kv-h">Fermandolo nulla più viene difeso finché non lo riattivi.</div></div>
      <div class="kv"><div class="kv-k">Modalità generale nel file</div><div class="kv-v"><b id="cfg-mode">…</b> <button class="chip" id="mode-toggle">…</button></div><div class="kv-h" id="cfg-hint">Vale per le protezioni senza una modalità propria; si sceglie per singola protezione nelle Regole.</div></div>
    </div>`;
}
