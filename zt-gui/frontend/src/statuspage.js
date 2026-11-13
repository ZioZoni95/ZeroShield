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
    // Impostazioni del kernel che cambiano l'efficacia dello scudo (ptrace, io_uring): non dipendono da
    // ZeroShield, ma se restano aperte aggirano i controlli. `fix` e' il comando da eseguire con sudo.
    (status.posture || []).forEach(p => items.push({ok: !!p.ok, t: p.title, d: p.detail, fix: p.fix || ''}));
    if (!v.enabled) items.push({ok: null, t: 'VPN', d: 'Non monitorata (facoltativa).', go: 'net'});
    return items;
}

// Una riga di «Ultimi eventi»: pallino colorato, frase, orario a destra.
const sentence = (e, esc, fmtTime) => {
    const what = e.canary ? `esca canary toccata (${esc(e.kind || e.action)})` : `<b>${esc(base(e.exe || e.comm || '?'))}</b> ha letto «${esc(friendlyRule(e.rule))}»`;
    const how = e.canary ? '' : (e.action === 'blocked' ? ' · <b class="ev-bl">bloccato</b>' : ' <span class="rl-d">· solo osservato</span>');
    const kind = e.canary ? 'canary' : (e.action === 'blocked' ? 'block' : 'audit');
    return `<li><span class="ev-dot ${kind}" aria-hidden="true"></span><span class="ev-what">${e.canary ? '🐤 ' : ''}${what}${how}</span><span class="rl-d mono ev-time">${esc(fmtTime(e.time))}</span></li>`;
};

// Simbolo grande della scheda in alto: scudo con spunta (a posto), con punto esclamativo (attenzione), barrato (spento).
const HERO_ICO = {
    ok: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="currentColor"/><path d="M8.5 12l2.4 2.4L15.5 9.5" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="currentColor"/><path d="M12 7.5v5" stroke="#fff" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="15.8" r="1.2" fill="#fff"/></svg>',
    bad: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="currentColor"/><path d="M9 9l6 6M15 9l-6 6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>',
};

export function statusHtml({status, events, esc, fmtTime, icons, appVersion, daemonMismatch, svcOk}) {
    const h = hero(status, events), ms = modeSummary(status);
    let nB = 0, nA = 0, nC = 0;
    (events || []).forEach(e => { if (e.canary) nC++; else if (e.action === 'blocked') nB++; else nA++; });
    const drops = (status.top_sources || []).reduce((a, s) => a + (s.total || 0), 0);
    const items = todo(status, events, svcOk), doneN = items.filter(i => i.ok === true).length, countN = items.filter(i => i.ok !== null).length;
    // Prima cio' che chiede un'azione, poi il resto: chi apre la pagina vede subito cosa manca.
    const ordered = [...items.filter(i => i.ok === false), ...items.filter(i => i.ok !== false)];
    const recent = (events || []).slice(-5).reverse();
    const heroBtn = h.action ? (h.action.act === 'enforce'
        ? `<button class="hero-btn" id="hero-act">${esc(h.action.label)}</button>`
        : `<button class="hero-btn${h.action.secondary ? ' ghost' : ''}" data-go="${h.action.go}">${esc(h.action.label)}</button>`) : '';
    const heroLink = h.link ? `<button class="linklike" data-go="${h.link.go}">${esc(h.link.label)} →</button>` : '';
    const mism = daemonMismatch ? `<div class="warn">${icons.warn}<div>${esc(daemonMismatch)}</div></div>` : '';
    const pct = countN ? Math.round(doneN / countN * 100) : 0;
    const tile = (k, n, unit, d, go, link) => `<div class="tile"><div class="tile-k">${k}</div>
        <div class="tile-v"><span class="tile-n" data-count="${n}">0</span> <span class="tile-u">${unit}</span></div>
        <div class="tile-d">${d}</div>
        <button class="linklike" data-go="${go}">${link} →</button></div>`;
    const row = (k, v) => `<div class="kv"><div class="kv-k">${k}</div><div class="kv-v">${v}</div></div>`;
    return `<h2>${icons.gauge}Stato</h2>
    <p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}${appVersion ? ` · ZeroShield ${esc(appVersion)}` : ''}</p>
    ${mism}
    <div class="hero ${h.level}" role="status"><div class="hero-ico">${HERO_ICO[h.level] || HERO_ICO.warn}</div>
      <div class="hero-m"><div class="hero-t">${esc(h.title)}</div><div class="hero-d">${esc(h.text)}</div></div>
      <div class="hero-a">${heroBtn}${heroLink}</div></div>
    <div class="tiles">
      ${tile('Segreti', status.protected, 'file protetti', `${ms.enf} protezion${ms.enf === 1 ? 'e' : 'i'} in Blocca, ${ms.aud} in sola osservazione · ${status.allowed} programmi autorizzati`, 'rules', 'Gestisci le regole')}
      ${tile('Rete', drops, 'pacchetti scartati', `${(status.xdp || []).length ? `Filtro su ${esc(status.xdp.join(', '))}` : 'Nessuna interfaccia filtrata'} · richieste sospette (LLMNR, mDNS, NetBIOS), spesso rumore normale`, 'radar', 'Apri il radar')}
      ${tile('Attività', nA + nB, 'letture di segreti', `Da quando hai aperto la finestra: ${nB} bloccate, ${nA} solo osservate${nC ? `, ${nC} allarmi canary` : ''}`, 'events', 'Vedi gli eventi')}
    </div>
    <h3 class="sec sec-row"><span>Da fare <span class="rl-d">· ${doneN} su ${countN}</span></span><span class="prog" role="progressbar" aria-valuemin="0" aria-valuemax="${countN}" aria-valuenow="${doneN}"><i style="width:${pct}%"></i></span></h3>
    <ul class="todo">${ordered.map(i => `<li class="${i.ok === true ? 'ok' : i.ok === false ? 'no' : 'na'}"><span class="todo-i" aria-hidden="true">${i.ok === true ? '✓' : i.ok === false ? '!' : '–'}</span>
      <span class="todo-b"><b>${esc(i.t)}</b> <span class="rl-d">${esc(i.d)}</span>${i.ok === false && i.fix ? `<span class="todo-how"><span class="rl-d">Per chiuderlo, in un terminale:</span><span class="code-row"><code class="mono todo-fix">${esc(i.fix)}</code><button class="copy" data-copy="${esc(i.fix)}" title="Copia negli appunti">copia</button></span></span>` : ''}</span>${i.ok === false && i.go ? `<button class="linklike todo-go" data-go="${i.go}">vai →</button>` : ''}</li>`).join('')}</ul>
    <h3 class="sec sec-row"><span>Ultimi eventi</span>${recent.length ? '<button class="linklike" data-go="events">Tutti gli eventi →</button>' : ''}</h3>
    ${recent.length ? `<ul class="recent">${recent.map(e => sentence(e, esc, fmtTime)).join('')}</ul>`
        : '<div class="rl-empty">Nessun evento da quando hai aperto la finestra.</div>'}
    <h3 class="sec">Controlli</h3>
    <div class="panel">
      <div class="kv"><div class="kv-k">Servizio</div><div class="kv-v"><b id="svc-state">…</b> <button class="chip danger" id="svc-stop">Ferma</button></div><div class="kv-h">Fermandolo nulla più viene difeso finché non lo riattivi.</div></div>
      <div class="kv"><div class="kv-k">Modalità generale nel file</div><div class="kv-v"><b id="cfg-mode">…</b> <button class="chip" id="mode-toggle">…</button></div><div class="kv-h" id="cfg-hint">Vale per le protezioni senza una modalità propria; si sceglie per singola protezione nelle Regole.</div></div>
    </div>
    <details class="rl-det tech"><summary>Dettagli tecnici</summary>
      <div class="panel">
        ${row('Modalità generale', esc(status.mode))}
        ${row('Hook LSM', status.hook_lsm ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento')}
        ${row('XDP su', `<span class="mono">${esc((status.xdp || []).join(', ') || '(spento)')}</span>`)}
        ${row('File protetti', status.protected)}
        ${row('Binari autorizzati', status.allowed)}
        ${status.version ? row('Versione del demone', `<span class="mono">${esc(status.version)}</span>`) : ''}
      </div></details>`;
}
