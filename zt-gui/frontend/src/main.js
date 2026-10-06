// ZeroShield GUI — client IPC: primo paint via GetStatus, poi push live.
// Solo lettura: nessun'azione privilegiata da qui (cambio mode via config+restart).
import {GetStatus, SocketPath, Version, ServiceState, ServiceInstall, ServiceStart, ServiceStop, ConfigMode, SetConfigMode, ConfigText, Preflight} from '../wailsjs/go/main/App.js';
import {EventsOn} from '../wailsjs/runtime/runtime.js';

const content = document.getElementById('content');
const badge = document.getElementById('mode-badge');
const modeText = document.getElementById('mode-text');
const viewTitle = document.getElementById('view-title');
const conn = document.getElementById('conn');
const evCount = document.getElementById('ev-count');
const buttons = [...document.querySelectorAll('#sidebar button')];
const TITLES = {status: 'Stato', events: 'Eventi', rules: 'Regole', net: 'Rete', radar: 'Radar', guide: 'Guida', config: 'Configurazione'};

let view = 'status';
let status = null;
let events = [];
let offlineMsg = '';
let evSearch = '';
let evType = 'all'; // all | blocked | audit | canary
let evSevFirst = false; // pericolosi prima (pattern SOC anti alert-fatigue)
let appVersion = ''; // dal binario (ldflags), non scritta a mano

// Drill-down: da Regole o Stato verso Eventi già filtrati.
function gotoEvents(q) {
    evSearch = q || '';
    evType = 'all';
    view = 'events';
    buttons.forEach(x => x.classList.toggle('active', x.dataset.view === 'events'));
    render();
}
let prevMode = '';

buttons.forEach(b => b.onclick = () => {
    view = b.dataset.view;
    buttons.forEach(x => x.classList.toggle('active', x === b));
    render();
});

function esc(s) {
    return String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
}

const ICO_BLOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICO_AUDIT = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="2.4" fill="currentColor"/></svg>';
const ICO_WARN = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3L22 20H2L12 3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="currentColor"/></svg>';
const ICO_KEY = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
const ICO_BAN = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICO_BIRD = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 14c4-1 5-4 5-8 3 0 5 2 5 4l4-2-1 4c1 3-1 7-5 8l-3 1-2-3c-1 0-2 0-3-1z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><circle cx="11" cy="8" r="1" fill="currentColor"/></svg>';

function h2(icon, text) { return `<h2>${icon}${esc(text)}</h2>`; }

function paintBadge() {
    if (!status) { badge.className = 'badge off'; modeText.textContent = 'non connesso'; return; }
    if (status.mode === 'enforce') { badge.className = 'badge enforce'; modeText.textContent = 'ENFORCE · blocca'; }
    else { badge.className = 'badge audit'; modeText.textContent = 'AUDIT · logga'; }
    // Toast su cambio mode (non al primo paint): transizione pericolosa merita avviso.
    if (prevMode && prevMode !== status.mode) {
        toast(`Modalità: ${prevMode} → ${status.mode}`, status.mode === 'enforce');
    }
    prevMode = status.mode;
}

// Contatore animato verso target in ~400ms (solo numeri interi).
//
// Il valore mostrato si ricorda FUORI dal DOM, per etichetta della scheda: ogni render
// ricostruisce la pagina, e il vecchio valore tenuto sull'elemento andava perso. Risultato:
// con eventi in arrivo piu' spesso di 400 ms i contatori ripartivano sempre da 0 e
// restavano praticamente a zero (trovato lanciando l'app vera). Ora l'elemento nasce gia'
// col numero precedente e l'animazione parte da li', senza mai passare da "0".
const shownCounts = {};
function countUp(el, target) {
    const label = el.closest('.card')?.querySelector('.k')?.textContent || '';
    const from = Number.isFinite(shownCounts[label]) ? shownCounts[label] : 0;
    shownCounts[label] = target;
    el.textContent = from;
    if (from === target) return;
    const t0 = performance.now();
    (function step(t) {
        const k = Math.min(1, (t - t0) / 400);
        el.textContent = Math.round(from + (target - from) * k);
        if (k < 1) requestAnimationFrame(step);
    })(t0);
}

// Ogni evento e ogni stato (anche 50 eventi/s in un flood) chiedevano un render
// completo: tabella da 200 righe ricostruita decine di volte al secondo. Qui le
// richieste si raggruppano in una sola per frame; a finestra nascosta il browser
// sospende i frame e il render arriva una volta sola al ritorno. I click dell'utente
// chiamano render() direttamente: risposta immediata.
let renderQueued = false;
function requestRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => { renderQueued = false; render(); });
}

let lastKey = '';
// force=true per gesti utente (click, tab, search): saltano la guardia.
// I poll automatici chiamano render() liscio e vengono dedupati.
function render(force) {
    // Guardia anti-sfarfallio: senza demone i poll falliti arrivano ogni 2s.
    // Rirendere tutto a ogni errore fa lampeggiare la pagina: se vista e
    // situazione non cambiano, si salta (gli stream live passano comunque).
    const key = view + '|' + (status ? status.time || 'live' : 'off:' + offlineMsg);
    if (!force && key === lastKey && view !== 'events' && view !== 'radar') return;
    lastKey = key;
    paintBadge();
    cancelAnimationFrame(radarRAF);
    const oldTip = document.getElementById('radar-tip');
    if (oldTip) oldTip.style.display = 'none';
    viewTitle.textContent = TITLES[view] || view;
    if (!status) return renderFirstRun();
    conn.textContent = 'aggiornato ' + (status.time || '…');
    evCount.textContent = events.length > 0 ? events.length : '';
    if (view === 'status') return renderStatus();
    if (view === 'events') return renderEvents();
    if (view === 'rules') return renderRules();
    if (view === 'radar') return renderRadar();
    if (view === 'guide') return renderGuide();
    if (view === 'config') return renderConfig();
    return renderNet();

// Configurazione: file reale su disco (persiste a ogni boot) + toggle mode.
// Regole e segreti si cambiano nel file con editor: la UI non riscrive YAML
// alla cieca, solo mode: con confirm + restart.
async function renderConfig() {
    let txt = '';
    try { txt = await ConfigText(); } catch (e) { txt = 'errore lettura: ' + (e.message || e); }
    let mode = '';
    try { mode = await ConfigMode(); } catch (_) {}
    content.innerHTML = `${h2(ICO_KEY, 'Configurazione')}<p class="sub">File su disco: <span class="mono">/etc/zt-shield/shield.yaml</span> — letto a ogni avvio, persiste ai reboot.</p>
    <div class="rule ok"><h3>Modalità: ${esc(mode || '?')}</h3>
    <div><button class="chip${mode === 'audit' ? ' on' : ''}" id="m-audit">audit (logga)</button>
    <button class="chip${mode === 'enforce' ? ' on' : ''}" id="m-enforce">enforce (blocca)</button></div>
    <p class="sub">Enforce solo a log puliti, poi restart automatico.</p></div>
    <h2 style="margin-top:16px">File</h2><pre>${esc(txt)}</pre>`;
    const set = async (m) => {
        if (m === 'enforce' && !confirm('Passare a ENFORCE? Blocca davvero: solo a log puliti.')) return;
        try { await SetConfigMode(m); toast('Modalità: ' + m, m === 'enforce'); } catch (e) { toast('Fallito: ' + (e.message || e), true); }
        render();
    };
    const ba = document.getElementById('m-audit');
    if (ba) ba.onclick = () => set('audit');
    const be = document.getElementById('m-enforce');
    if (be) be.onclick = () => set('enforce');
}
}

// Prima apertura vera: non "offline", ma setup. Mai-configurato (servizio
// missing) = percorso guidato; demone spento ma installato = riattiva.
// Distinguerli è tutta la differenza tra prodotto e demo.
let svcCached = '';
async function renderFirstRun() {
    conn.textContent = 'prima configurazione';
    let st = '';
    try { st = await ServiceState(); } catch (_) {}
    svcCached = st || '';
    if (st && st !== 'missing' && st !== 'unknown') {
        // Installato ma spento: non setup, solo riattiva.
        return renderOffline();
    }
    content.innerHTML = `<div class="offline">
    <div class="off-icon">🛡️</div>
    <h2>Benvenuto in ZeroShield</h2>
    <p class="sub">Tre passi e sei protetto. Audit prima (logga senza bloccare), enforce quando i log sono puliti.</p>
    <div id="preflight"><span class="sub">Verifica prerequisiti…</span></div>
    <div class="hero">
      <div><b>1 · Installa e attiva</b><br><span class="sub">Config + servizio in audit. Password chiesta dal sistema.</span></div>
      <div><button class="chip on big" id="svc-install">⬇ Installa</button></div>
    </div>
    <div class="cards">
      <div class="card"><div class="k">2 · Osserva</div><div class="sub">Tab Eventi: cosa toccherebbe bloccare.</div></div>
      <div class="card"><div class="k">3 · Stringi</div><div class="sub">Passa a enforce solo a log puliti.</div></div>
    </div>
    <details><summary>Demo finta senza installare</summary>
    <div class="card" style="margin-top:10px"><div><code>ZT_SOCKET=/tmp/z.sock zt-mockd &amp;</code></div><div class="sub">riapri la GUI con stesso socket</div></div></details>
    </div>`;
    const wire = (id, fn) => {
        const b = document.getElementById(id);
        if (b) b.onclick = fn;
    };
    wire('svc-install', async () => {
        const b = document.getElementById('svc-install');
        b.textContent = '…';
        try { await ServiceInstall(); toast('Installato e attivo in audit', false); }
        catch (e) { toast('Install fallita: ' + (e.message || e), true); }
        render();
    });
    Preflight().then(list => {
        const el = document.getElementById('preflight');
        if (!el) return;
        el.innerHTML = '<div class="checks">' + (list || []).map(c =>
            `<div class="check${c.ok ? ' ok' : ' ko'}"><span>${c.ok ? '●' : '○'}</span><span>${esc(c.name)}${c.hint ? ` <i>(${esc(c.hint)})</i>` : ''}</span></div>`
        ).join('') + '</div>';
    }).catch(() => {});
}

function renderOffline() {
    conn.textContent = 'demone non raggiungibile';
    // Offline contestuale: ogni tab spiega cosa manca, non lo stesso muro ovunque.
    const what = {
        status: ['a chi protegge cosa', 'Modalità, hook, file protetti e XDP vivono nel demone.'],
        events: ['chi ha toccato cosa', 'Lo stream eventi arriva dal ring buffer via socket.'],
        rules: ['quali segreti e chi li legge', 'Le regole stanno nel config letto dal demone.'],
        net: ['dove filtra la rete', 'Interfacce XDP e subnet bloccate le sa solo il demone.'],
        radar: ['chi ti scansiona', 'I drop per IP li conta il kernel via XDP.'],
        guide: ['come partire', 'La guida resta qui sotto, leggibile anche offline.'],
    }[view] || ['dati live', 'Servono dal demone.'];
    const guide = view === 'guide' ? renderGuideBody() : '';
    // Il socket e' leggibile solo da root e dall'utente protetto (campo user: del config):
    // da un altro utente l'errore e' "permission denied", non "demone spento".
    const perm = /permission denied/i.test(offlineMsg)
        ? '<p class="warn">Il demone risponde ma il socket è riservato a root e all\'utente protetto (<code>user:</code> nel config). Apri la GUI con quell\'utente.</p>' : '';
    content.innerHTML = `<div class="offline">
    <div class="off-icon">🔌</div>
    <h2>Senza demone, niente ${what[0]}</h2>
    <p class="sub">${what[1]}<br>${esc(offlineMsg)}</p>${perm}
    <div class="hero">
      <div><b>Vuoi attivare la protezione ora?</b><br><span class="sub">Installa + avvia in audit (logga, non blocca). Password chiesta dal sistema, mai qui.</span></div>
      <div><button class="chip on big" id="svc-install">⬇ Installa e attiva</button></div>
    </div>
    <div id="preflight"><span class="sub">Verifica prerequisiti…</span></div>
    <details><summary>Altri modi (terminale, demo finta)</summary>
    <div class="cards" style="margin-top:10px">
      <div class="card"><div class="k">Solo avvia (già installato)</div><div><button class="chip on" id="svc-start">▶ Attiva protezione</button></div><div class="sub">enable --now via pkexec</div></div>
      <div class="card"><div class="k">A mano (VM)</div><div><code>sudo systemctl enable --now zt-shield</code></div><div class="sub">prima <code>user:</code> in shield.yaml · audit</div></div>
      <div class="card"><div class="k">Demo finta</div><div><code>ZT_SOCKET=/tmp/z.sock zt-mockd &amp;</code></div><div class="sub">riapri la GUI con stesso socket</div></div>
    </div></details>${guide}</div>`;
    const wire = (id, fn) => {
        const b = document.getElementById(id);
        if (b) b.onclick = fn;
    };
    wire('svc-install', async () => {
        const b = document.getElementById('svc-install');
        b.textContent = '…';
        try { await ServiceInstall(); toast('Installato e attivo in audit', false); }
        catch (e) { toast('Install fallita: ' + (e.message || e), true); }
        render();
    });
    Preflight().then(list => {
        const el = document.getElementById('preflight');
        if (!el) return;
        el.innerHTML = '<div class="checks">' + (list || []).map(c =>
            `<div class="check${c.ok ? ' ok' : ' ko'}"><span>${c.ok ? '●' : '○'}</span><span>${esc(c.name)}${c.hint ? ` <i>(${esc(c.hint)})</i>` : ''}</span></div>`
        ).join('') + '</div>';
    }).catch(() => {});
    wire('svc-start', async () => {
        const b = document.getElementById('svc-start');
        b.textContent = '…';
        try { await ServiceStart(); toast('Protezione attivata', false); }
        catch (e) { toast('Avvio fallito: ' + (e.message || e), true); }
        render();
    });
}

function renderStatus() {
    const xdp = (status.xdp && status.xdp.length) ? status.xdp.join(', ') : '(spento)';
    const lsm = status.hook_lsm
        ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento';
    // Sessione: conteggi live + regola più colpita. Numeri che contano, non decorazione.
    let nB = 0, nA = 0, nC = 0;
    const byRule = {};
    events.forEach(e => {
        if (e.canary) { nC++; return; }
        if (e.action === 'blocked') { nB++; byRule[e.rule] = (byRule[e.rule] || 0) + 1; }
        else nA++;
    });
    let topRule = '—';
    let topN = 0;
    Object.entries(byRule).forEach(([r, n]) => { if (n > topN) { topN = n; topRule = r; } });
    let lastB = 'mai';
    for (let i = events.length - 1; i >= 0; i--) {
        const e = events[i];
        if (e.action === 'blocked' || e.action === 'killed') {
            lastB = `${e.canary ? '🐤' : '⛔'} ${(e.time || '').slice(11, 19)} ${esc(e.rule || 'canary')} pid=${e.pid}`;
            break;
        }
    }
    content.innerHTML = `<h2>Stato</h2><p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}${appVersion ? ` · ZeroShield ${esc(appVersion)}` : ''}</p>
    <div class="cards">
      <div class="card"><div class="k">Modalità</div><div class="v" style="font-size:17px">${esc(status.mode)}</div></div>
      <div class="card"><div class="k">Hook LSM</div><div class="v" style="font-size:17px">${lsm}</div></div>
      <div class="card"><div class="k">File protetti</div><div class="v" data-count="${status.protected}">0</div></div>
      <div class="card"><div class="k">Binari autorizzati</div><div class="v" data-count="${status.allowed}">0</div></div>
      <div class="card"><div class="k">XDP su</div><div class="v small">${esc(xdp)}</div></div>
    </div>
    <h2 style="margin-top:20px">Sessione</h2><p class="sub">dall'apertura della GUI</p>
    <div class="cards">
      <div class="card warn-top"><div class="k">Blocchi</div><div class="v" data-count="${nB}">0</div></div>
      <div class="card"><div class="k">Audit</div><div class="v" data-count="${nA}">0</div></div>
      <div class="card warn-top"><div class="k">Canary</div><div class="v" data-count="${nC}">0</div></div>
      <div class="card"><div class="k">Regola più colpita</div><div class="v small">${esc(topRule)}${topN ? ` ×${topN}` : ''}</div></div>
      <div class="card warn-top"><div class="k">Ultimo blocco</div><div class="v small mono">${lastB}</div></div>
      <div class="card"><div class="k">Servizio</div><div class="v small" id="svc-state">…</div><div style="margin-top:6px"><button class="chip" id="svc-stop">⏹ Ferma</button></div></div>
      <div class="card"><div class="k">Modalità config</div><div class="v small" id="cfg-mode">…</div><div style="margin-top:6px"><button class="chip" id="mode-toggle">⇄ audit/enforce</button></div></div>
    </div>`;
    content.querySelectorAll('[data-count]').forEach(el =>
        countUp(el, parseInt(el.dataset.count, 10)));
    ServiceState().then(st => {
        const el = document.getElementById('svc-state');
        if (el) el.textContent = st;
    }).catch(() => {});
    ConfigMode().then(md => {
        const el = document.getElementById('cfg-mode');
        if (el) el.textContent = md || '(non letto)';
    }).catch(() => {});
    const stop = document.getElementById('svc-stop');
    if (stop) stop.onclick = async () => {
        if (!confirm('Fermare la protezione? Da qui in poi niente blocca più nulla.')) return;
        try { await ServiceStop(); toast('Protezione fermata', true); }
        catch (e) { toast('Stop fallito: ' + (e.message || e), true); }
    };
    const tog = document.getElementById('mode-toggle');
    if (tog) tog.onclick = async () => {
        const cur = await ConfigMode().catch(() => '');
        const next = cur === 'enforce' ? 'audit' : 'enforce';
        const warn = next === 'enforce'
            ? 'Passare a ENFORCE? Blocca davvero: solo a log puliti.'
            : 'Tornare ad audit? Da qui logga senza bloccare.';
        if (!confirm(warn)) return;
        try { await SetConfigMode(next); toast('Modalità: ' + next + ' (servizio riavviato)', next === 'enforce'); }
        catch (e) { toast('Cambio fallito: ' + (e.message || e), true); }
        render();
    };
}

function filterEvents() {
    const q = evSearch.toLowerCase();
    return events.filter(e => {
        if (evType === 'blocked' && !(e.action === 'blocked' || e.action === 'killed')) return false;
        if (evType === 'audit' && (e.action === 'blocked' || e.canary)) return false;
        if (evType === 'canary' && !e.canary) return false;
        if (!q) return true;
        const hay = `${e.rule || ''} ${e.comm || ''} ${e.exe || ''} ${e.path || ''} ${e.pid || ''} ${e.kind || ''}`.toLowerCase();
        return hay.includes(q);
    });
}

function eventsTableHTML(pool) {
    const sev = e => (e.action === 'blocked' || e.action === 'killed') ? 0 : (e.canary ? 1 : 2);
    const listed = [...pool].sort((a, b) => evSevFirst ? (sev(a) - sev(b)) : 0);
    const rows = listed.reverse().slice(0, 200).map(e => {
        if (e.canary) {
            const tag = e.action === 'killed'
                ? `<span class="tag tag-block">${ICO_BIRD} KILL</span>`
                : `<span class="tag tag-canary">${ICO_BIRD} canary</span>`;
            const t = (e.time || '').slice(11, 19);
            const cls = e.action === 'killed' ? 'row-block' : 'row-canary';
            return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td>canary</td>
            <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.kind || '')}</td><td class="mono">${esc(e.exe || '')} ${esc(e.path || '')}</td></tr>`;
        }
        const tag = e.action === 'blocked'
            ? `<span class="tag tag-block">${ICO_BLOCK} BLOCCO</span>`
            : `<span class="tag tag-audit">${ICO_AUDIT} audit</span>`;
        const t = (e.time || '').slice(11, 19);
        const cls = e.action === 'blocked' ? 'row-block' : 'row-audit';
        return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td><button class="linklike" data-rule="${esc(e.rule)}">${esc(e.rule)}</button></td>
        <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.comm)}</td><td class="mono">${esc(e.exe || '(uscito)')}</td></tr>`;
    }).join('');
    return `<table><tr><th></th><th>ora</th><th>regola</th><th>pid</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
}

function eventsBarHTML() {
    const chips = [['all', 'tutti'], ['blocked', 'blocchi'], ['audit', 'audit'], ['canary', 'canary']]
        .map(([v, l]) => `<button class="chip${evType === v ? ' on' : ''}" data-t="${v}">${l}</button>`).join('');
    return `<div class="toolbar"><input id="ev-q" type="search" placeholder="Filtra regola, comm, exe, pid…" value="${esc(evSearch)}"><span class="chips">${chips}</span>
    <button id="ev-sev" class="chip${evSevFirst ? ' on' : ''}" title="Pericolosi prima (anti alert-fatigue)">⚠️ prima</button></div>`;
}

// La vista Eventi e' l'unica con un campo di testo: se a ogni evento in arrivo si
// ricostruisse tutta la pagina, la barra di ricerca perderebbe focus e cursore
// mentre scrivi (con un flood, di continuo; e le composizioni da tastiera con
// accenti si interromperebbero). Quindi la barra si costruisce UNA volta e dopo si
// aggiorna solo la tabella.
function renderEvents() {
    if (!events.length) {
        delete content.dataset.view;
        content.innerHTML = `${h2(ICO_AUDIT, 'Eventi')}
        <div class="empty"><span class="big">🌊</span><b>Rete calma, niente eventi.</b><br>In audit gli accessi legittimi compaiono qui: passa a enforce solo a log puliti.</div>`;
        return;
    }
    const pool = filterEvents();
    const sub = `${pool.length}/${events.length} eventi (ultimi 200, live)`;
    const body = document.getElementById('ev-body');
    if (content.dataset.view === 'events' && body) {
        document.getElementById('ev-sub').textContent = sub;
        body.innerHTML = eventsTableHTML(pool);
        syncEventsBar();
        wireEventLinks();
        return;
    }
    content.dataset.view = 'events';
    content.innerHTML = `${h2(ICO_AUDIT, 'Eventi')}<p class="sub" id="ev-sub">${sub}</p>
    <div id="ev-bar">${eventsBarHTML()}</div><div id="ev-body">${eventsTableHTML(pool)}</div>`;
    wireEventsBar();
    wireEventLinks();
}

// Riallinea chip e campo di ricerca allo stato (dopo un drill-down da Regole, per esempio)
// senza toccare il campo mentre l'utente ci sta scrivendo.
function syncEventsBar() {
    document.querySelectorAll('#ev-bar .chip[data-t]').forEach(c => c.classList.toggle('on', c.dataset.t === evType));
    const sev = document.getElementById('ev-sev');
    if (sev) sev.classList.toggle('on', evSevFirst);
    const q = document.getElementById('ev-q');
    if (q && q !== document.activeElement && q.value !== evSearch) q.value = evSearch;
}

// Barra: costruita una volta sola, quindi si collega una volta sola.
function wireEventsBar() {
    const q = document.getElementById('ev-q');
    if (q) q.oninput = () => { evSearch = q.value; render(); };
    document.querySelectorAll('#ev-bar .chip[data-t]').forEach(c => {
        c.onclick = () => { evType = c.dataset.t; render(); };
    });
    const sev = document.getElementById('ev-sev');
    if (sev) sev.onclick = () => { evSevFirst = !evSevFirst; render(); };
}

// I link "regola" stanno nella tabella, che si ricostruisce a ogni aggiornamento.
function wireEventLinks() {
    document.querySelectorAll('#ev-body .linklike[data-rule]').forEach(l => {
        l.onclick = () => { evSearch = l.dataset.rule; evType = 'all'; render(); };
    });
}

function renderRules() {
    const rules = status.rules || [];
    if (!rules.length) {
        content.innerHTML = `${h2(ICO_KEY, 'Regole')}<div class="empty"><span class="big">🗝️</span><b>Nessuna regola caricata.</b><br>Controlla il profilo nel config.</div>`;
        return;
    }
    content.innerHTML = `${h2(ICO_KEY, 'Regole')}<p class="sub">${rules.length} gruppi di segreti · solo questi binari leggono questi file</p>` +
        rules.map(r => `<div class="rule"><h3>${ICO_KEY} ${esc(r.name)}</h3>
        <div><span class="mono">file:</span> <span class="mono">${esc((r.paths || []).join(', '))}</span></div>
        <div><span class="mono">exe:</span> <span class="mono">${esc((r.allow || []).join(', '))}</span></div>
        <div class="links"><button class="linklike" data-goto="${esc(r.name)}">vedi eventi →</button></div></div>`).join('');
    document.querySelectorAll('#content .linklike[data-goto]').forEach(l => {
        l.onclick = () => gotoEvents(l.dataset.goto);
    });
}

// --- Radar: spazzata canvas con scia + alone + tooltip (dati eBPF) ---
let radarRAF = 0;
let radarAngle = 0;
let radarPts = [];

function hashIP(ip) {
    let h = 2166136261;
    for (let i = 0; i < ip.length; i++) { h ^= ip.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 360) * Math.PI / 180;
}

// Guida lettura: posizione fissa per IP, distanza logaritmica dai drop,
// colore per motivo dominante. La spazzata è solo eye-candy.
const RADAR_GUIDE = `<div id="radar-legend"><h4>Come leggerlo</h4><ul>
<li><b>Posizione</b> dell'IP fissa (hash): ritrovi sempre lo stesso host nello stesso punto.</li>
<li><b>Distanza dal centro</b> = quanti drop (scala logaritmica: 1 si vede, 1000 non esplode).</li>
<li><b>Rosso</b> = subnet bloccate, <b>ambra</b> = poisoning (LLMNR/mDNS). <b>Alone</b> ∝ volume.</li>
<li><b>Spazzata blu</b> solo animazione: i dati sono kernel, non dipendono da lei.</li>
<li>Passa il mouse sui blip: IP e conteggi.</li></ul></div>`;

function renderRadar() {
    cancelAnimationFrame(radarRAF);
    const src = status.top_sources || status.topSources || [];
    content.innerHTML = `${h2(ICO_AUDIT, 'Radar rete')}
    <p class="sub">${src.length ? src.length + ' sorgenti droppate da XDP (dati kernel)' : ''}</p>` +
    (src.length
        ? `<div id="radar-wrap"><canvas id="radar" width="360" height="360"></canvas>${RADAR_GUIDE}</div><div id="radar-list"></div>`
        : `<div class="empty"><span class="big">📡</span><b>Radar vuoto: nessun drop XDP.</b><br>Rete calma o demone appena partito. Genera poisoning in lab per vedere i blip.</div>`);
    if (!src.length) return;
    const cv = document.getElementById('radar');
    const cx = cv.getContext('2d');
    // Tooltip singolo globale: renderRadar gira a ogni evento, senza questo
    // si accumulava un div per frame.
    let tip = document.getElementById('radar-tip');
    if (!tip) {
        tip = document.createElement('div');
        tip.id = 'radar-tip';
        document.body.appendChild(tip);
    }
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    const ring = dark ? '#48484a' : '#d2d2d7';
    const sweepC = dark ? '#0a84ff' : '#0071e3';
    let max = 1;
    src.forEach(s => { const t = (s.total || s.Total || 0); if (t > max) max = t; });
    radarPts = src.map(s => {
        const t = s.total || s.Total || 0;
        const frac = Math.log10(t + 1) / Math.log10(max + 1);
        const r = 30 + 145 * frac;
        const ia = hashIP(s.ip || s.IP || '');
        return {s, t, frac, x: 180 + r * Math.cos(ia), y: 180 + r * Math.sin(ia)};
    });
    const list = document.getElementById('radar-list');
    list.innerHTML = radarPts.map(p => {
        const ip = esc(p.s.ip || p.s.IP || '');
        const kind = ((p.s.subnet || p.s.Subnet || 0) >= (p.s.poison || p.s.Poison || 0)) ? 'subnet' : 'poisoning';
        return `<div class="rule"><h3>${ICO_BAN} <span class="mono">${ip}</span></h3>
        <div><b>${p.t}</b> drop (${kind}) · ultimo ${(p.s.last_seen || p.s.LastSeen || '').slice(11, 19)}</div></div>`;
    }).join('');
    cv.onmousemove = ev => {
        const r = cv.getBoundingClientRect();
        const mx = (ev.clientX - r.left) * (360 / r.width);
        const my = (ev.clientY - r.top) * (360 / r.height);
        const hit = radarPts.find(p => (p.x - mx) ** 2 + (p.y - my) ** 2 < 18 ** 2);
        if (hit) {
            tip.style.display = 'block';
            tip.style.left = (ev.clientX + 12) + 'px';
            tip.style.top = (ev.clientY + 12) + 'px';
            tip.textContent = `${hit.s.ip || hit.s.IP} · ${hit.t} drop`;
        } else tip.style.display = 'none';
    };
    cv.onmouseleave = () => { tip.style.display = 'none'; };
    // Scia: ultime 8 posizioni della spazzata, alpha decrescente.
    const trail = [];
    function frame() {
        radarAngle = (radarAngle + 2) % 360;
        trail.push(radarAngle);
        if (trail.length > 8) trail.shift();
        const a = radarAngle * Math.PI / 180;
        cx.clearRect(0, 0, 360, 360);
        cx.strokeStyle = ring; cx.lineWidth = 1;
        [60, 120, 175].forEach(r => { cx.beginPath(); cx.arc(180, 180, r, 0, 7); cx.stroke(); });
        cx.beginPath(); cx.moveTo(180, 0); cx.lineTo(180, 360);
        cx.moveTo(0, 180); cx.lineTo(360, 180);
        cx.strokeStyle = ring; cx.stroke();
        trail.forEach((ta, i) => {
            const aa = ta * Math.PI / 180;
            cx.beginPath(); cx.moveTo(180, 180);
            cx.lineTo(180 + 175 * Math.cos(aa), 180 + 175 * Math.sin(aa));
            cx.strokeStyle = sweepC; cx.globalAlpha = (i + 1) / trail.length * 0.5;
            cx.lineWidth = 2; cx.stroke(); cx.globalAlpha = 1;
        });
        radarPts.forEach(p => {
            const sub = (p.s.subnet || p.s.Subnet || 0) >= (p.s.poison || p.s.Poison || 0);
            const R = 4 + 5 * p.frac;
            const grad = cx.createRadialGradient(p.x, p.y, 1, p.x, p.y, R * 3);
            const col = sub ? '215,0,21' : '184,134,11';
            grad.addColorStop(0, `rgba(${col},0.55)`);
            grad.addColorStop(1, `rgba(${col},0)`);
            cx.beginPath(); cx.arc(p.x, p.y, R * 3, 0, 7);
            cx.fillStyle = grad; cx.fill();
            cx.beginPath(); cx.arc(p.x, p.y, R, 0, 7);
            cx.fillStyle = sub ? '#d70015' : '#b8860b'; cx.fill();
            cx.beginPath(); cx.arc(p.x, p.y, R, 0, 7);
            cx.strokeStyle = '#fff'; cx.lineWidth = 1.5; cx.stroke();
        });
        radarRAF = requestAnimationFrame(frame);
    }
    frame();
}

// Guida primo avvio: il demone vuole root, le UI no. Passo-passo con comandi
// copiabili. Niente viene eseguito da qui: tutto resta nel tuo terminale.
function renderGuide() {
    content.innerHTML = `${h2(ICO_AUDIT, 'Guida avvio')}<p class="sub">Il demone vuole root, le UI no. Segui i passi, uno alla volta.</p>` +
        renderGuideBody() +
        `<p class="sub">Solo demo senza root: <code>ZT_SOCKET=/tmp/z.sock zt-mockd &amp;</code> + UI con stesso socket (dati finti).</p>`;
}

// Chi usa questa GUI l'ha quasi sempre installata dal pacchetto .deb (che tira dentro
// il demone): niente "make build", e la config esiste gia', quindi si MODIFICA, non si
// copia sopra. Il percorso da sorgente resta, in coda.
const GUIDE_PKG = [
    ['1 · Installa', 'La GUI dipende dal demone: un solo comando installa tutto. Il servizio non parte da solo.', 'sudo apt install ./zeroshield_*_amd64.deb ./zeroshield-gui_*_amd64.deb'],
    ['2 · Imposta l\'utente', 'Apri la config e scrivi il tuo utente in <b>user:</b>. Resta in <b>audit</b> (non blocca nulla). Il socket sarà leggibile solo da root e da quell\'utente.', 'sudoedit /etc/zt-shield/shield.yaml'],
    ['3 · Verifica il kernel', 'Ogni programma eBPF deve risultare ✅ e <b>bpf</b> deve comparire tra gli LSM attivi.', 'sudo zt-probe -xdp-lo && cat /sys/kernel/security/lsm'],
    ['4 · Avvia in audit', 'Poi guarda questa GUI popolarsi (o <span class="mono">zt-tui</span>).', 'sudo systemctl enable --now zt-shield && journalctl -u zt-shield -f'],
    ['5 · Passa a enforce', 'Solo a log puliti: nessun accesso legittimo negato per errore.', 'mode: enforce in /etc/zt-shield/shield.yaml, poi: sudo systemctl restart zt-shield'],
];
const GUIDE_SRC = [
    ['1 · Prerequisiti', 'Kernel ≥5.15 con BTF e voce <b>bpf</b> in <span class="mono">/sys/kernel/security/lsm</span> (senza: GRUB + reboot, vedi README).', 'bash scripts/check_prereqs.sh'],
    ['2 · Compila', 'Toolchain eBPF + binari demone e TUI.', 'make build'],
    ['3 · Configura', 'Copia l\'esempio SENZA sovrascrivere una config esistente (-n), poi imposta <b>user:</b> e resta in audit.', 'sudo mkdir -p /etc/zt-shield && sudo cp -n configs/shield.example.yaml /etc/zt-shield/shield.yaml'],
    ['4 · Prova in primo piano', 'Demone in audit: logga senza negare. Serve root (eBPF).', 'sudo SHIELD_USER=$USER ./bin/zt-shield'],
    ['5 · Servizio', 'Installa come servizio (a log puliti: mode enforce + restart).', 'sudo bash scripts/install_service.sh $USER home'],
];

// Corpo guida riusabile anche offline (tab Guida senza demone).
function renderGuideBody() {
    const block = steps => steps.map(([t, d, c]) => `<div class="rule"><h3>${esc(t)}</h3><div>${d}</div>
        <div style="margin-top:6px"><code>${esc(c)}</code></div></div>`).join('');
    return `<h2 style="margin-top:14px">Da pacchetto .deb (consigliato)</h2>${block(GUIDE_PKG)}
    <h2 style="margin-top:22px">Da sorgente</h2>${block(GUIDE_SRC)}`;
}

// Stato VPN: il verde richiede tunnel su E kill-switch attivo (misurati dal demone, non
// dedotti dal config). Un tunnel su senza kill-switch protegge solo finche' regge.
function vpnPanel(v) {
    if (!v.enabled) {
        return `<div class="empty"><span class="big">🔓</span><b>VPN non monitorata.</b><br>Nessuna stanza <code>vpn:</code> nel config: su rete ostile esci in chiaro.</div>`;
    }
    const hs = (typeof v.handshake_age === 'number' && v.handshake_age >= 0)
        ? `handshake ${v.handshake_age}s fa` : 'handshake mai/sconosciuto';
    const line = `<span class="mono">${esc(v.tunnel)} → ${esc(v.endpoint)}</span> · ${hs}`;
    if (v.up && v.killswitch) {
        return `<div class="rule ok"><h3>🔒 VPN protetta</h3><div>${line} · kill-switch attivo</div></div>`;
    }
    if (v.up) {
        return `<div class="warn">${ICO_WARN} VPN su ma kill-switch NON attivo: se il tunnel cade esci in chiaro.<br>${line}<br>
        <span class="sub">Attivalo: <code>vpn_killswitch.sh on ${esc(v.endpoint)} ${esc(v.tunnel)}</code> (vedi docs/VPN_SETUP.md)</span></div>`;
    }
    if (v.killswitch) {
        return `<div class="warn">${ICO_WARN} VPN giù (${esc(v.tunnel || '?')} assente), kill-switch attivo: sei offline ma non in chiaro. Alza il tunnel.</div>`;
    }
    return `<div class="warn">${ICO_WARN} VPN GIÙ (${esc(v.tunnel || '?')} assente) e nessun kill-switch: sei in chiaro! Alza il tunnel o esci dalla rete.</div>`;
}

// IPv6 va tra parentesi, altrimenti "::1:22" non si legge.
function hostPort(addr, port) {
    return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

function renderNet() {
    const subs = status.block_subnets || [];
    content.innerHTML = `${h2(ICO_AUDIT, 'Rete')}<p class="sub">XDP: ${esc((status.xdp || []).join(', ') || '(spento)')} · poisoning drop: ${status.block_poisoning}</p>` + vpnPanel(status.vpn || {}) +
        (subs.length ? `<div class="warn">${ICO_WARN} Il drop scarta anche le risposte da queste reti: mai gateway/DNS.</div>` : '') +
        (subs.length ? subs.map(c => `<div class="rule">🚫 <span class="mono">${esc(c)}</span></div>`).join('')
            : `<p class="sub">Nessuna subnet bloccata: solo drop poisoning + UFW.</p>`) +
        renderListening();
}

// Porte in ascolto (TCP e UDP: mDNS/LLMNR sono la superficie che XDP difende).
// Se non riconosci una riga, è quella da investigare.
function renderListening() {
    const ls = status.listening || [];
    if (!ls.length) return `<p class="sub">Nessuna porta in ascolto.</p>`;
    const rows = ls.map(l => {
        const who = l.exe ? `<span class="mono">${esc(l.exe)}</span> <span class="mono">pid=${l.pid}</span>` : '<i>sconosciuto: processo di altri o già uscito</i>';
        const open = l.addr === '0.0.0.0' || l.addr === '::' ? ' 🌐' : '';
        return `<tr><td class="mono">${esc(l.proto)}</td><td class="mono">${esc(hostPort(l.addr, l.port))}${open}</td><td>${who}</td></tr>`;
    }).join('');
    const total = status.listening_total || ls.length;
    const cut = total > ls.length ? `<p class="sub">… mostrate ${ls.length} di ${total}</p>` : '';
    return `<h2 style="margin-top:18px">In ascolto</h2><p class="sub">Superficie esposta · 🌐 = su tutte le interfacce</p>
    <table><tr><th>proto</th><th>porta</th><th>processo</th></tr>${rows}</table>${cut}`;
}

async function boot() {
    try {
        status = await GetStatus();
    } catch (e) {
        offlineMsg = String(e && e.message || e);
        try { offlineMsg += ' — socket: ' + await SocketPath(); } catch (_) {}
    }
    render();
    // Versione dal binario (ldflags al build): se manca il binding, nessun errore.
    try { appVersion = await Version(); requestRender(); } catch (_) {}
    // Onboarding: solo se demone mai visto E wizard mai completato.
    // Flag in localStorage (per-utente, niente root): chi reinstalla lo rivede.
    try {
        if (!status && !localStorage.getItem('zs-onboarded')) {
            showOnboarding();
        }
    } catch (_) {}
}

// Wizard primo avvio stile installazione: 4 passi, niente eseguito,
// solo spiegato con comandi copiabili. Salta o finisci: non ricompare.
let obStep = 0;
const OB_STEPS = [
    ['👋 Benvenuto in ZeroShield',
     'Questa GUI è solo la vetrina: la protezione vive nel demone (root) che parla su socket. Ora sei <b>offline</b>: nessun demone in ascolto, niente è attivo.',
     ''],
    ['1 · Installa e imposta l\'utente',
     'Dal pacchetto .deb il demone è già installato (non parte da solo). Scrivi il tuo utente in <b>user:</b>: il socket sarà leggibile solo da lui e da root.',
     'sudoedit /etc/zt-shield/shield.yaml'],
    ['2 · Verifica il kernel',
     'Serve la voce <b>bpf</b> tra gli LSM attivi (senza: GRUB + reboot, vedi README). Ogni programma eBPF deve risultare ✅.',
     'sudo zt-probe -xdp-lo\ncat /sys/kernel/security/lsm'],
    ['3 · Avvia in audit e osserva',
     '<b>Audit non blocca nulla</b>: logga e basta, il modo sicuro di iniziare. A log puliti: <b>mode: enforce</b> + restart. Da sorgente la Guida ha gli altri comandi.',
     'sudo systemctl enable --now zt-shield\njournalctl -u zt-shield -f'],
];
function showOnboarding() {
    let ov = document.getElementById('onboard');
    if (!ov) {
        ov = document.createElement('div');
        ov.id = 'onboard';
        document.body.appendChild(ov);
    }
    const [t, d, c] = OB_STEPS[obStep];
    const dots = OB_STEPS.map((_, i) =>
        `<span class="ob-dot${i === obStep ? ' on' : ''}"></span>`).join('');
    ov.innerHTML = `<div class="ob-card"><h2>${t}</h2><p>${d}</p>` +
        (c ? `<pre>${esc(c)}</pre>` : '') +
        `<div class="ob-dots">${dots}</div>
        <div class="ob-btns">
          <button id="ob-skip" class="chip">Salta</button>
          ${obStep > 0 ? '<button id="ob-back" class="chip">← Indietro</button>' : ''}
          ${obStep < OB_STEPS.length - 1
            ? '<button id="ob-next" class="chip on">Avanti →</button>'
            : '<button id="ob-done" class="chip on">Ho capito ✓</button>'}
        </div></div>`;
    const done = () => {
        try { localStorage.setItem('zs-onboarded', '1'); } catch (_) {}
        ov.remove();
    };
    document.getElementById('ob-skip').onclick = done;
    document.getElementById('ob-done') && (document.getElementById('ob-done').onclick = done);
    const nx = document.getElementById('ob-next');
    if (nx) nx.onclick = () => { obStep++; showOnboarding(); };
    const bk = document.getElementById('ob-back');
    if (bk) bk.onclick = () => { obStep--; showOnboarding(); };
}

EventsOn('shield:status', st => { status = st; offlineMsg = ''; requestRender(); });
EventsOn('shield:status-error', msg => { if (!status) { offlineMsg = msg; requestRender(); } });
EventsOn('shield:event', ev => {
    events.push(ev);
    if (events.length > 200) events = events.slice(-200);
    requestRender();
});

// Throttle notifiche canary lato UI (il backend notifica già i blocked;
// qui solo toast visivo: la riga resta comunque in tabella).
let lastCanaryToast = 0;
EventsOn('shield:canary', a => {
    events.push({
        canary: true, time: a.time, action: a.action, pid: a.pid,
        kind: a.kind, exe: a.exe, path: a.path, rule: 'canary',
    });
    if (events.length > 200) events = events.slice(-200);
    const now = Date.now();
    if (now - lastCanaryToast > 10000) {
        lastCanaryToast = now;
        toast(`🐤 Canary: ${a.action} pid=${a.pid} (${a.kind})`, a.action === 'killed');
    }
    requestRender();
});

// Toast non bloccante in alto a destra, sparisce da solo. danger=rosso.
function toast(text, danger) {
    let el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        document.body.appendChild(el);
    }
    el.textContent = text;
    el.classList.toggle('danger', !!danger);
    el.classList.add('show');
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.remove('show'), 6000);
}

boot();
