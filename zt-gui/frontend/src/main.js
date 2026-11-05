// ZeroShield GUI — client IPC: primo paint via GetStatus, poi push live.
// Solo lettura: nessun'azione privilegiata da qui (cambio mode via config+restart).
import {GetStatus, SocketPath, Version, ServiceState, ServiceInstall, ServiceInstallAs, ServiceStart, ServiceStop, ConfigMode, SetConfigMode, ConfigText, Preflight} from '../wailsjs/go/main/App.js';
import {EventsOn} from '../wailsjs/runtime/runtime.js';

const content = document.getElementById('content');
const badge = document.getElementById('mode-badge');
const modeText = document.getElementById('mode-text');
const viewTitle = document.getElementById('view-title');
const conn = document.getElementById('conn');
const evCount = document.getElementById('ev-count');
const buttons = [...document.querySelectorAll('#sidebar button')];
const TITLES = {status: 'Stato', events: 'Eventi', rules: 'Regole', net: 'Rete', radar: 'Radar', guide: 'Guida', config: 'Configurazione'};
// Stesso ordine della sidebar: i numeri accanto alle voci sono anche le scorciatoie da tastiera.
const VIEW_ORDER = ['status', 'events', 'radar', 'rules', 'net', 'config', 'guide'];

let view = 'status';
let status = null;
let events = [];
let offlineMsg = '';
let evSearch = '';
let evType = 'all'; // all | blocked | audit | canary
let evSevFirst = false; // pericolosi prima (pattern SOC anti alert-fatigue)
let evGroup = false; // raggruppa righe uguali (regola + exe) con un contatore
let appVersion = ''; // dal binario (ldflags), non scritta a mano
let lastStatusAt = 0; // quando e' arrivato l'ultimo stato (GetStatus o push)

// Cambio vista: unico punto, usato da click, tastiera e link interni.
function go(v) {
    view = v;
    buttons.forEach(x => x.classList.toggle('active', x.dataset.view === v));
    render(true);
}

// Drill-down: da Regole o Stato verso Eventi già filtrati.
function gotoEvents(q) {
    evSearch = q || '';
    evType = 'all';
    go('events');
}
let prevMode = '';

buttons.forEach(b => b.onclick = () => go(b.dataset.view));

// Scorciatoie 1-7. Mai mentre si scrive in un campo o c'e' una finestra aperta:
// la ricerca eventi non deve cambiare tab digitando un numero.
document.addEventListener('keydown', e => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target && e.target.tagName;
    if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT') return;
    if (document.getElementById('onboard') || document.getElementById('dlg')) return;
    const i = '1234567'.indexOf(e.key);
    if (i >= 0 && e.key.length === 1) go(VIEW_ORDER[i]);
});

function esc(s) {
    return String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
}

// Il demone manda orari ISO in UTC; il journal e il resto del sistema sono in ora
// locale. Mostrare UTC faceva sembrare gli eventi "di un'ora fa".
function fmtTime(iso) {
    const d = new Date(iso);
    if (!iso || isNaN(d.getTime())) return String(iso || '').slice(11, 19);
    return d.toLocaleTimeString('it-IT', {hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'});
}

// bound(fn): chiama un binding Go solo se esiste (stub di test vecchi o
// ambienti senza backend completo). Ritorna sempre una Promise: undefined se
// assente, mai un lancio. Così .then/.catch restano validi ovunque.
function bound(fn, ...args) {
    try { return typeof fn === 'function' ? fn(...args) : Promise.resolve(undefined); }
    catch (e) { return Promise.reject(e); }
}

const ICO_BLOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICO_AUDIT = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="2.4" fill="currentColor"/></svg>';
const ICO_WARN = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3L22 20H2L12 3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="currentColor"/></svg>';
const ICO_KEY = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
const ICO_BAN = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICO_BIRD = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 14c4-1 5-4 5-8 3 0 5 2 5 4l4-2-1 4c1 3-1 7-5 8l-3 1-2-3c-1 0-2 0-3-1z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><circle cx="11" cy="8" r="1" fill="currentColor"/></svg>';
// Una icona per pagina (la stessa del menu): prima quasi tutte usavano l'occhio e
// Configurazione mostrava il lucchetto di Regole.
const ICO_GAUGE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 13a8 8 0 1 1 16 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><path d="M12 13l4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="13" r="1.6" fill="currentColor"/></svg>';
const ICO_LIST = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 6h13M8 12h13M8 18h13" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="4" cy="6" r="1.4" fill="currentColor"/><circle cx="4" cy="12" r="1.4" fill="currentColor"/><circle cx="4" cy="18" r="1.4" fill="currentColor"/></svg>';
const ICO_RADAR = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="4.5" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M12 12l6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="16" cy="15" r="1.6" fill="currentColor"/></svg>';
const ICO_GLOBE = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M3 12h18M12 3c3 3.5 3 14 0 18M12 3c-3 3.5-3 14 0 18" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
const ICO_HELP = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.6 2.2c-.8.4-1.1.8-1.1 1.8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="currentColor"/></svg>';
const ICO_GEAR = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2-1.2L14.2 3h-4l-.4 2.7a7 7 0 0 0-2 1.2l-2.3-1-2 3.4 2 1.5A7 7 0 0 0 5 12c0 .4 0 .8.1 1.2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2 1.2l.4 2.7h4l.4-2.7a7 7 0 0 0 2-1.2l2.3 1 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';

function h2(icon, text) { return `<h2>${icon}${esc(text)}</h2>`; }
function sec(text) { return `<h3 class="sec">${esc(text)}</h3>`; }

// Comando copiabile: le guide dicevano "comandi copiabili" ma non c'era il pulsante.
function codeRow(cmd) {
    return `<div class="code-row"><code>${esc(cmd)}</code><button class="copy" data-copy="${esc(cmd)}" title="Copia negli appunti">copia</button></div>`;
}
async function copyText(t) {
    try { await navigator.clipboard.writeText(t); toast('Copiato negli appunti', false); }
    catch (_) { toast('Copia non riuscita: seleziona il testo a mano', true); }
}
// Un solo gestore per link interni (data-go) e pulsanti copia (data-copy): le pagine
// si ricostruiscono a ogni render, i gestori sul contenitore no.
content.addEventListener('click', e => {
    const g = e.target.closest && e.target.closest('[data-go]');
    if (g) { go(g.dataset.go); return; }
    const c = e.target.closest && e.target.closest('[data-copy]');
    if (c) copyText(c.dataset.copy);
});

// Conferma con spiegazione delle conseguenze (al posto di confirm() nudo).
function confirmDialog({title, body, ok, danger}) {
    return new Promise(resolve => {
        const ov = document.createElement('div');
        ov.id = 'dlg';
        ov.innerHTML = `<div class="ob-card" role="dialog" aria-modal="true"><h2>${esc(title)}</h2><p>${body}</p>
        <div class="ob-btns"><button class="chip" id="dlg-no">Annulla</button><button class="chip ${danger ? 'danger' : 'on'}" id="dlg-ok">${esc(ok)}</button></div></div>`;
        document.body.appendChild(ov);
        const done = v => { document.removeEventListener('keydown', onKey, true); ov.remove(); resolve(v); };
        const onKey = e => { if (e.key === 'Escape') { e.stopPropagation(); done(false); } };
        document.addEventListener('keydown', onKey, true);
        ov.querySelector('#dlg-no').onclick = () => done(false);
        ov.querySelector('#dlg-ok').onclick = () => done(true);
        ov.addEventListener('click', e => { if (e.target === ov) done(false); });
        // Il focus parte su Annulla: Invio per sbaglio non deve passare a enforce.
        ov.querySelector('#dlg-no').focus();
    });
}

// Cambio audit/enforce: stessa conferma da Stato e da Configurazione.
async function switchMode(next) {
    const enf = next === 'enforce';
    const ok = await confirmDialog({
        title: enf ? 'Passare a enforce?' : 'Tornare ad audit?',
        body: enf
            ? 'In <b>enforce</b> gli accessi non autorizzati vengono <b>negati davvero</b> (EACCES). Passa solo se in Eventi, in audit, non compaiono accessi legittimi. Il servizio si riavvia (il sistema chiede la password).'
            : 'In <b>audit</b> il demone registra gli accessi ma non blocca nulla. Il servizio si riavvia (il sistema chiede la password).',
        ok: enf ? 'Passa a enforce' : 'Torna ad audit',
        danger: enf,
    });
    if (!ok) return;
    try {
        if (await bound(SetConfigMode, next) === undefined) toast('Non supportato in questa build', true);
        else toast(`Modalità: ${next} (servizio riavviato)`, enf);
    } catch (e) { toast('Cambio fallito: ' + (e.message || e), true); }
    render(true);
}

function paintBadge() {
    if (!status) { badge.className = 'badge off'; modeText.textContent = 'DISATTIVO'; return; }
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
let statusSeq = 0; // ogni stato ricevuto e' un mondo nuovo, anche con stesso time
// force=true per gesti utente (click, tab, search): saltano la guardia.
// I poll automatici chiamano render() liscio e vengono dedupati.
function render(force) {
    // Guardia anti-sfarfallio: senza demone i poll falliti arrivano ogni 2s.
    // Rirendere tutto a ogni errore fa lampeggiare la pagina: se vista e
    // situazione non cambiano, si salta (gli stream live passano comunque).
    // statusSeq impedisce di mangiare stati diversi con stesso timestamp.
    const key = view + '|' + (status ? statusSeq + ':' + (status.time || 'live') + ':' + appVersion : 'off:' + offlineMsg);
    if (!force && key === lastKey && view !== 'events' && view !== 'radar') return;
    lastKey = key;
    paintBadge();
    cancelAnimationFrame(radarRAF);
    const oldTip = document.getElementById('radar-tip');
    if (oldTip) oldTip.style.display = 'none';
    viewTitle.textContent = TITLES[view] || view;
    // Senza demone: solo Stato fa da setup; le altre tab spiegano cosa manca
    // loro (non lo stesso muro ovunque, e non setup ripetuto).
    if (!status) return view === 'status' ? renderFirstRun() : renderOffline();
    // Frozen: demone muto da oltre 15s = card ferme, non dati vivi.
    // Distingue "tutto calmo" da "demone piantato senza chiudersi".
    const staleSec = Math.floor((Date.now() - lastStatusAt) / 1000);
    if (staleSec > 15) {
        conn.innerHTML = `⚠️ dati fermi da ${staleSec}s — demone muto? <button class="linklike" id="conn-retry">riprova</button>`;
        const rt = document.getElementById('conn-retry');
        if (rt) rt.onclick = () => render(true);
    } else {
        conn.textContent = 'aggiornato ' + fmtTime(status.time || new Date().toISOString());
    }
    evCount.textContent = events.length > 0 ? events.length : '';
    if (view === 'status') return renderStatus();
    if (view === 'events') return renderEvents();
    if (view === 'rules') return renderRules();
    if (view === 'radar') return renderRadar();
    if (view === 'guide') return renderGuide();
    if (view === 'config') return renderConfig();
    return renderNet();
}

// Riga impostazione: nome, valore, e una frase che spiega a cosa serve e dove si cambia.
function kv(k, v, hint) {
    return `<div class="kv"><div class="kv-k">${esc(k)}</div><div class="kv-v">${v}</div>${hint ? `<div class="kv-h">${hint}</div>` : ''}</div>`;
}

// Configurazione: file reale su disco (persiste a ogni boot) + toggle mode.
// Regole e segreti si cambiano nel file con editor: la UI non riscrive YAML
// alla cieca, solo mode: con conferma + restart.
async function renderConfig() {
    let txt = await bound(ConfigText, );
    if (txt === undefined) txt = '(config non leggibile da questa build)';
    let fileMode = '';
    try { fileMode = await bound(ConfigMode, ); } catch (_) {}
    // Le due letture sono asincrone: se nel frattempo si e' cambiata tab, non
    // sovrascrivere la pagina nuova con questa.
    if (view !== 'config' || !status) return;
    const running = status.mode;
    const mismatch = fileMode && fileMode !== running;
    const subs = status.block_subnets || [];
    const xdp = (status.xdp || []).length ? status.xdp.map(x => `<span class="mono">${esc(x)}</span>`).join(', ') : '<span class="dot-off">spento</span>';
    content.innerHTML = `${h2(ICO_GEAR, 'Configurazione')}
    <p class="sub">Riepilogo di ciò che il demone sta usando. Il file su disco è <span class="mono">/etc/zt-shield/shield.yaml</span>, letto a ogni avvio.</p>
    ${mismatch ? `<div class="warn">${ICO_WARN}<div>Il file dice <b>${esc(fileMode)}</b> ma il demone sta girando in <b>${esc(running)}</b>: la modifica non è ancora attiva. Riavvia il servizio.</div></div>` : ''}
    ${sec('Protezione')}
    <div class="panel">
      ${kv('Modalità', `<div class="seg" role="group" aria-label="Modalità"><button class="seg-b${running === 'audit' ? ' on' : ''}" id="m-audit">Audit · logga</button><button class="seg-b${running === 'enforce' ? ' on enf' : ''}" id="m-enforce">Enforce · blocca</button></div>`,
        'Audit registra senza negare nulla, enforce nega davvero. Il cambio riavvia il servizio.')}
      ${kv('Profilo', `<b>${esc(status.profile)}</b>`, 'Sceglie le regole di base. Si cambia nel file (<span class="mono">profile:</span>).')}
      ${kv('Utente protetto', `<span class="mono">${esc(status.home)}</span>`, 'La home di cui il demone difende i segreti (<span class="mono">user:</span>).')}
      ${kv('Regole', `<b>${(status.rules || []).length}</b> gruppi · ${status.protected} file · ${status.allowed} binari`, `<button class="linklike" data-go="rules">vedi le regole →</button>`)}
    </div>
    ${sec('Rete')}
    <div class="panel">
      ${kv('Interfacce con XDP', xdp, 'Le altre interfacce attive non sono filtrate. Per coprirne altre elencale in <span class="mono">interface:</span> nel file.')}
      ${kv('Drop poisoning', status.block_poisoning ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento', 'Scarta LLMNR, mDNS e NetBIOS in ingresso (porte 5355, 5353, 137, 138).')}
      ${kv('Subnet bloccate', subs.length ? subs.map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : 'nessuna', 'Scarta tutto il traffico da quelle reti, anche le risposte: mai gateway o DNS.')}
      ${kv('VPN', (status.vpn && status.vpn.enabled) ? 'monitorata' : 'non monitorata', `Il demone osserva tunnel e kill-switch, non li applica. <button class="linklike" data-go="net">stato in Rete →</button>`)}
    </div>
    ${sec('Altre opzioni')}
    <p class="sub">Canary, regole extra, intervallo di rescan e formato log si impostano nel file. Dopo ogni modifica:</p>
    ${codeRow('sudo systemctl restart zt-shield')}
    <details class="file"><summary>Mostra il file <span class="mono">shield.yaml</span></summary>
      <div class="file-bar"><button class="copy" data-copy="${esc(txt)}">copia contenuto</button><span class="sub">modifica con: </span><code>sudoedit /etc/zt-shield/shield.yaml</code></div>
      <pre>${esc(txt)}</pre></details>`;
    const target = m => () => { if (!(m === running && !mismatch)) switchMode(m); };
    const ba = document.getElementById('m-audit');
    if (ba) ba.onclick = target('audit');
    const be = document.getElementById('m-enforce');
    if (be) be.onclick = target('enforce');
}

// Prima apertura vera: non "offline", ma setup. Mai-configurato (servizio
// missing) = percorso guidato; demone spento ma installato = riattiva.
// Distinguerli è tutta la differenza tra prodotto e demo.
let svcCached = '';
async function renderFirstRun() {
    conn.textContent = 'prima configurazione';
    let st = '';
    try { st = await bound(ServiceState, ); } catch (_) {}
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
        try {
            if (await bound(ServiceInstall, ) === undefined) toast('Non supportato in questa build', true); else toast('Installato e attivo in audit', false);
        } catch (e) { toast('Install fallita: ' + (e.message || e), true); }
        render();
    });
    bound(Preflight).then(list => {
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
    <div class="off-banner">⛔ PROTEZIONE DISATTIVA — demone spento, questa vista mostra cosa manca</div>
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
        try {
            if (await bound(ServiceInstall, ) === undefined) toast('Non supportato in questa build', true); else toast('Installato e attivo in audit', false);
        } catch (e) { toast('Install fallita: ' + (e.message || e), true); }
        render();
    });
    bound(Preflight).then(list => {
        const el = document.getElementById('preflight');
        if (!el) return;
        el.innerHTML = '<div class="checks">' + (list || []).map(c =>
            `<div class="check${c.ok ? ' ok' : ' ko'}"><span>${c.ok ? '●' : '○'}</span><span>${esc(c.name)}${c.hint ? ` <i>(${esc(c.hint)})</i>` : ''}</span></div>`
        ).join('') + '</div>';
    }).catch(() => {});
    wire('svc-start', async () => {
        const b = document.getElementById('svc-start');
        b.textContent = '…';
        try {
            if (await bound(ServiceStart, ) === undefined) toast('Non supportato in questa build', true); else toast('Protezione attivata', false);
        } catch (e) { toast('Avvio fallito: ' + (e.message || e), true); }
        render();
    });
}

// Verdetto in una riga: "sono protetto?". Rosso = una difesa e' spenta, ambra = la
// protezione c'e' ma non blocca (audit) o ha un buco noto, verde = tutto attivo.
// La VPN non monitorata e' solo una nota: dipende dal profilo, non e' un guasto.
function verdict() {
    const s = status, v = s.vpn || {};
    const bad = [], warn = [], info = [];
    if (!s.hook_lsm) bad.push(['Hook LSM spento: i file protetti non sono difesi.', 'status']);
    if (!(s.xdp && s.xdp.length)) bad.push(['XDP spento: nessun drop di rete.', 'net']);
    if (s.mode !== 'enforce') warn.push(['Modalità audit: il demone registra ma non blocca nulla.', 'config']);
    if (v.enabled && !v.killswitch) warn.push(['VPN monitorata ma kill-switch non attivo.', 'net']);
    if (!v.enabled) info.push(['VPN non monitorata.', 'net']);
    const level = bad.length ? 'bad' : (warn.length ? 'warn' : 'ok');
    const title = {bad: 'Protezione non attiva', warn: 'Protezione parziale', ok: 'Protezione attiva'}[level];
    return {level, title, items: [...bad, ...warn, ...info]};
}

const SVC_IT = {active: 'attivo', inactive: 'fermo', failed: 'in errore', activating: 'in avvio', missing: 'non installato'};

function renderStatus() {
    const xdp = (status.xdp && status.xdp.length) ? status.xdp.join(', ') : '(spento)';
    const lsm = status.hook_lsm
        ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento';
    // Sessione: conteggi live + regola più colpita. Numeri che contano, non decorazione.
    let nB = 0, nA = 0, nC = 0;
    const byRule = {};
    events.forEach(e => {
        if (e.canary) { nC++; return; }
        if (e.action === 'blocked') nB++; else nA++;
        // In audit non ci sono blocchi: la regola piu' attiva conta tutti gli accessi, non
        // solo i blocchi (prima restava "—" per sempre).
        byRule[e.rule] = (byRule[e.rule] || 0) + 1;
    });
    let topRule = '—';
    let topN = 0;
    Object.entries(byRule).forEach(([r, n]) => { if (n > topN) { topN = n; topRule = r; } });
    let lastB = 'mai';
    for (let i = events.length - 1; i >= 0; i--) {
        const e = events[i];
        if (e.action === 'blocked' || e.action === 'killed') {
            lastB = `${e.canary ? '🐤' : '⛔'} ${fmtTime(e.time)} ${esc(e.rule || 'canary')} pid=${e.pid}`;
            break;
        }
    }
    const vd = verdict();
    content.innerHTML = `${h2(ICO_GAUGE, 'Stato')}<p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}${appVersion ? ` · ZeroShield ${esc(appVersion)}` : ''}</p>
    <div class="verdict ${vd.level}"><div class="verdict-t">${vd.level === 'ok' ? '●' : (vd.level === 'warn' ? '◐' : '○')} ${vd.title}</div>
      ${vd.items.length ? `<ul>${vd.items.map(([t, g]) => `<li>${esc(t)} <button class="linklike" data-go="${g}">vedi →</button></li>`).join('')}</ul>` : ''}</div>
    ${sec('Protezione')}
    <div class="cards">
      <div class="card"><div class="k">Modalità</div><div class="v" style="font-size:17px">${esc(status.mode)}</div></div>
      <div class="card"><div class="k">Hook LSM</div><div class="v" style="font-size:17px">${lsm}</div></div>
      <div class="card"><div class="k">XDP su</div><div class="v small">${esc(xdp)}</div></div>
      <div class="card"><div class="k">File protetti</div><div class="v" data-count="${status.protected}">0</div></div>
      <div class="card"><div class="k">Binari autorizzati</div><div class="v" data-count="${status.allowed}">0</div></div>
    </div>
    ${sec('Sessione · dall\'apertura della GUI')}
    <div class="cards">
      <div class="card warn-top"><div class="k">Blocchi</div><div class="v" data-count="${nB}">0</div></div>
      <div class="card"><div class="k">Audit</div><div class="v" data-count="${nA}">0</div></div>
      <div class="card warn-top"><div class="k">Canary</div><div class="v" data-count="${nC}">0</div></div>
      <div class="card"><div class="k">Regola più attiva</div><div class="v small">${esc(topRule)}${topN ? ` ×${topN}` : ''}</div></div>
      <div class="card warn-top"><div class="k">Ultimo blocco</div><div class="v small mono">${lastB}</div></div>
    </div>
    ${sec('Controlli')}
    <div class="panel">
      <div class="kv"><div class="kv-k">Servizio</div><div class="kv-v"><b id="svc-state">…</b> <button class="chip danger" id="svc-stop">■ Ferma</button></div><div class="kv-h">Fermandolo nulla più viene difeso finché non lo riattivi.</div></div>
      <div class="kv"><div class="kv-k">Modalità nel file</div><div class="kv-v"><b id="cfg-mode">…</b> <button class="chip" id="mode-toggle">…</button></div><div class="kv-h" id="cfg-hint">Quella che il demone userà al prossimo avvio.</div></div>
    </div>`;
    content.querySelectorAll('[data-count]').forEach(el =>
        countUp(el, parseInt(el.dataset.count, 10)));
    bound(ServiceState).then(st => {
        const el = document.getElementById('svc-state');
        if (el) el.textContent = SVC_IT[st] || st;
    }).catch(() => {});
    bound(ConfigMode).then(md => {
        const el = document.getElementById('cfg-mode');
        if (!el) return;
        el.textContent = md || '(non letto)';
        // Il bottone dice dove porta, non "audit/enforce": prima non si capiva la direzione.
        const tog = document.getElementById('mode-toggle');
        if (tog) tog.textContent = md === 'enforce' ? '→ torna ad audit' : '→ passa a enforce';
        const hint = document.getElementById('cfg-hint');
        if (hint && md && md !== status.mode) hint.innerHTML = `⚠️ Il demone sta girando in <b>${esc(status.mode)}</b>: riavvia il servizio per applicarla.`;
    }).catch(() => {});
    const stop = document.getElementById('svc-stop');
    if (stop) stop.onclick = async () => {
        const ok = await confirmDialog({
            title: 'Fermare la protezione?',
            body: 'Da qui in poi <b>niente blocca più nulla</b> e la rete non viene più filtrata, finché non riattivi il servizio.',
            ok: 'Ferma il servizio', danger: true,
        });
        if (!ok) return;
        try {
            if (await bound(ServiceStop, ) === undefined) toast('Non supportato in questa build', true); else toast('Protezione fermata', true);
        } catch (e) { toast('Stop fallito: ' + (e.message || e), true); }
    };
    const tog = document.getElementById('mode-toggle');
    if (tog) tog.onclick = async () => {
        const cur = await bound(ConfigMode, ).catch(() => '');
        switchMode(cur === 'enforce' ? 'audit' : 'enforce');
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

const evSev = e => (e.action === 'blocked' || e.action === 'killed') ? 0 : (e.canary ? 1 : 2);

// Etichetta e classe riga di un evento (condivise da tabella piatta e raggruppata).
function evTag(e) {
    if (e.canary) {
        return e.action === 'killed'
            ? [`<span class="tag tag-block">${ICO_BIRD} KILL</span>`, 'row-block']
            : [`<span class="tag tag-canary">${ICO_BIRD} canary</span>`, 'row-canary'];
    }
    return e.action === 'blocked'
        ? [`<span class="tag tag-block">${ICO_BLOCK} BLOCCO</span>`, 'row-block']
        : [`<span class="tag tag-audit">${ICO_AUDIT} audit</span>`, 'row-audit'];
}

function eventsTableHTML(pool) {
    const listed = [...pool].sort((a, b) => evSevFirst ? (evSev(a) - evSev(b)) : 0);
    const rows = listed.reverse().slice(0, 200).map(e => {
        const [tag, cls] = evTag(e);
        const t = fmtTime(e.time);
        if (e.canary) {
            return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td>canary</td>
            <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.kind || '')}</td><td class="mono">${esc(e.exe || '')} ${esc(e.path || '')}</td></tr>`;
        }
        return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td><button class="linklike" data-rule="${esc(e.rule)}">${esc(e.rule)}</button></td>
        <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.comm)}</td><td class="mono">${esc(e.exe || '(uscito)')}</td></tr>`;
    }).join('');
    return `<table><tr><th>tipo</th><th>ora</th><th>regola</th><th>pid</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
}

// Vista raggruppata: stessi (tipo, regola, exe) in una riga con contatore. In audit lo
// stesso programma (es. il prompt della shell) genera decine di righe identiche che
// nascondono quelle diverse: qui si vede chi e quante volte, non ogni singolo accesso.
function eventsGroupedHTML(pool) {
    const groups = new Map();
    pool.forEach(e => {
        const k = [e.canary ? 'canary' : e.action, e.rule, e.exe || e.comm || e.path].join('|');
        let g = groups.get(k);
        if (!g) { g = {first: e, n: 0}; groups.set(k, g); }
        g.n++; g.last = e;
    });
    let list = [...groups.values()];
    if (evSevFirst) list.sort((a, b) => evSev(a.last) - evSev(b.last));
    else list.reverse();
    const rows = list.slice(0, 200).map(g => {
        const e = g.last;
        const [tag, cls] = evTag(e);
        const rule = e.canary ? 'canary' : `<button class="linklike" data-rule="${esc(e.rule)}">${esc(e.rule)}</button>`;
        return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(fmtTime(e.time))}</td><td>${rule}</td>
        <td class="mono"><b>×${g.n}</b></td><td class="mono">${esc(e.comm || e.kind || '')}</td><td class="mono">${esc(e.exe || e.path || '(uscito)')}</td></tr>`;
    }).join('');
    return `<table><tr><th>tipo</th><th>ultimo</th><th>regola</th><th>volte</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
}

function eventsBarHTML() {
    const chips = [['all', 'tutti'], ['blocked', 'blocchi'], ['audit', 'audit'], ['canary', 'canary']]
        .map(([v, l]) => `<button class="chip${evType === v ? ' on' : ''}" data-t="${v}">${l}</button>`).join('');
    return `<div class="toolbar"><input id="ev-q" type="search" placeholder="Filtra regola, comm, exe, pid…" value="${esc(evSearch)}"><span class="chips">${chips}</span>
    <button id="ev-group" class="chip${evGroup ? ' on' : ''}" title="Una riga per programma, con il numero di accessi">raggruppa</button>
    <button id="ev-sev" class="chip${evSevFirst ? ' on' : ''}" title="Mostra prima blocchi e canary (contro l'alert-fatigue)">⚠️ pericolosi prima</button></div>`;
}

// La vista Eventi e' l'unica con un campo di testo: se a ogni evento in arrivo si
// ricostruisse tutta la pagina, la barra di ricerca perderebbe focus e cursore
// mentre scrivi (con un flood, di continuo; e le composizioni da tastiera con
// accenti si interromperebbero). Quindi la barra si costruisce UNA volta e dopo si
// aggiorna solo la tabella.
function renderEvents() {
    if (!events.length) {
        delete content.dataset.view;
        content.innerHTML = `${h2(ICO_LIST, 'Eventi')}
        <div class="empty"><span class="big">🌊</span><b>Rete calma, niente eventi.</b><br>In audit gli accessi legittimi compaiono qui: passa a enforce solo a log puliti.</div>`;
        return;
    }
    const pool = filterEvents();
    const sub = `${pool.length}/${events.length} eventi (ultimi 200, live)`;
    const body = document.getElementById('ev-body');
    const tableHTML = () => evGroup ? eventsGroupedHTML(pool) : eventsTableHTML(pool);
    if (content.dataset.view === 'events' && body) {
        document.getElementById('ev-sub').textContent = sub;
        body.innerHTML = tableHTML();
        syncEventsBar();
        wireEventLinks();
        return;
    }
    content.dataset.view = 'events';
    content.innerHTML = `${h2(ICO_LIST, 'Eventi')}<p class="sub" id="ev-sub">${sub}</p>
    <div id="ev-bar">${eventsBarHTML()}</div><div id="ev-body">${tableHTML()}</div>`;
    wireEventsBar();
    wireEventLinks();
}

// Riallinea chip e campo di ricerca allo stato (dopo un drill-down da Regole, per esempio)
// senza toccare il campo mentre l'utente ci sta scrivendo.
function syncEventsBar() {
    document.querySelectorAll('#ev-bar .chip[data-t]').forEach(c => c.classList.toggle('on', c.dataset.t === evType));
    const sev = document.getElementById('ev-sev');
    if (sev) sev.classList.toggle('on', evSevFirst);
    const grp = document.getElementById('ev-group');
    if (grp) grp.classList.toggle('on', evGroup);
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
    const grp = document.getElementById('ev-group');
    if (grp) grp.onclick = () => { evGroup = !evGroup; render(); };
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
    // Accessi visti in questa sessione per regola: chi e' attiva e chi e' muta.
    const seen = {};
    events.forEach(e => { if (!e.canary) seen[e.rule] = (seen[e.rule] || 0) + 1; });
    content.innerHTML = `${h2(ICO_KEY, 'Regole')}<p class="sub">${rules.length} gruppi di segreti · solo questi binari leggono questi file</p>` +
        rules.map(r => `<div class="rule"><h3>${ICO_KEY} ${esc(r.name)}${seen[r.name] ? ` <span class="pill">${seen[r.name]} accessi</span>` : ''}</h3>
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
<li><b>Rosso</b> = subnet bloccate, <b>ambra</b> = poisoning (LLMNR/mDNS/NetBIOS). <b>Alone</b> ∝ volume.</li>
<li>Il kernel conta i drop per IP ma <b>non distingue il protocollo</b>.</li>
<li><b>Spazzata blu</b> solo animazione: i dati sono kernel, non dipendono da lei.</li>
<li>Passa il mouse sui blip: si evidenzia la riga in tabella.</li></ul></div>`;

// Rete /24 di un IPv4 (per riassumere "11 sorgenti, tutte nella stessa rete").
function net24(ip) {
    const m = String(ip).match(/^(\d+\.\d+\.\d+)\.\d+$/);
    return m ? m[1] + '.0/24' : ip;
}

function renderRadar() {
    cancelAnimationFrame(radarRAF);
    const src = status.top_sources || status.topSources || [];
    const ipOf = s => s.ip || s.IP || '';
    const nets = new Set(src.map(s => net24(ipOf(s))));
    const summary = src.length
        ? `${src.length} sorgenti in ${nets.size} ${nets.size === 1 ? 'rete (' + [...nets][0] + ')' : 'reti'} · droppate da XDP (dati kernel)`
        : '';
    content.innerHTML = `${h2(ICO_RADAR, 'Radar rete')}
    <p class="sub">${esc(summary)}</p>` +
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
        const ia = hashIP(ipOf(s));
        return {s, t, frac, x: 180 + r * Math.cos(ia), y: 180 + r * Math.sin(ia)};
    });
    // Tabella compatta ordinata per drop: undici schede a tutta larghezza facevano
    // una pagina da 1300 px per dire poche righe.
    const list = document.getElementById('radar-list');
    const sorted = [...radarPts].sort((a, b) => b.t - a.t);
    list.innerHTML = `<table class="compact"><tr><th>IP</th><th>drop</th><th>tipo</th><th>ultimo</th></tr>` + sorted.map(p => {
        const kind = ((p.s.subnet || p.s.Subnet || 0) >= (p.s.poison || p.s.Poison || 0)) ? 'subnet' : 'poisoning';
        const w = Math.max(6, Math.round(p.t / max * 100));
        return `<tr data-ip="${esc(ipOf(p.s))}"><td class="mono">${esc(ipOf(p.s))}</td>
        <td><b>${p.t}</b> <span class="bar"><i class="${kind}" style="width:${w}%"></i></span></td>
        <td>${kind}</td><td class="mono">${esc(fmtTime(p.s.last_seen || p.s.LastSeen))}</td></tr>`;
    }).join('') + '</table>';
    const hl = ip => list.querySelectorAll('tr[data-ip]').forEach(tr => tr.classList.toggle('hl', tr.dataset.ip === ip));
    cv.onmousemove = ev => {
        const r = cv.getBoundingClientRect();
        const mx = (ev.clientX - r.left) * (360 / r.width);
        const my = (ev.clientY - r.top) * (360 / r.height);
        const hit = radarPts.find(p => (p.x - mx) ** 2 + (p.y - my) ** 2 < 18 ** 2);
        if (hit) {
            tip.style.display = 'block';
            tip.style.left = (ev.clientX + 12) + 'px';
            tip.style.top = (ev.clientY + 12) + 'px';
            tip.textContent = `${ipOf(hit.s)} · ${hit.t} drop`;
            hl(ipOf(hit.s));
        } else { tip.style.display = 'none'; hl(''); }
    };
    cv.onmouseleave = () => { tip.style.display = 'none'; hl(''); };
    // Scia: ultime 8 posizioni della spazzata, alpha decrescente.
    const trail = [];
    function frame() {
        radarAngle = (radarAngle + 2) % 360;
        trail.push(radarAngle);
        if (trail.length > 8) trail.shift();
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
    content.innerHTML = `${h2(ICO_HELP, 'Guida avvio')}<p class="sub">Il demone vuole root, le UI no. Segui i passi, uno alla volta.</p>
    <p><button class="chip on" id="guide-replay">↺ Rivedi introduzione guidata</button></p>` +
        renderGuideBody() +
        `<p class="sub">Solo demo senza root: <code>ZT_SOCKET=/tmp/z.sock zt-mockd &amp;</code> + UI con stesso socket (dati finti).</p>`;
    const rp = document.getElementById('guide-replay');
    // Replay: azzera passo e flag, mostra da capo. Per chi ha saltato troppo in fretta.
    if (rp) rp.onclick = () => {
        try { localStorage.removeItem('zs-onboarded-v2'); } catch (_) {}
        obStep = 0;
        showOnboarding();
    };
}

// Chi usa questa GUI l'ha quasi sempre installata dal pacchetto .deb (che tira dentro
// il demone): niente "make build", e la config esiste gia', quindi si MODIFICA, non si
// copia sopra. Il percorso da sorgente resta, in coda.
const GUIDE_PKG = [
    ['1 · Installa', 'Un solo pacchetto contiene demone, TUI e GUI. Il servizio non parte da solo.', 'sudo apt install ./zeroshield_*_amd64.deb'],
    ['2 · Imposta l\'utente', 'Apri la config e scrivi il tuo utente in <b>user:</b>. Resta in <b>audit</b> (non blocca nulla). Il socket sarà leggibile solo da root e da quell\'utente.', 'sudoedit /etc/zt-shield/shield.yaml'],
    ['3 · Verifica il kernel', 'Ogni programma eBPF deve risultare ✅ e <b>bpf</b> deve comparire tra gli LSM attivi.', 'sudo zt-probe -xdp-lo && cat /sys/kernel/security/lsm'],
    ['4 · Avvia in audit', 'Poi guarda questa GUI popolarsi (o <span class="mono">zt-tui</span>).', 'sudo systemctl enable --now zt-shield && journalctl -u zt-shield -f'],
    ['5 · Passa a enforce', 'Solo a log puliti: nessun accesso legittimo negato per errore. Dal tab Configurazione, oppure imposta <b>mode: enforce</b> nel file e riavvia.', 'sudo systemctl restart zt-shield'],
];
const GUIDE_SRC = [
    ['1 · Prerequisiti', 'Kernel ≥5.15 con BTF e voce <b>bpf</b> in <span class="mono">/sys/kernel/security/lsm</span> (senza: GRUB + reboot, vedi README).', 'bash scripts/check_prereqs.sh'],
    ['2 · Compila', 'Toolchain eBPF + binari demone e TUI.', 'make build'],
    ['3 · Configura', 'Copia l\'esempio SENZA sovrascrivere una config esistente (-n), poi imposta <b>user:</b> e resta in audit.', 'sudo mkdir -p /etc/zt-shield && sudo cp -n configs/shield.example.yaml /etc/zt-shield/shield.yaml'],
    ['4 · Prova in primo piano', 'Demone in audit: logga senza negare. Serve root (eBPF).', 'sudo SHIELD_USER=$USER ./bin/zt-shield'],
    ['5 · Servizio', 'Installa come servizio (a log puliti: mode enforce + restart).', 'sudo bash scripts/install_service.sh $USER home'],
];

// Corpo guida riusabile anche offline (tab Guida senza demone). Da sorgente e' chiuso di
// default: chi ha il pacchetto non deve scorrere dieci passi per trovare i suoi cinque.
function renderGuideBody() {
    const block = steps => steps.map(([t, d, c]) => `<div class="rule"><h3>${esc(t)}</h3><div>${d}</div>
        <div style="margin-top:6px">${codeRow(c)}</div></div>`).join('');
    return `<h2 style="margin-top:14px">Da pacchetto .deb (consigliato)</h2>${block(GUIDE_PKG)}
    <details class="src"><summary>Da sorgente (sviluppo)</summary>${block(GUIDE_SRC)}</details>`;
}

// Stato VPN: il verde richiede tunnel su E kill-switch attivo (misurati dal demone, non
// dedotti dal config). Un tunnel su senza kill-switch protegge solo finche' regge.
function vpnPanel(v) {
    if (!v.enabled) {
        return `<div class="rule neutral"><h3>🔓 VPN non monitorata</h3><div class="sub" style="margin:0">Nessuna stanza <code>vpn:</code> nel config: su rete ostile esci in chiaro.</div></div>`;
    }
    const hs = (typeof v.handshake_age === 'number' && v.handshake_age >= 0)
        ? `handshake ${v.handshake_age}s fa` : 'handshake mai/sconosciuto';
    const line = `<span class="mono">${esc(v.tunnel)} → ${esc(v.endpoint)}</span> · ${hs}`;
    if (v.up && v.killswitch) {
        return `<div class="rule ok"><h3>🔒 VPN protetta</h3><div>${line} · kill-switch attivo</div></div>`;
    }
    if (v.up) {
        return `<div class="warn">${ICO_WARN}<div>VPN su ma kill-switch NON attivo: se il tunnel cade esci in chiaro.<br>${line}<br>
        <span class="sub">Attivalo: <code>vpn_killswitch.sh on ${esc(v.endpoint)} ${esc(v.tunnel)}</code> (vedi docs/VPN_SETUP.md)</span></div></div>`;
    }
    if (v.killswitch) {
        return `<div class="warn">${ICO_WARN}<div>VPN giù (${esc(v.tunnel || '?')} assente), kill-switch attivo: sei offline ma non in chiaro. Alza il tunnel.</div></div>`;
    }
    return `<div class="warn">${ICO_WARN}<div>VPN GIÙ (${esc(v.tunnel || '?')} assente) e nessun kill-switch: sei in chiaro! Alza il tunnel o esci dalla rete.</div></div>`;
}

// IPv6 va tra parentesi, altrimenti "::1:22" non si legge.
function hostPort(addr, port) {
    return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

function renderNet() {
    const subs = status.block_subnets || [];
    const xdp = status.xdp || [];
    content.innerHTML = `${h2(ICO_GLOBE, 'Rete')}<p class="sub">Cosa filtra il demone e cosa è esposto.</p>
    ${sec('VPN')}${vpnPanel(status.vpn || {})}
    ${sec('Filtro XDP')}
    <div class="panel">
      ${kv('Interfacce coperte', xdp.length ? xdp.map(x => `<span class="mono">${esc(x)}</span>`).join(', ') : '<span class="dot-off">nessuna: XDP spento</span>', 'Le altre interfacce attive non sono filtrate (vedi <span class="mono">interface:</span> in Configurazione).')}
      ${kv('Drop poisoning', status.block_poisoning ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento', 'LLMNR, mDNS, NetBIOS. Dettaglio per IP nel tab Radar.')}
      ${kv('Subnet bloccate', subs.length ? subs.map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : 'nessuna', subs.length ? 'Il drop scarta anche le risposte da queste reti: mai gateway/DNS.' : 'Solo drop poisoning + UFW.')}
    </div>` + renderListening();
}

// Porte in ascolto (TCP e UDP: mDNS/LLMNR sono la superficie che XDP difende).
// Se non riconosci una riga, è quella da investigare.
function renderListening() {
    const ls = status.listening || [];
    if (!ls.length) return `${sec('In ascolto')}<p class="sub">Nessuna porta in ascolto.</p>`;
    const rows = ls.map(l => {
        const who = l.exe ? `<span class="mono">${esc(l.exe)}</span> <span class="mono">pid=${l.pid}</span>` : '<i>sconosciuto: processo di altri o già uscito</i>';
        const open = l.addr === '0.0.0.0' || l.addr === '::' ? ' 🌐' : '';
        return `<tr><td class="mono">${esc(l.proto)}</td><td class="mono">${esc(hostPort(l.addr, l.port))}${open}</td><td>${who}</td></tr>`;
    }).join('');
    const total = status.listening_total || ls.length;
    const cut = total > ls.length ? `<p class="sub">… mostrate ${ls.length} di ${total}</p>` : '';
    return `${sec('In ascolto')}<p class="sub">Superficie esposta · 🌐 = su tutte le interfacce. Se non riconosci una riga, investigala.</p>
    <table><tr><th>proto</th><th>porta</th><th>processo</th></tr>${rows}</table>${cut}`;
}

async function boot() {
    try {
        status = await GetStatus();
        lastStatusAt = Date.now(); // senza questo "dati fermi da <epoch>s" fino al primo push
    } catch (e) {
        offlineMsg = String(e && e.message || e);
        try { offlineMsg += ' — socket: ' + await SocketPath(); } catch (_) {}
    }
    render();
    // Versione dal binario (ldflags al build): se manca il binding, nessun errore.
    try { appVersion = await Version(); requestRender(); } catch (_) {}
    // Onboarding: se demone mai visto. Salta = solo questa sessione
    // (sessionStorage), Ho capito = per sempre (localStorage). Così chi
    // skippa per sbaglio rivede il wizard al prossimo avvio.
    try {
        if (!status && !localStorage.getItem('zs-onboarded-v2') && !sessionStorage.getItem('zs-skip')) {
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
    ['1 · Chi proteggiamo e dove?',
     'Utente da proteggere + profilo iniziale (sempre <b>audit</b>: logga senza bloccare). Premi Installa: config, servizio e avvio in un colpo solo.',
     'USER_INPUT'],
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
    // Step 1 (indice 1): utente + profilo + installa mirato. Configura davvero,
    // non spiega soltanto: alla fine di questo step il servizio gira in audit.
    const userBox = c === 'USER_INPUT'
        ? `<div class="ob-user"><input id="ob-user" placeholder="il tuo utente Linux" autocomplete="off"></div>
           <div class="ob-profiles">
             <button class="chip prof on" data-p="home">🏠 home</button>
             <button class="chip prof" data-p="corporate">🏢 corporate</button>
             <button class="chip prof" data-p="public-wifi">📶 public-wifi</button>
             <button class="chip prof" data-p="paranoid">🔒 paranoid</button>
           </div>
           <div class="sub" id="ob-prof-desc">home: audit, regole base. Il profilo giusto per iniziare.</div>
           <div><button id="ob-install" class="chip on big">⬇ Installa e attiva</button> <span class="sub" id="ob-msg"></span></div>`
        : '';
    ov.innerHTML = `<div class="ob-card"><h2>${t}</h2><p>${d}</p>` + userBox +
        (c && c !== 'USER_INPUT' ? `<pre>${esc(c)}</pre>` : '') +
        `<div class="ob-dots">${dots}</div>
        <div class="ob-btns">
          <button id="ob-skip" class="chip">Salta</button>
          ${obStep > 0 ? '<button id="ob-back" class="chip">← Indietro</button>' : ''}
          ${obStep < OB_STEPS.length - 1
            ? '<button id="ob-next" class="chip on">Avanti →</button>'
            : '<button id="ob-done" class="chip on">Ho capito ✓</button>'}
        </div></div>`;
    const done = (remember) => {
        try {
            if (remember) localStorage.setItem('zs-onboarded-v2', '1');
            else sessionStorage.setItem('zs-skip', '1');
        } catch (_) {}
        ov.remove();
    };
    document.getElementById('ob-skip').onclick = () => done(false);
    document.getElementById('ob-done') && (document.getElementById('ob-done').onclick = () => done(true));
    const nx = document.getElementById('ob-next');
    if (nx) nx.onclick = () => { obStep++; showOnboarding(); };
    const bk = document.getElementById('ob-back');
    if (bk) bk.onclick = () => { obStep--; showOnboarding(); };
    const ins = document.getElementById('ob-install');
    const PROF_DESC = {
        home: 'home: audit, regole base. Il profilo giusto per iniziare.',
        corporate: 'corporate: enforce da subito, DNS interni mantenuti. Solo se sai cosa fai.',
        'public-wifi': 'public-wifi: enforce + segreti browser + DoT. Per reti ostili.',
        paranoid: 'paranoid: come public-wifi ma DoT rigido (rompe i captive portal).',
    };
    let obProfile = 'home';
    document.querySelectorAll('#onboard .chip.prof').forEach(ch => {
        ch.onclick = () => {
            document.querySelectorAll('#onboard .chip.prof').forEach(x => x.classList.remove('on'));
            ch.classList.add('on');
            obProfile = ch.dataset.p;
            const dd = document.getElementById('ob-prof-desc');
            if (dd) dd.textContent = PROF_DESC[obProfile] || '';
        };
    });
    if (ins) ins.onclick = async () => {
        const u = (document.getElementById('ob-user').value || '').trim();
        const msg = document.getElementById('ob-msg');
        if (!u) { msg.textContent = 'Scrivi prima il tuo utente.'; return; }
        if (!/^[a-z_][a-z0-9_-]*$/i.test(u)) { msg.textContent = 'Nome utente non valido.'; return; }
        ins.textContent = '…';
        try {
            if (typeof ServiceInstallAs !== 'function') throw new Error('non supportato in questa build');
            await ServiceInstallAs(u, obProfile);
            msg.textContent = `Installato (${obProfile}) e attivo in audit per ${u}. Chiudi e guarda lo Stato.`;
        } catch (e) { msg.textContent = 'Fallito: ' + (e.message || e); }
        ins.textContent = '⬇ Installa e attiva';
    };
}

EventsOn('shield:status', st => { status = st; statusSeq++; lastStatusAt = Date.now(); offlineMsg = ''; requestRender(); });
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
