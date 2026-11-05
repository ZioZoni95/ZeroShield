// ZeroShield GUI — client IPC: primo paint via GetStatus, poi push live.
// Solo lettura: nessun'azione privilegiata da qui (cambio mode via config+restart).
import {GetStatus, SocketPath, Version, ServiceState, ServiceInstall, ServiceInstallAs, ServiceStart, ServiceStop, BootEnabled, SetBootEnabled, ConfigMode, SetConfigMode, ConfigText, Preflight, RulesModel, CheckProgram, ApplyRules, MakeTrusted, PreviewPaths, PickPath, ApplyInterfaces} from '../wailsjs/go/main/App.js';
import {createRulesView} from './rules.js';
import {statusHtml} from './statuspage.js';
import {createIfaceView} from './ifaces.js';
import {WHATS_NEW, baseVersion, pickWhatsNew} from './whatsnew.js';
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
// "Novita'": popup una sola volta per versione (vedi whatsnew.js). Cliccando la versione in fondo alla
// barra laterale si riapre quando vuoi.
function lsGet(k) { try { return localStorage.getItem(k) || ''; } catch (_) { return ''; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* senza storage: si rivede a ogni avvio, nessun danno */ } }
function showWhatsNew(manual, list) {
    // list: voci [versione, {title, items, note}] da mostrare; senza, la voce della versione in uso.
    const cur = WHATS_NEW[baseVersion(appVersion)];
    const entries = list || (cur ? [[baseVersion(appVersion), cur]] : []);
    if (!entries.length) { if (manual) toast('Nessuna novità registrata per questa versione.'); return; }
    if (document.getElementById('dlg')) return;
    const ov = document.createElement('div');
    ov.id = 'dlg';
    const title = entries.length === 1 ? entries[0][1].title : 'Novità dalle ultime versioni';
    const body = entries.map(([v, w]) => `${entries.length > 1 ? `<h3 class="wn-v">${esc(w.title)}</h3>` : ''}
        <ul class="wn-list">${w.items.map(([t, d]) => `<li><b>${esc(t)}</b><span>${esc(d)}</span></li>`).join('')}</ul>
        ${w.note ? `<p class="wn-note">${esc(w.note)}</p>` : ''}`).join('');
    ov.innerHTML = `<div class="ob-card wn" role="dialog" aria-modal="true" aria-label="${esc(title)}"><h2>${esc(title)}</h2>${body}
        <div class="ob-btns"><button class="chip on" id="wn-ok">Ho capito</button></div></div>`;
    document.body.appendChild(ov);
    const done = () => { document.removeEventListener('keydown', onKey, true); ov.remove(); };
    const onKey = e => { if (e.key === 'Escape' || e.key === 'Enter') { e.stopPropagation(); done(); } };
    document.addEventListener('keydown', onKey, true);
    ov.querySelector('#wn-ok').onclick = done;
    ov.addEventListener('click', e => { if (e.target === ov) done(); });
    ov.querySelector('#wn-ok').focus();
}
function maybeWhatsNew() {
    const r = pickWhatsNew(appVersion, lsGet('zs-seen-version'), !!lsGet('zs-onboarded-v2'));
    if (r.remember) lsSet('zs-seen-version', r.base);
    if (r.show) showWhatsNew(false, r.show);
}

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
    const label = el.closest('.card, .tile')?.querySelector('.k, .tile-k')?.textContent || '';
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
    if (!force && key === lastKey && view !== 'events' && view !== 'radar' && view !== 'rules') return;
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
    if (view === 'rules') return renderRules(force);
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
    let boot = null; // null = questa build non lo sa dire
    try { const b = await bound(BootEnabled, ); if (typeof b === 'boolean') boot = b; } catch (_) {}
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
      ${boot === null ? '' : kv('Avvio all\'accensione', `<button class="chip${boot ? ' on' : ''}" id="boot-toggle" aria-pressed="${boot}">${boot ? '● Attivo' : '○ Spento'}</button>`,
        boot ? 'Il demone parte da solo a ogni accensione. Spegnerlo lascia il PC senza protezione finché non lo avvii tu.' : 'Il demone NON parte da solo: dopo un riavvio il PC resta senza protezione. Attivalo per avviarlo a ogni accensione.')}
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
    const bt = document.getElementById('boot-toggle');
    if (bt) bt.onclick = async () => {
        const want = !boot;
        if (!want && !await confirmDialog({title: 'Spegnere l\'avvio all\'accensione?', body: 'Dopo il prossimo riavvio il PC resterà <b>senza protezione</b> finché non avvii tu il demone.', ok: 'Spegni', danger: true})) return;
        bt.textContent = '…';
        try {
            if (await bound(SetBootEnabled, want) === undefined) toast('Non supportato in questa build', true);
            else toast(want ? 'Il demone partirà a ogni accensione' : 'Avvio all\'accensione spento', !want);
        } catch (e) { toast('Non riuscito: ' + (e.message || e), true); }
        renderConfig();
    };
    const target = m => () => { if (!(m === running && !mismatch)) switchMode(m); };
    const ba = document.getElementById('m-audit');
    if (ba) ba.onclick = target('audit');
    const be = document.getElementById('m-enforce');
    if (be) be.onclick = target('enforce');
}

// Demo: un finto demone con dati inventati, per vedere la GUI senza root, senza installare e
// senza toccare il demone vero. E' lo stesso blocco ovunque si proponga la demo (primo avvio,
// demone spento, Guida), cosi' i comandi sono sempre gli stessi e copiabili.
function demoBlock() {
    return `<p class="sub">Mostra le schermate con dati inventati (compreso un canary finto ogni pochi secondi): non prova la protezione e non tocca il demone vero.</p>
    ${codeRow('ZT_SOCKET=/tmp/z.sock zt-mockd &')}
    <div style="margin-top:6px">${codeRow('ZT_SOCKET=/tmp/z.sock zt-gui')}</div>
    <div style="margin-top:6px">${codeRow('pkill zt-mockd')}</div>
    <p class="sub" style="margin:6px 0 0">Il secondo comando apre una seconda finestra collegata al finto demone; l'ultimo lo ferma. Dai sorgenti: <span class="mono">./bin/zt-mockd</span> e <span class="mono">./zt-gui/build/bin/zt-gui</span>.</p>`;
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
    <details><summary>Prova con dati finti (senza installare)</summary>
    <div style="margin-top:10px">${demoBlock()}</div></details>
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
      <div class="card"><div class="k">Solo avvia (già installato)</div><div><button class="chip on" id="svc-start">▶ Attiva protezione</button></div><div class="sub">enable --now via pkexec. Serve <code>user:</code> nel config (vedi i controlli sopra).</div></div>
      <div class="card"><div class="k">A mano (VM)</div><div><code>sudo systemctl enable --now zt-shield</code></div><div class="sub">prima <code>user:</code> in shield.yaml · audit</div></div>
      <div class="card"><div class="k">Prova con dati finti</div>${demoBlock()}</div>
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
    // Versioni a confronto: demone e finestra possono essere di release diverse dopo un aggiornamento
    // a meta' (il demone si riavvia a mano, la finestra no). Si confronta solo X.Y.Z.
    const dv = baseVersion(status.version), gv = baseVersion(appVersion);
    const mismatch = dv && gv && dv !== gv
        ? `Il demone è alla versione ${status.version} ma questa finestra è la ${appVersion}: riavvia il servizio e la finestra per allinearle.` : '';
    content.innerHTML = statusHtml({status, events, esc, fmtTime, icons: {gauge: ICO_GAUGE, warn: ICO_WARN}, appVersion, daemonMismatch: mismatch, svcOk: true});
    const heroAct = document.getElementById('hero-act');
    if (heroAct) heroAct.onclick = () => switchMode('enforce');
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

// La schermata Regole vive in rules.js (ha stato proprio: bozza, controlli asincroni, barra "Applica").
const rulesView = createRulesView({
    content, esc,
    api: {RulesModel, CheckProgram, ApplyRules, MakeTrusted, PreviewPaths, PickPath},
    getStatus: () => status,
    getEvents: () => events,
    confirmDialog, toast,
    icons: {key: ICO_KEY, warn: ICO_WARN},
    active: () => view === 'rules',
    goto: v => go(v),
});
function renderRules(force) { return rulesView.render(force); }

// Scelta delle interfacce (stessa idea di Regole: bozza in un modulo, «Applica» scrive il config).
const ifaceView = createIfaceView({
    esc, api: {RulesModel, ApplyInterfaces},
    getStatus: () => status, confirmDialog, toast,
    repaint: () => { if (view === 'net') paintIfaces(); },
});
function paintIfaces() {
    const box = document.getElementById('if-box');
    if (!box) return;
    box.innerHTML = ifaceView.html();
    ifaceView.bind(box);
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

// --- Radar: quali sorgenti sono sottofondo di rete e quali vanno guardate ---
//
// XDP scarta LLMNR/mDNS/NetBIOS in ingresso e conta i drop per IP. Il contatore non sa se il
// pacchetto era una RICHIESTA di un altro host (normale in una LAN: Windows, stampanti, Avahi)
// o una RISPOSTA avvelenata (Responder/Inveigh). Quindi la GUI non puo' dire "attacco": dice
// "rumore probabile" o "da verificare" con regole semplici e dichiarate, e lascia all'utente la
// conferma (comandi per verificare, "segna come noto").
const RADAR_BURST_PER_MIN = 20; // drop/min sostenuti da un solo IP
const RADAR_HIGH_TOTAL = 100;   // drop cumulati da un solo IP dall'avvio del demone
const RADAR_CLS = {
    noise: {label: 'rumore probabile', col: '120,120,134'},
    attention: {label: 'da verificare', col: '224,138,0'},
    blocked: {label: 'bloccata', col: '215,0,21'},
    known: {label: 'nota', col: '29,129,39'},
};

// Storico dei contatori per IP, per stimare il tasso. Si usa l'orario del demone (status.time),
// non quello della GUI: cosi' la stima non dipende da quando si e' aperta la finestra.
const radarHist = new Map(); // ip -> [{t, total}]
function recordRadar(st) {
    const src = (st && (st.top_sources || st.topSources)) || [];
    const t = Date.parse(st && st.time) || Date.now();
    src.forEach(s => {
        const ip = s.ip || s.IP || '';
        const total = s.total || s.Total || 0;
        let h = radarHist.get(ip);
        if (!h) { h = []; radarHist.set(ip, h); }
        if (h.length && total < h[h.length - 1].total) h.length = 0; // contatori ripartiti (demone riavviato)
        if (!h.length || t > h[h.length - 1].t) h.push({t, total});
        while (h.length > 1 && t - h[0].t > 10 * 60000) h.shift();
    });
}
// Drop al minuto osservati dalla GUI; null finche' non c'e' almeno un minuto di storico.
function srcRate(ip) {
    const h = radarHist.get(ip);
    if (!h || h.length < 2) return null;
    const dt = (h[h.length - 1].t - h[0].t) / 60000;
    return dt < 1 ? null : Math.max(0, (h[h.length - 1].total - h[0].total) / dt);
}

// Host che l'utente ha riconosciuto: preferenza per-utente, quindi localStorage (se manca, in memoria).
let knownMem = null;
function knownSet() {
    if (knownMem) return knownMem;
    try { knownMem = new Set(JSON.parse(localStorage.getItem('zs-radar-known') || '[]')); }
    catch (_) { knownMem = new Set(); }
    return knownMem;
}
function toggleKnown(ip) {
    const k = knownSet();
    if (k.has(ip)) k.delete(ip); else k.add(ip);
    try { localStorage.setItem('zs-radar-known', JSON.stringify([...k])); } catch (_) {}
}

// Espande un IPv6 ("fe80::1") nei suoi 8 gruppi; null se non e' un IPv6 leggibile.
function expand6(ip) {
    const s = String(ip).split('%')[0];
    if (!s.includes(':')) return null;
    const [head, tail] = s.split('::');
    const h = head ? head.split(':') : [];
    const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
    const fill = tail !== undefined ? Array(Math.max(0, 8 - h.length - t.length)).fill('0') : [];
    const g = [...h, ...fill, ...t];
    return g.length === 8 ? g.map(x => (x || '0').toLowerCase().replace(/^0+(?=.)/, '')) : null;
}
// Rete di un indirizzo, per riassumere "11 sorgenti, tutte nella stessa rete": /24 per IPv4, /64 per IPv6
// (la rete locale di un'interfaccia IPv6 e' un /64).
function net24(ip) {
    const g = expand6(ip);
    if (g) return g.slice(0, 4).join(':') + '::/64';
    const m = String(ip).match(/^(\d+\.\d+\.\d+)\.\d+$/);
    return m ? m[1] + '.0/24' : ip;
}
const famOf = ip => (String(ip).includes(':') ? 6 : 4);
// Rete in cui cade la maggioranza (>= 60%) delle sorgenti della STESSA famiglia: la LAN. Con meno di 3 sorgenti non si
// stima. Le famiglie si valutano a parte: una sorgente IPv6 non e' "fuori rete" solo perche' le altre sono IPv4.
function dominantNet(src) {
    const out = {4: null, 6: null};
    [4, 6].forEach(f => {
        const own = src.filter(s => famOf(s.ip || s.IP || '') === f);
        if (own.length < 3) return;
        const c = {};
        own.forEach(s => { const n = net24(s.ip || s.IP || ''); c[n] = (c[n] || 0) + 1; });
        const [n, k] = Object.entries(c).sort((x, y) => y[1] - x[1])[0];
        if (k / own.length >= 0.6) out[f] = n;
    });
    return out;
}

function classify(s, domNet) {
    const ip = s.ip || s.IP || '';
    const total = s.total || s.Total || 0;
    if (knownSet().has(ip)) return {cls: 'known', why: 'segnata da te come host noto'};
    if ((s.subnet || s.Subnet || 0) > 0) return {cls: 'blocked', why: 'rete bloccata da una tua regola (block_subnets)'};
    const why = [];
    const rate = srcRate(ip);
    if (rate !== null && rate >= RADAR_BURST_PER_MIN) why.push(`${Math.round(rate)} drop/min sostenuti`);
    if (total >= RADAR_HIGH_TOTAL) why.push(`${total} drop in totale`);
    const dn = domNet && domNet[famOf(ip)];
    if (dn && net24(ip) !== dn) why.push(`fuori dalla rete delle altre sorgenti (${dn})`);
    if (why.length) return {cls: 'attention', why: why.join(' · ')};
    return {cls: 'noise', why: 'pochi drop, stessa rete delle altre: tipico sottofondo di una LAN'};
}

function rateText(ip) {
    const r = srcRate(ip);
    if (r === null) return '<span class="sub">in osservazione</span>';
    return r < 0.5 ? '&lt;1/min' : `${r.toFixed(1)}/min`;
}

function radarLegend() {
    const dot = c => `<span class="dotkey" style="background:rgb(${RADAR_CLS[c].col})"></span>`;
    return `<div id="radar-legend"><h4>Come leggerlo</h4>
    <h5>Cosa vedi</h5>
    <p>Ogni punto è un indirizzo da cui XDP ha scartato traffico di scoperta di rete (LLMNR, mDNS, NetBIOS) <b>prima</b> che il sistema lo vedesse. Più è lontano dal centro, più pacchetti ha mandato (scala logaritmica). La posizione di un IP è sempre la stessa.</p>
    <h5>Colori</h5>
    <ul class="keys">
      <li>${dot('noise')}<b>Rumore probabile</b>: pochi pacchetti, stessa rete delle altre sorgenti.</li>
      <li>${dot('attention')}<b>Da verificare</b>: almeno ${RADAR_BURST_PER_MIN} drop/min costanti, oppure ${RADAR_HIGH_TOTAL} drop in totale, oppure una rete diversa da quella delle altre.</li>
      <li>${dot('blocked')}<b>Bloccata</b>: rete che hai messo tu in <span class="mono">block_subnets</span>.</li>
      <li>${dot('known')}<b>Nota</b>: host che hai segnato come riconosciuto.</li>
    </ul>
    <h5>Rumore o attacco?</h5>
    <p>In una LAN host e stampanti mandano di continuo queste richieste: è sottofondo. Un attacco tipo Responder risponde alle richieste altrui e si vede come <b>una sola sorgente con molti pacchetti, in modo costante</b>, o da una rete diversa. Il contatore però <b>non distingue</b> richieste da risposte: la classificazione è una stima, non un verdetto.</p>
    <h5>Cosa fare</h5>
    <p>Su un punto «da verificare» usa i comandi sotto la tabella per capire chi è. Se lo riconosci, «segna come noto».</p>
    <p class="sub" style="margin:0">Il tasso si vede dopo circa un minuto di osservazione. L'alone segue il volume; la spazzata blu è solo animazione.</p></div>`;
}

function renderRadar() {
    cancelAnimationFrame(radarRAF);
    const src = status.top_sources || status.topSources || [];
    const ipOf = s => s.ip || s.IP || '';
    const nets = new Set(src.map(s => net24(ipOf(s))));
    const summary = src.length
        ? `${src.length} sorgenti in ${nets.size} ${nets.size === 1 ? 'rete (' + [...nets][0] + ')' : 'reti'} · droppate da XDP (dati kernel)`
        : '';
    if (!src.length) {
        content.innerHTML = `${h2(ICO_RADAR, 'Radar rete')}<p class="sub"></p>
        <div class="empty"><span class="big">📡</span><b>Radar vuoto: nessun drop XDP.</b><br>Rete calma o demone appena partito. Genera poisoning in lab per vedere i blip.</div>`;
        return;
    }
    const dom = dominantNet(src);
    const classed = src.map(s => {
        const t = s.total || s.Total || 0;
        return Object.assign({s, ip: ipOf(s), t}, classify(s, dom));
    });
    const n = c => classed.filter(p => p.cls === c).length;
    const att = n('attention');
    const parts = [];
    if (n('noise')) parts.push(`${n('noise')} di rumore probabile`);
    if (n('blocked')) parts.push(`${n('blocked')} bloccate dalle tue subnet`);
    if (n('known')) parts.push(`${n('known')} note`);
    const title = att ? `${att} ${att === 1 ? 'sorgente da verificare' : 'sorgenti da verificare'}` : 'Nessuna sorgente da verificare';
    content.innerHTML = `${h2(ICO_RADAR, 'Radar rete')}
    <p class="sub">${esc(summary)}</p>
    <div class="verdict ${att ? 'warn' : 'ok'}"><div class="verdict-t">${att ? '◐' : '●'} ${esc(title)}</div>
      <ul>${parts.length ? `<li>${esc(parts.join(' · '))}</li>` : ''}
      <li>Il kernel non distingue richieste normali da risposte avvelenate: è una stima, non un verdetto.</li></ul></div>
    <div id="radar-wrap"><canvas id="radar" width="360" height="360"></canvas>${radarLegend()}</div>
    <div id="radar-list"></div><div id="radar-verify"></div>`;
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
    classed.forEach(p => { if (p.t > max) max = p.t; });
    radarPts = classed.map(p => {
        const frac = Math.log10(p.t + 1) / Math.log10(max + 1);
        const r = 30 + 145 * frac;
        const ia = hashIP(p.ip);
        return Object.assign({frac, x: 180 + r * Math.cos(ia), y: 180 + r * Math.sin(ia)}, p);
    });
    // Tabella compatta ordinata per drop, con esito e motivo: undici schede a tutta larghezza
    // facevano una pagina da 1300 px per dire poche righe.
    const list = document.getElementById('radar-list');
    const sorted = [...radarPts].sort((a, b) => b.t - a.t);
    list.innerHTML = `<table class="compact"><tr><th>IP</th><th>Esito</th><th>Drop</th><th>Tasso</th><th>Ultimo</th><th></th></tr>` + sorted.map(p => {
        const w = Math.max(6, Math.round(p.t / max * 100));
        const known = p.cls === 'known';
        return `<tr data-ip="${esc(p.ip)}" data-class="${p.cls}"><td class="mono">${esc(p.ip)}</td>
        <td><span class="cls cls-${p.cls}">${RADAR_CLS[p.cls].label}</span><span class="why">${esc(p.why)}</span></td>
        <td><b>${p.t}</b> <span class="bar"><i class="${p.cls}" style="width:${w}%"></i></span></td>
        <td>${rateText(p.ip)}</td><td class="mono">${esc(fmtTime(p.s.last_seen || p.s.LastSeen))}</td>
        <td>${p.cls === 'blocked' ? '' : `<button class="linklike" data-known="${esc(p.ip)}">${known ? 'togli nota' : 'segna come noto'}</button>`}</td></tr>`;
    }).join('') + '</table>';
    list.querySelectorAll('[data-known]').forEach(b => {
        b.onclick = () => { toggleKnown(b.dataset.known); render(true); };
    });
    // Come verificare: solo per le sorgenti da verificare (le prime tre), con comandi copiabili.
    // L'IP viene dal demone ma si controlla comunque il formato prima di metterlo in un comando.
    const iface = (status.xdp && status.xdp[0]) || '<interfaccia>';
    const toCheck = sorted.filter(p => p.cls === 'attention' && /^[0-9a-f:.]+$/i.test(p.ip)).slice(0, 3);
    document.getElementById('radar-verify').innerHTML = toCheck.length
        ? sec('Come verificare') + `<p class="sub">Il primo comando mostra l'indirizzo hardware dell'host se è sulla tua rete (poi cerca il produttore, o confrontalo con gateway, stampanti, colleghi). Il secondo cattura i pacchetti: se vedi risposte da porta 5355 o 137 verso di te senza aver fatto una richiesta, è il segnale tipico di un attacco.</p>` +
          toCheck.map(p => `<div class="rule neutral"><h3><span class="mono">${esc(p.ip)}</span> <span class="cls cls-attention">${esc(p.why)}</span></h3>
          ${codeRow(`ip neigh show ${p.ip}`)}
          <div style="margin-top:6px">${codeRow(`sudo tcpdump -ni ${iface} -c 30 'udp and host ${p.ip} and (port 5355 or port 5353 or port 137 or port 138)'`)}</div></div>`).join('')
        : '';
    cv.onmousemove = ev => {
        const r = cv.getBoundingClientRect();
        const mx = (ev.clientX - r.left) * (360 / r.width);
        const my = (ev.clientY - r.top) * (360 / r.height);
        const hit = radarPts.find(p => (p.x - mx) ** 2 + (p.y - my) ** 2 < 18 ** 2);
        const hl = ip => list.querySelectorAll('tr[data-ip]').forEach(tr => tr.classList.toggle('hl', tr.dataset.ip === ip));
        if (hit) {
            tip.style.display = 'block';
            tip.style.left = (ev.clientX + 12) + 'px';
            tip.style.top = (ev.clientY + 12) + 'px';
            tip.textContent = `${hit.ip} · ${hit.t} drop · ${RADAR_CLS[hit.cls].label}`;
            hl(hit.ip);
        } else { tip.style.display = 'none'; hl(''); }
    };
    cv.onmouseleave = () => { tip.style.display = 'none'; list.querySelectorAll('tr.hl').forEach(tr => tr.classList.remove('hl')); };
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
            const col = RADAR_CLS[p.cls].col;
            const R = 4 + 5 * p.frac;
            const grad = cx.createRadialGradient(p.x, p.y, 1, p.x, p.y, R * 3);
            grad.addColorStop(0, `rgba(${col},${p.cls === 'noise' ? 0.3 : 0.55})`);
            grad.addColorStop(1, `rgba(${col},0)`);
            cx.beginPath(); cx.arc(p.x, p.y, R * 3, 0, 7);
            cx.fillStyle = grad; cx.fill();
            cx.beginPath(); cx.arc(p.x, p.y, R, 0, 7);
            cx.fillStyle = `rgb(${col})`; cx.fill();
            cx.beginPath(); cx.arc(p.x, p.y, R, 0, 7);
            cx.strokeStyle = '#fff'; cx.lineWidth = 1.5; cx.stroke();
        });
        radarRAF = requestAnimationFrame(frame);
    }
    frame();
}

// Guida: schede brevi invece di un muro di passi. "Per iniziare" parte dallo stato reale
// (cosa e' gia' a posto), le altre spiegano le schermate, i termini e i problemi comuni.
// Niente viene eseguito da qui: i comandi si copiano e si lanciano nel proprio terminale.
let guideTab = 'start';
const GUIDE_TABS = [['start', 'Per iniziare'], ['screens', 'Le schermate'], ['terms', 'Glossario'], ['trouble', 'Problemi comuni']];

function renderGuide() {
    const tabs = `<div class="tabs" role="tablist">${GUIDE_TABS.map(([k, l]) =>
        `<button class="chip${guideTab === k ? ' on' : ''}" role="tab" aria-selected="${guideTab === k}" data-gtab="${k}">${l}</button>`).join('')}</div>`;
    const body = {start: guideStart, screens: guideScreens, terms: guideTerms, trouble: guideTrouble}[guideTab]();
    content.innerHTML = `${h2(ICO_HELP, 'Guida')}<p class="sub">Cosa fa ZeroShield, come leggere le schermate e cosa fare quando qualcosa non torna.</p>${tabs}${body}`;
    content.querySelectorAll('[data-gtab]').forEach(b => { b.onclick = () => { guideTab = b.dataset.gtab; render(true); }; });
    const rp = document.getElementById('guide-replay');
    // Replay: azzera passo e flag, mostra da capo. Per chi ha saltato troppo in fretta.
    if (rp) rp.onclick = () => {
        try { localStorage.removeItem('zs-onboarded-v2'); } catch (_) {}
        obStep = 0;
        showOnboarding();
    };
}

// Punti di controllo dal vivo: cosa e' gia' a posto e cosa manca, con il link alla schermata utile.
function guideChecklist() {
    if (!status) {
        return `<div class="verdict bad"><div class="verdict-t">○ Il demone non risponde</div><ul><li>Segui i passi qui sotto: il primo è installare il pacchetto e avviare il servizio.</li></ul></div>`;
    }
    const s = status, v = s.vpn || {};
    const enf = s.mode === 'enforce';
    const items = [
        ['ok', 'Il demone risponde', 'Il servizio è attivo e il socket è leggibile.', ''],
        [s.hook_lsm ? 'ok' : 'ko', 'Hook LSM (protezione dei file)', s.hook_lsm ? 'I file protetti sono sotto controllo.' : 'Spento: controlla che <b>bpf</b> sia tra gli LSM del kernel (vedi «Problemi comuni»).', 'status'],
        [(s.xdp || []).length ? 'ok' : 'ko', 'Filtro XDP (rete)', (s.xdp || []).length ? `Attivo su ${esc(s.xdp.join(', '))}. Le altre interfacce non sono filtrate.` : 'Spento: nessun drop di rete.', 'net'],
        [enf ? 'ok' : 'caution', enf ? 'Modalità enforce' : 'Modalità audit', enf ? 'Gli accessi non autorizzati vengono negati.' : 'Stai osservando: nulla viene bloccato. Passa a enforce quando in Eventi non compaiono più accessi legittimi.', 'config'],
        [v.enabled ? 'ok' : 'off', v.enabled ? 'VPN monitorata' : 'VPN non monitorata', v.enabled ? 'Il demone osserva tunnel e kill-switch.' : 'Facoltativa: su una rete ostile, senza VPN, il traffico esce in chiaro.', 'net'],
    ];
    const sym = {ok: '●', caution: '◐', ko: '○', off: '–'};
    return `<div class="panel checklist">${items.map(([st, t, h, g]) =>
        `<div class="check ${st}"><span>${sym[st]}</span><span><b>${t}</b> <span class="sub">${h}</span>${g ? ` <button class="linklike" data-go="${g}">vedi →</button>` : ''}</span></div>`).join('')}</div>`;
}

function guideStart() {
    return `${sec('Il tuo stato')}${guideChecklist()}
    <p><button class="chip on" id="guide-replay">↺ Rivedi l'introduzione guidata</button></p>
    ${renderGuideBody()}
    ${sec('Prova con dati finti')}${demoBlock()}`;
}

const GUIDE_SCREENS = [
    ['status', 'Stato', 'Sono protetto?', 'Il verdetto in cima (attiva, parziale, non attiva), poi hook, XDP, contatori della sessione e i controlli per fermare il servizio o cambiare modalità.', 'Appena apri la GUI.'],
    ['events', 'Eventi', 'Chi ha toccato i miei segreti?', 'Ogni accesso ai file protetti con regola, programma e PID. In audit sono quelli che enforce bloccherebbe. «Raggruppa» unisce le righe uguali.', 'Prima di passare a enforce.'],
    ['radar', 'Radar', 'Chi mi disturba in rete?', 'Gli IP da cui XDP ha scartato traffico di scoperta di rete, classificati in rumore probabile, da verificare, bloccati e noti.', 'Quando vedi drop o sospetti una rete ostile.'],
    ['rules', 'Regole', 'Cosa è protetto, e da chi?', 'I gruppi di segreti e i programmi autorizzati a leggerli, con gli accessi visti in sessione.', 'Quando un programma legittimo viene segnalato.'],
    ['net', 'Rete', 'Cosa filtra il demone e cosa è esposto?', 'Interfacce coperte da XDP, subnet bloccate, stato della VPN e porte in ascolto.', 'Su una rete nuova.'],
    ['config', 'Configurazione', 'Cosa sta usando il demone?', 'Riepilogo delle impostazioni, cambio audit/enforce e il file di configurazione.', 'Per cambiare modalità o controllare il file.'],
];
function guideScreens() {
    return `${sec('A cosa serve ogni schermata')}<div class="panel">${GUIDE_SCREENS.map(([g, name, q, d, when]) =>
        `<div class="kv"><div class="kv-k"><button class="linklike" data-go="${g}">${name}</button></div><div class="kv-v"><b>${q}</b></div><div class="kv-h">${d} <i>Quando: ${when}</i></div></div>`).join('')}</div>
    <p class="sub">Scorciatoie: i tasti <kbd>1</kbd>–<kbd>7</kbd> aprono le schermate nell'ordine del menu (non funzionano mentre scrivi in un campo).</p>`;
}

const GUIDE_TERMS = [
    ['Audit / Enforce', 'In <b>audit</b> il demone registra gli accessi ai file protetti senza negarne nessuno; in <b>enforce</b> nega (EACCES) quelli non autorizzati. Si parte sempre da audit.'],
    ['Hook LSM', 'Il controllo nel kernel che decide se un programma può aprire, cancellare o rinominare un file protetto. Richiede che <b>bpf</b> sia tra gli LSM attivi.'],
    ['XDP', 'Il filtro sui pacchetti di rete, prima che il sistema li veda. ZeroShield lo usa per scartare il traffico di poisoning (LLMNR, mDNS, NetBIOS) e le subnet che blocchi tu.'],
    ['Poisoning', 'Attacco su rete locale in cui un host risponde alle richieste di scoperta dei nomi (LLMNR, mDNS, NetBIOS) fingendosi quello cercato, per rubare credenziali. Strumenti tipici: Responder, Inveigh.'],
    ['Whitelist («autorizzati»)', 'I programmi che una regola lascia leggere i suoi file. Contano l\'identità del file (dispositivo e inode), non il nome: copiare o rinominare un binario non basta.'],
    ['Canary', 'File esca nascosti che nessun programma legittimo apre. Chi li tocca viene ucciso in enforce (solo allarme in audit). Spento di default.'],
    ['Rescan', 'Il riallineamento delle mappe del kernel con i file del disco. Parte da solo ogni 30 secondi e quando un file protetto cambia.'],
    ['Profilo', 'Un insieme di regole e modalità iniziali: <span class="mono">home</span>, <span class="mono">corporate</span>, <span class="mono">public-wifi</span>, <span class="mono">paranoid</span>.'],
    ['Fail-closed', 'Se un hook non si aggancia, il demone si ferma invece di fingersi attivo: un\'interfaccia «demone spento» è meglio di una protezione finta.'],
    ['Kill-switch VPN', 'Regola di firewall che blocca il traffico fuori dal tunnel: se la VPN cade non esci in chiaro. Il demone lo osserva ma non lo applica.'],
];
function guideTerms() {
    return `${sec('Glossario')}<div class="panel">${GUIDE_TERMS.map(([t, d]) =>
        `<div class="kv"><div class="kv-k">${t}</div><div class="kv-v">${d}</div></div>`).join('')}</div>`;
}

const GUIDE_TROUBLE = [
    ['La GUI dice «demone non raggiungibile» o «permission denied»',
     'Il servizio è fermo oppure il socket è riservato a root e all\'utente indicato in <b>user:</b>. Apri la GUI con quell\'utente e controlla il servizio.',
     ['systemctl status zt-shield', 'journalctl -u zt-shield -n 50']],
    ['Hook LSM spento, o il servizio non parte',
     'Il kernel deve avere <b>bpf</b> tra gli LSM attivi; senza, il demone si ferma di proposito. Se manca, aggiungilo alla riga <span class="mono">lsm=</span> di GRUB e riavvia (procedura nel README).',
     ['cat /sys/kernel/security/lsm', 'sudo zt-probe -xdp-lo']],
    ['In audit vedo tanti accessi dello stesso programma',
     'È normale: un programma legittimo che legge un segreto (per esempio il prompt della shell che legge la configurazione di kubectl) compare a ogni uso. In Eventi usa «raggruppa». Prima di passare a enforce, aggiungi quel programma ai binari autorizzati della regola, altrimenti verrebbe bloccato.',
     []],
    ['Il radar mostra IP della mia rete',
     'Host e stampanti mandano di continuo richieste di scoperta: di solito è sottofondo. Un punto «da verificare» merita un controllo con i comandi sotto la tabella del Radar; se riconosci l\'host, segnalo come noto. Il kernel non distingue richieste normali da risposte avvelenate.',
     []],
    ['XDP copre una sola interfaccia',
     'Le altre interfacce attive (Wi-Fi, tunnel, docker) non sono filtrate. Se una è esposta a una rete non fidata, elencale nel file di configurazione (nomi di esempio) e riavvia il servizio.',
     ['interface: "eth0,wlan0"', 'sudo systemctl restart zt-shield']],
    ['Nel journal compare «binario non risolto»',
     'Una regola elenca un programma che non è installato nel PATH del demone, quindi non è autorizzato. Non è un guasto: installalo o toglilo dalla regola. L\'avviso si ripete a ogni rescan (voce aperta in PUNTI_APERTI).',
     []],
    ['Voglio tornare da enforce ad audit',
     'Dalla scheda Configurazione scegli «Audit», oppure imposta <span class="mono">mode: audit</span> nel file e riavvia il servizio.',
     ['sudo systemctl restart zt-shield']],
    ['Un browser o un programma aggiornato risulta bloccato',
     'Dopo un aggiornamento (apt, snap) l\'inode del binario cambia e il programma resta fuori dai binari autorizzati fino al rescan successivo (entro 30 secondi).',
     []],
];
function guideTrouble() {
    return `${sec('Problemi comuni')}<div class="faq">${GUIDE_TROUBLE.map(([q, a, cmds]) =>
        `<details><summary>${q}</summary><p>${a}</p>${cmds.map(c => `<div style="margin-top:6px">${codeRow(c)}</div>`).join('')}</details>`).join('')}</div>`;
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
      ${kv('Interfacce coperte', xdp.length ? xdp.map(x => `<span class="mono">${esc(x)}</span>`).join(', ') : '<span class="dot-off">nessuna: XDP spento</span>', 'Le altre interfacce attive non sono filtrate: scegli quali qui sotto, in «Interfacce filtrate».')}
      ${kv('Drop poisoning', status.block_poisoning ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento', 'LLMNR, mDNS, NetBIOS. Dettaglio per IP nel tab Radar.')}
      ${kv('Subnet bloccate', subs.length ? subs.map(c => `<span class="mono">${esc(c)}</span>`).join(', ') : 'nessuna', subs.length ? 'Il drop scarta anche le risposte da queste reti: mai gateway/DNS.' : 'Solo drop poisoning + UFW.')}
    </div>
    <div id="if-box"></div>` + renderListening();
    ifaceView.ensureLoaded();
    paintIfaces();
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
        recordRadar(status);
        lastStatusAt = Date.now(); // senza questo "dati fermi da <epoch>s" fino al primo push
    } catch (e) {
        offlineMsg = String(e && e.message || e);
        try { offlineMsg += ' — socket: ' + await SocketPath(); } catch (_) {}
    }
    render();
    // Versione dal binario (ldflags al build): se manca il binding, nessun errore.
    try {
        appVersion = await Version();
        const ve = document.getElementById('ver');
        if (ve && appVersion) { ve.textContent = 'ZeroShield ' + (/^\d/.test(appVersion) ? 'v' : '') + appVersion; ve.title = 'Versione di questa finestra (GUI)'; }
        if (ve) { ve.onclick = () => showWhatsNew(true); }
        requestRender();
        maybeWhatsNew();
    } catch (_) {}
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

EventsOn('shield:status', st => { status = st; recordRadar(st); statusSeq++; lastStatusAt = Date.now(); offlineMsg = ''; requestRender(); });
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
