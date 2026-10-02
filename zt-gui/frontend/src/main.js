// Zero-Trust Shield GUI — client IPC: primo paint via GetStatus, poi push live.
// Solo lettura: nessun'azione privilegiata da qui (cambio mode via config+restart).
import {GetStatus, SocketPath} from '../wailsjs/go/main/App.js';
import {EventsOn} from '../wailsjs/runtime/runtime.js';

const content = document.getElementById('content');
const badge = document.getElementById('mode-badge');
const conn = document.getElementById('conn');
const evCount = document.getElementById('ev-count');
const buttons = [...document.querySelectorAll('#sidebar button')];

let view = 'status';
let status = null;
let events = [];
let offlineMsg = '';

buttons.forEach(b => b.onclick = () => {
    view = b.dataset.view;
    buttons.forEach(x => x.classList.toggle('active', x === b));
    render();
});

function esc(s) {
    return String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
}

function paintBadge() {
    if (!status) { badge.className = 'badge off'; badge.textContent = 'non connesso'; return; }
    if (status.mode === 'enforce') { badge.className = 'badge enforce'; badge.textContent = '● ENFORCE'; }
    else { badge.className = 'badge audit'; badge.textContent = '● AUDIT'; }
}

function render() {
    paintBadge();
    if (!status) return renderOffline();
    conn.textContent = 'aggiornato ' + (status.time || '…');
    evCount.textContent = events.length > 0 ? events.length : '';
    if (view === 'status') return renderStatus();
    if (view === 'events') return renderEvents();
    if (view === 'rules') return renderRules();
    return renderNet();
}

function renderOffline() {
    conn.textContent = 'demone non raggiungibile';
    content.innerHTML = `<div class="offline"><h2>Demone non raggiungibile</h2>
    <p class="sub">${esc(offlineMsg)}</p>
    <p>Avvialo prima (profilo audit, non blocca nulla):</p>
    <p><code>sudo SHIELD_USER=$USER ./bin/zt-shield</code></p>
    <p>oppure in locale senza root (dati finti, solo per vedere la UI):</p>
    <p><code>ZT_SOCKET=/tmp/z.sock ./bin/zt-mockd &<br>ZT_SOCKET=/tmp/z.sock ./bin/zt-gui</code></p></div>`;
}

function renderStatus() {
    const xdp = (status.xdp && status.xdp.length) ? status.xdp.join(', ') : '(spento)';
    content.innerHTML = `<h2>Stato</h2><p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}</p>
    <div class="cards">
      <div class="card"><div class="k">Modalità</div><div class="v">${esc(status.mode)}</div></div>
      <div class="card"><div class="k">Hook LSM</div><div class="v">${status.hook_lsm ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento'}</div></div>
      <div class="card"><div class="k">File protetti</div><div class="v">${status.protected}</div></div>
      <div class="card"><div class="k">Binari autorizzati</div><div class="v">${status.allowed}</div></div>
      <div class="card"><div class="k">XDP su</div><div class="v" style="font-size:15px">${esc(xdp)}</div></div>
    </div>`;
}

function renderEvents() {
    if (!events.length) {
        content.innerHTML = `<h2>Eventi</h2><p class="sub">Nessun evento ancora. In audit gli accessi legittimi compaiono qui: passa a enforce solo a log puliti.</p>`;
        return;
    }
    const rows = [...events].reverse().slice(0, 200).map(e => {
        const tag = e.action === 'blocked' ? '<span class="tag-block">🚨 BLOCCO</span>' : '<span class="tag-audit">👁 audit</span>';
        const t = (e.time || '').slice(11, 19);
        return `<tr><td>${tag}</td><td class="mono">${esc(t)}</td><td>${esc(e.rule)}</td>
        <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.comm)}</td><td class="mono">${esc(e.exe || '(uscito)')}</td></tr>`;
    }).join('');
    content.innerHTML = `<h2>Eventi</h2><p class="sub">${events.length} eventi (ultimi 200, live)</p>
    <table><tr><th></th><th>ora</th><th>regola</th><th>pid</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
}

function renderRules() {
    const rules = status.rules || [];
    content.innerHTML = `<h2>Regole</h2><p class="sub">${rules.length} gruppi di segreti</p>` +
        rules.map(r => `<div class="rule"><h3>■ ${esc(r.name)}</h3>
        <div><span class="mono">file:</span> <span class="mono">${esc((r.paths || []).join(', '))}</span></div>
        <div><span class="mono">exe:</span> <span class="mono">${esc((r.allow || []).join(', '))}</span></div></div>`).join('');
}

function renderNet() {
    const subs = status.block_subnets || [];
    content.innerHTML = `<h2>Rete</h2><p class="sub">XDP: ${esc((status.xdp || []).join(', ') || '(spento)')} · poisoning drop: ${status.block_poisoning}</p>` +
        (subs.length ? `<div class="warn">Il drop scarta anche le risposte da queste reti: mai gateway/DNS.</div>` : '') +
        (subs.length ? subs.map(c => `<div class="rule">🚫 <span class="mono">${esc(c)}</span></div>`).join('')
            : `<p class="sub">Nessuna subnet bloccata: solo drop poisoning + UFW.</p>`);
}

async function boot() {
    try {
        status = await GetStatus();
    } catch (e) {
        offlineMsg = String(e && e.message || e);
        try { offlineMsg += ' — socket: ' + await SocketPath(); } catch (_) {}
    }
    render();
}

EventsOn('shield:status', st => { status = st; offlineMsg = ''; render(); });
EventsOn('shield:status-error', msg => { if (!status) { offlineMsg = msg; render(); } });
EventsOn('shield:event', ev => {
    events.push(ev);
    if (events.length > 200) events = events.slice(-200);
    render();
});

boot();
