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

const ICO_BLOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const ICO_AUDIT = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="2.4" fill="currentColor"/></svg>';
const ICO_WARN = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3L22 20H2L12 3z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M12 10v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="17" r="1.2" fill="currentColor"/></svg>';
const ICO_KEY = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
const ICO_BAN = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';

function h2(icon, text) { return `<h2>${icon}${esc(text)}</h2>`; }

function paintBadge() {
    if (!status) { badge.className = 'badge off'; badge.textContent = 'non connesso'; return; }
    if (status.mode === 'enforce') { badge.className = 'badge enforce'; badge.textContent = '● ENFORCE'; }
    else { badge.className = 'badge audit'; badge.textContent = '● AUDIT'; }
}

function render() {
    paintBadge();
    cancelAnimationFrame(radarRAF);
    if (!status) return renderOffline();
    conn.textContent = 'aggiornato ' + (status.time || '…');
    evCount.textContent = events.length > 0 ? events.length : '';
    if (view === 'status') return renderStatus();
    if (view === 'events') return renderEvents();
    if (view === 'rules') return renderRules();
    if (view === 'radar') return renderRadar();
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
        const tag = e.action === 'blocked'
            ? `<span class="tag tag-block">${ICO_BLOCK} BLOCCO</span>`
            : `<span class="tag tag-audit">${ICO_AUDIT} audit</span>`;
        const t = (e.time || '').slice(11, 19);
        const cls = e.action === 'blocked' ? 'row-block' : 'row-audit';
        return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td>${esc(e.rule)}</td>
        <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.comm)}</td><td class="mono">${esc(e.exe || '(uscito)')}</td></tr>`;
    }).join('');
    content.innerHTML = `${h2(ICO_AUDIT, 'Eventi')}<p class="sub">${events.length} eventi (ultimi 200, live)</p>
    <table><tr><th></th><th>ora</th><th>regola</th><th>pid</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
}

function renderRules() {
    const rules = status.rules || [];
    content.innerHTML = `<h2>Regole</h2><p class="sub">${rules.length} gruppi di segreti</p>` +
        rules.map(r => `<div class="rule"><h3>■ ${esc(r.name)}</h3>
        <div><span class="mono">file:</span> <span class="mono">${esc((r.paths || []).join(', '))}</span></div>
        <div><span class="mono">exe:</span> <span class="mono">${esc((r.allow || []).join(', '))}</span></div></div>`).join('');
}

// --- Radar: spazzata canvas + blip per sorgente droppata da XDP (dati eBPF) ---
let radarRAF = 0;
let radarAngle = 0;

function hashIP(ip) {
    let h = 2166136261;
    for (let i = 0; i < ip.length; i++) { h ^= ip.charCodeAt(i); h = Math.imul(h, 16777619); }
    return ((h >>> 0) % 360) * Math.PI / 180;
}

function renderRadar() {
    cancelAnimationFrame(radarRAF);
    const src = status.top_sources || status.topSources || [];
    content.innerHTML = `${h2(ICO_AUDIT, 'Radar rete')}<p class="sub">${src.length ? src.length + ' sorgenti droppate da XDP (dati kernel)' : 'Nessun drop XDP: radar vuoto.'}</p>
    <canvas id="radar" width="360" height="360"></canvas>
    <div id="radar-list"></div>`;
    const cv = document.getElementById('radar');
    const cx = cv.getContext('2d');
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    const ring = dark ? '#48484a' : '#d2d2d7';
    const sweepC = dark ? '#0a84ff' : '#0071e3';
    let max = 1;
    src.forEach(s => { const t = (s.total || s.Total || 0); if (t > max) max = t; });
    const list = document.getElementById('radar-list');
    list.innerHTML = src.map(s => {
        const t = s.total || s.Total || 0;
        const ip = esc(s.ip || s.IP || '');
        const kind = ((s.subnet || s.Subnet || 0) >= (s.poison || s.Poison || 0)) ? 'subnet' : 'poisoning';
        return `<div class="rule"><h3>${ICO_BAN} <span class="mono">${ip}</span></h3>
        <div><b>${t}</b> drop (${kind}) · ultimo ${(s.last_seen || s.LastSeen || '').slice(11, 19)}</div></div>`;
    }).join('');
    function frame() {
        radarAngle = (radarAngle + 2) % 360;
        const a = radarAngle * Math.PI / 180;
        cx.clearRect(0, 0, 360, 360);
        cx.strokeStyle = ring; cx.lineWidth = 1;
        [60, 120, 175].forEach(r => { cx.beginPath(); cx.arc(180, 180, r, 0, 7); cx.stroke(); });
        cx.beginPath(); cx.moveTo(180, 180);
        cx.lineTo(180 + 175 * Math.cos(a), 180 + 175 * Math.sin(a));
        cx.strokeStyle = sweepC; cx.lineWidth = 2; cx.stroke();
        src.forEach(s => {
            const t = s.total || s.Total || 0;
            const frac = Math.log10(t + 1) / Math.log10(max + 1);
            const r = 30 + 145 * frac;
            const ia = hashIP(s.ip || s.IP || '');
            const x = 180 + r * Math.cos(ia), y = 180 + r * Math.sin(ia);
            const sub = (s.subnet || s.Subnet || 0) >= (s.poison || s.Poison || 0);
            cx.beginPath(); cx.arc(x, y, 4 + 5 * frac, 0, 7);
            cx.fillStyle = sub ? '#d70015' : '#b8860b'; cx.fill();
            cx.beginPath(); cx.arc(x, y, 4 + 5 * frac, 0, 7);
            cx.strokeStyle = '#fff'; cx.lineWidth = 1.5; cx.stroke();
        });
        radarRAF = requestAnimationFrame(frame);
    }
    frame();
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
