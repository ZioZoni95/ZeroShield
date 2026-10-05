// ZeroShield GUI — client IPC: primo paint via GetStatus, poi push live.
// Solo lettura: nessun'azione privilegiata da qui (cambio mode via config+restart).
import {GetStatus, SocketPath} from '../wailsjs/go/main/App.js';
import {EventsOn} from '../wailsjs/runtime/runtime.js';

const content = document.getElementById('content');
const badge = document.getElementById('mode-badge');
const modeText = document.getElementById('mode-text');
const viewTitle = document.getElementById('view-title');
const conn = document.getElementById('conn');
const evCount = document.getElementById('ev-count');
const buttons = [...document.querySelectorAll('#sidebar button')];
const TITLES = {status: 'Stato', events: 'Eventi', rules: 'Regole', net: 'Rete', radar: 'Radar'};

let view = 'status';
let status = null;
let events = [];
let offlineMsg = '';
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
function countUp(el, target) {
    const from = parseInt(el.dataset.v || '0', 10);
    if (from === target) return;
    el.dataset.v = String(target);
    const t0 = performance.now();
    (function step(t) {
        const k = Math.min(1, (t - t0) / 400);
        el.textContent = Math.round(from + (target - from) * k);
        if (k < 1) requestAnimationFrame(step);
    })(t0);
}

function render() {
    paintBadge();
    cancelAnimationFrame(radarRAF);
    const oldTip = document.getElementById('radar-tip');
    if (oldTip) oldTip.style.display = 'none';
    viewTitle.textContent = TITLES[view] || view;
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
    const lsm = status.hook_lsm
        ? '<span class="dot-ok">●</span> attivo' : '<span class="dot-off">●</span> spento';
    content.innerHTML = `<h2>Stato</h2><p class="sub">Profilo ${esc(status.profile)} · home ${esc(status.home)}</p>
    <div class="cards">
      <div class="card"><div class="k">Modalità</div><div class="v" style="font-size:17px">${esc(status.mode)}</div></div>
      <div class="card"><div class="k">Hook LSM</div><div class="v" style="font-size:17px">${lsm}</div></div>
      <div class="card"><div class="k">File protetti</div><div class="v" data-count="${status.protected}">0</div></div>
      <div class="card"><div class="k">Binari autorizzati</div><div class="v" data-count="${status.allowed}">0</div></div>
      <div class="card"><div class="k">XDP su</div><div class="v small">${esc(xdp)}</div></div>
    </div>`;
    content.querySelectorAll('[data-count]').forEach(el =>
        countUp(el, parseInt(el.dataset.count, 10)));
}

function renderEvents() {
    if (!events.length) {
        content.innerHTML = `${h2(ICO_AUDIT, 'Eventi')}
        <div class="empty"><span class="big">🌊</span><b>Rete calma, niente eventi.</b><br>In audit gli accessi legittimi compaiono qui: passa a enforce solo a log puliti.</div>`;
        return;
    }
    const rows = [...events].reverse().slice(0, 200).map(e => {
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
        return `<tr class="${cls}"><td>${tag}</td><td class="mono">${esc(t)}</td><td>${esc(e.rule)}</td>
        <td class="mono">pid=${e.pid}</td><td class="mono">${esc(e.comm)}</td><td class="mono">${esc(e.exe || '(uscito)')}</td></tr>`;
    }).join('');
    content.innerHTML = `${h2(ICO_AUDIT, 'Eventi')}<p class="sub">${events.length} eventi (ultimi 200, live)</p>
    <table><tr><th></th><th>ora</th><th>regola</th><th>pid</th><th>comm</th><th>exe</th></tr>${rows}</table>`;
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
        <div><span class="mono">exe:</span> <span class="mono">${esc((r.allow || []).join(', '))}</span></div></div>`).join('');
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

function renderNet() {
    const subs = status.block_subnets || [];
    const v = status.vpn || {};
    let vpn = `<div class="empty"><span class="big">🔓</span><b>VPN kill-switch spento.</b><br>Su rete ostile esci in chiaro: alza il tunnel.</div>`;
    if (v.enabled) {
        vpn = v.up
            ? `<div class="rule ok"><h3>🔒 VPN su</h3><div><span class="mono">${esc(v.tunnel)} → ${esc(v.endpoint)}</span></div></div>`
            : `<div class="warn">${ICO_WARN} VPN GIÙ: ${esc(v.tunnel || '?')} assente, sei in chiaro! Alza il tunnel o esci dalla rete.</div>`;
    }
    content.innerHTML = `${h2(ICO_AUDIT, 'Rete')}<p class="sub">XDP: ${esc((status.xdp || []).join(', ') || '(spento)')} · poisoning drop: ${status.block_poisoning}</p>` + vpn +
        (subs.length ? `<div class="warn">${ICO_WARN} Il drop scarta anche le risposte da queste reti: mai gateway/DNS.</div>` : '') +
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
    render();
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
