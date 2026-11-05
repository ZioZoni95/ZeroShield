// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT
//
// Test della GUI vera (frontend compilato) in un browser headless, con il demone
// simulato da stub (window.go / window.runtime, che Wails inietta nell'app reale).
//
//   cd zt-gui/frontend
//   npm run build
//   npm i --no-save playwright-core        # solo il driver: il browser e' quello di sistema
//   CHROME_PATH=/usr/bin/google-chrome node tests/gui.test.mjs       # SHOTS=dir per gli screenshot
//
// Browser: CHROME_PATH se impostato, altrimenti Google Chrome di sistema (channel
// "chrome", presente sui runner GitHub), altrimenti il Chromium di Playwright.
//
// Protegge dai difetti trovati nella revisione del 2026-10-05: la barra di ricerca
// eventi perdeva focus e testo a ogni evento in arrivo (con un flood si riusciva a
// digitare UNA lettera); stato VPN che dava verde con il solo tunnel su; IPv6 senza
// parentesi; testo ostile (comm/exe) interpretato come HTML.
import { chromium } from 'playwright-core';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const dist = path.resolve(process.argv[2] || 'dist');
const label = process.argv[3] || 'gui';
const shots = process.env.SHOTS || process.argv[4];
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.png': 'image/png' };

const server = http.createServer((req, res) => {
  let f = path.join(dist, req.url.split('?')[0]);
  if (f.endsWith('/')) f += 'index.html';
  fs.readFile(f, (err, data) => {
    if (err) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'content-type': mime[path.extname(f)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(0);
const port = server.address().port;

const STATUS = {
  profile: 'home', mode: 'audit', home: '/home/u', hook_lsm: true, xdp: ['eth0'], protected: 3, allowed: 2,
  block_poisoning: true, block_subnets: [], time: '2026-10-05T10:00:00Z',
  vpn: { enabled: false, up: false, killswitch: false, handshake_age: -1 },
  top_sources: [], listening: [], listening_total: 0, rules: [{ name: 'ssh-keys', paths: ['.ssh/id_*'], allow: ['ssh'] }],
};

const results = [];
const check = (name, ok, extra = '') => { results.push(ok); console.log(`${ok ? '✅' : '❌'} ${name}${extra ? '   ' + extra : ''}`); };

async function launchBrowser() {
  const args = ['--no-sandbox'];
  if (process.env.CHROME_PATH) return chromium.launch({ executablePath: process.env.CHROME_PATH, args });
  try { return await chromium.launch({ channel: 'chrome', args }); } catch (_) { /* ripiega sul Chromium di Playwright */ }
  return chromium.launch({ args });
}
const browser = await launchBrowser();
const page = await browser.newPage({ viewport: { width: 1100, height: 760 }, timezoneId: 'Europe/Rome' });
const errors = [];
page.on('pageerror', e => errors.push(String(e)));

await page.addInitScript((status) => {
  window.__handlers = {};
  window.__status = status;
  window.go = { main: { App: {
    GetStatus: async () => window.__status,
    SocketPath: async () => '/tmp/z.sock',
    Version: async () => '9.9.9-test',
    ServiceState: async () => 'active',
    ConfigMode: async () => window.__cfgMode,
    ConfigText: async () => { await new Promise(r => setTimeout(r, window.__cfgDelay || 0)); return 'profile: home\nuser: tester\n'; },
    SetConfigMode: async (m) => { window.__setModeCalls.push(m); },
  } } };
  window.__cfgMode = 'audit'; window.__cfgDelay = 0; window.__setModeCalls = [];
  window.runtime = {
    EventsOnMultiple: (name, cb) => { (window.__handlers[name] = window.__handlers[name] || []).push(cb); return () => {}; },
    EventsOff: () => {},
  };
  window.__emit = (name, payload) => (window.__handlers[name] || []).forEach(h => h(payload));
}, STATUS);

await page.goto(`http://127.0.0.1:${port}/`);
await page.waitForSelector('#content h2');

// --- versione dal binario
const sub = await page.textContent('#content .sub');
check('la versione arriva dal binario (Version())', sub.includes('ZeroShield 9.9.9-test'), sub.trim());

// --- ricerca eventi: focus e testo sopravvivono a un flood di eventi
await page.evaluate(() => { for (let i = 0; i < 5; i++) window.__emit('shield:event', { time: '2026-10-05T10:00:0' + i + 'Z', action: 'audit', pid: 100 + i, comm: 'cat', exe: '/usr/bin/cat', rule: 'ssh-keys', inode: 1 }); });
await page.click('#sidebar button[data-view="events"]');
await page.waitForSelector('#ev-q');
await page.focus('#ev-q');
let n = 0;
const flood = setInterval(() => {
  n++;
  page.evaluate((i) => window.__emit('shield:event', { time: '2026-10-05T10:01:00Z', action: 'blocked', pid: 1000 + i, comm: 'x' + i, exe: '/usr/bin/x', rule: 'ssh-keys', inode: 2 }), n).catch(() => {});
}, 15);
for (const ch of 'ssh-keys') { await page.keyboard.type(ch); await page.waitForTimeout(60); }
clearInterval(flood);
await page.waitForTimeout(150);
const st = await page.evaluate(() => ({ active: document.activeElement && document.activeElement.id, value: document.getElementById('ev-q').value }));
check(`la ricerca tiene focus e testo durante un flood di ${n} eventi`, st.active === 'ev-q' && st.value === 'ssh-keys', JSON.stringify(st));

const rows = await page.evaluate(() => document.querySelectorAll('#ev-body table tr').length);
check('...e la tabella continua ad aggiornarsi (righe > 5)', rows > 5, `righe=${rows}`);

// --- sanificazione: testo ostile in comm/exe non diventa HTML
await page.evaluate(() => window.__emit('shield:event', { time: '2026-10-05T10:02:00Z', action: 'blocked', pid: 7, comm: '<img src=x onerror=window.__pwned=1>', exe: '<script>window.__pwned=1</script>', rule: 'ssh-keys', inode: 3 }));
await page.fill('#ev-q', '');
await page.waitForTimeout(100);
const injected = await page.evaluate(() => ({ img: document.querySelectorAll('#ev-body img').length, script: document.querySelectorAll('#ev-body script').length, pwned: !!window.__pwned }));
check('comm/exe con HTML non vengono interpretati', injected.img === 0 && injected.script === 0 && !injected.pwned, JSON.stringify(injected));

// --- contatori di Stato: un nuovo render non deve farli ripartire da 0
// (trovato lanciando l'app vera: con eventi in arrivo ogni pochi secondi mostravano 0).
await page.click('#sidebar button[data-view="status"]');
await page.waitForTimeout(700); // lascia finire l'animazione di arrivo
const counter = (label) => page.evaluate((l) => {
  const card = [...document.querySelectorAll('#content .card')].find(c => c.querySelector('.k') && c.querySelector('.k').textContent === l);
  return card ? parseInt(card.querySelector('.v').textContent, 10) : NaN;
}, label);
const settled = await counter('Blocchi');
check('i contatori di sessione mostrano il valore reale a regime', settled > 0, `Blocchi=${settled}`);
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status)));
await page.waitForTimeout(60); // molto meno dei 400 ms di animazione
const afterRerender = await counter('Blocchi');
check('...e un nuovo render non li azzera (nessun ritorno a 0)', afterRerender === settled, `prima=${settled} dopo=${afterRerender}`);

// --- Rete: i quattro stati VPN
const vpnCases = [
  ['VPN protetta', { enabled: true, endpoint: '1.2.3.4:51820', tunnel: 'wg0', up: true, killswitch: true, handshake_age: 12 }, ['VPN protetta', 'kill-switch attivo', '12s']],
  ['tunnel su senza kill-switch', { enabled: true, endpoint: '1.2.3.4:51820', tunnel: 'wg0', up: true, killswitch: false, handshake_age: 12 }, ['kill-switch NON attivo']],
  ['giu con kill-switch', { enabled: true, endpoint: '1.2.3.4:51820', tunnel: 'wg0', up: false, killswitch: true, handshake_age: -1 }, ['non in chiaro']],
  ['giu senza kill-switch', { enabled: true, endpoint: '1.2.3.4:51820', tunnel: 'wg0', up: false, killswitch: false, handshake_age: -1 }, ['sei in chiaro']],
  ['non monitorata', { enabled: false }, ['non monitorata']],
];
await page.click('#sidebar button[data-view="net"]');
for (const [name, vpn, needles] of vpnCases) {
  await page.evaluate((v) => window.__emit('shield:status', Object.assign({}, window.__status, { vpn: v })), vpn);
  await page.waitForTimeout(80);
  const txt = await page.textContent('#content');
  check(`Rete: ${name}`, needles.every(x => txt.includes(x)), needles.join(' | '));
}
const prot = await page.evaluate(() => { window.__emit('shield:status', Object.assign({}, window.__status, { vpn: { enabled: true, endpoint: 'e', tunnel: 't', up: true, killswitch: false, handshake_age: 5 } })); return document.querySelector('#content .rule.ok') !== null; });
await page.waitForTimeout(80);
check('tunnel su SENZA kill-switch non e verde', !(await page.evaluate(() => document.querySelector('#content .rule.ok') !== null)));

// --- porte in ascolto: UDP, IPv6 con parentesi, troncamento, testo ostile
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, {
  vpn: { enabled: false },
  listening: [
    { proto: 'tcp', addr: '0.0.0.0', port: 22, pid: 5, exe: '/usr/sbin/sshd' },
    { proto: 'udp', addr: '0.0.0.0', port: 5353, pid: 7, exe: '/usr/sbin/avahi-daemon' },
    { proto: 'tcp6', addr: '::1', port: 631, pid: 9, exe: '<b>evil</b>' },
  ], listening_total: 300,
})));
await page.waitForTimeout(80);
const net = await page.textContent('#content');
check('Rete: mostra UDP', net.includes('udp') && net.includes('5353'));
check('Rete: IPv6 tra parentesi [::1]:631', net.includes('[::1]:631'));
check('Rete: dichiara il troncamento (mostrate 3 di 300)', net.includes('mostrate 3 di 300'));
check('Rete: exe con HTML non interpretato (nessun <b> creato dal testo ostile)', (await page.evaluate(() => Array.from(document.querySelectorAll('#content b')).filter(b => b.textContent === 'evil').length)) === 0);
check('Rete: ...e il testo ostile compare come testo letterale', net.includes('<b>evil</b>'));

// --- Guida: percorso da pacchetto e da sorgente, nessun cp che sovrascrive
await page.click('#sidebar button[data-view="guide"]');
await page.waitForTimeout(80);
const guide = await page.textContent('#content');
check('Guida: percorso da pacchetto .deb', guide.includes('Da pacchetto .deb') && guide.includes('sudoedit /etc/zt-shield/shield.yaml') && guide.includes('zt-probe'));
check('Guida: da sorgente usa cp -n (non sovrascrive)', guide.includes('cp -n configs/shield.example.yaml'));
check('Guida: nessun cp che sovrascrive la config', !/sudo cp configs\/shield\.example\.yaml/.test(guide));


// --- Correzioni UX (2026-11-04): menu, tastiera, ora locale, configurazione, eventi, guida.
await page.click('#sidebar button[data-view="status"]');
const nav = await page.evaluate(() => [...document.querySelectorAll('#sidebar button')].map(b => b.dataset.view + ':' + b.querySelector('kbd').textContent));
check('menu: ordine e numeri coerenti (1..7 in sequenza)', nav.join(',') === 'status:1,events:2,radar:3,rules:4,net:5,config:6,guide:7', nav.join(','));

await page.evaluate(() => document.activeElement && document.activeElement.blur());
await page.keyboard.press('4');
check('tastiera: il tasto 4 apre Regole', (await page.textContent('#view-title')) === 'Regole');
await page.keyboard.press('6');
check('tastiera: il tasto 6 apre Configurazione', (await page.textContent('#view-title')) === 'Configurazione');
await page.keyboard.press('2');
await page.waitForSelector('#ev-q');
await page.focus('#ev-q');
await page.keyboard.type('3');
check('tastiera: digitare un numero nella ricerca NON cambia tab', (await page.textContent('#view-title')) === 'Eventi' && (await page.inputValue('#ev-q')) === '3');
await page.fill('#ev-q', '');

// ora locale: 10:00:00Z in Europe/Rome (CET/CEST) non deve comparire come 10:00
await page.evaluate(() => window.__emit('shield:event', { time: '2026-11-04T10:00:00Z', action: 'audit', pid: 5, comm: 'tz', exe: '/usr/bin/tz', rule: 'tzcheck', inode: 9 }));
await page.fill('#ev-q', 'tzcheck');
await page.waitForTimeout(100);
const tzRow = await page.textContent('#ev-body table');
check('eventi: orario in ora locale, non UTC', tzRow.includes('11:00:00') && !tzRow.includes('10:00:00'), tzRow.replace(/\s+/g, ' ').slice(0, 80));
await page.fill('#ev-q', '');

// footer: appena aperta la GUI non deve dire "dati fermi" (lastStatusAt dal primo GetStatus)
const conn = await page.textContent('#conn');
check('footer: nessun "dati fermi" dopo il primo stato', conn.includes('aggiornato') && !conn.includes('dati fermi'), conn.trim());

// raggruppa: stessi (tipo, regola, exe) = una riga con contatore
await page.evaluate(() => { for (let i = 0; i < 6; i++) window.__emit('shield:event', { time: '2026-11-04T10:01:0' + i + 'Z', action: 'audit', pid: 900 + i, comm: 'prompt', exe: '/usr/bin/prompt', rule: 'grp', inode: 1 }); });
await page.fill('#ev-q', 'grp');
await page.waitForTimeout(100);
const flatRows = await page.evaluate(() => document.querySelectorAll('#ev-body table tr').length);
await page.click('#ev-group');
await page.waitForTimeout(100);
const grpTxt = await page.textContent('#ev-body table');
const grpRows = await page.evaluate(() => document.querySelectorAll('#ev-body table tr').length);
check('eventi: "raggruppa" unisce le righe uguali e mostra ×6', flatRows === 7 && grpRows === 2 && grpTxt.includes('×6'), `piatta=${flatRows} raggruppata=${grpRows}`);
await page.click('#ev-group'); await page.fill('#ev-q', '');

// Configurazione: riepilogo, avviso di disallineamento file/demone, dialogo di conferma
await page.evaluate(() => { window.__cfgMode = 'enforce'; });
await page.click('#sidebar button[data-view="config"]');
await page.waitForSelector('#m-audit');
const cfgTxt = await page.textContent('#content');
check('config: avviso "il file dice enforce ma il demone gira in audit"', /file dice\s*enforce/.test(cfgTxt) && /girando in\s*audit/.test(cfgTxt));
check('config: elenca interfacce XDP, poisoning e VPN', cfgTxt.includes('Interfacce con XDP') && cfgTxt.includes('Drop poisoning') && cfgTxt.includes('VPN'));
check('config: il file e ripiegato e copiabile', await page.evaluate(() => !!document.querySelector('details.file') && !!document.querySelector('details.file [data-copy]')));
await page.click('#m-enforce');
await page.waitForSelector('#dlg');
const focused = await page.evaluate(() => document.activeElement && document.activeElement.id);
check('conferma enforce: focus su Annulla (Invio non passa a enforce per errore)', focused === 'dlg-no', focused);
await page.keyboard.press('Escape');
await page.waitForTimeout(80);
check('conferma enforce: Esc annulla senza chiamare SetConfigMode', (await page.evaluate(() => document.getElementById('dlg') === null && window.__setModeCalls.length === 0)));
await page.click('#m-enforce');
await page.waitForSelector('#dlg');
await page.click('#dlg-ok');
await page.waitForTimeout(150);
check('conferma enforce: OK chiama SetConfigMode("enforce")', (await page.evaluate(() => window.__setModeCalls.join(','))) === 'enforce');
await page.evaluate(() => { window.__cfgMode = 'audit'; });

// race: lettura config lenta + cambio tab subito dopo non deve sovrascrivere la pagina nuova
await page.evaluate(() => { window.__cfgDelay = 250; });
await page.click('#sidebar button[data-view="config"]');
await page.click('#sidebar button[data-view="rules"]');
await page.waitForTimeout(500);
check('config: una lettura lenta non copre la tab aperta dopo', (await page.textContent('#view-title')) === 'Regole' && !(await page.textContent('#content')).includes('Riepilogo'));
await page.evaluate(() => { window.__cfgDelay = 0; });

// Stato: verdetto e controlli separati, regola piu attiva anche in audit
await page.click('#sidebar button[data-view="status"]');
await page.waitForTimeout(100);
const stTxt = await page.textContent('#content');
check('stato: verdetto "Protezione parziale" in audit', stTxt.includes('Protezione parziale') && stTxt.includes('audit'));
check('stato: "Regola più attiva" non resta vuota in audit', !/Regola più attiva\s*—/.test(stTxt), stTxt.replace(/\s+/g, ' ').match(/Regola più attiva[^A-Z]{0,30}/)?.[0]);
check('stato: sezione Controlli con Ferma e cambio modalità esplicito', stTxt.includes('Controlli') && stTxt.includes('Ferma') && /passa a enforce/.test(stTxt));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { hook_lsm: false })));
await page.waitForTimeout(80);
check('stato: hook LSM spento = "Protezione non attiva"', (await page.textContent('#content')).includes('Protezione non attiva'));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { hook_lsm: true })));

// Radar: tabella compatta ordinata, niente schede
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { top_sources: [
  { ip: '10.0.0.1', poison: 1, subnet: 0, total: 1, last_seen: '2026-11-04T10:00:00Z' },
  { ip: '10.0.0.2', poison: 9, subnet: 0, total: 9, last_seen: '2026-11-04T10:00:00Z' },
  { ip: '10.0.0.3', poison: 4, subnet: 0, total: 4, last_seen: '2026-11-04T10:00:00Z' } ] })));
await page.click('#sidebar button[data-view="radar"]');
await page.waitForTimeout(150);
const radar = await page.evaluate(() => ({ rows: [...document.querySelectorAll('#radar-list tr[data-ip]')].map(r => r.dataset.ip), cards: document.querySelectorAll('#radar-list .rule').length, sub: document.querySelector('#content .sub').textContent }));
check('radar: tabella ordinata per drop, senza schede', radar.rows.join(',') === '10.0.0.2,10.0.0.3,10.0.0.1' && radar.cards === 0, radar.rows.join(','));
check('radar: riassume le reti (3 sorgenti in 1 rete 10.0.0.0/24)', radar.sub.includes('3 sorgenti in 1 rete (10.0.0.0/24)'), radar.sub);

// Guida: pulsanti copia e "Da sorgente" ripiegato
await page.click('#sidebar button[data-view="guide"]');
await page.waitForTimeout(80);
const gd = await page.evaluate(() => ({ copy: document.querySelectorAll('#content .code-row [data-copy]').length, srcOpen: document.querySelector('details.src').open }));
check('guida: ogni comando ha il pulsante copia, "da sorgente" chiuso', gd.copy >= 10 && gd.srcOpen === false, JSON.stringify(gd));


// --- Radar: rumore o da verificare, tasso, host noti, legenda (2026-11-04)
const radarSt = (sources, time) => Object.assign({}, window.__status, { time, top_sources: sources });
const quiet = (n, c, ts = '2026-11-04T10:00:00Z') => ({ ip: '10.0.0.' + n, poison: c, subnet: 0, total: c, last_seen: ts });
await page.click('#sidebar button[data-view="radar"]');
await page.evaluate((st) => window.__emit('shield:status', st), { ...(await page.evaluate(() => window.__status)), time: '2026-11-04T10:00:00Z',
  top_sources: [quiet(1, 3), quiet(2, 2), quiet(3, 1), quiet(4, 120), { ip: '172.16.9.9', poison: 4, subnet: 0, total: 4, last_seen: '2026-11-04T10:00:00Z' }, { ip: '10.0.0.7', poison: 0, subnet: 9, total: 9, last_seen: '2026-11-04T10:00:00Z' }] });
await page.waitForTimeout(150);
const cls = await page.evaluate(() => Object.fromEntries([...document.querySelectorAll('#radar-list tr[data-ip]')].map(r => [r.dataset.ip, r.dataset.class])));
check('radar: pochi drop nella rete comune = rumore probabile', cls['10.0.0.1'] === 'noise' && cls['10.0.0.2'] === 'noise', JSON.stringify(cls));
check('radar: tanti drop da un solo IP = da verificare', cls['10.0.0.4'] === 'attention');
check('radar: IP fuori dalla rete delle altre = da verificare', cls['172.16.9.9'] === 'attention');
check('radar: subnet bloccata dall utente = bloccata', cls['10.0.0.7'] === 'blocked');
const banner = await page.textContent('#content .verdict');
check('radar: banner conta le sorgenti da verificare e dichiara il limite', banner.includes('2 sorgenti da verificare') && banner.includes('non distingue'), banner.replace(/\s+/g, ' ').slice(0, 90));
const verify = await page.textContent('#radar-verify');
check('radar: per le sorgenti da verificare ci sono i comandi (ip neigh, tcpdump) copiabili', verify.includes('ip neigh show 10.0.0.4') && verify.includes('tcpdump') && (await page.locator('#radar-verify [data-copy]').count()) >= 4);

// tasso: stesso IP, due stati a 2 minuti di distanza (orario del demone) -> 60 drop in 2 min = 30/min => da verificare
await page.evaluate(() => window.__emit('shield:status', window.__rs = { ...window.__status, time: '2026-11-04T10:02:00Z', top_sources: [
  { ip: '10.0.0.1', poison: 63, subnet: 0, total: 63, last_seen: '2026-11-04T10:02:00Z' }, { ip: '10.0.0.2', poison: 2, subnet: 0, total: 2, last_seen: '2026-11-04T10:00:00Z' }, { ip: '10.0.0.3', poison: 1, subnet: 0, total: 1, last_seen: '2026-11-04T10:00:00Z' }] }));
await page.waitForTimeout(150);
const rated = await page.evaluate(() => { const r = document.querySelector('#radar-list tr[data-ip="10.0.0.1"]'); return { cls: r.dataset.class, why: r.textContent }; });
check('radar: il tasso sostenuto (30 drop/min) rende un IP da verificare', rated.cls === 'attention' && /30 drop\/min/.test(rated.why), rated.why.replace(/\s+/g, ' ').slice(0, 100));

// segna come noto: passa a "nota", sopravvive al ridisegno
await page.click('#radar-list tr[data-ip="10.0.0.1"] [data-known]');
await page.waitForTimeout(100);
await page.evaluate(() => window.__emit('shield:status', { ...window.__rs, time: '2026-11-04T10:02:30Z' }));
await page.waitForTimeout(100);
check('radar: "segna come noto" -> nota, e resta dopo un nuovo stato', (await page.getAttribute('#radar-list tr[data-ip="10.0.0.1"]', 'data-class')) === 'known');
await page.click('#radar-list tr[data-ip="10.0.0.1"] [data-known]');
await page.waitForTimeout(100);
check('radar: "togli nota" lo riporta alla classificazione', (await page.getAttribute('#radar-list tr[data-ip="10.0.0.1"]', 'data-class')) === 'attention');

const legend = await page.textContent('#radar-legend');
check('radar: legenda a sezioni (cosa vedi, colori, rumore o attacco, cosa fare) e ammette il limite', ['Cosa vedi', 'Colori', 'Rumore o attacco?', 'Cosa fare', 'non distingue'].every(t => legend.includes(t)));

// Guida: schede, punti di controllo dal vivo, problemi comuni
await page.click('#sidebar button[data-view="guide"]');
await page.waitForTimeout(100);
const gTabs = await page.evaluate(() => [...document.querySelectorAll('[data-gtab]')].map(b => b.dataset.gtab).join(','));
check('guida: quattro schede (iniziare, schermate, glossario, problemi)', gTabs === 'start,screens,terms,trouble', gTabs);
const chk = await page.textContent('#content .checklist');
check('guida: punti di controllo dal vivo (demone, LSM, XDP, modalita)', ['Il demone risponde', 'Hook LSM', 'Filtro XDP', 'Modalità audit'].every(t => chk.includes(t)), chk.replace(/\s+/g, ' ').slice(0, 80));
await page.evaluate(() => window.__emit('shield:status', { ...window.__status, hook_lsm: false }));
await page.waitForTimeout(100);
check('guida: hook LSM spento si vede nei punti di controllo', (await page.locator('.checklist .check.ko').count()) === 1);
await page.evaluate(() => window.__emit('shield:status', { ...window.__status, hook_lsm: true }));
await page.click('[data-gtab="screens"]');
const scr = await page.textContent('#content');
check('guida: scheda schermate spiega ogni tab e le scorciatoie', ['Sono protetto?', 'Chi mi disturba in rete?', 'Cosa è protetto', '1', '7'].every(t => scr.includes(t)));
await page.click('[data-gtab="terms"]');
const trm = await page.textContent('#content');
check('guida: glossario con audit/enforce, XDP, poisoning, canary', ['Audit / Enforce', 'XDP', 'Poisoning', 'Canary', 'Fail-closed'].every(t => trm.includes(t)));
await page.click('[data-gtab="trouble"]');
const tb = await page.evaluate(() => ({ n: document.querySelectorAll('.faq details').length, copy: document.querySelectorAll('.faq [data-copy]').length, txt: document.querySelector('.faq').textContent }));
check('guida: problemi comuni con comandi copiabili (permission denied, bpf, interfacce)', tb.n >= 6 && tb.copy >= 5 && tb.txt.includes('permission denied') && tb.txt.includes('bpf') && tb.txt.includes('interface:'), `domande=${tb.n} copia=${tb.copy}`);
await page.click('[data-gtab="start"]');


// --- Senza demone: primo avvio e demone spento (demo con comandi copiabili, preflight nuovo)
async function offlinePage(svc) {
  const pg = await browser.newPage({ viewport: { width: 1100, height: 760 }, timezoneId: 'Europe/Rome' });
  pg.on('pageerror', e => errors.push(String(e)));
  await pg.addInitScript((svcState) => {
    window.go = { main: { App: {
      GetStatus: async () => { throw new Error('dial unix /run/zt-shield/api.sock: no such file or directory'); },
      SocketPath: async () => '/run/zt-shield/api.sock', Version: async () => '0.0.4',
      ServiceState: async () => svcState,
      Preflight: async () => [
        { name: 'Kernel ≥ 5.15 (7.0.0)', ok: true },
        { name: 'Servizio zt-shield (installato o installabile)', ok: true },
        { name: 'Utente protetto (user:) nel config', ok: false, hint: 'lo imposta l\'installazione guidata, oppure: sudoedit /etc/zt-shield/shield.yaml' },
      ],
    } } };
    window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
    localStorage.setItem('zs-onboarded-v2', '1');
  }, svc);
  await pg.goto(`http://127.0.0.1:${port}/`);
  await pg.waitForSelector('.offline');
  await pg.waitForSelector('#preflight .check');
  return pg;
}
const first = await offlinePage('missing');
const frTxt = await first.textContent('#content');
check('primo avvio: propone la demo con dati finti', frTxt.includes('Prova con dati finti') && frTxt.includes('Benvenuto'));
const frCopy = await first.evaluate(() => [...document.querySelectorAll('.offline details [data-copy]')].map(b => b.dataset.copy));
check('primo avvio: i tre comandi della demo sono copiabili (mockd, gui, pkill)', frCopy.length === 3 && frCopy[0] === 'ZT_SOCKET=/tmp/z.sock zt-mockd &' && frCopy[1] === 'ZT_SOCKET=/tmp/z.sock zt-gui' && frCopy[2] === 'pkill zt-mockd', frCopy.join(' | '));
const frPre = await first.textContent('#preflight');
check('preflight: mostra servizio e utente protetto, con il suggerimento quando manca user:', frPre.includes('Servizio zt-shield') && frPre.includes('Utente protetto') && frPre.includes('sudoedit') && !frPre.includes('install_service.sh'), frPre.replace(/\s+/g, ' ').slice(0, 120));
check('preflight: il controllo mancante e rosso, gli altri verdi', (await first.locator('#preflight .check.ko').count()) === 1 && (await first.locator('#preflight .check.ok').count()) === 2);
await first.close();

const off = await offlinePage('inactive');
const offTxt = await off.textContent('#content');
check('demone spento: spiega cosa manca e offre installa/attiva', offTxt.includes('PROTEZIONE DISATTIVA') && offTxt.includes('Installa e attiva'));
await off.click('.offline details summary');
const offCopy = await off.evaluate(() => [...document.querySelectorAll('.offline [data-copy]')].map(b => b.dataset.copy));
check('demone spento: stessa demo, stessi comandi copiabili', offCopy.includes('ZT_SOCKET=/tmp/z.sock zt-mockd &') && offCopy.includes('ZT_SOCKET=/tmp/z.sock zt-gui') && offCopy.includes('pkill zt-mockd'));
check('demone spento: "Solo avvia" avverte che serve user: nel config', (await off.textContent('.offline')).includes('Serve user: nel config'));
await off.close();

// Guida con demone acceso: la demo e in fondo alla scheda "Per iniziare"
await page.click('#sidebar button[data-view="guide"]');
await page.waitForTimeout(100);
const gDemo = await page.evaluate(() => [...document.querySelectorAll('#content [data-copy]')].map(b => b.dataset.copy).filter(c => /zt-mockd|zt-gui|pkill/.test(c)));
check('guida: la demo e nella scheda "Per iniziare" con gli stessi comandi', gDemo.length === 3, gDemo.join(' | '));

if (shots) {
  fs.mkdirSync(shots, { recursive: true });
  for (const v of ['status', 'events', 'net', 'guide']) {
    await page.click(`#sidebar button[data-view="${v}"]`);
    await page.waitForTimeout(250);
    await page.screenshot({ path: path.join(shots, `${label}-${v}.png`) });
  }
}

check('nessun errore JavaScript nella pagina', errors.length === 0, errors.join(' | '));
await browser.close();
server.close();
const failed = results.filter(x => !x).length;
console.log(`\n[${label}] ${results.length - failed} ok, ${failed} falliti`);
process.exit(failed ? 1 : 0);
