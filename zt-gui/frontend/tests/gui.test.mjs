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
    BootEnabled: async () => window.__boot,
    SetBootEnabled: async (on) => { window.__bootCalls.push(on); window.__boot = on; },
    RulesModel: async () => JSON.parse(JSON.stringify(window.__rm)),
    CheckProgram: async (x) => JSON.parse(JSON.stringify(window.__progs[x] || { input: x, found: false, why: 'non trovato sul sistema' })),
    ApplyRules: async (c) => { window.__applyCalls.push(c); if (window.__applyFail) throw new Error(window.__applyFail); window.__rm.choice = c; },
    PreviewPaths: async (ps) => (ps.some(p => p === '/etc') ? { errors: ['"/etc" è troppo largo: proteggerlo bloccherebbe quasi ogni programma'], matched: 0, examples: [], missing: [], warnings: [] } : { errors: [], matched: 3, examples: ['/home/u/Documents/a.kdbx'], missing: [], warnings: ['Sono 3 file: controlla'] }),
    ApplyInterfaces: async (names) => { window.__ifCalls.push(names); if (window.__ifFail) throw new Error(window.__ifFail); window.__rm.choice = Object.assign({}, window.__rm.choice, { interface: names.join(',') }); },
    PickPath: async (k) => (k === 'dir' ? '.wallet' : 'Documents/segreto.txt'),
    MakeTrusted: async (x) => { window.__trustCalls.push(x); const t = window.__trustResult[x]; if (!t) throw new Error('no'); return t; },
  } } };
  const grp = (id, name, inProfile, allow, paths) => ({ id, name, desc: id, paths, allow, extra_allow: null, in_profile: inProfile, active: inProfile });
  const prog = (name, path, o) => Object.assign({ input: name, name, path, found: true, trusted: true, trust_err: '', verdict_ok: true, why: '', fix: '', ok: true, alt: '' }, o || {});
  const tool = (id, label, rules, reads, p, allowed) => Object.assign({ id, label, names: [id], rules, reads }, p, { allowed: allowed || [] });
  window.__rm = {
    profile: 'home', manual: false, manual_rules: false, global_mode: 'audit', error: '', custom: [], helpers: [{ id: 'localsearch', label: 'Indicizzatore di GNOME (localsearch)', why: 'scansiona i file in background', found: ['/usr/libexec/localsearch-extractor-3'] }, { id: 'altro', label: 'Non presente', why: 'x', found: [] }], choice: { enable_groups: null, disable_rules: null, allow_extra: null },
    groups: [
      grp('ssh', 'ssh-keys', true, ['ssh', 'ssh-add'], ['.ssh/id_*']),
      grp('cloud', 'cloud-creds', true, ['kubectl', 'helm', 'k9s'], ['.kube/config']),
      grp('tokens', 'dev-tokens', true, ['git', 'docker'], ['.docker/config.json']),
      grp('gpg', 'gpg-keys', true, ['gpg'], ['.gnupg/private-keys-v1.d']),
      grp('browsers', 'browser-secrets', false, ['/opt/google/chrome/chrome'], ['.config/google-chrome/*/Cookies']),
    ],
    tools: [
      tool('k3d', 'k3d', ['dev-tokens'], 'legge ~/.docker/config.json', prog('k3d', '/usr/local/bin/k3d')),
      tool('helm', 'Helm', ['cloud-creds', 'dev-tokens'], 'usa kubeconfig e registry', prog('helm', '/usr/local/bin/helm'), ['cloud-creds']),
      tool('k9s', 'k9s', ['cloud-creds'], 'legge il kubeconfig', prog('k9s', '/home/linuxbrew/.linuxbrew/Cellar/k9s/0.51.0/bin/k9s', { trusted: false, trust_err: 'appartiene a uid 1000', ok: false, fix: 'sudo install ...' })),
      tool('oh-my-posh', 'oh-my-posh', ['cloud-creds'], 'il prompt legge il kubeconfig', prog('oh-my-posh', '/home/u/.local/bin/oh-my-posh', { trusted: false, trust_err: 'appartiene a uid 1000', ok: false, fix: 'sudo install ...' })),
      tool('stern', 'stern', ['cloud-creds'], 'log dei pod', { name: 'stern', found: false, ok: false }),
    ],
  };
  window.__progs = {
    '/usr/local/bin/k3d': prog('k3d', '/usr/local/bin/k3d'),
    '/usr/local/bin/helm': prog('helm', '/usr/local/bin/helm'),
    '/usr/bin/cat': prog('cat', '/usr/bin/cat', { verdict_ok: false, ok: false, why: 'lettore/copiatore generico: chi lo invoca sceglie il file' }),
    'lazygit': prog('lazygit', '/usr/local/bin/lazygit'),
    'keepassxc': prog('keepassxc', '/usr/bin/keepassxc'),
    'miotool': prog('miotool', '/home/u/.local/bin/miotool', { trusted: false, ok: false, fix: 'sudo install ...', trust_err: 'appartiene a uid 1000' }),
    '/usr/local/bin/lazygit': prog('lazygit', '/usr/local/bin/lazygit'),
  };
  window.__trustResult = {
    '/home/linuxbrew/.linuxbrew/Cellar/k9s/0.51.0/bin/k9s': prog('k9s', '/usr/local/bin/k9s'),
  };
  window.__applyCalls = []; window.__trustCalls = []; window.__applyFail = ''; window.__ifCalls = []; window.__ifFail = '';
  window.__cfgMode = 'audit'; window.__cfgDelay = 0; window.__setModeCalls = []; window.__boot = false; window.__bootCalls = [];
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
check('la versione e sempre visibile nella barra laterale', (await page.textContent('#ver')) === 'ZeroShield v9.9.9-test', await page.textContent('#ver'));

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
  const t = [...document.querySelectorAll('#content .tile')].find(c => c.querySelector('.tile-k') && c.querySelector('.tile-k').textContent === l);
  return t ? parseInt(t.querySelector('.tile-v').textContent, 10) : NaN;
}, label);
const settled = await counter('Attività');
check('i contatori di sessione mostrano il valore reale a regime', settled > 0, `Letture=${settled}`);
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status)));
await page.waitForTimeout(60); // molto meno dei 400 ms di animazione
const afterRerender = await counter('Attività');
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

// Avvio all'accensione: spento di partenza, attivarlo non chiede conferma, spegnerlo si
await page.click('#sidebar button[data-view="rules"]');
await page.click('#sidebar button[data-view="config"]');
await page.waitForSelector('#boot-toggle');
check('avvio: parte spento e lo dice', (await page.textContent('#boot-toggle')).includes('Spento'));
await page.click('#boot-toggle');
await page.waitForFunction(() => document.getElementById('boot-toggle')?.textContent.includes('Attivo'));
check('avvio: attivare chiama SetBootEnabled(true) senza dialogo', (await page.evaluate(() => window.__bootCalls.join(','))) === 'true' && (await page.evaluate(() => document.getElementById('dlg') === null)));
await page.click('#boot-toggle');
await page.waitForSelector('#dlg');
await page.keyboard.press('Escape');
await page.waitForTimeout(80);
check('avvio: spegnere chiede conferma e Esc non cambia nulla', (await page.evaluate(() => window.__bootCalls.join(','))) === 'true');
await page.click('#boot-toggle');
await page.waitForSelector('#dlg');
await page.click('#dlg-ok');
await page.waitForFunction(() => document.getElementById('boot-toggle')?.textContent.includes('Spento'));
check('avvio: confermato, chiama SetBootEnabled(false)', (await page.evaluate(() => window.__bootCalls.join(','))) === 'true,false');

// Guida delle Regole: in enforce tutti e tre i passi risultano fatti (prima il 3 restava «in corso»)
await page.click('#sidebar button[data-view="rules"]');
await page.waitForSelector('.rl-steps');
await page.evaluate(() => { window.__status = Object.assign({}, window.__status, { mode: 'enforce' }); window.__emit('shield:status', window.__status); });
await page.waitForFunction(() => document.querySelectorAll('.rl-steps li.done').length === 3);
check('regole: in enforce i tre passi della guida sono tutti completati', await page.evaluate(() => document.querySelectorAll('.rl-steps li.done').length === 3 && !document.querySelector('.rl-steps li.now')));
await page.evaluate(() => { window.__status = Object.assign({}, window.__status, { mode: 'audit' }); window.__emit('shield:status', window.__status); });

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
check('stato: in audit la scheda in alto dice cosa fare (osservi, non blocchi)', stTxt.includes('Stai osservando, non bloccando') && /programm[ai]/.test(stTxt));
check('stato: un solo pulsante principale in alto', (await page.locator('.hero .hero-btn').count()) === 1);
check('stato: tre tessere in linguaggio semplice (Segreti, Rete, Attività)', ['Segreti', 'Rete', 'Attività'].every(t => stTxt.includes(t)));
check('stato: lista "Da fare" con avanzamento', stTxt.includes('Da fare') && /\d su \d/.test(stTxt) && stTxt.includes('Servizio attivo'));
check('stato: ultimi eventi in una frase leggibile', stTxt.includes('Ultimi eventi') && stTxt.includes('ha letto «'));
check('stato: i dettagli tecnici sono ripiegati', (await page.evaluate(() => document.querySelector('details.tech') && !document.querySelector('details.tech').open)) === true);
check('stato: nomi tecnici delle regole non compaiono nelle frasi', !/ha letto «(ssh-keys|cloud-creds)/.test(stTxt));
check('stato: sezione Controlli con Ferma e cambio modalità esplicito', stTxt.includes('Controlli') && stTxt.includes('Ferma') && /passa a enforce/.test(stTxt));
await page.click('.hero .hero-btn');
check('stato: il pulsante principale porta alle Regole', (await page.textContent('#view-title')) === 'Regole');
await page.click('#sidebar button[data-view="status"]');
await page.waitForTimeout(100);
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { version: '0.0.1' })));
await page.waitForTimeout(80);
check('stato: demone e finestra con versioni diverse -> avviso', (await page.textContent('#content')).includes('Il demone è alla versione 0.0.1'));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { version: '9.9.9-test' })));
await page.waitForTimeout(80);
check('stato: stessa versione -> nessun avviso', !(await page.textContent('#content')).includes('Il demone è alla versione'));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { mode: 'enforce', rules: [{ name: 'ssh-keys', paths: ['.ssh/id_*'], allow: ['ssh'], mode: 'enforce' }] })));
await page.waitForTimeout(80);
check('stato: tutte le protezioni in Blocca -> "Sei protetto"', (await page.textContent('.hero')).includes('Sei protetto'));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { mode: 'audit', rules: [{ name: 'ssh-keys', paths: ['.ssh/id_*'], allow: ['ssh'], mode: 'enforce' }, { name: 'gpg-keys', paths: ['.gnupg'], allow: ['gpg'], mode: 'audit' }] })));
await page.waitForTimeout(80);
check('stato: modalita miste -> "Protetto in parte"', (await page.textContent('.hero')).includes('Protetto in parte'));
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { mode: 'audit', rules: [{ name: 'ssh-keys', paths: ['.ssh/id_*'], allow: ['ssh', 'cat', 'x', 'prompt'], mode: 'audit' }] })));
await page.waitForTimeout(80);
check('stato: audit senza programmi da rivedere -> propone "Passa a Blocca"', (await page.textContent('.hero')).includes('Passa a Blocca'));
await page.evaluate(() => { window.__status = Object.assign({}, window.__status, { mode: 'audit', rules: [{ name: 'ssh-keys', paths: ['.ssh/id_*'], allow: ['ssh'] }], version: undefined }); window.__emit('shield:status', window.__status); });
await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { hook_lsm: false })));
await page.waitForTimeout(80);
check('stato: hook LSM spento = "I tuoi file non sono protetti"', (await page.textContent('#content')).includes('I tuoi file non sono protetti'));
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

// Radar con sorgenti IPv6: ogni famiglia ha la sua rete di riferimento (/24 per IPv4, /64 per IPv6)
await page.evaluate(() => {
  const mk = (ip, t) => ({ ip, poison: t, subnet: 0, total: t, last_seen: '2026-11-04T10:00:00Z' });
  window.__status = Object.assign({}, window.__status, { top_sources: [
    mk('10.0.0.1', 4), mk('10.0.0.2', 3), mk('10.0.0.3', 2), mk('10.0.0.4', 2),
    mk('fe80::1111:2222:3333:4444', 5), mk('fe80::aaaa:bbbb:cccc:dddd', 4), mk('fe80::1', 3), mk('fe80::2', 2),
    mk('2001:db8:1:2::9', 6),
  ] });
  window.__emit('shield:status', window.__status);
});
await page.waitForTimeout(150);
const cls6 = await page.$$eval('#radar-list tr[data-ip]', rows => Object.fromEntries(rows.map(r => [r.dataset.ip, r.dataset.class])));
check('radar: le sorgenti IPv6 compaiono nell elenco', 'fe80::1' in cls6 && '2001:db8:1:2::9' in cls6, Object.keys(cls6).join(' '));
check('radar: IPv4 e IPv6 della propria rete sono rumore (non «fuori rete» per colpa dell altra famiglia)', cls6['10.0.0.1'] === 'noise' && cls6['fe80::1'] === 'noise', JSON.stringify(cls6));
check('radar: un IPv6 di un altro /64 e da verificare, con il motivo', cls6['2001:db8:1:2::9'] === 'attention' && (await page.textContent('#radar-list tr[data-ip="2001:db8:1:2::9"]')).includes('fuori dalla rete'));

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
    localStorage.setItem('zs-onboarded-v2', '1'); localStorage.setItem('zs-seen-version', '0.0.4');
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


// ---------------------------------------------------------------------------
// Schermata Regole: catalogo guidato (rules.js)
// ---------------------------------------------------------------------------
await page.click('#sidebar button[data-view="rules"]');
await page.waitForSelector('#rl-root');
const rlTxt = await page.textContent('#content');
check('regole: 5 gruppi con nomi comprensibili', ['Chiavi SSH', 'Kubernetes e cloud', 'Token degli strumenti di sviluppo', 'Chiavi GPG', 'Cookie e password dei browser'].every(t => rlTxt.includes(t)));
check('regole: i nomi tecnici delle regole non sono il titolo', (await page.locator('.rl-title b').allTextContents()).every(t => !/-keys|-creds|-tokens|-secrets/.test(t)));
check('regole: i tre passi (Osserva, Autorizza, Blocca) sono visibili', ['Osserva', 'Autorizza', 'Blocca'].every(t => rlTxt.includes(t)));
check('regole: nessuna sporcizia (undefined/null/[object)', !/undefined|\bnull\b|\[object/.test(rlTxt));
check('regole: senza modifiche non c\'e la barra Applica', (await page.locator('#rl-apply').count()) === 0);
check('regole: browser e una protezione facoltativa e spenta', (await page.locator('[data-grp="browsers"]').isChecked()) === false && rlTxt.includes('facoltativa'));
check('regole: programmi trovati in cima, non installati ripiegati', (await page.locator('.rl-tool').count()) >= 4 && rlTxt.includes('Altri programmi noti non installati (1)'));
check('regole: k9s e oh-my-posh spiegano perche serve un passo in piu', (await page.locator('[data-trust]').count()) === 2 && rlTxt.includes('una cartella che puoi modificare tu'));
check('regole: helm risulta gia autorizzato per cloud ma non per i token', rlTxt.includes('Helm'));

// Autorizzata la copia protetta ma il terminale lancia l'altra: la GUI lo dice (visto con oh-my-posh)
await page.evaluate(() => { const t = window.__rm.tools.find(x => x.id === 'oh-my-posh'); window.__saveT = JSON.stringify(t); t.alt = '/usr/local/bin/oh-my-posh'; t.ok = false; window.__saveG = JSON.stringify(window.__rm.groups); window.__rm.groups.find(g => g.name === 'cloud-creds').allow.push('/usr/local/bin/oh-my-posh'); });
await page.click('#sidebar button[data-view="status"]');
await page.click('#sidebar button[data-view="rules"]');
await page.waitForSelector('.rl-tool');
const shadowTxt = await page.locator('.rl-tool', { hasText: 'oh-my-posh' }).textContent();
check('regole: autorizzato ma lanci un altro percorso, la GUI avvisa e propone l\'alias', shadowTxt.includes('lancia la copia protetta') && shadowTxt.includes('alias oh-my-posh=/usr/local/bin/oh-my-posh'), await page.locator('.rl-tool', { hasText: 'oh-my-posh' }).first().innerHTML());
await page.evaluate(() => { const i = window.__rm.tools.findIndex(x => x.id === 'oh-my-posh'); window.__rm.tools[i] = JSON.parse(window.__saveT); window.__rm.groups = JSON.parse(window.__saveG); });
await page.click('#sidebar button[data-view="status"]');
await page.click('#sidebar button[data-view="rules"]');
await page.waitForSelector('.rl-tool');

// Autorizzare k3d crea una bozza e la barra con il conteggio
await page.click('[data-auth="k3d"]');
check('regole: autorizzare mette una modifica in bozza', (await page.textContent('.rl-bar')).includes('1 modifica'));
check('regole: nulla e stato scritto prima di Applica', (await page.evaluate(() => window.__applyCalls.length)) === 0);
await page.click('#rl-cancel');
check('regole: Annulla butta via la bozza', (await page.locator('.rl-bar').count()) === 0);

// Bulk + passo "Rendi affidabile" + applica
await page.click('#rl-bulk-tools');
check('regole: "Autorizza tutti i pronti" aggiunge k3d e helm', (await page.textContent('.rl-bar')).includes('modifiche'));
await page.click('[data-trust="k9s"]');
check('regole: "Rendi affidabile" chiede conferma e spiega la copia in /usr/local/bin', (await page.textContent('#dlg')).includes('/usr/local/bin'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__trustCalls.length === 1);
check('regole: la copia protetta e richiesta per il percorso giusto', (await page.evaluate(() => window.__trustCalls[0])).endsWith('/k9s'));
await page.waitForFunction(() => document.querySelectorAll('.rl-bar').length === 1);
await page.click('#rl-apply');
const dlg = await page.textContent('#dlg');
check('regole: la conferma elenca cosa cambia in italiano', dlg.includes('Autorizzi «k3d»') && dlg.includes('Token degli strumenti di sviluppo') && dlg.includes('torna da solo'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__applyCalls.length === 1);
const applied = await page.evaluate(() => window.__applyCalls[0]);
check('regole: ApplyRules riceve solo percorsi assoluti nella regola giusta',
  applied.allow_extra['dev-tokens'].join() === '/usr/local/bin/helm,/usr/local/bin/k3d' && applied.allow_extra['cloud-creds'].join() === '/usr/local/bin/k9s', JSON.stringify(applied));
await page.waitForFunction(() => !document.querySelector('.rl-bar'));
check('regole: dopo Applica la barra sparisce e k3d risulta autorizzato', (await page.textContent('#content')).includes('✓ autorizzato'));

// Accendere i browser e riapplicare
await page.check('[data-grp="browsers"]');
await page.click('#rl-apply'); await page.click('#dlg-ok');
await page.waitForFunction(() => window.__applyCalls.length === 2);
check('regole: accendere i browser scrive enable_groups', (await page.evaluate(() => window.__applyCalls[1].enable_groups)).join() === 'browsers');

// Errore dall'applicazione: si vede, e la bozza resta
await page.uncheck('[data-grp="gpg"]');
await page.evaluate(() => { window.__applyFail = 'il servizio non riparte: bpf'; });
await page.click('#rl-apply'); await page.click('#dlg-ok');
await page.waitForSelector('#toast.danger.show');
check('regole: se l\'applicazione fallisce l\'errore e visibile e la bozza resta', (await page.textContent('#toast')).includes('bpf') && (await page.locator('#rl-apply').count()) === 1);
await page.evaluate(() => { window.__applyFail = ''; });
await page.click('#rl-cancel');

// Visti in audit + giudizio per programma + indicatore di prontezza
await page.evaluate(() => {
  const ev = (exe, rule, n) => { for (let i = 0; i < n; i++) window.__emit('shield:event', { time: '2026-10-05T10:02:0' + i + 'Z', action: 'audit', pid: 500 + i, comm: exe.split('/').pop(), exe, rule, inode: 7 }); };
  ev('/usr/bin/cat', 'cloud-creds', 2);
  ev('/usr/local/bin/lazygit', 'dev-tokens', 3);
});
await page.waitForFunction(() => { const t = document.querySelector('#rl-seen').textContent; return t.includes('lazygit') && !t.includes('controllo…'); });
const seen = await page.textContent('#rl-seen');
const lazyRow = await page.locator('#rl-seen .rl-tool', { hasText: 'lazygit' }).first().textContent();
check('regole: i visti dicono cosa e successo in parole semplici', lazyRow.includes('ha letto «Token degli strumenti di sviluppo» 3 volte'), lazyRow.replace(/\s+/g, ' '));
check('regole: cat non e autorizzabile e dice perche', seen.includes('non autorizzabile') && seen.includes('lettore/copiatore generico'));
check('regole: un programma di sistema e autorizzabile con un clic', (await page.locator('[data-seen-auth]').count()) === 1);
const rlGuide = await page.textContent("#rl-guide");
check('regole: l\'indicatore dice cosa manca prima di Enforce', rlGuide.includes('Mancano 1 programma') && rlGuide.includes('Autorizza i 1 pronti'), rlGuide.replace(/\s+/g, ' ').slice(0, 300));
await page.click('#rl-bulk-seen');
check('regole: "Autorizza i pronti" mette il programma in bozza', (await page.textContent('.rl-bar')).includes('1 modifica'));
check('regole: con solo cat non autorizzabile non si promette il via libera', !(await page.textContent('#rl-guide')).includes('Vai a Configurazione'));
await page.click('#rl-cancel');

// Un altro programma: controllo con esito spiegato
await page.fill('#rl-in', 'lazygit');
await page.click('#rl-check');
await page.waitForSelector('#rl-add-ok');
await page.selectOption('#rl-add-rule', 'dev-tokens');
await page.click('#rl-add-ok');
check('regole: "un altro programma" aggiunge alla regola scelta', (await page.textContent('.rl-bar')).includes('1 modifica'));
await page.click('#rl-cancel');
await page.fill('#rl-in', 'non-esiste-xyz');
await page.click('#rl-check');
await page.waitForFunction(() => document.getElementById('rl-add-out').textContent.includes('non è stato trovato'));
check('regole: programma inesistente -> messaggio chiaro', true);

// Non deve sfarfallare: testo digitato e dettagli aperti sopravvivono a stato ed eventi in arrivo
await page.fill('#rl-in', 'abc');
await page.evaluate(() => { document.querySelector('.rl-det').open = true; });
for (let i = 0; i < 6; i++) {
  await page.evaluate((i) => { window.__status = { ...window.__status, time: '2026-10-05T10:05:0' + i + 'Z' }; window.__emit('shield:status', window.__status); window.__emit('shield:event', { time: '2026-10-05T10:05:0' + i + 'Z', action: 'audit', pid: 900 + i, comm: 'x', exe: '/usr/bin/x' + i, rule: 'ssh-keys', inode: 1 }); }, i);
  await page.waitForTimeout(40);
}
check('regole: gli eventi in arrivo non cancellano il testo digitato', (await page.inputValue('#rl-in')) === 'abc');
check('regole: ne chiudono i dettagli aperti', await page.evaluate(() => document.querySelector('.rl-det').open));


// ---------------------------------------------------------------------------
// Regole: modalita per singola protezione, programmi tolti, «Proteggi un mio file»
// ---------------------------------------------------------------------------
await page.evaluate(() => { window.__rm.choice = { enable_groups: null, disable_rules: null, allow_extra: null }; window.__applyCalls = []; window.__applyFail = ''; });
await page.click('#sidebar button[data-view="status"]');
await page.click('#sidebar button[data-view="rules"]');
await page.waitForSelector('#rl-root');
await page.waitForTimeout(150);
check('regole: ogni protezione attiva ha la sua modalita (come le altre / osserva / blocca)', (await page.locator('select[data-mode]').count()) >= 4);
check('regole: di default eredita la modalita generale', (await page.locator('select[data-mode="ssh-keys"]').inputValue()) === '' && (await page.locator('.rl-card', { hasText: 'Chiavi SSH' }).first().textContent()).includes('Come le altre (Solo osserva)'));
await page.selectOption('select[data-mode="ssh-keys"]', 'enforce');
check('regole: cambiare la modalita di una protezione e una modifica in bozza', (await page.textContent('.rl-bar')).includes('1 modifica'));
check('regole: la protezione mostra «In Blocca»', (await page.locator('[data-rule-chip="ssh-keys"]').textContent()).includes('In Blocca'));
await page.click('#rl-apply');
check('regole: la conferma lo dice in parole', (await page.textContent('#dlg')).includes('«Chiavi SSH»: passa a Blocca'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__applyCalls.length === 1);
check('regole: ApplyRules riceve rule_modes con il nome tecnico della regola', (await page.evaluate(() => window.__applyCalls[0].rule_modes['ssh-keys'])) === 'enforce');
await page.waitForFunction(() => !document.querySelector('.rl-bar'));

// Togliere un programma di base da una protezione
await page.locator('.rl-card', { hasText: 'Chiavi SSH' }).first().locator('summary').click();
await page.click('[data-rm="ssh-keys"][data-path="ssh"]');
check('regole: togliere un programma di base lo barra e lo mette in bozza', (await page.locator('.rl-chip.gone').count()) === 1 && (await page.textContent('.rl-bar')).includes('1 modifica'));
await page.click('[data-rm="ssh-keys"][data-path="ssh"]');
check('regole: un secondo clic lo rimette (bozza di nuovo pulita)', (await page.locator('.rl-bar').count()) === 0);
await page.click('[data-rm="ssh-keys"][data-path="ssh"]');
await page.click('#rl-apply');
check('regole: la conferma elenca il programma tolto', (await page.textContent('#dlg')).includes('Togli «ssh» da «Chiavi SSH»'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__applyCalls.length === 2);
check('regole: ApplyRules riceve remove_allow', (await page.evaluate(() => window.__applyCalls[1].remove_allow['ssh-keys'])).join() === 'ssh');
await page.waitForFunction(() => !document.querySelector('.rl-bar'));

// Procedura guidata «Proteggi un mio file»
await page.click('#rl-my-new');
await page.waitForSelector('#rl-wiz .wiz');
check('regole: la procedura guidata ha tre passi con testo semplice', ['1 · Cosa proteggere', '2 · Chi può usarlo', '3 · Nome e comportamento'].every(t => wizTxt(t)) , '');
function wizTxt(t) { return true; }
const wz = await page.textContent('#rl-wiz');
check('regole: i tre passi sono nominati', ['1 · Cosa proteggere', '2 · Chi può usarlo', '3 · Nome e comportamento'].every(t => wz.includes(t)));
await page.click('#wz-save');
check('regole: senza nome si viene fermati con una frase', (await page.textContent('#wz-err')).includes('Dai un nome'));
await page.fill('#wz-title', 'ssh keys');
check('regole: un nome gia usato da una protezione predefinita e segnalato', (await page.textContent('#wz-name')).includes('Esiste già'));
await page.fill('#wz-title', 'Wallet crypto');
check('regole: il nome tecnico si ricava dal titolo (wallet-crypto)', (await page.textContent('#wz-name')).includes('wallet-crypto'));
await page.click('#wz-save');
check('regole: senza percorso si viene fermati', (await page.textContent('#wz-err')).includes('almeno un file'));
await page.click('#wz-dir');
await page.waitForFunction(() => document.querySelectorAll('#wz-paths .rl-chip').length === 1);
await page.fill('#wz-path', 'Documents/*.kdbx');
await page.press('#wz-path', 'Enter');
check('regole: percorsi dal selettore e scritti a mano con jolly', (await page.locator('#wz-paths .rl-chip').allTextContents()).map(t => t.replace('✕', '').trim()).join() === '.wallet,Documents/*.kdbx');
await page.waitForFunction(() => document.getElementById('wz-pv').textContent.includes('Proteggerà 3 file'));
check('regole: anteprima con numero di file e avvisi', (await page.textContent('#wz-pv')).includes('Sono 3 file'));
await page.click('#wz-save');
check('regole: senza programmi si spiega perche serve', (await page.textContent('#wz-err')).includes('almeno un programma'));
await page.fill('#wz-prog', 'miotool'); await page.click('#wz-progcheck');
await page.waitForSelector('#wz-trust');
check('regole: un programma modificabile dall utente propone «Rendi affidabile»', (await page.textContent('#wz-prog-out')).includes('cartella che puoi modificare'));
check('regole: la procedura suggerisce l indicizzatore di sistema, solo se presente', (await page.locator('[data-helper]').count()) === 1 && (await page.textContent('#wz-helpers')).includes('Indicizzatore di GNOME') && !(await page.textContent('#wz-helpers')).includes('Non presente'));
await page.click('[data-helper="localsearch"]');
check('regole: un clic aggiunge i suoi percorsi e il pulsante diventa «✓»', (await page.locator('#wz-allow .rl-chip', { hasText: 'localsearch-extractor-3' }).count()) === 1 && (await page.locator('[data-helper="localsearch"]').isDisabled()));
await page.click('#wz-allow .rl-chip:has-text("localsearch-extractor-3") .rl-x');
check('regole: se lo togli il suggerimento torna disponibile', await page.locator('[data-helper="localsearch"]').isEnabled());
await page.fill('#wz-prog', 'keepassxc'); await page.click('#wz-progcheck');
await page.waitForFunction(() => document.querySelectorAll('#wz-allow .rl-chip').length === 1);
await page.selectOption('#wz-mode', 'enforce');
await page.check('#wz-dw');
await page.click('#wz-save');
await page.waitForFunction(() => !document.getElementById('rl-wiz'));
check('regole: la protezione personale compare con modalita e scritture', (await page.locator('.rl-card', { hasText: 'wallet-crypto' }).textContent()).includes('Blocca') && (await page.locator('.rl-card', { hasText: 'wallet-crypto' }).textContent()).includes('scrittura solo ai programmi in lista'));
check('regole: e in bozza finche non si preme Applica', (await page.textContent('.rl-bar')).includes('1 modifica') && (await page.evaluate(() => window.__applyCalls.length)) === 2);
await page.click('#rl-apply');
check('regole: la conferma la elenca', (await page.textContent('#dlg')).includes('Aggiungi la tua protezione «wallet-crypto»'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__applyCalls.length === 3);
const mine = await page.evaluate(() => window.__applyCalls[2].extra_rules[0]);
check('regole: ApplyRules riceve la regola personale completa', mine.name === 'wallet-crypto' && mine.paths.join() === '.wallet,Documents/*.kdbx' && mine.allow.join() === '/usr/bin/keepassxc' && mine.deny_write === true && mine.mode === 'enforce', JSON.stringify(mine));
await page.waitForFunction(() => !document.querySelector('.rl-bar'));

// Modifica ed eliminazione
await page.click('[data-my-edit="0"]');
await page.waitForSelector('#rl-wiz .wiz');
check('regole: la modifica riparte dai valori salvati', (await page.inputValue('#wz-title')) === 'wallet-crypto' && (await page.locator('#wz-paths .rl-chip').count()) === 2 && (await page.locator('#wz-dw').isChecked()));
await page.fill('#wz-path', '/etc'); await page.click('#wz-addpath');
await page.waitForFunction(() => document.getElementById('wz-pv').textContent.includes('troppo largo'));
await page.click('#wz-save');
check('regole: un percorso troppo largo blocca il salvataggio con il motivo', (await page.textContent('#wz-err')).includes('troppo largo'));
if (shots) { fs.mkdirSync(shots, { recursive: true }); await page.screenshot({ path: path.join(shots, `${label}-wizard.png`) }); }
await page.keyboard.press('Escape');
check('regole: Esc chiude la procedura senza salvare', (await page.locator('#rl-wiz').count()) === 0 && (await page.locator('.rl-bar').count()) === 0);
await page.click('[data-my-del="0"]');
check('regole: Elimina toglie la protezione in bozza', (await page.locator('.rl-card', { hasText: 'wallet-crypto' }).count()) === 0 && (await page.textContent('.rl-bar')).includes('1 modifica'));
await page.click('#rl-cancel');
check('regole: Annulla la ripristina', (await page.locator('.rl-card', { hasText: 'wallet-crypto' }).count()) === 1);
await page.evaluate(() => { window.__rm.choice = { enable_groups: null, disable_rules: null, allow_extra: null }; window.__applyCalls = []; });


// ---------------------------------------------------------------------------
// Rete: scelta delle interfacce da filtrare
// ---------------------------------------------------------------------------
await page.evaluate(() => {
  window.__status = Object.assign({}, window.__status, { xdp: ['eth0'], iface_auto: true, interfaces: [
    { name: 'eth0', kind: 'usb', up: true, covered: true }, { name: 'wlp1s0', kind: 'wifi', up: true, covered: false },
    { name: 'tide0', kind: 'vpn', up: true, covered: false }, { name: 'docker0', kind: 'bridge', up: true, covered: false },
    { name: 'veth1', kind: 'virtual', up: true, covered: false }, { name: 'lo', kind: 'loopback', up: true, covered: false },
  ] });
  window.__rm.choice = { enable_groups: null, disable_rules: null, allow_extra: null };
  window.__emit('shield:status', window.__status);
});
await page.click('#sidebar button[data-view="net"]');
await page.waitForSelector('#if-box .if-mode');
const ifTxt = await page.textContent('#if-box');
check('rete: sezione «Interfacce filtrate» con le fisiche in chiaro (nome, tipo, stato)', ifTxt.includes('Interfacce filtrate') && ifTxt.includes('eth0') && ifTxt.includes('USB') && ifTxt.includes('wlp1s0') && ifTxt.includes('Wi-Fi') && ifTxt.includes('filtrata'));
check('rete: avviso quando una fisica accesa non e filtrata', ifTxt.includes('wlp1s0') && ifTxt.includes('è accesa ma non è filtrata'));
check('rete: di default e «Automatica» e le caselle sono bloccate', (await page.locator('input[name="if-mode"][value="auto"]').isChecked()) && (await page.locator('[data-if="eth0"]').isDisabled()));
check('rete: le virtuali sono ripiegate e dette come tali', (await page.evaluate(() => !document.getElementById('if-virt').open)) && ifTxt.includes('interfacce virtuali (4'));
check('rete: niente barra Applica senza modifiche', (await page.locator('#if-apply').count()) === 0);
await page.click('input[name="if-mode"][value="manual"]');
check('rete: «Scelgo io» preseleziona le fisiche (cavo, USB, Wi-Fi), anche se una non e coperta', (await page.locator('[data-if="eth0"]').isChecked()) && (await page.locator('[data-if="wlp1s0"]').isChecked()) && !(await page.locator('[data-if="tide0"]').isChecked()));
check('rete: la barra dice quante interfacce', (await page.textContent('#if-barwrap')).includes('2 interfacce selezionate'));
await page.evaluate(() => { document.getElementById('if-virt').open = true; });
await page.check('[data-if="lo"]');
check('rete: la loopback spiega a cosa serve (prova del radar)', (await page.textContent('#if-box')).includes('prova') || (await page.textContent('#if-box')).includes('Radar'));
await page.check('[data-if="docker0"]');
check('rete: un bridge avverte che puo rompere la scoperta tra servizi', (await page.textContent('#if-box')).includes('scoperta tra servizi'));
await page.uncheck('[data-if="docker0"]');
await page.uncheck('[data-if="lo"]');
check('rete: la casella delle virtuali resta aperta dopo un ridisegno', await page.evaluate(() => document.getElementById('if-virt').open));
for (const n of ['eth0', 'wlp1s0']) await page.uncheck(`[data-if="${n}"]`);
check('rete: senza nessuna interfaccia Applica e spento e dice di sceglierne una', (await page.locator('#if-apply').isDisabled()) && (await page.textContent('#if-barwrap')).includes('scegline almeno una'));
await page.check('[data-if="eth0"]'); await page.check('[data-if="wlp1s0"]');
check('rete: il testo spiega che le interfacce si seguono senza riavviare', (await page.textContent('#if-box')).includes('senza riavviare') && (await page.textContent('#if-box')).includes('appena compaiono'));
check('rete: la bozza sopravvive agli stati che arrivano ogni 2 secondi', await (async () => {
  await page.evaluate(() => window.__emit('shield:status', Object.assign({}, window.__status, { time: '2026-10-05T11:00:00Z' })));
  await page.waitForTimeout(120);
  return (await page.locator('[data-if="wlp1s0"]').isChecked()) && (await page.locator('#if-apply').count()) === 1;
})());
await page.click('#if-apply');
const ifDlg = await page.textContent('#dlg');
check('rete: la conferma elenca le interfacce e rassicura sulla rete', ifDlg.includes('eth0, wlp1s0') && ifDlg.includes('La rete non si interrompe'));
await page.click('#dlg-ok');
await page.waitForFunction(() => window.__ifCalls.length === 1);
check('rete: ApplyInterfaces riceve la lista ordinata', (await page.evaluate(() => window.__ifCalls[0])).join() === 'eth0,wlp1s0');
await page.waitForFunction(() => !document.getElementById('if-apply'));
check('rete: dopo Applica la scelta resta in «Scelgo io»', (await page.locator('input[name="if-mode"][value="manual"]').isChecked()));
await page.click('input[name="if-mode"][value="auto"]');
await page.click('#if-apply'); await page.click('#dlg-ok');
await page.waitForFunction(() => window.__ifCalls.length === 2);
check('rete: tornare ad automatica manda una lista vuota', (await page.evaluate(() => window.__ifCalls[1])).length === 0);
await page.evaluate(() => { window.__ifFail = 'il servizio non riparte'; });
await page.click('input[name="if-mode"][value="manual"]');
await page.uncheck('[data-if="wlp1s0"]');
await page.click('#if-apply'); await page.click('#dlg-ok');
await page.waitForSelector('#toast.danger.show');
check('rete: se l applicazione fallisce l errore e visibile e la bozza resta', (await page.textContent('#toast')).includes('non riparte') && (await page.locator('#if-apply').count()) === 1);
await page.evaluate(() => { window.__ifFail = ''; window.__rm.choice = { enable_groups: null, disable_rules: null, allow_extra: null }; });

// interface scritta a mano nel config: sola lettura; demone vecchio senza elenco
const ifMan = await browser.newPage({ viewport: { width: 1100, height: 760 } });
ifMan.on('pageerror', e => errors.push(String(e)));
await ifMan.addInitScript((st) => {
  window.go = { main: { App: { GetStatus: async () => Object.assign({}, st, { xdp: ['eth0', 'lo'], interfaces: [{ name: 'eth0', kind: 'ethernet', up: true, covered: true }, { name: 'lo', kind: 'loopback', up: true, covered: true }] }),
    SocketPath: async () => '/x', Version: async () => '1', ServiceState: async () => 'active', ConfigMode: async () => 'audit', ConfigText: async () => '',
    RulesModel: async () => ({ profile: 'home', manual: false, manual_interface: true, base_interface: 'eth0,lo', choice: {}, groups: [], tools: [] }) } } };
  window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
  localStorage.setItem('zs-onboarded-v2', '1'); localStorage.setItem('zs-seen-version', '9.9.9');
}, STATUS);
await ifMan.goto(`http://127.0.0.1:${port}/`);
await ifMan.waitForSelector('#content h2');
await ifMan.click('#sidebar button[data-view="net"]');
await ifMan.waitForSelector('#if-box [data-if]');
check('rete: con interface scritta a mano si puo solo guardare, con la spiegazione', (await ifMan.textContent('#if-box')).includes('scritta a mano') && (await ifMan.locator('[data-if="eth0"]').isDisabled()) && (await ifMan.locator('input[name="if-mode"]').count()) === 0);
await ifMan.close();
const ifAbs = await browser.newPage({ viewport: { width: 1100, height: 760 } });
ifAbs.on('pageerror', e => errors.push(String(e)));
await ifAbs.addInitScript((st) => {
  window.go = { main: { App: { GetStatus: async () => Object.assign({}, st, { xdp: ['eth0'], interfaces: [{ name: 'eth0', kind: 'ethernet', up: true, covered: true }] }),
    SocketPath: async () => '/x', Version: async () => '1', ServiceState: async () => 'active', ConfigMode: async () => 'audit', ConfigText: async () => '',
    RulesModel: async () => ({ profile: 'home', manual: false, choice: { interface: 'eth0,usb9' }, groups: [], tools: [] }) } } };
  window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
  localStorage.setItem('zs-onboarded-v2', '1'); localStorage.setItem('zs-seen-version', '9.9.9');
}, STATUS);
await ifAbs.goto(`http://127.0.0.1:${port}/`);
await ifAbs.waitForSelector('#content h2');
await ifAbs.click('#sidebar button[data-view="net"]');
await ifAbs.waitForSelector('#if-box [data-if="usb9"]');
check('rete: un adattatore scelto ma scollegato resta in elenco e si aggancera quando compare', (await ifAbs.textContent('#if-box')).includes('non collegata ora') && (await ifAbs.textContent('#if-box')).includes('si aggancia quando compare') && (await ifAbs.locator('[data-if="usb9"]').isChecked()));
await ifAbs.close();
const ifOld = await browser.newPage({ viewport: { width: 1100, height: 760 } });
ifOld.on('pageerror', e => errors.push(String(e)));
await ifOld.addInitScript((st) => {
  window.go = { main: { App: { GetStatus: async () => st, SocketPath: async () => '/x', Version: async () => '1', ServiceState: async () => 'active', ConfigMode: async () => 'audit', ConfigText: async () => '',
    RulesModel: async () => ({ profile: 'home', choice: {}, groups: [], tools: [] }) } } };
  window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
  localStorage.setItem('zs-onboarded-v2', '1'); localStorage.setItem('zs-seen-version', '9.9.9');
}, STATUS);
await ifOld.goto(`http://127.0.0.1:${port}/`);
await ifOld.waitForSelector('#content h2');
await ifOld.click('#sidebar button[data-view="net"]');
await ifOld.waitForFunction(() => document.getElementById('if-box').textContent.includes('non ha ancora comunicato'));
check('rete: con un demone vecchio (senza elenco) lo dice invece di mostrare una lista vuota', true);
await ifOld.close();

// Modello con errore (servizio non installato)
const rlErr = await browser.newPage({ viewport: { width: 1100, height: 760 } });
rlErr.on('pageerror', e => errors.push(String(e)));
await rlErr.addInitScript((st) => {
  window.go = { main: { App: { GetStatus: async () => st, SocketPath: async () => '/x', Version: async () => '1', ServiceState: async () => 'active',
    ConfigMode: async () => 'audit', ConfigText: async () => '', RulesModel: async () => ({ error: 'config assente (/etc/zt-shield/shield.yaml): installa prima il servizio.' }) } } };
  window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
  localStorage.setItem('zs-onboarded-v2', '1');
}, STATUS);
await rlErr.goto(`http://127.0.0.1:${port}/`);
await rlErr.waitForSelector('#content h2');
await rlErr.click('#sidebar button[data-view="rules"]');
await rlErr.waitForFunction(() => document.getElementById('content').textContent.includes('installa prima il servizio'));
check('regole: se il config manca spiega di partire dallo Stato', (await rlErr.textContent('#content')).includes('scheda Stato'));
await rlErr.close();

// Scelte scritte a mano nel file: sola lettura
const rlMan = await browser.newPage({ viewport: { width: 1100, height: 760 } });
rlMan.on('pageerror', e => errors.push(String(e)));
await rlMan.addInitScript((st) => {
  window.go = { main: { App: { GetStatus: async () => st, SocketPath: async () => '/x', Version: async () => '1', ServiceState: async () => 'active',
    ConfigMode: async () => 'audit', ConfigText: async () => '',
    RulesModel: async () => ({ profile: 'home', manual: true, custom: ['mia'], choice: {}, tools: [], groups: [{ id: 'ssh', name: 'ssh-keys', desc: '', paths: ['.ssh/id_*'], allow: ['ssh'], in_profile: true, active: true }] }) } } };
  window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
  localStorage.setItem('zs-onboarded-v2', '1');
}, STATUS);
await rlMan.goto(`http://127.0.0.1:${port}/`);
await rlMan.waitForSelector('#content h2');
await rlMan.click('#sidebar button[data-view="rules"]');
await rlMan.waitForSelector('#rl-root');
check('regole: scelte a mano -> interruttori e campo disattivati, con spiegazione', (await rlMan.locator('[data-grp="ssh"]').isDisabled()) && (await rlMan.textContent('#content')).includes('scritte a mano'));
await rlMan.close();


// ---------------------------------------------------------------------------
// "Novita'": popup una sola volta per versione
// ---------------------------------------------------------------------------
async function wnPage(version, ls) {
  const pg = await browser.newPage({ viewport: { width: 1100, height: 760 }, timezoneId: 'Europe/Rome' });
  pg.on('pageerror', e => errors.push(String(e)));
  await pg.addInitScript(([st, ver, ls0]) => {
    window.go = { main: { App: { GetStatus: async () => st, SocketPath: async () => '/x', Version: async () => ver, ServiceState: async () => 'active', ConfigMode: async () => 'audit', ConfigText: async () => '' } } };
    window.runtime = { EventsOnMultiple: () => () => {}, EventsOff: () => {} };
    // Una sola volta per pagina: un reload non deve reimpostare lo storage di partenza.
    if (!sessionStorage.getItem('wn-init')) { sessionStorage.setItem('wn-init', '1'); Object.entries(ls0).forEach(([k, v]) => localStorage.setItem(k, v)); }
  }, [STATUS, version, ls]);
  await pg.goto(`http://127.0.0.1:${port}/`);
  await pg.waitForSelector('#content h2');
  await pg.waitForTimeout(150);
  return pg;
}
const wnUp = await wnPage('0.0.4~dev+abc1234', { 'zs-onboarded-v2': '1', 'zs-seen-version': '0.0.3' });
check('novita: dopo un aggiornamento compare il popup con le novita', (await wnUp.locator('#dlg.wn, #dlg .wn').count()) === 1 && (await wnUp.textContent('#dlg')).includes('Novità della versione 0.0.4'));
const wnTxt = await wnUp.textContent('#dlg');
check('novita: voci principali presenti', ['Icona nella barra di sistema', 'Regole guidate', 'Radar più chiaro', 'ancora in alpha'].every(t => wnTxt.includes(t)));
check('novita: il popup mette il focus sul pulsante', await wnUp.evaluate(() => document.activeElement && document.activeElement.id === 'wn-ok'));
await wnUp.keyboard.press('Enter');
check('novita: Invio lo chiude', (await wnUp.locator('#dlg').count()) === 0);
check('novita: la versione vista viene ricordata', (await wnUp.evaluate(() => localStorage.getItem('zs-seen-version'))) === '0.0.4');
await wnUp.reload(); await wnUp.waitForSelector('#content h2'); await wnUp.waitForTimeout(150);
check('novita: al riavvio della stessa versione non riappare', (await wnUp.locator('#dlg').count()) === 0);
await wnUp.click('#ver');
check('novita: cliccando la versione si riapre quando vuoi', (await wnUp.locator('#dlg').count()) === 1);
await wnUp.close();

const wnSkip = await wnPage('0.0.6', { 'zs-onboarded-v2': '1', 'zs-seen-version': '0.0.4' });
const skipTxt = await wnSkip.textContent('#dlg');
check('novita: chi salta una versione (0.0.4 -> 0.0.6) vede le novita di entrambe', skipTxt.includes('Novità dalle ultime versioni') && skipTxt.includes('Applica chiede di nuovo la password') && skipTxt.includes('Una modalità per ogni protezione'));
check('novita: la piu recente sta per prima', skipTxt.indexOf('0.0.6') < skipTxt.indexOf('0.0.5'));
await wnSkip.close();

const wnNew = await wnPage('0.0.4', {});
check('novita: alla prima installazione niente popup (c\'e il benvenuto)', (await wnNew.locator('#dlg').count()) === 0);
check('novita: ...ma la versione viene segnata', (await wnNew.evaluate(() => localStorage.getItem('zs-seen-version'))) === '0.0.4');
await wnNew.close();

const wnOld = await wnPage('0.0.4', { 'zs-onboarded-v2': '1' });
check('novita: chi aveva gia la GUI (senza versione salvata) le vede', (await wnOld.locator('#dlg').count()) === 1);
await wnOld.close();

const wnNone = await wnPage('9.9.9-test', { 'zs-onboarded-v2': '1', 'zs-seen-version': '9.9.8' });
check('novita: versione senza voce -> nessun popup e nessun errore', (await wnNone.locator('#dlg').count()) === 0);
await wnNone.close();

// Ogni release deve avere la sua voce: il file VERSION e whatsnew.js non devono andare fuori passo.
const verFile = fs.readFileSync(new URL('../../../VERSION', import.meta.url), 'utf8').trim();
const wnSrc = fs.readFileSync(new URL('../src/whatsnew.js', import.meta.url), 'utf8');
check('novita: la versione in VERSION (' + verFile + ') ha la sua voce in whatsnew.js', wnSrc.includes(`'${verFile}': {`));

if (shots) {
  fs.mkdirSync(shots, { recursive: true });
  for (const v of ['status', 'events', 'rules', 'net', 'guide']) {
    await page.click(`#sidebar button[data-view="${v}"]`);
    await page.waitForTimeout(250);
    await page.evaluate(() => { document.getElementById('content').scrollTop = 0; });
    await page.screenshot({ path: path.join(shots, `${label}-${v}.png`) });
  }
}

check('nessun errore JavaScript nella pagina', errors.length === 0, errors.join(' | '));
// Layout fluido: ogni componente segue la larghezza della finestra (stretta, normale, molto larga)
{
  const sizes = [[480, 700], [760, 700], [1100, 760], [1900, 1000]];
  const seenW = {};
  for (const [w, h] of sizes) {
    await page.setViewportSize({ width: w, height: h });
    for (const v of ['status', 'events', 'radar', 'rules', 'net', 'config', 'guide']) {
      await page.click(`#sidebar button[data-view="${v}"]`);
      await page.waitForTimeout(60);
      const m = await page.evaluate(() => ({
        overflowX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        contentOverflow: document.getElementById('content').scrollWidth - document.getElementById('content').clientWidth,
        side: document.getElementById('sidebar').getBoundingClientRect().width,
        cw: document.getElementById('content').getBoundingClientRect().width,
        kid: (document.querySelector('#content > *') || {}).getBoundingClientRect ? document.querySelector('#content > *').getBoundingClientRect().width : 0,
      }));
      check(`layout ${w}px, ${v}: nessuno scorrimento orizzontale della pagina`, m.overflowX <= 1 && m.contentOverflow <= 2, JSON.stringify(m));
      if (v === 'status') seenW[w] = m;
    }
  }
  check('layout: sotto 900px la barra laterale e a sole icone', seenW[760].side < 80 && seenW[1100].side > 140, JSON.stringify([seenW[760].side, seenW[1100].side]));
  check('layout: il contenuto occupa la finestra larga (non resta a 920px)', seenW[1900].kid > 1200, String(seenW[1900].kid));
  check('layout: la barra laterale resta cliccabile a finestra stretta', await page.evaluate(() => [...document.querySelectorAll('#sidebar button')].every(b => b.getBoundingClientRect().width > 30)));
  await page.setViewportSize({ width: 1100, height: 760 });
}

await browser.close();
server.close();
const failed = results.filter(x => !x).length;
console.log(`\n[${label}] ${results.length - failed} ok, ${failed} falliti`);
process.exit(failed ? 1 : 0);
