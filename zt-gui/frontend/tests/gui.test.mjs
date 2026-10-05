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
const page = await browser.newPage({ viewport: { width: 1100, height: 760 } });
const errors = [];
page.on('pageerror', e => errors.push(String(e)));

await page.addInitScript((status) => {
  window.__handlers = {};
  window.__status = status;
  window.go = { main: { App: {
    GetStatus: async () => window.__status,
    SocketPath: async () => '/tmp/z.sock',
    Version: async () => '9.9.9-test',
  } } };
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
