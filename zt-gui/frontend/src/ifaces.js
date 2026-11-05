// Scelta delle interfacce di rete da filtrare (scheda Rete).
//
// ZeroShield scarta le richieste di rete sospette (LLMNR, mDNS, NetBIOS) solo sulle interfacce in cui e' agganciato.
// Di default sono quelle della rete in uso al momento dell'avvio: se poi accendi il Wi-Fi o colleghi un adattatore USB
// restano scoperti. Qui si sceglie a mano, con il tipo di ogni interfaccia spiegato in parole semplici.
//
// Le modifiche sono una BOZZA: «Applica» scrive il config e riavvia il servizio (circa 3 secondi, la rete non si
// interrompe: il filtro e' in modalita' generica e non resetta la scheda).

const KIND = {
    ethernet: ['Cavo', 'Scheda di rete cablata'],
    usb: ['USB', 'Adattatore USB (cavo o tethering del telefono)'],
    wifi: ['Wi-Fi', 'Rete senza fili'],
    vpn: ['VPN / tunnel', 'Il traffico qui è già dentro la VPN: di norma basta filtrare l’interfaccia fisica'],
    bridge: ['Bridge (container)', 'Rete interna di Docker o macchine virtuali: filtrarla può rompere la scoperta tra servizi'],
    virtual: ['Virtuale (container)', 'Collegamento di un container: filtrarla può rompere la scoperta tra servizi'],
    loopback: ['Loopback', 'Solo per prove: il traffico che mandi a te stesso'],
};
const PHYSICAL = ['ethernet', 'usb', 'wifi'];
const label = k => (KIND[k] || [k])[0];

export function createIfaceView(d) {
    const {esc, api, getStatus, confirmDialog, toast, repaint} = d;
    let model = null, loading = false;
    let draft = null;          // {auto: bool, sel: Set}
    let showVirtual = false;
    let busy = '';

    const saved = () => ((model && model.choice && model.choice.interface) || '').split(',').map(s => s.trim()).filter(Boolean);
    function init() {
        const s = saved();
        draft = {auto: s.length === 0, sel: new Set(s)};
    }
    const list = () => (getStatus() && getStatus().interfaces) || [];
    const covered = () => new Set((getStatus() && getStatus().xdp) || []);
    const desired = () => draft.auto ? [] : [...draft.sel].sort();
    // «Scelgo io» senza nessuna interfaccia e' diverso da «Automatica» anche se la lista e' vuota in entrambi i casi.
    const dirty = () => {
        if (!model || !draft || model.manual_interface) return false;
        const savedAuto = saved().length === 0;
        if (draft.auto !== savedAuto) return true;
        return !draft.auto && desired().join(',') !== [...saved()].sort().join(',');
    };

    async function load() {
        if (loading) return;
        loading = true;
        try { model = await api.RulesModel(); } catch (e) { model = {error: String(e && e.message || e)}; }
        loading = false;
        if (model && !model.error) init();
        repaint();
    }

    // "Scelgo io": si parte da cio' che conviene davvero, tutte le fisiche (anche spente: se poi le accendi sono gia' coperte).
    function startManual() {
        draft.auto = false;
        draft.sel = new Set(list().filter(i => PHYSICAL.includes(i.kind)).map(i => i.name));
        covered().forEach(n => draft.sel.add(n));
    }

    function row(i, locked) {
        const on = draft.auto ? covered().has(i.name) : draft.sel.has(i.name);
        const k = KIND[i.kind] || [i.kind, ''];
        const state = !i.up ? '<span class="rl-b none">spenta</span>' : (covered().has(i.name) ? '<span class="rl-b ok">filtrata</span>' : '<span class="rl-b warn">non filtrata</span>');
        let hint = '';
        if (!locked && on && !PHYSICAL.includes(i.kind)) hint = `<div class="rl-help">${esc(k[1])}.${i.kind === 'loopback' ? ' Scarta UDP 5355, 5353, 137 e 138 sulla loopback: utile per provare il Radar con pacchetti che mandi a te stesso.' : ''}</div>`;
        if (!locked && !on && i.kind === 'wifi') hint = '<div class="rl-help">Se accendi questa interfaccia senza selezionarla, la rete Wi-Fi <b>non sarà filtrata</b>.</div>';
        return `<div class="rl-tool"><label class="if-l"><input type="checkbox" data-if="${esc(i.name)}" ${on ? 'checked' : ''} ${locked ? 'disabled' : ''}>
          <span><b class="mono">${esc(i.name)}</b> <span class="rl-d">${esc(k[0])}${k[1] && PHYSICAL.includes(i.kind) ? ' · ' + esc(k[1]) : ''}</span></span></label>
          <div class="rl-ta">${state}</div>${hint}</div>`;
    }

    function html() {
        if (!model) return '<h3 class="sec">Interfacce filtrate</h3><p class="rl-d">Carico…</p>';
        if (model.error) return `<h3 class="sec">Interfacce filtrate</h3><div class="rl-help">${esc(model.error)}</div>`;
        const all = list();
        if (!all.length) return '<h3 class="sec">Interfacce filtrate</h3><div class="rl-empty">Il demone non ha ancora comunicato l’elenco delle interfacce (versione del demone più vecchia?). Aggiorna e riavvia il servizio.</div>';
        const locked = !!model.manual_interface || draft.auto;
        const phys = all.filter(i => PHYSICAL.includes(i.kind)), other = all.filter(i => !PHYSICAL.includes(i.kind));
        const uncovered = phys.filter(i => i.up && !covered().has(i.name));
        const warn = uncovered.length ? `<div class="rl-ready warn"><b>${uncovered.map(i => esc(i.name)).join(', ')}</b> ${uncovered.length === 1 ? 'è accesa ma non è filtrata' : 'sono accese ma non filtrate'}: una rete ostile su ${uncovered.length === 1 ? 'questa interfaccia' : 'queste interfacce'} non verrebbe fermata.</div>` : '';
        const manual = model.manual_interface
            ? `<div class="rl-help">Nel config c’è già <span class="rl-mono">interface: ${esc(model.base_interface)}</span> scritta a mano, quindi da qui puoi solo guardare. Per sceglierle dalla GUI togli quella riga da <span class="rl-mono">/etc/zt-shield/shield.yaml</span>.</div>` : '';
        const mode = model.manual_interface ? '' : `<div class="if-mode">
          <label><input type="radio" name="if-mode" value="auto" ${draft.auto ? 'checked' : ''}> <b>Automatica</b> <span class="rl-d">— solo la rete che stai usando quando il servizio parte (oggi: ${esc([...covered()].join(', ') || 'nessuna')})</span></label>
          <label><input type="radio" name="if-mode" value="manual" ${draft.auto ? '' : 'checked'}> <b>Scelgo io</b> <span class="rl-d">— le fisiche (cavo, USB, Wi-Fi) sono consigliate, anche se spente ora</span></label></div>`;
        return `<h3 class="sec">Interfacce filtrate</h3>
          <p class="rl-d">Il filtro scarta le richieste di rete sospette (LLMNR, mDNS, NetBIOS) solo sulle interfacce selezionate. Cavo, USB e Wi-Fi sono quelle dove può arrivare una rete ostile.</p>
          ${warn}${manual}${mode}
          ${phys.map(i => row(i, locked)).join('') || '<div class="rl-empty">Nessuna interfaccia fisica trovata.</div>'}
          ${other.length ? `<details class="rl-det" id="if-virt" ${showVirtual ? 'open' : ''}><summary>Mostra anche le interfacce virtuali (${other.length}: VPN, container, loopback)</summary>${other.map(i => row(i, locked)).join('')}</details>` : ''}
          <div id="if-barwrap">${bar()}</div>`;
    }

    function bar() {
        if (!dirty()) return '';
        const n = desired().length;
        const need = !draft.auto && n === 0;
        return `<div class="rl-bar" role="region" aria-label="Modifiche alle interfacce"><span>${draft.auto ? 'Passi alla scelta <b>automatica</b>' : `<b>${n} ${n === 1 ? 'interfaccia selezionata' : 'interfacce selezionate'}</b> non ancora applicate`}${need ? ' — scegline almeno una' : ''}</span>
          <span class="rl-bar-b"><button class="chip" id="if-cancel" ${busy ? 'disabled' : ''}>Annulla</button><button class="chip on" id="if-apply" ${busy || need ? 'disabled' : ''}>${busy ? esc(busy) : 'Applica'}</button></span></div>`;
    }

    async function apply() {
        const names = desired();
        const ok = await confirmDialog({
            title: 'Applicare la scelta delle interfacce?',
            body: draft.auto
                ? 'ZeroShield tornerà a filtrare solo la rete in uso quando il servizio parte.'
                : `Il filtro sarà agganciato a: <b>${names.map(esc).join(', ')}</b>.`
                + '<br><br>Il servizio si riavvia per circa 3 secondi (ti viene chiesta la password di sistema). La rete non si interrompe. Se qualcosa non va, torna da solo alla configurazione precedente.',
            ok: 'Applica',
        });
        if (!ok) return;
        busy = 'Applico…'; repaint();
        try {
            await api.ApplyInterfaces(names);
            toast('Interfacce applicate. Il filtro è stato riagganciato.');
            model = await api.RulesModel();
            init();
        } catch (e) { toast(String(e && e.message || e), true); }
        busy = '';
        repaint();
    }

    // Collega la sezione appena disegnata (la pagina Rete si ridisegna a ogni stato, la bozza resta in questo modulo).
    function bind(root) {
        if (!root || !model || model.error) return;
        root.querySelectorAll('input[name="if-mode"]').forEach(r => {
            r.onchange = () => { if (r.value === 'auto') draft.auto = true; else startManual(); repaint(); };
        });
        root.querySelectorAll('[data-if]').forEach(c => {
            c.onchange = () => { c.checked ? draft.sel.add(c.dataset.if) : draft.sel.delete(c.dataset.if); repaint(); };
        });
        const v = root.querySelector('#if-virt');
        if (v) v.ontoggle = () => { showVirtual = v.open; };
        const a = root.querySelector('#if-apply'), c = root.querySelector('#if-cancel');
        if (a) a.onclick = apply;
        if (c) c.onclick = () => { init(); repaint(); };
    }

    return {html, bind, ensureLoaded() { if (!model && !loading) load(); }, reload() { model = null; load(); }};
}
