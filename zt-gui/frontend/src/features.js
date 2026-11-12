// Pagina «Funzioni»: un pulsante per attivare o spegnere ogni funzione di ZeroShield, una per una.
//
// Ogni scheda dice in parole semplici cosa fa la funzione, in che stato e' ADESSO (letto dal demone, non solo
// dal file) e cosa succede se la accendi o la spegni. Le funzioni che toccano il config lo riscrivono con
// config-apply (password di sistema, backup, ripristino se il servizio non riparte); l'avvio all'accensione e
// l'icona nella barra sono servizi e si cambiano senza toccare il config.

export function createFeaturesView(d) {
    const {content, esc, api, getStatus, confirmDialog, toast, goto, switchMode} = d;
    let model = null, boot = null, tray = null, loading = false, busy = '';
    let dirs = new Set();      // cartelle scelte per il canary (bozza finche' non si preme Attiva)
    let dirsInit = false;
    let hardProfile = '';      // profilo scelto per l'hardening (vuoto = quello del config)

    async function load() {
        if (loading) return;
        loading = true;
        try {
            model = await api.RulesModel();
            try { const b = await api.BootEnabled(); boot = typeof b === 'boolean' ? b : null; } catch (_) { boot = null; }
            try { const t = await api.TrayEnabled(); tray = typeof t === 'boolean' ? t : null; } catch (_) { tray = null; }
            if (!dirsInit && model && model.features) {
                const f = model.features;
                dirs = new Set(f.canary_enabled && (f.canary_dirs || []).length ? f.canary_dirs : (f.canary_candidates || []).slice(0, 1));
                dirsInit = true;
            }
        } catch (e) { model = null; }
        loading = false;
        paint();
    }

    const toggle = (id, on, labels, disabled) =>
        `<button class="chip big${on ? ' on' : ''}" id="${id}" aria-pressed="${on}" ${disabled ? 'disabled' : ''}>${on ? '● ' + labels[0] : '○ ' + labels[1]}</button>`;

    function card(title, state, stateCls, body, action) {
        return `<div class="fn-card"><div class="fn-head"><b>${title}</b><span class="fn-state ${stateCls}">${state}</span></div>
            <div class="fn-body">${body}</div>${action ? `<div class="fn-act">${action}</div>` : ''}</div>`;
    }

    function paint() {
        if (!content || !document.getElementById('fn-root')) return;
        const st = getStatus() || {};
        const f = (model && model.features) || {};
        const mode = st.mode || '?';
        const manualPoison = !!f.manual_block_poisoning, manualCanary = !!f.manual_canary;
        const canary = st.canary || {};
        const cards = [];

        // 1. Protezione dei segreti (hook LSM): sempre attiva, la modalita' si sceglie qui
        cards.push(card('Protezione dei segreti',
            mode === 'enforce' ? 'Blocca' : 'Solo osserva', mode === 'enforce' ? 'on' : 'warn',
            `Controlla chi legge le tue chiavi SSH, le credenziali cloud, i token e le chiavi GPG. In <b>Solo osserva</b> registra senza bloccare nulla; in <b>Blocca</b> nega a chi non è nella lista. <span class="rl-d">Le singole protezioni e i programmi autorizzati si scelgono in Regole.</span>`,
            `<button class="chip big${mode === 'enforce' ? '' : ' on'}" id="fn-mode-audit" ${mode === 'enforce' ? '' : 'disabled'}>Solo osserva</button>
             <button class="chip big${mode === 'enforce' ? ' on' : ''}" id="fn-mode-enforce" ${mode === 'enforce' ? 'disabled' : ''}>Blocca</button>
             <button class="linklike" data-go="rules">Scegli le protezioni →</button>`));

        // 2. Filtro di rete (anti-poisoning)
        const poisonOn = st.block_poisoning !== undefined ? !!st.block_poisoning : f.block_poisoning !== false;
        cards.push(card('Filtro di rete (anti-poisoning)', poisonOn ? 'Attivo' : 'Spento', poisonOn ? 'on' : 'off',
            `Scarta in ingresso le richieste e le risposte false di LLMNR, mDNS e NetBIOS: è come un attaccante su una rete Wi-Fi o di ufficio cerca di rubare le credenziali. Spegnerlo non rompe nulla, ma ti lascia scoperto su reti non fidate.
             ${manualPoison ? '<div class="rl-help">Nel config <code>block_poisoning</code> è scritto a mano: il pulsante è spento. Modificalo lì.</div>' : ''}`,
            toggle('fn-poison', poisonOn, ['Attivo', 'Spento'], manualPoison || !model) +
            ` <button class="linklike" data-go="net">Scegli le interfacce →</button>`));

        // 3. Anti-ransomware (canary)
        const cOn = !!canary.active;
        const cWant = !!(canary.enabled || f.canary_enabled);
        const cState = cOn ? 'Attivo' : cWant ? 'Voluto ma non partito' : 'Spento';
        const cCls = cOn ? 'on' : cWant ? 'warn' : 'off';
        const cands = f.canary_candidates || [];
        const chips = cands.length
            ? cands.map(c => `<label class="fn-dir"><input type="checkbox" data-dir="${esc(c)}" ${dirs.has(c) ? 'checked' : ''} ${manualCanary || cOn ? 'disabled' : ''}> ${esc(c)}</label>`).join('')
            : '<span class="rl-d">Nessuna cartella comune trovata nella tua home: il canary userà <code>Documents</code>.</span>';
        cards.push(card('Anti-ransomware (canary)', cState, cCls,
            `Mette file esca nascosti nelle cartelle che scegli. Se un programma li tocca, o inizia a cancellare o rinominare molti file di fila, ZeroShield avvisa; in <b>Blocca</b> uccide anche il programma. Conviene lasciarlo una settimana in <b>Solo osserva</b> per vedere cosa lo fa scattare.
             <div class="fn-dirs">${cOn ? '<span class="rl-d">Cartelle protette:</span> ' + (f.canary_dirs || []).map(esc).join(', ') : chips}</div>
             ${cWant && !cOn ? '<div class="rl-help warn">Il config lo chiede ma il demone non l’ha avviato: guarda <code>journalctl -u zt-shield -n 30</code>.</div>' : ''}
             ${manualCanary ? '<div class="rl-help">Nel config <code>canary</code> è scritto a mano: il pulsante è spento. Modificalo lì.</div>' : ''}`,
            toggle('fn-canary', cOn || cWant, ['Attivo', 'Spento'], manualCanary || !model) +
            (cOn ? ` <span class="rl-d">${mode === 'enforce' ? 'Uccide i programmi che toccano le esche.' : 'Solo avvisi (Solo osserva).'}</span>` : '')));

        // 4. Avvio all'accensione
        cards.push(card('Avvio all’accensione', boot === null ? 'Non disponibile' : boot ? 'Attivo' : 'Spento', boot ? 'on' : 'off',
            `Il demone parte da solo a ogni accensione del computer. Se lo spegni, dopo un riavvio il PC resta <b>senza protezione</b> finché non lo avvii tu.`,
            boot === null ? '' : toggle('fn-boot', boot, ['Attivo', 'Spento'], false)));

        // 5. Icona nella barra
        cards.push(card('Icona nella barra', tray === null ? 'Non disponibile' : tray ? 'Attiva' : 'Spenta', tray ? 'on' : 'off',
            `Mostra lo stato in alto (blu = blocca, arancione = solo osserva, rossa = demone spento) e ti avvisa dei blocchi anche a finestra chiusa. Chiuderla non ferma la protezione.`,
            tray === null ? '' : toggle('fn-tray', tray, ['Attiva', 'Spenta'], false)));

        // 6. Hardening del sistema (script harden_system.sh: sempre con anteprima prima)
        const profiles = ['home', 'corporate', 'public-wifi', 'paranoid'];
        const hp = hardProfile || (model && profiles.includes(model.profile) ? model.profile : 'home');
        cards.push(card('Hardening del sistema', 'Manuale', 'warn',
            `Chiude l’ingresso con il firewall (UFW), spegne LLMNR/mDNS nel resolver, irrigidisce i parametri di rete e, sulle reti ostili, spegne avahi. Prima ti mostro <b>esattamente cosa cambierebbe</b>, poi decidi. <span class="rl-d">Sperimentale: lo script non è mai stato provato su un sistema vero; meglio in una macchina virtuale.</span>`,
            `<select id="fn-hprof" aria-label="Profilo di hardening">${profiles.map(p => `<option value="${p}"${p === hp ? ' selected' : ''}>${p}</option>`).join('')}</select>
             <button class="chip big" id="fn-harden">Vedi cosa cambierebbe…</button>`));

        // 7. VPN: monitor (sempre) e kill-switch (se il tunnel e' configurato nel file)
        const vpn = st.vpn || {};
        const vpnCfg = !!(vpn.enabled && vpn.endpoint && vpn.tunnel);
        const ks = !!vpn.killswitch;
        cards.push(card('VPN: monitor e kill-switch', !vpnCfg ? 'Non configurata' : ks ? 'Kill-switch attivo' : 'Kill-switch spento', !vpnCfg ? 'off' : ks ? 'on' : 'warn',
            vpnCfg
                ? `Tunnel <code>${esc(vpn.tunnel)}</code> verso <code>${esc(vpn.endpoint)}</code>: ${vpn.up ? 'su' : '<b>giù</b>'}. Il <b>kill-switch</b> fa uscire solo il traffico del tunnel: se la VPN cade la rete <b>si ferma</b> invece di passare in chiaro. Si toglie da qui o con <code>vpn_killswitch.sh off</code>.`
                : `Il demone osserva tunnel e kill-switch, ma non c’è una VPN configurata. Aggiungi nel file <code>vpn:</code> con <code>endpoint</code> (IP:porta, mai un nome host) e <code>tunnel</code> per poter gestire il kill-switch da qui. <span class="rl-d">Provato solo in un namespace, mai su una rete vera.</span>`,
            vpnCfg ? toggle('fn-ks', ks, ['Attivo', 'Spento'], false) + ` <button class="linklike" data-go="net">Stato della rete →</button>`
                   : `<button class="linklike" data-go="net">Vedi lo stato della rete →</button>`));

        // 8. FIDO2: interattivo (chiave fisica, PIN, tocco): solo da terminale
        cards.push(card('Chiave FIDO2 (firma dei commit)', 'Da terminale', 'off',
            `Crea una chiave SSH legata alla tua chiave fisica (serve il PIN e un tocco) e configura git per firmare i commit. È interattiva, quindi non si può fare da qui: lancia nel terminale <code>bash /usr/share/zeroshield/scripts/setup_fido2.sh</code>. <span class="rl-d">Mai eseguito su un sistema vero.</span>`,
            ''));

        const root = document.getElementById('fn-root');
        root.innerHTML = `<div class="fn-grid">${cards.join('')}</div>${busy ? `<div class="rl-bar">${esc(busy)}</div>` : ''}`;
        bind();
    }

    function bind() {
        const $ = id => document.getElementById(id);
        document.querySelectorAll('#fn-root [data-go]').forEach(b => { b.onclick = () => goto(b.dataset.go); });
        document.querySelectorAll('#fn-root [data-dir]').forEach(c => { c.onchange = () => { if (c.checked) dirs.add(c.dataset.dir); else dirs.delete(c.dataset.dir); }; });
        const bm = (id, next) => { const b = $(id); if (b) b.onclick = () => switchMode(next); };
        bm('fn-mode-audit', 'audit'); bm('fn-mode-enforce', 'enforce');

        const run = async (label, fn, okMsg) => {
            busy = label; paint();
            try { await fn(); toast(okMsg); } catch (e) { toast(String((e && e.message) || e), true); }
            busy = '';
            await refreshAll();
        };
        const p = $('fn-poison');
        if (p) p.onclick = async () => {
            const f = model.features, on = !(getStatus() && getStatus().block_poisoning);
            if (!on && !await confirmDialog({title: 'Spegnere il filtro di rete?', body: 'Su una rete Wi-Fi o di ufficio non fidata un attaccante potrebbe rubare credenziali con LLMNR, mDNS o NetBIOS. Il servizio si riavvia (password di sistema).', ok: 'Spegni', danger: true})) return;
            run(on ? 'Accendo il filtro…' : 'Spengo il filtro…',
                () => api.ApplyFeatures(on, !!(f.canary_enabled), [...dirs]), on ? 'Filtro di rete acceso.' : 'Filtro di rete spento.');
        };
        const c = $('fn-canary');
        if (c) c.onclick = async () => {
            const f = model.features, st = getStatus() || {}, wantOn = !((st.canary && st.canary.active) || f.canary_enabled);
            const list = [...dirs];
            if (wantOn) {
                const ok = await confirmDialog({title: 'Accendere l’anti-ransomware?',
                    body: `ZeroShield metterà file esca nascosti in: <b>${(list.length ? list : ['Documents']).map(esc).join(', ')}</b>. Parte in base alla modalità globale (<b>${esc(st.mode || '?')}</b>): finché sei in <b>Solo osserva</b> ti avvisa e basta. Il servizio si riavvia (password di sistema).`,
                    ok: 'Accendi'});
                if (!ok) return;
            } else if (!await confirmDialog({title: 'Spegnere l’anti-ransomware?', body: 'Le esche non saranno più sorvegliate. Il servizio si riavvia (password di sistema).', ok: 'Spegni', danger: true})) return;
            run(wantOn ? 'Accendo il canary…' : 'Spengo il canary…',
                () => api.ApplyFeatures(st.block_poisoning !== false, wantOn, list), wantOn ? 'Canary acceso.' : 'Canary spento.');
        };
        const b = $('fn-boot');
        if (b) b.onclick = async () => {
            const want = !boot;
            if (!want && !await confirmDialog({title: 'Spegnere l’avvio all’accensione?', body: 'Dopo il prossimo riavvio il PC resterà <b>senza protezione</b> finché non avvii tu il demone.', ok: 'Spegni', danger: true})) return;
            run(want ? 'Attivo l’avvio…' : 'Spengo l’avvio…', () => api.SetBootEnabled(want), want ? 'Il demone partirà a ogni accensione.' : 'Avvio all’accensione spento.');
        };
        const hs = $('fn-hprof');
        if (hs) hs.onchange = () => { hardProfile = hs.value; };
        const hb = $('fn-harden');
        if (hb) hb.onclick = async () => {
            const prof = ($('fn-hprof') || {}).value || 'home';
            hb.disabled = true; hb.textContent = 'Calcolo…';
            let text = '', err = '';
            try { text = await api.HardenPreview(prof); } catch (e) { err = String((e && e.message) || e); }
            hb.disabled = false; hb.textContent = 'Vedi cosa cambierebbe…';
            if (err && !text) { toast(err, true); return; }
            const ok = await confirmDialog({
                title: `Hardening «${esc(prof)}»: anteprima`,
                body: `<div class="fn-pre">${esc(text || '(nessuna modifica)')}</div>${err ? `<p class="warn">${esc(err)}</p>` : ''}
                       Questa è solo l’anteprima: <b>non è stato cambiato nulla</b>. Se premi <b>Applica</b> lo script modifica firewall, resolver e parametri di rete (password di sistema). Meglio provarlo prima in una macchina virtuale.`,
                ok: 'Applica', danger: true});
            if (!ok) return;
            run('Applico l’hardening…', () => api.HardenApply(prof), `Hardening «${prof}» applicato.`);
        };
        const kb = $('fn-ks');
        if (kb) kb.onclick = async () => {
            const v = (getStatus() || {}).vpn || {}, want = !v.killswitch;
            const ok = await confirmDialog(want
                ? {title: 'Accendere il kill-switch?', body: `Da ora esce <b>solo</b> il traffico del tunnel <b>${esc(v.tunnel || '')}</b> verso <b>${esc(v.endpoint || '')}</b>, il DHCP e la rete locale. Se la VPN cade, la rete <b>si ferma</b> finché non torna su o non lo spegni. Password di sistema richiesta.`, ok: 'Accendi', danger: true}
                : {title: 'Spegnere il kill-switch?', body: 'Il traffico tornerà a uscire anche fuori dalla VPN. Password di sistema richiesta.', ok: 'Spegni', danger: true});
            if (!ok) return;
            run(want ? 'Accendo il kill-switch…' : 'Spengo il kill-switch…',
                () => want ? api.KillSwitchOn(v.endpoint, v.tunnel) : api.KillSwitchOff(), want ? 'Kill-switch acceso.' : 'Kill-switch spento.');
        };
        const t = $('fn-tray');
        if (t) t.onclick = () => {
            const want = !tray;
            run(want ? 'Accendo l’icona…' : 'Spengo l’icona…', () => api.SetTrayEnabled(want), want ? 'Icona nella barra accesa.' : 'Icona nella barra spenta.');
        };
    }

    async function refreshAll() { model = null; await load(); }

    function render() {
        // Lo scheletro si crea una volta; i dati si ridisegnano dentro (gli aggiornamenti di stato non lo ricostruiscono).
        if (!document.getElementById('fn-root')) {
            content.innerHTML = `<h2>Funzioni</h2>
            <p class="sub">Accendi o spegni ogni funzione una per una. Quello che vedi è lo stato <b>reale</b> del demone in questo momento.</p>
            <div id="fn-root"><p class="sub">Carico…</p></div>`;
            if (!model) load(); else paint();
            return;
        }
        paint();
        if (!model) load();
    }

    return {render, reset: () => { model = null; dirsInit = false; }};
}
