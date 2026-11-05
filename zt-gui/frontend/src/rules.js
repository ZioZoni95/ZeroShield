// Schermata Regole: scegli cosa proteggere e quali programmi possono usare i segreti, senza YAML.
//
// Pensata per chi non conosce il progetto: frasi semplici, scelte consigliate gia' pronte,
// nessun comando da copiare. Le modifiche restano una BOZZA finche' non premi «Applica»:
// a quel punto una sola autenticazione di sistema scrive il config (blocco gestito), riavvia
// il servizio e, se non riparte, ripristina da solo la configurazione precedente.
//
// Tutta la logica "puo' essere autorizzato?" sta nel backend (pkg/rules): qui solo presentazione.

const FRIENDLY = {
    ssh: 'Chiavi SSH',
    cloud: 'Kubernetes e cloud',
    tokens: 'Token degli strumenti di sviluppo',
    gpg: 'Chiavi GPG',
    browsers: 'Cookie e password dei browser',
};
const WHAT = {
    ssh: 'Le chiavi con cui accedi ai server (ssh, git su SSH).',
    cloud: 'Il file con cui kubectl e gli strumenti cloud entrano nei tuoi cluster.',
    tokens: 'Le credenziali di Docker, GitHub, GitLab e Cargo.',
    gpg: 'Le chiavi con cui firmi i commit e decifri.',
    browsers: 'Dove i browser salvano sessioni e password. Fa molto rumore in Audit: attivala solo se serve.',
};

const baseName = p => String(p).split('/').pop();

export function createRulesView(d) {
    const {content, esc, api, getStatus, getEvents, confirmDialog, toast, icons, active, goto} = d;
    let model = null;     // risposta di RulesModel()
    let draft = null;     // bozza: {enable:Set, disable:Set, allow:{regola:Set}}
    let loading = false;
    let busy = '';        // testo mentre un'azione e' in corso
    let seenSig = '';
    const progCache = new Map(); // exe -> {v: Program|null}

    // ---------- bozza ----------
    function draftFrom(choice) {
        const c = choice || {};
        const allow = {};
        Object.entries(c.allow_extra || {}).forEach(([k, v]) => { allow[k] = new Set(v || []); });
        const removed = {};
        Object.entries(c.remove_allow || {}).forEach(([k, v]) => { removed[k] = new Set(v || []); });
        const my = (c.extra_rules || []).map(r => ({name: r.name, paths: [...(r.paths || [])], allow: [...(r.allow || [])], deny_write: !!r.deny_write, mode: r.mode || ''}));
        return {enable: new Set(c.enable_groups || []), disable: new Set(c.disable_rules || []), allow, removed, my, modes: {...(c.rule_modes || {})}};
    }
    function norm(dr) {
        const allow = {}, removed = {};
        Object.keys(dr.allow).sort().forEach(k => { if (dr.allow[k].size) allow[k] = [...dr.allow[k]].sort(); });
        Object.keys(dr.removed).sort().forEach(k => { if (dr.removed[k].size) removed[k] = [...dr.removed[k]].sort(); });
        const modes = {};
        Object.keys(dr.modes).sort().forEach(k => { if (dr.modes[k]) modes[k] = dr.modes[k]; });
        const my = [...dr.my].sort((a, b) => a.name < b.name ? -1 : 1);
        return JSON.stringify({e: [...dr.enable].sort(), d: [...dr.disable].sort(), a: allow, r: removed, m: modes, x: my});
    }
    const dirty = () => !!(model && draft && norm(draft) !== norm(draftFrom(model.choice)));
    function choiceOut() {
        const allow = {};
        Object.keys(draft.allow).forEach(k => { if (draft.allow[k].size) allow[k] = [...draft.allow[k]].sort(); });
        const removed = {};
        Object.keys(draft.removed).forEach(k => { if (draft.removed[k].size) removed[k] = [...draft.removed[k]].sort(); });
        const modes = {};
        Object.keys(draft.modes).forEach(k => { if (draft.modes[k]) modes[k] = draft.modes[k]; });
        return {enable_groups: [...draft.enable].sort(), disable_rules: [...draft.disable].sort(), allow_extra: allow,
            remove_allow: removed, rule_modes: modes,
            extra_rules: draft.my.map(r => ({name: r.name, paths: r.paths, allow: r.allow, deny_write: !!r.deny_write, mode: r.mode || ''}))};
    }

    // ---------- modello ----------
    const groupActive = g => g.in_profile ? !draft.disable.has(g.name) : draft.enable.has(g.id);
    function toggleGroup(g) {
        if (g.in_profile) { draft.disable.has(g.name) ? draft.disable.delete(g.name) : draft.disable.add(g.name); }
        else { draft.enable.has(g.id) ? draft.enable.delete(g.id) : draft.enable.add(g.id); }
    }
    const groupByName = n => (model.groups || []).find(g => g.name === n);
    const label = g => FRIENDLY[g.id] || g.name;
    const labelOfRule = n => { const g = groupByName(n); return g ? label(g) : n; };

    // Il programma `p` (esito di CheckProgram o voce del catalogo) e' autorizzato per la regola?
    // Una voce per NOME conta solo se il binario e' affidabile: il demone la risolve con il suo
    // PATH e scarta quelli che l'utente puo' modificare.
    function allowedFor(g, p) {
        const path = p.alt || p.path;
        if (!path) return false;
        if (draft.allow[g.name] && draft.allow[g.name].has(path)) return true;
        return (g.allow || []).some(a => !isRemoved(g.name, a) && (a === path || (a === baseName(path) && (p.trusted || !!p.alt))));
    }
    const isRemoved = (rule, a) => !!(draft.removed[rule] && (draft.removed[rule].has(a) || draft.removed[rule].has(baseName(a))));
    function toggleRemoved(rule, a) {
        const set = (draft.removed[rule] = draft.removed[rule] || new Set());
        set.has(a) ? set.delete(a) : set.add(a);
    }
    // Modalita' mostrata per una regola: la sua scelta, altrimenti quella globale del demone.
    const globalMode = () => (model && model.global_mode) || (getStatus() || {}).mode || 'audit';
    const modeOf = rule => draft.modes[rule] || globalMode();
    const MODE_TXT = {audit: 'Solo osserva', enforce: 'Blocca'};
    function authorize(rules, p) {
        const path = p.alt || p.path;
        rules.forEach(n => { (draft.allow[n] = draft.allow[n] || new Set()).add(path); });
    }
    function revoke(rule, path) { if (draft.allow[rule]) draft.allow[rule].delete(path); }

    async function load() {
        if (loading) return;
        loading = true;
        try {
            model = await api.RulesModel();
            draft = draftFrom(model.choice);
        } catch (e) { model = {error: String(e && e.message || e)}; draft = draftFrom(null); }
        loading = false;
        justLoaded = true;
        render(true);
    }

    // Rientrando nella scheda si mostra subito il modello in memoria e lo si rilegge in silenzio:
    // un programma installato o cambiato nel frattempo compare senza perdere la bozza.
    async function refreshQuiet() {
        if (loading || dirty()) return;
        loading = true;
        try {
            const m = await api.RulesModel();
            if (!dirty()) { model = m; draft = draftFrom(m.choice); progCache.clear(); }
        } catch (_) { /* resta il modello precedente */ }
        loading = false;
        if (active() && !dirty() && !busy) render(true);
    }

    // ---------- viste ----------
    function groupCard(g) {
        const on = groupActive(g);
        const extra = [...(draft.allow[g.name] || [])];
        const progs = (g.allow || []).map(a => {
            const gone = isRemoved(g.name, a);
            return `<span class="rl-chip${gone ? ' gone' : ''}" title="${gone ? 'Tolto: non può più leggere questo segreto' : esc(a)}">${esc(baseName(a))}${model.manual ? '' : `<button class="rl-x" data-rm="${esc(g.name)}" data-path="${esc(a)}" aria-label="${gone ? 'Rimetti' : 'Togli'} ${esc(baseName(a))}">${gone ? '↺' : '✕'}</button>`}</span>`;
        }).join('') +
            extra.map(a => `<span class="rl-chip add" title="${esc(a)}">${esc(baseName(a))}<button class="rl-x" data-revoke="${esc(g.name)}" data-path="${esc(a)}" aria-label="Togli ${esc(baseName(a))}">✕</button></span>`).join('');
        return `<div class="rl-card${on ? '' : ' off'}">
          <div class="rl-head">
            <label class="sw"><input type="checkbox" data-grp="${esc(g.id)}" ${on ? 'checked' : ''} ${model.manual ? 'disabled' : ''}><span class="sw-t"></span></label>
            <div class="rl-title"><b>${esc(label(g))}</b>${g.in_profile ? '' : ' <span class="rl-tag">facoltativa</span>'}
              <div class="rl-d">${esc(WHAT[g.id] || g.desc)}</div></div>
            ${on ? modeSelect(g.name) : ''}
          </div>
          ${on ? `<div class="rl-rdy" data-rule-chip="${esc(g.name)}"></div>` : ''}
          <details class="rl-det"><summary>${on ? 'Cosa protegge e chi può usarlo' : 'Dettagli'}</summary>
            <div class="rl-k">File protetti</div><div class="rl-mono">${(g.paths || []).map(esc).join('<br>')}</div>
            <div class="rl-k">Programmi autorizzati</div><div>${progs || '<span class="rl-d">nessuno</span>'}</div>
          </details></div>`;
    }

    // Modalita' per singola regola: "come le altre" non scrive niente nel config.
    function modeSelect(rule, dis) {
        const cur = draft.modes[rule] || '';
        const glob = globalMode() === 'enforce' ? 'Blocca' : 'Solo osserva';
        return `<label class="rl-mode" title="Cosa fa ZeroShield quando un programma non autorizzato prova a leggere questo segreto"><span class="rl-d">Se non autorizzato</span>
          <select data-mode="${esc(rule)}" ${model.manual || dis ? 'disabled' : ''} aria-label="Modalità di questa protezione">
            <option value="" ${cur === '' ? 'selected' : ''}>Come le altre (${glob})</option>
            <option value="audit" ${cur === 'audit' ? 'selected' : ''}>Solo osserva</option>
            <option value="enforce" ${cur === 'enforce' ? 'selected' : ''}>Blocca</option>
          </select></label>`;
    }

    // Le tue regole (create con «Proteggi un mio file»).
    function myCard(r, i) {
        const progs = r.allow.map(a => `<span class="rl-chip add" title="${esc(a)}">${esc(baseName(a))}</span>`).join('');
        return `<div class="rl-card">
          <div class="rl-head"><span class="rl-mine" aria-hidden="true">★</span>
            <div class="rl-title"><b>${esc(r.name)}</b> <span class="rl-b ${modeOf2(r) === 'enforce' ? 'no' : 'ready'}">${MODE_TXT[modeOf2(r)]}</span>${r.deny_write ? ' <span class="rl-tag">scrittura solo ai programmi in lista</span>' : ''}
              <div class="rl-mono rl-d">${r.paths.map(esc).join('<br>')}</div></div>
            <div class="rl-ta"><button class="rl-btn ghost" data-my-edit="${i}" ${model.manual_rules ? 'disabled' : ''}>Modifica</button><button class="rl-btn ghost" data-my-del="${i}" ${model.manual_rules ? 'disabled' : ''}>Elimina</button></div></div>
          <div class="rl-k">Programmi autorizzati</div><div>${progs}</div></div>`;
    }
    const modeOf2 = r => r.mode || globalMode();

    function toolRow(t) {
        const rules = (t.rules || []).map(groupByName).filter(g => g && groupActive(g));
        const done = rules.length > 0 && rules.every(g => allowedFor(g, t));
        let badge = '', act = '', extra = '';
        if (!t.found) { badge = '<span class="rl-b none">non installato</span>'; }
        else if (done) {
            badge = '<span class="rl-b ok">✓ autorizzato</span>';
            const mine = rules.filter(g => draft.allow[g.name] && draft.allow[g.name].has(t.alt || t.path));
            if (mine.length) act = `<button class="rl-btn ghost" data-undo="${esc(t.id)}">Togli</button>`;
            // Autorizzata la copia protetta, ma il terminale lancia ancora l'altra: ZeroShield
            // continuerebbe a bloccarla (visto con oh-my-posh e k9s). Lo si dice subito.
            if (t.alt && t.path && t.alt !== t.path) {
                badge = '<span class="rl-b warn">✓ autorizzato · lancia la copia protetta</span>';
                extra = `<div class="rl-help"><b>Attenzione:</b> l’autorizzazione vale per <span class="rl-mono">${esc(t.alt)}</span>, ma il tuo terminale lancia <span class="rl-mono">${esc(t.path)}</span>, che verrebbe comunque bloccato. Lancia il percorso protetto, oppure aggiungi in <span class="rl-mono">~/.bashrc</span>: <span class="rl-mono">alias ${esc(t.name || t.id)}=${esc(t.alt)}</span></div>`;
            }
        } else if (!rules.length) { badge = '<span class="rl-b none">le sue regole sono spente</span>'; }
        else if (t.ok) {
            badge = '<span class="rl-b ready">pronto</span>';
            act = `<button class="rl-btn" data-auth="${esc(t.id)}">Autorizza</button>`;
        } else if (t.alt) {
            badge = '<span class="rl-b warn">usa la copia protetta</span>';
            act = `<button class="rl-btn" data-auth="${esc(t.id)}">Autorizza la copia protetta</button>`;
            extra = `<div class="rl-help">Esiste una copia sicura in <span class="rl-mono">${esc(t.alt)}</span>, ma il tuo terminale lancia <span class="rl-mono">${esc(t.path)}</span>, che ZeroShield non può considerare sicuro. Per usare la copia protetta, lancia <span class="rl-mono">${esc(t.alt)}</span> oppure togli l’altra dal PATH.</div>`;
        } else if (t.fix) {
            badge = '<span class="rl-b warn">serve un passo in più</span>';
            act = `<button class="rl-btn" data-trust="${esc(t.id)}">Rendi affidabile</button>`;
            extra = `<div class="rl-help">È installato in una cartella che puoi modificare tu (<span class="rl-mono">${esc(t.path)}</span>): un programma malevolo con i tuoi permessi potrebbe sostituirlo e farsi passare per lui, quindi ZeroShield non lo accetta. «Rendi affidabile» ne fa una copia protetta in <span class="rl-mono">/usr/local/bin</span> (ti chiede la password). Dopo un aggiornamento del programma va ripetuto.</div>`;
        } else {
            badge = '<span class="rl-b no">non autorizzabile</span>';
            extra = `<div class="rl-help">${esc(t.why || t.trust_err || '')}</div>`;
        }
        return `<div class="rl-tool"><div class="rl-tl"><b>${esc(t.label)}</b><div class="rl-d">${esc(t.reads)}</div></div>
          <div class="rl-ta">${badge}${act}</div>${extra}</div>`;
    }

    function bulkTools(found) {
        const ready = found.filter(t => {
            const rules = (t.rules || []).map(groupByName).filter(g => g && groupActive(g));
            return t.ok && rules.length && !rules.every(g => allowedFor(g, t));
        });
        return ready.length ? `<div class="rl-bulk"><button class="rl-btn" id="rl-bulk-tools">Autorizza tutti i ${ready.length} pronti</button><span class="rl-d">${ready.map(t => esc(t.label)).join(', ')}</span></div>` : '';
    }

    // Programmi visti dal demone (audit o blocco) in questa sessione, raggruppati per programma + regola.
    function seenList() {
        const m = new Map();
        (getEvents() || []).forEach(e => {
            if (e.canary || !e.exe || !e.rule || e.rule === 'canary') return;
            const k = e.rule + '\x00' + e.exe;
            const cur = m.get(k) || {rule: e.rule, exe: String(e.exe).replace(/ \(deleted\)$/, ''), n: 0, blocked: 0};
            cur.n++; if (e.action === 'blocked') cur.blocked++;
            m.set(k, cur);
        });
        return [...m.values()].sort((a, b) => b.n - a.n);
    }
    function prog(exe) {
        let c = progCache.get(exe);
        if (!c) {
            c = {v: null};
            progCache.set(exe, c);
            Promise.resolve(api.CheckProgram(exe)).then(v => { c.v = v; paintSeen(true); }).catch(() => { c.v = {found: false, why: 'controllo non riuscito'}; paintSeen(true); });
        }
        return c.v;
    }
    function seenRow(s, i) {
        const g = groupByName(s.rule);
        const p = prog(s.exe);
        const name = baseName(s.exe);
        let act = '<span class="rl-d">controllo…</span>';
        if (!g) act = `<span class="rl-d">regola ${esc(s.rule)} non modificabile da qui</span>`;
        else if (p) {
            if (allowedFor(g, p) || (draft.allow[g.name] && draft.allow[g.name].has(s.exe))) act = '<span class="rl-b ok">✓ autorizzato</span>';
            else if (p.ok) act = `<button class="rl-btn" data-seen-auth="${i}">Autorizza</button>`;
            else if (p.alt) act = `<button class="rl-btn" data-seen-auth="${i}">Autorizza la copia protetta</button>`;
            else if (p.fix) act = `<button class="rl-btn" data-seen-trust="${i}">Rendi affidabile</button>`;
            else act = `<span class="rl-b no" title="${esc(p.why || p.trust_err || '')}">non autorizzabile</span><div class="rl-help">${esc(p.why || p.trust_err || 'programma non adatto')}</div>`;
        }
        return `<div class="rl-tool"><div class="rl-tl"><b>${esc(name)}</b> <span class="rl-d">ha letto «${esc(g ? label(g) : s.rule)}» ${s.n} ${s.n === 1 ? 'volta' : 'volte'}${s.blocked ? ` (${s.blocked} bloccat${s.blocked === 1 ? 'a' : 'e'})` : ''}</span>
          <div class="rl-mono rl-d">${esc(s.exe)}</div></div><div class="rl-ta">${act}</div></div>`;
    }
    let seenCache = [];
    function seenHtml() {
        seenCache = seenList();
        if (!seenCache.length) {
            return '<div class="rl-empty">Finora nessun programma ha provato a leggere i tuoi segreti da quando hai aperto la finestra. Lascia ZeroShield in Audit qualche giorno: i programmi che usi compariranno qui.</div>';
        }
        return seenCache.map(seenRow).join('');
    }
    // Aggiorna solo la lista dei visti (arriva un evento o un controllo asincrono finisce) senza
    // ridisegnare la pagina: cosi' non si perdono scroll, campo di testo e dettagli aperti.
    function paintSeen(force) {
        const el = document.getElementById('rl-seen');
        if (!el || !model || !draft) return;
        const sig = JSON.stringify(seenList().map(s => [s.rule, s.exe, s.n])) + norm(draft) + ((getStatus() || {}).mode || '');
        if (!force && sig === seenSig) return;
        seenSig = sig;
        el.innerHTML = seenHtml();
        bindSeen(el);
        const gd = document.getElementById('rl-guide');
        if (gd) { gd.innerHTML = guideHtml(); bindGuide(); }
        paintRuleChips();
    }

    // Per ogni protezione attiva: e' pronta per «Blocca»? Si guarda cio' che il demone ha visto in questa sessione.
    function paintRuleChips() {
        document.querySelectorAll('[data-rule-chip]').forEach(el => {
            const rule = el.dataset.ruleChip, g = groupByName(rule);
            let seen = 0, pending = 0;
            seenCache.forEach(s => {
                if (s.rule !== rule) return;
                seen++;
                const p = (progCache.get(s.exe) || {}).v;
                if (!p) { pending++; return; }
                if (!(g && (allowedFor(g, p) || (draft.allow[rule] && draft.allow[rule].has(s.exe))))) pending++;
            });
            const enf = modeOf(rule) === 'enforce';
            let html = '';
            if (enf) html = '<span class="rl-b ok">In Blocca</span>';
            else if (seen === 0) html = '<span class="rl-d">Nessun accesso visto finora.</span>';
            else if (pending > 0) html = `<span class="rl-b warn">${pending} programm${pending === 1 ? 'a' : 'i'} da autorizzare prima di bloccare</span>`;
            else html = `<span class="rl-b ok">Pronta per Blocca</span><button class="rl-btn ghost" data-mode-go="${esc(rule)}">Metti solo questa in Blocca</button>`;
            el.innerHTML = html;
            el.querySelectorAll('[data-mode-go]').forEach(b => { b.onclick = () => { draft.modes[rule] = 'enforce'; render(true); }; });
        });
    }

    // Percorso guidato in 3 passi con l'indicatore "sei pronto per Enforce?". Si basa su cio' che il
    // demone ha visto in QUESTA sessione: lo dice chiaramente, per non far credere a un via libera
    // dato su pochi minuti di osservazione.
    function readiness() {
        let ready = [], fixable = [], impossible = [], total = 0;
        seenCache.forEach((s, i) => {
            const g = groupByName(s.rule);
            if (!g || !groupActive(g)) return;
            total++;
            const p = (progCache.get(s.exe) || {}).v;
            if (!p) return;
            if (allowedFor(g, p) || (draft.allow[g.name] && draft.allow[g.name].has(s.exe))) return;
            if (p.ok || p.alt) ready.push(i);
            else if (p.fix) fixable.push(i);
            else impossible.push(i);
        });
        return {ready, fixable, impossible, total};
    }
    function guideHtml() {
        const st = getStatus() || {}, r = readiness();
        const enforce = st.mode === 'enforce';
        const step = enforce ? 4 : (r.total === 0 ? 1 : (r.ready.length + r.fixable.length + r.impossible.length > 0 ? 2 : 3));
        const s = (n, t, dsc) => `<li class="${n < step ? 'done' : n === step ? 'now' : ''}"><span class="rl-n">${n < step ? '✓' : n}</span><div><b>${t}</b><div class="rl-d">${dsc}</div></div></li>`;
        let msg = '';
        if (enforce) {
            msg = `<div class="rl-ready ok"><b>Enforce attivo.</b> Se un tuo programma smette di funzionare, compare qui sotto: autorizzalo e premi Applica.</div>`;
        } else if (r.total === 0) {
            msg = `<div class="rl-ready"><b>Per ora non c’è nulla da fare.</b> Usa il computer normalmente (terminale, kubectl, docker…): i programmi che toccano i tuoi segreti compariranno nella lista «Visti» qui sotto. Meglio lasciare Audit acceso qualche giorno.</div>`;
        } else if (r.ready.length + r.fixable.length > 0) {
            const n = r.ready.length + r.fixable.length;
            msg = `<div class="rl-ready"><b>Mancano ${n} programm${n === 1 ? 'a' : 'i'} da autorizzare</b>: passando a Enforce ora verrebbero bloccati.
              ${r.ready.length ? `<button class="rl-btn" id="rl-bulk-seen">Autorizza i ${r.ready.length} pronti</button>` : ''}</div>`;
        } else if (r.impossible.length) {
            msg = `<div class="rl-ready warn"><b>${r.impossible.length} programm${r.impossible.length === 1 ? 'a non si può' : 'i non si possono'} autorizzare</b> (vedi i motivi sotto): in Enforce verrebbero bloccati. È normale per shell, interpreti e programmi in cartelle modificabili da te.</div>`;
        } else {
            msg = `<div class="rl-ready ok"><b>Tutto ciò che hai usato finora è autorizzato.</b> Se lo usi da qualche giorno, puoi passare a Enforce.
              <button class="rl-btn" id="rl-go-config">Vai a Configurazione</button></div>`;
        }
        const imp = (!enforce && r.impossible.length && (r.ready.length + r.fixable.length) > 0)
            ? `<div class="rl-ready warn">Altri ${r.impossible.length} non si possono autorizzare: in Enforce verrebbero comunque bloccati.</div>` : '';
        return `<ol class="rl-steps">
            ${s(1, 'Osserva', 'ZeroShield registra chi legge i tuoi segreti, senza bloccare nulla (Audit).')}
            ${s(2, 'Autorizza', 'Metti nella lista i programmi tuoi: kubectl, helm, docker…')}
            ${s(3, 'Blocca', 'Passa a Enforce: da lì solo i programmi in lista leggono i segreti.')}
          </ol>${msg}${imp}`;
    }
    function bindGuide() {
        const g = document.getElementById('rl-guide');
        if (!g) return;
        const b = document.getElementById('rl-bulk-seen'), c = document.getElementById('rl-go-config');
        if (b) b.onclick = () => {
            readiness().ready.forEach(i => { const sn = seenCache[i], p = (progCache.get(sn.exe) || {}).v; if (p) authorize([sn.rule], p); });
            render(true);
        };
        if (c) c.onclick = () => goto('config');
    }

    function applyBar() {
        if (!dirty()) return '';
        const n = changes().length;
        return `<div class="rl-bar" role="region" aria-label="Modifiche in sospeso"><span><b>${n} ${n === 1 ? 'modifica' : 'modifiche'}</b> non ancora applicat${n === 1 ? 'a' : 'e'}</span>
          <span class="rl-bar-b"><button class="chip" id="rl-cancel" ${busy ? 'disabled' : ''}>Annulla</button><button class="chip on" id="rl-apply" ${busy ? 'disabled' : ''}>${busy ? esc(busy) : 'Applica'}</button></span></div>`;
    }
    // Elenco leggibile delle differenze tra stato salvato e bozza (per la barra e per la conferma).
    function changes() {
        const out = [], base = draftFrom(model.choice);
        (model.groups || []).forEach(g => {
            const was = g.in_profile ? !base.disable.has(g.name) : base.enable.has(g.id);
            const now = groupActive(g);
            if (was !== now) out.push(now ? `Attivi la protezione «${label(g)}»` : `Spegni la protezione «${label(g)}»`);
        });
        const names = new Set([...Object.keys(base.modes), ...Object.keys(draft.modes)]);
        names.forEach(r => {
            const a = base.modes[r] || '', b = draft.modes[r] || '';
            if (a !== b) out.push(`«${labelOfRule(r)}»: ${b ? (b === 'enforce' ? 'passa a Blocca' : 'passa a Solo osserva') : 'torna alla modalità generale'}`);
        });
        const rnames = new Set([...Object.keys(base.removed), ...Object.keys(draft.removed)]);
        rnames.forEach(r => {
            const a = base.removed[r] || new Set(), b = draft.removed[r] || new Set();
            [...b].filter(x => !a.has(x)).forEach(x => out.push(`Togli «${baseName(x)}» da «${labelOfRule(r)}»`));
            [...a].filter(x => !b.has(x)).forEach(x => out.push(`Rimetti «${baseName(x)}» in «${labelOfRule(r)}»`));
        });
        const bm = Object.fromEntries(base.my.map(r => [r.name, JSON.stringify(r)])), dm = Object.fromEntries(draft.my.map(r => [r.name, JSON.stringify(r)]));
        Object.keys(dm).forEach(n => { if (!(n in bm)) out.push(`Aggiungi la tua protezione «${n}»`); else if (bm[n] !== dm[n]) out.push(`Modifichi la tua protezione «${n}»`); });
        Object.keys(bm).forEach(n => { if (!(n in dm)) out.push(`Elimini la tua protezione «${n}»`); });
        const rules = new Set([...Object.keys(base.allow), ...Object.keys(draft.allow)]);
        rules.forEach(r => {
            const a = base.allow[r] || new Set(), b = draft.allow[r] || new Set();
            [...b].filter(x => !a.has(x)).forEach(x => out.push(`Autorizzi «${baseName(x)}» per «${labelOfRule(r)}»`));
            [...a].filter(x => !b.has(x)).forEach(x => out.push(`Togli «${baseName(x)}» da «${labelOfRule(r)}»`));
        });
        return out;
    }

    let justLoaded = false;
    function render(force) {
        if (!active()) return;
        if (!model) {
            content.innerHTML = `<h2>${icons.key}Regole</h2><p class="sub">Carico le regole…</p>`;
            load();
            return;
        }
        // Un evento o un poll di stato non devono ridisegnare la pagina mentre stai scegliendo.
        if (!force && document.getElementById('rl-root')) { paintSeen(false); return; }
        const reentering = !document.getElementById('rl-root') && !justLoaded;
        justLoaded = false;
        if (model.error) {
            content.innerHTML = `<h2>${icons.key}Regole</h2><div class="warn">${icons.warn}<div>${esc(model.error)}<br>Se il servizio non è ancora installato, parti dalla scheda <b>Stato</b>.</div></div>`;
            return;
        }
        const scrollY = content.scrollTop;
        // I riquadri «Dettagli» aperti restano aperti quando la pagina si ridisegna (altrimenti ogni clic li chiude).
        const wasOpen = [...content.querySelectorAll('details.rl-det')].map(d => d.open);
        const found = (model.tools || []).filter(t => t.found), rest = (model.tools || []).filter(t => !t.found);
        content.innerHTML = `<div id="rl-root"><h2>${icons.key}Regole</h2>
          <p class="sub">Scegli quali segreti proteggere e quali programmi possono usarli. Per tutti gli altri l’accesso è ${(getStatus() || {}).mode === 'enforce' ? 'bloccato' : 'solo registrato'}.</p>
          <div id="rl-guide"></div>
          ${model.manual ? `<div class="warn">${icons.warn}<div>Nel file di configurazione queste scelte sono scritte a mano, quindi da qui puoi solo guardarle. Per cambiarle modifica <span class="rl-mono">/etc/zt-shield/shield.yaml</span>.</div></div>` : ''}
          <h3 class="sec">Cosa proteggere</h3>
          ${(model.groups || []).map(groupCard).join('')}
          ${(model.custom || []).length ? `<div class="rl-d">Regole personalizzate nel file di configurazione (non modificabili da qui): ${model.custom.map(esc).join(', ')}.</div>` : ''}
          <h3 class="sec">Le tue protezioni</h3>
          ${draft.my.length ? draft.my.map(myCard).join('') : '<div class="rl-empty">Non hai ancora aggiunto protezioni tue. Per esempio un portafoglio crypto, un database di password o una cartella di documenti riservati.</div>'}
          ${model.manual_rules ? `<div class="warn">${icons.warn}<div>Nel config ci sono già <span class="rl-mono">extra_rules</span> scritte a mano: le protezioni personali si modificano lì.</div></div>` : ''}
          <div class="rl-bulk"><button class="rl-btn" id="rl-my-new" ${model.manual || model.manual_rules ? 'disabled' : ''}>+ Proteggi un mio file</button><span class="rl-d">Scegli un file o una cartella e decidi chi può leggerli.</span></div>
          <h3 class="sec">Programmi che usi</h3>
          <p class="rl-d">Gli strumenti noti che hanno bisogno di leggere un segreto. Quelli trovati sul tuo computer sono in cima.</p>
          ${bulkTools(found)}
          ${found.length ? found.map(toolRow).join('') : '<div class="rl-empty">Nessuno dei programmi noti è installato.</div>'}
          ${rest.length ? `<details class="rl-det"><summary>Altri programmi noti non installati (${rest.length})</summary>${rest.map(toolRow).join('')}</details>` : ''}
          <h3 class="sec">Visti da quando hai aperto la finestra</h3>
          <p class="rl-d">Programmi che hanno provato a leggere un segreto. Se è roba tua e ne hai bisogno, autorizzali.</p>
          <div id="rl-seen"></div>
          <h3 class="sec">Un altro programma</h3>
          <div class="rl-add"><input id="rl-in" type="text" placeholder="nome (es. lazygit) o percorso completo" aria-label="Nome o percorso del programma" ${model.manual ? 'disabled' : ''}>
            <button class="rl-btn" id="rl-check" ${model.manual ? 'disabled' : ''}>Controlla</button></div>
          <div id="rl-add-out"></div>
          <div class="rl-spacer"></div></div>
          <div id="rl-barwrap">${applyBar()}</div>`;
        content.scrollTop = scrollY;
        content.querySelectorAll('details.rl-det').forEach((d, i) => { if (wasOpen[i]) d.open = true; });
        seenSig = '';
        paintSeen(true);
        bind();
        if (reentering) refreshQuiet();
    }
    function repaintBar() {
        const w = document.getElementById('rl-barwrap');
        if (w) { w.innerHTML = applyBar(); bindBar(); }
    }

    // ---------- azioni ----------
    async function trust(input) {
        const ok = await confirmDialog({
            title: 'Rendere affidabile questo programma?',
            body: `ZeroShield farà una <b>copia protetta</b> di <span class="rl-mono">${esc(input)}</span> in <span class="rl-mono">/usr/local/bin</span> (di proprietà di root), perché possa fidarsi di lui. Ti verrà chiesta la password di sistema.<br><br>Dopo un aggiornamento del programma la copia non si aggiorna da sola: basterà ripetere questo passaggio.`,
            ok: 'Continua',
        });
        if (!ok) return null;
        busy = 'Copio…'; repaintBar();
        try {
            const p = await api.MakeTrusted(input);
            toast('Copia protetta creata in ' + (p.path || '/usr/local/bin'));
            progCache.clear();
            const keep = draft;
            model = await api.RulesModel();
            // la bozza dell'utente resta: ricarico solo il modello (stato dei programmi)
            draft = keep;
            return p;
        } catch (e) { toast(String(e && e.message || e), true); return null; }
        finally { busy = ''; }
    }

    async function apply() {
        const lines = changes();
        const ok = await confirmDialog({
            title: 'Applicare le modifiche?',
            body: `<ul class="rl-ul">${lines.map(l => `<li>${esc(l)}</li>`).join('')}</ul>ZeroShield si riavvia per circa 3 secondi e rilegge le regole (ti viene chiesta la password di sistema). Se qualcosa non va, torna da solo alla configurazione precedente; una copia di sicurezza resta in <span class="rl-mono">/etc/zt-shield</span>.`,
            ok: 'Applica',
        });
        if (!ok) return;
        busy = 'Applico…'; repaintBar();
        try {
            await api.ApplyRules(choiceOut());
            toast('Regole applicate. ZeroShield le sta usando.');
            progCache.clear();
            model = await api.RulesModel();
            draft = draftFrom(model.choice);
        } catch (e) { toast(String(e && e.message || e), true); }
        busy = '';
        render(true);
    }

    // ---------- collegamenti ----------
    function bindBar() {
        const a = document.getElementById('rl-apply'), c = document.getElementById('rl-cancel');
        if (a) a.onclick = apply;
        if (c) c.onclick = () => { draft = draftFrom(model.choice); render(true); };
    }
    function bindSeen(root) {
        root.querySelectorAll('[data-seen-auth]').forEach(b => {
            b.onclick = () => {
                const s = seenCache[+b.dataset.seenAuth], p = prog(s.exe);
                if (!s || !p) return;
                authorize([s.rule], p);
                render(true);
            };
        });
        root.querySelectorAll('[data-seen-trust]').forEach(b => {
            b.onclick = async () => {
                const s = seenCache[+b.dataset.seenTrust], p = prog(s.exe);
                if (!s || !p) return;
                const r = await trust(s.exe);
                if (r && r.ok) authorize([s.rule], r);
                render(true);
            };
        });
    }
    function bind() {
        const root = document.getElementById('rl-root');
        root.querySelectorAll('[data-grp]').forEach(i => {
            i.onchange = () => { toggleGroup((model.groups || []).find(g => g.id === i.dataset.grp)); render(true); };
        });
        root.querySelectorAll('[data-mode]').forEach(sel => {
            sel.onchange = () => { draft.modes[sel.dataset.mode] = sel.value; render(true); };
        });
        root.querySelectorAll('[data-rm]').forEach(b => {
            b.onclick = e => { e.preventDefault(); toggleRemoved(b.dataset.rm, b.dataset.path); render(true); };
        });
        const nw = document.getElementById('rl-my-new');
        if (nw) nw.onclick = () => openWizard(null);
        root.querySelectorAll('[data-my-edit]').forEach(b => { b.onclick = () => openWizard(+b.dataset.myEdit); });
        root.querySelectorAll('[data-my-del]').forEach(b => { b.onclick = () => { draft.my.splice(+b.dataset.myDel, 1); render(true); }; });
        root.querySelectorAll('[data-revoke]').forEach(b => {
            b.onclick = e => { e.preventDefault(); revoke(b.dataset.revoke, b.dataset.path); render(true); };
        });
        const tool = id => (model.tools || []).find(t => t.id === id);
        const activeRules = t => (t.rules || []).filter(n => { const g = groupByName(n); return g && groupActive(g); });
        // Solo le regole dove il programma non e' gia' autorizzato: niente voci doppie nel config.
        const pendingRules = t => activeRules(t).filter(n => !allowedFor(groupByName(n), t));
        root.querySelectorAll('[data-auth]').forEach(b => {
            b.onclick = () => { const t = tool(b.dataset.auth); authorize(pendingRules(t), t); render(true); };
        });
        const bt = document.getElementById('rl-bulk-tools');
        if (bt) bt.onclick = () => {
            (model.tools || []).filter(t => t.found && t.ok).forEach(t => {
                const rs = pendingRules(t);
                if (rs.length) authorize(rs, t);
            });
            render(true);
        };
        root.querySelectorAll('[data-undo]').forEach(b => {
            b.onclick = () => { const t = tool(b.dataset.undo); activeRules(t).forEach(n => revoke(n, t.alt || t.path)); render(true); };
        });
        root.querySelectorAll('[data-trust]').forEach(b => {
            b.onclick = async () => {
                const t = tool(b.dataset.trust);
                const r = await trust(t.path);
                if (r && r.ok) { const nt = tool(t.id); authorize(pendingRules(t), {...nt, ...r}); }
                render(true);
            };
        });
        const inp = document.getElementById('rl-in'), out = document.getElementById('rl-add-out');
        const check = async () => {
            const v = inp.value.trim();
            if (!v) return;
            out.innerHTML = '<div class="rl-d">controllo…</div>';
            let p;
            try { p = await api.CheckProgram(v); } catch (e) { out.innerHTML = `<div class="rl-help">${esc(String(e && e.message || e))}</div>`; return; }
            const opts = (model.groups || []).filter(groupActive).map(g => `<option value="${esc(g.name)}">${esc(label(g))}</option>`).join('');
            if (!p.found) { out.innerHTML = `<div class="rl-help">«${esc(v)}» non è stato trovato sul computer. Prova con il percorso completo.</div>`; return; }
            if (!p.ok && !p.fix && !p.alt) { out.innerHTML = `<div class="rl-help"><b>${esc(p.name)}</b> non si può autorizzare: ${esc(p.why || p.trust_err)}</div>`; return; }
            const action = p.ok || p.alt
                ? `<button class="rl-btn" id="rl-add-ok">Autorizza</button>`
                : `<button class="rl-btn" id="rl-add-trust">Rendi affidabile</button>`;
            out.innerHTML = `<div class="rl-tool"><div class="rl-tl"><b>${esc(p.name)}</b><div class="rl-mono rl-d">${esc(p.path)}</div>
              ${p.ok || p.alt ? '' : '<div class="rl-help">Per poterlo autorizzare serve prima una copia protetta (ti chiede la password).</div>'}</div>
              <div class="rl-ta"><label class="rl-d">per <select id="rl-add-rule">${opts}</select></label>${action}</div></div>`;
            const rule = () => document.getElementById('rl-add-rule').value;
            const ok = document.getElementById('rl-add-ok'), tr = document.getElementById('rl-add-trust');
            if (ok) ok.onclick = () => { authorize([rule()], p); render(true); };
            if (tr) tr.onclick = async () => { const r = await trust(p.path); if (r && r.ok) authorize([rule()], r); render(true); };
        };
        document.getElementById('rl-check').onclick = check;
        inp.onkeydown = e => { if (e.key === 'Enter') check(); };
        bindBar();
    }


    // ---------- «Proteggi un mio file» ----------
    let wiz = null; // {idx, title, paths, allow, deny_write, mode}
    let wzTimer = 0;
    const slug = t => String(t || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
    function wzName() {
        const n = slug(wiz.title);
        const taken = (model.groups || []).some(g => g.name === n) || draft.my.some((r, i) => r.name === n && i !== wiz.idx);
        return {n, bad: !n ? 'Dai un nome alla protezione.' : taken ? 'Esiste già una protezione con questo nome.' : ''};
    }
    function openWizard(i) {
        const r = i == null ? null : draft.my[i];
        wiz = {idx: i, title: r ? r.name : '', paths: r ? [...r.paths] : [], allow: r ? [...r.allow] : [], deny_write: r ? !!r.deny_write : false, mode: r ? r.mode : ''};
        const ov = document.createElement('div');
        ov.id = 'rl-wiz';
        ov.innerHTML = `<div class="ob-card wiz" role="dialog" aria-modal="true" aria-label="Proteggi un mio file">
          <h2>${i == null ? 'Proteggi un mio file' : 'Modifica la protezione'}</h2>
          <p class="rl-d">Tre passi: cosa proteggere, chi può usarlo, come chiamarla. Non cambia nulla finché non premi <b>Applica</b>.</p>
          <div class="wz-sec"><b>1 · Cosa proteggere</b>
            <div class="wz-row"><button class="rl-btn" id="wz-file">Scegli un file…</button><button class="rl-btn" id="wz-dir">Scegli una cartella…</button></div>
            <div class="rl-add"><input id="wz-path" type="text" placeholder="oppure scrivi un percorso o uno schema, es. Documents/*.kdbx" aria-label="Percorso o schema"><button class="rl-btn" id="wz-addpath">Aggiungi</button></div>
            <div class="rl-d">Senza «/» iniziale il percorso parte dalla tua cartella personale. Il jolly <span class="rl-mono">*</span> sostituisce una parte del nome (<span class="rl-mono">*.kdbx</span> = tutti i file .kdbx).</div>
            <div id="wz-paths"></div><div id="wz-pv"></div></div>
          <div class="wz-sec"><b>2 · Chi può usarlo</b>
            <p class="rl-d">Solo questi programmi potranno aprire quei file: aggiungi quelli che usi davvero (per esempio il tuo gestore di password).</p>
            <div class="rl-add"><input id="wz-prog" type="text" placeholder="nome o percorso del programma, es. keepassxc" aria-label="Programma"><button class="rl-btn" id="wz-progcheck">Controlla</button></div>
            <div id="wz-prog-out"></div><div id="wz-allow"></div><div id="wz-helpers"></div></div>
          <div class="wz-sec"><b>3 · Nome e comportamento</b>
            <div class="wz-row"><input id="wz-title" type="text" placeholder="es. Wallet crypto" aria-label="Nome" value="${esc(wiz.title)}"></div>
            <div class="rl-d" id="wz-name"></div>
            <div class="wz-row"><label class="rl-mode"><span class="rl-d">Se un programma non autorizzato prova a leggerlo</span>
              <select id="wz-mode"><option value="">Come le altre protezioni (${globalMode() === 'enforce' ? 'Blocca' : 'Solo osserva'})</option><option value="audit">Solo osserva</option><option value="enforce">Blocca</option></select></label></div>
            <label class="wz-chk"><input type="checkbox" id="wz-dw"> <span>Blocca le <b>scritture</b> dei programmi non autorizzati <span class="rl-d">(utile contro i ransomware; chi è in lista scrive normalmente, ma un programma che non hai autorizzato, per esempio un gestore di password che salva, non potrà più)</span></span></label></div>
          <div class="wz-err" id="wz-err" role="alert"></div>
          <div class="ob-btns"><button class="chip" id="wz-cancel">Annulla</button><button class="chip on" id="wz-save">${i == null ? 'Aggiungi alla bozza' : 'Salva nella bozza'}</button></div></div>`;
        document.body.appendChild(ov);
        const done = () => { document.removeEventListener('keydown', onKey, true); clearTimeout(wzTimer); ov.remove(); wiz = null; };
        const onKey = e => { if (e.key === 'Escape') { e.stopPropagation(); done(); } };
        document.addEventListener('keydown', onKey, true);
        const $ = id => ov.querySelector('#' + id);
        $('wz-mode').value = wiz.mode; $('wz-dw').checked = wiz.deny_write;
        $('wz-cancel').onclick = done;
        ov.addEventListener('mousedown', e => { if (e.target === ov) done(); });
        const paintPaths = () => {
            $('wz-paths').innerHTML = wiz.paths.map((p, k) => `<span class="rl-chip add" title="${esc(p)}">${esc(p)}<button class="rl-x" data-wz-rmp="${k}" aria-label="Togli ${esc(p)}">✕</button></span>`).join('');
            $('wz-paths').querySelectorAll('[data-wz-rmp]').forEach(b => { b.onclick = () => { wiz.paths.splice(+b.dataset.wzRmp, 1); paintPaths(); schedulePreview(); }; });
        };
        const paintAllow = () => {
            $('wz-allow').innerHTML = wiz.allow.map((a, k) => `<span class="rl-chip add" title="${esc(a)}">${esc(baseName(a))}<button class="rl-x" data-wz-rma="${k}" aria-label="Togli ${esc(baseName(a))}">✕</button></span>`).join('') || '<span class="rl-d">Nessun programma ancora.</span>';
            $('wz-allow').querySelectorAll('[data-wz-rma]').forEach(b => { b.onclick = () => { wiz.allow.splice(+b.dataset.wzRma, 1); paintAllow(); paintHelpers(); }; });
        };
        // Programmi di sistema che leggono i file in background (indicizzatori): senza, ogni loro scansione compare tra i blocchi.
        const paintHelpers = () => {
            const hs = (model.helpers || []).filter(h => (h.found || []).length);
            const box = $('wz-helpers');
            if (!hs.length) { box.innerHTML = ''; return; }
            box.innerHTML = `<div class="rl-d" style="margin-top:8px">Suggeriti se proteggi una cartella di documenti:</div>` + hs.map(h => {
                const added = h.found.every(p => wiz.allow.includes(p));
                return `<div class="wz-row"><button class="rl-btn ghost" data-helper="${esc(h.id)}" ${added ? 'disabled' : ''}>${added ? '✓ ' : '+ '}${esc(h.label)}</button><span class="rl-d">${esc(h.why)}</span></div>`;
            }).join('');
            box.querySelectorAll('[data-helper]').forEach(b => {
                b.onclick = () => {
                    const h = hs.find(x => x.id === b.dataset.helper);
                    h.found.forEach(p => { if (!wiz.allow.includes(p)) wiz.allow.push(p); });
                    paintAllow(); paintHelpers();
                };
            });
        };
        const paintName = () => { const nm = wzName(); $('wz-name').innerHTML = nm.n ? `Nome tecnico (compare nei log): <span class="rl-mono">${esc(nm.n)}</span>${nm.bad ? ` <span class="bad" style="color:var(--red)">· ${esc(nm.bad)}</span>` : ''}` : ''; };
        const preview = async () => {
            if (!wiz) return;
            if (!wiz.paths.length) { $('wz-pv').innerHTML = ''; return; }
            let r;
            try { r = await api.PreviewPaths([...wiz.paths]); } catch (e) { $('wz-pv').innerHTML = `<div class="wz-pv bad">${esc(String(e && e.message || e))}</div>`; return; }
            if (!wiz || !document.getElementById('wz-pv')) return;
            wiz.pv = r;
            const parts = [];
            (r.errors || []).forEach(e => parts.push(`<div class="bad">✕ ${esc(e)}</div>`));
            if (r.matched > 0) parts.push(`<div><b>Proteggerà ${r.capped ? 'più di ' : ''}${r.matched} file</b> <span class="rl-d">(es. ${(r.examples || []).map(x => esc(baseName(x))).join(', ')})</span></div>`);
            (r.missing || []).forEach(m => parts.push(`<div class="rl-d">«${esc(m)}» oggi non esiste: la protezione scatterà se compare.</div>`));
            (r.warnings || []).forEach(w => parts.push(`<div class="warn-t">⚠ ${esc(w)}</div>`));
            $('wz-pv').innerHTML = parts.length ? `<div class="wz-pv">${parts.join('')}</div>` : '';
        };
        const schedulePreview = () => { clearTimeout(wzTimer); wzTimer = setTimeout(preview, 250); };
        const addPath = p => {
            p = String(p || '').trim();
            if (p && !wiz.paths.includes(p)) { wiz.paths.push(p); paintPaths(); schedulePreview(); }
        };
        $('wz-file').onclick = async () => { try { addPath(await api.PickPath('file')); } catch (e) { toast(String(e && e.message || e), true); } };
        $('wz-dir').onclick = async () => { try { addPath(await api.PickPath('dir')); } catch (e) { toast(String(e && e.message || e), true); } };
        $('wz-addpath').onclick = () => { addPath($('wz-path').value); $('wz-path').value = ''; };
        $('wz-path').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); $('wz-addpath').click(); } };
        const progCheck = async () => {
            const v = $('wz-prog').value.trim();
            if (!v) return;
            const out = $('wz-prog-out');
            out.innerHTML = '<div class="rl-d">controllo…</div>';
            let p;
            try { p = await api.CheckProgram(v); } catch (e) { out.innerHTML = `<div class="rl-help">${esc(String(e && e.message || e))}</div>`; return; }
            if (!p.found) { out.innerHTML = `<div class="rl-help">«${esc(v)}» non è stato trovato sul computer. Prova con il percorso completo.</div>`; return; }
            const add = pp => { const path = pp.alt || pp.path; if (!wiz.allow.includes(path)) wiz.allow.push(path); out.innerHTML = ''; $('wz-prog').value = ''; paintAllow(); };
            if (p.ok || p.alt) { add(p); return; }
            if (p.fix) {
                out.innerHTML = `<div class="rl-help"><b>${esc(p.name)}</b> si trova in una cartella che puoi modificare tu (<span class="rl-mono">${esc(p.path)}</span>): ZeroShield non può fidarsi.
                  <button class="rl-btn" id="wz-trust">Rendi affidabile</button></div>`;
                $('wz-trust').onclick = async () => { const r = await trust(p.path); if (r && r.ok) add(r); };
                return;
            }
            out.innerHTML = `<div class="rl-help"><b>${esc(p.name)}</b> non si può autorizzare: ${esc(p.why || p.trust_err || '')}</div>`;
        };
        $('wz-progcheck').onclick = progCheck;
        $('wz-prog').onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); progCheck(); } };
        $('wz-title').oninput = () => { wiz.title = $('wz-title').value; paintName(); };
        $('wz-mode').onchange = () => { wiz.mode = $('wz-mode').value; };
        $('wz-dw').onchange = () => { wiz.deny_write = $('wz-dw').checked; };
        $('wz-save').onclick = async () => {
            const err = $('wz-err'), nm = wzName();
            err.textContent = '';
            if (nm.bad) { err.textContent = nm.bad; return; }
            if (!wiz.paths.length) { err.textContent = 'Scegli almeno un file o una cartella.'; return; }
            if (!wiz.allow.length) { err.textContent = 'Aggiungi almeno un programma che può usarlo: senza, nemmeno tu potresti più aprire quei file.'; return; }
            try {
                const r = await api.PreviewPaths([...wiz.paths]);
                if (r.errors && r.errors.length) { err.textContent = r.errors[0]; return; }
            } catch (e) { err.textContent = String(e && e.message || e); return; }
            const rule = {name: nm.n, paths: [...wiz.paths], allow: [...wiz.allow], deny_write: wiz.deny_write, mode: wiz.mode};
            if (wiz.idx == null) draft.my.push(rule); else draft.my[wiz.idx] = rule;
            done();
            render(true);
        };
        paintPaths(); paintAllow(); paintHelpers(); paintName(); preview();
        $('wz-file').focus();
    }

    return {
        render,
        // Per i test e per tornare alla vista: forza una nuova lettura del modello.
        reload() { model = null; render(true); },
        isDirty: dirty,
    };
}
