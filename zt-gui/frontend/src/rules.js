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
        return {enable: new Set(c.enable_groups || []), disable: new Set(c.disable_rules || []), allow};
    }
    function norm(dr) {
        const allow = {};
        Object.keys(dr.allow).sort().forEach(k => { if (dr.allow[k].size) allow[k] = [...dr.allow[k]].sort(); });
        return JSON.stringify({e: [...dr.enable].sort(), d: [...dr.disable].sort(), a: allow});
    }
    const dirty = () => !!(model && draft && norm(draft) !== norm(draftFrom(model.choice)));
    function choiceOut() {
        const allow = {};
        Object.keys(draft.allow).forEach(k => { if (draft.allow[k].size) allow[k] = [...draft.allow[k]].sort(); });
        return {enable_groups: [...draft.enable].sort(), disable_rules: [...draft.disable].sort(), allow_extra: allow};
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
        return (g.allow || []).some(a => a === path || (a === baseName(path) && (p.trusted || !!p.alt)));
    }
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
        const progs = (g.allow || []).map(a => `<span class="rl-chip">${esc(baseName(a))}</span>`).join('') +
            extra.map(a => `<span class="rl-chip add" title="${esc(a)}">${esc(baseName(a))}<button class="rl-x" data-revoke="${esc(g.name)}" data-path="${esc(a)}" aria-label="Togli ${esc(baseName(a))}">✕</button></span>`).join('');
        return `<div class="rl-card${on ? '' : ' off'}">
          <div class="rl-head">
            <label class="sw"><input type="checkbox" data-grp="${esc(g.id)}" ${on ? 'checked' : ''} ${model.manual ? 'disabled' : ''}><span class="sw-t"></span></label>
            <div class="rl-title"><b>${esc(label(g))}</b>${g.in_profile ? '' : ' <span class="rl-tag">facoltativa</span>'}
              <div class="rl-d">${esc(WHAT[g.id] || g.desc)}</div></div>
          </div>
          <details class="rl-det"><summary>${on ? 'Cosa protegge e chi può usarlo' : 'Dettagli'}</summary>
            <div class="rl-k">File protetti</div><div class="rl-mono">${(g.paths || []).map(esc).join('<br>')}</div>
            <div class="rl-k">Programmi autorizzati</div><div>${progs || '<span class="rl-d">nessuno</span>'}</div>
          </details></div>`;
    }

    function toolRow(t) {
        const rules = (t.rules || []).map(groupByName).filter(g => g && groupActive(g));
        const done = rules.length > 0 && rules.every(g => allowedFor(g, t));
        let badge = '', act = '', extra = '';
        if (!t.found) { badge = '<span class="rl-b none">non installato</span>'; }
        else if (done) {
            badge = '<span class="rl-b ok">✓ autorizzato</span>';
            const mine = rules.filter(g => draft.allow[g.name] && draft.allow[g.name].has(t.alt || t.path));
            if (mine.length) act = `<button class="rl-btn ghost" data-undo="${esc(t.id)}">Togli</button>`;
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
        const sig = JSON.stringify(seenList().map(s => [s.rule, s.exe, s.n])) + norm(draft);
        if (!force && sig === seenSig) return;
        seenSig = sig;
        el.innerHTML = seenHtml();
        bindSeen(el);
        const gd = document.getElementById('rl-guide');
        if (gd) { gd.innerHTML = guideHtml(); bindGuide(); }
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
        const step = enforce ? 3 : (r.total === 0 ? 1 : (r.ready.length + r.fixable.length + r.impossible.length > 0 ? 2 : 3));
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
        const found = (model.tools || []).filter(t => t.found), rest = (model.tools || []).filter(t => !t.found);
        content.innerHTML = `<div id="rl-root"><h2>${icons.key}Regole</h2>
          <p class="sub">Scegli quali segreti proteggere e quali programmi possono usarli. Per tutti gli altri l’accesso è ${(getStatus() || {}).mode === 'enforce' ? 'bloccato' : 'solo registrato'}.</p>
          <div id="rl-guide"></div>
          ${model.manual ? `<div class="warn">${icons.warn}<div>Nel file di configurazione queste scelte sono scritte a mano, quindi da qui puoi solo guardarle. Per cambiarle modifica <span class="rl-mono">/etc/zt-shield/shield.yaml</span>.</div></div>` : ''}
          <h3 class="sec">Cosa proteggere</h3>
          ${(model.groups || []).map(groupCard).join('')}
          ${(model.custom || []).length ? `<div class="rl-d">Regole personalizzate nel file di configurazione (non modificabili da qui): ${model.custom.map(esc).join(', ')}.</div>` : ''}
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

    return {
        render,
        // Per i test e per tornare alla vista: forza una nuova lettura del modello.
        reload() { model = null; render(true); },
        isDirty: dirty,
    };
}
