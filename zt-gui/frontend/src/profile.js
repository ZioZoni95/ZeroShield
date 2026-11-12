// «Profilo condiviso» (pagina Configurazione): esporta le scelte della GUI in un file e importa quello di un'altra
// macchina (per esempio, la configurazione comune dell'ufficio).
//
// L'importazione non scrive mai da sola: mostra prima cosa cambierebbe (anteprima calcolata dal demone-lato Go con
// gli stessi controlli di sempre), scarta i programmi non di root, per impostazione porta le modalita' in sola
// osservazione e applica solo il file che si e' visto (impronta SHA-256). Applicare = password di sistema.

const SIGN = {add: '+', remove: '−', change: '~'};

export function createProfileView(d) {
    const {esc, api, toast, confirmDialog, onApplied} = d;
    let box = null;
    let name = '', note = '';          // campi dell'esportazione (si conservano fra un disegno e l'altro)
    let exported = null;               // esito dell'ultima esportazione
    let path = '', pv = null, err = '';  // file scelto, anteprima, errore
    let replace = false, audit = true; // opzioni di importazione
    let busy = '';

    function mount(el) { box = el; paint(); }

    function msg(e) { return String((e && e.message) || e || 'errore sconosciuto'); }

    async function doExport() {
        busy = 'export'; paint();
        try {
            exported = await api.ExportProfile(name.trim(), note.trim());
            if (exported && exported.cancelled) { exported = null; }
            else toast('Profilo salvato');
        } catch (e) { exported = null; toast('Esportazione non riuscita: ' + msg(e), true); }
        busy = ''; paint();
    }

    async function preview() {
        busy = 'preview'; err = ''; paint();
        try { pv = await api.PreviewProfile(path, replace, audit); }
        catch (e) { pv = null; err = msg(e); }
        busy = ''; paint();
    }

    async function pick() {
        let p = '';
        try { p = await api.ChooseProfile(); } catch (e) { toast('Non riesco ad aprire il selettore: ' + msg(e), true); return; }
        if (!p) return;
        path = p; await preview();
    }

    function reset() { path = ''; pv = null; err = ''; replace = false; audit = true; paint(); }

    async function apply() {
        if (!pv || pv.unchanged) return;
        const n = (pv.changes || []).length;
        const ok = await confirmDialog({
            title: 'Importare il profilo?',
            body: `Si applicano <b>${n}</b> cambiament${n === 1 ? 'o' : 'i'}${replace ? ' e si <b>sostituiscono</b> le tue scelte attuali' : ''}. Il servizio si riavvia (password di sistema); se non riparte si torna alla configurazione di prima.`,
            ok: 'Importa', danger: replace,
        });
        if (!ok) return;
        busy = 'apply'; paint();
        try {
            await api.ApplyProfile(path, pv.sha256, replace, audit);
            toast('Profilo importato');
            path = ''; pv = null; err = ''; busy = ''; paint();
            if (onApplied) onApplied();
            return;
        } catch (e) { toast('Importazione non riuscita: ' + msg(e), true); }
        busy = ''; paint();
    }

    function exportHtml() {
        const left = (exported && exported.left) || [];
        return `<div class="panel pf-card">
          <div class="pf-t">Esporta le tue scelte</div>
          <p class="sub">Salva in un file i programmi autorizzati, le protezioni, le modalità, le regole personali, il filtro di rete e il canary. Non contiene il tuo utente, l'interfaccia di rete, la VPN né programmi nelle tue cartelle.</p>
          <div class="pf-row"><input id="pf-name" placeholder="Nome (es. Ufficio)" maxlength="80" value="${esc(name)}" aria-label="Nome del profilo">
            <input id="pf-note" placeholder="Nota (facoltativa)" maxlength="2000" value="${esc(note)}" aria-label="Nota"></div>
          <div class="pf-row"><button class="rl-btn" id="pf-export"${busy ? ' disabled' : ''}>${busy === 'export' ? '…' : 'Esporta…'}</button></div>
          ${exported ? `<div class="pf-ok">Salvato in <span class="mono">${esc(exported.path)}</span></div>` : ''}
          ${left.length ? `<details class="rl-det" open><summary>${left.length} cos${left.length === 1 ? 'a è rimasta' : 'e sono rimaste'} fuori</summary><ul class="pf-list">${left.map(l => `<li class="pf-skip"><span class="pf-s">✗</span> ${esc(l)}</li>`).join('')}</ul></details>` : ''}
        </div>`;
    }

    function previewHtml() {
        if (busy === 'preview') return '<div class="rl-d">Controllo il profilo…</div>';
        if (err) return `<div class="warn" id="pf-err"><div>${esc(err)}</div></div><div class="pf-row"><button class="chip" id="pf-cancel">Chiudi</button></div>`;
        if (!pv) return '';
        const ch = pv.changes || [], sk = pv.skipped || [], wr = pv.warnings || [];
        const head = `<div class="pf-head"><b>${esc(pv.name || '(senza nome)')}</b>${pv.exported_by ? ` <span class="rl-d">· creato con ZeroShield ${esc(pv.exported_by)}</span>` : ''}
          <div class="rl-d mono" title="${esc(pv.sha256)}">impronta ${esc(String(pv.sha256 || '').slice(0, 16))}…</div>${pv.note ? `<div class="rl-d">${esc(pv.note)}</div>` : ''}</div>`;
        const opts = `<div class="pf-opts">
          <label><input type="checkbox" id="pf-audit"${audit ? ' checked' : ''}> Importa le modalità in sola osservazione <span class="rl-d">(consigliato per iniziare: nulla viene bloccato)</span></label>
          <label><input type="checkbox" id="pf-replace"${replace ? ' checked' : ''}> Sostituisci le mie scelte invece di unirle</label></div>`;
        const list = pv.unchanged
            ? '<div class="pf-ok" id="pf-same">Nessuna differenza: questo computer ha già queste scelte.</div>'
            : `<div class="pf-sub">Cosa cambierebbe</div><ul class="pf-list" id="pf-changes">${ch.map(c => `<li class="pf-${esc(c.kind)}"><span class="pf-s">${SIGN[c.kind] || '~'}</span> ${esc(c.text)}</li>`).join('')}</ul>`;
        const skipped = sk.length ? `<div class="pf-sub">Non importato</div><ul class="pf-list" id="pf-skipped">${sk.map(s => `<li class="pf-skip"><span class="pf-s">✗</span> ${esc(s)}</li>`).join('')}</ul>` : '';
        const warns = wr.length ? `<div class="pf-sub">Da sapere</div><ul class="pf-list" id="pf-warns">${wr.map(s => `<li class="pf-warn"><span class="pf-s">!</span> ${esc(s)}</li>`).join('')}</ul>` : '';
        const risk = pv.unchanged ? '' : '<p class="rl-d">Controlla l’elenco: ogni programma «autorizzato» potrà leggere quel segreto. Importa solo profili di cui ti fidi.</p>';
        return `${head}${opts}${list}${skipped}${warns}${risk}
          <div class="pf-row"><button class="rl-btn" id="pf-apply"${pv.unchanged || busy ? ' disabled' : ''}>${busy === 'apply' ? '…' : 'Importa (chiede la password)'}</button>
          <button class="chip" id="pf-cancel">Annulla</button></div>`;
    }

    function importHtml() {
        return `<div class="panel pf-card">
          <div class="pf-t">Importa un profilo</div>
          <p class="sub">Per usare le scelte di un altro computer, per esempio quelle comuni dell'ufficio. Prima vedi cosa cambierebbe: finché non confermi non viene scritto niente.</p>
          ${path ? '' : `<div class="pf-row"><button class="rl-btn" id="pf-pick"${busy ? ' disabled' : ''}>Scegli un file…</button></div>`}
          ${path ? `<div class="rl-d">File: <span class="mono">${esc(path)}</span></div>` : ''}
          ${previewHtml()}
        </div>`;
    }

    function paint() {
        if (!box || !box.isConnected) return;
        box.innerHTML = `<h3 class="sec">Profilo condiviso</h3>${exportHtml()}${importHtml()}`;
        const $ = id => box.querySelector('#' + id);
        const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
        on('pf-name', 'input', e => { name = e.target.value; });
        on('pf-note', 'input', e => { note = e.target.value; });
        on('pf-export', 'click', doExport);
        on('pf-pick', 'click', pick);
        on('pf-cancel', 'click', reset);
        on('pf-apply', 'click', apply);
        on('pf-audit', 'change', e => { audit = e.target.checked; preview(); });
        on('pf-replace', 'change', e => { replace = e.target.checked; preview(); });
    }

    return {mount};
}
