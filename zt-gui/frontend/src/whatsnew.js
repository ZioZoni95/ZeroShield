// Novità per versione, mostrate in un popup al primo avvio dopo un aggiornamento.
//
// REGOLA: a ogni versione che si rilascia si aggiunge qui la voce (la chiave e' la versione senza
// il suffisso ~dev+commit). Un test controlla che il file VERSION abbia la sua voce: senza, chi
// aggiorna non vedrebbe cosa e' cambiato. Il testo e' per chi non conosce il progetto: cosa puoi
// fare ora, non cosa e' stato modificato nel codice.
export const WHATS_NEW = {
    '0.0.5': {
        title: 'Novità della versione 0.0.5',
        items: [
            ['Una modalità per ogni protezione', 'Non devi più scegliere tutto o niente: metti in Blocca le chiavi SSH e lascia il resto in sola osservazione, e passa alle altre quando sei pronto.'],
            ['Proteggi un tuo file', 'Scegli un file o una cartella (anche con *.kdbx), vedi quanti file protegge prima di salvare e decidi quali programmi possono usarli.'],
            ['Togli programmi dalle liste', 'Ogni protezione ti fa togliere (e rimettere) i programmi autorizzati di base, non solo aggiungerne.'],
            ['Una nuova pagina Stato', 'Una frase sul tuo stato, un solo pulsante con la cosa da fare adesso, una lista «Da fare» e gli ultimi eventi in italiano. I dettagli tecnici sono ripiegati.'],
            ['Avviso sulle versioni', 'Se il demone e la finestra sono di versioni diverse dopo un aggiornamento, lo vedi subito nello Stato.'],
        ],
        note: 'Le modalità per protezione richiedono il demone nuovo: dopo l\'aggiornamento riavvia il servizio. ZeroShield resta in alpha.',
    },
    '0.0.4': {
        title: 'Novità della versione 0.0.4',
        items: [
            ['Icona nella barra di sistema', 'Verde se sei protetto, gialla in audit, rossa se il demone è spento. Parte da sola al login e ti avvisa anche a finestra chiusa.'],
            ['Regole guidate, senza file da scrivere', 'Nella scheda Regole scegli cosa proteggere e autorizzi i programmi che usi (k3d, helm, k9s, oh-my-posh…). Un indicatore ti dice quando sei pronto per Enforce.'],
            ['Radar più chiaro', 'Distingue il rumore normale di rete da ciò che va verificato, con la spiegazione e i comandi per controllare.'],
            ['Schermate riordinate', 'Stato con verdetto in cima, Configurazione a sezioni, scorciatoie da tastiera 1–7, orari nel tuo fuso.'],
            ['Un solo pacchetto', 'Demone, terminale, finestra e icona stanno in un unico .deb.'],
        ],
        note: 'ZeroShield è ancora in alpha: lascialo in Audit finché non hai controllato che i tuoi programmi risultino autorizzati.',
    },
};

// "0.0.4~dev+abc123" -> "0.0.4"; "v0.1.0" -> "0.1.0".
export function baseVersion(v) {
    return String(v || '').replace(/^v/, '').split(/[~+-]/)[0];
}

// Decide se mostrare le novita'. lastSeen: ultima versione di cui l'utente le ha viste ('' = mai).
// Prima installazione (mai visto nulla e mai fatto l'onboarding): niente popup, ci pensa il
// benvenuto; si segna solo la versione. Chi aveva gia' la GUI prima di questa funzione le vede.
export function pickWhatsNew(version, lastSeen, onboarded) {
    const base = baseVersion(version);
    const entry = WHATS_NEW[base];
    if (!base || lastSeen === base) return {show: null, remember: false};
    if (!lastSeen && !onboarded) return {show: null, remember: true, base};
    return {show: entry || null, remember: true, base};
}
