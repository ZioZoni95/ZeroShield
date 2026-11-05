// Novità per versione, mostrate in un popup al primo avvio dopo un aggiornamento.
//
// REGOLA: a ogni versione che si rilascia si aggiunge qui la voce (la chiave e' la versione senza
// il suffisso ~dev+commit). Un test controlla che il file VERSION abbia la sua voce: senza, chi
// aggiorna non vedrebbe cosa e' cambiato. Il testo e' per chi non conosce il progetto: cosa puoi
// fare ora, non cosa e' stato modificato nel codice.
export const WHATS_NEW = {
    '0.0.8': {
        title: 'Novità della versione 0.0.8',
        items: [
            ['Il filtro segue la rete, senza riavviare', 'Se colleghi un adattatore USB, accendi il Wi-Fi o ricolleghi un cavo mentre ZeroShield è in funzione, viene filtrato da solo nel giro di un paio di secondi. Prima restava scoperto fino al riavvio.'],
            ['Automatica ora protegge di più', 'In modalità automatica il filtro copre tutte le reti fisiche accese (cavo, USB, Wi-Fi) e quella in uso, non solo quella con cui hai avviato il servizio.'],
            ['Interfacce scelte ma non collegate', 'Se scegli un adattatore USB e lo scolleghi, resta nell\'elenco e si aggancia da solo quando lo rimetti.'],
        ],
        note: 'Serve il demone nuovo: dopo l\'aggiornamento riavvia il servizio.',
    },
    '0.0.7': {
        title: 'Novità della versione 0.0.7',
        items: [
            ['Scegli le interfacce da proteggere', 'Nella scheda Rete vedi cavo, USB, Wi-Fi e VPN, quali sono filtrate e quali no, e scegli tu: anche il Wi-Fi spento ora, così è già coperto quando lo accendi.'],
            ['Meno avvisi inutili', 'Il log non elenca più decine di interfacce di container e bridge: ti avvisa solo se una rete fisica o una VPN è accesa e non filtrata.'],
        ],
        note: 'La scelta delle interfacce richiede il demone nuovo: dopo l\'aggiornamento riavvia il servizio.',
    },
    '0.0.6': {
        title: 'Novità della versione 0.0.6',
        items: [
            ['Applica chiede di nuovo la password', 'Se aprivi la finestra dall\'icona nella barra, Applica, Installa e il cambio modalità fallivano con «pkexec must be setuid root». Ora funzionano.'],
        ],
        note: 'Per aggiornare anche l\'icona: systemctl --user restart zeroshield-tray, poi riapri la finestra.',
    },
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

// Confronto numerico X.Y.Z (le stringhe "0.0.10" e "0.0.9" non si ordinano bene alfabeticamente).
export function cmpVersion(a, b) {
    const pa = baseVersion(a).split('.').map(n => parseInt(n, 10) || 0), pb = baseVersion(b).split('.').map(n => parseInt(n, 10) || 0);
    for (let i = 0; i < 3; i++) { if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0); }
    return 0;
}

// Le voci da mostrare: tutte quelle piu' nuove dell'ultima versione vista, fino a quella in uso (la piu'
// recente per prima). Chi salta una versione (0.0.4 -> 0.0.6) non perde le novita' di quella di mezzo.
export function entriesSince(version, lastSeen) {
    const cur = baseVersion(version);
    return Object.keys(WHATS_NEW)
        .filter(v => cmpVersion(v, cur) <= 0 && (!lastSeen || cmpVersion(v, lastSeen) > 0))
        .sort((a, b) => cmpVersion(b, a))
        .map(v => [v, WHATS_NEW[v]]);
}

// Decide se mostrare le novita'. lastSeen: ultima versione di cui l'utente le ha viste ('' = mai).
// Prima installazione (mai visto nulla e mai fatto l'onboarding): niente popup, ci pensa il
// benvenuto; si segna solo la versione. Chi aveva gia' la GUI prima di questa funzione vede la voce corrente.
export function pickWhatsNew(version, lastSeen, onboarded) {
    const base = baseVersion(version);
    if (!base || lastSeen === base) return {show: null, remember: false};
    if (!lastSeen && !onboarded) return {show: null, remember: true, base};
    const list = lastSeen ? entriesSince(version, lastSeen) : (WHATS_NEW[base] ? [[base, WHATS_NEW[base]]] : []);
    return {show: list.length ? list : null, remember: true, base};
}
