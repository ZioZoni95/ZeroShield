// Nomi leggibili per le protezioni predefinite: nei log e nel config restano quelli tecnici
// (ssh-keys, cloud-creds...), le schermate mostrano questi. Per le regole personali vale il nome scelto.
export const FRIENDLY_RULE = {
    'ssh-keys': 'Chiavi SSH',
    'cloud-creds': 'Kubernetes e cloud',
    'dev-tokens': 'Token degli strumenti di sviluppo',
    'gpg-keys': 'Chiavi GPG',
    'browser-secrets': 'Cookie e password dei browser',
};
export const friendlyRule = n => FRIENDLY_RULE[n] || n;
