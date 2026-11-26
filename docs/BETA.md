# Verso la beta

La versione resta **alpha** (nessun tag `beta`) finché i bloccanti non sono chiusi. Il collaudo si fa su un PC reale
(scelta del 2026-11-26): senza snapshot, quindi solo prove su file finti o reversibili.

## Bloccanti

- [ ] `scripts/collaudo_hooks.sh` tutto verde, con e senza `deny_write`
- [ ] «Annulla hardening» provato dal vivo
- [ ] Installazione da zero, aggiornamento e disinstallazione su un secondo PC o VM usa e getta
- [ ] Ritorno in «Solo osserva» provato con GUI chiusa o demone in errore
- [ ] Due o tre settimane in enforce senza riavvii anomali né falsi blocchi, sospensione compresa

## Prova di un'altra persona

Dare solo il `.deb` e il [README](../README.md), senza aiutare. Annotare dove si ferma:

1. installazione del pacchetto e primo avvio (kernel senza `bpf` in `lsm=`: il messaggio si capisce?);
2. apre la GUI e capisce se è protetto o no;
3. passa un giorno in «Solo osserva» e autorizza un programma segnalato;
4. passa in «Blocca» e torna indietro;
5. applica l'hardening (anteprima), controlla rete e VPN, poi «Annulla hardening»;
6. disinstalla: la rete e i suoi file sono come prima?

## Tag

`v0.1.0-beta` solo a bloccanti chiusi e su richiesta esplicita.
