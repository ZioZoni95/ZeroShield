# Profilo condiviso: esportare e importare le scelte tra macchine

Dalla 0.0.22 le scelte fatte con la GUI si possono salvare in un file e riprendere su un'altra macchina Linux, per esempio per usare in ufficio una lista comune di programmi autorizzati. È la stessa idea del blocco gestito del config (`docs/` e `README`), reso portabile.

## Come si usa

**Dalla GUI**: Configurazione → *Profilo condiviso*.
- *Esporta…*: scrivi un nome (es. «Ufficio») e, se vuoi, una nota; scegli dove salvare. Sotto compare l'elenco di ciò che **non** è stato esportato e perché.
- *Importa → Scegli un file…*: vedi l'anteprima (cosa si aggiunge, cosa si toglie, cosa cambia), cosa è stato scartato e gli avvisi. Solo con *Importa (chiede la password)* si scrive qualcosa.

**Dal terminale** (l'anteprima non richiede privilegi):
```
zt-shield profile export -name Ufficio -note "pilota" -o ufficio.yaml
zt-shield profile import ufficio.yaml            # solo anteprima, non scrive nulla
zt-shield profile import -yes ufficio.yaml       # applica (password di sistema)
zt-shield profile import -replace -keep-modes -yes ufficio.yaml
```

## Cosa contiene e cosa no

| Contiene | Non contiene mai |
|---|---|
| programmi autorizzati per regola (`allow_extra`) e tolti dalla lista di base (`remove_allow`) | `user` (l'utente protetto) |
| protezioni accese o spente, modalità per protezione (Osserva/Blocca) | `interface` (l'interfaccia di rete) |
| regole personali («Proteggi un mio file») | la sezione `vpn:` (endpoint e dati sensibili) |
| filtro di rete (solo se spento) e canary (solo se acceso, cartelle relative) | percorsi nelle cartelle di un utente: `/home`, `/root`, `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/mnt`, `/media` |
| nome, nota, versione di ZeroShield, profilo di base di origine (solo informativi) | qualsiasi programma che non sia nei percorsi di sistema |

Il file è YAML leggibile (`format: zeroshield-profile`, `version: 1`). **Rileggilo prima di condividerlo**: elenca i nomi dei programmi che usi (es. `oh-my-posh`, `k9s`), e questo è già un'informazione sulla tua macchina.

## Unire o sostituire

- **Unisci** (predefinito): le tue scelte restano, quelle del profilo si aggiungono. Dove i due dicono cose opposte (una protezione accesa da una parte e spenta dall'altra, una modalità diversa) vince il profilo.
- **Sostituisci**: le scelte del profilo prendono il posto delle tue. L'interfaccia di rete resta sempre quella della tua macchina.

Per impostazione l'importazione porta le modalità in **sola osservazione**, anche se nel profilo erano in Blocca: serve per un pilota, dove prima si vede cosa succede e poi si decide di bloccare. Si può togliere la spunta (GUI) o usare `-keep-modes` (terminale).

## Valutazione dei rischi

Una lista di programmi autorizzati è un permesso di leggere i segreti, quindi **importare un profilo è una decisione di sicurezza**. Scelta dichiarata per questa fase alpha: **nessuna firma** del file. I rischi e cosa li limita:

| Rischio | Cosa lo limita oggi | Cosa resta |
|---|---|---|
| Un profilo manomesso autorizza un programma ostile | solo binari **di root** in percorsi di sistema: il demone scarta il resto, e l'importazione lo scarta già in anteprima; i percorsi di utente non entrano mai | un binario di root legittimo ma indesiderato (per esempio un interprete) passerebbe: l'anteprima lo mostra, va letto |
| Importazione per errore | anteprima obbligatoria; password di sistema; conferma con il focus su *Annulla*; sostituire è segnalato in chiaro | chi conferma senza leggere |
| File scambiato fra anteprima e applicazione | l'applicazione ricalcola tutto e rifiuta se l'impronta SHA-256 non è quella vista | — |
| File enorme o malformato | limite di 256 KB, solo file normali, chiavi sconosciute rifiutate, formato e versione controllati, validazione con lo stesso parser del demone | — |
| Una macchina passa a Blocca e si blocca il lavoro (falsi blocchi) | le modalità si importano in sola osservazione per impostazione | chi toglie la spunta |
| Il profilo svela quali strumenti usi | l'elenco di ciò che esce si vede subito; niente utente, VPN, interfaccia | i nomi dei programmi di sistema sono comunque nel file |
| Applicazione che lascia il servizio fermo | stessi backup e ripristino automatico di `config-apply` | — |
| Autenticità: «è davvero il profilo del mio ufficio?» | **nessuna** (niente firma né checksum distribuito) | da risolvere prima di usarlo su molte macchine: firma o checksum pubblicato a parte (vedi `docs/PUNTI_APERTI.md`) |

**Regola pratica**: ricevi il file da un canale che conosci, leggi l'anteprima, importa prima in sola osservazione su una o due macchine.

## Cosa è stato provato e cosa no

- Provato: formato, estrazione, importazione, unione/sostituzione, scarto di percorsi non sicuri, impronta, idempotenza, errori e file ostili (test automatici); riga di comando sul config reale di questa macchina (esportazione e anteprima, senza applicare); interfaccia nel browser con il demone simulato (24 controlli).
- **Non provato**: le finestre native di salvataggio/apertura file nell'app vera; l'applicazione di un profilo importato con `pkexec` su una seconda macchina; la compatibilità fra versioni diverse di ZeroShield (c'è il campo `version`, ma oggi esiste solo la 1).

## Limiti

- Solo scelte della GUI: le chiavi scritte a mano nel config (`allow_extra`, `disable_rules`, `enable_groups`, `interface`...) non si esportano né si importano; con chiavi a mano l'esportazione e l'importazione si rifiutano con lo stesso messaggio della GUI.
- Nessuna distribuzione centrale: il file si porta a mano (o con i vostri strumenti: scp, un repository, Ansible).
- Il profilo di base (`profile:`) non viaggia: se è diverso fra le macchine l'anteprima lo segnala.
