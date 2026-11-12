# Audit delle connessioni in uscita (0.0.20)

**Cosa fa.** Segnala quando un programma che ha appena letto un tuo segreto si collega a una destinazione di rete:
«`python3` ha letto `ssh-keys` e poi si è collegato a `203.0.113.9:443`». È il registro che manca per accorgersi
di un'esfiltrazione, ed è la risposta alla domanda «il radar dovrebbe rilevare gli invii di dati?»: il radar guarda il traffico
**in ingresso** (XDP), questa funzione guarda quello **in uscita** dei soli programmi che toccano i segreti.

**Cosa NON fa.**
- **Non blocca mai** una connessione: restituisce sempre 0. Non è un firewall in uscita.
- **Non vede il contenuto** (traffico cifrato) né quanti byte escono: solo programma, regola e destinazione.
- **Segue i processi, non i figli**: un `git` che lancia `ssh` è un altro processo e non risulta.
- Un programma si segue per **60 secondi** dopo l'ultima lettura di un segreto.

## Come funziona

1. Quando un programma **autorizzato** legge un file protetto (o, in audit, uno non autorizzato), il kernel lo ricorda per 60 s
   (mappa `touched`: tgid → regola, ora). Si passa da qui solo per i file protetti: il percorso caldo degli altri `open` non cambia.
2. L'hook `lsm/socket_connect` guarda quella mappa a ogni `connect()`. Se il processo è «sospetto» e la destinazione è IPv4/IPv6 non loopback (dal demone, `0.0.0.0` e `::` si scartano: connettersi a 0.0.0.0 significa connettersi a localhost),
   scrive un evento in un ring buffer dedicato (`egress_logs`).
3. Il demone segnala **solo la prima volta** che compare la coppia (programma, destinazione): un `kubectl get pods` ripetuto non riempie il registro.
   Tetto di 20 eventi al secondo.
4. Ogni evento ha un **ambito**: `lan` (indirizzi privati, link-local) o `internet`. In GUI → Eventi, filtro **uscita**: Internet è in evidenza.

È un **hook opzionale**: se il kernel non lo ha o il verifier lo rifiuta, lo scudo parte lo stesso e lo dice nel journal.

## Come si legge

```text
📤 [USCITA] regola=ssh-keys PID=7001 comm='python3' exe=/usr/bin/python3.12 → 203.0.113.9:443 (internet, nuova destinazione)
```

- `kubectl → 10.209.4.1:6443 (lan)` dopo `cloud-creds`: normale, è il tuo cluster.
- `python3 → 203.0.113.9:443 (internet)` dopo `ssh-keys`: **da guardare**. Chi ha lanciato quel python? Controlla l'albero dei processi e gli eventi vicini.

## Rumore atteso

Programmi che leggono un segreto per mestiere e poi parlano in rete (`git` verso GitLab, `docker` verso un registry, `aws`) compaiono **una volta** per
destinazione, poi basta. Il rumore vero è la lista delle destinazioni: una destinazione mai vista per quel programma è l'informazione utile.

## Limiti e cose da collaudare (VM)

- Mai provato su un kernel reale: compila, passa il verifier in CI, non è stato visto scattare. Vedi `docs/COLLAUDO_HARDENING.md`, sezione 7.
- I figli di un processo non sono seguiti (limite strutturale della mappa per tgid).
- Un programma che legge il segreto **prima** dell'avvio del demone, o via un fd ereditato, non è seguito.
