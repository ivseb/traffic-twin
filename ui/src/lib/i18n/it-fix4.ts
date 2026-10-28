// Testi della passata di usabilità 4 (Marco, orders-api): editor di regole senza stati, «Cerca nuove regole» seguita come
// lavoro, preset di guasti, «Simula nel mock» con la classificazione del server, il passo «valori in chiaro» reso
// visibile (chi approva, messaggio da copiare), il comando `tt mock --console`. Tenuti a parte come it-ux.ts.
export const itFix4 = {
  'fix4.loading': 'Sto caricando…',
  'fix4.computing': 'Sto calcolando…',
  'fix4.slow': 'Ci vuole più del solito: il server sta ancora lavorando.',
  'fix4.renderFailed': 'Questa parte della pagina non si è potuta mostrare ({error}).',
  'fix4.renderRetry': 'Riprova',

  // M1 editor di regole
  'fix4.re.loading': 'Sto preparando l’editor: leggo contratti ed entità del gruppo…',
  'fix4.re.noStates':
    'Non ho ancora visto stati degli oggetti: per scrivere regole su stati (un ordine che passa da created a shipped) serve che lo status esca in chiaro. Di norma succede da solo come «codice in chiaro» (code), senza approvazione; solo se il campo ha un nome che non è di uno stato serve un keep, che un’altra persona deve approvare. Intanto puoi scrivere regole che non usano stati: «la prossima chiamata risponde X» oppure «una chiamata su N risponde con un errore».',
  'fix4.re.noStatesLink': 'Fai uscire gli stati in chiaro (Rivedi in blocco › Stati e codici)',
  'fix4.re.noValues': 'Le entità ci sono, ma nessun campo ha valori in chiaro: i valori di stato li scrivi a mano finché lo status non esce in chiaro (di norma come «codice in chiaro», senza approvazione).',
  'fix4.re.batchNeedsEntity': 'Le regole a orario cambiano oggetti: servono entità riconosciute dal miner.',

  // M2 Rivedi in blocco
  'fix4.bulk.loading': 'Sto calcolando i campi del gruppo dal traffico osservato…',

  // M3 Cerca nuove regole
  'fix4.rules.mining.queued': 'Ricerca in coda dietro un altro lavoro pesante ({s} s). La pagina la segue da sola: puoi restare qui.',
  'fix4.rules.mining.running': 'Ricerca in corso da {s} s: con molto traffico servono uno o due minuti. La pagina la segue da sola.',
  'fix4.rules.mining.retrying': 'Il server per un momento non risponde: continuo a seguire la ricerca ({s} s)…',
  'fix4.rules.lastTitle': 'Risultato dell’ultima ricerca ({time})',
  'fix4.rules.noEffect':
    '{op} su {service} crea {entity}, ma nessun ciclo di vita osservato: lo stato degli oggetti non esce dal servizio. Serve che lo status esca in chiaro: di norma basta «codice in chiaro» (code), che si applica senza approvazione; un keep serve solo per i campi che non hanno il nome di uno stato e va approvato.',
  'fix4.rules.noEffectLink': 'Apri Rivedi in blocco › Stati e codici',
  'fix4.rules.failed': 'La ricerca si è fermata con un errore del server ({code}). Riprova; se si ripete, chiedi a un amministratore di guardare i log di tt-core.',

  // M4 preset di guasti
  'fix4.sc.deterministicHint': 'I guasti che aggiungi qui sotto scattano sempre: l’interruttore spegne solo quelli casuali copiati dal traffico.',
  'fix4.sc.status': 'Status HTTP',
  'fix4.sc.p': 'Probabilità (0–1)',
  'fix4.sc.legacyOff': 'Salvato da una versione precedente della console: i guasti di questo preset non scattano. Aprilo e salvalo di nuovo.',

  // M5 Simula questo host nel mock
  'fix4.twin.note':
    'Nasce una nuova versione della policy che aggiunge questo host come servizio esterno. Se non apre valori in chiaro si applica subito; se li apre resta una bozza da approvare. Prima di confermare ti dico cosa risponde il server.',
  'fix4.twin.check': 'Controlla cosa cambia',
  'fix4.twin.confirm': 'Conferma e crea',
  'fix4.twin.checking': 'Chiedo al server come si applica la modifica…',
  'fix4.twin.safe': 'Il server dice: questa modifica non apre valori in chiaro e si applica subito, senza approvazioni.',
  'fix4.twin.opens': 'Il server dice: questa modifica apre valori in chiaro, servono {n, plural, one {# approvazione} other {# approvazioni di persone diverse}}. Finché non è approvata le sorgenti non cambiano comportamento.',
  'fix4.twin.unknown': 'Il server non sa ancora classificare la modifica (l’assistente non ha visto questo host): lo dirà appena la crei.',
  'fix4.twin.applied': 'Applicata alle {time}: la versione {v} è attiva, non serviva nessuna approvazione.',
  'fix4.twin.waiting': 'Bozza v{v} in attesa: {n} di {total} approvazioni. Finché non è approvata le sorgenti non cambiano comportamento.',
  'fix4.twin.ids': 'Gli identificativi delle risposte del nuovo servizio restano nascosti (drop) finché non diventano sigle (hmac): controllali con Rivedi in blocco › Identificativi.',
  'fix4.twin.idsLink': 'Apri Rivedi in blocco',

  // B1 il passo «valori in chiaro»
  'fix4.next.title': 'Prossimo passo: fai approvare i valori in chiaro',
  'fix4.next.draft': 'La bozza {policy} v{v} del gruppo {group} aspetta {n, plural, one {# approvazione} other {# approvazioni di persone diverse}} (finora {have}).',
  'fix4.next.lose': 'Finché non è approvata:',
  'fix4.next.lose1': 'niente regole con stati (un ordine che passa da created a delivered): il miner non vede cicli di vita;',
  'fix4.next.lose2': 'niente campi collegati nei contratti (macrocategoria → categoria);',
  'fix4.next.lose3': 'il mock risponde con valori finti e statici («synthetic»).',
  'fix4.next.self': 'Hai proposto tu questa bozza: deve approvarla un’altra persona.',
  'fix4.next.message': 'Messaggio per chi approva',
  'fix4.next.copy': 'Copia il messaggio',
  'fix4.next.open': 'Apri la bozza',
  'fix4.next.msgText':
    'Ciao, puoi approvare la bozza di policy {policy} v{v} del gruppo {group} su traffic-twin? Fa uscire in chiaro alcuni campi (keep) e gli importi in fasce (bucket): serve per le regole con stati, i campi collegati e un mock realistico. Link alla bozza: {link}',
  'fix4.appr.adminTag': '(amministratore: approva da solo, con una motivazione)',
  'fix4.appr.none': 'Nessuno può approvare le policy di questo gruppo: chiedi a un amministratore di dare il ruolo Approvatore di policy a qualcuno.',

  // m1 il mock lanciato da te
  'fix4.mk.cli': 'tt (kit)',
  'fix4.mk.cliNote':
    'Con il binario tt del kit, della stessa versione della console ({version}): controlla con «tt version». Metti accanto al comando console-ca.pem, la CA del certificato della console (con un certificato di una CA pubblica togli --console-ca).',
  'fix4.mk.dockerNote': 'L’immagine è della stessa versione della console ({version}). Il comando monta console-ca.pem (la CA del certificato della console) e lo passa con --console-ca.',
  'fix4.mk.tokenPrefix': 'ttm_… è il segreto (va in TT_MOCK_TOKEN, lo vedi una volta sola); mtk-… è solo il suo identificativo, quello dell’elenco qui sotto con cui lo revochi.',

  // m2 filtro Gruppo
  'fix4.scope.mineNone': 'I miei gruppi (ancora nessuno)',
  'fix4.scope.noneNote': 'Non lavori ancora con nessun gruppo (nessun token creato, nessuna policy proposta): le liste mostrano i dati di tutti i team, la Panoramica conta solo i tuoi.',
  'fix4.home.noGroups': 'Non hai ancora collegato un servizio: la Panoramica conta solo i gruppi con cui lavori. Comincia da Collega.',

  // m4 preparazione del mock
  'fix4.prep.last': 'Ultima preparazione del gruppo {group}, avviata alle {time}:',

  // m5 / m6 wizard
  'fix4.wiz.capturing': 'La cattura è già attiva con la policy v{v}: le bozze qui sotto servono solo a far uscire valori in chiaro.',
  'fix4.wiz.pickGroup': 'Per aprire l’assistente policy serve il gruppo: scegline uno in fondo a questa pagina («Riprendi un gruppo»), oppure collega un servizio nuovo.',
  'fix4.wiz.stepLoading': 'Sto aprendo l’assistente policy del gruppo {group}…',
  'fix4.wiz.stepFailed': 'Non riesco ad aprire questo passo.',
  'fix4.wiz.backStart': 'Torna all’inizio',

  // estetica
  'fix4.cs.downloadJson': 'Scarica JSON',
  'fix4.cs.downloadYaml': 'Scarica YAML',
  'fix4.cs.show': 'Mostra {f}',
  'fix4.src.draftsBadge': 'bozze in attesa',
  'fix4.pub.risk.how': 'Come leggere questi numeri',
  'fix4.pub.risk.explain':
    'Sono misure sui profili reali da cui nascono gli archetipi: non fanno parte del pacchetto, che contiene solo dati sintetici. Ogni archetipo raggruppa almeno k persone («Archetipo più piccolo»): il controllo delle soglie k del gate blocca il pacchetto se un gruppo è più piccolo.',
  'fix4.pub.risk.exactHint': 'quota di profili reali identici al profilo tipo del loro archetipo. Al 100% con pochi archetipi vuol dire che i clienti si comportano quasi tutti allo stesso modo (normale con un carico di prova): l’archetipo descrive tutti, ma ognuno resta in mezzo ad almeno k persone.',
  'fix4.pub.risk.homogeneityHint': 'nell’archetipo più uniforme, la quota di membri con lo stesso profilo. Al 100% sapere che una persona è in quell’archetipo dice tutto il suo comportamento (aggregato), non chi è.',
  'fix4.pub.risk.uniqueHint': 'quote di profili unici prima del raggruppamento e di archetipi che corrispondono a una sola persona reale: sono questi i numeri che devono restare bassi.',
} as const;

export type Fix4Key = keyof typeof itFix4;
