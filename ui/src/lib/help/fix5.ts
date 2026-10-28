import type { FieldHelp } from './types';

// Help of the controls added by usability pass 5 (it-fix5.ts). Merged into the help packs by index.svelte.ts.

export const fix5FieldsIt: Record<string, FieldHelp> = {
  'policy.withdraw': {
    title: 'Ritira bozza',
    meaning: 'Toglie dalla coda delle approvazioni una bozza di policy che non ha ancora raggiunto il numero di approvazioni. La ritira chi l’ha proposta o un amministratore.',
    effect: 'La bozza non diventa mai attiva e le approvazioni già date vanno perse. La policy attiva non cambia e i pacchetti non cambiano. Resta nell’audit. Puoi proporne una nuova, anche più stretta.',
    when: 'Quando hai proposto più campi del necessario, hai cambiato idea, o nessuno può approvare e non vuoi lasciarla ferma.',
    term: 'opens-values',
  },
  'rule.retire': {
    title: 'Ritira regola',
    meaning: 'Toglie una regola approvata dai pacchetti: dal prossimo «Prepara e avvia il mock» il mock non applica più i suoi effetti. Serve il ruolo Revisore regole (o amministratore).',
    effect: 'La regola resta nell’elenco come Ritirata e il miner non la ripropone uguale. Non si cancella nulla; per averla di nuovo scrivi o approvi una nuova regola.',
    when: 'Quando una regola nuova ne sostituisce una vecchia (restano approvate tutte e due e gli effetti si sommano), o quando una regola non descrive più il servizio.',
  },
  'obs.bulk.field': {
    title: 'Campo per campo',
    meaning: 'Ogni riga è un campo con una casella. L’azione scelta per il gruppo vale per i campi spuntati; toglila ai campi che non vuoi cambiare. Su ogni riga vedi cosa fa la policy ora, la proposta dell’assistente e cosa diventa.',
    effect: 'Un campo che è già «codice in chiaro» non diventa mai keep da qui: keep farebbe uscire qualsiasi valore e chiederebbe approvazioni. Il conto «aprono valori» include solo i campi che davvero lasciano uscire valori in chiaro.',
    term: 'opens-values',
  },
  'obs.bulk.approvals': {
    title: 'Quante approvazioni e chi le dà',
    meaning: 'Prima di inviare la bozza vedi quante approvazioni servono e chi può darle: le persone con il ruolo Approvatore di policy, che non siano tu.',
    effect: 'Se le persone sono meno delle approvazioni richieste la bozza resta in attesa: un amministratore può approvare da solo, con una motivazione che resta nell’audit. Puoi sempre ritirare la bozza.',
    term: 'opens-values',
  },
  're.partial': {
    title: 'Comincia con quello che c’è',
    meaning: 'L’editor aspetta dal server contratti, entità e valori di stato. Se ci mette troppo puoi cominciare con servizi, operazioni e status dei contratti già letti.',
    effect: 'Entità e valori di stato compaiono da soli quando il server finisce. Quello che hai scritto non si perde.',
  },
  'mock.prepare.resume': {
    title: 'Preparazione che riprende',
    meaning: 'La preparazione del mock gira sul server: se lasci la pagina continua. Tornando qui la console riprende il lavoro per numero di job e mostra di nuovo i passi.',
    effect: 'Il pulsante «Prepara e avvia il mock» resta spento finché quel lavoro è in corso, così non ne parte un secondo.',
  },
  'hosts.counters': {
    title: 'Contatori degli host',
    meaning: 'Domini e host distinti che i servizi chiamano. Un host dichiarato conta una volta sola, anche se prima della dichiarazione compariva con un altro nome.',
    effect: 'Gli indirizzi IP (ip:private, ip:public) contano come host, non come domini.',
  },
  'status.withdrawn': { title: 'Ritirata', meaning: 'Una bozza di policy che chi l’ha proposta, o un amministratore, ha tolto prima che fosse approvata.', effect: 'Non diventa mai attiva. La policy attiva non è cambiata.' },
  'status.retired': { title: 'Ritirata', meaning: 'Una regola approvata che un revisore ha tolto dai pacchetti, o che una regola più nuova ha sostituito.', effect: 'Il mock non applica più i suoi effetti dal prossimo «Prepara e avvia il mock». Resta nell’elenco; il miner non la ripropone uguale.' },
};

export const fix5FieldsEn: Record<string, FieldHelp> = {
  'policy.withdraw': {
    title: 'Withdraw draft',
    meaning: 'Takes out of the approval queue a policy draft that has not reached the number of approvals yet. Whoever proposed it, or an administrator, withdraws it.',
    effect: 'The draft never becomes active and the approvals already given are lost. The active policy and the packs do not change. It stays in the audit. You can propose a new one, even a narrower one.',
    when: 'When you proposed more fields than needed, changed your mind, or nobody can approve and you do not want to leave it stuck.',
    term: 'opens-values',
  },
  'rule.retire': {
    title: 'Retire rule',
    meaning: 'Takes an approved rule out of the packs: from the next “Prepare and start the mock” the mock no longer applies its effects. It needs the Rule reviewer role (or administrator).',
    effect: 'The rule stays in the list as Retired and the miner does not propose it again unchanged. Nothing is deleted; to have it back you write or approve a new rule.',
    when: 'When a new rule replaces an old one (both stay approved and their effects add up), or when a rule no longer describes the service.',
  },
  'obs.bulk.field': {
    title: 'Field by field',
    meaning: 'Each row is a field with a box. The action chosen for the group applies to the ticked fields; untick the ones you do not want to change. On each row you see what the policy does now, the assistant’s proposal and what it becomes.',
    effect: 'A field that already is “code in clear” never becomes keep from here: keep would let any value out and ask for approvals. The “open values” count includes only the fields that really let values out in clear.',
    term: 'opens-values',
  },
  'obs.bulk.approvals': {
    title: 'How many approvals and who gives them',
    meaning: 'Before sending the draft you see how many approvals are needed and who can give them: the people with the Policy approver role, other than you.',
    effect: 'If there are fewer people than approvals required the draft waits: an administrator can approve alone, with a reason that stays in the audit. You can always withdraw the draft.',
    term: 'opens-values',
  },
  're.partial': {
    title: 'Start with what is there',
    meaning: 'The editor waits for the contracts, entities and state values from the server. If it takes too long you can start with the services, operations and statuses of the contracts already read.',
    effect: 'Entities and state values appear by themselves when the server finishes. What you wrote is not lost.',
  },
  'mock.prepare.resume': {
    title: 'Preparation that resumes',
    meaning: 'The preparation of the mock runs in the server: if you leave the page it goes on. Coming back the console picks the work up by job number and shows the steps again.',
    effect: 'The “Prepare and start the mock” button stays off while that job runs, so a second one does not start.',
  },
  'hosts.counters': {
    title: 'Host counters',
    meaning: 'Distinct domains and hosts the services call. A declared host counts once, even if before the declaration it showed up under another name.',
    effect: 'IP addresses (ip:private, ip:public) count as hosts, not as domains.',
  },
  'status.withdrawn': { title: 'Withdrawn', meaning: 'A policy draft that whoever proposed it, or an administrator, took back before it was approved.', effect: 'It never becomes active. The active policy did not change.' },
  'status.retired': { title: 'Retired', meaning: 'An approved rule that a reviewer took out of the packs, or that a newer rule replaced.', effect: 'The mock no longer applies its effects from the next “Prepare and start the mock”. It stays in the list; the miner does not propose it again unchanged.' },
};
