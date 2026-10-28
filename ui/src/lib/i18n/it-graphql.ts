// Testi delle operazioni e degli schemi GraphQL (pagina del contratto di un servizio). Tenuti a parte come it-ux.ts.
export const itGraphql = {
  'gql.badge': 'GraphQL',
  'gql.anonymous': '(anonima)',
  'gql.title': 'Operazione GraphQL',
  'gql.subtitle': 'Un servizio GraphQL ha un solo indirizzo ({method} {endpoint}); ogni operazione che i client chiamano lì diventa un’operazione del contratto, con le sue variabili e la sua risposta.',
  'gql.kind': 'Tipo',
  'gql.name': 'Nome',
  'gql.anonymousNote': 'Il client non dà un nome a questa operazione: traffic-twin la riconosce dalla forma del documento (il codice dopo ~).',
  'gql.document': 'Documento osservato',
  'gql.documentNote': 'È la forma del documento: nomi di campi, argomenti e tipi. I valori scritti dentro la query sono diventati ?s (testo), ?i (intero), ?f (decimale), ?b (vero/falso), ?n (null), ?e (valore di enum): la sorgente non li manda mai.',
  'gql.variables': 'Variabili',
  'gql.noVariables': 'Nessuna variabile: gli argomenti, se ci sono, sono scritti nel documento.',
  'gql.fields': 'Campi della risposta: {fields}',
  'gql.introspection': 'È la richiesta di introspezione (lo schema del servizio): il mock risponde con lo schema catturato o con uno ricostruito dalle operazioni.',
  'gql.tab': 'GraphQL',
  'gql.schemaTitle': 'Schema GraphQL',
  'gql.schemaCaptured': 'Schema catturato dall’introspezione di {endpoint} il {date}: solo nomi e tipi, senza descrizioni. Il mock lo usa per rispondere ai client che lo chiedono (per esempio un gateway che fa schema stitching).',
  'gql.schemaMissing': 'Nessuna introspezione catturata: il mock ricostruisce uno schema dalle operazioni osservate. Per avere quello vero basta che il client chieda lo schema mentre la sorgente è attiva (succede all’avvio di un gateway).',
  'gql.operationsTitle': 'Operazioni osservate',
  'gql.operationsHint': 'Le operazioni GraphQL che i client hanno chiamato, nella forma in cui sono arrivate a traffic-twin (senza valori).',
  'gql.download': 'Scarica lo schema (.graphql)',
  'soap.subtitle': 'Operazione SOAP dell’indirizzo {method} {endpoint}: il client la sceglie con SOAPAction o con il primo elemento del Body. I corpi sono alberi XML: @nome è un attributo, #text il testo, una lista sono elementi ripetuti.',
  'soap.mockNote': 'Il mock risponde anche ai servizi SOAP e XML: sceglie l’operazione da SOAPAction o dal primo elemento del Body, risponde con la stessa busta e gli stessi spazi dei nomi e trasforma i guasti in SOAP Fault.',
} as const;

export type GraphqlKey = keyof typeof itGraphql;
