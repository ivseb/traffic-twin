import type { GraphqlKey } from './it-graphql';

// English texts of the GraphQL operations and schemas (see it-graphql.ts).
export const enGraphql: Record<GraphqlKey, string> = {
  'gql.badge': 'GraphQL',
  'gql.anonymous': '(anonymous)',
  'gql.title': 'GraphQL operation',
  'gql.subtitle': 'A GraphQL service has a single address ({method} {endpoint}); every operation the clients call there becomes an operation of the contract, with its variables and its response.',
  'gql.kind': 'Kind',
  'gql.name': 'Name',
  'gql.anonymousNote': 'The client does not name this operation: traffic-twin recognises it by the shape of the document (the code after ~).',
  'gql.document': 'Observed document',
  'gql.documentNote': 'This is the shape of the document: names of fields, arguments and types. The values written inside the query became ?s (text), ?i (integer), ?f (decimal), ?b (true/false), ?n (null), ?e (enum value): the source never sends them.',
  'gql.variables': 'Variables',
  'gql.noVariables': 'No variables: the arguments, if any, are written in the document.',
  'gql.fields': 'Response fields: {fields}',
  'gql.introspection': 'This is the introspection request (the schema of the service): the mock answers with the captured schema or with one rebuilt from the operations.',
  'gql.tab': 'GraphQL',
  'gql.schemaTitle': 'GraphQL schema',
  'gql.schemaCaptured': 'Schema captured from the introspection of {endpoint} on {date}: names and types only, no descriptions. The mock uses it to answer the clients that ask for it (for instance a gateway doing schema stitching).',
  'gql.schemaMissing': 'No introspection captured: the mock rebuilds a schema from the observed operations. To get the real one, a client only has to ask for the schema while the source is active (a gateway does it when it starts).',
  'gql.operationsTitle': 'Observed operations',
  'gql.operationsHint': 'The GraphQL operations the clients called, in the shape they reached traffic-twin (without values).',
  'gql.download': 'Download the schema (.graphql)',
  'soap.subtitle': 'SOAP operation of the address {method} {endpoint}: the client picks it with SOAPAction or with the first element of the Body. The bodies are XML trees: @name is an attribute, #text the text, a list is repeated elements.',
  'soap.mockNote': 'The mock answers SOAP and XML services too: it picks the operation from SOAPAction or from the first element of the Body, answers with the same envelope and namespaces and turns faults into SOAP Faults.',
};
