import { describe, expect, it } from 'vitest';
import { capturedSchemas, graphqlLabel, graphqlOf, graphqlOperations, operationsText, prettyDocument, sdlOf } from './graphql';

const doc = {
  openapi: '3.1.0',
  paths: {
    '/graphql#GetOrder': {
      post: {
        'x-tt-graphql': { endpoint: '/graphql', method: 'POST', in: 'json', type: 'query', name: 'GetOrder', document: 'query GetOrder($id:ID!){order(id:$id){id status ...on Order{total}}}', variables: [{ name: 'id', type: 'ID!' }], fields: ['order'] },
      },
    },
    '/graphql#~0a1b2c3d4e': { post: { 'x-tt-graphql': { endpoint: '/graphql', method: 'POST', type: 'query', name: '~0a1b2c3d4e', anonymous: true, document: '{orders(first:?i){id}}' } } },
    '/orders': { get: {} },
  },
  'x-tt-graphql-schemas': [
    {
      endpoint: 'POST /graphql',
      captured_at: '2026-10-20',
      data: {
        __schema: {
          queryType: { name: 'Query' },
          mutationType: null,
          types: [
            { kind: 'OBJECT', name: 'Query', fields: [{ name: 'order', args: [{ name: 'id', type: { kind: 'NON_NULL', name: null, ofType: { kind: 'SCALAR', name: 'ID', ofType: null } } }], type: { kind: 'OBJECT', name: 'Order', ofType: null } }], interfaces: [] },
            { kind: 'OBJECT', name: 'Order', fields: [{ name: 'id', args: [], type: { kind: 'NON_NULL', name: null, ofType: { kind: 'SCALAR', name: 'ID' } } }], interfaces: [] },
            { kind: 'ENUM', name: 'OrderStatus', enumValues: [{ name: 'CREATED' }, { name: 'SHIPPED' }] },
            { kind: 'INPUT_OBJECT', name: 'OrderInput', inputFields: [{ name: 'note', type: { kind: 'SCALAR', name: 'String' } }] },
            { kind: 'SCALAR', name: 'ID' },
            { kind: 'OBJECT', name: '__Type', fields: [] },
          ],
        },
      },
    },
  ],
};

describe('graphql contracts', () => {
  it('reads x-tt-graphql', () => {
    const g = graphqlOf(doc.paths['/graphql#GetOrder'].post)!;
    expect(g.name).toBe('GetOrder');
    expect(graphqlLabel(g)).toBe('QUERY GetOrder');
    expect(g.variables).toEqual([{ name: 'id', type: 'ID!' }]);
    expect(graphqlOf({})).toBeUndefined();
    const ops = graphqlOperations(doc);
    expect(ops.map((o) => o.key)).toEqual(['POST /graphql#GetOrder', 'POST /graphql#~0a1b2c3d4e']);
    expect(graphqlLabel(ops[1].info, 'anonima')).toBe('QUERY anonima');
  });

  it('indents a shape', () => {
    expect(prettyDocument('query GetOrder($id:ID!){order(id:$id){id status ...on Order{total}}}')).toBe(
      'query GetOrder($id:ID!) {\n  order(id:$id) {\n    id\n    status\n    ...on Order {\n      total\n    }\n  }\n}',
    );
    expect(operationsText(doc)).toContain('# QUERY (anonymous) · POST /graphql\n{\n  orders(first:?i) {');
  });

  it('writes the SDL of a captured schema without introspection types', () => {
    const [c] = capturedSchemas(doc);
    expect(c.endpoint).toBe('POST /graphql');
    const sdl = sdlOf(c.schema);
    expect(sdl).toContain('schema {\n  query: Query\n}');
    expect(sdl).toContain('type Query {\n  order(id: ID!): Order\n}');
    expect(sdl).toContain('enum OrderStatus {\n  CREATED\n  SHIPPED\n}');
    expect(sdl).toContain('input OrderInput {\n  note: String\n}');
    expect(sdl).not.toContain('__Type');
    expect(sdl).not.toContain('scalar ID');
  });
});
