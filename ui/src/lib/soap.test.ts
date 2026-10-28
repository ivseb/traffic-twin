import { describe, expect, it } from 'vitest';
import { soapBadge, soapOf, xmlFormatOf } from './soap';

// Invented contract fragments (pack.md 4: x-tt-xml on the media type).
const xmlBody = (format: string) => ({ content: { 'text/xml': { schema: { type: 'object' }, 'x-tt-xml': { format } } } });

describe('soap operations', () => {
  it('reads a logical SOAP operation', () => {
    const op = { requestBody: xmlBody('soap11'), responses: { '200': xmlBody('soap11') } };
    expect(soapOf('post', '/ws/orders.asmx#GetOrder', op)).toEqual({ name: 'GetOrder', endpoint: '/ws/orders.asmx', method: 'POST', format: 'soap11' });
    expect(soapBadge('soap11')).toBe('SOAP 1.1');
  });
  it('falls back to the responses for the format', () => {
    expect(xmlFormatOf({ responses: { '200': xmlBody('soap12') } })).toBe('soap12');
  });
  it('ignores GraphQL, plain paths and JSON bodies', () => {
    expect(soapOf('POST', '/graphql#GetOrder', { 'x-tt-graphql': {}, requestBody: xmlBody('xml') })).toBeUndefined();
    expect(soapOf('POST', '/api/rate', { requestBody: xmlBody('xml') })).toBeUndefined();
    expect(soapOf('POST', '/ws#X', { requestBody: { content: { 'application/json': { schema: {} } } } })).toBeUndefined();
    expect(soapOf('POST', '/ws#X', { requestBody: xmlBody('other') })).toBeUndefined();
  });
});
