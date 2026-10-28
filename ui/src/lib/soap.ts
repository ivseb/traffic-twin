// SOAP and XML operations of a contract (docs/spec/event.md 6.1, pack.md 4 x-tt-xml, mock.md 10). A SOAP service has
// one endpoint (POST /ws/orders.asmx) and many logical operations, each an operation of the contract
// ("POST /ws/orders.asmx#GetOrder"); the bodies carry the envelope in x-tt-xml.

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

export type XmlFormat = 'soap11' | 'soap12' | 'xml';

export interface SoapOpInfo {
  /** Operation name (from SOAPAction or the Body element). */
  name: string;
  /** Endpoint path ("/ws/orders.asmx") and its method. */
  endpoint: string;
  method: string;
  format: XmlFormat;
}

const FORMATS: XmlFormat[] = ['soap11', 'soap12', 'xml'];

/** The x-tt-xml format of the first XML body of a content map. */
function contentFormat(content: unknown): XmlFormat | undefined {
  if (!isObj(content)) return undefined;
  for (const item of Object.values(content)) {
    const x = isObj(item) && isObj(item['x-tt-xml']) ? item['x-tt-xml'] : undefined;
    const f = x && typeof x.format === 'string' ? (x.format as XmlFormat) : undefined;
    if (f && FORMATS.includes(f)) return f;
  }
  return undefined;
}

/** The XML format of an OpenAPI operation: its request body first, then its responses. */
export function xmlFormatOf(op: unknown): XmlFormat | undefined {
  if (!isObj(op)) return undefined;
  const rb = isObj(op.requestBody) ? contentFormat(op.requestBody.content) : undefined;
  if (rb) return rb;
  const rs = isObj(op.responses) ? op.responses : {};
  for (const r of Object.values(rs)) {
    const f = isObj(r) ? contentFormat(r.content) : undefined;
    if (f) return f;
  }
  return undefined;
}

/** A logical SOAP (or XML) operation: a path with "#" and an XML body; GraphQL operations are not. */
export function soapOf(method: string, path: string, op: unknown): SoapOpInfo | undefined {
  if (!isObj(op) || isObj(op['x-tt-graphql'])) return undefined;
  const i = path.indexOf('#');
  if (i < 0) return undefined;
  const format = xmlFormatOf(op);
  if (!format) return undefined;
  return { name: path.slice(i + 1), endpoint: path.slice(0, i), method: method.toUpperCase(), format };
}

/** "SOAP 1.1", "SOAP 1.2" or "XML". */
export function soapBadge(f: XmlFormat): string {
  return f === 'soap11' ? 'SOAP 1.1' : f === 'soap12' ? 'SOAP 1.2' : 'XML';
}
