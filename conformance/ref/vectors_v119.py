"""Vector definitions of spec v1.19 (sanitizer.md 5.6 alnum, 20): executed inside gen_vectors.py.

Kept in a separate file for size; it uses the names of gen_vectors.py (V, unsafe, policy, ...).
"""

# flake8: noqa: F821

import base64 as _b64

CODE_ALNUM = {'action': 'code', 'shape': 'alnum'}
S12 = lambda *secs: ['sanitizer.md#' + s for s in secs]  # noqa: E731
V12_ACCEPTED = []


def BODIES(xml=True, multipart=True, docs=True, large=0, large_array=50, large_nested=5):
    return {'bodies': {'xml': xml, 'multipart': multipart, 'docs': docs, 'max_large_body_bytes': N(large),
                       'large_array': N(large_array), 'large_nested_array': N(large_nested)}}


def P12(services=(), bodies=None, **kw):
    """A policy with the bodies switches of spec v1.19 (all on by default)."""
    extra = dict(kw.pop('extra', {}) or {})
    extra.update(bodies if bodies is not None else BODIES())
    return policy(services=services, extra=extra, **kw)


def V12(id, category, description, secs, inp, pol, now=NOW):
    V12_ACCEPTED.append(id)
    V(id, category, description, S12(*secs), inp, pol=pol, now=now)


def svc_op(key, request=None, response=None, **kw):
    return [service('shop-api', ops={key: op(request=request, response=response)}, **kw)]


# ---- code with the alnum shape (5.6, v1.19) --------------------------------------------------------------

def alnum_pol(body_rules, side='response', key='GET /orders/{id}', **kw):
    p = part(body=body_rules)
    return policy(services=svc_op(key, **{side: p}), **kw)


V12('2200-code-alnum-accepted', 'code-alnum',
    'code with shape alnum: digits, dots, one letter and leading zeros leave as keep:.',
    ('5.6',), jresp(J.dumps({'itemCode': '0000123450', 'storeCode': '004711', 'channelType': 'R',
                             'version': '2.1', 'type': 'A-1_b.2', 'kind': 'x' * 16})),
    alnum_pol({'$.itemCode': CODE_ALNUM, '$.storeCode': CODE_ALNUM, '$.channelType': CODE_ALNUM,
               '$.version': CODE_ALNUM, '$.type': CODE_ALNUM, '$.kind': CODE_ALNUM}))
V12('2201-code-alnum-length-bounds', 'code-alnum',
    'Length bounds 1..16 bytes: the empty string and 17 bytes leave as shapes; 1 and 16 as keep:.',
    ('5.6',), jresp(J.dumps({'a': {'code': ''}, 'b': {'code': '7'}, 'c': {'code': '1234567890ABCDEF'},
                             'd': {'code': '1234567890ABCDEFG'}, 'e': {'code': '.'}})),
    alnum_pol({'$.*.code': CODE_ALNUM}))
V12('2202-code-alnum-refused-chars', 'code-alnum',
    'Spaces, slash, colon, plus, comma, newline, tilde and non-ASCII digits (Arabic-Indic, fullwidth) are refused.',
    ('5.6',), jresp(J.dumps({'a': {'code': '2 1'}, 'b': {'code': '2/1'}, 'c': {'code': 'A:1'}, 'd': {'code': '+39'},
                             'e': {'code': '1,5'}, 'f': {'code': '21\n'}, 'g': {'code': '2~1'},
                             'h': {'code': '٣'}, 'i': {'code': '１'}, 'j': {'code': '1​'}})),
    alnum_pol({'$.*.code': CODE_ALNUM}))
V12('2203-code-alnum-non-strings', 'code-alnum',
    'Numbers (also 123450 without quotes), booleans and null under code alnum leave as their shapes.',
    ('5.6',), jresp('{"a":{"code":123450},"b":{"code":2.1},"c":{"code":true},"d":{"code":null}}'),
    alnum_pol({'$.*.code': CODE_ALNUM}))
V12('2204-code-alnum-keep-max-bytes', 'code-alnum',
    'code alnum honours limits.keep_max_bytes: with 4, 2.1 leaves and 00012 does not.',
    ('5.3', '5.6'), jresp('{"a":{"code":"2.1"},"b":{"code":"00012"}}'),
    alnum_pol({'$.*.code': CODE_ALNUM}, limits={'keep_max_bytes': 4}))
V12('2205-code-alnum-path-query-headers', 'code-alnum',
    'code alnum on a path parameter, a query value and a header value.',
    ('4.2', '5.6', '8.1', '8.3'),
    X('GET', '/items/0000123450', 'version=2.1&version=2%201', h=[('X-Store-Code', '004711')]),
    policy(services=[service('shop-api', request=part(query={'version': CODE_ALNUM},
                                                      headers={'x-store-code': CODE_ALNUM}),
                             ops={'GET /items/{itemCode}': op(request=part(path={'itemCode': CODE_ALNUM}))})]))
V12('2206-code-alnum-and-code', 'code-alnum',
    'Both shapes in one policy: code keeps refusing digits, code alnum lets them out.',
    ('5.6',), jresp('{"status":"E404","code":"E404","state":"IN_STOCK","type":"IN_STOCK_SINCE_2026"}'),
    alnum_pol({'$.status': CODE, '$.code': CODE_ALNUM, '$.state': CODE, '$.type': CODE_ALNUM}))
V12('2207-code-alnum-form', 'code-alnum', 'code alnum on form fields.', ('5.6', '9.1'),
    X('POST', '/quotes', h=[('Content-Type', 'application/x-www-form-urlencoded')],
      body='itemCode=0000123450&version=2.1&note=a+b'),
    policy(services=[service('shop-api', request=part(body={'$.itemCode': CODE_ALNUM, '$.version': CODE_ALNUM,
                                                            '$.note': CODE_ALNUM}))]))
V12('2208-code-alnum-discovery', 'code-alnum',
    'Discovery on: a value refused by code alnum adds no disc entry (it has a rule).', ('5.6', '15'),
    jpost('{"code":"2 1","other":"x"}'),
    policy(discovery=(True, MODE_EXPIRES), services=[service('shop-api', request=part(body={'$.code': CODE_ALNUM}))]))
V12('2209-code-alnum-errors', 'code-alnum', 'code alnum in errors rules on a 422.', ('5.0', '5.6'),
    jresp('{"error":{"code":"ERR.4021"}}', status=422),
    policy(services=[service('shop-api', errors=part(body={'$.error.code': CODE_ALNUM}))]))

for _id, _desc, _pol in (
        ('2210-refuse-h1-code-alnum', 'H1: code alnum on the authorization header.',
         policy(global_=scope(request=part(headers={'authorization': CODE_ALNUM})))),
        ('2211-refuse-h2-code-alnum', 'H2: code alnum on $.items[*].code in the global response rules.',
         policy(global_=scope(response=part(body={'$.items[*].code': CODE_ALNUM}))))):
    unsafe(_id, _desc, _pol)
V('2212-refuse-code-unknown-shape', 'refusal', 'A code shape other than alnum is not valid.', ['policy.md#2'],
  X('GET', '/'), pol=alnum_pol({'$.code': {'action': 'code', 'shape': 'digits'}}))
V('2213-refuse-keep-with-shape', 'refusal', 'shape belongs to code only: keep with shape is not valid.',
  ['policy.md#2'], X('GET', '/'), pol=alnum_pol({'$.code': {'action': 'keep', 'shape': 'alnum'}}))

# ---- base64 documents (22.4) ------------------------------------------------------------------------------


def DOC(magic, n, seed=7):
    """A synthetic document: the magic bytes, then deterministic filler up to n bytes."""
    fill = bytes((i * 31 + seed) % 251 for i in range(max(0, n - len(magic))))
    return magic + fill


def ZIPDOC(name, n):
    head = b'PK\x03\x04\x14\x00\x00\x00\x08\x00' + b'\x00' * 16 + bytes([len(name), 0, 0, 0]) + name
    return DOC(head, n)


def b64(b, url=False, pad=True):
    s = (_b64.urlsafe_b64encode(b) if url else _b64.b64encode(b)).decode('ascii')
    return s if pad else s.rstrip('=')


PDF = DOC(b'%PDF-1.7\n', 900)
PNG = DOC(b'\x89PNG\r\n\x1a\n', 2000)
JPEG = DOC(b'\xff\xd8\xff\xe0', 3000)
GIF = DOC(b'GIF89a', 40)
WEBP = b'RIFF\x10\x00\x00\x00WEBPVP8 ' + DOC(b'', 64)
OLE = DOC(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 512)

V12('2220-docs-pdf-in-json', 'docs', 'A base64 PDF inside JSON leaves as drop:doc:pdf:<class> with bodies.docs on.',
    ('22.4',), jpost(J.dumps({'fileName': 'documento.pdf', 'content': b64(PDF)})), P12())
V12('2221-docs-image-kinds', 'docs', 'PNG, JPEG, GIF, WebP and OLE (old Office) magic bytes.',
    ('22.4',), jresp(J.dumps({'png': b64(PNG), 'jpeg': b64(JPEG), 'gif': b64(GIF), 'webp': b64(WEBP),
                              'ole': b64(OLE)})), P12())
V12('2222-docs-zip-kinds', 'docs', 'ZIP archives: docx, xlsx and pptx by the names they hold, otherwise zip.',
    ('22.4',), jresp(J.dumps({'docx': b64(ZIPDOC(b'word/document.xml', 700)),
                              'xlsx': b64(ZIPDOC(b'xl/workbook.xml', 700)),
                              'pptx': b64(ZIPDOC(b'ppt/presentation.xml', 700)),
                              'zip': b64(ZIPDOC(b'data/readme.txt', 700))})), P12())
V12('2223-docs-data-uri', 'docs', 'A data: URI with ;base64 is read after the comma; without ;base64 it is a plain string.',
    ('22.4',), jresp(J.dumps({'a': 'data:application/pdf;base64,' + b64(PDF),
                              'b': 'data:image/png;name=scan.png;base64,' + b64(PNG),
                              'c': 'data:application/pdf,' + b64(PDF),
                              'd': 'data:;base64,' + b64(GIF)})), P12())
V12('2224-docs-url-alphabet', 'docs', 'The base64url alphabet and missing padding are accepted.',
    ('22.4',), jresp(J.dumps({'a': b64(JPEG, url=True, pad=False), 'b': b64(PDF[:301], pad=False)})), P12())
V12('2225-docs-not-documents', 'docs',
    'Not documents: base64 without magic, under 16 characters, bad padding, inner whitespace, length 4n+1, bad characters.',
    ('22.4', '6.2'), jresp(J.dumps({'a': b64(DOC(b'', 300)), 'b': b64(b'%PDF-1'), 'c': b64(PDF)[:-1] + '==',
                                    'd': b64(PDF)[:40] + ' ' + b64(PDF)[40:], 'e': b64(PDF) + 'A',
                                    'f': b64(PDF).replace('A', '*', 1), 'g': '=' + b64(PDF)})), P12())
V12('2226-docs-off', 'docs', 'Without bodies (behaviour before v1.19) a base64 PDF is a long string.',
    ('22.4', '6.2'), jpost(J.dumps({'content': b64(PDF)})), policy())
V12('2227-docs-size-classes', 'docs', 'Document classes on the decoded length: 1024, 1025, 16384, 16385 bytes.',
    ('22.4',), jresp(J.dumps({'a': b64(DOC(b'%PDF-', 1024)), 'b': b64(DOC(b'%PDF-', 1025)),
                              'c': b64(DOC(b'%PDF-', 16384)), 'd': b64(DOC(b'%PDF-', 16385))})), P12())
V12('2228-docs-boundary-128k', 'docs', 'Document classes 131072 (l128k) and 131073 (l1m) bytes.',
    ('22.4',), jresp(J.dumps({'a': b64(DOC(b'%PDF-', 131072)), 'b': b64(DOC(b'%PDF-', 131073))})), P12())
V12('2229-docs-everywhere', 'docs', 'The document shape applies to every string shape: query values, headers, path segments.',
    ('22.4', '4.2', '8.1', '8.3'),
    X('GET', '/files/' + b64(GIF, url=True, pad=False), 'doc=' + b64(GIF, url=True, pad=False),
      h=[('X-Attachment', b64(PDF))]), P12())
V12('2230-docs-rules-win', 'docs',
    'Rules come first: hmac gives a token; keep beyond keep_max_bytes and explicit drop give the document shape.',
    ('22.4', '5.1'), jpost(J.dumps({'a': b64(PDF), 'b': b64(PDF), 'c': b64(PDF)})),
    P12(services=[service('shop-api', request=part(body={'$.a': HMAC('doc'), '$.b': KEEP, '$.c': DROP}))]))
V12('2231-docs-discovery', 'docs', 'Discovery on: a document dropped by default still adds its disc entry.',
    ('22.4', '15'), jpost(J.dumps({'content': b64(PNG)})), P12(discovery=(True, MODE_EXPIRES)))
V12('2232-docs-formats-first', 'docs',
    'The formats of 6.3 come first: a 32-character hex string stays drop:str:hex even though it is valid base64.',
    ('22.4', '6.3'), jresp(J.dumps({'a': 'deadbeefcafebabe0123456789abcdef', 'b': 'JVBERi0xLjcK'})), P12())
V12('2233-docs-invalid-utf8-shape', 'docs', 'A lone surrogate is drop:str:invalid even with docs on.',
    ('22.4', '9.2'), jresp('{"a":"JVBERi0xLjcKJVBERi0x\\ud800"}'), P12())

# ---- multipart/form-data (22.3) ----------------------------------------------------------------------------

BND = '----ttBoundary7MA4YWxk'


def MP(parts, boundary=BND, preamble=b'', epilogue=b'', close=True):
    """parts: list of (headers bytes, content bytes)."""
    d = bytes(preamble)
    for head, content in parts:
        d += b'--' + boundary.encode() + b'\r\n' + head + b'\r\n' + content + b'\r\n'
    if close:
        d += b'--' + boundary.encode() + b'--' + epilogue
    return d


def FIELD(name, value, extra=b''):
    return (b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n' + extra,
            value if isinstance(value, bytes) else value.encode('utf-8'))


def FILE(name, filename, content, ct='application/octet-stream'):
    head = (b'Content-Disposition: form-data; name="' + name.encode() + b'"; filename="' + filename.encode() +
            b'"\r\n' + (b'Content-Type: ' + ct.encode() + b'\r\n' if ct else b''))
    return (head, content)


def mpost(data, boundary=BND, ct=None, path='/uploads', **kw):
    return X('POST', path, h=[('Content-Type', ct or 'multipart/form-data; boundary=' + boundary)], body=data, **kw)


V12('2240-multipart-basic', 'multipart',
    'Text parts leave like form fields (name -> [token]); a file part only as drop:file:<kind>:<class>.',
    ('22.3',), mpost(MP([FIELD('orderNumber', 'ORD-2026-000184'), FIELD('note', 'Left at the front desk'),
                         FILE('attachment', 'receipt.pdf', PDF, 'application/pdf')])), P12())
V12('2241-multipart-rules', 'multipart',
    'Rules $.name and $.* apply to text parts; a file part ignores every rule (keep, hmac).',
    ('22.3', '9.1'), mpost(MP([FIELD('type', 'RETURN'), FIELD('ref', 'ORD-2026-000184'),
                               FIELD('free', 'Some text'), FILE('type', 'a.png', PNG, 'image/png'),
                               FILE('ref', 'b.pdf', PDF, 'application/pdf')])),
    P12(services=[service('shop-api', request=part(body={'$.type': CODE, '$.ref': HMAC('ref'), '$.*': KEEP}))]))
V12('2242-multipart-file-kinds', 'multipart',
    'File kinds: magic bytes first (PDF declared as image/png is pdf), then the declared type, then bin.',
    ('22.3', '22.4'), mpost(MP([FILE('a', 'a.png', PNG, 'image/png'), FILE('b', 'b.txt', b'hello', 'text/plain; charset=utf-8'),
                                FILE('c', 'c.csv', b'a,b\n1,2\n', 'text/csv'), FILE('d', 'd.json', b'{}', 'application/json'),
                                FILE('e', 'e.xml', b'<a/>', 'text/xml'), FILE('f', 'f.bin', b'\x00\x01', 'application/octet-stream'),
                                FILE('g', 'g', b'', None), FILE('h', 'h.png', PDF, 'image/png'),
                                FILE('i', 'i.docx', ZIPDOC(b'word/document.xml', 2000), 'application/zip')])), P12())
V12('2243-multipart-framing', 'multipart',
    'Quoted boundary parameter, preamble, epilogue and transport padding after a delimiter.',
    ('22.3',), mpost(MP([FIELD('a', 'x')], boundary='b-1', preamble=b'This is a preamble\r\n', epilogue=b'\r\nepilogue')
                     .replace(b'--b-1\r\n', b'--b-1  \r\n', 1),
                     ct='multipart/form-data; charset=utf-8; boundary="b-1"'), P12())
for _i, (_tag, _desc, _data, _ct) in enumerate((
        ('no-boundary', 'no boundary parameter', MP([FIELD('a', 'x')]), 'multipart/form-data'),
        ('long-boundary', 'a 71-byte boundary', MP([FIELD('a', 'x')], boundary='b' * 71),
         'multipart/form-data; boundary=' + 'b' * 71),
        ('no-close', 'no close delimiter', MP([FIELD('a', 'x')], close=False), None),
        ('no-disposition', 'a part without content-disposition', MP([(b'Content-Type: text/plain\r\n', b'x')]), None),
        ('not-form-data', 'a disposition other than form-data',
         MP([(b'Content-Disposition: attachment; name="a"\r\n', b'x')]), None),
        ('no-name', 'a part without name', MP([(b'Content-Disposition: form-data; filename="a.txt"\r\n', b'x')]), None),
        ('bad-header', 'a part header line without a colon',
         MP([(b'Content-Disposition: form-data; name="a"\r\nX-Bad\r\n', b'x')]), None),
        ('no-headers', 'a part with no header block', MP([(b'', b'x')]), None),
        ('unterminated-quote', 'an unterminated quoted name',
         MP([(b'Content-Disposition: form-data; name="a\r\n', b'x')]), None),
        ('garbage-delimiter', 'bytes after a delimiter',
         MP([FIELD('a', 'x')]).replace(b'--' + BND.encode() + b'\r\n', b'--' + BND.encode() + b'X\r\n', 1), None))):
    V12('%d-multipart-invalid-%s' % (2250 + _i, _tag), 'multipart',
        'Malformed multipart (%s): the whole body is trunc:invalid-multipart.' % _desc, ('22.3',),
        mpost(_data, ct=_ct), P12())
V12('2260-multipart-off', 'multipart', 'Without bodies.multipart the body stays drop:bytes:<class>.',
    ('9.1', '22.3'), mpost(MP([FIELD('a', 'x')])), P12(bodies=BODIES(multipart=False)))
V12('2261-multipart-names', 'multipart',
    'Field names follow the name rule: files[], items[0][sku] and a 6-digit name collapse to {*}; escaped quotes in names.',
    ('22.3', '9.3'), mpost(MP([FIELD('files[]', 'a'), FIELD('items[0][sku]', 'b'), FIELD('c123456', 'c'),
                               (b'Content-Disposition: form-data; name="q\\"x"\r\n', b'd'),
                               (b'Content-Disposition: form-data; name=plain\r\n', b'e'),
                               (b'content-disposition: FORM-DATA;name="lower"\r\n', b'f')])), P12())
V12('2262-multipart-values', 'multipart',
    'A text part that is not UTF-8 is drop:bytes; an empty one is drop:str:l8; part bytes are not percent-decoded.',
    ('22.3',), mpost(MP([FIELD('a', b'\xff\xfe'), FIELD('b', ''), FIELD('c', 'a%20b'), FIELD('d', 'x\r\ny')])),
    P12(services=[service('shop-api', request=part(body={'$.c': KEEP, '$.d': KEEP}))]))
V12('2263-multipart-filename-star', 'multipart', 'filename* alone makes a file part.', ('22.3',),
    mpost(MP([(b"Content-Disposition: form-data; name=\"doc\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n", PDF)])), P12())
V12('2264-multipart-discovery', 'multipart', 'Discovery on: text parts add disc entries, file parts do not.',
    ('22.3', '15'), mpost(MP([FIELD('a', 'x'), FILE('f', 'f.pdf', PDF, 'application/pdf'), FIELD('b[]', 'y')])),
    P12(discovery=(True, MODE_EXPIRES)))
V12('2265-multipart-limits', 'multipart', 'Repeated names keep max_array values (2 here) and the trunc:n marker.',
    ('22.3', '6.4'), mpost(MP([FIELD('tag', 'a'), FIELD('tag', 'b'), FILE('tag', 'x.png', PNG, 'image/png')])),
    P12(limits={'max_array': 2}))
V12('2266-multipart-empty', 'multipart', 'Only the close delimiter: an empty name map.', ('22.3',),
    mpost(MP([])), P12())
V12('2267-multipart-response', 'multipart', 'A multipart response follows the same rules.', ('22.3',),
    X('GET', '/docs/1', rh=[('Content-Type', 'multipart/form-data; boundary=' + BND)],
      rbody=MP([FIELD('meta', 'x'), FILE('file', 'a.pdf', PDF)])), P12())

# ---- XML and SOAP (22.2) -----------------------------------------------------------------------------------


def xpost(body, ct='text/xml; charset=utf-8', path='/ws/StockService.asmx', h=(), **kw):
    return X('POST', path, h=[('Content-Type', ct)] + list(h), body=body, **kw)


SOAP11_REQ = ('<?xml version="1.0" encoding="utf-8"?>\n'
              '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" '
              'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
              '  <soap:Header><AuthHeader xmlns="http://ws.shop.example/policy/v2"><Token>s3cr3t-T0k3n</Token>'
              '</AuthHeader></soap:Header>\n'
              '  <soap:Body>\n'
              '    <GetOrder xmlns="http://ws.shop.example/policy/v2">\n'
              '      <orderNumber>ORD-2026-000184</orderNumber>\n'
              '      <itemCode>0000123450</itemCode>\n'
              '      <asOf xsi:nil="true"/>\n'
              '    </GetOrder>\n'
              '  </soap:Body>\n'
              '</soap:Envelope>\n')
SOAP11_RESP = ('<?xml version="1.0" encoding="utf-8"?>'
               '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
               '<soap:Body><GetOrderResponse xmlns="http://ws.shop.example/policy/v2">'
               '<GetOrderResult status="IN_STOCK">'
               '<holder><name>Mario Rossi</name><email>mario.rossi@example.com</email></holder>'
               '<line code="RCA"><amount>412.50</amount></line>'
               '<line code="FURTO"><amount>88.00</amount></line>'
               '<startDate>2026-01-01</startDate>'
               '</GetOrderResult></GetOrderResponse></soap:Body></soap:Envelope>')

V12('2300-xml-soap11', 'xml',
    'SOAP 1.1 request and response with an empty policy: shapes only, fmt soap11, SOAPAction name, namespace patterns.',
    ('22.2',), xpost(SOAP11_REQ, h=[('SOAPAction', '"http://ws.shop.example/orders/v2/GetOrder"')],
                     rh=[('Content-Type', 'text/xml; charset=utf-8')], rbody=SOAP11_RESP), P12())
V12('2301-xml-soap11-rules', 'xml',
    'Rules on a SOAP exchange: code on attributes, code alnum, keep, bucket(time), hmac.',
    ('22.2', '5.0'), xpost(SOAP11_REQ, h=[('SOAPAction', 'GetOrder')], rh=[('Content-Type', 'text/xml')], rbody=SOAP11_RESP),
    P12(services=[service('shop-api', response=part(body={
        '$.Envelope.Body.GetOrderResponse.GetOrderResult.@status': CODE,
        '$.Envelope.Body.GetOrderResponse.GetOrderResult.line[*].@code': CODE_ALNUM,
        '$.Envelope.Body.GetOrderResponse.GetOrderResult.line[*].amount': KEEP,
        '$.Envelope.Body.GetOrderResponse.GetOrderResult.startDate': BTIME('month'),
        '$.Envelope.Body.GetOrderResponse.GetOrderResult.holder.email': HMAC('email')}),
        request=part(body={'$.Envelope.Body.GetOrder.orderNumber': HMAC('policy'),
                           '$.Envelope.Body.GetOrder.itemCode': CODE_ALNUM}))]))
V12('2302-xml-soap12', 'xml', 'SOAP 1.2: fmt soap12 and the operation name from the action parameter of the content type.',
    ('22.2',), xpost('<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>'
                     '<m:Quote xmlns:m="urn:shop-example:quotes:2"><m:amount>100</m:amount></m:Quote>'
                     '</env:Body></env:Envelope>',
                     ct='application/soap+xml; charset=utf-8; action="urn:shop-example:quotes:2#Quote"'), P12())
V12('2303-xml-tree-mapping', 'xml',
    'Attributes as @name, repeated elements as arrays, mixed content as #text, empty elements, CDATA and references.',
    ('22.2',), xpost('<order id="ORD-1" xml:lang="it"><line sku="A"/><line sku="B">two</line><note><![CDATA[a<b & c]]></note>'
                     '<empty/><mixed>hello <b>big</b> world</mixed><refs>&lt;&#65;&#x42;&amp;&quot;&apos;&gt;</refs>'
                     '<ws>  </ws></order>', ct='application/xml'),
    P12(services=[service('shop-api', request=part(body={'$.order.note': KEEP, '$.order.refs': KEEP, '$.order.ws': KEEP,
                                                         '$.order.mixed.#text': KEEP, '$.order.@lang': KEEP,
                                                         '$.order.line[*].#text': KEEP}))]))
V12('2304-xml-namespaces', 'xml',
    'Namespaces: default, prefixed, unqualified children ({none}), undeclaration, value-like segments, urn, @ in the URI.',
    ('22.2',), xpost('<r xmlns="http://a.example/ns/v1"><p:x xmlns:p="urn:example:orders:2026"><y/></p:x>'
                     '<z xmlns=""><w/></z><c xmlns="http://a.example/customers/3912345678/deadbeefcafe12"/>'
                     '<d xmlns="mailto:mario.rossi@example.com"/><e xmlns="http://a.example/ns/v1"/>'
                     '<f xmlns="http://b.example/%7Euser"/><g xmlns="http://b.example/{x}"/></r>', ct='application/xml'), P12())
V12('2305-xml-xml-prefix', 'xml',
    'The xml prefix needs no declaration; prefixed attributes lose the prefix; same local name: last wins.',
    ('22.2',), xpost('<a xmlns:p="urn:p" xmlns:q="urn:q" p:k="1" q:k="22" xml:space="preserve"><b/></a>', ct='application/xml'),
    P12(services=[service('shop-api', request=part(body={'$.a.@k': KEEP}))]))
V12('2306-xml-prolog-and-misc', 'xml',
    'BOM, XML declaration, comments and processing instructions before, inside and after the root.',
    ('22.2',), xpost(b'\xef\xbb\xbf<?xml version="1.0"?><!-- c --><?pi x?><a><!-- in --><?pi y?>t<b/>u</a><!-- after -->\n',
                     ct='application/xml'),
    P12(services=[service('shop-api', request=part(body={'$.a.#text': KEEP}))]))
V12('2307-xml-line-endings', 'xml',
    'CRLF and CR become LF; tabs and newlines in attribute values become spaces; char refs stay.',
    ('22.2',), xpost(b'<a v="x\r\ny\tz" w="1&#10;2"><t>l1\r\nl2\rl3</t></a>', ct='application/xml'),
    P12(services=[service('shop-api', request=part(body={'$.a.@v': KEEP, '$.a.@w': KEEP, '$.a.t': KEEP}))]))
V12('2308-xml-depth', 'xml', 'max_depth 4: containers deeper than 4 become trunc:depth (the body object is depth 1).',
    ('22.2', '9.2'), xpost('<a><b><c><d><e>x</e></d></c></b></a>', ct='application/xml'), P12(limits={'max_depth': 4}))
V12('2309-xml-limits', 'xml', 'max_keys 3 and max_array 2 apply to the XML tree like to JSON.',
    ('22.2', '6.4'), xpost('<a p="1" q="2"><i>1</i><i>2</i><i>3</i><j/><k/></a>', ct='application/xml'),
    P12(limits={'max_keys': 3, 'max_array': 2}))
V12('2310-xml-off', 'xml', 'Without bodies.xml an XML body stays drop:bytes:<class> and no soap_action leaves.',
    ('9.1', '22.2'), xpost(SOAP11_REQ, h=[('SOAPAction', 'GetOrder')]), P12(bodies=BODIES(xml=False)))
V12('2311-xml-plus-xml', 'xml', 'Any +xml media type is XML (application/atom+xml).', ('22.2',),
    X('GET', '/feed', rh=[('Content-Type', 'application/atom+xml')], rbody='<feed><title>x</title></feed>'), P12())
V12('2312-xml-dynamic-names', 'xml',
    'Element and attribute names that look like values collapse to {*}; namespace paths use .*.',
    ('22.2', '9.3'), xpost('<r><ORD-2026000184 xmlns="urn:o">x</ORD-2026000184><a b123456="y" c="z"/>'
                           '<mario.rossi_example.com>v</mario.rossi_example.com></r>', ct='application/xml'), P12())
for _i, (_tag, _sa) in enumerate((('url', '"http://ws.shop.example/orders/v2/GetOrder"'),
                                  ('fragment', 'urn:shop#Renew'), ('empty', '""'),
                                  ('value', '"http://x.example/ops/ORD-2026000184"'), ('trailing-slash', 'http://x.example/'),
                                  ('bare', 'Cancel'))):
    V12('%d-xml-soapaction-%s' % (2313 + _i, _tag), 'xml',
        'SOAPAction %s: the name after the last /, # or : if it follows the name rule.' % _sa, ('22.2',),
        xpost('<a/>', h=[('SOAPAction', _sa)]), P12())
V12('2319-xml-soapaction-no-xml-body', 'xml',
    'soap_action needs an XML request content type: a SOAPAction with a JSON body adds nothing.', ('22.2',),
    jpost('{}', h=[('SOAPAction', 'GetOrder')]), P12())
V12('2320-xml-discovery', 'xml', 'Discovery paths of XML leaves: attributes as .@name, text as .#text, arrays as [*].',
    ('22.2', '15'), xpost('<a k="v"><i>1</i><i>2</i><m>t<b/></m></a>', ct='application/xml'),
    P12(discovery=(True, MODE_EXPIRES)))
V12('2321-xml-xmlns-limit', 'xml', 'More than 64 namespace changes: the first 64 paths and {trunc}.', ('22.2',),
    xpost('<r>' + ''.join('<e%d xmlns="urn:n%d"/>' % (i, i) for i in range(70)) + '</r>', ct='application/xml'), P12())
V12('2322-xml-container-drop', 'xml', 'An explicit drop on an element collapses it like a JSON object.', ('22.2', '5.0'),
    xpost(SOAP11_REQ), P12(services=[service('shop-api', request=part(body={'$.Envelope.Header': DROP}))]))
V12('2323-xml-gzip', 'xml', 'A gzip XML body is decoded first.', ('22.2', '9.0'),
    xpost(gzip_bytes('<a><b>1</b></a>'), ct='application/xml', h=[('Content-Encoding', 'gzip')]), P12())
V12('2324-json-at-keys', 'xml', 'In JSON, @type and #text stay dynamic keys ({*}) even with bodies.xml on.', ('9.3', '22.2'),
    jresp('{"@type":"Order","#text":"x","id":"1"}'), P12())
V12('2325-xml-nesting-256', 'xml', '256 nested elements are accepted (deeper ones are trunc:depth).', ('22.2',),
    xpost('<a>' * 256 + '</a>' * 256, ct='application/xml'), P12())
V12('2327-xml-nesting-empty-257', 'xml',
    'The 256 limit counts open elements: an empty <b/> inside 256 open elements is accepted.', ('22.2',),
    xpost('<a>' * 256 + '<b/>' + '</a>' * 256, ct='application/xml'), P12())
V12('2328-xml-lenient-corners', 'xml',
    'Accepted corners of the subset: ]]> in text, xmlns:p="" and an XML declaration with any content.', ('22.2',),
    xpost('<?xml version="1.0" encoding="ISO-8859-1"?><a xmlns:p=""><t>x]]>y</t></a>', ct='application/xml'),
    P12(services=[service('shop-api', request=part(body={'$.a.t': KEEP}))]))
V12('2326-xml-response-only', 'xml', 'An XML response to a JSON request.', ('22.2',),
    X('GET', '/legacy', rh=[('Content-Type', 'text/xml')], rbody='<status code="OK">ready</status>'), P12())
for _i, (_tag, _desc, _body) in enumerate((
        ('doctype', 'a DOCTYPE (XXE: external entity)',
         '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'),
        ('billion-laughs', 'a DOCTYPE with nested entities',
         '<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><l>&b;</l>'),
        ('entity', 'an undeclared entity', '<r>&nbsp;</r>'),
        ('bare-amp', 'a bare &', '<r>a & b</r>'),
        ('undeclared-prefix', 'an undeclared prefix', '<p:r/>'),
        ('mismatched', 'a mismatched end tag', '<a><b></a></b>'),
        ('duplicate-attr', 'a duplicate attribute', '<a x="1" x="2"/>'),
        ('two-roots', 'two root elements', '<a/><b/>'),
        ('text-after', 'text after the root', '<a/>x'),
        ('text-before', 'text before the root', 'x<a/>'),
        ('unclosed', 'an unclosed element', '<a><b/>'),
        ('lt-in-attr', 'a < in an attribute value', '<a x="<"/>'),
        ('control-char', 'a control character', '<a>\x01</a>'),
        ('char-ref-zero', 'a reference to U+0000', '<a>&#0;</a>'),
        ('char-ref-big', 'a reference beyond U+10FFFF', '<a>&#x110000;</a>'),
        ('no-space-attr', 'attributes without space', '<a x="1"y="2"/>'),
        ('bad-name', 'an element name starting with a digit', '<1a/>'),
        ('empty', 'only whitespace and a comment', '  <!-- -->  '),
        ('nesting-257', '257 nested elements', '<a>' * 257 + '</a>' * 257),
        ('cdata-unterminated', 'an unterminated CDATA section', '<a><![CDATA[x</a>'),
        ('declaration-in-content', 'a declaration inside an element', '<a><!ELEMENT a ANY></a>'),
        ('double-colon', 'a name with two colons', '<a:b:c xmlns:a="urn:a"/>'),
        ('not-utf8', 'bytes that are not UTF-8', b'<a>\xff</a>'))):
    V12('%d-xml-invalid-%s' % (2340 + _i, _tag), 'xml',
        'Malformed or forbidden XML (%s): the whole body is trunc:invalid-xml.' % _desc, ('22.2',),
        xpost(_body, ct='application/xml'), P12())

# ---- large bodies (22.5) -------------------------------------------------------------------------------------


def big_list(n, inner, tag='P'):
    return J.dumps({'total': N(n), 'items': [{'id': '%s-%06d' % (tag, i), 'status': 'IN_STOCK',
                                                'lines': [{'code': 'C%d' % k, 'amount': N(10 + k)} for k in range(inner)]}
                                               for i in range(n)]})


LARGE = BODIES(large=200000, large_array=6, large_nested=2)
_big = big_list(80, 4)
V12('2400-large-json', 'large-body',
    'A JSON body over max_body_bytes and within max_large_body_bytes keeps its structure: outer arrays large_array, '
    'nested large_nested_array.', ('22.5',), jresp(_big), P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2401-large-over-limit', 'large-body', 'Over max_large_body_bytes: trunc:size as before.', ('22.5', '9.0'),
    jresp(_big), P12(bodies=BODIES(large=4096), limits={'max_body_bytes': 2048}))
V12('2402-large-off', 'large-body', 'Without bodies: trunc:size as before v1.19.', ('22.5', '9.0'),
    jresp(_big), policy(limits={'max_body_bytes': 2048}))
V12('2403-large-gzip', 'large-body', 'A gzip body whose decoded length is over max_body_bytes and within the large limit.',
    ('22.5', '9.0'), jresp(gzip_bytes(_big), rh=[('Content-Encoding', 'gzip')]),
    P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2404-large-gzip-over', 'large-body', 'A gzip body whose decoded length is over the large limit: trunc:size.',
    ('22.5', '9.0'), jresp(gzip_bytes(_big), rh=[('Content-Encoding', 'gzip')]),
    P12(bodies=BODIES(large=4096), limits={'max_body_bytes': 2048}))
V12('2405-large-xml', 'large-body', 'A large XML body: repeated elements are arrays with the large caps.', ('22.5', '22.2'),
    X('GET', '/ws/list', rh=[('Content-Type', 'text/xml')],
      rbody='<list>' + ''.join('<policy n="%d"><cov>a</cov><cov>b</cov><cov>c</cov></policy>' % i for i in range(150)) + '</list>'),
    P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2406-large-prefix-only', 'large-body', 'Only a prefix kept by the source (req_body shorter than the total): trunc:size.',
    ('22.5', '9.0'), jpost(_big[:3000], req_total=len(_big)), P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2407-large-zero-arrays', 'large-body', 'large_array 0: every outer array is only its trunc:n marker.', ('22.5',),
    jresp(_big), P12(bodies=BODIES(large=200000, large_array=0, large_nested=0), limits={'max_body_bytes': 2048}))
V12('2408-large-form', 'large-body', 'A large form body is analysed too.', ('22.5', '9.1'),
    X('POST', '/bulk', h=[('Content-Type', 'application/x-www-form-urlencoded')],
      body='&'.join('k%d=%d' % (i % 40, i) for i in range(600))), P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2409-large-other-type', 'large-body', 'A large body of a type that is not parsed stays trunc:size.', ('22.5', '9.0'),
    X('POST', '/upload', h=[('Content-Type', 'application/octet-stream')], body=DOC(b'', 3000)),
    P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2410-large-invalid-json', 'large-body', 'A large body that is not valid JSON: trunc:invalid-json.', ('22.5', '9.2'),
    jresp(_big[:-1]), P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2411-large-multipart', 'large-body', 'A large multipart upload: the file part is measured, never read.', ('22.5', '22.3'),
    mpost(MP([FIELD('kind', 'scan'), FILE('f', 'scan.jpg', DOC(b'\xff\xd8\xff\xe0', 20000), 'image/jpeg')])),
    P12(bodies=LARGE, limits={'max_body_bytes': 2048}))
V12('2412-normal-body-unchanged', 'large-body', 'A body within max_body_bytes keeps max_array, not the large caps.', ('22.5',),
    jresp(big_list(10, 4)), P12(bodies=LARGE, limits={'max_array': 3}))

V('2450-refuse-bodies-missing-field', 'refusal', 'bodies needs every field.', ['policy.md#2', 'sanitizer.md#22'],
  X('GET', '/'), pol=policy(extra={'bodies': {'xml': True}}))
V('2451-refuse-bodies-large-limit', 'refusal', 'max_large_body_bytes is at most 64 MiB.', ['policy.md#2', 'sanitizer.md#22'],
  X('GET', '/'), pol=P12(bodies={'bodies': dict(BODIES()['bodies'], max_large_body_bytes=N(67108865))}))
V('2452-refuse-bodies-unknown-field', 'refusal', 'bodies accepts no other field.', ['policy.md#2', 'sanitizer.md#22'],
  X('GET', '/'), pol=P12(bodies={'bodies': dict(BODIES()['bodies'], yaml=True)}))
V('2453-refuse-ttpath-bad-hash', 'refusal', 'A tt-path step .#name other than .#text is not valid.',
  ['policy.md#2'], X('GET', '/'), pol=alnum_pol({'$.a.#value': KEEP}))
