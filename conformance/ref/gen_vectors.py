#!/usr/bin/env python3
"""Generate conformance/vectors/*.json and conformance/policies/*.json.

Usage: python3 conformance/ref/gen_vectors.py [--check]

--check regenerates in memory and fails if any file on disk differs (CI mode).
Expected outputs are computed by the reference implementation in this directory.
"""

import os
import sys

sys.setrecursionlimit(20000)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import policyload as PL  # noqa: E402
import ttjson as J  # noqa: E402
import vectorio  # noqa: E402
from build import (BNUM, BTIME, CREATED_AT, CT_JSON, DROP, EPOCH, FLEET_KID, FLEET_SEED, GROUP, HMAC,  # noqa: E402
                   KEEP, KEY, KEY_BYTES, MODE_EXPIRES, N, NOW, X, gzip_bytes, jpost, jresp, op, part, policy,
                   scope, service)
from ed25519 import public_key  # noqa: E402
from sanitizer import Sanitizer  # noqa: E402

ROOT = vectorio.ROOT
VECTORS = []
POLICIES = {
    'empty': policy(),
    'auto-words': policy(auto_words=True),
}


def V(id, category, description, spec, inp, pol='empty', key=KEY, now=NOW, amb=(), group=GROUP,
      last_seq=None, min_seq=None):
    v = {'format': 'tt.conformance.vector/v1', 'id': id, 'category': category,
         'description': description, 'spec': list(spec)}
    if amb:
        v['ambiguities'] = list(amb)
    if isinstance(pol, str):
        v['policy_ref'] = 'policies/%s.json' % pol
    elif isinstance(pol, tuple):
        v['policy_envelope'] = pol[1]
        v['fleet_keys'] = pol[2]
    elif pol is not None:
        v['policy'] = pol
    if pol is not None and group is not None:
        v['source_group'] = group
    if last_seq is not None:
        v['last_issued_seq'] = N(last_seq)
    if min_seq is not None:
        v['min_issued_seq'] = N(min_seq)
    if key is not None:
        v['hmac_key'] = key
    v['now'] = now
    v['input'] = inp
    VECTORS.append(v)


S = lambda *secs: ['sanitizer.md#' + s for s in secs]  # noqa: E731
AUTO = 'auto-words'
SEVEN_DAYS = '2026-10-27T08:00:00Z'  # CREATED_AT + 7 days: the longest window a source accepts

# =========================================================================== default drop (13)

V('0001-default-drop', 'default-drop',
  'Empty policy: every part of an inbound exchange (path, query, headers, cookies, JSON bodies, set-cookie) leaves only shapes.',
  S('13', '4.2', '8.1', '8.2', '8.3', '9.2'),
  X('POST', '/customers/mario.rossi%40example.com/orders', 'promo=AUTUMN10&email=giulia.neri%40example.com',
    h=[CT_JSON, ('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjLTEwMDQyIn0.c2lnbmF0dXJl'),
       ('X-Request-Id', '550e8400-e29b-41d4-a716-446655440000'), ('Cookie', 'sid=9f8e7d6c5b4a; cart=CART-778812')],
    body='{"customer":{"name":"Mario Rossi","phone":"+390212345678"},"items":[{"sku":"TSHIRT-RED-M","qty":2,"price":19.90}],"gift":false,"coupon":null}',
    status=201, rh=[('Content-Type', 'application/json; charset=utf-8'), ('Set-Cookie', 'sid=9f8e7d6c5b4a; Path=/; HttpOnly')],
    rbody='{"id":"ORD-2026-000184","status":"CREATED","total":39.80,"eta":"2026-10-21"}'))

V('0002-hmac-equal-values', 'hmac',
  'Reference token of sanitizer.md 7.3 (key k1 = 0x00..0x1f, epoch 2026-10, domain order, value ORD-2026-000184): the same value in a query parameter and in a response body field yields the same token.',
  S('7.2', '7.3', '5.4', '8.3'),
  X('GET', '/v1/shipments', 'orderId=ORD-2026-000184', rh=[CT_JSON],
    rbody='{"items":[{"orderId":"ORD-2026-000184","shipmentId":"SHP-77120","status":"IN_TRANSIT"}]}'),
  pol=policy(services=[service('shop-api', ops={
      'GET /v1/shipments': op(request=part(query={'orderId': HMAC('order')}),
                              response=part(body={'$.items[*].orderId': HMAC('order'),
                                                  '$.items[*].shipmentId': HMAC('shipment'),
                                                  '$.items[*].status': KEEP}))})]))

V('0003-path-segment-email', 'path',
  'auto_words: lowercase words stay, a percent-encoded e-mail segment becomes {drop:str:email}.',
  S('4.1', '4.2', '6.3'),
  X('GET', '/customers/mario.rossi%40example.com/orders'), pol=AUTO)

V('0004-dynamic-keys', 'body',
  'Keys that are not names (uuid, hex, e-mail, digits-first) collapse under {*}; the array is sorted by the canonical form of the values.',
  S('9.3', '6.3'),
  jpost('{"stock":{"a50e8400-e29b-41d4-a716-446655440000":3,"deadbeefdeadbeef":"x","SKU_RED":2,"12345":true},'
        '"byEmail":{"mario.rossi@example.com":{"n":1},"giulia.neri@example.com":{"n":22}}}'))

V('0005-spec-section-14-example', 'default-drop',
  'The complete example of sanitizer.md section 14, with the real token.',
  S('14', '5.3', '5.4', '5.5', '8.1', '8.2', '9.1'),
  X('POST', '/orders', 'promo=AUTUMN10', h=[CT_JSON, ('Cookie', 'sid=9f8e7d6c5b4a')],
    body='{"items":[{"sku":"TSHIRT-RED-M","qty":2}],"email":"giulia.neri@example.com","note":""}',
    status=201, rh=[('Content-Type', 'application/json; charset=utf-8')],
    rbody='{"id":"ORD-2026-000184","status":"CREATED","total":73.40}'),
  pol=policy(auto_words=True, services=[service('shop-api', ops={
      'POST /orders': op(response=part(body={'$.id': HMAC('order'), '$.status': KEEP,
                                             '$.total': BNUM(0, 50, 100, 250)}))})]))

V('0006-default-drop-error-text-body', 'default-drop',
  'A 500 with a text/plain error body containing an e-mail: only drop:bytes:<class>.',
  S('9.1', '13'),
  X('GET', '/orders/ORD-2026-000184', status=500, rh=[('Content-Type', 'text/plain; charset=utf-8')],
    rbody='Order ORD-2026-000184 for mario.rossi@example.com failed: card 4111111111111111 declined'))

V('0007-default-drop-outbound', 'default-drop',
  'Outbound call with no service in policy: service is the host pattern (spec v1.5, hosts.discovery auto by default), everything else is a shape.',
  S('3.1', '3.5', '13'),
  X('POST', '/v1/shipments', 'ref=ORD-2026-000184', h=[CT_JSON, ('X-Api-Key', 'sk_test_51Hc0nf0rmance')],
    body='{"orderId":"ORD-2026-000184","to":{"name":"Giulia Neri","city":"Torino"}}',
    status=201, rh=[CT_JSON], rbody='{"shipmentId":"SHP-77120","label":"https://labels.carrier.example/SHP-77120.pdf"}',
    dir='outbound', url_base='https://api.carrier.example'))

V('0008-default-drop-scalars', 'body',
  'Shapes of every JSON scalar kind with an empty policy.',
  S('6.2'),
  jpost('{"n":null,"t":true,"f":false,"zero":0,"neg":-12,"dec":1.5,"exp":1e3,"s":"","u":"\\u00e8"}'))

# =========================================================================== path (4)

V('0101-path-root', 'path', 'raw_path "/" sanitizes to "/".', S('4.2'), X('GET', '/'))
V('0102-path-empty', 'path', 'An empty raw_path sanitizes to "/".', S('4.1', '4.2'), X('GET', ''))
V('0103-path-empty-segments', 'path', 'Empty segments are removed: //orders//items/ equals /orders/items.',
  S('4.1'), X('GET', '//orders//items/'), pol=AUTO)
V('0104-path-auto-words-off', 'path', 'With auto_words false and no allow list every segment is dropped, even v1.',
  S('4.2', '13'), X('GET', '/v1/shipments'))
V('0105-path-auto-words-patterns', 'path',
  'auto_words regex: lowercase words joined by single - or _, and v + 1..3 digits; everything else is dropped.',
  S('4.2'),
  X('GET', '/orders/order-items/order_items/a-b_c/v1/v999/v1000/Orders/order--items/-orders/orders-/ord3rs/V1/x'),
  pol=AUTO)
V('0106-path-auto-words-40-bytes', 'path', 'auto_words: a 40-byte word stays, a 41-byte word is dropped.',
  S('4.2'), X('GET', '/' + 'w' * 40 + '/' + 'q' * 41), pol=AUTO)
V('0107-path-allow-list', 'path', 'segments.allow keeps listed literals (exact, case-sensitive) with auto_words off.',
  S('4.2'), X('GET', '/API/v2/api/Orders'), pol=policy(allow=['API', 'v2', 'Orders']))
V('0108-path-percent-decoding', 'path',
  'Segments are percent-decoded before matching: %6f%72ders and %6F%72ders are both "orders".',
  S('4.1'), X('GET', '/%6f%72ders/%6F%72ders'), pol=AUTO)
V('0109-path-percent-literal', 'path', 'A % not followed by two hex digits stays literal (a%zzb, abc%, %2).',
  S('4.1'), X('GET', '/a%zzb/abc%/%2'), pol=AUTO)
V('0110-path-plus-not-space', 'path',
  'In the path + is not a space: "+390212345678" is a phone; "%20390212345678" is not.',
  S('4.1', '6.3'), X('GET', '/+390212345678/%20390212345678'))
V('0111-path-encoded-slash', 'path',
  '%2F decodes inside a segment and does not split it: orders%2Fitems is one segment, not an auto word.',
  S('4.1', '4.2'), X('GET', '/orders%2Fitems'), pol=AUTO)
V('0112-path-invalid-utf8', 'path',
  'Segments whose decoded bytes are not UTF-8 become {drop:bytes} (lone %ff, overlong %C0%AF, surrogate %ED%A0%80); %C3%A8 is valid.',
  S('4.1', '4.2'), X('GET', '/%ff%fe/%C0%AF/%ED%A0%80/%C3%A8'), pol=AUTO)
V('0113-path-raw-invalid-utf8-bytes', 'path', 'Raw (not percent-encoded) invalid bytes in raw_path also give {drop:bytes}.',
  S('4.1', '4.2'), X('GET', b'/orders/\xff\xfeA'), pol=AUTO)
V('0114-path-32-segments', 'path', 'Exactly 32 segments: no truncation.', S('4.1'),
  X('GET', '/' + '/'.join(['s'] * 32)), pol=AUTO)
V('0115-path-33-segments', 'path', '33 segments: the 33rd is replaced by a single {trunc} segment.', S('4.1'),
  X('GET', '/' + '/'.join(['s'] * 30) + '/x/y/z'), pol=AUTO)
V('0116-path-40-segments', 'path', '40 segments still give one {trunc} segment.', S('4.1'),
  X('GET', '/' + '/'.join('seg%d' % i for i in range(40))), pol=AUTO)
V('0117-path-formats', 'path', 'Recognized formats in path segments.',
  S('4.2', '6.3'),
  X('GET', '/550e8400-e29b-41d4-a716-446655440000/2026-10-19/192.168.0.1/184/deadbeefdeadbeef0011/'
           'mario.rossi%40example.com/2026-10-19T10%3A00%3A00Z'))
V('0118-path-non-ascii', 'path', 'Non-ASCII segments get the class of their UTF-8 length (percent-encoded and raw).',
  S('4.1', '6.2'), X('GET', '/caf%C3%A9/caf\u00e9/\u00e8'), pol=AUTO)
V('0119-path-control-bytes', 'path', 'A decoded NUL or DEL makes a segment non-printable: length class only.',
  S('4.1', '6.3'), X('GET', '/%00orders/184%7F'), pol=AUTO)

# =========================================================================== query (8.3)

V('0201-query-default-drop', 'query', 'Query values are dropped by default; names follow the key rule.',
  S('8.3'), X('GET', '/search', 'q=red+shirt&page=2&from=2026-10-01'))
V('0202-query-repeated', 'query', 'Repeated names keep every value, in order of appearance.',
  S('8.3'), X('GET', '/search', 'tag=a&tag=bbbbb&tag=c&tag=x@y.example'))
V('0203-query-empty-parts', 'query', 'Empty parts between & are ignored.', S('8.3'), X('GET', '/s', '&&a=1&&b=22&'))
V('0204-query-empty-string', 'query', 'An empty raw_query gives no query object.', S('8.3', '10.1'), X('GET', '/s', ''))
V('0205-query-plus-and-percent', 'query', 'Names and values: + becomes space first, then %XY; %2B is a literal +.',
  S('8.3'), X('GET', '/s', 'q=a+b&q=a%2Bb&q=a%20b&%6e%61me=x'),
  pol=policy(global_=scope(request=part(query={'q': KEEP, 'name': KEEP}))))
V('0206-query-split-first-equals', 'query', 'A part splits on the first "=" only.', S('8.3'),
  X('GET', '/s', 'a=b=c&e==&f='), pol=policy(global_=scope(request=part(query={'a': KEEP, 'e': KEEP, 'f': KEEP}))))
V('0207-query-no-equals', 'query', 'A part without "=" has the name {*} and its whole text as value, always dropped.', S('8.3'),
  X('GET', '/s', 'flag&debug'))
V('0208-query-invalid-utf8', 'query', 'Non-UTF-8 value gives drop:bytes; non-UTF-8 name gives {*}.', S('8.3'),
  X('GET', '/s', 'a=%ff&%fe=1&b=%C3%A8'))
V('0209-query-dynamic-names', 'query',
  'Names that break the key rule (e-mail, hex, uuid, empty, digit-first) collapse into {*}, in order of appearance.',
  S('8.3', '9.3'),
  X('GET', '/s', 'mario.rossi%40example.com=1&deadbeefdeadbeef=2&ok=3&=4&9lives=5&a50e8400-e29b-41d4-a716-446655440000=6'))
V('0210-query-semicolon', 'query', '";" is not a separator.', S('8.3'), X('GET', '/s', 'a=1;b=2'),
  pol=policy(global_=scope(request=part(query={'a': KEEP}))))
V('0211-query-encoded-ampersand', 'query', '%26 and %3D inside a value do not split it.', S('8.3'),
  X('GET', '/s', 'a=x%26b%3D2'), pol=policy(global_=scope(request=part(query={'a': KEEP}))))
V('0212-query-name-length', 'query', 'Name of 64 bytes is literal, 65 bytes collapses.', S('8.3', '9.3'),
  X('GET', '/s', 'k' * 64 + '=1&' + 'm' * 65 + '=2'))
V('0213-query-actions', 'query',
  'Query values are strings: hmac and keep work on the string, bucket(num) becomes drop, bucket(time) works.',
  S('8.3', '5.1', '5.5'),
  X('GET', '/s', 'orderId=184&total=73.40&day=2026-10-19T10%3A15%3A00%2B02%3A00&status=OPEN'),
  pol=policy(global_=scope(request=part(query={'orderId': HMAC('order'), 'total': BNUM(0, 50, 100),
                                               'day': BTIME('day'), 'status': KEEP}))))
V('0214-query-64-names', 'query', 'Exactly 64 distinct names: no {trunc}.', S('8.3'),
  X('GET', '/s', '&'.join('p%d=1' % i for i in range(64))))
V('0215-query-65-names', 'query', '65 distinct names: 64 kept plus {trunc} = ["trunc:keys:<class of 65>"].',
  S('8.3', '6.4'), X('GET', '/s', '&'.join('p%d=1' % i for i in range(65)) + '&p0=2'))

# =========================================================================== headers (8.1)

V('0301-headers-lowercase', 'headers', 'Header names are lowercased; values dropped by default.', S('8.1'),
  X('GET', '/', h=[('X-Request-ID', 'req-0001'), ('ACCEPT', 'application/json'), ('user-agent', 'shop-app/1.4')]))
V('0302-headers-repeated', 'headers', 'Repeated header fields are joined with ", " into one value per name.',
  S('8.1'), X('GET', '/', h=[('X-Tag', 'a'), ('Accept', 'text/html'), ('x-tag', 'bbbbbb')]))
V('0303-headers-invalid-names', 'headers', 'Names outside the token grammar become {*}; their values are joined into one.',
  S('8.1'), X('GET', '/', h=[('x bad', 'v1'), ('x-\u00e9', 'v2'), ('x:colon', 'v3'), ('', 'v4')]))
V('0304-headers-name-length', 'headers', 'Name of 64 bytes is kept, 65 bytes becomes {*}.', S('8.1'),
  X('GET', '/', h=[('x' * 64, '1'), ('y' * 65, '2')]))
V('0305-headers-invalid-utf8', 'headers', 'A non-UTF-8 header value is drop:bytes, whatever the action.',
  S('8.1'), X('GET', '/', h=[('X-Name', b'Mar\xedo'), ('Accept', b'\xc3\xa8')]),
  pol=policy(global_=scope(request=part(headers={'x-name': KEEP, 'accept': KEEP}))))
V('0306-headers-keep', 'headers', 'keep on content-type and accept in request and response.', S('8.1', '5.3'),
  X('POST', '/', h=[('Accept', 'application/json'), ('Content-Type', 'application/json')], body='{}',
    rh=[('Content-Type', 'application/json; charset=utf-8')], rbody='{}'),
  pol=policy(global_=scope(request=part(headers={'accept': KEEP, 'content-type': KEEP}),
                           response=part(headers={'content-type': KEEP}))))
V('0307-headers-keep-limit', 'headers', 'keep_max_bytes on headers: 64 bytes kept, 65 bytes dropped to a shape.',
  S('5.3'), X('GET', '/', h=[('X-A', 'x' * 64), ('X-B', 'y' * 65)]),
  pol=policy(global_=scope(request=part(headers={'x-a': KEEP, 'x-b': KEEP}))))
V('0308-headers-65-names', 'headers', '65 distinct header names: the first 64 are kept, then {trunc} = ["trunc:keys:<class>"].',
  S('8.1', '6.4'), X('GET', '/', h=[('x-h%02d' % i, 'v') for i in range(65)] + [('x-h00', 'w')]))
V('0309-headers-cookie-excluded', 'headers', 'cookie and set-cookie never appear in headers.', S('8.1', '8.2'),
  X('GET', '/', h=[('Cookie', 'a=1'), ('X-A', 'x')], rh=[('Set-Cookie', 'b=2'), ('X-B', 'y')]))
V('0310-headers-formats', 'headers', 'Header values get format shapes: a bare JWT is jwt, "Bearer <jwt>" is not.',
  S('8.1', '6.3'),
  X('GET', '/', h=[('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'),
                   ('X-Token', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'), ('X-Forwarded-For', '203.0.113.7'),
                   ('X-Customer-Email', 'giulia.neri@example.com'), ('Date', 'Mon, 19 Oct 2026 10:00:00 GMT')]))
V('0311-headers-hmac', 'headers', 'hmac on a header value.', S('8.1', '7.2'),
  X('GET', '/', h=[('X-Customer-Id', 'C-10042')]),
  pol=policy(global_=scope(request=part(headers={'x-customer-id': HMAC('customer')}))))
V('0312-headers-empty-value', 'headers', 'An empty header value is drop:str:l8.', S('8.1', '6.2'),
  X('GET', '/', h=[('X-Empty', '')]))
V('0320-ct-params', 'headers', 'ct is the media type before ";": parameters never leave.', S('8.1'),
  X('POST', '/', h=[('Content-Type', 'application/json; charset=utf-8; profile="x"')], body='{}'))
V('0321-ct-case-and-spaces', 'headers', 'ct is trimmed of spaces and lowercased.', S('8.1'),
  X('POST', '/', h=[('Content-Type', '  Application/JSON  ;x=1')], body='[]'))
V('0322-ct-invalid', 'headers', 'A media type outside the ct grammar is "invalid" and the body is not parsed.',
  S('8.1', '9.1'), X('POST', '/', h=[('Content-Type', 'json')], body='{"a":1}'))
V('0323-ct-repeated-joined', 'headers', 'Two content-type headers are joined with ", ", so ct is invalid.', S('8.0', '8.1'),
  X('POST', '/', h=[('Content-Type', 'text/plain'), ('Content-Type', 'application/json')], body='{"a":1}'))
V('0324-ct-empty', 'headers', 'An empty content-type value gives ct "invalid".', S('8.1'),
  X('POST', '/', h=[('Content-Type', '')], body='{"a":1}'))
V('0325-ct-tab', 'headers', 'Tabs around the media type are stripped like spaces.', S('8.1'),
  X('POST', '/', h=[('Content-Type', '\tapplication/json\t; charset=utf-8')], body='{"a":1}'))
V('0326-ct-invalid-utf8', 'headers', 'A non-UTF-8 content-type value gives ct "invalid".', S('8.1'),
  X('POST', '/', h=[('Content-Type', b'application/js\xffon')], body='{"a":1}'))

# =========================================================================== cookies (8.2)

V('0401-cookies-basic', 'cookies', 'One cookie header with several pairs.', S('8.2'),
  X('GET', '/', h=[('Cookie', 'sid=9f8e7d6c5b4a; lang=it; cart=CART-778812')]))
V('0402-cookies-trim-and-noeq', 'cookies', 'Parts are trimmed of spaces and tabs; parts without "=" are ignored.',
  S('8.2'), X('GET', '/', h=[('Cookie', ' flag ;\ta=1\t;;  b=two ; =anon')]))
V('0403-cookies-first-equals-and-quotes', 'cookies', 'Split on the first "="; outer double quotes are kept.',
  S('8.2'), X('GET', '/', h=[('Cookie', 'a=b=c; q="xyz"')]),
  pol=policy(global_=scope(request=part(cookies={'a': KEEP, 'q': KEEP}))))
V('0404-cookies-multiple-headers', 'cookies', 'Several cookie headers: values in order of reception.', S('8.2'),
  X('GET', '/', h=[('Cookie', 'a=1; b=2'), ('X-A', 'x'), ('cookie', 'a=333')]))
V('0405-set-cookie', 'cookies', 'set-cookie: only the part before the first ";"; attributes never leave.',
  S('8.2'),
  X('GET', '/', rh=[('Set-Cookie', 'sid=9f8e7d6c5b4a; Path=/; Domain=shop.example; HttpOnly'),
                    ('Set-Cookie', 'pref=dark'), ('Set-Cookie', 'noequals; Path=/')]))
V('0406-set-cookie-trim', 'cookies', 'set-cookie parts are trimmed at the edges; a space inside the name still collapses it.',
  S('8.2'), X('GET', '/', rh=[('Set-Cookie', '\tsid=abc '), ('Set-Cookie', 'ok =1')]))
V('0407-cookies-dynamic-names', 'cookies', 'Cookie names outside the key rule collapse into {*}.', S('8.2', '9.3'),
  X('GET', '/', h=[('Cookie', 'mario.rossi@example.com=1; deadbeefdeadbeef=2; _ga=GA1.2.3')]))
V('0408-cookies-invalid-utf8', 'cookies', 'Non-UTF-8 cookie value: drop:bytes; non-UTF-8 name: {*}.', S('8.2'),
  X('GET', '/', h=[('Cookie', b'a=\xff; \xfe=1')]))
V('0409-cookies-direction', 'cookies',
  'A set-cookie in a request and a cookie in a response are not parsed (and never in headers).',
  S('8.1', '8.2'), X('GET', '/', h=[('Set-Cookie', 'x=1')], rh=[('Cookie', 'y=2')]))
V('0410-cookies-hmac', 'cookies', 'hmac on a cookie value.', S('8.2', '7.2'),
  X('GET', '/', h=[('Cookie', 'cid=C-10042')]),
  pol=policy(global_=scope(request=part(cookies={'cid': HMAC('customer')}))))

# =========================================================================== body (9)

V('0501-body-top-level-string', 'body', 'A top-level JSON string is a leaf.', S('9.2', '6.2'), jpost('"hello world"'))
V('0502-body-top-level-number', 'body', 'A top-level JSON number is a leaf.', S('9.2', '6.2'), jpost(' 42 '))
V('0503-body-empty-containers', 'body', 'Empty objects and arrays stay empty.', S('9.2', '9.4'),
  jpost('{"a":{},"b":[],"c":[{}],"d":[[]]}'))
V('0504-body-nested-arrays', 'body', 'Nested and mixed arrays keep order and shape every element.', S('9.4'),
  jpost('[[1,[2.5,[]]],"x",null,true,{"k":[false]}]'))
V('0505-body-duplicate-keys', 'body', 'Duplicate keys: only the last occurrence is kept.', S('9.2'),
  jpost('{"a":"mario.rossi@example.com","b":1,"a":2}'))
V('0506-body-duplicate-escaped-key', 'body', '"a" and "\\u0061" are the same key: last wins.', S('9.2'),
  jpost('{"a":1,"\\u0061":"str"}'))
V('0507-body-duplicate-position', 'body',
  'The surviving duplicate takes the position of the last occurrence; this decides which keys survive max_keys.',
  S('9.2', '6.4'), jpost('{"a":1,"b":2,"a":3,"c":4}'), pol=policy(limits={'max_keys': 2}))
V('0508-body-whitespace', 'body', 'RFC 8259 whitespace (space, tab, CR, LF) is accepted anywhere between tokens.',
  S('9.2'), jpost(' \t\r\n{ "a" :\n[ 1 ,\t2 ] }\r\n'))
V('0509-body-unicode-escapes', 'body',
  'Escapes are decoded before shaping: \\u00e8 is 2 bytes, an escaped surrogate pair is 4 bytes, raw UTF-8 likewise.',
  S('9.2', '6.2'), jpost('{"a":"\\u00e8","b":"\\ud83d\\ude00","c":"\u00e8\u00e8\u00e8","d":"\\u0041\\u0042"}'))
V('0510-body-lone-surrogate', 'body', 'A lone escaped surrogate makes the string invalid, whatever the action.',
  S('9.2', '6.2', '5.1'), jpost('{"a":"\\ud800","b":"x\\udfff","c":"\\ude00\\ud83d","k":"\\ud800"}'),
  pol=policy(global_=scope(request=part(body={'$.k': KEEP, '$.c': HMAC()}))))
V('0511-body-escaped-email', 'body', 'An e-mail hidden behind \\u escapes is still recognized.', S('9.2', '6.3'),
  jpost('{"e":"\\u006dario.rossi\\u0040example.com","s":"\\/"}'))
V('0512-body-plus-json', 'body', 'application/problem+json and vendor +json types are parsed as JSON.', S('9.1'),
  X('GET', '/', status=404, rh=[('Content-Type', 'application/problem+json')],
    rbody='{"type":"about:blank","title":"Not Found","detail":"Order ORD-1 not found"}'))
V('0513-body-text-json-not-json', 'body', 'text/json is not a JSON type: drop:bytes.', S('9.1'),
  X('POST', '/', h=[('Content-Type', 'text/json')], body='{"a":1}'))
V('0514-body-non-json', 'body', 'text/plain body: drop:bytes:<class of length>.', S('9.1'),
  X('POST', '/', h=[('Content-Type', 'text/plain')], body='hello'))
V('0515-body-no-ct', 'body', 'Body without content-type: drop:bytes:<class>.', S('9.1'), X('POST', '/', body='{"a":1}'))
V('0516-body-absent', 'body', 'Empty body: body absent, size l8.', S('9.0'), X('GET', '/'))
V('0517-body-binary', 'body', 'application/octet-stream with arbitrary bytes.', S('9.1'),
  X('PUT', '/upload', h=[('Content-Type', 'application/octet-stream')], body=bytes(range(256)) * 2))
V('0518-body-form', 'body', 'application/x-www-form-urlencoded is handled like the query.', S('9.1', '8.3'),
  X('POST', '/login', h=[('Content-Type', 'application/x-www-form-urlencoded')],
    body='email=mario.rossi%40example.com&password=s3cret+pass&remember=on&remember=1'))
V('0519-body-form-rules', 'body', 'Form fields take body rules $.name; collapsed names only match $.*.',
  S('9.1', '8.3'),
  X('POST', '/checkout', h=[('Content-Type', 'application/x-www-form-urlencoded; charset=utf-8')],
    body='orderId=ORD-2026-000184&total=73.40&step=pay&mario%40example.com=x'),
  pol=policy(global_=scope(request=part(body={'$.orderId': HMAC('order'), '$.total': BNUM(0, 50, 100),
                                              '$.step': KEEP}))))
V('0520-body-json-uppercase-ct', 'body', 'Content-Type Application/Json; Charset=UTF-8 is JSON.', S('8.1', '9.1'),
  X('POST', '/', h=[('Content-Type', 'Application/Json; Charset=UTF-8')], body='{"a":"b"}'))
V('0521-body-response-and-request', 'body', 'Request and response bodies are sanitized independently.', S('9'),
  X('POST', '/', h=[CT_JSON], body='{"q":"x"}', status=200, rh=[CT_JSON], rbody='[1,"two"]'))
V('0522-body-empty-non-json', 'body', 'Empty body with a content-type: body absent, size l8.', S('9.0'),
  X('POST', '/', h=[('Content-Type', 'text/plain')], body=''))
V('0523-body-key-rule', 'body', 'Literal keys: up to 64 chars of [A-Za-z0-9_.-] starting with a letter or _.',
  S('9.3'),
  jpost('{"' + 'k' * 64 + '":1,"' + 'm' * 65 + '":2,"_x":3,"a.b-c_d":4,"9a":5,"":6,"a b":7,"{*}":8,"\u00e8":9}'))
V('0524-body-key-formats', 'body', 'Keys that pass the regex but are uuid, hex or jwt still collapse.',
  S('9.3', '6.3'),
  jpost('{"abcdefabcdefabcd":1,"abcdefabcdefabc":2,"a50e8400-e29b-41d4-a716-446655440000":3,'
        '"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln":4,"Deadbeef":5}'))
V('0525-body-lone-surrogate-key', 'body', 'A key with a lone surrogate is dynamic and collapses.', S('9.3', '9.2'),
  jpost('{"\\ud800":"x","ok":1}'))

for i, (name, text) in enumerate([
        ('trailing-comma', '{"a":1,}'), ('comment', '{"a":1 /* c */}'), ('nan', '{"a":NaN}'),
        ('infinity', '[Infinity]'), ('leading-zero', '[01]'), ('single-quotes', "{'a':1}"),
        ('truncated', '{"a":[1,2'), ('control-char', '{"a":"x\ny"}'), ('bad-escape', '{"a":"\\x41"}'),
        ('two-values', '{} {}'), ('bare-word', 'hello'), ('number-dot', '[1.]'),
        ('number-leading-dot', '[.5]'), ('number-plus', '[+1]'), ('number-exp-empty', '[1e]'),
        ('unquoted-key', '{a:1}'), ('short-unicode-escape', '["\\u00e"]'), ('uppercase-literal', '[TRUE]')]):
    V('%04d-invalid-json-%s' % (550 + i, name), 'body', 'Invalid JSON (%s): body is trunc:invalid-json.' % name,
      S('9.2', '6.4'), jpost(text))
V('0570-invalid-json-utf8', 'body', 'Invalid UTF-8 inside a JSON string: trunc:invalid-json.', S('9.2'),
  jpost(b'{"name":"Mar\xedo"}'))
V('0571-invalid-json-bom', 'body', 'A UTF-8 BOM before the JSON text: trunc:invalid-json.', S('9.2'),
  jpost(b'\xef\xbb\xbf{"a":1}'))
V('0574-json-empty-body', 'body', 'An empty body declared as JSON is absent, not invalid JSON.', S('9.0'), jpost(''))
V('0572-invalid-json-deep', 'body',
  'A syntax error inside a container already beyond max_depth still makes the body invalid.',
  S('9.2'), jpost('{"a":{"b":{"c":[1,2,}}}}'), pol=policy(limits={'max_depth': 2}))
V('0573-invalid-json-encoded-surrogate', 'body', 'UTF-8-encoded surrogate bytes (ED A0 80) are not UTF-8.',
  S('9.2'), jpost(b'{"a":"\xed\xa0\x80"}'))

# =========================================================================== formats (6.3)

def fmt_vec(id, desc, values, amb=()):
    body = '{' + ','.join('"v%02d":%s' % (i, J.dumps(v)) for i, v in enumerate(values)) + '}'
    V(id, 'formats', desc, S('6.3', '6.2'), jpost(body), amb=amb)


fmt_vec('0601-format-uuid', 'uuid: 8-4-4-4-12 hex, any case; wrong group length is not uuid.',
        ['550e8400-e29b-41d4-a716-446655440000', '550E8400-E29B-41D4-A716-446655440000',
         '550e8400e29b41d4a716446655440000', '550e8400-e29b-41d4-a716-44665544000', '{550e8400-e29b-41d4-a716-446655440000}'])
fmt_vec('0602-format-jwt', 'jwt: eyJ prefix, three dot-separated base64url parts, middle part non-empty.',
        ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln', 'eyJ.x.', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.',
         'eyJ..sig', 'eyXhbGc.eyJ.sig', 'eyJa.b.c.d', 'eyJ+.a.b'])
fmt_vec('0603-format-email', 'email: local part 1..64, at least two domain labels of 1..63.',
        ['mario.rossi@example.com', 'a@b.c', 'a@b', 'x' * 64 + '@shop.example', 'x' * 65 + '@shop.example',
         'a@' + 'd' * 63 + '.example', 'a@' + 'd' * 64 + '.example', 'mario rossi@example.com', 'a+tag%x@shop-1.example',
         'a@b..example', '@shop.example'])
fmt_vec('0604-format-datetime', 'datetime: T, t or space; Z, z or offset; fraction 1..9 digits.',
        ['2026-10-19T10:00:00Z', '2026-10-19t10:00:00z', '2026-10-19 10:00:00+02:00', '2026-10-19T10:00:00.123456789Z',
         '2026-10-19T10:00:00.1234567890Z', '2026-10-19T10:00:00', '2026-10-19T10:00Z', '9999-99-99T99:99:99Z',
         '2026-10-19T10:00:00.Z'])
fmt_vec('0605-format-date', 'date: shape only, no calendar check.', ['2026-10-19', '2026-13-45', '26-10-19', '2026-1-19',
                                                                     '2026/10/19'])
fmt_vec('0606-format-url', 'url: scheme of 1..16 chars, "://", then printable non-space ASCII.',
        ['https://shop.example/orders?id=1', 'a://x', 'abcdefghijklmnop://x', 'abcdefghijklmnopq://x',
         'https://shop.example/a b', '1http://x', 'https://', 'mailto:mario@example.com'])
fmt_vec('0607-format-ipv4', 'ipv4: four 0..255 octets without leading zeros.',
        ['192.168.0.1', '255.255.255.255', '256.1.1.1', '01.2.3.4', '0.0.0.0', '1.2.3', '1.2.3.4.5'])
fmt_vec('0608-format-phone', 'phone: + then 7..15 digits, first digit 1..9.',
        ['+3912345', '+391234', '+391234567890123', '+3912345678901234', '+0123456789', '+39 02 1234567'])
fmt_vec('0609-format-digits', 'digits: optional minus and 1..19 digits; 20+ digits fall to hex.',
        ['0', '-0', '184', '-184', '1234567890123456789', '12345678901234567890', '-1234567890123456789',
         '-12345678901234567890', '1.5', '-'])
fmt_vec('0610-format-hex', 'hex: 16 or more hex digits, any case.',
        ['deadbeefdeadbeef', 'DEADBEEFdeadbeef00', 'deadbeefdeadbee', 'deadbeefdeadbeeg'])
fmt_vec('0611-format-order', 'Detection order: uuid, jwt, email, datetime, date, url, ipv4, phone, digits, hex.',
        ['1234567890123456', '0123456789abcdef', 'https://a@b.example', '2026-10-19', '+1234567', '1234567',
         '1.2.3.4', 'eyJa@b.example', '00000000-0000-0000-0000-000000000000'])
fmt_vec('0612-format-printable-only', 'Formats apply only to printable ASCII strings: tabs, newlines and non-ASCII disable them.',
        ['mario.rossi@example.com\n', '2026-10-19\n', '\t184', 'mar\u00eco@example.com', '184\u00a0', '2026-10-19 '],
        )

# =========================================================================== length classes (6.2)

lens = [0, 1, 8, 9, 32, 33, 128, 129, 1024, 1025]
V('0651-length-classes-ascii', 'length-classes', 'Every length class boundary on ASCII strings (no format matches "x"*n).',
  S('6.2'), jpost('[' + ','.join('"%s"' % ('x' * n) for n in lens) + ']'))
V('0652-length-classes-utf8', 'length-classes', 'Length classes count UTF-8 bytes, not characters.', S('6.2'),
  jpost(J.dumps(['\u00e8' * 4, '\u00e8' * 5, '\U0001F600' * 2, '\U0001F600' * 3, '\u20ac' * 3, '\u20ac' * 11,
                 '\u00e8' * 16, '\u00e8' * 17])))
V('0653-length-classes-containers', 'length-classes', 'Collapsed containers use the class of the element / key count.',
  S('6.2', '5.1'),
  jpost('{"o0":{},"o1":{"a":1},"o5":{"a":1,"b":2,"c":3,"d":4,"e":5},"a0":[],"a4":[1,2,3,4],"a9":[1,2,3,4,5,6,7,8,9]}'),
  pol=policy(global_=scope(request=part(body={'$.o0': DROP, '$.o1': DROP, '$.o5': DROP, '$.a0': DROP,
                                              '$.a4': DROP, '$.a9': DROP}))))

# =========================================================================== numbers (10.2)

NUMS = ['0', '-0', '10', '1.0', '1.50', '15e-1', '-0.0', '1E3', '1e+3', '-1.5E-3', '123456789012345678901234567890',
        '1e21', '1e20', '123e18', '1234e18', '0.000001', '0.0000001', '1.5e-7', '0.0015', '100e-2', '0e10', '-0e-5',
        '1e400', '-1e-400', '0.5e1', '9007199254740993', '0.1', '-123.456e+2']
V('0701-number-shapes', 'numbers', 'drop:int only for integer lexemes; any fraction or exponent is drop:dec.',
  S('6.2'), jpost('[' + ','.join(NUMS) + ']'))
V('0702-number-keep-canonical', 'numbers', 'keep on numbers emits the canonical form computed from the lexeme.',
  S('5.3', '10.2'), jpost('[' + ','.join(NUMS) + ']'),
  pol=policy(services=[service('shop-api', request=part(body={'$[*]': KEEP}))]))
V('0703-number-keep-bool-null', 'numbers', 'keep on booleans and null emits them unchanged.', S('5.3'),
  jpost('{"t":true,"f":false,"n":null}'), pol=policy(services=[service('shop-api', request=part(body={'$.*': KEEP}))]))
V('0704-hmac-number-string-equality', 'hmac',
  '184, "184", 184.0, 1.84e2 and 18400e-2 give one token; "184.0" and " 184" differ; -0 equals "0".',
  S('7.2', '10.2'),
  jpost('{"a":184,"b":"184","c":184.0,"d":1.84e2,"e":18400e-2,"f":"184.0","g":" 184","h":-0,"i":"0","j":"-0"}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.*': HMAC('order')}))]))

# =========================================================================== hmac (7)

V('0801-hmac-default-domain', 'hmac', 'Domain "id" (the compiled default) differs from domain "order" for the same value.',
  S('5.4', '7.2'), jpost('{"a":"ORD-2026-000184","b":"ORD-2026-000184"}'),
  pol=policy(global_=scope(request=part(body={'$.a': HMAC(), '$.b': HMAC('order')}))))
V('0802-hmac-non-applicable', 'hmac', 'hmac on booleans and null falls back to drop.', S('5.1'),
  jpost('{"a":true,"b":null,"c":false}'), pol=policy(services=[service('shop-api', request=part(body={'$.*': HMAC()}))]))
V('0803-hmac-no-normalization', 'hmac', 'No Unicode normalization or trimming: NFC, NFD, padded and empty values differ.',
  S('7.2'), jpost('{"nfc":"caf\\u00e9","nfd":"cafe\\u0301","pad":" ORD","raw":"ORD","empty":""}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.*': HMAC()}))]))
V('0804-hmac-cross-part', 'hmac', 'Same domain and value in path, query, header, cookie and body: one token everywhere.',
  S('5.4', '7.2'),
  X('POST', '/orders/ORD-2026-000184', 'ref=ORD-2026-000184',
    h=[CT_JSON, ('X-Order', 'ORD-2026-000184'), ('Cookie', 'last=ORD-2026-000184')], body='{"orderId":"ORD-2026-000184"}'),
  pol=policy(services=[service('shop-api', ops={'POST /orders/{id}': op(request=part(
      path={'id': HMAC('order')}, query={'ref': HMAC('order')}, headers={'x-order': HMAC('order')},
      cookies={'last': HMAC('order')}, body={'$.orderId': HMAC('order')}))})]))
V('0805-hmac-long-key', 'hmac', 'A 64-byte key is accepted and gives a different token.', S('7.1', '7.2'),
  jpost('{"a":"ORD-2026-000184"}'), pol=policy(global_=scope(request=part(body={'$.a': HMAC('order')}))),
  key='k1:' + PL.b64url_nopad(bytes(range(64))))
V('0806-hmac-epoch', 'hmac', 'Another epoch gives another token for the same value.', S('7.2'),
  jpost('{"a":"ORD-2026-000184"}'), pol=policy(epoch='2026-11', global_=scope(request=part(body={'$.a': HMAC('order')}))))
V('0807-hmac-kid', 'hmac', 'The kid (up to 8 chars) is part of the token.', S('7.1', '7.2'),
  jpost('{"a":"ORD-2026-000184"}'),
  pol=policy(kid='kz9y8x7w', global_=scope(request=part(body={'$.a': HMAC('order')}))),
  key='kz9y8x7w:' + PL.b64url_nopad(bytes(range(32))))
V('0808-hmac-on-container', 'hmac', 'hmac on an object or array is not applied: children are visited.', S('5.1'),
  jpost('{"o":{"x":"a"},"l":["b",1]}'), pol=policy(global_=scope(request=part(body={'$.o': HMAC(), '$.l': HMAC()}))))
V('0809-hmac-non-ascii', 'hmac', 'hmac of a non-ASCII and an astral string (UTF-8 bytes).', S('7.2'),
  jpost('{"a":"Citt\\u00e0","b":"\\ud83d\\udce6"}'), pol=policy(services=[service('shop-api', request=part(body={'$.*': HMAC('city')}))]))

# =========================================================================== keep / bucket / drop (5)

V('0901-keep-string-limit', 'actions', 'keep_max_bytes=64 on UTF-8 bytes: 64 kept, 65 dropped, 63+2-byte char dropped.',
  S('5.3'), jpost(J.dumps({'a': 'x' * 64, 'b': 'x' * 65, 'c': 'x' * 63 + '\u00e8', 'd': 'x' * 62 + '\u00e8'})),
  pol=policy(services=[service('shop-api', request=part(body={'$.*': KEEP}))]))
V('0902-keep-max-zero', 'actions', 'keep_max_bytes=0 keeps only the empty string.', S('5.3'), jpost('{"a":"","b":"x"}'),
  pol=policy(limits={'keep_max_bytes': 0}, services=[service('shop-api', request=part(body={'$.*': KEEP}))]))
V('0903-keep-escaping', 'canonical', 'Kept strings are escaped per tt-cjson: \\uXXXX lowercase, no short escapes, "/" unescaped.',
  S('10.1', '5.3'),
  jpost('{"q":"say \\"hi\\"","bs":"a\\\\b","nl":"a\\nb","tab":"\\t","del":"\\u007f","sl":"a/b","e":"\\u00e8","astral":"\\ud83d\\ude00","nul":"\\u0000","bmp":"\\uffff"}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.*': KEEP}))]))
V('0904-bucket-num', 'actions', 'bucket(num): below, inside, on a bound, above.', S('5.5'),
  jpost('[-1,0,49.999,50,73.40,100,249.99,250,1000]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BNUM(0, 50, 100, 250)}))))
V('0905-bucket-num-extremes', 'actions', 'bucket(num) with lexemes that overflow or underflow a double.', S('5.5'),
  jpost('[1e400,-1e400,1e-400,-1e-400,123456789012345678901234567890]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BNUM(0, 50, 100, 250)}))))
V('0906-bucket-num-single-bound', 'actions', 'A single bound gives only <b0 and >=b0.', S('5.5'), jpost('[9,10,11]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BNUM(10)}))))
V('0907-bucket-num-bounds-canonical', 'actions', 'Bounds are written in canonical form, negatives included.',
  S('5.5', '10.2'), jpost('[-20,-10,0,0.5,7,1e22]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BNUM(-10, 0.5, '1e+21')}))))
V('0908-bucket-num-wrong-type', 'actions', 'bucket(num) on strings, booleans and null falls back to drop.', S('5.1', '5.5'),
  jpost('["73","x",true,null]'), pol=policy(global_=scope(request=part(body={'$[*]': BNUM(0, 50)}))))
V('0909-bucket-time-units', 'actions', 'bucket(time) units year, month, day, hour.', S('5.5'),
  jpost('{"y":"2026-10-19T10:15:00Z","m":"2026-10-19T10:15:00Z","d":"2026-10-19T10:15:00Z","h":"2026-10-19T10:15:00Z"}'),
  pol=policy(global_=scope(request=part(body={'$.y': BTIME('year'), '$.m': BTIME('month'),
                                              '$.d': BTIME('day'), '$.h': BTIME('hour')}))))
V('0910-bucket-time-utc', 'actions', 'Offsets are converted to UTC before truncation (crossing day and year).', S('5.5'),
  jpost('["2026-12-31T23:30:00-01:00","2027-01-01T00:30:00+01:00","2026-10-19 23:59:59.999+00:00","2026-10-19t05:00:00z"]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BTIME('hour')}))))
V('0911-bucket-time-date-only', 'actions', 'A date without time counts as T00:00:00Z.', S('5.5'), jpost('["2026-10-19"]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BTIME('hour')}))))
V('0912-bucket-time-invalid-dates', 'actions', 'Calendar-invalid values fall back to drop (their regex shape).',
  S('5.5', '6.3'),
  jpost('["2026-02-29","2028-02-29","2026-13-01","2026-04-31","2026-10-19T24:00:00Z","2026-10-19T10:60:00Z",'
        '"2026-10-19T10:00:60Z","2026-00-10","2026-10-00","1900-02-29","2000-02-29","0000-01-01","0001-01-01",'
        '"0001-01-01T00:30:00+01:00","9999-12-31T23:30:00-01:00","2026-10-19T10:00:00+23:59","2026-10-19T10:00:00+24:00",'
        '"2026-10-19T10:00:00-00:60"]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BTIME('day')}))))
V('0913-bucket-time-wrong-type', 'actions', 'bucket(time) on numbers and non-date strings falls back to drop.',
  S('5.1', '5.5'), jpost('[20261019,"19/10/2026","yesterday"]'),
  pol=policy(global_=scope(request=part(body={'$[*]': BTIME('day')}))))
V('0914-drop-containers', 'actions', 'Explicit drop on containers collapses them without visiting children.', S('5.1', '6.2'),
  jpost('{"addr":{"street":"Via Roma 1","city":"Torino"},"items":[1,2,3,4,5],"leaf":"x","n":{}}'),
  pol=policy(global_=scope(request=part(body={'$.addr': DROP, '$.items': DROP, '$.leaf': DROP, '$.n': DROP}))))
V('0915-keep-on-container', 'actions', 'keep on a container is not applied: children get their own rules (default drop).',
  S('5.1'), jpost('{"addr":{"city":"Torino"},"tags":["a"]}'),
  pol=policy(global_=scope(request=part(body={'$.addr': KEEP, '$.tags': KEEP}))))
V('0916-drop-root', 'actions', 'Explicit drop on $ collapses the whole body.', S('5.0', '5.1'), jpost('{"a":1,"b":2}'),
  pol=policy(global_=scope(request=part(body={'$': DROP}))))
V('0917-keep-root-scalar', 'actions', '$ matches a top-level scalar.', S('5.0'), jpost('"CREATED"'),
  pol=policy(global_=scope(request=part(body={'$': KEEP}))))

# =========================================================================== rule selection (5.0)

V('0951-rules-op-over-global', 'rules', 'Operation rules win over global rules for the same leaf.', S('5.0'),
  X('GET', '/orders/1', rh=[CT_JSON], rbody='{"status":"OPEN","note":"x"}'),
  pol=policy(global_=scope(response=part(body={'$.status': KEEP, '$.note': KEEP})),
             services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.*': HMAC('x')}))})]))
V('0952-rules-specificity-names', 'rules', 'More .name steps wins: $.a.b over $.*.b and $.a.*.', S('5.0'),
  jpost('{"a":{"b":"v1","c":"v2"},"z":{"b":"v3"}}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.a.b': KEEP, '$.*.b': HMAC('star'), '$.a.*': HMAC('astar')}))]))
V('0953-rules-specificity-bytes', 'rules', 'Equal .name count and length: the smaller tt-path by bytes wins ($.*.b < $.a.*).',
  S('5.0'), jpost('{"a":{"b":"v"}}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.*.b': KEEP, '$.a.*': HMAC()}))]))
ERR_POL = policy(global_=scope(errors=part(body={'$.error.code': KEEP})))
V('0954-rules-errors-200', 'rules', 'errors rules do not apply below status 400.', S('5.0'),
  jresp('{"error":{"code":"E_STOCK","message":"x"}}', status=200), pol=ERR_POL)
V('0955-rules-errors-404', 'rules', 'errors rules apply to responses with status >= 400.', S('5.0'),
  jresp('{"error":{"code":"E_STOCK","message":"Order ORD-1 for mario.rossi@example.com"}}', status=404), pol=ERR_POL)
V('0956-rules-errors-399-400', 'rules', 'Boundary: status 399 does not use errors rules.', S('5.0'),
  jresp('{"error":{"code":"E_STOCK"}}', status=399), pol=ERR_POL)
V('0957-rules-errors-service-first', 'rules', 'Service errors rules come before global errors rules.', S('5.0'),
  jresp('{"error":{"code":"E_STOCK"}}', status=409),
  pol=policy(global_=scope(errors=part(body={'$.error.code': KEEP})),
             services=[service('shop-api', errors=part(body={'$.error.code': HMAC('err')}))]))
V('0958-rules-errors-over-service-response', 'rules', 'errors rules come before service response rules.', S('5.0'),
  jresp('{"code":"E1"}', status=500),
  pol=policy(global_=scope(errors=part(body={'$.code': HMAC('err')})),
             services=[service('shop-api', response=part(body={'$.code': KEEP}))]))
V('0959-rules-container-drop-group', 'rules',
  'A global drop on a container is ignored when an operation rule (a stronger group) reaches a descendant.',
  S('5.0', '5.1'), X('GET', '/orders', rh=[CT_JSON], rbody='{"items":[{"status":"OPEN"}]}'),
  pol=policy(global_=scope(response=part(body={'$.items': DROP})),
             services=[service('shop-api', ops={'GET /orders': op(response=part(body={'$.items[*].status': KEEP}))})]))
V('0960-rules-group-shadow', 'rules', 'A keep on a container is ignored, so it does not shadow a weaker drop on the same container.',
  S('5.0', '5.1'), X('GET', '/orders', rh=[CT_JSON], rbody='{"items":[{"status":"OPEN"}]}'),
  pol=policy(global_=scope(response=part(body={'$.items': DROP})),
             services=[service('shop-api', ops={'GET /orders': op(response=part(body={'$.items': KEEP}))})]),
  amb=['A-CONTAINER-KEEP'])
V('0961-rules-array-steps', 'rules', '[*] matches array elements at any index, nested.', S('5.0'),
  jpost('{"m":[["a","b"],["c"]],"n":[{"id":"x"},{"id":"y"}]}'),
  pol=policy(services=[service('shop-api', request=part(body={'$.m[*][*]': KEEP, '$.n[*].id': HMAC()}))]))
V('0962-rules-name-on-collapsed-key', 'rules', '.name matches the original key even when that key collapses (hex key).',
  S('5.0', '9.3'), jpost('{"deadbeefdeadbeef":"v","other0000000000a":"w"}'),
  pol=policy(global_=scope(request=part(body={'$.deadbeefdeadbeef': KEEP}))))
V('0963-rules-headers-by-group', 'rules', 'Header rules follow the same group order (operation, service, global).',
  S('5.0', '8.1'),
  X('GET', '/orders', h=[('X-A', 'a'), ('X-B', 'b'), ('X-C', 'c')]),
  pol=policy(global_=scope(request=part(headers={'x-a': KEEP, 'x-b': KEEP, 'x-c': KEEP})),
             services=[service('shop-api', request=part(headers={'x-b': HMAC()}),
                               ops={'GET /orders': op(request=part(headers={'x-a': HMAC('op')}))})]))
V('0964-rules-request-response-separate', 'rules', 'request rules never apply to the response and vice versa.', S('5.0'),
  X('POST', '/', h=[CT_JSON], body='{"a":"x"}', rh=[CT_JSON], rbody='{"a":"y"}'),
  pol=policy(global_=scope(request=part(body={'$.a': KEEP}))))

# =========================================================================== limits (6.4, 9)

def nest(n):
    return '[' * n + ']' * n


V('1001-depth-default', 'limits', 'Default max_depth 32: the container at depth 33 becomes trunc:depth.', S('9.2', '6.4'),
  jpost(nest(33)))
V('1002-depth-32-ok', 'limits', 'Depth exactly 32 is kept.', S('9.2'), jpost(nest(32)))
V('1003-depth-custom', 'limits', 'max_depth 2: objects at depth 3 are trunc:depth, scalars at depth 3 are kept as leaves.',
  S('9.2', '6.4'), jpost('{"a":{"b":{"c":1},"d":2,"e":[]},"f":[3,[4]]}'), pol=policy(limits={'max_depth': 2}))
V('1004-depth-one', 'limits', 'max_depth 1: the root is visited, every child container is trunc:depth.', S('9.2'),
  jpost('{"a":{},"b":[1],"c":"x"}'), pol=policy(limits={'max_depth': 1}))
V('1005-depth-adversarial', 'limits', '3000 nested arrays: no crash, trunc:depth at 33.', S('9.2', '6.4'), jpost(nest(3000)))
V('1010-array-32', 'limits', 'An array of exactly 32 elements is not truncated.', S('9.4'),
  jpost('[' + ','.join(['1'] * 32) + ']'))
V('1011-array-33', 'limits', 'An array of 33: 32 elements then trunc:n:<class of 33>.', S('9.4', '6.4'),
  jpost('[' + ','.join(['1'] * 33) + ']'))
V('1012-array-custom', 'limits', 'max_array 2.', S('9.4'), jpost('[1,"a",true]'), pol=policy(limits={'max_array': 2}))
V('1013-array-zero', 'limits', 'max_array 0: a non-empty array holds only the marker; an empty one stays empty.', S('9.4'),
  jpost('{"a":[1,2],"b":[]}'), pol=policy(limits={'max_array': 0}))
V('1020-keys-limit', 'limits', 'max_keys 3 on 5 keys: the first 3 survive, {trunc} = trunc:keys:<class of 5>.',
  S('6.4', '9.3'), jpost('{"a":1,"b":2,"c":3,"d":4,"e":5}'), pol=policy(limits={'max_keys': 3}))
V('1021-keys-limit-collapsed', 'limits', 'Collapsed keys count towards max_keys.', S('9.3', '6.4'),
  jpost('{"mario.rossi@example.com":1,"giulia.neri@example.com":2,"a":3,"b":4}'), pol=policy(limits={'max_keys': 3}))
V('1030-body-at-limit', 'limits', 'A body exactly max_body_bytes long is parsed.', S('9.1'), jpost('{"a":"xxxx"}'),
  pol=policy(limits={'max_body_bytes': 12}))
V('1031-body-over-limit', 'limits', 'One byte over max_body_bytes: body trunc:size, size lmax.', S('9.0', '6.4'),
  jpost('{"a":"xxxxx"}'), pol=policy(limits={'max_body_bytes': 12}))
V('1032-body-over-limit-large', 'limits', 'A body far over the limit: trunc:size without class.', S('6.4', '9.0'),
  jpost('{"a":"' + 'x' * 4992 + '"}'), pol=policy(limits={'max_body_bytes': 1000}))
V('1033-body-over-limit-non-json', 'limits', 'The size check runs before the content-type choice.', S('9.1'),
  X('POST', '/', h=[('Content-Type', 'text/plain')], body='x' * 2049), pol=policy(limits={'max_body_bytes': 2048}))
V('1034-body-streaming-prefix', 'limits', 'A read prefix with a known total above the limit: trunc:size on the total.',
  S('9.1'), jpost('{"items":[', req_total=3 * 1048576))
V('1035-body-unknown-total', 'limits', 'Unknown total length counts as over the limit.', S('9.1'),
  jpost('{"a":1}', req_total='unknown'))
V('1036-body-default-limit', 'limits',
  'Default max_body_bytes 1048576: a total of 1048577 bytes is truncated (trunc:size, size lmax). Only a prefix is passed.',
  S('9.0', '6.4'), X('POST', '/', h=[('Content-Type', 'text/plain')], body='y' * 64, req_total=1048577))
V('1038-body-default-limit-equal', 'limits',
  'A total of exactly 1048576 bytes is not over the default limit: drop:bytes:lmax. Only a prefix is passed.',
  S('9.0'), X('POST', '/', h=[('Content-Type', 'text/plain')], body='y' * 64, req_total=1048576))
V('1037-body-max-zero', 'limits', 'max_body_bytes 0: an empty JSON body is absent, a one-byte body is truncated.', S('9.0'),
  jpost('', rbody='1', rh=[CT_JSON]), pol=policy(limits={'max_body_bytes': 0}))

# =========================================================================== routing (3)

SHOP = policy(services=[service('shop-api', ops={
    'GET /orders/{id}': op(request=part(path={'id': HMAC('order')})),
    'GET /orders/search': op(),
    'GET /{a}/{b}': op(),
    'POST /orders': op(),
})])
V('1101-route-template-param', 'routing', 'Template match: op is the template, the parameter gets its path rule.',
  S('3.2', '4.2'), X('GET', '/orders/ORD-2026-000184'), pol=SHOP)
V('1102-route-most-literals', 'routing', 'The template with more literals wins (/orders/search over /orders/{id}).',
  S('3.2'), X('GET', '/orders/search'), pol=SHOP)
V('1103-route-key-order', 'routing', 'Equal literal count: the smaller key by bytes wins.', S('3.2'), X('GET', '/x/x'),
  pol=policy(services=[service('shop-api', ops={'GET /{a}/x': op(request=part(path={'a': KEEP})),
                                                'GET /x/{b}': op(request=part(path={'b': HMAC()}))})]))
V('1104-route-method-mismatch', 'routing', 'No template for the method: raw route.', S('3.2'),
  X('DELETE', '/orders/ORD-2026-000184'), pol=SHOP)
V('1105-route-segment-count', 'routing', 'Templates must have the same number of segments.', S('3.2'),
  X('GET', '/orders/ORD-1/items/3'), pol=SHOP)
V('1106-route-param-no-rule', 'routing', 'A template parameter without a rule is {drop:<shape>}.', S('4.2'),
  X('GET', '/customers/mario.rossi%40example.com'), pol=SHOP)
V('1107-route-param-invalid', 'routing', 'A parameter matches only valid segments: an invalid one gives the raw route.',
  S('4.2'), X('GET', '/orders/%ff'), pol=SHOP)
V('1108-route-param-actions', 'routing', 'keep and bucket(time) on path parameters.', S('4.2', '5.5'),
  X('GET', '/reports/2026-10-19/OPEN'),
  pol=policy(services=[service('shop-api', ops={'GET /reports/{day}/{state}': op(
      request=part(path={'day': BTIME('month'), 'state': KEEP}))})]))
V('1109-route-framework', 'routing', 'framework_route /orders/:id selects the policy operation GET /orders/{id}.',
  S('3.3'), X('GET', '/orders/ORD-2026-000184', framework='express', framework_route='/orders/:id'), pol=SHOP)
V('1110-route-framework-other-name', 'routing',
  'framework_route /orders/:orderId matches GET /orders/{id} (same literals and parameter positions).',
  S('3.3'), X('GET', '/orders/ORD-2026-000184', framework='express', framework_route='/orders/:orderId'), pol=SHOP)
V('1111-route-framework-fallback', 'routing',
  'A framework_route with no policy operation falls back to policy template matching.', S('3.2'),
  X('GET', '/orders/search', framework='express', framework_route='/orders/:id/extra'), pol=SHOP)
V('1113-route-method-case', 'routing', 'The method is uppercased before matching.', S('3.2'), X('post', '/orders'), pol=SHOP)
V('1114-route-method-other', 'routing', 'Methods outside ^[A-Z]{1,16}$ after uppercasing become OTHER.', S('3.2'),
  X('M-SEARCH', '/x'), pol=AUTO)
V('1115-route-method-17', 'routing', 'A 17-letter method becomes OTHER.', S('3.2'), X('ABCDEFGHIJKLMNOPQ', '/x'), pol=AUTO)
V('1116-route-method-non-ascii', 'routing', 'ASCII-only uppercasing: a non-ASCII method becomes OTHER.', S('3.2'),
  X('g\u00e9t', '/x'), pol=AUTO)
V('1117-route-literal-case', 'routing', 'Template literals are compared exactly: /Orders/1 does not match /orders/{id}.',
  S('3.2'), X('GET', '/Orders/1'), pol=SHOP)
V('1118-route-literal-decoded', 'routing', 'Literals are compared with the decoded segment: /%6Frders/1 matches.',
  S('3.2', '4.1'), X('GET', '/%6Frders/1'), pol=SHOP)
V('1119-route-truncated-path', 'routing', 'A path with more than 32 segments never matches a template.', S('4.1', '3.2'),
  X('GET', '/' + '/'.join(['a'] * 33)), pol=policy(services=[service('shop-api', ops={
      'GET ' + '/a' * 32: op()})]))
V('1120-route-service-name-mismatch', 'routing', 'A service_name not in policy: service = service_name, only global rules.',
  S('3.1'), X('GET', '/orders/1', service='billing-api', rh=[CT_JSON], rbody='{"status":"OPEN"}'),
  pol=policy(global_=scope(response=part(body={'$.status': KEEP})),
             services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.status': HMAC()}))})]))

CARRIER = policy(services=[
    service('carrier', base='https://api.carrier.example', ops={
        'POST /v1/shipments': op(request=part(body={'$.orderId': HMAC('order')})),
        'GET /v1/shipments/{id}': op(request=part(path={'id': HMAC('shipment')}))}),
    service('carrier-v2', base='https://api.carrier.example/v2', ops={'GET /tracking/{id}': op()}),
])
V('1130-outbound-base', 'routing', 'Outbound: match.base selects the service; op from its templates.', S('3.1', '3.2'),
  X('POST', '/v1/shipments', h=[CT_JSON], body='{"orderId":"ORD-2026-000184"}', dir='outbound',
    url_base='https://api.carrier.example'), pol=CARRIER)
V('1131-outbound-base-path', 'routing',
  'A base with a path: the longest base wins, the operation uses the remainder, req.path stays complete.',
  S('3.1', '3.2'), X('GET', '/v2/tracking/SHP-77120', dir='outbound', url_base='https://api.carrier.example'), pol=CARRIER)
V('1132-outbound-base-boundary', 'routing', 'A base matches only at a segment boundary: /v20 is not under /v2.', S('3.1'),
  X('GET', '/v20/tracking/SHP-77120', dir='outbound', url_base='https://api.carrier.example'), pol=CARRIER)
V('1133-outbound-encoded-slash', 'routing', '/v2%2Ftracking is one segment and is not under the base /v2.', S('3.1', '4.1'),
  X('GET', '/v2%2Ftracking/SHP-77120', dir='outbound', url_base='https://api.carrier.example'), pol=CARRIER)
V('1134-outbound-unmatched-host', 'routing',
  'No base matches and the host is not listed: the host pattern, default port removed (spec v1.5; strict copy in 1901).',
  S('3.1', '3.5'), X('GET', '/v1/rates', dir='outbound', url_base='https://payments.example:443'), pol=CARRIER)
V('1135-outbound-hosts-allow-port', 'routing', 'A host in segments.hosts_allow leaves in clear, lowercased, with its non-default port.',
  S('3.1'), X('GET', '/', dir='outbound', url_base='http://Stock.Warehouse.example:8080'),
  pol=policy(hosts_allow=['stock.warehouse.example:8080']))
V('1136-outbound-host-invalid', 'routing', 'A host outside [a-z0-9.-] gives host:invalid.', S('3.1'),
  X('GET', '/', dir='outbound', url_base='https://st\u00f6ck.example'))
V('1137-net-error', 'routing', 'net_error: no resp part (service is the host pattern, spec v1.5).', S('2', '3.5'),
  X('GET', '/v1/rates', dir='outbound', url_base='https://payments.example', net_error='timeout'))

# =========================================================================== discovery (15)

NOW = '2026-10-23T10:00:00Z'
DISC = policy(auto_words=True, discovery=(True, '2026-10-26T10:00:00Z'),
              global_=scope(request=part(headers={'content-type': KEEP}, body={'$.status': KEEP, '$.meta': DROP})))
V('1201-discovery-basic', 'discovery',
  'Discovery on: every default-dropped leaf adds path -> tkd token (path, query, headers, cookies, body).',
  S('15'),
  X('POST', '/customers/C-10042/orders', 'page=2&page=3', h=[CT_JSON, ('X-Request-Id', 'req-1'), ('Cookie', 'sid=abc')],
    body='{"items":[{"sku":"A-1","qty":2},{"sku":"B-2","qty":10}],"status":"OPEN","meta":{"x":1},"flag":true,"none":null}',
    rh=[CT_JSON], rbody='{"id":"ORD-1"}'), pol=DISC, now=NOW)
V('1202-discovery-expired', 'discovery', 'expires_at in the past: no disc.', S('15'),
  jpost('{"a":"x"}'), pol=DISC, now='2026-10-27T00:00:00Z')
V('1203-discovery-expiry-equal', 'discovery', 'expires_at equal to now is not in the future: no disc.', S('15'),
  jpost('{"a":"x"}'), pol=DISC, now='2026-10-26T10:00:00Z')
V('1204-discovery-disabled', 'discovery', 'enabled=false: no disc.', S('15'), jpost('{"a":"x"}'),
  pol=policy(discovery=(False, '2026-10-26T10:00:00Z')), now=NOW)
V('1205-discovery-min-value', 'discovery', 'One token per path: the leaf with the smallest canonical bytes ("10" < "9").',
  S('15'), jpost('{"v":[9,"10",9.0,"b"]}'), pol=DISC, now=NOW)
V('1206-discovery-collapsed', 'discovery', 'Collapsed keys appear as .* in discovery paths; invalid strings are skipped.',
  S('15'), jpost('{"mario.rossi@example.com":"x","deadbeefdeadbeef":{"a":"y"},"bad":"\\ud800"}'), pol=DISC, now=NOW)
V('1207-discovery-template', 'discovery', 'Template parameters without a rule are default drops: req.path.<index>.',
  S('15', '4.2'), X('GET', '/orders/ORD-1/items/7'),
  pol=policy(discovery=(True, '2026-10-26T10:00:00Z'),
             services=[service('shop-api', ops={'GET /orders/{id}/items/{n}': op(request=part(path={'id': HMAC('order')}))})]),
  now=NOW)

# =========================================================================== subject and sampling (11, 12)

JWT_SUB = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":"c-10042","iat":1792404000}') + '.c2lnbmF0dXJl'
JWT_NUM = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":10042}') + '.c2ln'
JWT_STR_NUM = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":"10042"}') + '.c2ln'
ID_HDR = {'from': 'header', 'name': 'x-customer-id'}
ID_JWT = {'from': 'header', 'name': 'authorization', 'jwt_claim': 'sub'}
ID_COOKIE = {'from': 'cookie', 'name': 'uid'}

V('1301-subject-header', 'subject-sampling', 'Subject from a raw header value: subject = HMAC with domain "subject".',
  S('11', '12'), X('GET', '/', h=[('X-Customer-Id', 'C-10042')]), pol=policy(identity=ID_HDR))
V('1302-subject-jwt', 'subject-sampling', 'Subject from a JWT claim after a case-insensitive "Bearer " prefix.', S('11'),
  X('GET', '/', h=[('Authorization', 'bearer ' + JWT_SUB)]), pol=policy(identity=ID_JWT))
V('1303-subject-jwt-number', 'subject-sampling', 'A numeric claim uses its canonical form: 10042 and "10042" give one subject.',
  S('11', '7.2'), X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_NUM)]), pol=policy(identity=ID_JWT))
V('1304-subject-jwt-string-number', 'subject-sampling', 'Same subject as 1303, from the string claim "10042".', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_STR_NUM)]), pol=policy(identity=ID_JWT))
V('1305-subject-cookie', 'subject-sampling', 'Subject from a cookie.', S('11'),
  X('GET', '/', h=[('Cookie', 'lang=it; uid=C-10042')]), pol=policy(identity=ID_COOKIE))
V('1306-subject-missing', 'subject-sampling', 'No subject header: subject absent, random sampling.', S('11', '12'),
  X('GET', '/'), pol=policy(identity=ID_HDR))
V('1307-subject-jwt-malformed', 'subject-sampling', 'A JWT whose payload is not base64url JSON: subject absent.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.not*base64.sig')]), pol=policy(identity=ID_JWT))
V('1308-subject-jwt-no-claim', 'subject-sampling', 'The claim is missing: subject absent.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"iss":"shop"}') + '.c2ln')]),
  pol=policy(identity=ID_JWT))
V('1309-subject-not-equal-hmac', 'subject-sampling',
  'The subject token (domain subject) differs from an hmac(id) of the same value in a header.', S('11', '7.2'),
  X('GET', '/', h=[('X-Customer-Id', 'C-10042')]),
  pol=policy(identity=ID_HDR, global_=scope(request=part(headers={'x-customer-id': HMAC()}))))


def sample_u(domain, value):
    s = Sanitizer(POLICIES['empty'], 'k1', KEY_BYTES, NOW)
    return int.from_bytes(s.mac(domain, value)[:4], 'big') % 10000


u_sub = sample_u('sample', b'C-10042')
V('1320-sampling-subject-in', 'subject-sampling', 'Subject sampling: u mod 10000 < rate_bp (rate_bp = u+1) is sampled.',
  S('12'), X('GET', '/', h=[('X-Customer-Id', 'C-10042')]), pol=policy(identity=ID_HDR, rate_bp=u_sub + 1))
V('1321-sampling-subject-out', 'subject-sampling', 'Subject sampling: rate_bp = u is not sampled.', S('12'),
  X('GET', '/', h=[('X-Customer-Id', 'C-10042')]), pol=policy(identity=ID_HDR, rate_bp=u_sub))
TRACE = '4bf92f3577b34da6a3ce929d0e0e4736'
u_tr = sample_u('sample-trace', TRACE.encode())
V('1322-sampling-trace-in', 'subject-sampling', 'Trace sampling with rate_bp = u+1: sampled.', S('12'),
  X('GET', '/', trace_id=TRACE), pol=policy(rate_bp=u_tr + 1))
V('1323-sampling-trace-out', 'subject-sampling', 'Trace sampling with rate_bp = u: not sampled.', S('12'),
  X('GET', '/', trace_id=TRACE), pol=policy(rate_bp=u_tr))
BAGGAGE_POL = policy(trust_baggage=True, services=[service('shop-api', internal=True)])
V('1324-sampling-baggage-on', 'subject-sampling',
  'trust_baggage on an internal service: baggage tt.s=1 wins over rate 0 and over the subject.', S('12'),
  X('GET', '/', h=[('Baggage', 'tenant=shop, tt.s = 1;prop=x'), ('X-Customer-Id', 'C-10042')], trace_id=TRACE),
  pol=policy(identity=ID_HDR, rate_bp=0, trust_baggage=True, services=[service('shop-api', internal=True)]))
V('1325-sampling-baggage-off', 'subject-sampling', 'Baggage tt.s=0: not sampled, even at rate 10000.', S('12'),
  X('GET', '/', h=[('baggage', 'tt.s=0')]), pol=BAGGAGE_POL)
V('1326-sampling-baggage-other-value', 'subject-sampling', 'tt.s=2 is ignored: falls through to the trace.', S('12'),
  X('GET', '/', h=[('baggage', 'tt.s=2')], trace_id=TRACE),
  pol=policy(rate_bp=u_tr + 1, trust_baggage=True, services=[service('shop-api', internal=True)]))
V('1327-sampling-random-zero', 'subject-sampling', 'Random sampling with rate_bp 0: never sampled.', S('12'),
  X('GET', '/'), pol=policy(rate_bp=0))
V('1328-sampling-subject-before-trace', 'subject-sampling', 'With subject and trace, the subject decides.', S('12'),
  X('GET', '/', h=[('X-Customer-Id', 'C-10042')], trace_id=TRACE), pol=policy(identity=ID_HDR, rate_bp=u_sub + 1))

# =========================================================================== refusal (7.1, policy.md 4)

V('1401-refuse-no-key', 'refusal', 'No HMAC key: the source does not capture (key_missing).', S('7.1'), X('GET', '/'), key=None)
V('1402-refuse-short-key', 'refusal', 'A 31-byte key: key_missing.', S('7.1'), X('GET', '/'),
  key='k1:' + PL.b64url_nopad(bytes(range(31))))
V('1403-refuse-key-no-colon', 'refusal', 'Key material without "<kid>:": key_missing.', S('7.1'), X('GET', '/'),
  key=PL.b64url_nopad(bytes(range(32))))
V('1404-refuse-key-bad-kid', 'refusal', 'A kid outside ^[a-z0-9]{1,8}$: key_missing.', S('7.1'), X('GET', '/'),
  key='K1:' + PL.b64url_nopad(bytes(range(32))))
V('1405-refuse-key-padding', 'refusal', 'base64url with "=" padding is malformed: key_missing.', S('7.1'), X('GET', '/'),
  key='k1:' + PL.b64url_nopad(bytes(range(32))) + '=')
V('1406-refuse-key-std-base64', 'refusal', 'Standard base64 characters (+ /) are malformed: key_missing.', S('7.1'),
  X('GET', '/'), key='k1:' + '+/' * 22)
V('1407-refuse-kid-mismatch', 'refusal', 'Key kid differs from policy hmac.kid: key_mismatch.', S('7.1'), X('GET', '/'),
  key='k2:' + PL.b64url_nopad(bytes(range(32))))
V('1408-refuse-no-policy', 'refusal', 'No policy: no_policy.', S('7.1'), X('GET', '/'), pol=None)
V('1409-refuse-body-format', 'refusal', 'Unknown body format tt.policy.body/v2: policy_rejected.', ['policy.md#4'],
  X('GET', '/'), pol=policy(fmt='tt.policy.body/v2'))
V('1410-refuse-reserved-domain', 'refusal', 'A rule using the reserved domain "subject": policy_rejected.',
  S('7.2'), X('GET', '/'), pol=policy(global_=scope(request=part(body={'$.a': HMAC('subject')}))))

FLEET_PUB = PL.b64url_nopad(public_key(FLEET_SEED))
FLEET_KEYS = {FLEET_KID: FLEET_PUB}
ENV_BODY = policy(global_=scope(request=part(body={'$.orderId': HMAC('order')})))


def envelope(body=ENV_BODY, mutate=None, policy_id='p-conformance', version=1, issued_seq=1, prefix=PL.SIG_PREFIX):
    raw = J.dumps(body).encode('utf-8')
    env = PL.make_envelope(raw, FLEET_SEED, FLEET_KID, policy_id, N(version), N(issued_seq), prefix)
    if mutate:
        mutate(env)
    return ('env', env, FLEET_KEYS)


ENV_INPUT = jpost('{"orderId":"ORD-2026-000184"}')
V('1420-envelope-valid', 'refusal', 'A correctly signed envelope is accepted and used.', ['policy.md#3'], ENV_INPUT,
  pol=envelope())


def _flip_sig(e):
    s = e['signature']['sig']
    e['signature']['sig'] = ('B' if s[0] == 'A' else 'A') + s[1:]


V('1421-envelope-bad-signature', 'refusal', 'Signature does not verify: policy_rejected.', ['policy.md#3', 'policy.md#4'],
  ENV_INPUT, pol=envelope(mutate=_flip_sig))
V('1422-envelope-hash-mismatch', 'refusal', 'hash does not match the body bytes: policy_rejected.', ['policy.md#3'],
  ENV_INPUT, pol=envelope(mutate=lambda e: e.update(hash='sha256:' + '0' * 64)))
V('1423-envelope-unknown-kid', 'refusal', 'Unknown signing kid: policy_rejected.', ['policy.md#4'], ENV_INPUT,
  pol=envelope(mutate=lambda e: e['signature'].update(kid='fleet-other')))
V('1424-envelope-format-v2', 'refusal', 'Unknown envelope format tt.policy.compiled/v2: policy_rejected.',
  ['policy.md#3'], ENV_INPUT, pol=envelope(mutate=lambda e: e.update(format='tt.policy.compiled/v2')))
V('1425-envelope-id-mismatch', 'refusal', 'Envelope policy_id differs from the body: policy_rejected.', ['policy.md#3'],
  ENV_INPUT, pol=envelope(policy_id='p-other'))
V('1426-envelope-version-mismatch', 'refusal', 'Envelope version differs from the body: policy_rejected.',
  ['policy.md#3'], ENV_INPUT, pol=envelope(version=2))
V('1427-envelope-padded-body', 'refusal', 'body_b64 with "=" padding is not base64url without padding: policy_rejected.',
  ['policy.md#3'], ENV_INPUT,
  pol=envelope(body=policy(global_=scope(request=part(body={'$.orderId': HMAC('ord')}))),
               mutate=lambda e: e.update(body_b64=e['body_b64'] + '=' * (-len(e['body_b64']) % 4 or 4))))
V('1428-envelope-alg', 'refusal', 'signature.alg other than Ed25519: policy_rejected.', ['policy.md#3'], ENV_INPUT,
  pol=envelope(mutate=lambda e: e['signature'].update(alg='HS256')))
V('1429-envelope-body-v2', 'refusal', 'Signed body with format tt.policy.body/v2: policy_rejected.', ['policy.md#4'],
  ENV_INPUT, pol=envelope(body=policy(fmt='tt.policy.body/v2')))

# =========================================================================== adversarial

V('1501-adv-pii-in-keys', 'adversarial', 'PII used as JSON keys (e-mail, phone, card, uuid) must collapse, never leak.',
  S('9.3', '13'),
  jpost('{"mario.rossi@example.com":{"+390212345678":"x"},"4111111111111111":1,"a50e8400-e29b-41d4-a716-446655440000":2}'))
V('1502-adv-pii-in-path', 'adversarial', 'PII in raw and percent-encoded path segments, also with auto_words.', S('4.2', '13'),
  X('GET', '/customers/mario.rossi@example.com/cards/4111111111111111/phone/%2B390212345678/name/giulia'), pol=AUTO)
V('1503-adv-pii-in-error-body', 'adversarial', 'Error body echoing the request: only the errors-rule field is kept.',
  S('5.0', '13'),
  jresp('{"error":{"code":"E_CARD","message":"Card 4111111111111111 of mario.rossi@example.com declined",'
        '"echo":{"email":"mario.rossi@example.com"}}}', status=402), pol=ERR_POL)
V('1504-adv-pii-in-content-type', 'adversarial', 'PII in content-type parameters never reaches ct.', S('8.1'),
  X('POST', '/', h=[('Content-Type', 'application/json; name="mario.rossi@example.com"; charset=utf-8')], body='{}'))
V('1505-adv-pii-in-header-names', 'adversarial',
  'Header names with "@" or spaces collapse; token-like names are kept as names (allowed by section 13).',
  S('8.0', '13'), X('GET', '/', h=[('x-mario.rossi@example.com', '1'), ('X-Giulia Neri', '2'), ('x-ok', '3'),
                                      ('x-3912345678', '4')]))
V('1506-adv-pii-in-query-names', 'adversarial', 'PII as query names collapses into {*}.', S('8.3', '13'),
  X('GET', '/s', 'mario.rossi%40example.com&%2B390212345678=1&4111111111111111=2'))
V('1507-adv-pii-in-form-body', 'adversarial', 'PII in form bodies (names and values).', S('9.1', '13'),
  X('POST', '/s', h=[('Content-Type', 'application/x-www-form-urlencoded')],
    body='mario.rossi%40example.com=1&card=4111111111111111&cvv=123'))
V('1508-adv-keep-overflow', 'adversarial', 'A keep field abused for free text above keep_max_bytes becomes a shape.',
  S('5.3'), jpost(J.dumps({'status': 'OPEN - customer mario.rossi@example.com phone +390212345678 asked for a refund'})),
  pol=policy(global_=scope(request=part(body={'$.status': KEEP}))))
V('1509-adv-duplicate-key-shadow', 'adversarial', 'A duplicate key cannot smuggle the first value past a keep rule.',
  S('9.2'), jpost('{"status":"mario.rossi@example.com","status":"OPEN"}'),
  pol=policy(global_=scope(request=part(body={'$.status': KEEP}))))
V('1510-adv-escaped-key-shadow', 'adversarial',
  'An escaped duplicate of a kept key: the last value (a number) is the one kept.', S('9.2'),
  jpost('{"st\\u0061tus":"mario.rossi@example.com","status":7}'),
  pol=policy(global_=scope(request=part(body={'$.status': KEEP}))))
V('1511-adv-set-cookie-attributes', 'adversarial', 'set-cookie attributes (Domain, Path) never leave.', S('8.2'),
  X('GET', '/', rh=[('Set-Cookie', 'sid=1; Domain=mario-rossi.example; Path=/customers/mario.rossi@example.com')]))
V('1512-adv-crlf-in-header', 'adversarial', 'A header value with CR LF is just a string shape.', S('8.1'),
  X('GET', '/', h=[('X-Note', 'a\r\nX-Evil: mario.rossi@example.com')]))
V('1513-adv-subject-raw-never-out', 'adversarial', 'The raw subject value never appears; only tk1 and the header shape.',
  S('11'), X('GET', '/', h=[('X-Customer-Id', 'mario.rossi@example.com')]), pol=policy(identity=ID_HDR))
V('1514-adv-baggage-pii', 'adversarial', 'PII in baggage members is dropped like any header value.', S('12', '8.1'),
  X('GET', '/', h=[('baggage', 'user=mario.rossi%40example.com,tt.s=1')]))
V('1515-adv-userinfo-url-base', 'adversarial', 'Credentials in url_base userinfo give host:invalid.', S('3.1'),
  X('GET', '/', dir='outbound', url_base='https://mario:s3cret@api.carrier.example'))
V('1516-adv-key-looks-like-name', 'adversarial', 'A long hex key starting with a letter is caught by the hex check.',
  S('9.3'), jpost('{"cafebabecafebabe00":"x","cafebabe":"y"}'))
V('1517-adv-jwt-in-query', 'adversarial', 'A JWT in a query value is only a shape.', S('8.3', '6.3'),
  X('GET', '/cb', 'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln&code=4%2F0AX4XfWh'))
V('1518-adv-number-key-pii', 'adversarial', 'Numeric keys holding phone numbers collapse.', S('9.3'),
  jpost('{"390212345678":{"calls":3}}'))
V('1519-adv-template-literal-mismatch', 'adversarial',
  'A literal template position never echoes a different raw segment.', S('3.2', '4.2'),
  X('GET', '/orders/ORD-1'), pol=policy(services=[service('shop-api', ops={'GET /orders/{id}': op()})]))
V('1520-adv-deep-pii', 'adversarial', 'PII below max_depth is replaced by trunc:depth, not leaked.', S('9.2'),
  jpost('{"a":{"b":{"email":"mario.rossi@example.com"}}}'), pol=policy(limits={'max_depth': 2}))
V('1521-adv-array-overflow-pii', 'adversarial', 'Elements beyond max_array are not visited.', S('9.4'),
  jpost('["x","y","mario.rossi@example.com"]'), pol=policy(limits={'max_array': 2}))
V('1522-adv-unicode-lookalike', 'adversarial', 'A fullwidth-@ e-mail is not an email shape but still only a length class.',
  S('6.3'), jpost('{"e":"mario.rossi\\uff20example.com"}'))

# =========================================================================== canonical (10)

V('1601-canonical-key-order', 'canonical', 'Output keys sorted by bytes: uppercase < _ < lowercase < {.', S('10.1'),
  jpost('{"b":1,"B":2,"_":3,"a.b":4,"a-b":5,"a":6,"Z":7,"mario@example.com":8}'))
V('1602-canonical-nested-order', 'canonical', 'Every nested object is sorted; arrays keep their order.', S('10.1'),
  jpost('{"z":[{"y":1,"x":2},{"b":3,"a":4}],"a":{"d":1,"c":2}}'))


# =========================================================================== revision 1.1 additions

# ---- path (0.1, 4.3)
V('0120-path-newline', 'path', 'A decoded newline stops the auto_words match (whole-input regex, 0.1): /orders%0A is dropped.',
  S('0.1', '4.2'), X('GET', '/orders%0A/orders'), pol=AUTO)
V('0121-path-auto-words-expired', 'path', 'auto_words is off once now reaches auto_words_expires_at.', S('4.3'),
  X('GET', '/v1/shipments'), pol=AUTO, now=MODE_EXPIRES)
V('0122-path-auto-words-seven-days', 'path',
  'auto_words expires at created_at + 7 days, the longest window a source accepts (hardening.md 2.1 H3): off from that instant.',
  S('4.3') + ['hardening.md#2.1'], X('GET', '/v1/shipments'),
  pol=policy(auto_words=True, auto_words_expires_at=SEVEN_DAYS), now=SEVEN_DAYS)
V('0123-path-auto-words-seven-days-before', 'path',
  'One second before created_at + 7 days auto_words is still on (the expiry sits exactly on the 7-day limit, which is accepted).',
  S('4.3') + ['hardening.md#2.1'], X('GET', '/v1/shipments'),
  pol=policy(auto_words=True, auto_words_expires_at=SEVEN_DAYS), now='2026-10-27T07:59:59Z')

# ---- headers (8.0, 8.1)
V('0330-headers-pseudo', 'headers', 'HTTP/2 pseudo-headers (names starting with ":") are removed before anything else.',
  S('8.0'), X('GET', '/', h=[(':authority', 'shop.example'), (':path', '/orders?email=mario.rossi%40example.com'),
                             ('X-A', 'a')]))
V('0331-headers-ows-and-join', 'headers',
  'OWS is trimmed from every value, then same-name values are joined with ", " in arrival order.', S('8.0'),
  X('GET', '/', h=[('X-Tag', '  a\t'), ('Accept', 'text/html'), ('x-tag', ' b '), ('X-TAG', 'c')]),
  pol=policy(global_=scope(request=part(headers={'x-tag': KEEP}))))
EQUIV_POL = policy(global_=scope(request=part(headers={'x-a': KEEP})))
V('0332-headers-separate-values', 'headers', 'X-A: 1 and X-A: 2 as separate fields: same output as vector 0333.',
  S('8.0'), X('GET', '/', h=[('X-A', '1'), ('X-A', '2')]), pol=EQUIV_POL)
V('0333-headers-prejoined-value', 'headers', 'X-A: "1, 2" already joined by the runtime: same output as vector 0332.',
  S('8.0'), X('GET', '/', h=[('X-A', '1, 2')]), pol=EQUIV_POL)
V('0334-headers-collapsed-joined', 'headers',
  'Values of different names that collapse to {*} are joined into one value; with several original names no rule applies.',
  S('8.0', '5.0'), X('GET', '/', h=[('x bad', '1'), ('X-Ok', '2'), ('x-3912345678', '3')]),
  pol=policy(global_=scope(request=part(headers={'x-3912345678': KEEP}))), amb=['A-HDR-COLLAPSED-RULE'])
V('0335-headers-collapsed-rule', 'headers',
  'A collapsed header with a single original name still takes the rule of that name (compared on the original name).',
  S('8.0', '5.0'), X('GET', '/', h=[('X-3912345678', 'opt-in')]),
  pol=policy(global_=scope(request=part(headers={'x-3912345678': KEEP}))), amb=['A-HDR-COLLAPSED-RULE'])
V('0336-headers-name-rule', 'headers',
  'Header names that are uuid, hex or digits, or hold six consecutive digits, collapse; five digits stay.',
  S('8.0', '9.3'),
  X('GET', '/', h=[('x-12345', 'a'), ('x-123456', 'b'), ('deadbeefdeadbeef', 'c'), ('12345', 'd'),
                   ('550e8400-e29b-41d4-a716-446655440000', 'e'), ('x-req-2026', 'f')]))
V('0337-headers-cookie-joined', 'cookies', 'Several cookie headers are joined with "; " before parsing.', S('8.0', '8.2'),
  X('GET', '/', h=[('Cookie', 'a=1'), ('cookie', 'b=22; a=333')]))
V('0338-headers-set-cookie-separate', 'cookies',
  'set-cookie values are never joined, so a comma inside Expires does not split anything.', S('8.0', '8.2'),
  X('GET', '/', rh=[('Set-Cookie', 'sid=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT'), ('Set-Cookie', 'pref=dark')]))
V('0339-headers-blank-value', 'headers', 'A value made only of spaces and tabs becomes empty.', S('8.0'),
  X('GET', '/', h=[('X-Blank', ' \t ')]), pol=policy(global_=scope(request=part(headers={'x-blank': KEEP}))))

# ---- query and cookies (8.2, 8.3)
V('0216-query-per-name-limit', 'query', 'A query name keeps at most max_array values, then trunc:n:<class of the total>.',
  S('8.3', '8.2'), X('GET', '/s', '&'.join('tag=v%d' % i for i in range(5))), pol=policy(limits={'max_array': 3}))
V('0217-query-noeq-never-kept', 'query',
  'A part without "=" is always dropped, even when a rule exists for that text used as a name.', S('8.3', '5.0'),
  X('GET', '/s', 'ORD2026000184&status=OPEN&status'),
  pol=policy(global_=scope(request=part(query={'ORD2026000184': KEEP, 'status': KEEP}))))
V('0218-query-name-digits', 'query', 'Query names with six or more consecutive digits collapse; five digits stay.',
  S('8.3', '9.3'), X('GET', '/s', 'order_12345=a&order_123456=b&ref2026101900=c'))
V('0411-cookies-per-name-limit', 'cookies', 'A cookie name keeps at most max_array values, then trunc:n.', S('8.2'),
  X('GET', '/', h=[('Cookie', 'a=1; a=2; a=3; b=4')]), pol=policy(limits={'max_array': 2}))
V('0412-cookies-65-names', 'cookies', '65 distinct cookie names: 64 kept, then {trunc} = ["trunc:keys:<class>"].',
  S('8.2', '8.1'), X('GET', '/', h=[('Cookie', '; '.join('c%02d=v' % i for i in range(65)))]))
V('0413-cookies-name-digits', 'cookies', 'Cookie names with six or more consecutive digits collapse.', S('8.2', '9.3'),
  X('GET', '/', h=[('Cookie', 'cart_12345=a; cart_123456=b')]))

# ---- body keys (9.3)
V('0526-body-key-digits', 'body', 'JSON keys with six or more consecutive digits collapse; five digits stay literal.',
  S('9.3'), jpost('{"order_12345":1,"order_123456":2,"x2026101900":3,"sku":4}'))
V('0527-body-collapsed-order', 'body',
  'Values under {*} are sorted by the bytes of their canonical form, not by the hidden keys.', S('9.3', '10.1'),
  jpost('{"zz@shop.example":"a","aa@shop.example":true,"mm@shop.example":{"k":1},"bb@shop.example":[1],'
        '"cc@shop.example":12,"dd@shop.example":"' + 'x' * 40 + '"}'))

# ---- numbers (5.3, 10.2)
L64 = '1' + '0' * 63
L65 = '1' + '0' * 64
V('0705-number-lexeme-limits', 'numbers',
  'keep, hmac and bucket need a lexeme of at most 64 bytes and a written exponent of at most 9999; otherwise drop.',
  S('5.3', '5.4', '5.5', '10.2'),
  jpost('{"k64":%s,"k65":%s,"ke":1e9999,"kE":1E+10000,"h64":%s,"h65":%s,"b":1e09999,"bx":-1e-10000}'
        % (L64, L65, L64, L65)),
  pol=policy(global_=scope(request=part(body={'$.k64': KEEP, '$.k65': KEEP, '$.ke': KEEP, '$.kE': KEEP,
                                              '$.h64': HMAC(), '$.h65': HMAC(), '$.b': BNUM(0, 1), '$.bx': BNUM(0, 1)}))))

# ---- rules (5.0)
V('0965-rules-container-drop-stronger', 'rules',
  'An operation drop on a container applies when only a weaker group (global) has rules for its descendants.',
  S('5.0'), X('GET', '/orders', rh=[CT_JSON], rbody='{"order":{"status":"OPEN"},"n":1}'),
  pol=policy(global_=scope(response=part(body={'$.order.status': KEEP})),
             services=[service('shop-api', ops={'GET /orders': op(response=part(body={'$.order': DROP}))})]))
V('0966-rules-container-drop-same-group', 'rules',
  'A drop on a container is ignored when a rule of the same group reaches a descendant.', S('5.0'),
  jpost('{"addr":{"city":"Torino","street":"Via Roma 1"}}'),
  pol=policy(global_=scope(request=part(body={'$.addr': DROP, '$.addr.city': KEEP}))))

# ---- path parameters (4.2)
PATHKEEP = policy(services=[service('shop-api', ops={
    'GET /codes/{a}/{b}/{c}': op(request=part(path={'a': KEEP, 'b': KEEP, 'c': KEEP})),
    'GET /days/{d}/{t}': op(request=part(path={'d': BTIME('day'), 't': BTIME('day')}))})])
V('1124-route-path-keep-grammar', 'routing',
  'keep on a path parameter applies only to values matching [A-Za-z0-9._~-]{1,64}; others are dropped.', S('4.2'),
  X('GET', '/codes/ABC-1.x~y/a%20b/x%40y.example'), pol=PATHKEEP)
V('1125-route-path-time-grammar', 'routing',
  'bucket(time) on a path parameter: a date works, a datetime with ":" is dropped like a keep would be.', S('4.2', '5.5'),
  X('GET', '/days/2026-10-19/2026-10-19T10%3A00%3A00Z'), pol=PATHKEEP, amb=['A-PATH-TIME'])
V('1126-route-method-other', 'routing', 'Method OTHER never matches a template, even an "OTHER /x" operation.', S('3.3'),
  X('M-SEARCH', '/x'), pol=policy(auto_words=True, services=[service('shop-api', ops={'OTHER /x': op()})]))

# ---- outbound hosts (3.1)
V('1138-outbound-hosts-allow', 'routing', 'A host listed in segments.hosts_allow leaves in clear.', S('3.1'),
  X('GET', '/v1/rates', dir='outbound', url_base='https://api.partner.example'),
  pol=policy(hosts_allow=['api.partner.example']))
V('1139-outbound-default-port', 'routing', 'Scheme and host are lowercased and the default port is removed before lookup.',
  S('3.1'), X('GET', '/', dir='outbound', url_base='HTTPS://API.Partner.Example:443'),
  pol=policy(hosts_allow=['api.partner.example']))
V('1140-outbound-discovery-host', 'routing', 'During discovery an unlisted host leaves as its pattern (all labels safe here).', S('3.1', '3.5', '15'),
  X('GET', '/', dir='outbound', url_base='https://api.partner.example:8443'),
  pol=policy(discovery=(True, MODE_EXPIRES)))
V('1141-outbound-url-base-path', 'routing', 'A url_base with a path is not valid: host:invalid.', S('3.1'),
  X('GET', '/', dir='outbound', url_base='https://api.partner.example/v1'), pol=policy(hosts_allow=['api.partner.example']))
V('1142-outbound-ipv6', 'routing',
  'A bracketed IPv6 literal is a valid host from spec v1.5: never the address, only its class and the non-default port (2001:db8::/32 is documentation, so private).',
  S('3.1', '3.6'),
  X('GET', '/', dir='outbound', url_base='http://[2001:db8::1]:8080'))
V('1143-outbound-port-zero', 'routing', 'Port 0 is outside 1-65535: host:invalid.', S('3.1'),
  X('GET', '/', dir='outbound', url_base='https://api.partner.example:0'))
V('1144-outbound-port-too-big', 'routing', 'Port 65536 is outside 1-65535: host:invalid.', S('3.1'),
  X('GET', '/', dir='outbound', url_base='https://api.partner.example:65536'))
V('1145-outbound-base-normalized', 'routing', 'An uppercase url_base with the default port matches a normalized base.',
  S('3.1'), X('POST', '/v1/shipments', h=[CT_JSON], body='{"orderId":"ORD-2026-000184"}', dir='outbound',
                url_base='HTTPS://API.Carrier.Example:443'), pol=CARRIER)

# ---- framework_route normalization (3.3, 3.4)
FW_POL = policy(services=[service('shop-api', ops={
    'GET /api/orders/{id}': op(request=part(path={'id': HMAC('order')})),
    'GET /api/files/{name}': op()})])
FW_CASES = [
    ('express', '/api/orders/:id(\\\\d+)', '/api/orders/:id?'),
    ('koa', '/api/orders/:orderId', '/api/orders/:id+'),
    ('fastify', '/api/orders/:id', '/api/orders/*'),
    ('flask', '/api/orders/<int:id>', '/api/orders/<path:id>'),
    ('fastapi', '/api/orders/{id:int}', '/api/orders/{id:path}'),
    ('django', '/api/orders/<str:id>', '^api/orders/(?P<id>[A-Z0-9-]+)/$'),
    ('spring', '/api/orders/{id:[A-Z0-9-]+}', '/api/orders/**'),
    ('jaxrs', '/api/orders/{ id : [A-Z0-9-]+ }', '/api/orders/{id: .+/.+}'),
    ('aspnetcore', '/api/orders/{id:alpha:minlength(3)}', '/api/orders/{id?}'),
    ('gin', '/api/orders/:id', '/api/orders/*id'),
    ('chi', '/api/orders/{id:[A-Z0-9-]+}', '/api/orders/*'),
    ('nethttp', '/api/orders/{id}/{$}', '/api/orders/{id...}'),
    ('laravel', '/api/orders/{id}', '/api/orders/{id?}'),
    ('symfony', '/api/orders/{id<[A-Z0-9-]+>}', '/api/orders/{id?}'),
]
for n, (fw, ok_route, bad_route) in enumerate(FW_CASES):
    V('%04d-framework-%s-ok' % (1160 + 2 * n, fw), 'framework',
      '%s route %s normalizes to /api/orders/{id}: route_source framework.' % (fw, ok_route), S('3.3', '3.4'),
      X('GET', '/api/orders/ORD-2026-000184', framework=fw, framework_route=ok_route), pol=FW_POL, amb=['A-FRAMEWORK-ID'])
    V('%04d-framework-%s-fallback' % (1161 + 2 * n, fw), 'framework',
      '%s route %s cannot be normalized: fall back to policy templates (route_source policy).' % (fw, bad_route),
      S('3.3', '3.4'), X('GET', '/api/orders/ORD-2026-000184', framework=fw, framework_route=bad_route), pol=FW_POL)
V('1150-framework-policy-literals', 'framework',
  'With a framework match the policy literals are emitted even if the request segments differ (case-insensitive router).',
  S('3.3'), X('GET', '/API/Orders/ORD-2026-000184', framework='express', framework_route='/api/orders/:id'), pol=FW_POL)
V('1151-framework-missing-mount-prefix', 'framework',
  'A route without its mount prefix has fewer segments than the path: fall back to policy templates.', S('3.3', '3.4'),
  X('GET', '/api/orders/ORD-2026-000184', framework='express', framework_route='/orders/:id'), pol=FW_POL)
V('1152-framework-not-in-policy', 'framework', 'A framework template that is not in the policy never appears in the output.',
  S('3.3'), X('GET', '/api/things/T-1', framework='gin', framework_route='/api/things/:id'), pol=FW_POL)

# ---- content-encoding and streaming (9.0)
ORDER_JSON = '{"orderId":"ORD-2026-000184","email":"mario.rossi@example.com","total":73.40,"items":[{"sku":"TSHIRT-RED-M"}]}'
ENC_POL = policy(global_=scope(request=part(body={'$.orderId': HMAC('order'), '$.total': KEEP}),
                               response=part(body={'$.status': KEEP})))


def enc_post(ce, body, **kw):
    h = [CT_JSON] + ([('Content-Encoding', ce)] if ce is not None else [])
    return X('POST', '/orders', h=h, body=body, **kw)


V('1050-encoding-gzip', 'encoding', 'gzip body: decoded, size is the class of the decoded length, then parsed.', S('9.0'),
  enc_post('gzip', gzip_bytes(ORDER_JSON)), pol=ENC_POL)
V('1051-encoding-deflate', 'encoding', 'deflate (zlib, RFC 1950) body: decoded and parsed.', S('9.0'),
  enc_post('deflate', gzip_bytes(ORDER_JSON, deflate=True)), pol=ENC_POL)
V('1052-encoding-x-gzip', 'encoding', 'x-gzip is gzip.', S('9.0'), enc_post('x-gzip', gzip_bytes(ORDER_JSON)), pol=ENC_POL)
V('1053-encoding-already-decoded', 'encoding', 'Body already decoded by the runtime (req_body_decoded): used as is.',
  S('9.0'), enc_post('gzip', ORDER_JSON, req_decoded=True), pol=ENC_POL)
V('1054-encoding-unsupported', 'encoding', 'Content-Encoding br: body drop:bytes and no size.', S('9.0', '6.2'),
  enc_post('br', bytes(range(40))), pol=ENC_POL)
V('1055-encoding-stacked', 'encoding', 'Two codings ("gzip, br"): body drop:bytes and no size.', S('9.0'),
  enc_post('gzip, br', gzip_bytes(ORDER_JSON)), pol=ENC_POL)
V('1056-encoding-corrupt', 'encoding', 'Content-Encoding gzip on bytes that are not gzip: drop:bytes, no size.', S('9.0'),
  enc_post('gzip', ORDER_JSON), pol=ENC_POL)
V('1057-encoding-identity', 'encoding', 'Content-Encoding identity: body used as received.', S('9.0'),
  enc_post('identity', ORDER_JSON), pol=ENC_POL)
V('1058-encoding-bomb', 'encoding',
  'A small gzip body that inflates beyond max_body_bytes: trunc:size, size lmax, nothing parsed.', S('9.0'),
  enc_post('gzip', gzip_bytes('{"a":"' + '0' * (2 * 1048576) + '"}')), pol=ENC_POL)
V('1059-body-not-consumed', 'encoding', 'A body the app did not read: trunc:size, size lmax.', S('9.0'),
  X('POST', '/orders', h=[CT_JSON], body='{"a":', req_total=500, req_consumed=False), pol=ENC_POL)
V('1060-encoding-decoded-unsupported', 'encoding',
  'An unsupported coding stays drop:bytes even if the runtime already decoded it.', S('9.0'),
  enc_post('br', ORDER_JSON, req_decoded=True), pol=ENC_POL)
V('1061-encoding-case-and-ows', 'encoding', 'The coding name is trimmed and lowercased: " GZIP " is gzip.', S('8.1', '9.0'),
  enc_post(' GZIP ', gzip_bytes(ORDER_JSON)), pol=ENC_POL)
V('1062-encoding-response', 'encoding', 'A gzip response body is decoded the same way.', S('9.0'),
  X('GET', '/orders/1', rh=[CT_JSON, ('Content-Encoding', 'gzip')],
    rbody=gzip_bytes('{"status":"SHIPPED","eta":"2026-10-21"}')), pol=ENC_POL)
V('1063-encoding-truncated-stream', 'encoding', 'A gzip stream cut short is a decoding error: drop:bytes.', S('9.0'),
  enc_post('gzip', gzip_bytes(ORDER_JSON)[:30]), pol=ENC_POL, amb=['A-GZIP-STRICT'])
V('1064-encoding-repeated-header', 'encoding', 'Two Content-Encoding: gzip headers join to "gzip, gzip": two codings, drop:bytes.',
  S('8.0', '9.0'), X('POST', '/orders', h=[CT_JSON, ('Content-Encoding', 'gzip'), ('Content-Encoding', 'gzip')],
                     body=gzip_bytes(gzip_bytes(ORDER_JSON))), pol=ENC_POL)
V('1065-encoding-empty-body', 'encoding', 'An empty body is absent whatever its coding.', S('9.0'),
  enc_post('br', ''), pol=ENC_POL)
V('1066-encoding-text', 'encoding', 'A gzip text/plain body: decoded length gives the drop:bytes class.', S('9.0', '9.1'),
  X('POST', '/notes', h=[('Content-Type', 'text/plain'), ('Content-Encoding', 'gzip')],
    body=gzip_bytes('note ' * 40)), pol=ENC_POL)

# ---- event size limit (10.3)
BIG_OP = policy(limits={'keep_max_bytes': 1024, 'max_keys': 1024}, services=[service('shop-api', ops={
    'POST /bulk': op(request=part(body={'$.*': KEEP}), response=part(body={'$.*': KEEP}))})])


def big_json(n, size, tag):
    return '{' + ','.join('"%s%04d":"%s"' % (tag, i, (tag * size)[:size]) for i in range(n)) + '}'


REQ_BIG = big_json(600, 1000, 'q')
RESP_BIG = big_json(600, 1000, 'r')
V('1070-size-limit-request-body', 'event-size', 'An output over 512 KiB loses req.body first (trunc:size); size stays.',
  S('10.3'), X('POST', '/bulk', h=[CT_JSON, ('Content-Encoding', 'gzip')], body=gzip_bytes(REQ_BIG),
                rh=[CT_JSON], rbody='{"ok":"yes"}'), pol=BIG_OP, amb=['A-EVENT-SIZE-BASE'])
V('1071-size-limit-both-bodies', 'event-size', 'Still over the limit after req.body: resp.body becomes trunc:size too.',
  S('10.3'), X('POST', '/bulk', h=[CT_JSON, ('Content-Encoding', 'gzip')], body=gzip_bytes(REQ_BIG),
                rh=[CT_JSON, ('Content-Encoding', 'gzip')], rbody=gzip_bytes(RESP_BIG)), pol=BIG_OP,
  amb=['A-EVENT-SIZE-BASE'])
DEEP_KEYS = '{' + ','.join('"key%04d%s":{"%s":{"%s":1}}' % (i, 'k' * 56, 'm' * 60, 'n' * 60) for i in range(4096)) + '}'
V('1072-size-limit-disc', 'event-size',
  'Discovery output alone over the limit: after the bodies, disc is removed.', S('10.3', '15'),
  X('POST', '/bulk', h=[CT_JSON, ('Content-Encoding', 'gzip')], body=gzip_bytes(DEEP_KEYS)),
  pol=policy(limits={'max_keys': 4096}, discovery=(True, MODE_EXPIRES)), amb=['A-EVENT-SIZE-BASE'])

# ---- discovery (15)
V('1208-discovery-path-in-hmac', 'discovery', 'The same value in two fields gives two different tkd tokens (path in the HMAC).',
  S('15'), jpost('{"a":"ORD-1","b":"ORD-1"}'), pol=policy(discovery=(True, MODE_EXPIRES)))
V('1209-discovery-seven-days', 'discovery',
  'Discovery expires at created_at + 7 days, the longest window a source accepts (hardening.md 2.1 H3): off from that instant.',
  S('15') + ['hardening.md#2.1'],
  jpost('{"a":"x"}'), pol=policy(discovery=(True, SEVEN_DAYS)), now=SEVEN_DAYS)
V('1213-discovery-seven-days-before', 'discovery',
  'One second before created_at + 7 days discovery is still on (the expiry sits exactly on the 7-day limit, which is accepted).',
  S('15') + ['hardening.md#2.1'],
  jpost('{"a":"x"}'), pol=policy(discovery=(True, SEVEN_DAYS)), now='2026-10-27T07:59:59Z')
V('1210-discovery-noeq', 'discovery', 'A query part without "=" adds a req.query.{*} entry (dropped by default, no rule).',
  S('15', '8.3'), X('GET', '/s', 'ORD2026000184&x=1'), pol=policy(discovery=(True, MODE_EXPIRES)), amb=['A-NOEQ-DISC'])
V('1211-discovery-number-limits', 'discovery', 'A number beyond the lexeme limits adds no discovery entry.', S('15', '5.3'),
  jpost('{"ok":12,"big":1e10000}'), pol=policy(discovery=(True, MODE_EXPIRES)))
V('1212-discovery-form', 'discovery', 'Form fields: req.body.<name>, collapsed names as req.body.*.', S('15', '9.1'),
  X('POST', '/f', h=[('Content-Type', 'application/x-www-form-urlencoded')], body='a=1&b=2&mario%40shop.example=3'),
  pol=policy(discovery=(True, MODE_EXPIRES)))

# ---- subject (11)
ID_PLAIN = {'from': 'header', 'name': 'authorization'}
V('1310-subject-bearer-ows', 'subject-sampling', 'The bearer prefix is case-insensitive and followed by spaces or tabs.',
  S('11'), X('GET', '/', h=[('Authorization', 'BEARER \t c-10042')]), pol=policy(identity=ID_PLAIN))
V('1311-subject-bearer-same-token', 'subject-sampling', 'Same subject token as 1310: the prefix is not part of the value.',
  S('11'), X('GET', '/', h=[('Authorization', 'c-10042')]), pol=policy(identity=ID_PLAIN))
V('1312-subject-bearer-word-only', 'subject-sampling', '"Bearer" with no separator is not a prefix: it is the value.',
  S('11'), X('GET', '/', h=[('Authorization', 'Bearer ')]), pol=policy(identity=ID_PLAIN))
JWT_PAD = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":"c-1"}') + '==.c2ln'
V('1313-subject-jwt-padding', 'subject-sampling', 'The JWT payload may carry "=" padding.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_PAD)]), pol=policy(identity=ID_JWT))
V('1314-subject-jwt-four-parts', 'subject-sampling', 'A JWS must have exactly three parts.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_SUB + '.x')]), pol=policy(identity=ID_JWT))
JWT_DOT = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"user":{"id":"nested"},"user.id":"c-77"}') + '.c2ln'
V('1315-subject-jwt-dotted-claim', 'subject-sampling', 'jwt_claim "user.id" is a literal top-level name, not a path.',
  S('11'), X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_DOT)]),
  pol=policy(identity={'from': 'header', 'name': 'authorization', 'jwt_claim': 'user.id'}))
JWT_EMPTY = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":""}') + '.c2ln'
V('1316-subject-jwt-empty-claim', 'subject-sampling', 'An empty string claim gives no subject.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_EMPTY)]), pol=policy(identity=ID_JWT))
V('1317-subject-header-repeated', 'subject-sampling', 'A repeated subject header is joined with ", " and the JWT no longer parses.',
  S('11', '8.0'), X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_SUB), ('Authorization', 'Bearer ' + JWT_NUM)]),
  pol=policy(identity=ID_JWT))
V('1318-subject-cookie-first', 'subject-sampling', 'With a repeated cookie name the first occurrence is the subject.',
  S('11'), X('GET', '/', h=[('Cookie', 'uid=C-10042; uid=C-99999')]), pol=policy(identity=ID_COOKIE))
V('1319-subject-too-long', 'subject-sampling', 'A raw subject over 8192 bytes gives no subject.', S('11'),
  X('GET', '/', h=[('X-Customer-Id', 'C' * 8193)]), pol=policy(identity=ID_HDR))
JWT_BIGNUM = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'{"sub":' + L65.encode() + b'}') + '.c2ln'
V('1330-subject-jwt-number-limits', 'subject-sampling', 'A numeric claim beyond the lexeme limits gives no subject.',
  S('11', '5.3'), X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_BIGNUM)]), pol=policy(identity=ID_JWT))
JWT_ARR = 'eyJhbGciOiJIUzI1NiJ9.' + PL.b64url_nopad(b'["c-1"]') + '.c2ln'
V('1331-subject-jwt-not-object', 'subject-sampling', 'A payload that is not a JSON object gives no subject.', S('11'),
  X('GET', '/', h=[('Authorization', 'Bearer ' + JWT_ARR)]), pol=policy(identity=ID_JWT))
V('1332-subject-jwt-alphabet', 'subject-sampling', 'A payload with a character outside base64url gives no subject.',
  S('11'), X('GET', '/', h=[('Authorization', 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjLTEifQ+.c2ln')]),
  pol=policy(identity=ID_JWT))

# ---- sampling (12)
OUT_RATES = dict(dir='outbound', url_base='https://api.carrier.example')
V('1340-sampling-inherited-on', 'subject-sampling', 'Outbound inside a sampled inbound exchange: sampled_by inherited.',
  S('12'), X('GET', '/v1/rates', inherited=True, **OUT_RATES), pol=policy(rate_bp=0))
V('1341-sampling-inherited-off', 'subject-sampling', 'Outbound inside an unsampled inbound exchange: not captured.',
  S('12'), X('GET', '/v1/rates', inherited=False, **OUT_RATES))
V('1342-sampling-outbound-trace', 'subject-sampling',
  'Outbound without context ignores the subject for sampling and uses the trace (the subject token is still emitted).',
  S('12', '11'), X('GET', '/v1/rates', h=[('X-Customer-Id', 'C-10042')], trace_id=TRACE, **OUT_RATES),
  pol=policy(identity=ID_HDR, rate_bp=u_tr + 1), amb=['A-SUBJECT-OUTBOUND'])
V('1343-sampling-outbound-no-baggage', 'subject-sampling', 'Outbound calls never follow baggage.', S('12'),
  X('GET', '/v1/rates', h=[('baggage', 'tt.s=0')], **OUT_RATES), pol=policy(trust_baggage=True))
V('1344-sampling-baggage-border-service', 'subject-sampling',
  'trust_baggage on a service that is not internal: baggage is ignored.', S('12'),
  X('GET', '/', h=[('baggage', 'tt.s=0')]), pol=policy(trust_baggage=True, services=[service('shop-api')]))
V('1345-sampling-baggage-not-trusted', 'subject-sampling', 'An internal service without trust_baggage ignores baggage.',
  S('12'), X('GET', '/', h=[('baggage', 'tt.s=0')]), pol=policy(services=[service('shop-api', internal=True)]))

# ---- keys (7.1)
K0 = 'k0:' + PL.b64url_nopad(bytes(range(100, 132)))
K1 = KEY
KEY_POL = policy(kid='k1', accept_kids=['k0'], global_=scope(request=part(body={'$.a': HMAC('order')})))
KEY_IN = jpost('{"a":"ORD-2026-000184"}')
V('1440-key-accept-kids', 'keys', 'Only k0 is present and hmac.accept_kids lists it: tokens use tk1:k0.', S('7.1'),
  KEY_IN, pol=KEY_POL, key=K0)
V('1441-key-multi-line', 'keys', 'Two key lines: the key with hmac.kid wins over accept_kids.', S('7.1'), KEY_IN,
  pol=KEY_POL, key=K0 + '\n' + K1)
V('1442-key-crlf-blank-lines', 'keys', 'Trailing \\r on lines and empty lines are ignored.', S('7.1'), KEY_IN,
  pol=KEY_POL, key='\r\n\n' + K1 + '\r\n\n')
V('1443-key-bad-line', 'keys', 'One invalid line invalidates the whole key configuration.', S('7.1'), KEY_IN,
  pol=KEY_POL, key=K1 + '\nk2:' + PL.b64url_nopad(bytes(16)))
V('1444-key-no-accepted-kid', 'keys', 'No key for hmac.kid nor for accept_kids: key_mismatch.', S('7.1'), KEY_IN,
  pol=KEY_POL, key='k9:' + PL.b64url_nopad(bytes(range(32))))
V('1445-key-inner-space', 'keys', 'A space inside a line is not allowed.', S('7.1'), KEY_IN, pol=KEY_POL,
  key='k1: ' + PL.b64url_nopad(bytes(range(32))))

# ---- policy acceptance (policy.md 4)
P_ACC = ['policy.md#4']
V('1450-refuse-group', 'refusal', 'The source group is not in targets.groups: policy_rejected.', P_ACC, X('GET', '/'),
  group='billing')
V('1451-refuse-not-after', 'refusal', 'now has reached not_after: expired_policy.', P_ACC, X('GET', '/'),
  now='2026-11-19T08:00:00Z')
V('1452-refuse-issued-seq-replay', 'refusal', 'issued_seq not greater than the last accepted one: policy_rejected.',
  P_ACC, X('GET', '/'), last_seq=1)
V('1453-refuse-min-issued-seq', 'refusal', 'issued_seq below min_issued_seq of the heartbeat: policy_rejected.', P_ACC,
  X('GET', '/'), pol=policy(issued_seq=4), last_seq=2, min_seq=5)
V('1454-accept-issued-seq', 'refusal', 'issued_seq above the last accepted and at least min_issued_seq: accepted.', P_ACC,
  X('GET', '/'), pol=policy(issued_seq=5), last_seq=4, min_seq=5)
V('1455-refuse-auto-words-no-expiry', 'refusal', 'auto_words without auto_words_expires_at fails the body schema.',
  P_ACC, X('GET', '/'), pol=policy(auto_words=True, auto_words_expires_at=None))
V('1456-refuse-allow-grammar', 'refusal', 'A segments.allow entry outside [A-Za-z0-9._~-] fails the body schema.', P_ACC,
  X('GET', '/'), pol=policy(allow=['a+b']))
V('1457-refuse-discovery-no-expiry', 'refusal', 'discovery without expires_at fails the body schema.', P_ACC,
  X('GET', '/'), pol=policy(extra={'discovery': {'enabled': True}}))
V('1458-refuse-op-key-grammar', 'refusal', 'An operation key outside the grammar ({*}) fails the body schema.', P_ACC,
  X('GET', '/'), pol=policy(services=[service('shop-api', ops={'GET /files/{*}': op()})]))
V('1459-refuse-unknown-field', 'refusal', 'An unknown field in the body fails the schema.', P_ACC, X('GET', '/'),
  pol=policy(extra={'debug': True}))
V('1430-envelope-no-prefix', 'refusal', 'A signature over the bare body bytes (without "tt.policy.body/v1" 0x00) is rejected.',
  ['policy.md#3'], ENV_INPUT, pol=envelope(prefix=b''))
V('1431-envelope-issued-seq-mismatch', 'refusal', 'Envelope issued_seq differs from the body: policy_rejected.',
  ['policy.md#3'], ENV_INPUT, pol=envelope(mutate=lambda e: e.update(issued_seq=N(2))))


# =========================================================================== revision 1.3: unsafe policies (hardening.md 2)
# A source refuses a signed policy that breaks H1 to H3 before it sanitizes anything: refused/policy_rejected
# (heartbeat state), last_errors code policy_unsafe. Every refused vector below is checked to be refused for
# that reason alone (the body is schema-valid and uses no reserved domain).

H13 = ['hardening.md#2.1', 'hardening.md#2.2', 'policy.md#4']
UNSAFE = []


def unsafe(id, description, pol, now=NOW):
    """A vector whose policy a v1.3 source refuses as unsafe, and nothing else."""
    try:
        PL.check_body(pol)
    except PL.Refused as r:
        assert r.detail.startswith('unsafe:'), (id, r.detail)
    else:
        raise AssertionError('%s is not refused' % id)
    UNSAFE.append(id)
    V(id, 'refusal', description, H13,
      X('GET', '/orders/1', h=[CT_JSON, ('Authorization', 'Bearer t-1'), ('Cookie', 'sid=1')],
        rh=[CT_JSON, ('Set-Cookie', 'sid=1')], rbody='{"a":1}'), pol=pol, now=now)


H1_HEADERS = ['authorization', 'cookie', 'set-cookie', 'proxy-authorization']
H1_PLACES = {
    'global-request': lambda p: policy(global_=scope(request=p)),
    'global-response': lambda p: policy(global_=scope(response=p)),
    'global-errors': lambda p: policy(global_=scope(errors=p)),
    'service-errors': lambda p: policy(services=[service('shop-api', errors=p)]),
    'op-request': lambda p: policy(services=[service('shop-api', ops={'GET /orders/{id}': op(request=p)})]),
    'op-response': lambda p: policy(services=[service('shop-api', ops={'GET /orders/{id}': op(response=p)})]),
}
_n = 1700
for _h in H1_HEADERS:
    for _kind, _act in (('keep', KEEP), ('hmac', HMAC('tok'))):
        for _place, _mk in H1_PLACES.items():
            _n += 1
            unsafe('%d-refuse-h1-%s-%s-%s' % (_n, _h, _kind, _place),
                   'H1: %s on header %s in %s rules: the source refuses the policy.'
                   % (_kind, _h, _place.replace('-', ' ')),
                   _mk(part(headers={_h: _act})))
assert _n == 1748

_n = 1750
for _place, _mk in (('request', lambda p: scope(request=p)), ('response', lambda p: scope(response=p)),
                    ('errors', lambda p: scope(errors=p))):
    for _kind, _act in (('keep', KEEP), ('hmac', HMAC('tok'))):
        _n += 1
        unsafe('%d-refuse-h2-global-%s-%s' % (_n, _place, _kind),
               'H2: %s on $.* in the global %s body rules: the source refuses the policy.' % (_kind, _place),
               policy(global_=_mk(part(body={'$.*': _act}))))
unsafe('1757-refuse-h2-global-nested-keep', 'H2: keep on $.a.* (a .* step anywhere in the tt-path) in the global request rules.',
       policy(global_=scope(request=part(body={'$.a.*': KEEP}))))
unsafe('1758-refuse-h2-global-array-member-hmac', 'H2: hmac on $.items[*].* in the global response rules.',
       policy(global_=scope(response=part(body={'$.items[*].*': HMAC('tok')}))))
unsafe('1759-refuse-h2-global-among-fine-rules',
       'H2: one global .* keep among otherwise acceptable global rules still refuses the whole policy.',
       policy(global_=scope(request=part(body={'$.a': KEEP, '$.b.*': KEEP, '$.c': HMAC('tok')}),
                            response=part(headers={'content-type': KEEP}))))

_n = 1790
for _path in ('$[*]', '$[*].x', '$.a[*]', '$.a[*][*]', '$.a[*].b[*]'):
    for _kind, _act in (('keep', KEEP), ('hmac', HMAC('tok'))):
        _place = ('request', 'response', 'errors')[_n % 3]
        _n += 1
        unsafe('%d-refuse-h2-global-array-%s-%s' % (_n, _kind, _place),
               'H2: %s on %s (an array wildcard step) in the global %s body rules: refused like .*.' % (_kind, _path, _place),
               policy(global_=scope(**{_place: part(body={_path: _act})})))

unsafe('1760-refuse-h3-discovery-seven-days-plus-1s', 'H3: discovery expires one second after created_at + 7 days.',
       policy(discovery=(True, '2026-10-27T08:00:01Z')))
unsafe('1761-refuse-h3-auto-words-seven-days-plus-1s', 'H3: auto_words expires one second after created_at + 7 days.',
       policy(auto_words=True, auto_words_expires_at='2026-10-27T08:00:01Z'))
unsafe('1762-refuse-h3-discovery-thirty-days', 'H3: discovery expires 30 days after created_at.',
       policy(discovery=(True, '2026-11-19T08:00:00Z')))
unsafe('1763-refuse-h3-auto-words-thirty-days', 'H3: auto_words expires 30 days after created_at.',
       policy(auto_words=True, auto_words_expires_at='2026-11-19T08:00:00Z'))
unsafe('1764-refuse-h3-discovery-fraction',
       'H3: discovery expires 1 ms after created_at + 7 days (fractional seconds count).',
       policy(discovery=(True, '2026-10-27T08:00:00.001Z')))
unsafe('1765-refuse-h3-auto-words-offset', 'H3: auto_words expiry written with an offset (10:00:01+02:00 is 08:00:01Z).',
       policy(auto_words=True, auto_words_expires_at='2026-10-27T10:00:01+02:00'))
unsafe('1766-refuse-h3-compares-body-instants',
       'H3 compares body instants, not the source clock: the window is long over by now and the policy is still refused.',
       policy(discovery=(True, '2026-11-19T08:00:00Z')), now='2026-11-25T08:00:00Z')
unsafe('1767-refuse-h3-one-of-two-unsafe',
       'H3: a safe discovery window does not excuse an auto_words window beyond 7 days.',
       policy(auto_words=True, auto_words_expires_at='2026-10-27T08:00:01Z', discovery=(True, '2026-10-26T10:00:00Z')))
unsafe('1768-refuse-h3-both-unsafe', 'H3: discovery and auto_words both beyond 7 days.',
       policy(auto_words=True, auto_words_expires_at='2026-11-19T08:00:00Z', discovery=(True, '2026-11-19T08:00:00Z')))

unsafe('1770-refuse-mixed-h1-op-and-h3', 'Mixed: hmac on cookie in an operation and a discovery window of 30 days.',
       policy(discovery=(True, '2026-11-19T08:00:00Z'),
              services=[service('shop-api', ops={'GET /orders/{id}': op(request=part(headers={'cookie': HMAC('tok')}))})]))
unsafe('1771-refuse-mixed-h1-global-and-h2', 'Mixed: keep on authorization and keep on $.* in the global rules.',
       policy(global_=scope(request=part(headers={'authorization': KEEP}, body={'$.*': KEEP}))))
unsafe('1772-refuse-mixed-h2-and-h3', 'Mixed: hmac on a global $.*.id and an auto_words window beyond 7 days.',
       policy(auto_words=True, auto_words_expires_at='2026-11-19T08:00:00Z',
              global_=scope(response=part(body={'$.*.id': HMAC('tok')}))))
unsafe('1773-refuse-mixed-all-three', 'Mixed: H1 (keep on set-cookie), H2 (hmac on $.*) and H3 in one policy.',
       policy(discovery=(True, '2026-11-19T08:00:00Z'),
              global_=scope(request=part(body={'$.*': HMAC('tok')}), response=part(headers={'set-cookie': KEEP}))))
unsafe('1774-refuse-one-unsafe-rule-among-fine-ones',
       'An otherwise acceptable policy with one keep on proxy-authorization in a service: nothing is captured.',
       policy(services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.status': KEEP}))},
                                request=part(headers={'proxy-authorization': KEEP}))]))

# the accepted limits of the subset
V('1780-accept-h1-credential-headers-dropped', 'refusal',
  'The four credential headers named with drop are not a violation: the policy is accepted (nothing is kept).',
  H13, X('GET', '/orders/1', h=[CT_JSON, ('Authorization', 'Bearer t-1'), ('Cookie', 'sid=1')],
         rh=[CT_JSON, ('Set-Cookie', 'sid=1')]),
  pol=policy(global_=scope(request=part(headers={'authorization': DROP, 'cookie': DROP, 'proxy-authorization': DROP}),
                           response=part(headers={'set-cookie': DROP}))))
V('1781-accept-h2-service-star-keep', 'refusal', 'keep on $.* in a service rule is accepted (H2 is about global rules).',
  H13, jpost('{"a":"x","b":true}'), pol=policy(services=[service('shop-api', request=part(body={'$.*': KEEP}))]))
V('1782-accept-h2-op-star-hmac', 'refusal', 'hmac on $.items[*].* in an operation rule is accepted.', H13,
  X('GET', '/orders/1', rh=[CT_JSON], rbody='{"items":[{"a":"x","b":"y"}]}'),
  pol=policy(services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.items[*].*': HMAC('tok')}))})]))
V('1783-accept-h2-global-star-drop', 'refusal', 'drop on $.* in the global rules is accepted: only keep and hmac are refused.',
  H13, jpost('{"a":"x"}'), pol=policy(global_=scope(request=part(body={'$.*': DROP}))))



# =========================================================================== code values (spec v1.11: 5.6)
# code lets a status or code value out as keep: only when it is a string of 2 to 32 ASCII letters, "_" or
# "-" (and within keep_max_bytes); anything else leaves as the shape that drop would emit. tt-core and
# keyguard accept code only on status/code-like names (policy.md 1.5): every policy below uses such names.

CODE = {'action': 'code'}
SC = lambda *secs: ['sanitizer.md#' + s for s in secs] + ['policy.md#1.5']  # noqa: E731
CODE_ACCEPTED = []


def CV(id, description, inp, pol, secs=('5.6',), now=NOW):
    CODE_ACCEPTED.append(id)
    V(id, 'code', description, SC(*secs), inp, pol=pol, now=now)


def code_op(response=None, request=None, ops_key='GET /orders/{id}'):
    return policy(services=[service('shop-api', ops={ops_key: op(request=request, response=response)})])


CV('1810-code-accepted-shapes', 'Code-shaped strings leave as keep:, case and separators as written.',
   jresp(J.dumps({'status': 'DELIVERED', 'state': 'in_transit', 'reason': 'card_declined',
                  'returnStatus': 'Return-Requested', 'type': 'ok', 'kind': 'x' * 32})),
   code_op(response=part(body={'$.status': CODE, '$.state': CODE, '$.reason': CODE, '$.returnStatus': CODE,
                               '$.type': CODE, '$.kind': CODE})))
CV('1811-code-length-bounds', 'Length bounds 2..32 bytes: 0, 1 and 33 letters leave as shapes; 2 and 32 as keep:.',
   jresp(J.dumps({'status': '', 'state': 'A', 'stage': 'AB', 'phase': 'Q' * 32, 'step': 'Q' * 33})),
   code_op(response=part(body={'$.status': CODE, '$.state': CODE, '$.stage': CODE, '$.phase': CODE, '$.step': CODE})))
CV('1812-code-digits-refused', 'A single digit anywhere makes the value a shape (E404, v2, 2026, 0, ORDER_1).',
   jresp(J.dumps({'code': 'E404', 'mode': 'v2', 'phase': '2026', 'level': '0', 'status': 'ORDER_1'})),
   code_op(response=part(body={'$.code': CODE, '$.mode': CODE, '$.phase': CODE, '$.level': CODE, '$.status': CODE})))
CV('1813-code-spaces-and-punctuation', 'Spaces, dots, colons, slashes, plus, tab, newline and trailing space are refused.',
   jresp(J.dumps({'a': {'status': 'in transit'}, 'b': {'status': 'IN.TRANSIT'}, 'c': {'status': 'a:b'},
                  'd': {'status': 'a/b'}, 'e': {'status': 'a+b'}, 'f': {'status': '\tOPEN'}, 'g': {'status': 'OPEN\n'},
                  'h': {'status': 'OPEN '}, 'i': {'status': "o'clock"}, 'j': {'status': 'ok!'}})),
   code_op(response=part(body={'$.*.status': CODE})))
CV('1814-code-unicode-lookalikes', 'Non-ASCII letters never match: Cyrillic E, fullwidth, zero-width space, Greek, sharp s, e acute, NBSP.',
   jresp(J.dumps({'a': {'status': 'DЕLIVERED'}, 'b': {'status': 'ＤＥＬＩＶＥＲＥＤ'},
                  'c': {'status': 'DELI​VERED'}, 'd': {'status': 'ΑΒ'}, 'e': {'status': 'große'},
                  'f': {'status': 'annulé'}, 'g': {'status': 'OPEN '}})),
   code_op(response=part(body={'$.*.status': CODE})))
CV('1815-code-non-strings', 'Numbers, booleans and null under code leave as their shapes (code never applies to them).',
   jresp('{"a":{"status":1},"b":{"status":2.5},"c":{"status":true},"d":{"status":false},"e":{"status":null},"f":{"status":-0}}'),
   code_op(response=part(body={'$.*.status': CODE})))
CV('1816-code-nested-and-arrays', 'Nested paths and array elements: each leaf is checked on its own.',
   jresp(J.dumps({'order': {'payment': {'status': 'AUTHORIZED', 'method': 'card'}},
                  'items': [{'status': 'SHIPPED'}, {'status': 'back order'}, {'status': 'RETURNED'}, {'status': 7}],
                  'events': [{'type': 'order_created'}, {'type': 'order.updated'}]})),
   code_op(response=part(body={'$.order.payment.status': CODE, '$.order.payment.method': CODE,
                               '$.items[*].status': CODE, '$.events[*].type': CODE})))
CV('1817-code-on-container', 'code on an object or an array is ignored like keep: the children get their own rules.',
   jresp(J.dumps({'status': {'code': 'OPEN', 'text': 'Open'}, 'type': ['A', 'B']})),
   code_op(response=part(body={'$.status': CODE, '$.type': CODE, '$.status.code': CODE})), secs=('5.0', '5.6'))
CV('1818-code-keep-max-bytes', 'code also honours limits.keep_max_bytes: with 8, SHIPPED leaves and DELIVERED does not.',
   jresp(J.dumps({'a': {'status': 'SHIPPED'}, 'b': {'status': 'DELIVERED'}, 'c': {'status': 'AB'}})),
   policy(limits={'keep_max_bytes': 8},
          services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.*.status': CODE}))})]),
   secs=('5.3', '5.6'))
CV('1819-code-query-and-headers', 'code on query and header values: the same shape rule, repeated values one by one.',
   X('GET', '/orders', 'status=shipped&status=in%20transit&type=Return-Requested&channel=web2',
     h=[('X-Order-Status', 'DELIVERED'), ('X-Error-Code', 'E_42')],
     rh=[('X-Result', 'card_declined')]),
   policy(services=[service('shop-api', request=part(query={'status': CODE, 'type': CODE, 'channel': CODE},
                                                     headers={'x-order-status': CODE, 'x-error-code': CODE}),
                            response=part(headers={'x-result': CODE}))]), secs=('5.6', '8.1', '8.3'))
CV('1820-code-path-parameter', 'code on a path parameter: {keep:SHIPPED} for a code.',
   X('GET', '/orders/state/SHIPPED'), policy(services=[service('shop-api', ops={'GET /orders/state/{state}': op(
       request=part(path={'state': CODE}))})]), secs=('4.2', '5.6'))
CV('1821-code-path-parameter-refused', 'code on a path parameter with a value that is not a code (percent-decoded first).',
   X('GET', '/orders/state/in%20transit'), policy(services=[service('shop-api', ops={'GET /orders/state/{state}': op(
       request=part(path={'state': CODE}))})]), secs=('4.2', '5.6'))
CV('1822-code-form-body', 'code on form fields: status leaves, a reason with spaces is a shape.',
   X('POST', '/payments', h=[('Content-Type', 'application/x-www-form-urlencoded')],
     body='status=paid&reason=card+declined&method=card'),
   policy(services=[service('shop-api', request=part(body={'$.status': CODE, '$.reason': CODE, '$.method': CODE}))]),
   secs=('5.6', '9.1'))
CV('1823-code-errors-rules', 'code in errors rules: E_STOCK leaves on a 409, ERR-409 does not.',
   jresp('{"error":{"code":"E_STOCK","message":"Out of stock"},"errors":[{"code":"ERR-409"}]}', status=409),
   policy(services=[service('shop-api', errors=part(body={'$.error.code': CODE}),
                            ops={'GET /orders/{id}': op(response=part(body={'$.errors[*].code': CODE}))})]),
   secs=('5.0', '5.6'))
CV('1824-code-does-not-fall-back', 'A value refused by code leaves as its shape even when a weaker group keeps it.',
   jresp('{"status":"in transit","reason":"lost"}'),
   policy(global_=scope(response=part(body={'$.status': KEEP, '$.reason': KEEP})),
          services=[service('shop-api', ops={'GET /orders/{id}': op(response=part(body={'$.status': CODE, '$.reason': CODE}))})]),
   secs=('5.0', '5.6'))
CV('1825-code-escapes-and-invalid', 'JSON escapes are decoded before the check; lone surrogates are drop:str:invalid.',
   jresp('{"a":{"status":"\\u0044ELIVERED"},"b":{"status":"\\ud800"},"c":{"status":"in\\u005ftransit"},"d":{"status":"A\\u0000"}}'),
   code_op(response=part(body={'$.*.status': CODE})))
CV('1826-code-separators-only', 'The shape allows separators only ("--", "__", "-_"): they leave like any code.',
   jresp('{"a":{"status":"--"},"b":{"status":"__"},"c":{"status":"-_"},"d":{"status":"-"}}'),
   code_op(response=part(body={'$.*.status': CODE})))
CV('1827-code-discovery', 'Discovery on: a code rule is a rule, so a refused value adds no disc entry.',
   jpost('{"status":"in transit","note":"x"}'),
   policy(discovery=(True, MODE_EXPIRES), services=[service('shop-api', request=part(body={'$.status': CODE}))]),
   secs=('5.6', '15'))
CV('1828-code-service-wildcard-accepted', 'code on $.items[*].status and $.*.state in a service rule is accepted (H2 is about global rules).',
   jresp('{"items":[{"status":"OPEN"}],"x":{"state":"done"}}'),
   policy(services=[service('shop-api', response=part(body={'$.items[*].status': CODE, '$.*.state': CODE}))]))

# H1 and H2 refuse code like keep and hmac (hardening.md 2.1, v1.11).
_n = 1849
for _h, _place in (('authorization', 'global-request'), ('cookie', 'op-request'), ('set-cookie', 'op-response'),
                   ('proxy-authorization', 'service-errors')):
    _n += 1
    unsafe('%d-refuse-h1-%s-code-%s' % (_n, _h, _place),
           'H1: code on header %s in %s rules: the source refuses the policy.' % (_h, _place.replace('-', ' ')),
           H1_PLACES[_place](part(headers={_h: CODE})))
unsafe('1855-refuse-h2-global-star-code', 'H2: code on $.*.status in the global response body rules.',
       policy(global_=scope(response=part(body={'$.*.status': CODE}))))
unsafe('1856-refuse-h2-global-array-code', 'H2: code on $.items[*].status in the global request body rules.',
       policy(global_=scope(request=part(body={'$.items[*].status': CODE}))))
unsafe('1857-refuse-h2-global-errors-code', 'H2: code on $.errors[*].code in the global errors body rules.',
       policy(global_=scope(errors=part(body={'$.errors[*].code': CODE}))))



# =========================================================================== graphql (spec v1.14: 5.7, 9.1)
# The graphql action turns a GraphQL document into its shape (names kept, every literal a placeholder) and,
# behind the introspection gate, lets the names of an introspection result out. tt-core and keyguard accept it
# only on $.query / $ / the query parameter query of a request and under $.data.__schema or $.data.__type of a
# response (policy.md 1.6): the vectors below use those places, plus a few the source applies as received.

GQL = {'action': 'graphql'}
SG = lambda *secs: ['sanitizer.md#' + s for s in secs] + ['policy.md#1.6']  # noqa: E731
GQL_ACCEPTED = []
GQL_PATH = '/graphql'
CT_GQL = ('Content-Type', 'application/graphql')


def GV(id, description, inp, pol, secs=('5.7',), now=NOW):
    GQL_ACCEPTED.append(id)
    V(id, 'graphql', description, SG(*secs), inp, pol=pol, now=now)


INTRO_RESP = ('$.data.__schema.queryType.name', '$.data.__schema.mutationType.name', '$.data.__schema.types[*].kind',
              '$.data.__schema.types[*].name', '$.data.__schema.types[*].fields[*].name',
              '$.data.__schema.types[*].fields[*].args[*].name', '$.data.__schema.types[*].fields[*].type.kind',
              '$.data.__schema.types[*].fields[*].type.name', '$.data.__schema.types[*].fields[*].type.ofType.kind',
              '$.data.__schema.types[*].fields[*].type.ofType.name', '$.data.__schema.types[*].enumValues[*].name',
              '$.data.__schema.directives[*].name', '$.data.__schema.directives[*].locations[*]',
              '$.data.__type.name', '$.data.__type.kind', '$.data.__type.fields[*].name')


def gql_policy(request=None, response=None, ops_key='POST /graphql', extra_ops=None, **kw):
    ops = {ops_key: op(request=request or part(body={'$.query': GQL, '$.variables.id': HMAC('order')}),
                       response=response or part(body={p: GQL for p in INTRO_RESP}))}
    ops.update(extra_ops or {})
    return policy(services=[service('orders-graph', ops=ops)], **kw)


def gql_post(query, variables=None, rbody='{"data":{"order":{"id":"ORD-1","status":"SHIPPED"}}}', op_name=None,
             status=200, **kw):
    b = {'query': query}
    if variables is not None:
        b['variables'] = variables
    if op_name is not None:
        b['operationName'] = op_name
    return X('POST', GQL_PATH, h=[CT_JSON], body=J.dumps(b), status=status, rh=[CT_JSON], rbody=rbody,
             service='orders-graph', **kw)


INTROSPECTION_QUERY = ('query IntrospectionQuery { __schema { queryType { name } mutationType { name } '
                       'types { ...FullType } directives { name description locations args { ...InputValue } } } }\n'
                       'fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name '
                       'description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } '
                       'enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } }\n'
                       'fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }\n'
                       'fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name } } }')


def intro_result(ntypes=3):
    types = [{'kind': 'OBJECT', 'name': 'Query', 'description': 'Root query of Mario Rossi\'s shop',
              'fields': [{'name': 'order', 'description': 'One order', 'isDeprecated': False, 'deprecationReason': None,
                          'args': [{'name': 'id', 'description': None, 'defaultValue': '"ORD-1"',
                                    'type': {'kind': 'NON_NULL', 'name': None, 'ofType': {'kind': 'SCALAR', 'name': 'ID', 'ofType': None}}}],
                          'type': {'kind': 'OBJECT', 'name': 'Order', 'ofType': None}}],
              'enumValues': None},
             {'kind': 'ENUM', 'name': 'OrderStatus', 'description': None, 'fields': None,
              'enumValues': [{'name': 'SHIPPED', 'description': 'sent', 'isDeprecated': False, 'deprecationReason': None},
                             {'name': 'IN_TRANSIT_2', 'description': None, 'isDeprecated': True, 'deprecationReason': 'use SHIPPED'}]}]
    for i in range(ntypes - 2):
        types.append({'kind': 'OBJECT', 'name': 'Type%d' % i, 'description': None, 'enumValues': None,
                      'fields': [{'name': 'field%d' % i, 'description': None, 'args': [], 'isDeprecated': False,
                                  'deprecationReason': None, 'type': {'kind': 'SCALAR', 'name': 'String', 'ofType': None}}]})
    return J.dumps({'data': {'__schema': {'queryType': {'name': 'Query'}, 'mutationType': None, 'types': types,
                                          'directives': [{'name': 'include', 'description': 'Include when true',
                                                          'locations': ['FIELD', 'FRAGMENT_SPREAD'], 'args': []}]}}})


GV('2000-graphql-named-query', 'A named query with variables: the document leaves as its shape, the variable id as an HMAC token, operationName as a shape.',
   gql_post('query GetOrder($id: ID!) {\n  order(id: $id) { id status items { sku qty } }\n}', {'id': 'ORD-2026-000184'},
            op_name='GetOrder'),
   gql_policy())
GV('2001-graphql-inline-literals', 'Inline literals of every kind become placeholders: string, block string, int, float, true, false, null, enum, list, object.',
   gql_post('{ orders(buyer: "mario.rossi@example.com", note: """VIP\n "client" """, first: 25, minTotal: 99.90, '
            'gift: true, paid: false, coupon: null, status: SHIPPED, ids: ["ORD-1", "ORD-2"], '
            'where: {city: "Torino", zip: 10121}) { id } }'),
   gql_policy())
GV('2002-graphql-mutation-fragments-directives', 'Mutation with list and non-null variable types, a default value, aliases, fragment spreads, inline fragments and directives.',
   gql_post('mutation CreateOrder($in: [OrderIn!]! = [{note: "urgente"}], $notify: Boolean = true) @audit(reason: "x") {\n'
            '  created: createOrder(input: $in) @include(if: $notify) { ...OrderParts ... on Order { total } ... @skip(if: false) { eta } }\n'
            '}\nfragment OrderParts on Order { id status }',
            {'in': [{'note': 'consegna al portiere'}], 'notify': True}, rbody='{"data":{"created":{"id":"ORD-9"}}}'),
   gql_policy())
GV('2003-graphql-anonymous-and-shorthand', 'Shorthand and anonymous operations, comments, commas, a BOM and tabs are not output.',
   gql_post('﻿# order lookup for mario.rossi@example.com\n{\torder(id: 42) ,, { id , status } }'),
   gql_policy())
GV('2004-graphql-collapsed-names', 'Names that look like values (six digits, 16+ hex digits, over 64 bytes) leave as *; 5 digits and 64 bytes stay.',
   gql_post('{ o4821553: order(id: 1) { deadbeefdeadbeef p12345 %s %s } }' % ('n' * 64, 'n' * 65)),
   gql_policy())
GV('2005-graphql-not-a-document', 'Strings that are not executable documents leave as the shape of the string.',
   X('POST', GQL_PATH, h=[CT_JSON], service='orders-graph', rh=[CT_JSON], rbody='{"data":null}',
     body=J.dumps({'query': 'Mario Rossi'})),
   gql_policy())
_bad = ['type Query { order: Order }', '{ a(x: 01) }', '{ a(x: 1.) }', '{ a(x: 1abc) }', '{ a(x: "open) }',
        '{ a(x: "line\nbreak") }', '{ a(x: "\\q") }', '{ a } }', '{ a', '{}', 'query Q() { a }', '{ a() }',
        '{ a } extra', 'fragment on on T { a }', '{ a(x: ?s) }', '{ a(x: 1) } *', '{ "s" }', 'query', '',
        '{ a(x: "\\u12G4") }', '{ a(x: """never closed) }', '{ a(x: 1e) }', '{ a(x: -) }', '{ a. }']
GV('2006-graphql-syntax-errors', 'Lexical and syntactic errors (type definitions, bad numbers, open strings, bad escapes, unbalanced or empty brackets, extra tokens, characters outside the grammar): the shape of the string.',
   X('GET', GQL_PATH, '&'.join('query=' + pct for pct in [
       ''.join(c if c.isalnum() else '%%%02X' % ord(c) for c in s) for s in _bad]),
     service='orders-graph', rh=[CT_JSON], rbody='{"errors":[{"message":"Syntax Error"}]}'),
   gql_policy(ops_key='GET /graphql', request=part(query={'query': GQL})), secs=('5.7', '8.3'))
GV('2007-graphql-nesting-limit', 'At most 64 open brackets ({, ( and [ together): 64 pass, 65 leave as the shape.',
   X('GET', GQL_PATH, 'query=' + '%7Ba' * 64 + '%7D' * 64 + '&query=' + '%7Ba' * 65 + '%7D' * 65
     + '&query=%7Ba(x%3A' + '%5B' * 62 + '1' + '%5D' * 62 + ')%7D'
     + '&query=%7Ba(x%3A' + '%5B' * 63 + '1' + '%5D' * 63 + ')%7D',
     service='orders-graph', rh=[CT_JSON], rbody='{"data":{}}'),
   gql_policy(ops_key='GET /graphql', request=part(query={'query': GQL})), secs=('5.7', '8.3'))
GV('2008-graphql-length-limit', 'A shape of exactly 32768 bytes leaves; one byte more leaves as the shape of the string.',
   X('POST', GQL_PATH, h=[CT_JSON], service='orders-graph', rh=[CT_JSON], rbody='{"data":{}}',
     body=J.dumps({'query': '{' + 'a ' * 16382 + 'bc}', 'q2': '{' + 'a ' * 16382 + 'bcd}'})),
   gql_policy(request=part(body={'$.query': GQL, '$.q2': GQL})))
GV('2009-graphql-get-query-parameter', 'GET with the document in the query parameter query (percent-encoded, + as space) and variables as JSON text.',
   X('GET', GQL_PATH, 'query=query+GetOrder(%24id%3A+ID!)+%7B+order(id%3A+%24id)+%7B+id+%7D+%7D&variables=%7B%22id%22%3A%22ORD-7%22%7D&operationName=GetOrder',
     service='orders-graph', rh=[CT_JSON], rbody='{"data":{"order":{"id":"ORD-7"}}}'),
   gql_policy(ops_key='GET /graphql', request=part(query={'query': GQL})), secs=('5.7', '8.3'))
GV('2010-graphql-application-graphql-body', 'A request body application/graphql with a graphql rule on $ is one string leaf.',
   X('POST', GQL_PATH, h=[CT_GQL], body='query { order(id: "ORD-1") { id } }', service='orders-graph',
     rh=[CT_JSON], rbody='{"data":{"order":{"id":"ORD-1"}}}'),
   gql_policy(request=part(body={'$': GQL})), secs=('5.7', '9.1'))
GV('2011-graphql-application-graphql-no-rule', 'Without a graphql rule on $ an application/graphql body stays drop:bytes:<class>, as before v1.14.',
   X('POST', GQL_PATH, h=[CT_GQL], body='query { order(id: "ORD-1") { id } }', service='orders-graph',
     rh=[CT_JSON], rbody='{"data":{"order":{"id":"ORD-1"}}}'),
   gql_policy(request=part(body={'$.query': GQL})), secs=('9.1',))
GV('2012-graphql-application-graphql-invalid-utf8', 'An application/graphql body that is not UTF-8 under a graphql rule: drop:str:invalid, and the gate stays closed.',
   X('POST', GQL_PATH, h=[CT_GQL], body=b'{ __schema { types { name } } }\xff', service='orders-graph',
     rh=[CT_JSON], rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy(request=part(body={'$': GQL})), secs=('5.7', '9.1'))
GV('2013-graphql-non-strings', 'graphql on numbers, booleans, null and containers: shapes, and containers are walked like keep.',
   X('POST', GQL_PATH, h=[CT_JSON], service='orders-graph', rh=[CT_JSON], rbody='{"data":{}}',
     body='{"query":{"text":"{ a }"},"q1":1,"q2":true,"q3":null,"q4":["{ b }"]}'),
   gql_policy(request=part(body={'$.query': GQL, '$.query.text': GQL, '$.q1': GQL, '$.q2': GQL, '$.q3': GQL, '$.q4': GQL,
                                 '$.q4[*]': GQL})), secs=('5.0', '5.7'))
GV('2020-graphql-introspection-gate-open', 'The standard introspection query opens the gate: type, field, argument, enum and directive names leave; descriptions, default values and deprecation reasons are shapes.',
   gql_post(INTROSPECTION_QUERY, op_name='IntrospectionQuery', rbody=intro_result()),
   gql_policy())
GV('2021-graphql-introspection-arrays', 'With the gate open the response body keeps arrays up to 4096 elements (40 types here, max_array 32).',
   gql_post('{ __schema { types { name kind } } }', rbody=intro_result(40)),
   gql_policy())
GV('2022-graphql-gate-closed-mixed-root', 'A document that also selects a data field closes the gate: the names stay shapes, arrays keep max_array.',
   gql_post('{ __schema { types { name kind } } order(id: 1) { id } }', rbody=intro_result(40)),
   gql_policy())
GV('2023-graphql-gate-closed-alias', 'An alias __schema on a data field closes the gate (the alias trick).',
   gql_post('{ __schema: customers { types: list { name: fullName } } }',
            rbody='{"data":{"__schema":{"types":[{"name":"MarioRossi"},{"name":"GiuliaNeri"}]}}}'),
   gql_policy())
GV('2024-graphql-gate-closed-spread', 'A fragment spread at the root closes the gate, even towards introspection fields.',
   gql_post('{ ...Intro } fragment Intro on Query { __schema { types { name } } }',
            rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy())
GV('2025-graphql-gate-closed-other-operation', 'Two operations, one of them not introspection: the gate stays closed.',
   gql_post('query A { __schema { types { name } } } query B { order(id: 1) { id } }', op_name='A',
            rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy())
GV('2026-graphql-gate-closed-invalid-document', 'A request value under a graphql rule that is not a document closes the gate, even next to an introspection document.',
   X('POST', GQL_PATH, h=[CT_JSON], service='orders-graph', rh=[CT_JSON],
     body=J.dumps({'query': '{ __schema { types { name } } }', 'q2': 'not graphql'}),
     rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy(request=part(body={'$.query': GQL, '$.q2': GQL})))
GV('2027-graphql-gate-closed-no-request-rule', 'Without a graphql rule in the request the gate is closed: response graphql rules give shapes.',
   gql_post('{ __schema { types { name } } }', rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy(request=part(body={'$.variables.id': HMAC('order')})))
GV('2028-graphql-gate-closed-invalid-query-bytes', 'A query parameter under a graphql rule that is not UTF-8 (drop:bytes) closes the gate.',
   X('GET', GQL_PATH, 'query=%7B__schema%7Btypes%7Bname%7D%7D%7D&query=%FF', service='orders-graph', rh=[CT_JSON],
     rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}}}'),
   gql_policy(ops_key='GET /graphql', request=part(query={'query': GQL})), secs=('5.7', '8.3'))
GV('2029-graphql-response-names-only', 'With the gate open only safe GraphQL names leave: a space, a dot, six digits, 16 hex digits, 65 bytes, numbers and booleans are shapes.',
   gql_post('{ __type(name: "Order") { name kind fields { name } } }',
            rbody=J.dumps({'data': {'__type': {'name': 'Order', 'kind': 'OBJECT', 'fields': [
                {'name': 'id'}, {'name': 'buyer name'}, {'name': 'a.b'}, {'name': 'f123456'}, {'name': 'deadbeefdeadbeef'},
                {'name': 'n' * 65}, {'name': 'n' * 64}, {'name': 7}, {'name': True}, {'name': None}, {'name': '_x'}]}}})),
   gql_policy())
GV('2030-graphql-introspection-get', 'The gate also opens for an introspection document in a GET query parameter.',
   X('GET', GQL_PATH, 'query=%7B__type(name%3A%22Order%22)%7Bname+kind%7D%7D', service='orders-graph', rh=[CT_JSON],
     rbody='{"data":{"__type":{"name":"Order","kind":"OBJECT"}}}'),
   gql_policy(ops_key='GET /graphql', request=part(query={'query': GQL})), secs=('5.7', '8.3'))
GV('2031-graphql-errors-response', 'A GraphQL error response (200 with errors): messages and paths are shapes, data null.',
   gql_post('query GetOrder($id: ID!) { order(id: $id) { id } }', {'id': 'ORD-404'},
            rbody='{"errors":[{"message":"Order ORD-404 of mario.rossi@example.com not found","path":["order"],'
                  '"extensions":{"code":"NOT_FOUND"}}],"data":null}'),
   gql_policy())
GV('2032-graphql-discovery', 'Discovery on: a graphql rule is a rule, so neither the document nor the response names add disc entries.',
   gql_post('{ __schema { types { name } } }', rbody='{"data":{"__schema":{"types":[{"name":"Query"}]}},"extra":"x"}'),
   gql_policy(discovery=(True, MODE_EXPIRES)), secs=('5.7', '15'))
GV('2033-graphql-escapes', 'JSON escapes in the query member are decoded before the analysis (\\n, \\u0022 for quotes, \\t).',
   X('POST', GQL_PATH, h=[CT_JSON], service='orders-graph', rh=[CT_JSON], rbody='{"data":{}}',
     body='{"query":"query Q {\\n\\torder(id: \\u0022ORD-1\\u0022) { id }\\n}"}'),
   gql_policy())

# =========================================================================== host patterns (spec v1.5: 3.1, 3.5, 3.6)

OFF = 'off'


def HV(id, description, url_base, pol=None, secs=('3.1', '3.5'), path='/', amb=()):
    """Outbound GET with no body: only `service` depends on the host."""
    V(id, 'hosts', description, S(*secs), X('GET', path, dir='outbound', url_base=url_base),
      pol=policy() if pol is None else pol, amb=amb)


# ---- strict mode: copies of the vectors rewritten for v1.5, under hosts.discovery off
V('1900-hosts-off-default-drop-outbound', 'hosts',
  'Copy of 0007 under hosts.discovery off (strict mode): the host never leaves, service is host:unlisted.',
  S('3.1', '3.5', '13'),
  X('POST', '/v1/shipments', 'ref=ORD-2026-000184', h=[CT_JSON, ('X-Api-Key', 'sk_test_51Hc0nf0rmance')],
    body='{"orderId":"ORD-2026-000184","to":{"name":"Giulia Neri","city":"Torino"}}',
    status=201, rh=[CT_JSON], rbody='{"shipmentId":"SHP-77120","label":"https://labels.carrier.example/SHP-77120.pdf"}',
    dir='outbound', url_base='https://api.carrier.example'), pol=policy(hosts=OFF))
V('1901-hosts-off-unmatched-host', 'hosts', 'Copy of 1134 under hosts.discovery off: host:unlisted.', S('3.1', '3.5'),
  X('GET', '/v1/rates', dir='outbound', url_base='https://payments.example:443'),
  pol=policy(hosts=OFF, services=CARRIER['services']))
V('1902-hosts-off-net-error', 'hosts', 'Copy of 1137 under hosts.discovery off: host:unlisted, no resp part.', S('2', '3.5'),
  X('GET', '/v1/rates', dir='outbound', url_base='https://payments.example', net_error='timeout'), pol=policy(hosts=OFF))
V('1903-hosts-off-sampling-inherited', 'hosts', 'Copy of 1340 under hosts.discovery off.', S('12', '3.5'),
  X('GET', '/v1/rates', inherited=True, **OUT_RATES), pol=policy(rate_bp=0, hosts=OFF))
V('1904-hosts-off-sampling-outbound-trace', 'hosts', 'Copy of 1342 under hosts.discovery off.', S('12', '11', '3.5'),
  X('GET', '/v1/rates', h=[('X-Customer-Id', 'C-10042')], trace_id=TRACE, **OUT_RATES),
  pol=policy(identity=ID_HDR, rate_bp=u_tr + 1, hosts=OFF), amb=['A-SUBJECT-OUTBOUND'])
V('1905-hosts-off-sampling-no-baggage', 'hosts', 'Copy of 1343 under hosts.discovery off.', S('12', '3.5'),
  X('GET', '/v1/rates', h=[('baggage', 'tt.s=0')], **OUT_RATES), pol=policy(trust_baggage=True, hosts=OFF))
HV('1906-hosts-off-ipv6', 'Copy of 1142 under hosts.discovery off: an IPv6 literal is valid (v1.5) and leaves as host:unlisted.',
   'http://[2001:db8::1]:8080', policy(hosts=OFF), ('3.1', '3.5'))
HV('1907-hosts-off-discovery-mode', 'hosts.discovery off during discovery mode: the pattern, never the raw host (v1.5 changes 15).',
   'https://t-3912345678.tenant.example:8443', policy(hosts=OFF, discovery=(True, MODE_EXPIRES)), ('3.5', '15'))
HV('1908-hosts-off-hosts-allow', 'hosts.discovery off: a host in segments.hosts_allow still leaves exactly as listed.',
   'https://api.partner.example', policy(hosts=OFF, hosts_allow=['api.partner.example']))
HV('1909-hosts-auto-explicit', 'An explicit hosts.discovery auto is the same as an absent hosts object.',
   'https://api.partner.example', policy(hosts='auto'))

# ---- safe-label rule (3.5 a-d)
HV('1910-hosts-label-six-digits', 'A label with 6 or more consecutive digits becomes {*} (rule b).',
   'https://t-3912345678.tenant.example')
HV('1911-hosts-label-five-digits', 'Five consecutive digits are not a value by rule b: the label stays.',
   'https://shard-12345.db.example')
HV('1912-hosts-label-uuid', 'A UUID label (starting with a letter, so it passes rule a) becomes {*}.',
   'https://a50e8400-e29b-41d4-a716-446655440000.files.example')
HV('1913-hosts-label-hex12', 'A run of 12 hexadecimal characters inside a label makes it {*} (rule c).',
   'https://cdn-9f8e7d6c5b4a.assets.example')
HV('1914-hosts-label-hex11', 'Eleven hexadecimal characters do not trigger rule c: the label stays.',
   'https://build-9f8e7d6c5b4.ci.example')
HV('1915-hosts-label-digit-first', 'A label must start with a letter (rule a): 1password becomes {*}.',
   'https://1password.example')
HV('1916-hosts-label-63', 'A label of 63 bytes is the longest literal label.',
   'https://' + 'k' * 63 + '.example')
HV('1927-hosts-label-64', 'A label of 64 bytes fails rule a: {*}.', 'https://' + 'k' * 64 + '.example')
HV('1917-hosts-label-hyphen-first', 'A label starting with a hyphen fails rule a; one ending with a hyphen passes it.',
   'https://-edge.cdn-.example')
HV('1918-hosts-label-underscore', 'An underscore is outside [a-z0-9.-]: the host is not valid (3.1).',
   'https://_dmarc.carrier.example')
HV('1919-hosts-consecutive-stars', 'Consecutive {*} labels are kept one by one, never merged.',
   'https://ab12cd34ef56.0012345678.u-4400000001.cdn.example')
HV('1920-hosts-label-hex-letters', 'Twelve hex letters (no digit) are still a run of rule c.',
   'https://deadbeefcafe.example')
HV('1921-hosts-tld-unsafe', 'The rule applies to every label, the last one included.',
   'https://api.carrier.123456')
HV('1922-hosts-base-wins', 'A matching base keeps the declared service name, whatever the labels look like.',
   'https://api.carrier.example', CARRIER, path='/v1/shipments')
HV('1923-hosts-allow-unsafe-literal',
   'segments.hosts_allow wins over the pattern: the listed host leaves as listed, digits included.',
   'https://t-3912345678.tenant.example', policy(hosts_allow=['t-3912345678.tenant.example']))
HV('1924-hosts-discovery-mode-auto',
   'Discovery mode with hosts.discovery auto: still the pattern, never the raw host (v1.5 changes 15).',
   'https://t-3912345678.tenant.example', policy(discovery=(True, MODE_EXPIRES)), ('3.5', '15'))
HV('1925-hosts-single-label', 'A single-label host (cluster-internal name) with its port.', 'http://orders-svc:8080')
HV('1926-hosts-localhost', 'localhost is a single safe label.', 'http://localhost:3000')

# ---- ports (3.1, 3.5)
HV('1930-hosts-port-non-default', 'A non-default port is kept after the pattern.', 'https://api.carrier.example:8443')
HV('1931-hosts-port-http-default', 'Port 80 is the default of http and is removed.', 'http://api.carrier.example:80')
HV('1932-hosts-port-cross-default', 'Port 80 is not the default of https: it is kept.', 'https://api.carrier.example:80')
HV('1933-hosts-port-leading-zeros', 'Leading zeros of the port are removed before comparing with the default.',
   'https://api.carrier.example:0443', amb=['A-PORT-ZEROS'])
HV('1934-hosts-port-with-star', 'A {*} label and a port together.', 'https://t-3912345678.tenant.example:9443')

# ---- IP literals (3.6)
HV('1940-hosts-ipv4-private', 'IPv4 in 10.0.0.0/8: ip:private, never the address.', 'http://10.0.0.5', secs=('3.5', '3.6'))
HV('1941-hosts-ipv4-private-port', 'IPv4 in 192.168.0.0/16 with a port.', 'http://192.168.1.20:8080', secs=('3.5', '3.6'))
HV('1942-hosts-ipv4-public', 'A public IPv4 address: ip:public.', 'https://8.8.8.8', secs=('3.5', '3.6'))
HV('1943-hosts-ipv4-link-local', 'The metadata address 169.254.169.254 is link-local: ip:private.',
   'http://169.254.169.254', secs=('3.5', '3.6'))
HV('1944-hosts-ipv4-cgnat', 'Shared address space 100.64.0.0/10 is private.', 'http://100.64.1.1', secs=('3.5', '3.6'))
HV('1945-hosts-ipv4-edge-172', '172.32.0.1 is just outside 172.16.0.0/12: public.', 'http://172.32.0.1', secs=('3.5', '3.6'))
HV('1946-hosts-ipv4-leading-zero', 'An IPv4-looking host with a leading zero is not an ipv4 literal: every label is {*}.',
   'http://010.0.0.1', secs=('3.5', '3.6'))
HV('1947-hosts-ipv4-trailing-dot', 'The final dot is removed before recognizing an IPv4 literal.', 'http://10.0.0.5.',
   secs=('3.5', '3.6'))
HV('1948-hosts-ipv4-hosts-allow', 'An IPv4 literal listed in segments.hosts_allow leaves as listed.', 'http://10.0.0.5:8080',
   policy(hosts_allow=['10.0.0.5:8080']), ('3.1', '3.6'))
HV('1949-hosts-ipv6-loopback', 'IPv6 loopback [::1]: ip:private.', 'http://[::1]:3000', secs=('3.1', '3.6'))
HV('1950-hosts-ipv6-public', 'A global unicast IPv6 address: ip:public.', 'https://[2606:4700::1111]', secs=('3.1', '3.6'))
HV('1951-hosts-ipv6-mapped-private', 'IPv4-mapped IPv6 takes the class of the embedded IPv4 (10.0.0.1: private).',
   'http://[::ffff:10.0.0.1]', secs=('3.1', '3.6'))
HV('1952-hosts-ipv6-mapped-public', 'IPv4-mapped IPv6 with a public embedded IPv4.', 'http://[::ffff:8.8.8.8]',
   secs=('3.1', '3.6'))
HV('1953-hosts-ipv6-ula', 'Unique local fd00::/8 with a port: ip:private.', 'http://[fd12:3456::1]:9000', secs=('3.1', '3.6'))
HV('1954-hosts-ipv6-zone', 'A zone identifier is not accepted: host:invalid.', 'http://[fe80::1%25eth0]', secs=('3.1',))
HV('1955-hosts-ipv6-bad-groups', 'Two "::" are not an IPv6 literal: host:invalid.', 'http://[2001:db8::1::2]', secs=('3.1',))
HV('1956-hosts-ipv6-nine-groups', 'Nine groups are not an IPv6 literal: host:invalid.', 'http://[1:2:3:4:5:6:7:8:9]',
   secs=('3.1',))
HV('1957-hosts-ipv6-uppercase', 'Hexadecimal digits are case-insensitive.', 'http://[2001:DB8::1]', secs=('3.1', '3.6'))
HV('1958-hosts-ipv6-unbracketed', 'An IPv6 address without brackets is not a host: host:invalid.', 'http://2001:db8::1',
   secs=('3.1',))
HV('1959-hosts-ipv6-unspecified', 'The unspecified address [::] is private.', 'http://[::]', secs=('3.1', '3.6'))
HV('1960-hosts-ipv6-trailing-garbage', 'Anything after "]" other than ":port" makes the host invalid.', 'http://[::1]x',
   secs=('3.1',))
HV('1961-hosts-ipv6-ipv4-tail', 'An IPv4 tail in a public IPv6 address.', 'http://[2001:470::203.0.113.9]',
   secs=('3.1', '3.6'))

# ---- IDN and punycode (3.1, 3.5)
HV('1965-hosts-punycode', 'A punycode label (xn--) stays literal when it passes the rule.', 'https://xn--bcher-kva.example')
HV('1966-hosts-punycode-uppercase', 'Uppercase punycode is lowercased first.', 'https://XN--BCHER-KVA.Example')
HV('1967-hosts-punycode-digits', 'A punycode label with 6 consecutive digits becomes {*}.', 'https://xn--3912345678-abc.example')
HV('1968-hosts-idn-raw', 'A raw non-ASCII host is not valid (no IDNA conversion): host:invalid.', 'https://bücher.example')

# ---- case, dots, length, many labels (3.1, 3.5)
HV('1970-hosts-uppercase', 'Scheme and host are lowercased before the rule.', 'HTTPS://API.Carrier.EXAMPLE')
HV('1971-hosts-trailing-dot', 'One final dot (fully qualified name) is removed.', 'https://api.carrier.example.')
HV('1972-hosts-trailing-dot-port', 'A final dot before the port.', 'https://api.carrier.example.:8443')
HV('1973-hosts-empty-label', 'An empty label in the middle: host:invalid.', 'https://api..carrier.example')
HV('1974-hosts-leading-dot', 'A leading dot: host:invalid.', 'https://.carrier.example')
HV('1975-hosts-two-trailing-dots', 'Two final dots leave an empty label: host:invalid.', 'https://carrier.example..')
HV('1976-hosts-253-bytes', 'A host of exactly 253 bytes is valid; its labels follow the rule.',
   'https://' + '.'.join(['k' * 62] * 3 + ['m' * 56, 'example']))
HV('1977-hosts-254-bytes', 'A host of 254 bytes is not valid: host:invalid.',
   'https://' + '.'.join(['k' * 62] * 3 + ['m' * 57, 'example']))
HV('1978-hosts-many-labels', 'Many single-letter labels: every label is kept, in order.',
   'https://' + '.'.join('abcdefghijklmnopqrstuvwxyz') + '.example')
HV('1979-hosts-many-labels-mixed', 'Many labels, some unsafe: each unsafe label is one {*}.',
   'https://' + '.'.join(['x1', '1x', 'a123456', 'b', '9', 'c'] * 4) + '.example')
HV('1980-hosts-only-dot', 'A host made of one dot is invalid.', 'https://.')
HV('1981-hosts-one-char-labels-max', 'The largest pattern: 127 one-character labels that all become {*}.',
   'https://' + '.'.join(['1'] * 127))

# ---- policy acceptance
V('1990-refuse-hosts-discovery-value', 'refusal', 'hosts.discovery must be auto or off.',
  ['policy.md#2', 'sanitizer.md#3.5'], X('GET', '/'), pol=policy(extra={'hosts': {'discovery': 'on'}}))
V('1991-refuse-hosts-unknown-field', 'refusal', 'hosts accepts no other field.', ['policy.md#2', 'sanitizer.md#3.5'],
  X('GET', '/'), pol=policy(extra={'hosts': {'discovery': 'auto', 'allow': []}}))
V('1992-refuse-hosts-empty', 'refusal', 'hosts without discovery is not valid.', ['policy.md#2', 'sanitizer.md#3.5'],
  X('GET', '/'), pol=policy(extra={'hosts': {}}))

# =========================================================================== subject from a JSON header (11 step 4 bis, spec v1.18)

import base64 as _b64  # noqa: E402

JP_HDR = 'X-User-Context'


def jp_id(path='user.id', name='x-user-context'):
    return {'from': 'header', 'name': name, 'json_path': path}


def jp_vec(vid, desc, value, path='user.id', secs=('11', '9.2'), name='x-user-context', hdr=JP_HDR, extra_h=(), **kw):
    """One inbound exchange whose subject header is `value` (str or bytes)."""
    V(vid, 'subject-sampling', desc, S(*secs), X('GET', '/', h=[(hdr, value)] + list(extra_h)),
      pol=policy(identity=jp_id(path, name)), **kw)


def b64s(raw, url=False, pad=True):
    enc = _b64.urlsafe_b64encode if url else _b64.b64encode
    out = enc(raw if isinstance(raw, bytes) else raw.encode('utf-8')).decode('ascii')
    return out if pad else out.rstrip('=')


# Documents chosen so that the standard and the URL alphabet differ ("??>>" gives '/' '+' and '_' '-') and the
# padding is not empty.
JP_DOC = '{"user":{"id":"u-10042"},"pad":"??>>~~"}'
assert '+' in b64s(JP_DOC) or '/' in b64s(JP_DOC)
assert len(JP_DOC.encode()) % 3 != 0 and ('-' in b64s(JP_DOC, True) or '_' in b64s(JP_DOC, True))

jp_vec('2100-subject-json-plain', 'json_path "user.id" reads a nested member of a header that is a JSON object.',
       '{"user":{"id":"u-10042","name":"n"},"roles":["a"]}')
jp_vec('2101-subject-json-base64-std-padded', 'Same subject token as 2100 shape: base64 (standard alphabet) with padding.',
       b64s(JP_DOC), secs=('11',))
jp_vec('2102-subject-json-base64-std-unpadded', 'Standard alphabet without padding: same subject token as 2101.',
       b64s(JP_DOC, pad=False), secs=('11',))
jp_vec('2103-subject-json-base64url-padded', 'URL alphabet with padding: same subject token as 2101.',
       b64s(JP_DOC, url=True), secs=('11',))
jp_vec('2104-subject-json-base64url-unpadded', 'URL alphabet without padding: same subject token as 2101.',
       b64s(JP_DOC, url=True, pad=False), secs=('11',))
jp_vec('2105-subject-json-base64-plain-alphabet', 'A payload whose base64 has only characters common to both alphabets decodes.',
       b64s('{"user":{"id":"u-1"}}'), secs=('11',))
_mixed = None
for _i in range(2, 400):
    _d = '{"user":{"id":"u"},"p":"' + '\xff~?>' * _i + '"}'
    _s, _u = b64s(_d), b64s(_d, True)
    if '+' in _s and '/' in _s:
        _mixed = _s.replace('/', '_')
        break
assert _mixed and '+' in _mixed and '_' in _mixed
jp_vec('2106-subject-json-base64-mixed-alphabets', 'Characters of both alphabets in one value: no subject.', _mixed,
       secs=('11',))
jp_vec('2107-subject-json-top-level-member', 'A one-member path reads a top-level member.', '{"sub":"s-9","user":{"id":"x"}}',
       path='sub')
jp_vec('2108-subject-json-eight-members', 'The longest path: eight members.',
       '{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":"deep-1"}}}}}}}}', path='a.b.c.d.e.f.g.h', secs=('11',))
jp_vec('2109-subject-json-name-characters', 'Members may contain digits, "-" and "_".',
       '{"ctx_1":{"user-id":"u-77"}}', path='ctx_1.user-id', secs=('11',))
jp_vec('2110-subject-json-number-canonical', 'A numeric member uses its canonical form: 42.50 is "42.5".',
       '{"user":{"id":42.50}}', secs=('11', '10.2'))
jp_vec('2111-subject-json-number-same-as-string', 'The string "42.5" gives the same subject token as the number 42.50 (2110).',
       '{"user":{"id":"42.5"}}', secs=('11', '10.2'))
jp_vec('2112-subject-json-number-limits', 'A numeric member beyond the lexeme limits gives no subject.',
       '{"user":{"id":' + L65 + '}}', secs=('11', '5.3'))
jp_vec('2113-subject-json-duplicate-last-wins', 'A duplicated member: the last occurrence wins (same token as 2100 shape).',
       '{"user":{"id":"first"},"user":{"id":"u-10042"}}', secs=('11', '9.3'))
jp_vec('2114-subject-json-duplicate-inner', 'A duplicated inner member: the last wins even when it is an object after a string.',
       '{"user":"x","user":{"id":"u-10042"}}', secs=('11', '9.3'))
jp_vec('2115-subject-json-trim-spaces-tabs', 'Spaces and tabs around the value are removed (JSON).',
       ' \t{"user":{"id":"u-10042"}} \t', secs=('11',))
jp_vec('2116-subject-json-trim-base64', 'Spaces and tabs around the value are removed (base64).',
       ' \t' + b64s(JP_DOC) + '\t ', secs=('11',))
jp_vec('2117-subject-json-escapes', 'JSON escapes in the string are decoded: the subject is the UTF-8 of the text.',
       '{"user":{"id":"caf\\u00e9\\n\\"x"}}', secs=('11', '9.2'))
jp_vec('2118-subject-json-unicode-value', 'A non-ASCII value in the JSON is the subject as UTF-8.',
       '{"user":{"id":"Zoë-Ü"}}', secs=('11',))
jp_vec('2119-subject-json-sampled-by-subject', 'With a subject, sampling follows it (sampled_by subject).',
       '{"user":{"id":"u-sample"}}', secs=('11', '12'))
jp_vec('2120-subject-json-authorization-name', 'The header may have any name, here authorization; no bearer prefix is stripped.',
       '{"user":{"id":"u-auth"}}', name='authorization', hdr='Authorization', secs=('11',))
jp_vec('2121-subject-json-name-case', 'The header name is matched without regard to case.',
       '{"user":{"id":"u-10042"}}', hdr='x-USER-context', secs=('11', '8.0'))
jp_vec('2122-subject-json-base64-single-pad', 'Base64 with a single "=" of padding.', b64s('{"user":{"id":"u-100"}}'),
       secs=('11',))
assert b64s('{"user":{"id":"u-100"}}').endswith('=') and not b64s('{"user":{"id":"u-100"}}').endswith('==')

# ---- no subject
jp_vec('2130-subject-json-dotted-name-is-no-path', 'A member called "user.id" does not match: the dot always separates.',
       '{"user.id":"flat"}', secs=('11',))
jp_vec('2131-subject-json-intermediate-array', 'An intermediate member that is an array gives no subject.',
       '{"user":[{"id":"x"}]}', secs=('11',))
jp_vec('2132-subject-json-intermediate-string', 'An intermediate member that is a string gives no subject.',
       '{"user":"id"}', secs=('11',))
jp_vec('2133-subject-json-final-array', 'A final member that is an array gives no subject.', '{"user":{"id":["a"]}}',
       secs=('11',))
jp_vec('2134-subject-json-final-object', 'A final member that is an object gives no subject.', '{"user":{"id":{"x":1}}}',
       secs=('11',))
jp_vec('2135-subject-json-final-true', 'A final member that is true gives no subject.', '{"user":{"id":true}}',
       secs=('11',))
jp_vec('2136-subject-json-final-null', 'A final member that is null gives no subject.', '{"user":{"id":null}}',
       secs=('11',))
jp_vec('2137-subject-json-final-empty-string', 'A final member that is an empty string gives no subject.',
       '{"user":{"id":""}}', secs=('11',))
jp_vec('2138-subject-json-member-missing', 'A missing member gives no subject.', '{"user":{"name":"n"}}', secs=('11',))
jp_vec('2139-subject-json-root-array', 'A root that is an array gives no subject.', '[{"user":{"id":"x"}}]', secs=('11',))
jp_vec('2140-subject-json-root-string', 'A root that is a string gives no subject.', '"user"', secs=('11',))
jp_vec('2141-subject-json-not-json', 'A value that is neither JSON nor base64 gives no subject.', 'not json at all',
       secs=('11',))
jp_vec('2142-subject-json-trailing-data', 'Data after the object gives no subject.', '{"user":{"id":"x"}} trailing',
       secs=('11', '9.2'))
jp_vec('2143-subject-json-truncated', 'A truncated document gives no subject.', '{"user":{"id":"x"}', secs=('11', '9.2'))
jp_vec('2144-subject-json-trailing-comma', 'A trailing comma gives no subject.', '{"user":{"id":"x",}}',
       secs=('11', '9.2'))
jp_vec('2145-subject-json-bearer-prefix', 'The bearer prefix is not stripped with json_path: no subject.',
       'Bearer ' + b64s(JP_DOC), secs=('11',))
jp_vec('2146-subject-json-bom', 'A byte order mark before the JSON gives no subject.',
       b'\xef\xbb\xbf{"user":{"id":"x"}}', secs=('11', '9.2'))
jp_vec('2147-subject-json-bom-in-base64', 'A byte order mark inside the base64 payload gives no subject.',
       b64s(b'\xef\xbb\xbf{"user":{"id":"x"}}'), secs=('11', '9.2'))
jp_vec('2148-subject-json-invalid-utf8-header', 'A header that is not valid UTF-8 gives no subject.',
       b'{"user":{"id":"\xff\xfe"}}', secs=('11', '0.2'))
jp_vec('2149-subject-json-invalid-utf8-in-base64', 'Base64 whose payload is not valid UTF-8 gives no subject.',
       b64s(b'{"user":{"id":"\xff\xfe"}}'), secs=('11', '9.2'))
jp_vec('2150-subject-json-lone-surrogate', 'A string with an unpaired surrogate escape gives no subject.',
       '{"user":{"id":"\\ud800"}}', secs=('11', '9.2'))
_u = b64s(JP_DOC, pad=False)
jp_vec('2151-subject-json-base64-bad-length', 'A base64 value whose length mod 4 is 1 gives no subject.',
       _u[:4 * (len(_u) // 4) - 3], secs=('11',))
jp_vec('2152-subject-json-base64-padding-mismatch', 'Padding that does not complete a multiple of 4 gives no subject.',
       b64s(JP_DOC, pad=False) + '=', secs=('11',))
jp_vec('2153-subject-json-base64-three-equals', 'More than two "=" give no subject.', b64s('{"a":1}') .rstrip('=') + '===',
       secs=('11',))
jp_vec('2154-subject-json-base64-padding-inside', 'A "=" inside the value gives no subject.',
       b64s(JP_DOC)[:8] + '=' + b64s(JP_DOC)[9:], secs=('11',))
jp_vec('2155-subject-json-base64-whitespace-inside', 'A space inside a base64 value gives no subject.',
       b64s(JP_DOC)[:8] + ' ' + b64s(JP_DOC)[8:], secs=('11',))
jp_vec('2156-subject-json-only-padding', 'A value of only "=" gives no subject.', '==', secs=('11',))
jp_vec('2157-subject-json-blank', 'A value of only spaces gives no subject.', '   ', secs=('11',))
jp_vec('2158-subject-json-header-absent', 'The subject header is absent: no subject.', '{"user":{"id":"x"}}',
       hdr='X-Other', secs=('11',))
jp_vec('2159-subject-json-header-repeated', 'A repeated header is joined with ", ": no subject.',
       '{"user":{"id":"x"}}', extra_h=[(JP_HDR, '{"user":{"id":"y"}}')], secs=('11', '8.0'))
jp_vec('2160-subject-json-cookie-not-read', 'The subject is read from the header only: a cookie of the same name is ignored.',
       '{"user":{"id":"x"}}', hdr='Cookie', name='x-user-context', secs=('11',))

# ---- limits
_pre, _post = '{"user":{"id":"', '"}}'
jp_vec('2170-subject-json-8192-bytes', 'A raw value of exactly 8192 bytes is still read.',
       _pre + 'u' * (8192 - len(_pre) - len(_post)) + _post, secs=('11',))
jp_vec('2171-subject-json-8193-bytes', 'A raw value of 8193 bytes gives no subject.',
       _pre + 'u' * (8193 - len(_pre) - len(_post)) + _post, secs=('11',))
jp_vec('2172-subject-json-base64-8193-bytes', 'The 8192-byte limit applies to the raw header, before decoding.',
       b64s(_pre + 'u' * 6200 + _post), secs=('11',))
jp_vec('2173-subject-json-nested-ignored-members', 'Members off the path may be of any shape and size.',
       '{"x":[[[[1,2,{"a":null}]]]],"user":{"id":"u-10042","t":[true,false,1e5]},"y":{}}', secs=('11', '9.2'))
jp_vec('2174-subject-json-deep-nesting-off-path', 'Nesting deeper than any limit off the path does not matter: the whole document is validated, the member is read.',
       '{"x":' + '[' * 200 + ']' * 200 + ',"user":{"id":"u-10042"}}', secs=('11', '9.2'))
jp_vec('2175-subject-json-deep-nesting-invalid', 'The same deep nesting with one closing bracket missing: invalid, no subject.',
       '{"x":' + '[' * 200 + ']' * 199 + ',"user":{"id":"u-10042"}}', secs=('11', '9.2'))

# ---- acceptance of the policy body (policy.md 7.1, schema policy-compiled.v1)
V('2180-refuse-json-path-with-jwt-claim', 'refusal', 'json_path excludes jwt_claim.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'),
  pol=policy(identity={'from': 'header', 'name': 'x-user-context', 'json_path': 'user.id', 'jwt_claim': 'sub'}))
V('2181-refuse-json-path-from-cookie', 'refusal', 'json_path is for headers only.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'),
  pol=policy(identity={'from': 'cookie', 'name': 'ctx', 'json_path': 'user.id'}))
V('2182-refuse-json-path-nine-members', 'refusal', 'A path has at most eight members.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'),
  pol=policy(identity=jp_id('a.b.c.d.e.f.g.h.i')))
V('2183-refuse-json-path-empty', 'refusal', 'An empty path is not valid.', ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'),
  pol=policy(identity=jp_id('')))
V('2184-refuse-json-path-empty-member', 'refusal', 'A path with an empty member ("a..b") is not valid.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'), pol=policy(identity=jp_id('a..b')))
V('2185-refuse-json-path-trailing-dot', 'refusal', 'A path ending with a dot is not valid.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'), pol=policy(identity=jp_id('user.')))
V('2186-refuse-json-path-characters', 'refusal', 'A member outside [A-Za-z0-9_-] (here "$.user") is not valid.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'), pol=policy(identity=jp_id('$.user')))
V('2187-refuse-json-path-index', 'refusal', 'Array indexes are not part of a path ("items[0]").',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'), pol=policy(identity=jp_id('items[0].id')))
V('2188-refuse-json-path-member-65', 'refusal', 'A member of 65 characters is too long.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/'), pol=policy(identity=jp_id('a' * 65)))
V('2189-refuse-json-path-not-string', 'refusal', 'json_path must be a string.', ['policy.md#7.1', 'sanitizer.md#11'],
  X('GET', '/'), pol=policy(identity={'from': 'header', 'name': 'x-user-context', 'json_path': ['user', 'id']}))
V('2190-accept-json-path-member-64', 'subject-sampling', 'A member of 64 characters is accepted.',
  ['policy.md#7.1', 'sanitizer.md#11'], X('GET', '/', h=[(JP_HDR, '{"' + 'a' * 64 + '":"u-64"}')]),
  pol=policy(identity=jp_id('a' * 64)))

# =========================================================================== spec v1.19 (5.6 alnum, 22)

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors_v119.py'), encoding='utf-8') as _fh:
    exec(compile(_fh.read(), 'vectors_v119.py', 'exec'))

# ===========================================================================

def build():
    """Return {relative path: bytes} for every generated file."""
    import minischema
    files = {}
    pschema = vectorio.load_file(os.path.join(ROOT, '..', 'schemas', 'policy-compiled.v1.schema.json'))
    pval = minischema.Validator(pschema)
    for name, body in POLICIES.items():
        data = J.dumps(body).encode('ascii')
        errs = pval.errors(J.to_py(J.parse(data)), pschema['$defs']['body'])
        assert not errs, (name, errs[:3])
        files['policies/%s.json' % name] = data + b'\n'
    seen = set()
    unexpected = []
    for v in VECTORS:
        assert v['id'] not in seen, v['id']
        seen.add(v['id'])
        # Round-trip through the vector file format so expected values come from what runners read.
        text = J.pretty(v)
        parsed = J.to_py(J.parse(text.encode('ascii')))
        res = vectorio.execute(parsed, ROOT, files)
        if (v['id'].startswith('178') or v['id'] in CODE_ACCEPTED or v['id'] in GQL_ACCEPTED
                or v['id'] in V12_ACCEPTED) and res.get('outcome') != 'event':
            unexpected.append('%s must be accepted: %s' % (v['id'], res))
        if v['id'] in UNSAFE and res != {'outcome': 'refused', 'code': 'policy_rejected'}:
            unexpected.append('%s must be refused: %s' % (v['id'], res))
        if res.get('outcome') == 'refused' and v['category'] not in ('refusal', 'keys'):
            unexpected.append('%s refused unexpectedly: %s' % (v['id'], res))
        v['expected'] = res
        files['vectors/%s.json' % v['id']] = (J.pretty(v) + '\n').encode('ascii')
    if unexpected:
        raise AssertionError('\n'.join(unexpected))
    return files


def main():
    files = build()
    check = '--check' in sys.argv
    bad = 0
    for rel, data in sorted(files.items()):
        path = os.path.join(ROOT, rel)
        if check:
            try:
                with open(path, 'rb') as fh:
                    if fh.read() != data:
                        print('DIFFERS', rel)
                        bad += 1
            except FileNotFoundError:
                print('MISSING', rel)
                bad += 1
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as fh:
                fh.write(data)
    if not check:
        vdir = os.path.join(ROOT, 'vectors')
        for f in os.listdir(vdir):
            if 'vectors/' + f not in files:
                os.remove(os.path.join(vdir, f))
    cats = {}
    for v in VECTORS:
        cats[v['category']] = cats.get(v['category'], 0) + 1
    print('%d vectors: %s' % (len(VECTORS), ', '.join('%s=%d' % kv for kv in sorted(cats.items()))))
    if bad:
        sys.exit(1)


if __name__ == '__main__':
    main()
