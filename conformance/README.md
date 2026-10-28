# Sanitizer conformance vectors

Byte-exact test suite for `tt.sanitizer/v1` **revision 1.1** with the host patterns of spec
**v1.5** (`docs/spec/sanitizer.md` §3.1, §3.5, §3.6) and the `code` action of spec **v1.11** (§5.6) and for the source-side policy and key
checks (`docs/spec/policy.md` §3-§4 and, from spec v1.3, the safety subset H1-H3 of
`docs/spec/hardening.md` §2). Every
sanitizer implementation (the Go reference in `internal/sanitizer/`, the SDKs in
`sdk/*/`, `tt-egress`, the OBI adapter, the importers) must pass all of them. When a
vector and a prose example of the spec disagree, the vector wins (sanitizer.md §14).

## Layout

```
conformance/
  README.md            this file
  format.md            vector format and how to execute a vector (normative, sanitizer.md §16)
  AMBIGUITIES.md       readings chosen where the spec text is ambiguous
  schema/
    vector.v1.schema.json
  policies/            shared compiled policy bodies (tt.policy.body/v1), tt-cjson bytes
    empty.json         the minimal policy of sanitizer.md §13
    auto-words.json    empty policy with timed segments.auto_words
  vectors/             one file per vector, NNNN-name.json
  ref/                 independent reference generator, Python 3 standard library only
    sanitizer.py       the reference sanitizer
    ttjson.py          lexeme-preserving JSON parser, tt-cjson writer, canonical numbers
    policyload.py      key parsing, envelope verification, body and acceptance checks
    ed25519.py         RFC 8032 Ed25519 (fixtures only, not constant time)
    specprofile.py     spec constants and the switches of the open ambiguities
    build.py           builders used by the vector definitions
    gen_vectors.py     the vector definitions; writes vectors/ and policies/
    fixtures/          compressed bodies, kept so regeneration is byte-stable on any zlib
    vectorio.py        loads and executes one vector
    run.py             self-check: schema, expected results, event schema, ambiguity ids
    leakcheck.py       G1 property check on every empty-policy vector
    minischema.py      small JSON Schema validator (no pip)
    show.py            prints expected results, for review
```

## Vector ids

| Range | Category |
|---|---|
| 0001-0099 | default drop, reference examples (0002 holds the token of sanitizer.md §7.3) |
| 0100 | path (§4), timed auto_words (§4.3) |
| 0200 | query (§8.3) |
| 0300 | header normalization, headers and content-type (§8.0, §8.1) |
| 0400 | cookies (§8.2) |
| 0500 | body: JSON parsing, keys, invalid JSON, non-JSON, form (§9) |
| 0600 | formats (§6.3) and length classes (§0.3) |
| 0700 | numbers and lexeme limits (§5.3, §10.2) |
| 0800 | HMAC (§7) |
| 0900 | actions keep / bucket / drop (§5); 0950 rule selection (§5.0) |
| 1000 | limits (§6.4, §9); 1050 content-encoding and streaming (§9.0); 1070 event size (§10.3) |
| 1100 | service, outbound hosts, template selection (§3); 1150 framework routes (§3.3, §3.4) |
| 1200 | discovery mode (§15); 1209/1213 sit on the 7-day limit of H3 |
| 1300 | subject and sampling (§11, §12) |
| 1400 | refusal: keys, policy acceptance, signed envelopes; 1440 key files and rotation |
| 1500 | adversarial: attempts to leak a value |
| 1600 | canonical serialization (§10) |
| 1700 | refusal, spec v1.3 (hardening.md §2.1): unsafe policies. 1701-1748 H1 (4 headers x keep/hmac x 6 places), 1751-1759 H2, 1760-1768 H3, 1770-1774 mixed; 1780-1783 are the accepted limits (drop on credential headers, `.*` in a service or operation, drop on a global `.*`) |
| 1800 | the `code` action, spec v1.11 (sanitizer.md §5.6, policy.md §1.5; category `code`). 1810-1828 accepted and refused shapes: case and separators, length bounds 2..32, digits, spaces and punctuation, Unicode lookalikes (Cyrillic, fullwidth, zero-width, NBSP), non-strings, nested paths and arrays, containers, `keep_max_bytes`, query and headers, path parameters, forms, `errors` rules, no fallback to a weaker group, JSON escapes and lone surrogates, separators only, discovery, `.*` in a service rule. 1850-1857 refusal: `code` in H1 and H2 (hardening.md §2.1, category `refusal`) |
| 1900 | host patterns, spec v1.5 (sanitizer.md §3.1, §3.5, §3.6; category `hosts`). 1900-1908 strict mode `hosts.discovery: off` (1900-1906 are copies of 0007, 1134, 1137, 1340, 1342, 1343, 1142, which v1.5 rewrote for the default `auto`), 1909 explicit `auto`, 1910-1927 safe-label rules a-c, base and `hosts_allow` precedence, discovery mode, single labels, 1930-1934 ports, 1940-1961 IPv4 and IPv6 literals and classes, 1965-1968 punycode and raw IDN, 1970-1981 case, final dot, empty labels, 253/254 bytes, many labels; 1990-1992 refusal of a malformed `hosts` object |
| 2000 | the `graphql` action, spec v1.14 (sanitizer.md §5.7, §9.1, policy.md §1.6; category `graphql`). 2000-2013 request documents: named query with variables, inline literals of every kind, mutation with list types, default values, aliases, fragments and directives, shorthand with comments, commas, BOM and tabs, names collapsed to `*`, strings that are not documents, 24 lexical and syntactic errors, nesting limit 64, shape length limit 32768, GET query parameter, `application/graphql` body with and without a rule and not UTF-8, non-strings and containers. 2020-2033 the introspection gate: standard introspection query (names out, descriptions and defaults as shapes), arrays up to 4096, gate closed by a mixed root, an alias `__schema`, a root fragment spread, a second operation, an invalid document, no request rule, undecodable query bytes; response names only, GET introspection, GraphQL error responses, discovery, JSON escapes. `leakcheck.py` (E) checks that no inline literal reaches a `gql:` token |
| 2100 | the subject from a JSON header, `identity.subject.json_path`, spec v1.18 (sanitizer.md §11 step 4 bis, §21, policy.md §7.1; category `subject-sampling`, refusals in `refusal`). 2100-2122 accepted: plain JSON and base64 (standard and URL alphabet, with and without padding, single and double `=`), one-member and eight-member paths, `-` and `_` in names, canonical numbers (2110 and 2111 share one token), last duplicate wins, spaces and tabs trimmed, JSON escapes, non-ASCII, header names. 2130-2160 no subject: dotted name is no path, intermediate array or string, final array, object, boolean, `null`, empty string, missing member, root array or string, not JSON, trailing data, truncated, trailing comma, `Bearer` prefix, BOM (plain and in base64), invalid UTF-8 (header and decoded), lone surrogate, mixed alphabets, bad base64 length and padding, blank, absent or repeated header, cookie of the same name. 2170-2175 limits: 8192 and 8193 raw bytes, the limit on the raw header, off-path members of any shape, nesting of 200 levels off the path (read) and the same with a missing bracket (invalid). 2180-2189 refusal of the body: `json_path` with `jwt_claim`, from a cookie, nine members, empty, empty member, trailing dot, characters outside `[A-Za-z0-9_-]`, array index, member of 65 characters, not a string; 2190 member of 64 characters accepted |
| 2200 | bodies and the code shape `alnum`, spec v1.19 (sanitizer.md §5.6, §22, policy.md §1.5; categories `code-alnum`, `docs`, `multipart`, `xml`, `large-body`, refusals in `refusal`). 2200-2209 `code(alnum)`: accepted shapes `^[A-Za-z0-9_.-]{1,16}$`, length bounds, refused characters, non-strings, `keep_max_bytes`, path, query and headers, together with `code`, forms, discovery, `errors` rules; 2210-2213 refusal: `code(alnum)` in H1 and H2, unknown shape, `shape` on `keep`. 2220-2233 base64 documents (`drop:doc:<type>:<class>`): PDF, image and zip kinds (docx, xlsx, pptx), data URIs, URL alphabet, strings that are not documents, `bodies.docs` off, size classes and the 128 KiB boundary, every place a string shape is used, rules that win, discovery, formats first, invalid UTF-8. 2240-2267 `multipart/form-data`: text parts as form fields, file parts as `drop:file:<type>:<class>`, framing (preamble, epilogue), ten malformed bodies (`trunc:invalid-multipart`), switch off, part names, values, `filename*`, discovery, limits, empty body, responses. 2300-2362 XML and SOAP: SOAP 1.1 and 1.2 envelopes with rules, the tree mapping (`@name`, `#text`, repeated elements as arrays), namespaces (`xmlns`, `ns:` patterns), the `xml` prefix, prolog, line endings, depth and key limits, `+xml` types, dynamic names, `soap_action` from the header and the `content-type` (URL, fragment, empty, value, trailing slash, bare, no XML body), discovery, gzip, `@` keys in JSON stay dynamic, nesting 256/257; 2340-2362 invalid documents (`trunc:invalid-xml`): DOCTYPE, billion laughs, unknown entities, bare `&`, undeclared prefix, mismatched and unclosed tags, duplicate attributes, two roots, text outside the root, `<` in an attribute, control characters, character references out of range, bad names, empty body, nesting 257, unterminated CDATA, declarations in content, double colon, not UTF-8. 2400-2412 large bodies (`bodies.max_large_body_bytes`): JSON, over the large limit, off, gzip, XML, prefix only, zero arrays kept, form, other types, invalid JSON, multipart, a normal body unchanged. 2450-2453 refusal: `bodies` with a missing field, a large limit out of range, an unknown field; a `tt-path` with a bad `#` step. `leakcheck.py` (F) checks that no XML or multipart content leaves as a name, `fmt`, `soap_action` or `xmlns` pattern |

## Writing a runner

A runner in another language needs only the files in `vectors/` and `policies/`:

1. Read every `vectors/*.json` (any JSON parser; numbers in `policy` are canonical).
2. Build the policy: inline `policy`, the file named by `policy_ref`, or verify
   `policy_envelope` with `fleet_keys`; apply the body and acceptance checks, then the
   key checks. See [format.md](format.md#executing-a-vector).
3. Decode the `bytes` fields (`"string"` = UTF-8, `{"b64": ...}` = base64), feed the
   exchange to the sanitizer exactly as the production code path would (headers
   unnormalized, bodies possibly compressed), with `now` as the clock, and serialize the
   result in tt-cjson.
4. Compare. For `outcome: event` the comparison is **byte for byte** between the
   implementation's canonical output and the UTF-8 bytes of `expected.canonical`; no
   re-parsing, no normalization. For `not_sampled` and `refused` compare the outcome and
   its reason or code.

A runner must report the vector id and both byte strings on a mismatch. It must not
skip vectors silently; a vector that needs an input the implementation cannot receive
(for example a `framework` the SDK does not integrate) is reported as "not applicable",
never as passed.

## Reference generator

The expected values are computed by `ref/`, a second implementation written only from
the spec text. It is readable on purpose and is not the product.

```sh
make vectors                                    # --check, run.py and leakcheck.py
python3 conformance/ref/gen_vectors.py          # regenerate vectors/ and policies/
python3 conformance/ref/gen_vectors.py --check  # CI: fail if any file would change
python3 conformance/ref/run.py                  # self-check all vectors
python3 conformance/ref/run.py 05 1101          # only ids starting with 05 or 1101
python3 conformance/ref/leakcheck.py            # G1: no input value in empty-policy outputs, host labels safe
python3 conformance/ref/show.py 1050            # print expected results
```

`run.py` also wraps each expected output into a full `tt.http.exchange/v1` event and
validates it against `schemas/event.v1.schema.json`, so every expected output is accepted
by the intake. The generator validates every inline policy through the same body checks
a source runs, so a vector that is not meant to be refused can never be refused.

## Adding a vector

1. Add a `V(...)` call to `ref/gen_vectors.py` in the right id range, with a description
   and the spec sections it exercises. Use invented data only (e-commerce, carrier,
   `*.example` hosts).
2. If the expected bytes depend on a reading of an unclear sentence, add or extend an
   entry in `AMBIGUITIES.md` and list its id in `amb=[...]`.
3. Run `make vectors`. Review the generated `expected` by hand against the spec before
   committing (`show.py`): the generator is a second opinion, not an oracle.
4. Never edit a file in `vectors/` by hand. From revision 1.1 on, ids are never reused or
   renumbered (the 1.0 set was regenerated once, before any release).

Spec v1.11 added the `code` action and the vectors 1810-1857; no earlier vector changed.

Any change to an expected output is a sanitizer major change (docs/spec/README.md,
"Versioni") unless it fixes a vector that contradicted the spec. The one exception after
revision 1.1 is spec v1.5 (host patterns, a product decision): 0007, 1134, 1137, 1142, 1340,
1342 and 1343 changed their `service`, and their previous output is kept under
`hosts.discovery: off` in 1900-1906.
