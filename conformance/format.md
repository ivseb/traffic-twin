# Vector format `tt.conformance.vector/v1`

Normative for every sanitizer implementation (`docs/spec/sanitizer.md` §16), for
sanitizer revision **1.1** with the host patterns of spec **v1.5** (§3.1, §3.5, §3.6) and the
`code` action of spec **v1.11** (§5.6: `{"action":"code"}` in the policy body).

Schema: [`schema/vector.v1.schema.json`](schema/vector.v1.schema.json) (JSON Schema
draft 2020-12, RE2-compatible patterns). One vector per file, `vectors/<id>.json`.
Files are ASCII-only JSON (non-ASCII characters are written as `\uXXXX`).

## Top-level fields

| Field | Required | Meaning |
|---|---|---|
| `format` | yes | `tt.conformance.vector/v1` |
| `id` | yes | `NNNN-words`, equal to the file name without `.json`. Numbers group categories (see README) |
| `category` | yes | One of the categories in the schema; informative |
| `description` | yes | What the vector checks |
| `spec` | yes | Spec sections, e.g. `sanitizer.md#8.3`, `policy.md#4` |
| `ambiguities` | no | Ids from [`AMBIGUITIES.md`](AMBIGUITIES.md) whose chosen reading decides the expected bytes |
| `policy` | one of | Inline `tt.policy.body/v1` document (the decoded `body_b64` of a compiled policy) |
| `policy_ref` | one of | Path, relative to `conformance/`, of a shared body in `policies/` |
| `policy_envelope` | one of | A full `tt.policy.compiled/v1` envelope; requires `fleet_keys` |
| `fleet_keys` | with envelope | Pinned policy signing keys: `{ "<signature kid>": "<32-byte Ed25519 public key, base64url no padding>" }` |
| `source_group` | with a policy | Group assigned to the source at enrollment, checked against `targets.groups` |
| `last_issued_seq` | no | `issued_seq` of the last policy the source accepted (absent = 0) |
| `min_issued_seq` | no | `min_issued_seq` from the last heartbeat (absent = 0) |
| `hmac_key` | no | The content of `TT_HMAC_KEY`: one or more `<kid>:<base64url-nopad>` lines separated by `\n`. Absent = no key configured |
| `now` | yes | The source clock (RFC 3339 UTC): `not_after`, `auto_words` and discovery expiry |
| `input` | yes | The exchange (below) |
| `expected` | yes | The exact result (below) |

None of `policy`, `policy_ref`, `policy_envelope` means "no policy received".

The HMAC **epoch** is not a separate field: it is `hmac.epoch` of the policy body, as in
production (sanitizer.md §7.2). The reference key of §7.3 (kid `k1`, bytes `0x00..0x1f`)
is `k1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` and is used by every vector unless it
tests key handling.

Numbers inside `policy` (limits, `rate_bp`, `version`, `issued_seq`, `bounds`) are written
in tt-cjson canonical form. A runner that needs the lexeme of a bucket bound (§5.5) takes
it from the file as is; a runner that parses into doubles gets the same canonical form
back for every bound used here (all have at most 15 significant digits).

## `input`

Field names follow sanitizer.md §1.

| Field | Type | Notes |
|---|---|---|
| `dir` | `inbound` \| `outbound` | |
| `service_name` | string | Required for `inbound`: the name assigned at enrollment |
| `url_base` | string | Required for `outbound`: `scheme://host[:port]` as seen by the source (not normalized) |
| `method` | string | As received, before any normalization |
| `raw_path` | bytes | Not decoded, without the query |
| `raw_query` | bytes | Not decoded, without `?`. **Absent** = the URL has no `?` |
| `framework` | enum | Required with `framework_route`: `express`, `koa`, `fastify`, `flask`, `fastapi` (also Starlette), `django`, `spring`, `jaxrs`, `aspnetcore`, `gin`, `chi`, `nethttp`, `laravel`, `symfony` (see A-FRAMEWORK-ID) |
| `framework_route` | string | Optional, inbound only, complete with mount prefixes (§3.3) |
| `trace_id` | string | Optional, 32 lowercase hex |
| `inherited` | boolean | Optional, outbound only: sampling decision of the inbound exchange in progress (§12) |
| `req_headers` | list of `[name, bytes]` | In the order the source sees them, duplicates included. Cookies travel here as `Cookie` headers. Normalization (§8.0) is the implementation's job |
| `req_body` | bytes | Absent = empty. With a supported `content-encoding` these are the **encoded** bytes, unless `req_body_decoded` is true |
| `req_body_total` | integer \| `"unknown"` | Total length after de-chunking, when only a prefix is in `req_body`. Absent = length of `req_body` |
| `req_body_consumed` | boolean | Absent = `true`; `false` if the app did not read the body |
| `req_body_decoded` | boolean | Absent = `false`; `true` if the runtime already removed the `content-encoding` |
| `status` | integer | Absent if and only if `net_error` is present |
| `net_error` | string | `timeout` \| `reset` \| `refused` \| `dns` \| `tls` \| `other` |
| `resp_headers` | list of `[name, bytes]` | Set-cookies travel here as `Set-Cookie` headers |
| `resp_body`, `resp_body_total`, `resp_body_consumed`, `resp_body_decoded` | | As for the request |

The content-type and content-encoding of each body are not separate fields: they come
from the normalized headers of the same side (§8.0, §8.1).

### The `bytes` type

Either:

- a JSON string: the bytes are its UTF-8 encoding (the string never holds lone
  surrogates); or
- an object `{"b64": "<standard base64 with padding>", "text": "..."}`. `b64` is
  normative. `text`, when present, is an informative copy equal to the UTF-8 decoding of
  `b64` (omitted for non-UTF-8 data and for bodies over 4 KiB).

Bodies always use the object form; paths, queries and header values use the string form
unless they are not valid UTF-8. Compressed bodies are stored compressed; the generator
keeps the compressed streams in `ref/fixtures/` so that regeneration is byte-stable on any
zlib build.

## `expected`

Exactly one of:

```json
{ "outcome": "event", "canonical": "<tt-cjson bytes as a JSON string>" }
{ "outcome": "not_sampled", "sampled_by": "baggage | subject | trace | random | inherited" }
{ "outcome": "refused", "code": "no_policy | policy_rejected | expired_policy | key_missing | key_mismatch" }
```

`canonical` is the sanitizer output of §2 serialized in tt-cjson (§10): `service`, `op`,
`route_source`, `sampled_by`, `subject` (if any), `req`, `resp` (absent with `net_error`)
and `disc` (if any). It is always ASCII. Event fields that the source fills (`schema`,
`policy`, `source`, `ts`, `latency_ms`, `dir`, `status`, `net_error`, ids) are **not**
part of it. `refused.code` uses the heartbeat states of `api/fleet-api.v1.openapi.yaml`.

## Executing a vector

The order follows sanitizer.md §1: policy, then key, then sampling.

1. **Policy.**
   - `policy_envelope`: verify it as a source does (policy.md §3-§4): `format` is
     `tt.policy.compiled/v1`; `signature.alg` is `Ed25519`; `signature.kid` is in
     `fleet_keys`; `body_b64` is base64url without padding; `hash` equals
     `sha256:<hex>` of the decoded bytes; the signature verifies over
     `"tt.policy.body/v1" || 0x00 || body bytes`; `policy_id`, `version` and `issued_seq`
     match between envelope and body.
   - `policy` or `policy_ref`: take the body as the decoded bytes of a verified envelope.
   - none: `refused/no_policy`.
   - In every case the body must be valid against `#/$defs/body` of
     `schemas/policy-compiled.v1.schema.json` (from spec v1.5 it may hold
     `hosts: {"discovery": "auto" | "off"}`; absent means `auto`), use no reserved HMAC domain and pass the
     safety subset of `docs/spec/hardening.md` §2.1 (spec v1.3), which depends on the body
     alone, not on `now` or the group:
     **H1** no `keep` and no `hmac` on the header names `authorization`, `cookie`,
     `set-cookie`, `proxy-authorization` (header rules of `request`, `response` and `errors`;
     `global`, services and operations);
     **H2** no `keep` and no `hmac` on a `body` tt-path with any wildcard step (`.*` or `[*]`) in the `global` rules
     (`bucket` is not checked here);
     **H3** `discovery.enabled` with `discovery.expires_at`, or `segments.auto_words` with
     `auto_words_expires_at`, not later than `created_at` + 7 days (exactly + 7 days is
     accepted; fractions of a second and offsets count).
     A violation is `refused/policy_rejected` (the heartbeat state); sources report the
     `last_errors` code `policy_unsafe`, which the vectors do not compare.
   - Then policy.md §4 conditions 3-5: `source_group` in `targets.groups`;
     `now < not_after` (otherwise `refused/expired_policy`); `issued_seq` greater than
     `last_issued_seq` and not lower than `min_issued_seq`.
   - Every other failure: `refused/policy_rejected`.
2. **Key** (§7.1). Parse `hmac_key` line by line; an absent value, a malformed line or a
   key shorter than 32 bytes: `refused/key_missing`. Use the key of `hmac.kid`, else the
   first of `hmac.accept_kids` present; none: `refused/key_mismatch`. Tokens carry the kid
   of the key used.
3. **Sampling** (§11-§12). If not sampled: `not_sampled` with the reason. Vectors use
   random sampling only with `rate_bp` 0 or 10000.
4. **Sanitize** and serialize in tt-cjson, including the §10.3 size reductions. No vector
   sits within 4096 bytes of the 512 KiB limit (A-EVENT-SIZE-BASE).
5. **Compare** with `expected`: for events, the output bytes must equal the UTF-8 bytes
   of `canonical` exactly. For the other outcomes the outcome and its code or reason must
   match.

The reference runner `ref/vectorio.py` (`execute`) is the executable version of these
steps. No vector needs network, the real clock or randomness.
