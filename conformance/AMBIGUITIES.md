# Spec ambiguities found while writing the vectors

The vectors are written from `docs/spec/sanitizer.md` and `docs/spec/policy.md` without
looking at any implementation. Every place where the text allowed more than one reading
is listed here, with the reading the reference generator implements and the vectors
that depend on it. Vectors cite these ids in their `ambiguities` field; `ref/run.py`
checks that every cited id is defined here.

To adopt a different reading, change the matching switch in `ref/specprofile.py` (or the
code at the `A-...` tag in `ref/sanitizer.py`) and run
`python3 conformance/ref/gen_vectors.py`.

- [Open in revision 1.1](#open-in-revision-11): readings chosen by the conformance agent;
  each one should be confirmed or overruled by a spec patch.
- [Resolved by revision 1.1](#resolved-by-revision-11): the v1.0 ambiguities, now settled
  by the spec text. Kept for traceability with the changelog in `docs/spec/README.md`.

## Open in revision 1.1

### A-CONTAINER-KEEP
§5.0 says that `keep`, `hmac` and `bucket` rules matching a container "are always
ignored", and that an explicit `drop` "found in group g" applies unless a rule of groups
1..g reaches a descendant. It does not say whether an ignored `keep` in a stronger group
still counts as "the rule found" for that container. Reading: ignored rules are as if
absent, so a weaker `drop` on the same container applies (switch
`CONTAINER_NON_DROP_SHADOWS = False`). Vectors: 0960-rules-group-shadow.

### A-HDR-COLLAPSED-RULE
§5.0 compares header rules with the original lowercase name "also when that name
collapses into `{*}`", but §8.0 joins the values of **all** names that collapse into one
`{*}` value. When several original names are joined, which rule applies is undefined.
Reading: the rule of the original name applies only when every joined value came from
that one name; otherwise the value is a default `drop`. Vectors: 0334, 0335.

### A-NOEQ-DISC
§5.0 and §8.3 say a query or form part without `=` "always receives drop"; §15 adds a
discovery entry for every leaf that gets `drop` "by default (not by explicit rule)".
Reading: no rule applies to such a part, so it is a default drop and adds a
`req.query.{*}` (or `req.body.*`) entry. Vectors: 1210-discovery-noeq.

### A-PATH-TIME
§4.2 point 4: "lo stesso vale per il valore originale da cui nasce un `time:`". Reading:
`bucket(time)` on a path parameter applies only when the decoded segment matches the keep
grammar `^[A-Za-z0-9._~-]{1,64}$`, so a date works and a datetime with `:` is dropped.
Vectors: 1125-route-path-time-grammar.

### A-FRAMEWORK-ID
§3.4 normalizes `framework_route` with a table **per framework**, and the syntaxes
conflict (`{id:path}` fails for FastAPI but is a regex for Spring; `*` means different
things). §1 lists `framework_route` but no framework identifier. Reading: the vector
input carries `framework` (one of `express`, `koa`, `fastify`, `flask`, `fastapi`
(also Starlette), `django`, `spring`, `jaxrs`, `aspnetcore`, `gin`, `chi`, `nethttp`,
`laravel`, `symfony`), which an SDK knows from its integration. A segment that is not one
of the framework's parameter syntaxes must be a literal of the operation-key grammar,
which makes every "not normalizable" case of the table fail. Vectors: 1160-1187.

### A-SUBJECT-OUTBOUND
§11 reads the subject "only from the request" and §12 never uses it for outbound
sampling. Reading: the subject token is still computed and emitted for outbound
exchanges (from the outgoing request), but outbound sampling ignores it. Vectors:
1342-sampling-outbound-trace.

### A-EVENT-SIZE-BASE
§10.3 measures "the complete canonical event", whose source-filled fields (`source.id`,
`source.version`, span ids, `ts`) differ between sources, so a vector cannot fix the
bytes of the whole event. Reading: the reference measures the sanitizer output object,
and the generator refuses any vector whose output is within 4096 bytes of the 512 KiB
limit at any step, so every reasonable envelope gives the same result. Step 4 ("no
event, `sanitizer_errors`") has no outcome in §16 and no vector. Vectors: 1070-1072.

### A-GZIP-STRICT
§9.0 says "an error of decoding" gives `drop:bytes` but does not define errors. Reading:
a stream that does not end (truncated) or has bytes after its end is an error; reaching
the `max_body_bytes + 1` output cap is not (it gives `trunc:size`). A compressed body of
which only a prefix was kept is therefore an error unless its output reaches the cap.
Vectors: 1063-encoding-truncated-stream.

### A-FORM-TRUNC
A form body is "like the query" (§9.1) but lives in `body`, where §9.3 point 5 writes
`{trunc}` as a string. Reading: a form body is a name map, so it uses the query limits
(64 names, `max_array` values per name) and `{trunc}` is `["trunc:keys:<class>"]`. Not
covered by a vector.

### A-PORT-ZEROS
§3.1 accepts a port of "1-5 digits with value 1-65535" and removes the default one. A
port with leading zeros (`:0443`) is read by value: it is the default port for `https`,
and other ports are printed without leading zeros. Not covered by a vector.

### A-KEY-DUPLICATE
§7.1 allows several key lines but does not say what happens when two lines have the same
`kid`. Reading: the first line wins. Not covered by a vector.

### A-CE-EMPTY
A `content-encoding` header whose value is empty after trimming is neither "absent" nor
`identity`. Reading: it is an unsupported coding (`drop:bytes`, no `size`). Not covered
by a vector.

## Resolved by revision 1.1

Each entry gives the v1.0 question, the section of revision 1.1 that answers it and the
vectors that now test it. Entries marked **flipped** changed the expected bytes of the
v1.0 vectors.

| Id | v1.0 question | Settled by | Vectors |
|---|---|---|---|
| A-OUTPUT-FIELDS | Which fields form the compared object | §2, §16 | all events |
| A-VECTOR-PATH | Path of the reference token vector | §7.3, §16 | 0002 |
| A-TRACE-INPUT | `trace_id` was not an input | §1 | 1322, 1323, 1342 |
| A-KEY-ERROR-CODE | Code for a malformed or short key | §7.1 (`key_missing`) | 1402-1406, 1443, 1445 |
| A-REFUSAL-ORDER | Policy before key before sampling | §1 | 1407, 1450-1459 |
| A-POLICY-BODY | Source rejects reserved domains | §1, policy.md §4 | 1410 |
| A-PATH-TRUNC-TEMPLATE | Truncated path vs templates | §3.3 | 1119 |
| A-FRAMEWORK-MATCH | Structural framework match | §3.3 | 1110, 1160-1187 |
| A-FRAMEWORK-FALLBACK | Fallback to step 2 | §3.3 | 1111, 1151, odd 1161-1187 |
| A-FRAMEWORK-LITERAL | Literal emitted with a framework match | §3.3 (policy literal) | 1150 |
| A-BASE-SEGMENTS | `%2F` and base matching | §3.1 (segments) | 1133 |
| A-BASE-COMPARE | Normalization before base matching (**flipped**: now normalized) | §3.1 | 1145 |
| A-BASE-REMAINDER | `req.path` for outbound with base (**flipped**: full path) | §3.2 | 1131 |
| A-HOST-VALID | Valid host, ports | §3.1 | 1136, 1139, 1141-1144 |
| A-HOST-USERINFO | Credentials in `url_base` | §3.1 (`host:invalid`) | 1515 |
| A-PATH-TOKEN-CHARSET | `keep` on path parameters, allow entries | §4.2, schema | 1124, 1456 |
| A-ERRORS-GROUP | errors as one or two groups | §5.0 (2a, 2b) | 0957, 0958 |
| A-SPECIFICITY-STEPS | Vacuous "more steps" tie-break | §5.0 (removed) | 0953 |
| A-CONTAINER-GROUP | Container drop vs descendant rules (**flipped**: drop ignored) | §5.0 | 0959, 0965, 0966 |
| A-FORM | Form rules `$.name` and `$.*` | §5.0, §9.1 | 0519, 1212 |
| A-HDR-LIMIT | Header limit unit (**flipped**: distinct output names) | §8.1 | 0308 |
| A-QUERY-LIMIT | Query limit unit | §8.1 | 0215 |
| A-TRUNC-VALUE | `{trunc}` value shape (**flipped** in maps: array) | §8.1, §9.3 | 0215, 0308, 0412, 1020 |
| A-COLLAPSE-ORDER | Order under `{*}` (**flipped** in JSON: by canonical value) | §8.2, §8.3, §9.3 | 0004, 0209, 0527 |
| A-CT-OWS | Spaces and tabs around the media type | §8.1 | 0325 |
| A-COOKIE-DIRECTION | cookie in responses, set-cookie in requests | §8.1 | 0409 |
| A-SETCOOKIE-TRIM | Trimming set-cookie (**flipped**: trimmed) | §8.2 | 0406 |
| A-SETCOOKIE-NOEQ | set-cookie without `=` | §8.2 | 0405 |
| A-SIZE-EMPTY | `size` of an empty body (**flipped**: `l8`, body absent even with a content-type) | §9.0 | 0516, 0522, 0574 |
| A-SIZE-UNKNOWN | Unknown total length | §9.0 | 1035 |
| A-PREFIX | Prefix with known total | §9.0 | 1034, 1036, 1038 |
| A-JSON-BOM | BOM before JSON | §9.2 | 0571 |
| A-DEPTH-VALIDATE | Validation beyond `max_depth` | §9.2 | 0572 |
| A-MAXKEYS-WHICH | Which keys survive `max_keys` | §9.3 | 0507, 1020, 1021 |
| A-REGEX-ANCHOR | `$` before a final newline | §0.1 | 0612, 0120 |
| A-BUCKET-DOUBLE | `-1e-400` and infinities | §5.5 | 0905 |
| A-TIME-OFFSET, A-TIME-YEAR | Offsets and years in `bucket(time)` | §5.5 | 0912 |
| A-JWT-B64 | JWT payload padding (**flipped**: padding allowed) | §11 | 1313, 1332 |
| A-SUBJECT-FIRST, A-SUBJECT-EMPTY | Repeated and empty subjects | §11 | 1312, 1316-1319 |
| A-BAGGAGE-FIRST | Baggage parsing | §12 (now only with `trust_baggage` on internal services) | 1324-1326, 1344, 1345 |
| A-NET-ERROR | `resp` with `net_error` | §1, §2 | 1137 |
| A-DISC-VALUE | Booleans and null in discovery | §15 | 1201 |
| A-DISC-INVALID | Invalid leaves in discovery | §15 | 1206, 1211 |
| A-DISC-PATH-POS | Path index base (**flipped**: index on the full `req.path`) | §15 | 1201, 1207 |
| A-DISC-NAMED | Names in discovery paths; HMAC input (**flipped**: path in the HMAC) | §15 | 1201, 1208, 1212 |
| A-NAME-PII | Names that carry values | §8.0, §9.3 (six digits), §4.3 (timed auto_words), §13 | 0218, 0336, 0413, 0526, 1502, 1505 |
