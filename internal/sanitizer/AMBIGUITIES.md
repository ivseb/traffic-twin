# Sanitizer and policy: implementation readings (spec rev. 1.1.1)

Developer note for the spec owners. Since v1.1.1 the readings of
`conformance/AMBIGUITIES.md` are normative and the Go implementation passes all
422 vectors of `conformance/vectors/` byte for byte
(`go test ./internal/sanitizer -run TestConformanceVectors`). This file lists only
the choices that **no vector fixes**. Rule of thumb: when two readings are
possible, emit less or fail closed.

## Policy acceptance at the source

1. **What a source re-checks.** `policy.ValidateSource` (used by `DecodeBody`,
   `Verify`, `Accept`, `NewEngine`) applies exactly what `conformance/format.md`
   asks: the compiled schema (`#/$defs/body`) and no reserved HMAC domain, then
   group, `not_after` and `issued_seq` (`CheckAcceptance`). The cross-field rules
   of policy.md 1.4 (7-day windows, `keep` on `authorization` & co., `.*` with
   keep/hmac/bucket in global rules, equivalent operations, path parameters not
   in the template, bounds strictly increasing as doubles, duplicate bases,
   `propagate_to` vs bases, `accept_kids` containing `hmac.kid`) are checked by
   `policy.Validate`, used by `Compile`. Vectors 0122, 0703, 0901, 0952, 1209 and
   others require sources to accept bodies that break some of these rules.
   **Worth a spec decision:** a signed body with `keep` on `authorization` is
   accepted by sources; only tt-core and keyguard stop it.
2. Array order and canonical bytes of the body are not checked at the source
   (the signature covers the bytes). Duplicate inbound service names: the first
   entry is used.
3. `Store`: no capture before the first heartbeat; the kill switch is part of
   the persisted cache; a `min_issued_seq` above the current policy's
   `issued_seq` drops the current policy; re-offering the same envelope counts
   as a confirmation for `policy_max_age`.

## Body

4. A prefix shorter than a known total **within** `max_body_bytes` (a source
   should keep `max_body_bytes + 1` bytes) cannot be analysed: JSON and form
   bodies give `trunc:size` with `size` = class of the total; other content
   types keep `drop:bytes:<class>` (vector 1038 fixes the latter).
5. A total smaller than the bytes passed uses the length of the bytes.
6. gzip is decoded with multistream off: a second member counts as bytes after
   the end of the stream (A-GZIP-STRICT).

## Framework routes (A-FRAMEWORK-ID)

7. ASP.NET Core: a parameter whose constraints end with `?` or contain `=` is not
   normalizable (optional/default). Spring and chi: `{name:}` (empty regex) is
   not normalizable. Flask/Django: an empty converter (`<:name>`) is not
   normalizable. Go `net/http`: `{$}` anywhere but last is not normalizable.

## Subject

8. JWT payload with padding: when `=` is present (at most two, at the end) the
   padded length must be a multiple of 4.

## Discovery

9. A path that would not fit the event schema (`disc` keys up to 256 bytes) is
   omitted, like the overflow beyond 4096 paths.

## Event construction

10. `Sanitize` applies §10.3 on its own output (A-EVENT-SIZE-BASE) and returns
    `ErrEventTooLarge` for step 4. `BuildEvent` applies the same reductions
    again on the full event, which can only matter within a few hundred bytes of
    the limit.
