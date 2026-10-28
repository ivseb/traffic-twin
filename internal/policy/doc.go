// Package policy implements the tt policy formats of docs/spec/policy.md
// (rev. 1.1): the compiled body (tt.policy.body/v1), its signed envelope
// (tt.policy.compiled/v1), author-side compilation from an already parsed
// author document (tt.policy/v1), the signed-message format
// ("tt.policy.body/v1" || 0x00 || body), and fail-closed verification,
// acceptance (targets.groups, not_after, issued_seq) and caching for sources.
//
// YAML is not parsed here: tt-core decodes the author YAML into a generic
// tree and calls AuthorFromGeneric, then Compile. Signing happens in tt
// keyguard over SignedMessage(body); Envelope assembles the result (Sign is
// a helper for keyguard, tests and fixtures). Sources only ever see the
// signed envelope and use Store (or Accept) to take it.
package policy
