package policy

import "strings"

// Identity sources that apply without approval (policy.md 7.1, spec v1.12).
//
// identity.subject never lets a value out in clear: the source turns the
// raw subject into an HMAC token (sanitizer.md 11) and uses it for per-user
// sampling (sanitizer.md 12). So choosing where the user is read from is
// observe-safe for any request header, whatever its name, except where the
// raw value is a credential: then even a keyed token of it is refused
// without approvals. The rule is generic: no list of application header
// names, only the credential ones.
//
//   - cookies: never observe-safe (they carry session secrets);
//   - cookie, set-cookie, proxy-authorization and the ForbiddenKeepHeaders
//     other than authorization: never;
//   - authorization: only with a jwt_claim (any claim of the bearer JWT:
//     the claim is an identifier, the token itself is never hashed);
//   - a header whose name looks like a credential (CredentialLikeName):
//     only with a jwt_claim or (spec v1.18) a json_path: a member of a JSON
//     header value;
//   - any other header, with or without jwt_claim: observe-safe.
//
// The subject is read only from a header or a cookie (sanitizer.md 11):
// query parameters are not a subject source.

// IdentityObserveSafe reports whether identity.subject s applies without
// approvals (nil: no identity, nothing read).
func IdentityObserveSafe(s *Subject) bool {
	if s == nil {
		return true
	}
	if s.From != "header" {
		return false
	}
	name := strings.ToLower(s.Name)
	if name == "authorization" {
		return s.JWTClaim != ""
	}
	if CredentialHeaders[name] || ForbiddenKeepHeaders[name] {
		return false
	}
	if CredentialLikeName(name) {
		// A claim of a JWT or a member of a JSON header (spec v1.18): only
		// the token of that identifier leaves, never the header.
		return s.JWTClaim != "" || s.JSONPath != ""
	}
	return true
}

// credentialParts are substrings that make a name look like a credential:
// tokens, secrets, passwords, keys, sessions, signatures, anti-forgery
// tokens. Generic protocol and security words, never application names.
var credentialParts = []string{
	"token", "secret", "passw", "pwd", "apikey", "api-key", "api_key", "session", "csrf", "xsrf",
	"signature", "credential", "auth", "cookie", "nonce",
}

// credentialWords are whole words (split on non-alphanumerics) that make a
// name look like a credential.
var credentialWords = map[string]bool{
	"key": true, "sig": true, "sid": true, "pin": true, "otp": true, "pass": true, "jwt": true, "bearer": true, "code": true,
}

// CredentialLikeName reports whether a header (or parameter) name looks
// like it carries a credential: a credential header, a name containing a
// credential word (token, secret, password, key, session, auth, csrf,
// signature...). In doubt it says yes: the identity then needs approvals
// or a jwt_claim.
func CredentialLikeName(name string) bool {
	n := strings.ToLower(name)
	if CredentialHeaders[n] || ForbiddenKeepHeaders[n] {
		return true
	}
	for _, p := range credentialParts {
		if strings.Contains(n, p) {
			return true
		}
	}
	for _, w := range strings.FieldsFunc(n, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
		if credentialWords[w] {
			return true
		}
	}
	return false
}
