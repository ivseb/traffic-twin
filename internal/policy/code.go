package policy

import "strings"

// Code values (sanitizer.md 5.6, policy.md 1.5, spec v1.11).
//
// The action code lets a status or code value leave in clear without human
// approval, in a strictly bounded way: the source lets the value out (as a
// keep: token) only when it is a string of 2 to 32 ASCII letters, "_" or
// "-" (CodeValue), and tt-core and keyguard accept the rule only on a field
// whose name says it is a status or a code (CodeName). Every other value
// leaves as its drop shape.

// CodeMinBytes and CodeMaxBytes bound a code value (sanitizer.md 5.6).
const (
	CodeMinBytes = 2
	CodeMaxBytes = 32
)

// CodeValue reports whether s has the code shape ^[A-Za-z_-]{2,32}$
// (ASCII only, no digit, no space, no other byte).
func CodeValue(s []byte) bool {
	if len(s) < CodeMinBytes || len(s) > CodeMaxBytes {
		return false
	}
	for _, c := range s {
		if !isAlpha(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// CodeWords is the closed list of the last name words that make a field
// status- or code-like (policy.md 1.5). "category" alone is not in the list
// (free text); "category_code" is, through "code".
var CodeWords = map[string]bool{
	"status": true, "state": true, "type": true, "kind": true, "reason": true, "code": true,
	"error": true, "outcome": true, "result": true, "stage": true, "phase": true, "step": true,
	"mode": true, "method": true, "channel": true, "level": true, "severity": true, "priority": true,
	"tier": true, "event": true, "action": true, "currency": true, "unit": true, "format": true,
	"verdict": true, "decision": true,
}

// CodeExcludedWords make a name never code-like, wherever they appear in
// it: secrets and one-time codes (an OAuth code, an OTP, a reset or
// invite code), personal or postal codes, credentials and identifiers
// that people read as codes (policy.md 1.5).
var CodeExcludedWords = map[string]bool{
	"auth": true, "authorization": true, "oauth": true, "access": true, "refresh": true,
	"verification": true, "verify": true, "otp": true, "totp": true, "mfa": true, "pin": true,
	"secret": true, "security": true, "reset": true, "activation": true, "confirmation": true,
	"invite": true, "invitation": true, "referral": true, "promo": true, "coupon": true,
	"voucher": true, "gift": true, "discount": true, "postal": true, "zip": true, "post": true,
	"postcode": true, "password": true, "passcode": true, "pass": true, "token": true,
	"session": true, "api": true, "key": true, "login": true, "recovery": true, "sms": true,
	"captcha": true, "nonce": true, "csrf": true, "xsrf": true, "signature": true, "sig": true,
	"hash": true, "salt": true, "license": true, "serial": true, "tracking": true, "bank": true,
	"iban": true, "swift": true, "bic": true, "tax": true, "vat": true, "fiscal": true,
	"ssn": true, "passport": true,
}

// CodeQueryReserved are query names that are never code-like, even if
// their only word is in CodeWords: the OAuth 2.0 authorization response
// parameters (RFC 6749 4.1.2), which carry one-time secrets.
var CodeQueryReserved = map[string]bool{"code": true, "state": true}

// NameWords splits a field name into lowercase words: on "_", "-", "."
// and on case changes (orderStatus → order status, HTTPStatus → http
// status, error2Code → error2 code). Only ASCII letters change case.
func NameWords(name string) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			out = append(out, strings.ToLower(name[start:end]))
		}
		start = -1
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c == '-' || c == '.' {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		if isUpper(c) {
			p := name[i-1]
			next := i+1 < len(name) && isLower(name[i+1])
			if isLower(p) || isDigit(p) || (isUpper(p) && next) {
				flush(i)
				start = i
			}
		}
	}
	flush(len(name))
	return out
}

// CodeName reports whether a field name is status- or code-like: its last
// word is in CodeWords and no word is in CodeExcludedWords.
func CodeName(name string) bool {
	w := NameWords(name)
	if len(w) == 0 || !CodeWords[w[len(w)-1]] {
		return false
	}
	for _, x := range w {
		if CodeExcludedWords[x] {
			return false
		}
	}
	return true
}

// Rule kinds for CodeRuleAllowed.
const (
	CodePartPath    = "path"
	CodePartQuery   = "query"
	CodePartHeaders = "headers"
	CodePartCookies = "cookies"
	CodePartBody    = "body"
)

// CodePersonalWords make a name never a code field when they are its last
// word, also for a person (spec v1.19): names, contacts and addresses of
// people, whose short values (a first name, a city) would have the shape of
// a code.
var CodePersonalWords = map[string]bool{
	"name": true, "firstname": true, "lastname": true, "surname": true, "fullname": true, "nickname": true,
	"username": true, "email": true, "mail": true, "phone": true, "mobile": true, "fax": true, "address": true,
	"street": true, "city": true, "birthdate": true, "birthday": true, "dob": true, "gender": true,
	"user": true, "customer": true, "client": true, "person": true, "owner": true, "holder": true, "contact": true,
}

// CodeRuleSafe reports whether a code rule (either shape) may stand on the
// rule name of the given kind (policy.md 1.5, spec v1.19): never on cookies,
// never on a credential header, never on the OAuth query parameters, on a
// body tt-path only when its last step is a name (.name or .@name; .#text
// takes the name of the step before), never on a name with an excluded word
// or ending with a personal word. It is what a person may mark as a code
// field: the source still lets out only code-shaped values and the intake
// quarantines a field with more than 50 distinct values.
func CodeRuleSafe(kind, name string) bool {
	switch kind {
	case CodePartCookies:
		return false
	case CodePartHeaders:
		if ForbiddenKeepHeaders[name] || CredentialHeaders[name] {
			return false
		}
	case CodePartQuery:
		if CodeQueryReserved[strings.ToLower(name)] {
			return false
		}
	case CodePartBody:
		n, ok := codeBodyName(name)
		if !ok {
			return false
		}
		name = n
	}
	w := NameWords(name)
	if len(w) == 0 || CodePersonalWords[w[len(w)-1]] {
		return false
	}
	for _, x := range w {
		if CodeExcludedWords[x] {
			return false
		}
	}
	return true
}

// codeBodyName is the field name of a body tt-path for the code rules: the
// last .name step (an attribute without its @), or the step before .#text.
func codeBodyName(path string) (string, bool) {
	steps, ok := ParseTTPath(path)
	if !ok || len(steps) == 0 {
		return "", false
	}
	last := steps[len(steps)-1]
	if last.Kind == StepName && last.Name == "#text" {
		if len(steps) < 2 {
			return "", false
		}
		last = steps[len(steps)-2]
	}
	if last.Kind != StepName || last.Name == "#text" {
		return "", false
	}
	return strings.TrimPrefix(last.Name, "@"), true
}

// CodeRuleAllowed reports whether the observe phase may propose a code rule
// on the rule name of the given kind without a person (policy.md 1.5): a
// field CodeRuleSafe allows whose name is status- or code-like (CodeName).
func CodeRuleAllowed(kind, name string) bool {
	if !CodeRuleSafe(kind, name) {
		return false
	}
	if kind == CodePartBody {
		name, _ = codeBodyName(name)
	}
	return CodeName(name)
}

// CodeAlnumWords are the last words of the code-like names (a subset of
// CodeWords) on which the observe phase proposes the alnum shape even when
// the observed values are short strings (spec v1.19): codes, types, kinds,
// levels and tiers often hold digits ("A1", "R", "2"). On any other
// code-like name it proposes alnum only when the values are digits.
var CodeAlnumWords = map[string]bool{"code": true, "type": true, "kind": true, "level": true, "tier": true}

// CodeProposalShape returns the code shape the observe phase proposes for
// a field CodeRuleAllowed admits, from the drop shape observed most often
// ("drop:str:l8", "drop:str:l32", "drop:str:digits"); ok is false when no
// code fits the shape.
func CodeProposalShape(kind, name, observed string, alnum bool) (shape string, ok bool) {
	if kind == CodePartBody {
		name, _ = codeBodyName(name)
	}
	w := NameWords(name)
	switch observed {
	case "drop:str:digits":
		if !alnum {
			return "", false
		}
		return CodeShapeAlnum, true
	case "drop:str:l8", "drop:str:l32":
		if alnum && len(w) > 0 && CodeAlnumWords[w[len(w)-1]] {
			return CodeShapeAlnum, true
		}
		return CodeShapeAlpha, true
	}
	return "", false
}
