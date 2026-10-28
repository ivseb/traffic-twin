package fleet

import (
	"math"
	"sort"
	"strings"

	"github.com/ivseb/traffic-twin/internal/policy"
)

// Automatic detection of who the user is (identity.subject, policy.md 7.4).
//
// The detection is generic: it never relies on a list of application
// header names. It works only from what the core already has in the
// discovery sketches of the inbound calls, never a value: for each request
// header (and cookie) the estimated distinct values, the calls carrying it
// and its dominant shape. Each candidate gets a score from
//
//   - cardinality (35): many distinct values but clearly fewer than calls,
//     because a user repeats calls. A value on almost every call is a
//     request or trace id; a handful of values is a tenant, a channel, a
//     version (or too few users yet);
//   - shape (25): id-like (uuid, digits, hex) best, short text next,
//     personal formats (email, phone) lower: still only a token leaves;
//     dates, URLs, addresses and long text are not an identity;
//   - presence (25): carried by most inbound calls;
//   - name (15, weak): the name contains a word that often names a person
//     in some language (user, customer, member, account, utente...).
//
// The stability of a value across one caller's consecutive calls would be
// a further signal, but the sketches are per operation, not per caller:
// it is not used. A bearer JWT on most calls wins (claim sub), then a
// header whose values are JWTs; otherwise the best header with a score of
// at least identityMinScore. Cookies are listed but never chosen by
// themselves: they carry session secrets, so a cookie needs approvals.

// identityMinScore is the score a header needs to become the identity by
// itself.
const identityMinScore = 60

// identityMaxCandidates bounds the ranking returned.
const identityMaxCandidates = 20

// Thresholds of the cardinality signal.
const (
	identityPerCallMax = 0.9 // distinct per call at or above: a request id
	identityRepeatFull = 0.5 // distinct per call at or below: full score
	identityRareShare  = 0.2 // presence below: not the user
)

// Signal and exclusion codes of a candidate (the console translates them).
const (
	sigJWTBearer  = "jwt_bearer"     // most inbound calls carry a bearer token: its claim sub
	sigJWTShape   = "jwt_shape"      // the values are JWTs: their claim sub
	sigIDShape    = "id_shape"       // uuid, digits or hex values
	sigShortShape = "short_shape"    // short text values
	sigPersonal   = "personal_shape" // e-mail or phone: still only a token leaves
	sigLongShape  = "long_shape"     // long text values
	sigRepeats    = "repeats"        // many distinct values, fewer than calls
	sigMostCalls  = "most_calls"     // on most inbound calls
	sigSomeCalls  = "some_calls"     // on part of the inbound calls
	sigNameHint   = "name_hint"      // the name suggests a person (weak)

	exclCredential = "credential"   // a credential (or a credential-like name)
	exclCookie     = "cookie"       // a cookie: needs approvals, never automatic
	exclFewValues  = "few_values"   // few distinct values: tenant, channel, version
	exclPerCall    = "per_call"     // a new value on almost every call: request or trace id
	exclShape      = "not_id_shape" // dates, URLs, addresses, long text
	exclRare       = "rare"         // on few of the inbound calls
)

// protocolHeaders never name the user: HTTP, proxy and tracing headers.
var protocolHeaders = map[string]bool{
	"accept": true, "accept-charset": true, "accept-encoding": true, "accept-language": true, "cache-control": true,
	"connection": true, "content-encoding": true, "content-language": true, "content-length": true, "content-md5": true,
	"content-type": true, "date": true, "dnt": true, "expect": true, "forwarded": true, "host": true, "if-match": true,
	"if-modified-since": true, "if-none-match": true, "if-range": true, "if-unmodified-since": true, "keep-alive": true,
	"max-forwards": true, "origin": true, "pragma": true, "priority": true, "purpose": true, "range": true, "referer": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true, "upgrade-insecure-requests": true,
	"user-agent": true, "via": true, "x-real-ip": true, "x-requested-with": true, "x-http-method-override": true,
}

var protocolPrefixes = []string{"sec-", "x-forwarded-", "x-envoy-", "x-b3-", "x-amzn-", "x-datadog-", "x-cloud-trace", "x-original-"}

func protocolHeader(name string) bool {
	if protocolHeaders[name] || traceHeaders[name] {
		return true
	}
	for _, p := range protocolPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// personWords often name a person in a field name, in several languages;
// they are matched as substrings. personTokens are short words matched as
// whole words only. A weak hint: the data decide.
var personWords = []string{
	"user", "person", "customer", "client", "member", "account", "subject", "principal", "owner", "profile", "patient",
	"employee", "citizen", "utente", "cliente", "persona", "socio", "iscritt", "abbonat", "dipendent", "cittadin",
	"kunde", "benutzer", "nutzer", "mitglied", "usuario", "utilisateur", "membre", "compte", "conta", "kund",
}

var personTokens = map[string]bool{"uid": true, "usr": true, "sub": true, "acct": true, "cust": true, "mbr": true, "pid": true}

func personNameHint(name string) bool {
	n := strings.ToLower(name)
	for _, w := range personWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	for _, w := range strings.FieldsFunc(n, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }) {
		if personTokens[w] {
			return true
		}
	}
	return false
}

// shapeWeight rates a drop shape as an identity: the weight (0 when it is
// not one) and the signal code.
func shapeWeight(shape string) (float64, string) {
	kind, detail := shapeKind(shape)
	switch {
	case shape == "":
		return 0.5, ""
	case kind != "str":
		return 0, ""
	}
	switch detail {
	case "uuid", "digits", "hex":
		return 1, sigIDShape
	case "l32":
		return 0.8, sigShortShape
	case "l8":
		return 0.7, sigShortShape
	case "email":
		return 0.6, sigPersonal
	case "phone":
		return 0.5, sigPersonal
	case "l128":
		return 0.4, sigLongShape
	}
	return 0, ""
}

// identityAgg collects the discovery evidence of one header or cookie.
type identityAgg struct {
	from, name string
	observed   int64 // Σ calls carrying it, over the operations
	distinctOp int64 // Σ distinct per operation
	distinct   int   // max distinct of one operation (a lower bound)
	services   map[string]bool
	shapes     map[string]int64
}

// detectIdentity ranks the identity candidates of the inbound traffic of
// disc and returns them best first (at most identityMaxCandidates) with
// the source to use by itself, or nil.
func detectIdentity(disc *Discovery) ([]IdentityCandidate, *AssistIdentity) {
	inboundCalls := map[string]int64{}
	for _, op := range disc.Ops {
		if op.Inbound {
			inboundCalls[op.Service] += op.Calls
		}
	}
	aggs := map[[2]string]*identityAgg{}
	for _, df := range disc.Fields {
		if _, ok := inboundCalls[df.Service]; !ok {
			continue
		}
		for _, kind := range []string{"header", "cookie"} {
			name, ok := strings.CutPrefix(df.Path, "req."+kind+"s.")
			if !ok || name == "{*}" || name == "" {
				continue
			}
			name = strings.ToLower(name)
			if kind == "header" && (protocolHeader(name) || name == "authorization") {
				continue // the bearer token is judged from the Authorization statistics
			}
			k := [2]string{kind, name}
			a := aggs[k]
			if a == nil {
				a = &identityAgg{from: kind, name: name, services: map[string]bool{}, shapes: map[string]int64{}}
				aggs[k] = a
			}
			obs := max(df.Observed, int64(df.Distinct))
			a.observed += obs
			a.distinctOp += int64(df.Distinct)
			a.distinct = max(a.distinct, df.Distinct)
			a.services[df.Service] = true
			if df.Shape != "" {
				a.shapes[df.Shape] += obs
			}
		}
	}
	out := []IdentityCandidate{}
	if c := bearerCandidate(disc); c != nil {
		out = append(out, *c)
	}
	for _, a := range aggs {
		var calls int64
		for s := range a.services {
			calls += inboundCalls[s]
		}
		out = append(out, scoreCandidate(a, calls))
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.Excluded == "") != (b.Excluded == "") {
			return a.Excluded == ""
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Calls != b.Calls {
			return a.Calls > b.Calls
		}
		return a.From+" "+a.Name < b.From+" "+b.Name
	})
	if len(out) > identityMaxCandidates {
		out = out[:identityMaxCandidates]
	}
	var best *AssistIdentity
	for i := range out {
		c := &out[i]
		if c.Excluded == "" && c.ObserveSafe && c.Score >= identityMinScore {
			c.Best = true
			best = &AssistIdentity{From: c.From, Name: c.Name, JWTClaim: c.JWTClaim}
			break
		}
	}
	return out, best
}

// bearerCandidate is the claim sub of the bearer JWT of the Authorization
// header, from the inbound service where most calls carry one.
func bearerCandidate(disc *Discovery) *IdentityCandidate {
	var best string
	var bs AuthStat
	for svc, st := range disc.Auth {
		if st.WithAuthorization > bs.WithAuthorization || (st.WithAuthorization == bs.WithAuthorization && svc < best) {
			best, bs = svc, st
		}
	}
	if best == "" || bs.Calls <= 0 || bs.WithAuthorization <= 0 {
		return nil
	}
	share := math.Min(1, float64(bs.WithAuthorization)/float64(bs.Calls))
	c := &IdentityCandidate{From: "header", Name: "authorization", JWTClaim: "sub", JWT: true, Calls: bs.WithAuthorization, Presence: round2(share),
		Signals: []string{sigJWTBearer}}
	for _, df := range disc.Fields {
		if df.Service == best && df.Path == "req.headers.authorization" {
			c.Distinct = max(c.Distinct, df.Distinct)
		}
	}
	c.ObserveSafe = policy.IdentityObserveSafe(&policy.Subject{From: c.From, Name: c.Name, JWTClaim: c.JWTClaim})
	if share >= identityMinShare {
		c.Score = 100
		c.Signals = append(c.Signals, sigMostCalls)
	} else {
		c.Score = int(math.Round(100 * share))
		c.Signals = append(c.Signals, sigSomeCalls)
		if share < identityRareShare {
			c.Excluded = exclRare
		}
	}
	return c
}

// scoreCandidate scores one header or cookie seen on calls inbound calls.
func scoreCandidate(a *identityAgg, calls int64) IdentityCandidate {
	c := IdentityCandidate{From: a.from, Name: a.name, Calls: a.observed, Distinct: a.distinct, Signals: []string{}}
	var shape string
	var shapeN int64
	for s, n := range a.shapes {
		if n > shapeN || (n == shapeN && s < shape) {
			shape, shapeN = s, n
		}
	}
	c.Shape = shape
	if calls < a.observed {
		calls = a.observed
	}
	presence := 0.0
	if calls > 0 {
		presence = float64(a.observed) / float64(calls)
	}
	perCall := 0.0
	if a.observed > 0 {
		perCall = math.Min(1, float64(a.distinctOp)/float64(a.observed))
	}
	c.Presence, c.PerCall = round2(presence), round2(perCall)

	_, detail := shapeKind(shape)
	if a.from == "header" && detail == "jwt" {
		// A header whose values are JWTs: the claim sub, as the bearer token.
		c.JWT, c.JWTClaim = true, "sub"
		c.Signals = append(c.Signals, sigJWTShape)
		c.Score = int(math.Round(90 * math.Min(1, presence/0.8)))
	} else {
		card := 0.0
		switch {
		case a.distinct <= assistEnumMax:
		case perCall <= identityRepeatFull:
			card = 1
		case perCall < identityPerCallMax:
			card = (identityPerCallMax - perCall) / (identityPerCallMax - identityRepeatFull)
		}
		if card > 0 {
			c.Signals = append(c.Signals, sigRepeats)
		}
		sw, sig := shapeWeight(shape)
		if sig != "" {
			c.Signals = append(c.Signals, sig)
		}
		hint := 0.0
		if personNameHint(a.name) {
			hint = 1
			c.Signals = append(c.Signals, sigNameHint)
		}
		c.Score = int(math.Round(35*card + 25*sw + 25*math.Min(1, presence/0.8) + 15*hint))
		switch {
		case a.distinct <= assistEnumMax:
			c.Excluded = exclFewValues
		case perCall >= identityPerCallMax:
			c.Excluded = exclPerCall
		case sw == 0:
			c.Excluded = exclShape
		}
	}
	if presence >= 0.8 {
		c.Signals = append(c.Signals, sigMostCalls)
	} else {
		c.Signals = append(c.Signals, sigSomeCalls)
	}
	c.ObserveSafe = policy.IdentityObserveSafe(&policy.Subject{From: c.From, Name: c.Name, JWTClaim: c.JWTClaim})
	switch {
	case a.from == "cookie":
		c.Excluded = exclCookie
	case !c.ObserveSafe:
		c.Excluded = exclCredential
	case c.Excluded == "" && presence < identityRareShare:
		c.Excluded = exclRare
	}
	return c
}

func round2(x float64) float64 { return math.Round(x*100) / 100 }
