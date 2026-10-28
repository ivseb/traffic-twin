package policy

import (
	"time"
)

// Format identifiers.
const (
	FormatAuthor   = "tt.policy/v1"
	FormatBody     = "tt.policy.body/v1"
	FormatEnvelope = "tt.policy.compiled/v1"
)

// Default limits (policy.md section 1, sanitizer.md sections 5.3, 9).
const (
	DefaultMaxBodyBytes = 1048576
	DefaultMaxDepth     = 32
	DefaultMaxArray     = 32
	DefaultMaxKeys      = 256
	DefaultKeepMaxBytes = 64
)

// Upper bounds of the limits (both schemas).
const (
	MaxMaxBodyBytes = 16777216
	MaxMaxDepth     = 128
	MaxMaxArray     = 1024
	MaxMaxKeys      = 4096
	MaxKeepMaxBytes = 1024
)

// Time windows (policy.md 1.4, 2; sanitizer.md 4.3, 15).
const (
	DefaultMaxAge   = 24 * time.Hour      // policy_max_age default
	DefaultValidity = 30 * 24 * time.Hour // not_after default after created_at
	MaxOpenWindow   = 7 * 24 * time.Hour  // discovery and auto_words
)

// MaxBoundLexeme is the longest bucket bound lexeme accepted (policy.md 1.4).
const MaxBoundLexeme = 64

// ReservedDomains are HMAC domains that rules must not use.
var ReservedDomains = map[string]bool{"subject": true, "sample": true, "sample-trace": true, "discovery": true}

// ForbiddenKeepHeaders may never carry a keep action (policy.md 1.4).
var ForbiddenKeepHeaders = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true, "proxy-authorization": true, "x-api-key": true,
}

// CredentialHeaders may carry neither keep nor hmac (hardening.md 2.1 H1):
// a source refuses a signed policy that does. x-api-key is not part of the
// source-side subset (keep stays forbidden to tt-core through
// ForbiddenKeepHeaders).
var CredentialHeaders = map[string]bool{
	"authorization": true, "cookie": true, "set-cookie": true, "proxy-authorization": true,
}

// ActionKind enumerates the rule actions.
type ActionKind uint8

// Action kinds.
const (
	ActDrop ActionKind = iota
	ActKeep
	ActHMAC
	ActBucketNum
	ActBucketTime
	// ActCode lets a code-shaped string out as a keep: token, otherwise
	// its drop shape (sanitizer.md 5.6, spec v1.11).
	ActCode
	// ActGraphQL turns a GraphQL document into its shape (request) and
	// lets the names of an introspection result out (response), as gql:
	// tokens (sanitizer.md 5.7, spec v1.14).
	ActGraphQL
)

// Bound is one numeric bucket bound.
type Bound struct {
	Lexeme string  // canonical form of the compiled lexeme (sanitizer 10.2)
	F      float64 // IEEE-754 double of the lexeme
}

// Code shapes (sanitizer.md 5.6). CodeShapeAlpha is the v1.11 shape
// ^[A-Za-z_-]{2,32}$ (compiled without a shape field); CodeShapeAlnum is the
// spec v1.19 shape ^[A-Za-z0-9_.-]{1,16}$ ({"action":"code","shape":"alnum"}).
const (
	CodeShapeAlpha = ""
	CodeShapeAlnum = "alnum"
)

// Action is a compiled rule action.
type Action struct {
	Kind   ActionKind
	Domain string  // ActHMAC
	Bounds []Bound // ActBucketNum
	Unit   string  // ActBucketTime: year | month | day | hour
	Shape  string  // ActCode: CodeShapeAlpha or CodeShapeAlnum
}

// BodyRule is one body rule (tt-path → action).
type BodyRule struct {
	Path   string
	Action Action
}

// Part holds the rules for one side of an exchange.
type Part struct {
	Path    map[string]Action // operations only
	Query   map[string]Action
	Headers map[string]Action
	Cookies map[string]Action
	Body    []BodyRule
}

// IsEmpty reports whether the part has no rule.
func (p *Part) IsEmpty() bool {
	return p == nil || (len(p.Path) == 0 && len(p.Query) == 0 && len(p.Headers) == 0 && len(p.Cookies) == 0 && len(p.Body) == 0)
}

// Scope groups request, response and errors parts.
type Scope struct {
	Request  Part
	Response Part
	Errors   Part
}

// Match selects a service: Inbound (optionally Internal), or Base.
type Match struct {
	Inbound  bool
	Internal bool
	Base     string // normalized (policy.md 1.3)
}

// Op is one operation of a service.
type Op struct {
	Op       string // "METHOD /template"
	Request  Part
	Response Part
}

// Service is one service entry.
type Service struct {
	Name  string
	Match Match
	Scope
	Ops []Op
}

// HMACRef names the HMAC key, the keys accepted during a rotation and the epoch.
type HMACRef struct {
	Kid        string
	AcceptKids []string
	Epoch      string
}

// Subject tells where to read the subject (sanitizer section 11).
type Subject struct {
	From     string // header | cookie
	Name     string
	JWTClaim string
	// JSONPath (spec v1.18, C14) reads the subject from a dotted path of
	// members inside a header whose value is a JSON object (or base64 of
	// one). Header only; excludes JWTClaim.
	JSONPath string
}

// Sampling configures sampling (sanitizer section 12).
type Sampling struct {
	RateBP       int
	TrustBaggage bool
	PropagateTo  []string
}

// Segments configures raw path segments and external hosts.
type Segments struct {
	AutoWords          bool
	AutoWordsExpiresAt time.Time // zero when absent
	autoWordsRaw       string
	Allow              []string
	HostsAllow         []string
}

// Limits are the sanitizer limits; all fields are always set.
type Limits struct {
	MaxBodyBytes int64
	MaxDepth     int
	MaxArray     int
	MaxKeys      int
	KeepMaxBytes int
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{DefaultMaxBodyBytes, DefaultMaxDepth, DefaultMaxArray, DefaultMaxKeys, DefaultKeepMaxBytes}
}

// Bounds of the bodies switches (sanitizer.md 22.1, spec v1.19).
const (
	MaxLargeBodyBytes = 67108864
	MaxLargeArray     = 1024
	// Defaults tt-core writes when bodies are on (policy.md 2).
	DefaultLargeBodyBytes   = 8388608
	DefaultLargeArray       = 50
	DefaultLargeNestedArray = 5
)

// Bodies are the body switches of sanitizer.md 22 (spec v1.19). The zero
// value (field absent) turns every switch off: the behaviour before v1.19.
type Bodies struct {
	XML              bool
	Multipart        bool
	Docs             bool
	MaxLargeBytes    int64 // 0 = large-body mode off
	LargeArray       int
	LargeNestedArray int
}

// DefaultBodies returns every switch on with the default large-body limits.
func DefaultBodies() *Bodies {
	return &Bodies{XML: true, Multipart: true, Docs: true, MaxLargeBytes: DefaultLargeBodyBytes,
		LargeArray: DefaultLargeArray, LargeNestedArray: DefaultLargeNestedArray}
}

// CaptureLimit is how many body bytes a source keeps (sanitizer.md 9.0 and
// 22.5): max(max_body_bytes, bodies.max_large_body_bytes) + 1.
func (p *Policy) CaptureLimit() int64 {
	n := p.Limits.MaxBodyBytes
	if p.Bodies != nil && p.Bodies.MaxLargeBytes > n {
		n = p.Bodies.MaxLargeBytes
	}
	return n + 1
}

// Discovery configures discovery mode (sanitizer section 15).
type Discovery struct {
	Enabled    bool
	ExpiresAt  time.Time
	expiresRaw string
}

// Host discovery modes (hosts.discovery, sanitizer.md 3.1 and 3.5, spec v1.5).
const (
	HostsAuto = "auto"
	HostsOff  = "off"
)

// Hosts configures how outbound hosts without a matching base leave
// (sanitizer.md 3.5). The zero value means auto.
type Hosts struct {
	// Discovery is HostsAuto or HostsOff; "" (field absent) means auto.
	Discovery string
}

// Auto reports whether host patterns are emitted (absent or auto).
func (h Hosts) Auto() bool { return h.Discovery != HostsOff }

// Policy is a compiled policy body (tt.policy.body/v1).
type Policy struct {
	PolicyID    string
	Version     int64
	IssuedSeq   int64
	CreatedAt   time.Time
	createdRaw  string
	NotAfter    time.Time
	notAfterRaw string
	Groups      []string // targets.groups
	HMAC        HMACRef
	Subject     *Subject // identity.subject; nil when absent
	Sampling    Sampling
	Segments    Segments
	Limits      Limits
	Discovery   *Discovery // nil when absent
	Hosts       Hosts      // hosts (spec v1.5); Discovery "" when absent
	Bodies      *Bodies    // bodies (spec v1.19); nil when absent (all off)
	Global      Scope
	Services    []Service
}

// DiscoveryActive reports whether discovery mode is on at the source time
// now (sanitizer 15): enabled, now < expires_at and now < created_at + 7 days.
func (p *Policy) DiscoveryActive(now time.Time) bool {
	d := p.Discovery
	return d != nil && d.Enabled && !now.IsZero() && now.Before(d.ExpiresAt) && now.Before(p.CreatedAt.Add(MaxOpenWindow))
}

// AutoWordsActive reports whether automatic path words are on at now
// (sanitizer 4.3).
func (p *Policy) AutoWordsActive(now time.Time) bool {
	s := &p.Segments
	return s.AutoWords && !now.IsZero() && !s.AutoWordsExpiresAt.IsZero() && now.Before(s.AutoWordsExpiresAt) &&
		now.Before(p.CreatedAt.Add(MaxOpenWindow))
}

// HasGroup reports whether group is in targets.groups.
func (p *Policy) HasGroup(group string) bool {
	for _, g := range p.Groups {
		if g == group {
			return true
		}
	}
	return false
}
