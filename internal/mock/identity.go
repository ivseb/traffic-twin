package mock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Sessions chosen by the caller's identity (docs/spec/mock.md 2.6). A real
// application cannot send X-TT-Session; with an identity header configured
// the mock reads the header chosen in configuration (or a claim of the JWT
// it carries), maps its value with a keyed hash to a session of its own and
// to a synthetic customer of the world, and keeps doing so for the same
// value. The value itself is never kept, logged or journaled: only its hash.

// Environment of the identity sessions (flags win).
const (
	EnvIdentityHeader = "TT_MOCK_IDENTITY_HEADER"
	EnvIdentityClaim  = "TT_MOCK_IDENTITY_CLAIM"
	EnvIdentityKey    = "TT_MOCK_IDENTITY_KEY"
	EnvIdentityMap    = "TT_MOCK_IDENTITY_MAP"
	// MinIdentityKey is the shortest accepted key, in bytes.
	MinIdentityKey = 32
	// identitySessionPrefix starts the id of a session chosen by identity.
	identitySessionPrefix = "u-"
	maxIdentityValue      = 1024
	maxIdentityMap        = 10000
)

var (
	identityHeaderRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]{1,64}$`)
	identityClaimRE  = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	identityHashRE   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	customerRE       = regexp.MustCompile(`^[A-Z]{2,5}-SYN-[0-9]{4,}$`)
)

// IdentityConfig configures the identity sessions. A zero Header turns
// them off.
type IdentityConfig struct {
	// Header is the request header that carries the identity (any name).
	Header string `json:"header"`
	// Claim, when set, is a claim of the JWT carried by Header (with or
	// without "Bearer "); the signature is not verified (the mock does not
	// authenticate). Dotted names reach nested claims.
	Claim string `json:"claim,omitempty"`
	// Key is the hashing key (at least 32 bytes). Empty: a random key per
	// process (the mapping then changes at every start).
	Key []byte `json:"-"`
	// Map assigns a synthetic customer to an identity: keys are the
	// identity in clear (a file of the tester) or "h:" + IdentityHash
	// (the console stores only hashes).
	Map map[string]string `json:"-"`
}

// Validate checks names, key and map entries.
func (c *IdentityConfig) Validate() error {
	if c == nil || c.Header == "" {
		if c != nil && (c.Claim != "" || len(c.Map) > 0) {
			return errors.New("mock: identity claim or map without an identity header")
		}
		return nil
	}
	if !identityHeaderRE.MatchString(c.Header) {
		return errors.New("mock: malformed identity header name")
	}
	if c.Claim != "" && !identityClaimRE.MatchString(c.Claim) {
		return errors.New("mock: malformed identity claim name")
	}
	if len(c.Key) > 0 && len(c.Key) < MinIdentityKey {
		return fmt.Errorf("mock: the identity key must be at least %d bytes", MinIdentityKey)
	}
	if len(c.Map) > maxIdentityMap {
		return errors.New("mock: identity map too large")
	}
	for k, v := range c.Map {
		if k == "" || len(k) > maxIdentityValue {
			return errors.New("mock: identity map: empty or too long user")
		}
		if h, ok := strings.CutPrefix(k, "h:"); ok && !identityHashRE.MatchString(h) {
			return errors.New("mock: identity map: malformed hash (h: + 32 hex digits)")
		}
		if !customerRE.MatchString(v) {
			return errors.New("mock: identity map: malformed customer id")
		}
	}
	return nil
}

// IdentityHash is the keyed hash of an identity value (32 hex digits): the
// console and the mock compute the same with the same key.
func IdentityHash(key []byte, value string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tt.mock.identity/v1\x00"))
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// identityState is the compiled configuration (immutable once built).
type identityState struct {
	header, claim string
	key           []byte
	byHash        map[string]string // hash -> customer
}

func newIdentityState(c *IdentityConfig) (*identityState, error) {
	if c == nil || c.Header == "" {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	st := &identityState{header: http.CanonicalHeaderKey(c.Header), claim: c.Claim, key: c.Key, byHash: map[string]string{}}
	if len(st.key) == 0 {
		st.key = make([]byte, MinIdentityKey)
		_, _ = rand.Read(st.key)
	}
	for k, v := range c.Map {
		h, ok := strings.CutPrefix(k, "h:")
		if !ok {
			h = IdentityHash(st.key, k)
		}
		st.byHash[h] = v
	}
	return st, nil
}

// identity extracts the identity of a request ("" when there is none).
func (st *identityState) identity(h http.Header) string {
	v := strings.TrimSpace(h.Get(st.header))
	if v == "" || len(v) > 8192 {
		return ""
	}
	if st.claim == "" {
		if len(v) > maxIdentityValue {
			return ""
		}
		return v
	}
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		v = strings.TrimSpace(v[7:])
	}
	claims := identityClaims(v)
	if claims == nil {
		return ""
	}
	var cur any = claims
	if _, direct := claims[st.claim]; direct {
		cur = claims[st.claim]
	} else {
		for _, k := range strings.Split(st.claim, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return ""
			}
			cur = m[k]
		}
	}
	switch x := cur.(type) {
	case string:
		if len(x) <= maxIdentityValue {
			return x
		}
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// identityClaims decodes the object the claim is read from: the payload of
// a JWT (three dot-separated parts) or (rules v1.9, C14) a header whose
// value is a JSON object, plain or base64/base64url encoded. nil when the
// value is none of them. The value is never kept.
func identityClaims(v string) map[string]any {
	decode := func(raw []byte) map[string]any {
		var claims map[string]any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if dec.Decode(&claims) != nil {
			return nil
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil // trailing data
		}
		return claims
	}
	if strings.HasPrefix(v, "{") {
		return decode([]byte(v))
	}
	if parts := strings.Split(v, "."); len(parts) == 3 {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
		if err != nil {
			return nil
		}
		return decode(raw)
	}
	trimmed := strings.TrimRight(v, "=")
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		if raw, err := enc.DecodeString(trimmed); err == nil && len(raw) > 0 && raw[0] == '{' {
			return decode(raw)
		}
	}
	return nil
}

// SetIdentity replaces the identity configuration (console mode applies the
// console's setting live). Existing sessions are kept.
func (m *Mock) SetIdentity(c *IdentityConfig) error {
	st, err := newIdentityState(c)
	if err != nil {
		return err
	}
	if st != nil {
		for h, cust := range st.byHash {
			if m.model.custByID[cust] == nil {
				// A customer the pack does not have (a typo, or a new pack):
				// that identity falls back to the hashed choice.
				m.log.Warn("identity map names a customer the pack does not have; using the hashed choice", "customer", cust)
				delete(st.byHash, h)
			}
		}
	}
	m.ident.Store(st)
	return nil
}

// identitySession returns the session of the request's identity, creating
// it on first use (nil, "" when the request has none or the feature is off).
// The error is the envelope to answer (too many sessions).
func (m *Mock) identitySession(r *http.Request) (*session, string, error) {
	st := m.ident.Load()
	if st == nil {
		return nil, "", nil
	}
	v := st.identity(r.Header)
	if v == "" {
		return nil, "", nil
	}
	h := IdentityHash(st.key, v)
	sid := identitySessionPrefix + h[:16]
	if s := m.lookup(sid); s != nil {
		return s, sid, nil
	}
	var customer *string
	if c, ok := st.byHash[h]; ok {
		customer = &c
	} else if n := len(m.model.custs); n > 0 {
		raw, _ := hex.DecodeString(h)
		c := m.model.custs[binary.BigEndian.Uint64(raw[8:16])%uint64(n)].ID
		customer = &c
	}
	seed := m.model.pack.Manifest.Seed
	if m.cfg.Seed != nil {
		seed = *m.cfg.Seed
	}
	if m.cfg.SessionIdleTTL > 0 {
		m.EvictIdle()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[sid]; s != nil {
		return s, sid, nil
	}
	if len(m.sessions) >= m.cfg.MaxSessions {
		return nil, "", errTooManySessions
	}
	s := newSession(m, sessionInit{id: sid, seed: seed, customer: customer, t0: m.model.t0,
		createFaults: FaultsConfig{Mode: m.cfg.Faults}, baseFaults: FaultsConfig{Mode: m.cfg.Faults}})
	s.byIdentity = true
	m.sessions[sid] = s
	return s, sid, nil
}

var errTooManySessions = errors.New("too_many_sessions")

// IdentityFromEnv fills the identity settings that flags left empty from
// the environment: header, claim, key (TT_MOCK_IDENTITY_KEY, at least 32
// bytes) and the map file (TT_MOCK_IDENTITY_MAP).
func (c *IdentityConfig) fromEnv(mapFile string) error {
	if c.Header == "" {
		c.Header = os.Getenv(EnvIdentityHeader)
	}
	if c.Claim == "" {
		c.Claim = os.Getenv(EnvIdentityClaim)
	}
	if k := os.Getenv(EnvIdentityKey); k != "" {
		c.Key = []byte(k)
	}
	if mapFile == "" {
		mapFile = os.Getenv(EnvIdentityMap)
	}
	if mapFile != "" {
		b, err := os.ReadFile(mapFile)
		if err != nil {
			return fmt.Errorf("identity map: %w", err)
		}
		if err := json.Unmarshal(b, &c.Map); err != nil {
			return errors.New("identity map: the file must be a JSON object {\"<test user>\": \"<customer id>\"}")
		}
	}
	return c.Validate()
}
