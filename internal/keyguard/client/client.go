// Package client is tt-core's client of tt keyguard
// (api/keyguard-api.v1.openapi.yaml): the intake token feed, the gate's
// reverse-HMAC check and pack signing, and the policy approval flow.
//
// It holds no key: only tt-core's TLS client identity (or nothing, over a
// Unix socket). Errors never contain request content.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Environment variables read by tt-core to reach keyguard. None of them is
// a key of keyguard: only tt-core's own TLS identity.
const (
	EnvURL        = "TT_KEYGUARD_URL"              // https://host:port or unix:///path/to/socket
	EnvClientCert = "TT_KEYGUARD_CLIENT_CERT_FILE" // tt-core's client certificate (PEM)
	EnvClientKey  = "TT_KEYGUARD_CLIENT_KEY_FILE"  // tt-core's client key (PEM)
	EnvCA         = "TT_KEYGUARD_CA_FILE"          // CA that issued keyguard's server certificate
	EnvServerPin  = "TT_KEYGUARD_SERVER_PIN"       // sha256:<hex SPKI> of keyguard's certificate
)

// Config tells how to reach keyguard.
type Config struct {
	// URL is "https://host:port" (mTLS) or "unix:///path/to/socket".
	URL string
	// ClientCert and ClientKey are tt-core's TLS identity (mTLS only).
	ClientCert, ClientKey string
	// CA verifies keyguard's certificate chain and host name. ServerPin
	// ("sha256:<hex SPKI>") pins keyguard's key. At least one is required
	// for mTLS; with both, both are checked.
	CA, ServerPin string
	// Timeout per request (default 2 minutes; pack signing may take long).
	Timeout time.Duration
}

// ConfigFromEnv reads the client configuration from environment entries.
func ConfigFromEnv(environ []string) Config {
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return Config{URL: env[EnvURL], ClientCert: env[EnvClientCert], ClientKey: env[EnvClientKey], CA: env[EnvCA], ServerPin: env[EnvServerPin]}
}

// Client calls keyguard. It is safe for concurrent use.
type Client struct {
	base string
	hc   *http.Client
}

// New builds a client.
func New(c Config) (*Client, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, errors.New("keyguard client: invalid URL")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	tr := &http.Transport{MaxIdleConns: 4, IdleConnTimeout: time.Minute, ForceAttemptHTTP2: false}
	base := ""
	switch u.Scheme {
	case "unix":
		path := u.Path
		if path == "" {
			return nil, errors.New("keyguard client: unix URL needs a socket path")
		}
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		base = "http://keyguard"
	case "https":
		if c.ClientCert == "" || c.ClientKey == "" {
			return nil, errors.New("keyguard client: mTLS needs a client certificate and key")
		}
		if c.CA == "" && c.ServerPin == "" {
			return nil, errors.New("keyguard client: mTLS needs a CA or a server pin")
		}
		cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, errors.New("keyguard client: cannot load the client certificate and key")
		}
		tc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
		if c.CA != "" {
			b, err := os.ReadFile(c.CA)
			if err != nil {
				return nil, fmt.Errorf("keyguard client: read CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return nil, errors.New("keyguard client: CA file has no certificate")
			}
			tc.RootCAs = pool
		}
		if c.ServerPin != "" {
			h, ok := strings.CutPrefix(c.ServerPin, "sha256:")
			pin, err := hex.DecodeString(h)
			if !ok || err != nil || len(pin) != sha256.Size {
				return nil, errors.New("keyguard client: server pin is not sha256:<64 hex>")
			}
			if c.CA == "" {
				// Pin only: the chain is not verified, the key is.
				tc.InsecureSkipVerify = true
			}
			tc.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("keyguard: no server certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
					return errors.New("keyguard: server certificate is not pinned")
				}
				return nil
			}
		}
		tr.TLSClientConfig = tc
		base = "https://" + u.Host
	default:
		return nil, errors.New("keyguard client: URL scheme must be https or unix")
	}
	return &Client{base: base, hc: &http.Client{Transport: tr, Timeout: timeout}}, nil
}

// Close releases idle connections.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

// Error is a keyguard error response.
type Error struct {
	Status  int
	Code    string
	Message string
	// ReverseHMAC is set when pack signing found real values.
	ReverseHMAC *ReverseHMAC
}

func (e *Error) Error() string {
	return fmt.Sprintf("keyguard: %d %s: %s", e.Status, e.Code, e.Message)
}

// IsRateLimited reports a 429 (rate limit or daily budget).
func IsRateLimited(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusTooManyRequests
}

func (c *Client) do(ctx context.Context, method, path, ctype string, body []byte, hdr map[string]string, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("keyguard unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode}
		var eb struct {
			Code        string       `json:"code"`
			Message     string       `json:"message"`
			ReverseHMAC *ReverseHMAC `json:"reverse_hmac"`
		}
		if json.Unmarshal(data, &eb) == nil {
			e.Code, e.Message, e.ReverseHMAC = eb.Code, eb.Message, eb.ReverseHMAC
		}
		return e
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("keyguard: malformed response")
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, "application/json", b, nil, out)
}

// AddTokens feeds real tokens accepted by the intake (at most 100000 per
// call) for one epoch.
func (c *Client) AddTokens(ctx context.Context, epoch string, tokens []string) error {
	return c.postJSON(ctx, "/keyguard/v1/tokens", map[string]any{"epoch": epoch, "tokens": tokens}, nil)
}

// PolicyRef names a signed policy version.
type PolicyRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// Candidate is a value for Match: a string, or a JSON number lexeme.
type Candidate struct {
	raw json.RawMessage
}

// Str is a string candidate.
func Str(s string) Candidate {
	b, _ := json.Marshal(s)
	return Candidate{raw: b}
}

// Num is a number candidate given by its JSON lexeme (for pack numbers, the
// canonical form). An invalid lexeme is sent as a string.
func Num(lexeme string) Candidate {
	if !ttjson.IsNumberLexeme([]byte(lexeme)) {
		return Str(lexeme)
	}
	return Candidate{raw: json.RawMessage(lexeme)}
}

// MarshalJSON implements json.Marshaler.
func (c Candidate) MarshalJSON() ([]byte, error) { return c.raw, nil }

// MatchResult is one boolean per candidate, in order.
type MatchResult struct {
	Matches   []bool `json:"matches"`
	Positives int    `json:"positives"`
}

// Match runs the reverse-HMAC check (at most 10000 candidates per call by
// default, rate-limited: see IsRateLimited).
func (c *Client) Match(ctx context.Context, policies []PolicyRef, candidates []Candidate) (*MatchResult, error) {
	var out MatchResult
	err := c.postJSON(ctx, "/keyguard/v1/match", map[string]any{"policies": policies, "candidates": candidates}, &out)
	if err != nil {
		return nil, err
	}
	if len(out.Matches) != len(candidates) {
		return nil, errors.New("keyguard: match answer has the wrong length")
	}
	return &out, nil
}

// Approval is one approval forwarded to keyguard.
type Approval struct {
	User    string    `json:"user"`
	Roles   []string  `json:"roles"`
	At      time.Time `json:"at"`
	IDToken string    `json:"id_token,omitempty"`
	// Reason is mandatory for an admin approval.
	Reason string `json:"reason,omitempty"`
}

// Signature is a policy signature.
type Signature struct {
	Alg            string `json:"alg"`
	Kid            string `json:"kid"`
	Sig            string `json:"sig"`
	Classification string `json:"classification,omitempty"`
	ApprovalMode   string `json:"approval_mode,omitempty"`
	// OpensValues is keyguard's observe-safe verdict (policy.md 7).
	OpensValues *bool `json:"opens_values,omitempty"`
}

// Envelope assembles the signed envelope (tt.policy.compiled/v1) of body.
func (s *Signature) Envelope(body []byte) ([]byte, error) {
	p, err := policy.DecodeBody(body)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Sig)
	if err != nil {
		return nil, errors.New("keyguard: malformed signature")
	}
	return policy.Envelope(body, p, s.Kid, sig)
}

// SignPolicy asks keyguard to sign compiled body bytes. keyguard recomputes
// the classification and checks the approvals; a refusal is an *Error with
// status 403 (approvals, issued_seq) or 422 (body).
func (c *Client) SignPolicy(ctx context.Context, body []byte, proposer string, approvals []Approval) (*Signature, error) {
	var out Signature
	err := c.postJSON(ctx, "/keyguard/v1/policy/sign", map[string]any{
		"body_b64": base64.RawURLEncoding.EncodeToString(body), "proposer": proposer, "approvals": approvals,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RenewPolicy asks keyguard to re-sign a body that differs from the last
// signed one only in version, issued_seq, created_at and not_after.
func (c *Client) RenewPolicy(ctx context.Context, body []byte) (*Signature, error) {
	var out Signature
	if err := c.postJSON(ctx, "/keyguard/v1/policy/renew", map[string]any{"body_b64": base64.RawURLEncoding.EncodeToString(body)}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PackSignature is manifest.sig.json.
type PackSignature struct {
	Format         string `json:"format"`
	Alg            string `json:"alg"`
	Kid            string `json:"kid"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Sig            string `json:"sig"`
}

// SigFile renders manifest.sig.json in tt canonical JSON with a final
// newline.
func (p PackSignature) SigFile() []byte {
	v := ttjson.Obj(
		ttjson.Member{Key: "alg", Value: ttjson.Str(p.Alg)},
		ttjson.Member{Key: "format", Value: ttjson.Str(p.Format)},
		ttjson.Member{Key: "kid", Value: ttjson.Str(p.Kid)},
		ttjson.Member{Key: "manifest_sha256", Value: ttjson.Str(p.ManifestSHA256)},
		ttjson.Member{Key: "sig", Value: ttjson.Str(p.Sig)},
	)
	b, _ := ttjson.Encode(v)
	return append(b, '\n')
}

// Finding locates a reverse-HMAC positive (never the value).
type Finding struct {
	File    string `json:"file"`
	Pointer string `json:"pointer"`
	Reason  string `json:"reason"`
}

// ReverseHMAC is keyguard's reverse-HMAC result for a pack.
type ReverseHMAC struct {
	Status         string    `json:"status"`
	StringsChecked int64     `json:"strings_checked"`
	Findings       []Finding `json:"findings,omitempty"`
}

// PackResult is the answer of SignPack.
type PackResult struct {
	Signature    PackSignature `json:"signature"`
	ReverseHMAC  ReverseHMAC   `json:"reverse_hmac"`
	ApprovalMode string        `json:"approval_mode"`
}

// HeaderApproval is the header carrying the publishing requester.
const HeaderApproval = "X-TT-Approval"

// SignPack sends a .ttpack archive (gzip tar, without manifest.sig.json)
// for verification and signing. requester, optional, is the person who asked
// to publish (publisher, or admin with a reason). On reverse-HMAC positives
// the *Error carries ReverseHMAC findings.
func (c *Client) SignPack(ctx context.Context, archive []byte, requester *Approval) (*PackResult, error) {
	var hdr map[string]string
	if requester != nil {
		b, err := json.Marshal(requester)
		if err != nil {
			return nil, err
		}
		hdr = map[string]string{HeaderApproval: base64.RawURLEncoding.EncodeToString(b)}
	}
	var out PackResult
	if err := c.do(ctx, http.MethodPost, "/keyguard/v1/pack/sign", "application/gzip", archive, hdr, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PublicKey is a public signing key. EndorsedBy and Endorsement, when set,
// endorse a rotated policy key with the next older one (keyguard.md 6).
type PublicKey struct {
	Kid         string `json:"kid"`
	Alg         string `json:"alg"`
	PublicKey   string `json:"public_key"`
	EndorsedBy  string `json:"endorsed_by,omitempty"`
	Endorsement string `json:"endorsement,omitempty"`
}

// PublicKeys are keyguard's policy and pack signing public keys.
type PublicKeys struct {
	Policy []PublicKey `json:"policy"`
	Pack   []PublicKey `json:"pack"`
}

// GatePubKeys renders the pack keys as a TT_GATE_PUBKEYS value.
func (p *PublicKeys) GatePubKeys() string {
	parts := make([]string, 0, len(p.Pack))
	for _, k := range p.Pack {
		parts = append(parts, k.Kid+":"+k.PublicKey)
	}
	return strings.Join(parts, ",")
}

// PublicKeys fetches the public signing keys.
func (c *Client) PublicKeys(ctx context.Context) (*PublicKeys, error) {
	var out PublicKeys
	if err := c.do(ctx, http.MethodGet, "/keyguard/v1/public-keys", "", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status is keyguard's status (key ids, never keys).
type Status struct {
	HMACKids            []string `json:"hmac_kids"`
	Epochs              []string `json:"epochs"`
	ApprovalsUnverified bool     `json:"approvals_unverified"`
	MatchBudgetLeft     int64    `json:"match_budget_left"`
	PolicyKid           string   `json:"policy_kid"`
	PackKid             string   `json:"pack_kid"`
	RevokedKids         []string `json:"revoked_kids"`
	Filters             []struct {
		Epoch    string `json:"epoch"`
		Kid      string `json:"kid"`
		Tokens   uint64 `json:"tokens"`
		Segments int    `json:"segments"`
	} `json:"filters"`
	LastIssuedSeq    int64  `json:"last_issued_seq"`
	OpeningApprovals int    `json:"opening_approvals"`
	AdminOverride    bool   `json:"admin_override"`
	ObserveAuto      bool   `json:"observe_auto"`
	Transport        string `json:"transport"`
	// OIDC is set when keyguard verifies approvals with OIDC.
	OIDC *struct {
		Issuer     string `json:"issuer"`
		Audience   string `json:"audience"`
		RolesClaim string `json:"roles_claim"`
	} `json:"oidc,omitempty"`
}

// Status fetches the status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var out Status
	if err := c.do(ctx, http.MethodGet, "/keyguard/v1/status", "", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Health checks that keyguard answers.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/keyguard/v1/health", "", nil, nil, nil)
}

// AuditEntry is one entry of keyguard's audit log.
type AuditEntry struct {
	Seq      int64             `json:"seq"`
	At       time.Time         `json:"at"`
	Op       string            `json:"op"`
	Outcome  string            `json:"outcome"`
	Detail   map[string]string `json:"detail"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Audit returns audit entries after sinceSeq (at most 1000 per call).
func (c *Client) Audit(ctx context.Context, sinceSeq int64) ([]AuditEntry, error) {
	var out []AuditEntry
	if err := c.do(ctx, http.MethodGet, "/keyguard/v1/audit?since_seq="+strconv.FormatInt(sinceSeq, 10), "", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}
