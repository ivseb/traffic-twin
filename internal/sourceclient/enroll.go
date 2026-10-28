package sourceclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Enrollment errors. They are stable codes: callers log them and report them
// in the heartbeat, never anything that came from a payload.
var (
	ErrTokenMalformed    = errors.New("sourceclient: enrollment token malformed")
	ErrEnrollNotHTTPS    = errors.New("sourceclient: enrollment url must be https")
	ErrPinMismatch       = errors.New("sourceclient: tt-core root certificate does not match the token pin")
	ErrEnrollRejected    = errors.New("sourceclient: enrollment rejected by tt-core")
	ErrEnrollBadResponse = errors.New("sourceclient: invalid enrollment response")
)

var tokenRE = regexp.MustCompile(`^tte_[A-Za-z0-9_-]{32,128}\.([A-Za-z0-9_-]{43})$`)

var (
	sourceIDRE    = regexp.MustCompile(`^src-[0-9A-Za-z]{1,32}$`)
	groupRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	serviceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
)

// TokenPin returns the CA pin embedded in an enrollment token.
func TokenPin(token string) (string, bool) {
	m := tokenRE.FindStringSubmatch(token)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// PinOf is base64url(SHA-256(DER)) without padding, the pin format of the
// enrollment token.
func PinOf(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Identity is what enrollment produced (without the private key).
type Identity struct {
	SourceID    string `json:"source_id"`
	Group       string `json:"group"`
	ServiceName string `json:"service_name"`
	// ClientCertPEM and CAChainPEM are PEM bundles.
	ClientCertPEM string    `json:"client_cert"`
	CAChainPEM    string    `json:"ca_chain"`
	NotAfter      time.Time `json:"not_after"`

	IntakeURL string `json:"intake_url"`
	FleetURL  string `json:"fleet_url"`

	PolicyMaxAgeS       int64 `json:"policy_max_age_s"`
	HeartbeatIntervalS  int64 `json:"heartbeat_interval_s"`
	PolicyPollIntervalS int64 `json:"policy_poll_interval_s"`

	// PinnedKeys are the policy signing keys currently trusted; RevokedKids
	// the ones that must never be trusted again (Fleet revoke_signing_keys).
	PinnedKeys  []SigningKey `json:"pinned_keys"`
	RevokedKids []string     `json:"revoked_kids"`

	// Bookkeeping.
	EnrollURL string `json:"enroll_url"`
	Pin       string `json:"pin"`
	UsedCSR   bool   `json:"used_csr"`
}

// EnrollOptions configure Enroll.
type EnrollOptions struct {
	EnrollURL string
	Token     string
	Source    SourceInfo
	// NoCSR asks tt-core to generate the key pair (the key then travels once
	// over the pinned TLS channel). The default builds a CSR locally, so the
	// private key never leaves the source.
	NoCSR   bool
	Timeout time.Duration
	Now     func() time.Time
}

// Enroll exchanges the token for a client certificate. The server is
// authenticated only through the pin in the token: the chain presented by
// tt-core must include its root, the root must hash to the pin, and the leaf
// must verify against that root and the enrollment host name.
func Enroll(ctx context.Context, o EnrollOptions) (*Identity, []byte, error) {
	pin, ok := TokenPin(o.Token)
	if !ok {
		return nil, nil, ErrTokenMalformed
	}
	base, err := url.Parse(o.EnrollURL)
	if err != nil || base.Host == "" {
		return nil, nil, fmt.Errorf("sourceclient: enrollment url: %w", ErrEnrollNotHTTPS)
	}
	if base.Scheme != "https" {
		return nil, nil, ErrEnrollNotHTTPS
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig:   pinnedTLSConfig(base.Hostname(), pin, now),
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	body := map[string]any{"token": o.Token, "source": o.Source}
	var keyPEM []byte
	if !o.NoCSR {
		var csrPEM []byte
		keyPEM, csrPEM, err = NewCSR(o.Source.ServiceName)
		if err != nil {
			return nil, nil, err
		}
		body["csr"] = string(csrPEM)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.JoinPath("/fleet/v1/enroll").String(), bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, ErrPinMismatch) {
			return nil, nil, ErrPinMismatch
		}
		return nil, nil, fmt.Errorf("sourceclient: enroll request: %w", unwrapNet(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("sourceclient: enroll response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, nil, &StatusError{Op: "enroll", Status: resp.StatusCode}
	}
	var er enrollmentResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, nil, ErrEnrollBadResponse
	}
	if o.NoCSR {
		if er.ClientKey == "" {
			return nil, nil, ErrEnrollBadResponse
		}
		keyPEM = []byte(er.ClientKey)
	}
	id, err := identityFromResponse(&er, pin, o.EnrollURL, !o.NoCSR, keyPEM, now())
	if err != nil {
		return nil, nil, err
	}
	return id, keyPEM, nil
}

// unwrapNet keeps the error useful without carrying URLs (which may hold
// secrets in user-info) into logs.
func unwrapNet(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// StatusError is an unexpected HTTP status from tt-core.
type StatusError struct {
	Op     string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("sourceclient: %s: http status %d", e.Op, e.Status)
}

func identityFromResponse(er *enrollmentResponse, pin, enrollURL string, usedCSR bool, keyPEM []byte, now time.Time) (*Identity, error) {
	bad := ErrEnrollBadResponse
	if !sourceIDRE.MatchString(er.SourceID) || !groupRE.MatchString(er.Group) || !serviceNameRE.MatchString(er.ServiceName) {
		return nil, bad
	}
	if len(er.PolicySigningKeys) == 0 {
		return nil, bad
	}
	for _, u := range []string{er.IntakeURL, er.FleetURL} {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme != "https" || pu.Host == "" {
			return nil, bad
		}
	}
	chain, err := parseCerts([]byte(er.CAChain))
	if err != nil || len(chain) == 0 {
		return nil, bad
	}
	pinned := false
	for _, c := range chain {
		if PinOf(c.Raw) == pin {
			pinned = true
		}
	}
	if !pinned {
		return nil, ErrPinMismatch
	}
	leaf, err := parseCerts([]byte(er.ClientCert))
	if err != nil || len(leaf) == 0 {
		return nil, bad
	}
	if _, err := tls.X509KeyPair([]byte(er.ClientCert), keyPEM); err != nil {
		return nil, bad
	}
	if !certHasSourceID(leaf[0], er.SourceID) {
		return nil, bad
	}
	pool := x509.NewCertPool()
	for _, c := range chain {
		pool.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range leaf[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		return nil, bad
	}
	id := &Identity{
		SourceID: er.SourceID, Group: er.Group, ServiceName: er.ServiceName,
		ClientCertPEM: er.ClientCert, CAChainPEM: er.CAChain,
		IntakeURL: er.IntakeURL, FleetURL: er.FleetURL,
		PolicyMaxAgeS: er.PolicyMaxAgeS, HeartbeatIntervalS: er.HeartbeatIntervalS, PolicyPollIntervalS: er.PolicyPollIntervalS,
		EnrollURL: enrollURL, Pin: pin, UsedCSR: usedCSR,
		NotAfter: leaf[0].NotAfter,
	}
	if id.PolicyMaxAgeS <= 0 {
		id.PolicyMaxAgeS = 86400
	}
	if id.HeartbeatIntervalS <= 0 {
		id.HeartbeatIntervalS = 30
	}
	if id.PolicyPollIntervalS <= 0 {
		id.PolicyPollIntervalS = 60
	}
	for _, k := range er.PolicySigningKeys {
		if k.Alg != "Ed25519" || k.Kid == "" || k.PublicKey == "" {
			return nil, bad
		}
		id.PinnedKeys = append(id.PinnedKeys, SigningKey{Kid: k.Kid, Alg: "Ed25519", PublicKey: k.PublicKey})
	}
	return id, nil
}

func certHasSourceID(c *x509.Certificate, id string) bool {
	for _, d := range c.DNSNames {
		if d == id {
			return true
		}
	}
	for _, u := range c.URIs {
		if u.Opaque == id || u.Host == id || strings.HasSuffix(u.Path, "/"+id) {
			return true
		}
	}
	return false
}

// pinnedTLSConfig authenticates the server with the pin only: the certificate
// chain presented must contain a self-signed CA whose DER hashes to pin, and
// the leaf must verify against it for the host. Nothing else is trusted.
func pinnedTLSConfig(host, pin string, now func() time.Time) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Verification is done below, against the pinned root only.
		InsecureSkipVerify: true, //nolint:gosec // see VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(raw))
			for _, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return ErrPinMismatch
				}
				certs = append(certs, c)
			}
			if len(certs) == 0 {
				return ErrPinMismatch
			}
			var root *x509.Certificate
			for _, c := range certs {
				if c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil && PinOf(c.Raw) == pin {
					root = c
					break
				}
			}
			if root == nil {
				return ErrPinMismatch
			}
			roots := x509.NewCertPool()
			roots.AddCert(root)
			inter := x509.NewCertPool()
			for _, c := range certs[1:] {
				if c != root {
					inter.AddCert(c)
				}
			}
			_, err := certs[0].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: inter, DNSName: host,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now(),
			})
			if err != nil {
				return fmt.Errorf("%w: %v", ErrPinMismatch, err)
			}
			return nil
		},
	}
	if ip := net.ParseIP(host); ip == nil {
		cfg.ServerName = host
	}
	return cfg
}

// NewCSR generates an ECDSA P-256 key and a PKCS#10 request. It returns the
// PKCS#8 private key and the CSR, both PEM.
func NewCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

func parseCerts(pemData []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
