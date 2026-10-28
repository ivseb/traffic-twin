// Package fakecore is a fake tt-core for tests of capture sources: a TLS
// server with a private test CA that serves the Fleet source endpoints
// (enroll with a pinned token, policy with ETag, heartbeat, renew) and an
// OTLP/HTTP JSON intake over mTLS that keeps the events it receives.
//
// It is test support only (like internal/pack/packtest): nothing in the
// product imports it. It trusts what the test tells it and does no policy
// checks of its own beyond what a source can observe.
package fakecore

import (
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// SigningKid is the kid of the initial policy signing key.
const SigningKid = "policy-test-1"

// Core is the fake tt-core.
type Core struct {
	tb     testing.TB
	Server *httptest.Server
	// URL is the base URL of the (single) source-facing listener.
	URL string
	// Token is the enrollment token (tte_<secret>.<pin of the root>).
	Token string
	// Group and the service names allowed for it.
	Group string
	// ClientCertTTL is the validity of issued client certificates.
	ClientCertTTL time.Duration

	rootDER   []byte
	rootKey   *ecdsa.PrivateKey
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
	rootCert  *x509.Certificate

	signPub  ed25519.PublicKey
	signPriv ed25519.PrivateKey

	mu            sync.Mutex
	nextID        int
	envelope      []byte
	envHash       string
	hbResp        sourceclient.HeartbeatResponse
	heartbeats    []sourceclient.Heartbeat
	enrolls       int
	renews        int
	events        [][]byte
	batches       int
	revoked       map[string]bool
	logsFailN     int
	logsFailSt    int
	logsRetry     string
	logsBlock     chan struct{}
	logsReject    int
	services      map[string]string // source id -> service name assigned at enrollment
	rejectReasons map[string]int
	rejectDetails []string
	policyFetch   int
}

// New starts a fake core. Group is the group assigned at enrollment.
func New(tb testing.TB, group string) *Core {
	tb.Helper()
	c := &Core{tb: tb, Group: group, ClientCertTTL: 24 * time.Hour, revoked: map[string]bool{}, services: map[string]string{}}
	c.hbResp = sourceclient.HeartbeatResponse{NextHeartbeatS: 1}
	var err error
	seed := make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		tb.Fatal(err)
	}
	c.signPriv = ed25519.NewKeyFromSeed(seed)
	c.signPub = c.signPriv.Public().(ed25519.PublicKey)

	c.rootKey = genKey(tb)
	c.rootCert = issue(tb, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tt test root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
	}, nil, &c.rootKey.PublicKey, c.rootKey)
	c.rootDER = c.rootCert.Raw
	c.interKey = genKey(tb)
	c.interCert = issue(tb, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tt test intermediate"},
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour),
	}, c.rootCert, &c.interKey.PublicKey, c.rootKey)
	leafKey := genKey(tb)
	leaf := issue(tb, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "tt-core.test"},
		DNSNames: []string{"localhost", "tt-core.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	}, c.interCert, &leafKey.PublicKey, c.interKey)

	secret := make([]byte, 24)
	_, _ = rand.Read(secret)
	c.Token = "tte_" + base64.RawURLEncoding.EncodeToString(secret) + "." + sourceclient.PinOf(c.rootDER)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(c.rootCert)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fleet/v1/enroll", c.handleEnroll)
	mux.HandleFunc("GET /fleet/v1/policy", c.mtls(c.handlePolicy))
	mux.HandleFunc("POST /fleet/v1/heartbeat", c.mtls(c.handleHeartbeat))
	mux.HandleFunc("POST /fleet/v1/renew", c.mtls(c.handleRenew))
	mux.HandleFunc("POST /v1/logs", c.mtls(c.handleLogs))
	c.Server = httptest.NewUnstartedServer(mux)
	c.Server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			// The chain presented includes the root, as the Fleet API requires.
			Certificate: [][]byte{leaf.Raw, c.interCert.Raw, c.rootDER}, PrivateKey: leafKey,
		}},
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCAs,
	}
	c.Server.StartTLS()
	c.URL = c.Server.URL
	tb.Cleanup(c.Server.Close)
	return c
}

func genKey(tb testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func issue(tb testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// SigningPublicKey returns the initial policy signing key as the Fleet API
// advertises it.
func (c *Core) SigningPublicKey() sourceclient.SigningKey {
	return sourceclient.SigningKey{Kid: SigningKid, Alg: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(c.signPub)}
}

// SigningPrivateKey lets a test sign envelopes (or endorse new keys) itself.
func (c *Core) SigningPrivateKey() ed25519.PrivateKey { return c.signPriv }

// ForeignKey returns an unrelated key pair, to build policies that must be
// rejected.
func ForeignKey() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

// Compile compiles an author policy (JSON) for the core's group and signs it
// with the core's key.
func (c *Core) Compile(authorJSON string, version, issuedSeq int64) []byte {
	c.tb.Helper()
	return c.CompileWith(authorJSON, policy.CompileMeta{Version: version, IssuedSeq: issuedSeq, CreatedAt: time.Now(), Groups: []string{c.Group}}, SigningKid, c.signPriv)
}

// CompileWith is Compile with explicit metadata and signer.
func (c *Core) CompileWith(authorJSON string, meta policy.CompileMeta, kid string, priv ed25519.PrivateKey) []byte {
	c.tb.Helper()
	dec := json.NewDecoder(strings.NewReader(authorJSON))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		c.tb.Fatal(err)
	}
	a, err := policy.AuthorFromGeneric(doc)
	if err != nil {
		c.tb.Fatal(err)
	}
	body, _, err := policy.Compile(a, meta)
	if err != nil {
		c.tb.Fatal(err)
	}
	env, err := policy.Sign(body, kid, priv)
	if err != nil {
		c.tb.Fatal(err)
	}
	return env
}

// SetPolicy makes the core serve this envelope (nil: 404, no policy).
func (c *Core) SetPolicy(envelope []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.envelope = envelope
	c.envHash = ""
	if envelope != nil {
		var e struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(envelope, &e)
		c.envHash = e.Hash
	}
}

// SetHeartbeatResponse sets the fixed heartbeat answer (NextHeartbeatS
// defaults to 1 second).
func (c *Core) SetHeartbeatResponse(f func(*sourceclient.HeartbeatResponse)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(&c.hbResp)
}

// Kill sets the kill switch.
func (c *Core) Kill(on bool) {
	c.SetHeartbeatResponse(func(r *sourceclient.HeartbeatResponse) { r.Kill = on })
}

// RevokeSource makes every call of this source answer 403.
func (c *Core) RevokeSource(id string, on bool) {
	c.mu.Lock()
	c.revoked[id] = on
	c.mu.Unlock()
}

// FailLogs makes the next n intake requests answer status (with Retry-After).
func (c *Core) FailLogs(n, status int, retryAfter string) {
	c.mu.Lock()
	c.logsFailN, c.logsFailSt, c.logsRetry = n, status, retryAfter
	c.mu.Unlock()
}

// BlockLogs makes the intake wait on ch before answering (nil: stop).
func (c *Core) BlockLogs(ch chan struct{}) {
	c.mu.Lock()
	c.logsBlock = ch
	c.mu.Unlock()
}

// RejectLogs makes the intake report n rejected log records per batch
// (partialSuccess).
func (c *Core) RejectLogs(n int) {
	c.mu.Lock()
	c.logsReject = n
	c.mu.Unlock()
}

// Events returns the canonical event strings received so far.
func (c *Core) Events() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.events...)
}

// Batches returns the number of accepted OTLP requests.
func (c *Core) Batches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.batches
}

// Heartbeats returns the heartbeats received so far.
func (c *Core) Heartbeats() []sourceclient.Heartbeat {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sourceclient.Heartbeat(nil), c.heartbeats...)
}

// Enrollments returns how many enrollments succeeded.
func (c *Core) Enrollments() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enrolls
}

// Renewals returns how many certificate renewals succeeded.
func (c *Core) Renewals() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renews
}

// PolicyFetches returns the number of GET /fleet/v1/policy calls.
func (c *Core) PolicyFetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policyFetch
}

// WaitEvents waits until at least n events arrived.
func (c *Core) WaitEvents(n int, d time.Duration) [][]byte {
	c.tb.Helper()
	deadline := time.Now().Add(d)
	for {
		if ev := c.Events(); len(ev) >= n {
			return ev
		}
		if time.Now().After(deadline) {
			c.tb.Fatalf("fakecore: %d events after %v, wanted %d", len(c.Events()), d, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Eventually polls f until it is true.
func (c *Core) Eventually(d time.Duration, what string, f func() bool) {
	c.tb.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			c.tb.Fatalf("fakecore: timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- handlers ----

func (c *Core) sourceID(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	for _, d := range r.TLS.PeerCertificates[0].DNSNames {
		if strings.HasPrefix(d, "src-") {
			return d, true
		}
	}
	return "", false
}

func (c *Core) mtls(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := c.sourceID(r)
		if !ok {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		c.mu.Lock()
		rev := c.revoked[id]
		c.mu.Unlock()
		if rev {
			http.Error(w, "revoked", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

type enrollReq struct {
	Token  string                  `json:"token"`
	CSR    string                  `json:"csr"`
	Source sourceclient.SourceInfo `json:"source"`
}

func (c *Core) signClient(pub any, id string) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: id},
		DNSNames: []string{id}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(c.ClientCertTTL),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.interCert, pub, c.interKey)
	if err != nil {
		c.tb.Error(err)
		return nil
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func (c *Core) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Token != c.Token {
		http.Error(w, `{"code":"token","message":"unknown token"}`, http.StatusUnauthorized)
		return
	}
	blk, _ := pem.Decode([]byte(req.CSR))
	if blk == nil {
		http.Error(w, "csr required", http.StatusUnprocessableEntity)
		return
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "bad csr", http.StatusUnprocessableEntity)
		return
	}
	c.mu.Lock()
	c.nextID++
	id := fmt.Sprintf("src-TEST%04d", c.nextID)
	c.services[id] = req.Source.ServiceName
	c.enrolls++
	c.mu.Unlock()
	cert := c.signClient(csr.PublicKey, id)
	if cert == nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	chainPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.interCert.Raw})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootDER}))
	resp := map[string]any{
		"source_id": id, "group": c.Group, "service_name": req.Source.ServiceName,
		"client_cert":         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		"ca_chain":            chainPEM,
		"not_after":           cert.NotAfter.UTC().Format(time.RFC3339),
		"policy_signing_keys": []sourceclient.SigningKey{c.SigningPublicKey()},
		"intake_url":          c.URL + "/v1/logs", "fleet_url": c.URL,
		"policy_max_age_s": 86400, "heartbeat_interval_s": 1, "policy_poll_interval_s": 1,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *Core) handlePolicy(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.policyFetch++
	env, hash := c.envelope, c.envHash
	c.mu.Unlock()
	if env == nil {
		http.Error(w, "no policy", http.StatusNotFound)
		return
	}
	etag := `"` + hash + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(env)
}

func (c *Core) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb sourceclient.Heartbeat
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.heartbeats = append(c.heartbeats, hb)
	resp := c.hbResp
	if c.envHash != "" && resp.PolicyCurrent == nil {
		var e struct {
			PolicyID  string `json:"policy_id"`
			Version   int64  `json:"version"`
			IssuedSeq int64  `json:"issued_seq"`
		}
		_ = json.Unmarshal(c.envelope, &e)
		resp.PolicyCurrent = &sourceclient.PolicyCurrent{PolicyID: e.PolicyID, Version: e.Version, IssuedSeq: e.IssuedSeq, Hash: c.envHash}
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *Core) handleRenew(w http.ResponseWriter, r *http.Request) {
	id, _ := c.sourceID(r)
	var req struct {
		CSR string `json:"csr"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
	blk, _ := pem.Decode([]byte(req.CSR))
	if blk == nil {
		http.Error(w, "csr required", http.StatusUnprocessableEntity)
		return
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		http.Error(w, "bad csr", http.StatusUnprocessableEntity)
		return
	}
	cert := c.signClient(csr.PublicKey, id)
	c.mu.Lock()
	c.renews++
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"client_cert": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		"not_after":   cert.NotAfter.UTC().Format(time.RFC3339),
	})
}

func (c *Core) handleLogs(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	block := c.logsBlock
	failN, failSt, retry := c.logsFailN, c.logsFailSt, c.logsRetry
	if failN > 0 {
		c.logsFailN--
	}
	reject := c.logsReject
	c.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-r.Context().Done():
			return
		}
	}
	if failN > 0 {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		http.Error(w, "injected failure", failSt)
		return
	}
	var rd io.Reader = io.LimitReader(r.Body, 8<<20)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(rd)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		rd = io.LimitReader(zr, 32<<20)
	}
	raw, _ := io.ReadAll(rd)
	id, _ := c.sourceID(r)
	c.mu.Lock()
	service := c.services[id]
	c.mu.Unlock()
	// The checks of the real intake that need no state (internal/intake
	// ValidateBatch): request and record shape, event schema and canonical
	// bytes, source identity, agreement of the OTLP envelope with the event
	// (resource attributes, ids, timeUnixNano). An exporter bug the real core
	// rejects fails here too.
	accepted, rejects, err := intake.ValidateBatch(raw, intake.SourceInfo{ID: id, ServiceName: service})
	if err != nil {
		http.Error(w, "the body is not a valid OTLP logs request", http.StatusBadRequest)
		return
	}
	evs := make([][]byte, 0, len(accepted))
	for _, a := range accepted {
		evs = append(evs, a.Event)
	}
	c.mu.Lock()
	c.events = append(c.events, evs...)
	c.batches++
	for _, rj := range rejects {
		if c.rejectReasons == nil {
			c.rejectReasons = map[string]int{}
		}
		c.rejectReasons[rj.Reason.String()]++
		c.rejectDetails = append(c.rejectDetails, rj.Reason.String()+": "+rj.Detail)
	}
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if n := reject + len(rejects); n > 0 {
		_, _ = fmt.Fprintf(w, `{"partialSuccess":{"rejectedLogRecords":"%d"}}`, n)
		return
	}
	_, _ = w.Write([]byte("{}"))
}

// RejectedByIntake returns, by intake reason code, the records the fake
// refused because the real intake checks would refuse them (never the
// records the test injected with RejectLogs).
func (c *Core) RejectedByIntake() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.rejectReasons))
	for k, v := range c.rejectReasons {
		out[k] = v
	}
	return out
}

// RejectDetails lists the reason and detail of every record refused by the
// intake checks, for failure messages.
func (c *Core) RejectDetails() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.rejectDetails...)
}

// PinOfRoot returns the pin of the core's root (the part after the dot in
// Token).
func (c *Core) PinOfRoot() string {
	sum := sha256.Sum256(c.rootDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TokenWithPin returns a syntactically valid token carrying another pin.
func TokenWithPin(pin string) string {
	return "tte_" + strings.Repeat("A", 32) + "." + pin
}

// EndorseNewKey returns an add_signing_keys entry for a new key endorsed by
// the core's initial key.
func (c *Core) EndorseNewKey(kid string) (sourceclient.AddSigningKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return sourceclient.AddSigningKey{
		Kid: kid, Alg: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		EndorsedBy: SigningKid, Endorsement: policy.Endorse(c.signPriv, kid, pub),
	}, priv
}
