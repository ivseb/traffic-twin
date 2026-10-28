package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/intake"
)

func TestEnrollmentOverTLSWithPin(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	nt := e.newToken(TokenOneTime, "sdk-node")
	if !reToken.MatchString(nt.Token) || tokenPin(nt.Token) != e.fleet.CAPin() {
		t.Fatalf("token shape: %q", nt.Token)
	}
	if len(nt.Snippets) == 0 || !strings.Contains(nt.Snippets[0].Text, nt.Token) {
		t.Fatalf("snippets do not carry the token: %+v", nt.Snippets)
	}
	kinds := map[string]bool{}
	for _, s := range nt.Snippets {
		kinds[s.Language] = true
		if strings.Contains(s.Text, "traffic-twin.io/inject: node") {
			kinds["k8s"] = true
		}
	}
	if !kinds["k8s"] || !kinds["bash"] {
		t.Fatalf("missing Kubernetes annotation or bash snippet: %+v", kinds)
	}

	// A client pinning another CA refuses the server before sending anything.
	bad := "tte_" + strings.Repeat("A", 43) + "." + strings.Repeat("B", 43)
	if _, err := e.enroll(bad, map[string]any{"source": srcInfo("sdk-node", "shop-api")}); err == nil {
		t.Fatal("handshake with a wrong pin must fail on the client")
	}

	s := e.enrollSource(nt.Token, "sdk-node", "shop-api")
	if !ValidSourceID(s.id) || s.enr.Group != "shop" || s.enr.ServiceName != "shop-api" || s.enr.ClientKey == "" {
		t.Fatalf("enrollment: %+v", s.enr)
	}
	if len(s.enr.PolicySigningKeys) != 1 || s.enr.PolicySigningKeys[0].Kid != "policy-2026-1" {
		t.Fatalf("signing keys: %+v", s.enr.PolicySigningKeys)
	}
	if s.enr.IntakeURL != "https://"+e.intake+"/v1/logs" || s.enr.HeartbeatIntervalS != 30 || s.enr.PolicyMaxAgeS != 86400 {
		t.Fatalf("urls/intervals: %+v", s.enr)
	}
	leaf := certPEMToX509(t, s.enr.ClientCert)
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != s.id || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("client certificate SAN/EKU: %v %v", leaf.DNSNames, leaf.ExtKeyUsage)
	}
	if id, ok := intake.SourceIDFromCert(leaf); !ok || id != s.id {
		t.Fatalf("intake does not read the source id: %q %v", id, ok)
	}
	if time.Until(leaf.NotAfter) > DefaultClientCertTTL+time.Minute {
		t.Fatalf("certificate too long-lived: %v", leaf.NotAfter)
	}
	// The generated key is never stored: neither in the DB nor in the CA dir.
	keyBody := strings.Split(strings.TrimSpace(s.enr.ClientKey), "\n")[1]
	dbBytes, _ := os.ReadFile(filepath.Join(e.dir, "tt.db"))
	walBytes, _ := os.ReadFile(filepath.Join(e.dir, "tt.db-wal"))
	if strings.Contains(string(dbBytes)+string(walBytes), keyBody) {
		t.Fatal("generated client key persisted")
	}

	// One-time token reuse.
	r, err := e.enroll(nt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api")})
	if err != nil || r.code != 401 || r.errCode() != "token_exhausted" {
		t.Fatalf("reuse: %v %d %s", err, r.code, r.body)
	}

	// Group token: many uses, CSR with Ed25519 key, no key returned.
	gt := e.newToken(TokenGroup, "sdk-node")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	for i := 0; i < 2; i++ {
		r, err = e.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api"), "csr": csr})
		if err != nil || r.code != 201 {
			t.Fatalf("group token use %d: %v %d %s", i, err, r.code, r.body)
		}
		var enr Enrollment
		r.json(t, &enr)
		if enr.ClientKey != "" || !certPEMToX509(t, enr.ClientCert).PublicKey.(ed25519.PublicKey).Equal(pub) {
			t.Fatal("CSR enrollment must certify the CSR key and return no key")
		}
	}

	// Errors: service not allowed (403), kind mismatch, bad CSR (422).
	r, _ = e.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "billing")})
	if r.code != 403 || r.errCode() != "service_not_allowed" {
		t.Fatalf("service: %d %s", r.code, r.body)
	}
	r, _ = e.enroll(gt.Token, map[string]any{"source": srcInfo("egress", "shop-api")})
	if r.code != 422 || r.errCode() != "kind_mismatch" {
		t.Fatalf("kind: %d %s", r.code, r.body)
	}
	r, _ = e.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api"), "csr": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"})
	if r.code != 422 || r.errCode() != "invalid_csr" {
		t.Fatalf("csr: %d %s", r.code, r.body)
	}
	r, _ = e.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api"), "extra": 1})
	if r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}

	// Revoked token.
	e.must(e.as("olivia", "DELETE", "/api/v1/fleet/enrollment-tokens/"+gt.TokenID, nil), 204)
	r, _ = e.enroll(gt.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api")})
	if r.code != 401 || r.errCode() != "token_revoked" {
		t.Fatalf("revoked: %d %s", r.code, r.body)
	}

	// Expired token.
	et := e.newToken(TokenOneTime, "sdk-node")
	e.clk.Add(2 * time.Hour)
	r, _ = e.enroll(et.Token, map[string]any{"source": srcInfo("sdk-node", "shop-api")})
	if r.code != 401 || r.errCode() != "token_expired" {
		t.Fatalf("expired: %d %s", r.code, r.body)
	}

	// Token expiry limits.
	e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-node", "group": "shop", "token_type": "one_time", "expires_in_s": 90000}), 422)
	e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-node", "group": "shop", "token_type": "group", "expires_in_s": 31536000}), 201)

	// Listing never returns secrets.
	list := e.must(e.as("olivia", "GET", "/api/v1/fleet/enrollment-tokens", nil), 200)
	if strings.Contains(string(list.body), nt.Token[4:20]) {
		t.Fatal("token secret listed")
	}
}

func TestRevokedCertRefusedAtTLS(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	s := e.enrollSource(e.newToken(TokenOneTime, "sdk-node").Token, "sdk-node", "shop-api")
	if _, r := s.heartbeat("starting", 0); r.code != 200 {
		t.Fatalf("heartbeat: %d %s", r.code, r.body)
	}
	// The intake registry sees the source.
	if v, ok := e.fleet.IntakeSources().LookupSource(s.id); !ok || v.Group != "shop" || v.ServiceName != "shop-api" || v.Revoked {
		t.Fatalf("intake view: %+v", v)
	}
	// Renewal (no CSR) gives a new certificate that works.
	r, err := s.do("POST", PathRenew, nil, nil)
	if err != nil || r.code != 200 {
		t.Fatalf("renew: %v %d %s", err, r.code, r.body)
	}
	var rn struct {
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}
	r.json(t, &rn)
	cert, err := tls.X509KeyPair([]byte(rn.ClientCert), []byte(rn.ClientKey))
	if err != nil {
		t.Fatal(err)
	}
	renewed := &source{e: e, id: s.id, client: e.httpClient(e.fleet.CAPin(), &cert)}
	if _, r := renewed.heartbeat("starting", 0); r.code != 200 {
		t.Fatalf("renewed heartbeat: %d", r.code)
	}

	e.must(e.as("olivia", "POST", "/api/v1/fleet/sources/"+s.id+"/revoke", nil), 204)
	for _, c := range []*source{s, renewed} {
		if _, err := c.do("POST", PathHeartbeat, map[string]any{"source_id": s.id}, nil); err == nil {
			t.Fatal("a revoked certificate must be refused during the TLS handshake")
		}
	}
	if v, _ := e.fleet.IntakeSources().LookupSource(s.id); !v.Revoked {
		t.Fatal("intake view not revoked")
	}
	// The hook itself.
	if err := e.fleet.verifyPeer(certPEMToX509(t, s.enr.ClientCert), nil); err != ErrRevokedCert {
		t.Fatalf("verifyPeer: %v", err)
	}
	// A certificate from another CA never reaches the hook (chain check),
	// and a cert with an unknown serial is refused by the hook.
	other, _ := e.fleet.ca.issueClient("src-unknown1", nil, time.Hour)
	if err := e.fleet.verifyPeer(certPEMToX509(t, other.CertPEM), nil); err != ErrUnknownCert {
		t.Fatalf("unknown serial: %v", err)
	}
	// Revocation survives a restart (reload from DB).
	if err := e.fleet.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.fleet.verifyPeer(certPEMToX509(t, rn.ClientCert), nil); err == nil {
		t.Fatal("revocation lost after reload")
	}
}

func TestCAPersistsAndKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	c1, err := loadOrCreateCA(dir, time.Now, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := loadOrCreateCA(dir, time.Now, nil)
	if err != nil || c1.pin != c2.pin {
		t.Fatalf("CA not reused: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dir, caKeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	_ = os.Chmod(filepath.Join(dir, caKeyFile), 0o644)
	if _, err := loadOrCreateCA(dir, time.Now, nil); err == nil {
		t.Fatal("world-readable CA key accepted")
	}
	sc, err := c1.serverCertificate()
	if err != nil || len(sc.Certificate) != 2 || pinOf(sc.Certificate[1]) != c1.pin {
		t.Fatal("server chain must include the pinned root")
	}
}

// A group created without service names takes the name of its first
// source; the next sources must use the same name.
func TestFirstEnrollmentSetsServiceName(t *testing.T) {
	e := newEnv(t, nil)
	e.user("olivia", "operator")
	e.must(e.as("olivia", "POST", "/api/v1/fleet/groups", map[string]any{"name": "fresh", "allowed_service_names": []string{}}), 201)
	tok := func() string {
		var nt NewToken
		e.must(e.as("olivia", "POST", "/api/v1/fleet/enrollment-tokens", map[string]any{"kind": "sdk-node", "group": "fresh", "token_type": "one_time"}), 201).json(t, &nt)
		return nt.Token
	}
	e.enrollSource(tok(), "sdk-node", "orders-api")
	var g Group
	e.must(e.as("olivia", "GET", "/api/v1/fleet/groups/fresh", nil), 200).json(t, &g)
	if len(g.AllowedServiceNames) != 1 || g.AllowedServiceNames[0] != "orders-api" {
		t.Fatalf("allowed names after the first enrollment: %v", g.AllowedServiceNames)
	}
	if r, _ := e.enroll(tok(), map[string]any{"source": srcInfo("sdk-node", "other-api")}); r.code != 403 || r.errCode() != "service_not_allowed" {
		t.Fatalf("second name: %d %s", r.code, r.body)
	}
	e.enrollSource(tok(), "sdk-node", "orders-api")
	if !strings.Contains(e.auditDump(), `"reason":"first_enrollment"`) {
		t.Fatal("the adopted name is not audited")
	}
}
