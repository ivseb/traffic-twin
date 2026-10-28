package keyguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
	"github.com/ivseb/traffic-twin/internal/policy"
)

type certFiles struct{ cert, key string }

type testPKI struct {
	dir    string
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caFile string
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tt test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{dir: dir, caCert: ca, caKey: key, caFile: filepath.Join(dir, "ca.pem")}
	_ = os.WriteFile(p.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	return p
}

func (p *testPKI) issue(t *testing.T, name string, server bool) certFiles {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	f := certFiles{cert: filepath.Join(p.dir, name+".pem"), key: filepath.Join(p.dir, name+".key")}
	_ = os.WriteFile(f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	writeKeyFile(t, f.key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})))
	return f
}

func serve(t *testing.T, e *testEnv, cfg Config) string {
	t.Helper()
	ln, transport, err := Listen(&cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.transport = transport
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.svc.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

func TestIntegrationMTLS(t *testing.T) {
	pki := newPKI(t)
	srv := pki.issue(t, "keyguard", true)
	core := pki.issue(t, "tt-core", false)
	intruder := pki.issue(t, "intruder", false) // same CA, not pinned
	corePin, err := PinFromPEMFile(core.cert)
	if err != nil {
		t.Fatal(err)
	}
	srvPin, _ := PinFromPEMFile(srv.cert)

	e := newEnv(t, func(c *Config) { c.MatchInterval = 0; c.PackInterval = 0 })
	cfg := e.cfg
	cfg.Listen, cfg.TLSCert, cfg.TLSKey, cfg.ClientPins, cfg.ClientCA = "127.0.0.1:0", srv.cert, srv.key, []string{corePin}, pki.caFile
	addr := serve(t, e, cfg)
	ctx := context.Background()

	kc, err := client.New(client.Config{URL: "https://" + addr, ClientCert: core.cert, ClientKey: core.key, CA: pki.caFile, ServerPin: srvPin})
	if err != nil {
		t.Fatal(err)
	}
	defer kc.Close()
	if err := kc.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}

	// Unpinned client certificate, even from the same CA: refused.
	bad, _ := client.New(client.Config{URL: "https://" + addr, ClientCert: intruder.cert, ClientKey: intruder.key, CA: pki.caFile})
	if err := bad.Health(ctx); err == nil {
		t.Fatal("unpinned client accepted")
	}
	// Wrong server pin: the client refuses keyguard.
	wrong, _ := client.New(client.Config{URL: "https://" + addr, ClientCert: core.cert, ClientKey: core.key, ServerPin: corePin})
	if err := wrong.Health(ctx); err == nil {
		t.Fatal("wrong server pin accepted")
	}

	// Policy approval flow through the client.
	body := compileBody(t, bodyOpts{version: 7, seq: 1})
	if _, err := kc.SignPolicy(ctx, body, "alice", []client.Approval{{User: "alice", Roles: []string{"policy-approver"}, At: t0}}); err == nil {
		t.Fatal("one approval accepted for a first policy")
	} else if ce, ok := err.(*client.Error); !ok || ce.Status != 403 || ce.Code != "insufficient_approvals" {
		t.Fatalf("error %v", err)
	}
	sig, err := kc.SignPolicy(ctx, body, "alice", []client.Approval{
		{User: "alice", Roles: []string{"policy-approver"}, At: t0},
		{User: "bob", Roles: []string{"policy-approver"}, At: t0},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := sig.Envelope(body)
	if err != nil {
		t.Fatal(err)
	}
	pks, err := kc.PublicKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ring := policy.NewKeyRing()
	if err := ring.PinEncoded(pks.Policy[0].Kid, pks.Policy[0].Alg, pks.Policy[0].PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Accept(env, ring, "shop", t0, 0, 0); err != nil {
		t.Fatalf("source acceptance: %v", err)
	}

	// Token feed and match, numbers in canonical form.
	realTok := tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("ORD-2026-000184"))
	numTok := tokenFor(k1Secret(), "k1", "2026-10", "order", []byte("73.4"))
	if err := kc.AddTokens(ctx, "2026-10", []string{realTok, numTok}); err != nil {
		t.Fatal(err)
	}
	refs := []client.PolicyRef{{ID: "p-shop", Version: 7}}
	mr, err := kc.Match(ctx, refs, []client.Candidate{client.Str("ORD-2026-000184"), client.Num("73.40"), client.Str("ORD-2026-000185"), client.Num("73.41")})
	if err != nil {
		t.Fatal(err)
	}
	if !mr.Matches[0] || !mr.Matches[1] || mr.Matches[2] || mr.Matches[3] || mr.Positives != 2 {
		t.Fatalf("match %+v", mr)
	}

	// Pack signing.
	files, arc := demoPack(t, nil)
	pr, err := kc.SignPack(ctx, arc, &client.Approval{User: "pat", Roles: []string{"publisher"}, At: t0})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pack.ParseKeySet(pks.GatePubKeys())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pack.VerifySignature(files["manifest.json"], pr.Signature.SigFile(), keys); err != nil {
		t.Fatalf("pack.VerifySignature: %v", err)
	}
	// A real value in the pack: refused with findings.
	_, arc2 := demoPack(t, func(s *packtest.Spec) {
		s.Files["faults.json"] = []byte(strings.Replace(string(s.Files["faults.json"]), `"upstream-unavailable"`, `"ORD-2026-000184"`, 1))
	})
	_, err = kc.SignPack(ctx, arc2, nil)
	ce, ok := err.(*client.Error)
	if !ok || ce.Code != "reverse_hmac" || ce.ReverseHMAC == nil || len(ce.ReverseHMAC.Findings) == 0 || ce.ReverseHMAC.Findings[0].File != "faults.json" {
		t.Fatalf("pack with real value: %v", err)
	}

	// Renewal through the client.
	e.clock.Add(20 * 24 * time.Hour)
	renewed := compileBody(t, bodyOpts{version: 8, seq: 2, created: e.clock.Now()})
	if _, err := kc.RenewPolicy(ctx, renewed); err != nil {
		t.Fatalf("renew: %v", err)
	}

	st, err := kc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Transport != "mtls" || !st.ApprovalsUnverified || st.LastIssuedSeq != 2 || len(st.HMACKids) != 2 {
		t.Fatalf("status %+v", st)
	}
	entries, err := kc.Audit(ctx, 0)
	if err != nil || len(entries) < 6 {
		t.Fatalf("audit %d %v", len(entries), err)
	}
	if v, err := e.svc.VerifyAudit(ctx); err != nil || v.Entries != int64(len(entries)) {
		t.Fatalf("audit chain: %v", err)
	}

	// Nothing secret in logs, audit or status.
	auditJSON, _ := json.Marshal(entries)
	stJSON, _ := json.Marshal(st)
	secrets := map[string]string{
		"hmac k1":     b64(k1Secret()),
		"hmac k2":     b64(e.k2),
		"policy seed": b64(e.policySeed),
		"pack seed":   b64(e.packSeed),
		"real token":  realTok,
		"token mac":   strings.TrimPrefix(realTok, "tk1:k1:"),
		"candidate":   "ORD-2026-000184",
		"candidate2":  "73.40",
	}
	for what, s := range secrets {
		for where, text := range map[string]string{"logs": e.logs.String(), "audit": string(auditJSON), "status": string(stJSON)} {
			if strings.Contains(text, s) {
				t.Errorf("%s found in %s", what, where)
			}
		}
	}
	if !strings.Contains(e.logs.String(), "keyguard request") {
		t.Fatal("no access log written")
	}
}

func TestIntegrationUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "kg")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	e := newEnv(t, nil)
	cfg := e.cfg
	cfg.Socket = filepath.Join(dir, "kg.sock")
	serve(t, e, cfg)
	st, err := os.Stat(cfg.Socket)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v %v", st.Mode(), err)
	}
	kc, err := client.New(client.Config{URL: "unix://" + cfg.Socket})
	if err != nil {
		t.Fatal(err)
	}
	s, err := kc.Status(context.Background())
	if err != nil || s.Transport != "unix" {
		t.Fatalf("status %+v %v", s, err)
	}
	// Malformed requests get 400 with a fixed message.
	if err := kc.AddTokens(context.Background(), "2026-10", []string{"not-a-token"}); err == nil {
		t.Fatal("malformed token accepted")
	}
}

func TestListenerConfigRefusals(t *testing.T) {
	pki := newPKI(t)
	srv := pki.issue(t, "keyguard", true)
	c := DefaultConfig()
	c.Listen, c.TLSCert, c.TLSKey = "127.0.0.1:0", srv.cert, srv.key
	if _, _, err := Listen(&c, nil); err == nil {
		t.Fatal("mTLS without a client pin accepted")
	}
	c.ClientPins = []string{"sha256:" + strings.Repeat("ab", 32)}
	_ = os.Chmod(srv.key, 0o644)
	if _, _, err := Listen(&c, nil); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("world-readable TLS key accepted: %v", err)
	}
	c.Socket = "/tmp/x.sock"
	if err := c.ValidateListener(); err == nil {
		t.Fatal("both transports accepted")
	}
}
