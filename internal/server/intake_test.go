package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePair(t *testing.T, dir, name string, c tls.Certificate) (string, string) {
	t.Helper()
	kb, _ := x509.MarshalECPrivateKey(c.PrivateKey.(*ecdsa.PrivateKey))
	cp, kp := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cp, kp
}

type running struct {
	adminAddr, intakeAddr string
	cancel                context.CancelFunc
	done                  chan error
}

func start(t *testing.T, hs *harness) *running {
	t.Helper()
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	intakeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	if hs.cfg.Intake.Addr == "" {
		_ = intakeLn.Close()
		intakeLn = nil
	}
	rn := &running{adminAddr: adminLn.Addr().String(), intakeAddr: addrOf(intakeLn), cancel: cancel, done: done}
	go func() { done <- hs.srv.Serve(ctx, adminLn, intakeLn) }()
	t.Cleanup(func() { rn.stop(t) })
	return rn
}

func (rn *running) stop(t *testing.T) {
	t.Helper()
	if rn.cancel == nil {
		return
	}
	rn.cancel()
	rn.cancel = nil
	select {
	case err := <-rn.done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func client(serverCA *testCA, cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(serverCA.cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func get(t *testing.T, c *http.Client, url string) (int, string, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestIntakeMTLS(t *testing.T) {
	dir := t.TempDir()
	serverCA := newCA(t, "tt-core server CA")
	sourcesCA := newCA(t, "tt sources CA")
	rogueCA := newCA(t, "rogue CA")
	certFile, keyFile := writePair(t, dir, "intake", serverCA.issue(t, "tt-core", true))
	caFile := filepath.Join(dir, "sources-ca.pem")
	_ = os.WriteFile(caFile, sourcesCA.pem, 0o600)

	hs := newHarness(t, func(c *config.Config) {
		c.Intake.Addr = "127.0.0.1:4318" // replaced by the test listener
		c.Intake.TLS = config.IntakeTLS{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile}
	})
	hs.srv.MountIntake("/v1/logs", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("source:" + PeerCertificate(r).Subject.CommonName))
	}))
	hs.srv.MountIntake("/fleet/v1/enroll", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("enroll"))
	}), AllowNoClientCert())
	hs.srv.SetIntakeTLS(IntakeTLSHooks{VerifyPeer: func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if leaf.Subject.CommonName == "src-revoked" {
			return errors.New("revoked")
		}
		return nil
	}})
	rn := start(t, hs)
	base := "https://" + rn.intakeAddr

	good := sourcesCA.issue(t, "src-01JB7Q2W", false)
	code, body, err := get(t, client(serverCA, &good), base+"/v1/logs")
	if err != nil || code != http.StatusOK || body != "source:src-01JB7Q2W" {
		t.Fatalf("with client cert: %d %q %v", code, body, err)
	}
	code, _, err = get(t, client(serverCA, nil), base+"/v1/logs")
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("without client cert: %d %v", code, err)
	}
	code, body, err = get(t, client(serverCA, nil), base+"/fleet/v1/enroll")
	if err != nil || code != http.StatusOK || body != "enroll" {
		t.Fatalf("enroll without cert: %d %q %v", code, body, err)
	}
	code, _, err = get(t, client(serverCA, nil), base+"/healthz")
	if err != nil || code != http.StatusOK {
		t.Fatalf("intake healthz: %d %v", code, err)
	}
	rogue := rogueCA.issue(t, "src-rogue", false)
	// The Go client withholds a certificate that does not chain to the CAs
	// the server advertises, so the request arrives without one (403); a
	// client that sends it anyway fails the handshake. Either way: refused.
	if code, _, err := get(t, client(serverCA, &rogue), base+"/v1/logs"); err == nil && code != http.StatusForbidden {
		t.Fatalf("certificate from an unknown CA accepted: %d", code)
	}
	forced := client(serverCA, nil)
	forced.Transport.(*http.Transport).TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &rogue, nil
	}
	if _, _, err := get(t, forced, base+"/v1/logs"); err == nil {
		t.Fatal("forced certificate from an unknown CA accepted")
	}
	revoked := sourcesCA.issue(t, "src-revoked", false)
	if _, _, err := get(t, client(serverCA, &revoked), base+"/v1/logs"); err == nil {
		t.Fatal("VerifyPeer hook not enforced")
	}
	// Plaintext is refused on the intake.
	if _, _, err := get(t, &http.Client{Timeout: 2 * time.Second}, "http://"+rn.intakeAddr+"/healthz"); err == nil {
		code, _, _ := get(t, &http.Client{Timeout: 2 * time.Second}, "http://"+rn.intakeAddr+"/healthz")
		if code == http.StatusOK {
			t.Fatal("plaintext request served by the intake")
		}
	}

	// Admin listener is up (plaintext loopback) and shuts down gracefully.
	code, _, err = get(t, &http.Client{Timeout: 2 * time.Second}, "http://"+rn.adminAddr+"/healthz")
	if err != nil || code != http.StatusOK {
		t.Fatalf("admin healthz: %d %v", code, err)
	}
	rn.stop(t)
	if _, _, err := get(t, &http.Client{Timeout: time.Second}, "http://"+rn.adminAddr+"/healthz"); err == nil {
		t.Fatal("admin still serving after shutdown")
	}
}

func TestIntakeManagedCertAndCAHook(t *testing.T) {
	serverCA := newCA(t, "managed CA")
	sourcesCA := newCA(t, "rotating sources CA")
	srvCert := serverCA.issue(t, "tt-core", true)
	hs := newHarness(t, func(c *config.Config) {
		c.Intake.Addr = "127.0.0.1:4318"
		c.Intake.TLS = config.IntakeTLS{Managed: true}
	})
	pool := x509.NewCertPool()
	pool.AddCert(sourcesCA.cert)
	hs.srv.SetIntakeTLS(IntakeTLSHooks{
		ClientCAs:      func() *x509.CertPool { return pool },
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
	})
	hs.srv.MountIntake("/v1/logs", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	rn := start(t, hs)
	cert := sourcesCA.issue(t, "src-1", false)
	code, _, err := get(t, client(serverCA, &cert), "https://"+rn.intakeAddr+"/v1/logs")
	if err != nil || code != http.StatusOK {
		t.Fatalf("managed: %d %v", code, err)
	}
}

func TestIntakeManagedWithoutProviderFails(t *testing.T) {
	hs := newHarness(t, func(c *config.Config) {
		c.Intake.Addr = "127.0.0.1:4318"
		c.Intake.TLS = config.IntakeTLS{Managed: true}
	})
	a, _ := net.Listen("tcp", "127.0.0.1:0")
	i, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := hs.srv.Serve(context.Background(), a, i); err == nil {
		t.Fatal("managed intake without certificate provider started")
	}
}

func TestAdminTLS(t *testing.T) {
	dir := t.TempDir()
	ca := newCA(t, "admin CA")
	certFile, keyFile := writePair(t, dir, "admin", ca.issue(t, "tt-core", true))
	hs := newHarness(t, func(c *config.Config) {
		c.Admin.TLS = config.TLSFiles{CertFile: certFile, KeyFile: keyFile}
	})
	rn := start(t, hs)
	resp, err := client(ca, nil).Get("https://" + rn.adminAddr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS over TLS")
	}
	// The session cookie uses the __Host- prefix over TLS.
	tok, _ := hs.svc.EnsureSetupToken(context.Background())
	req, _ := http.NewRequest("POST", "https://"+rn.adminAddr+"/api/v1/setup",
		strings.NewReader(`{"setup_token":"`+tok+`","username":"alice","password":"`+pw+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = client(ca, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-tt_session" && c.Secure && c.HttpOnly && c.SameSite == http.SameSiteStrictMode {
			found = true
		}
	}
	if !found {
		t.Fatalf("no __Host- session cookie: %v", resp.Header["Set-Cookie"])
	}
}
