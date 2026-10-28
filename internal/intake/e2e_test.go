package intake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/store"
)

func writeCertPair(t *testing.T, dir, name string, c tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	kb, err := x509.MarshalECPrivateKey(c.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

// The intake mounted on the real core server: TLS with client certificates,
// the OTLP route, body limit of the listener.
func TestMountedOnTheCoreServer(t *testing.T) {
	dir := t.TempDir()
	serverCA, sourcesCA := newTestCA(t), newTestCA(t)
	srvCert, srvKey := writeCertPair(t, dir, "intake", serverCA.issue(t, "tt-core", nil, nil, true))
	caFile := filepath.Join(dir, "sources-ca.pem")
	_ = os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sourcesCA.cert.Raw}), 0o600)

	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "tt.db")
	cfg.Intake.Addr = "127.0.0.1:4318" // replaced by the test listener
	cfg.Intake.TLS = config.IntakeTLS{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: caFile}
	cfg.Keyguard.URL = "unix:///run/tt/keyguard.sock" // required by config since the core integration; not dialled here
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := store.Open(context.Background(), cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	al := audit.New(db)
	fast := auth.PasswordParams{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	svc, err := auth.New(db, al, auth.Options{IdleTimeout: time.Hour, AbsoluteTimeout: time.Hour, LocalEnabled: true, PasswordParams: &fast, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(cfg, server.Deps{Logger: logger, Auth: svc, Audit: al, DB: db})
	if err != nil {
		t.Fatal(err)
	}

	sources, policies := NewMemSourceRegistry(), NewMemPolicyRegistry()
	sources.Set(SourceInfo{ID: testSource, Group: testGroup, ServiceName: "shop-api", AllowedServices: []string{"shop-api"}})
	pol := mustPolicy(t, discoveryOn)
	policies.Add(pol)
	icfg := DefaultConfig()
	icfg.FlushInterval = time.Hour
	icfg.PurgeInterval = time.Hour
	in, err := New(context.Background(), icfg, Deps{DB: db, Sources: sources, Policies: policies, Audit: al, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close(context.Background())
	in.Mount(srv)

	adminLn, _ := net.Listen("tcp", "127.0.0.1:0")
	intakeLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, adminLn, intakeLn) }()
	defer func() {
		cancel()
		<-done
	}()

	pool := x509.NewCertPool()
	pool.AddCert(serverCA.cert)
	src := sourcesCA.issue(t, "ignored", []string{testSource}, nil, false)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{src}, MinVersion: tls.VersionTLS12}}}
	url := "https://" + intakeLn.Addr().String() + Path
	post := func(body []byte) (int, string) {
		resp, err := c.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, body := post(marshalOTLP(t, otlpFor(t, orderPost(pol.Hash), orderGet(pol.Hash)))); code != 200 || strings.TrimSpace(body) != "{}" {
		t.Fatalf("%d %s", code, body)
	}
	idle, cancelIdle := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelIdle()
	if err := in.WaitIdle(idle); err != nil {
		t.Fatal(err)
	}
	if n, _ := in.Store().Count(context.Background()); n != 2 {
		t.Fatalf("stored %d", n)
	}
	// A larger request (300 events) goes through the listener.
	pad := orderPost(pol.Hash)
	var recs []string
	for i := 0; i < 300; i++ {
		recs = append(recs, pad)
	}
	if code, body := post(marshalOTLP(t, otlpFor(t, recs...))); code != 200 {
		t.Fatalf("%d %s", code, body)
	}

	// Without a client certificate the route answers 403, and the handshake
	// itself refuses a certificate from another CA.
	noCert := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := noCert.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without a certificate: %d", resp.StatusCode)
	}
}
