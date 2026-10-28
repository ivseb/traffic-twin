package keyguard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SPKIPin returns the pin of a certificate: "sha256:" + lowercase hex of
// the SHA-256 of its SubjectPublicKeyInfo. It survives certificate renewal
// with the same key.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PinFromPEMFile reads a PEM certificate and returns its SPKI pin.
func PinFromPEMFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", errors.New("keyguard: not a PEM certificate")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", err
	}
	return SPKIPin(c), nil
}

func parsePin(p string) ([]byte, error) {
	h, ok := strings.CutPrefix(p, "sha256:")
	b, err := hex.DecodeString(h)
	if !ok || err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("keyguard: client pin %q is not sha256:<64 hex>", p)
	}
	return b, nil
}

// ServerTLSConfig returns the mTLS configuration: TLS 1.3 only, a client
// certificate required and accepted only when its SPKI matches a pin (and,
// when a client CA is configured, when it also chains to it with client
// auth usage). The server key file must not be accessible by group or
// others.
func ServerTLSConfig(c *Config, now func() time.Time) (*tls.Config, error) {
	keyPEM, err := ReadKeyFile(c.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("tls key: %w", err)
	}
	defer zero(keyPEM)
	certPEM, err := os.ReadFile(c.TLSCert)
	if err != nil {
		return nil, fmt.Errorf("keyguard: read tls certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("keyguard: tls certificate and key do not form a pair")
	}
	var pins [][]byte
	for _, p := range c.ClientPins {
		b, err := parsePin(p)
		if err != nil {
			return nil, err
		}
		pins = append(pins, b)
	}
	if len(pins) == 0 {
		return nil, errors.New("keyguard: no client pin configured")
	}
	var roots *x509.CertPool
	if c.ClientCA != "" {
		b, err := os.ReadFile(c.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("keyguard: read client CA: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("keyguard: client CA file has no certificate")
		}
	}
	if now == nil {
		now = time.Now
	}
	verify := func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("client certificate required")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return errors.New("bad client certificate")
		}
		t := now()
		if t.Before(leaf.NotBefore) || t.After(leaf.NotAfter) {
			return errors.New("client certificate expired or not yet valid")
		}
		sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		ok := 0
		for _, p := range pins {
			ok |= subtle.ConstantTimeCompare(sum[:], p)
		}
		if ok != 1 {
			return errors.New("client certificate is not pinned")
		}
		if roots != nil {
			inter := x509.NewCertPool()
			for _, r := range raw[1:] {
				if c, err := x509.ParseCertificate(r); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: t, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				return errors.New("client certificate does not chain to the client CA")
			}
		}
		return nil
	}
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verify,
	}, nil
}

// Listen opens the configured listener: a Unix socket (mode 0600 or 0660,
// created fresh) or a TCP listener wrapped in pinned mTLS. It returns the
// transport name for the status.
func Listen(c *Config, now func() time.Time) (net.Listener, string, error) {
	if err := c.ValidateListener(); err != nil {
		return nil, "", err
	}
	if c.Socket != "" {
		if st, err := os.Lstat(c.Socket); err == nil {
			if st.Mode()&os.ModeSocket == 0 {
				return nil, "", fmt.Errorf("keyguard: %s exists and is not a socket", c.Socket)
			}
			_ = os.Remove(c.Socket)
		}
		if err := os.MkdirAll(filepath.Dir(c.Socket), 0o700); err != nil {
			return nil, "", err
		}
		old := umask(0o177)
		ln, err := net.Listen("unix", c.Socket)
		umask(old)
		if err != nil {
			return nil, "", err
		}
		if err := os.Chmod(c.Socket, os.FileMode(c.SocketMode)); err != nil {
			ln.Close()
			return nil, "", err
		}
		return ln, "unix", nil
	}
	tc, err := ServerTLSConfig(c, now)
	if err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return nil, "", err
	}
	return tls.NewListener(ln, tc), "mtls", nil
}

// Serve serves the API on ln until ctx is cancelled, then shuts down
// gracefully.
func (s *Service) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := srv.Shutdown(sctx)
		<-errc
		return err
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
