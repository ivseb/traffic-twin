package fleet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// The Fleet CA is a single-level ECDSA P-256 root created at first start.
// It signs the managed intake server certificate and the short-lived source
// client certificates. Its private key lives in CADir (0600, directory
// 0700), never in the database, and is never returned by any API.

const (
	caCertFile = "fleet-ca.crt"
	caKeyFile  = "fleet-ca.key"

	caValidity         = 10 * 365 * 24 * time.Hour
	serverCertValidity = 30 * 24 * time.Hour
	clockSkew          = 5 * time.Minute
)

var reSourceID = regexp.MustCompile(`^src-[0-9A-Za-z]{1,32}$`)

// ValidSourceID reports whether s has the enrollment id form src-<alnum>.
func ValidSourceID(s string) bool { return reSourceID.MatchString(s) }

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pin  string // base64url(SHA-256(root DER)), no padding
	pool *x509.CertPool
	pem  []byte

	serverNames []string
	now         func() time.Time

	mu         sync.Mutex
	serverCert *tls.Certificate
	serverExp  time.Time
}

// pinOf returns the token pin of a certificate.
func pinOf(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// loadOrCreateCA loads the CA from dir, creating it on first start.
func loadOrCreateCA(dir string, now func() time.Time, serverNames []string) (*ca, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("fleet: ca dir: %w", err)
	}
	if st, err := os.Stat(dir); err == nil && st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("fleet: ca dir permissions: %w", err)
		}
	}
	certPath, keyPath := filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)
	_, errC := os.Stat(certPath)
	_, errK := os.Stat(keyPath)
	switch {
	case errors.Is(errC, fs.ErrNotExist) && errors.Is(errK, fs.ErrNotExist):
		if err := createCA(certPath, keyPath, now()); err != nil {
			return nil, err
		}
	case errC != nil || errK != nil:
		return nil, errors.New("fleet: CA certificate and key must both exist (or neither)")
	}
	st, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("fleet: %s must not be readable by group or others (chmod 600)", caKeyFile)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || cb.Type != "CERTIFICATE" || kb == nil || kb.Type != "PRIVATE KEY" {
		return nil, errors.New("fleet: malformed CA files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fleet: CA certificate: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fleet: CA key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) || !cert.IsCA {
		return nil, errors.New("fleet: CA key does not match the CA certificate")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &ca{
		cert: cert, key: key, pin: pinOf(cert.Raw), pool: pool,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		serverNames: serverNames, now: now,
	}, nil
}

func createCA(certPath, keyPath string, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	skid := sha256.Sum256(spki)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "traffic-twin fleet root CA", Organization: []string{"traffic-twin"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skid[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// Key first: a crash between the two writes leaves an orphan key, which
	// is reported at the next start instead of silently regenerating.
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// issuedCert is a freshly issued client certificate.
type issuedCert struct {
	CertPEM  string
	KeyPEM   string // only when the key was generated by tt-core
	Serial   string // lowercase hex
	NotAfter time.Time
}

// clientPublicKey extracts and checks the public key of a PEM CSR:
// Ed25519 or ECDSA P-256, valid self-signature.
func clientPublicKey(csrPEM string) (crypto.PublicKey, error) {
	b, rest := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || len(trimSpace(rest)) != 0 {
		return nil, errors.New("csr: expected one PEM CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, errors.New("csr: unparsable")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("csr: bad signature")
	}
	switch k := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return k, nil
		}
	}
	return nil, errors.New("csr: key must be Ed25519 or ECDSA P-256")
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// issueClient signs a client certificate for sourceID. With pub == nil a
// fresh ECDSA P-256 key is generated and returned (PKCS#8 PEM); tt-core
// never stores it.
func (c *ca) issueClient(sourceID string, pub crypto.PublicKey, ttl time.Duration) (issuedCert, error) {
	var out issuedCert
	if pub == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return out, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return out, err
		}
		out.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		pub = &k.PublicKey
	}
	serial, err := randomSerial()
	if err != nil {
		return out, err
	}
	now := c.now()
	notAfter := now.Add(ttl).UTC().Truncate(time.Second)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sourceID, Organization: []string{"traffic-twin source"}},
		DNSNames:     []string{sourceID},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, pub, c.key)
	if err != nil {
		return out, err
	}
	out.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	out.Serial = hex.EncodeToString(serial.Bytes())
	out.NotAfter = notAfter
	return out, nil
}

// serverCertificate returns the managed intake server certificate, chained
// to the root so sources can pin it (fleet-api: "tt-core MUST include the
// root certificate in the TLS chain it presents"). It is regenerated in
// memory when less than a third of its lifetime is left; its key is never
// written anywhere.
func (c *ca) serverCertificate() (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.serverCert != nil && now.Before(c.serverExp.Add(-serverCertValidity/3)) {
		return c.serverCert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tt-core intake"},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range c.serverNames {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c.serverCert = &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key, Leaf: leaf}
	c.serverExp = tmpl.NotAfter
	return c.serverCert, nil
}

// SourceIDFromCert returns the enrollment id in the SAN of a client
// certificate issued by Fleet: exactly one DNS name of the form src-<alnum>.
func SourceIDFromCert(cert *x509.Certificate) (string, bool) {
	if cert == nil || len(cert.DNSNames) != 1 || !ValidSourceID(cert.DNSNames[0]) {
		return "", false
	}
	return cert.DNSNames[0], true
}
