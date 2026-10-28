// Command mkpki writes a throwaway PKI for the Kubernetes end-to-end test
// (deploy/test/kind-e2e.sh): a CA, a server certificate for tt-core, one for
// keyguard and tt-core's client certificate for keyguard's mTLS.
//
//	go run ./deploy/test/mkpki -out DIR -core-dns a,b -keyguard-dns c,d
//
// Test fixture only. The keys are written with mode 0600.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "", "output directory")
	coreDNS := flag.String("core-dns", "", "comma separated DNS names of the tt-core server certificate")
	kgDNS := flag.String("keyguard-dns", "", "comma separated DNS names of the keyguard server certificate")
	flag.Parse()
	if *out == "" || *coreDNS == "" || *kgDNS == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*out, strings.Split(*coreDNS, ","), strings.Split(*kgDNS, ",")); err != nil {
		fmt.Fprintf(os.Stderr, "mkpki: %v\n", err)
		os.Exit(1)
	}
}

func run(dir string, coreDNS, kgDNS []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "tt-e2e-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER, 0o644); err != nil {
		return err
	}
	leaf := func(name, cn string, dns []string, usage x509.ExtKeyUsage) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		kb, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(dir, name+".crt"), "CERTIFICATE", der, 0o644); err != nil {
			return err
		}
		return writePEM(filepath.Join(dir, name+".key"), "EC PRIVATE KEY", kb, 0o600)
	}
	if err := leaf("core", "tt-core", coreDNS, x509.ExtKeyUsageServerAuth); err != nil {
		return err
	}
	if err := leaf("keyguard", "tt-keyguard", kgDNS, x509.ExtKeyUsageServerAuth); err != nil {
		return err
	}
	return leaf("core-client", "tt-core", nil, x509.ExtKeyUsageClientAuth)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	return n
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), mode)
}
