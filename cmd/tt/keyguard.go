package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ivseb/traffic-twin/internal/keyguard"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// keyEnvVars are cleared from the process environment once read, so child
// processes and later environment dumps do not see inline keys.
var keyEnvVars = []string{keyguard.EnvHMACKeys, keyguard.EnvPolicyKey, keyguard.EnvPackKey}

func runKeyguard(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "pin":
			return runKeyguardPin(args[1:], stdout, stderr)
		case "genkey":
			return runKeyguardGenkey(args[1:], stdout, stderr)
		}
	}
	fs := newFlagSet("keyguard", stderr)
	listen := fs.String("listen", "", "override "+keyguard.EnvListen+" (host:port, mTLS)")
	socket := fs.String("socket", "", "override "+keyguard.EnvSocket+" (Unix socket path)")
	db := fs.String("db", "", "override "+keyguard.EnvDB+" (default "+keyguard.DefaultDBPath+")")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: tt keyguard [flags]            run the key custodian (configuration from TT_KEYGUARD_* variables)")
		fmt.Fprintln(stderr, "       tt keyguard pin CERT.pem        print the sha256 SPKI pin of a certificate")
		fmt.Fprintln(stderr, "       tt keyguard genkey -type hmac|ed25519 -kid KID -out FILE")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	cfg, err := keyguard.ConfigFromEnv(os.Environ())
	for _, k := range keyEnvVars {
		_ = os.Unsetenv(k)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tt keyguard: %v\n", err)
		return 1
	}
	if *listen != "" {
		cfg.Listen, cfg.Socket = *listen, ""
	}
	if *socket != "" {
		cfg.Socket, cfg.Listen = *socket, ""
	}
	if *db != "" {
		cfg.DBPath = *db
	}
	logger := keyguard.NewLogger(stderr, cfg.LogLevel, cfg.LogFormat)
	ln, transport, err := keyguard.Listen(&cfg, nil)
	if err != nil {
		fmt.Fprintf(stderr, "tt keyguard: %v\n", err)
		return 1
	}
	svc, err := keyguard.New(ctx, cfg, keyguard.Options{Logger: logger, Transport: transport})
	if err != nil {
		_ = ln.Close()
		fmt.Fprintf(stderr, "tt keyguard: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "tt keyguard %s listening on %s (%s)\n", version, ln.Addr(), transport)
	if transport == "unix" {
		logger.Warn("keyguard on a Unix socket: same host as tt-core, allowed for test installations only")
	}
	serveErr := svc.Serve(ctx, ln)
	closeErr := svc.Close()
	if err := errors.Join(serveErr, closeErr); err != nil {
		fmt.Fprintf(stderr, "tt keyguard: %v\n", err)
		return 1
	}
	return 0
}

func runKeyguardPin(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("keyguard pin", stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "Usage: tt keyguard pin CERT.pem")
		return 2
	}
	pin, err := keyguard.PinFromPEMFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "tt keyguard pin: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, pin)
	return 0
}

// runKeyguardGenkey writes a new key line to a fresh file with mode 0600.
// The key is never printed; for ed25519 the public key is.
func runKeyguardGenkey(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("keyguard genkey", stderr)
	typ := fs.String("type", "", "hmac (32-byte HMAC key) or ed25519 (signing seed)")
	kid := fs.String("kid", "", "key id")
	out := fs.String("out", "", "output file (must not exist; created with mode 0600)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if *out == "" {
		fmt.Fprintln(stderr, "tt keyguard genkey: -out is required")
		return 2
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fmt.Fprintf(stderr, "tt keyguard genkey: %v\n", err)
		return 1
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	switch *typ {
	case "hmac":
		if !policy.ValidKid(*kid) {
			fmt.Fprintln(stderr, "tt keyguard genkey: hmac kid must match ^[a-z0-9]{1,8}$")
			return 2
		}
	case "ed25519":
		if !policy.ValidSigningKid(*kid) {
			fmt.Fprintln(stderr, "tt keyguard genkey: signing kid must match ^[A-Za-z0-9._-]{1,64}$")
			return 2
		}
	default:
		fmt.Fprintln(stderr, "tt keyguard genkey: -type must be hmac or ed25519")
		return 2
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "tt keyguard genkey: %v\n", err)
		return 1
	}
	line := []byte(*kid + ":" + base64.RawURLEncoding.EncodeToString(secret) + "\n")
	_, werr := f.Write(line)
	for i := range line {
		line[i] = 0
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintf(stderr, "tt keyguard genkey: %v\n", werr)
		return 1
	}
	if *typ == "ed25519" {
		priv := ed25519.NewKeyFromSeed(secret)
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Fprintf(stdout, "%s:%s\n", *kid, base64.RawURLEncoding.EncodeToString(pub))
		for i := range priv {
			priv[i] = 0
		}
	} else {
		fmt.Fprintf(stdout, "wrote hmac key %s to %s\n", *kid, *out)
	}
	return 0
}
