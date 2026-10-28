package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/keyguard"
)

// Key ids generated for single-host trials.
const (
	DevHMACKid   = "k1"
	DevPolicyKid = "policy-dev-1"
	DevPackKid   = "pack-dev-1"
)

// maxSocketPath is the portable bound of a Unix socket path (macOS: 104).
const maxSocketPath = 100

// DevKeyguard is a keyguard running in-process on a Unix socket, with keys
// generated on first start in <dir>/keys (mode 0600). It is the
// single-host trial layout (`tt dev up`, tests): production runs keyguard
// as a separate process on another host (docs/spec/keyguard.md).
type DevKeyguard struct {
	Service *keyguard.Service
	// Socket is the absolute path of the Unix socket; URL is unix://Socket.
	Socket, URL string
	// HMACKeyFile holds the HMAC key the sources need (TT_HMAC_KEY_FILE).
	HMACKeyFile string

	ln     net.Listener
	tmp    string // temporary socket directory, removed by Close
	cancel context.CancelFunc
	done   chan error
}

// DevKeyguardOptions configure StartDevKeyguard.
type DevKeyguardOptions struct {
	// Dir holds keys/, the keyguard database and (when short enough) the
	// socket.
	Dir    string
	Logger *slog.Logger
	// Now is keyguard's clock (tests).
	Now func() time.Time
	// Tune adjusts the configuration before start (tests).
	Tune func(*keyguard.Config)
}

// StartDevKeyguard generates missing keys, opens keyguard and serves it on
// a Unix socket until Close.
func StartDevKeyguard(ctx context.Context, o DevKeyguardOptions) (*DevKeyguard, error) {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return nil, err
	}
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		return nil, err
	}
	hmacFile := filepath.Join(keys, "hmac.keys")
	for _, k := range []struct{ file, kid string }{
		{hmacFile, DevHMACKid},
		{filepath.Join(keys, "policy.key"), DevPolicyKid},
		{filepath.Join(keys, "pack.key"), DevPackKid},
	} {
		if err := ensureKeyFile(k.file, k.kid); err != nil {
			return nil, err
		}
	}
	cfg := keyguard.DefaultConfig()
	cfg.DBPath = filepath.Join(dir, "tt-keyguard.db")
	cfg.HMACKeys = keyguard.KeySource{File: hmacFile}
	cfg.PolicyKey = keyguard.KeySource{File: filepath.Join(keys, "policy.key")}
	cfg.PackKey = keyguard.KeySource{File: filepath.Join(keys, "pack.key")}
	cfg.Socket = filepath.Join(dir, "keyguard.sock")
	var tmp string
	if len(cfg.Socket) > maxSocketPath {
		if tmp, err = os.MkdirTemp("", "ttkg"); err != nil {
			return nil, err
		}
		cfg.Socket = filepath.Join(tmp, "keyguard.sock")
	}
	cfg.LogLevel, cfg.LogFormat = "warn", "text"
	if o.Tune != nil {
		o.Tune(&cfg)
	}
	ln, transport, err := keyguard.Listen(&cfg, o.Now)
	if err != nil {
		return nil, err
	}
	logger := o.Logger
	if logger == nil {
		logger = keyguard.NewLogger(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	}
	svc, err := keyguard.New(ctx, cfg, keyguard.Options{Logger: logger, Now: o.Now, Transport: transport})
	if err != nil {
		ln.Close()
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	k := &DevKeyguard{Service: svc, Socket: cfg.Socket, URL: "unix://" + cfg.Socket, HMACKeyFile: hmacFile,
		ln: ln, tmp: tmp, cancel: cancel, done: make(chan error, 1)}
	go func() { k.done <- svc.Serve(sctx, ln) }()
	return k, nil
}

// Close stops keyguard and closes its database.
func (k *DevKeyguard) Close() error {
	k.cancel()
	err := <-k.done
	err = errors.Join(err, k.Service.Close())
	if k.tmp != "" {
		_ = os.RemoveAll(k.tmp)
	}
	return err
}

// ensureKeyFile writes "<kid>:<base64url 32 random bytes>" to a new file
// with mode 0600, unless the file exists.
func ensureKeyFile(path, kid string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "%s:%s\n", kid, base64.RawURLEncoding.EncodeToString(secret))
	clear(secret)
	return errors.Join(werr, f.Close())
}

// DevConfig returns the configuration of a single-host trial rooted at dir:
// admin UI on loopback with a self-signed certificate, intake on loopback
// with the Fleet-managed certificate, keyguard on the given Unix socket.
func DevConfig(dir, keyguardURL, adminAddr, intakeAddr string) (*config.Config, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	certFile, keyFile, err := LoopbackCert(filepath.Join(dir, "tls"))
	if err != nil {
		return nil, err
	}
	cfg := config.Default()
	cfg.Storage.Path = filepath.Join(dir, "tt-core.db")
	cfg.Admin.Addr = adminAddr
	cfg.Admin.TLS = config.TLSFiles{CertFile: certFile, KeyFile: keyFile}
	cfg.Intake.Addr = intakeAddr
	cfg.Keyguard.URL = keyguardURL
	cfg.Log.Format = "text"
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
