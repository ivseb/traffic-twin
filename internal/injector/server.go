package injector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// MaxReviewBytes bounds the AdmissionReview body (pods are far smaller; the
// API server itself caps objects at 3 MiB).
const MaxReviewBytes = 4 << 20

// Handler returns the HTTP handler: POST /mutate, GET /healthz, GET /readyz.
func Handler(m *Mutator, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /mutate", func(w http.ResponseWriter, r *http.Request) {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxReviewBytes))
		if err != nil {
			http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		var in AdmissionReview
		if err := json.Unmarshal(body, &in); err != nil || in.Request == nil {
			http.Error(w, "not an AdmissionReview", http.StatusBadRequest)
			return
		}
		if in.APIVersion != "admission.k8s.io/v1" {
			http.Error(w, "only admission.k8s.io/v1 is supported", http.StatusBadRequest)
			return
		}
		out, oc := m.Review(&in)
		// Names only: never the pod's env, command or image.
		logger.Info("admission", "namespace", oc.Namespace, "pod", oc.Pod, "language", oc.Language,
			"result", oc.Result, "reason", oc.Reason)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	return mux
}

// certReloader serves the certificate from files and re-reads them when the
// modification time changes (cert-manager and Helm rotate the Secret in place).
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	certMod, keyMod   time.Time
	checked           time.Time
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && time.Since(c.checked) < 30*time.Second {
		return c.cert, nil
	}
	c.checked = time.Now()
	cs, err1 := os.Stat(c.certFile)
	ks, err2 := os.Stat(c.keyFile)
	if err1 != nil || err2 != nil {
		if c.cert != nil {
			return c.cert, nil // keep serving the last good certificate
		}
		return nil, errors.Join(err1, err2)
	}
	if c.cert != nil && cs.ModTime().Equal(c.certMod) && ks.ModTime().Equal(c.keyMod) {
		return c.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.certMod, c.keyMod = &pair, cs.ModTime(), ks.ModTime()
	return c.cert, nil
}

// Serve serves the webhook over TLS on ln until ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, certFile, keyFile string, h http.Handler) error {
	rl := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := rl.get(nil); err != nil {
		return fmt.Errorf("injector: tls: %w", err)
	}
	srv := &http.Server{
		Handler:           h,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: rl.get},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		return nil
	}
}
