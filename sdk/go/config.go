package ttsdk

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variables read by ConfigFromEnv (same names as the other SDKs).
const (
	EnvEnrollURL       = "TT_ENROLL_URL"
	EnvEnrollToken     = "TT_ENROLL_TOKEN"
	EnvHMACKey         = "TT_HMAC_KEY"
	EnvHMACKeyFile     = "TT_HMAC_KEY_FILE"
	EnvServiceName     = "TT_SERVICE_NAME"
	EnvOTelServiceName = "OTEL_SERVICE_NAME"
	EnvStateDir        = "TT_STATE_DIR"
	EnvDisabled        = "TT_DISABLED"
	EnvDebug           = "TT_DEBUG"
	EnvHeartbeatMS     = "TT_HEARTBEAT_INTERVAL_MS"
	EnvPolicyPollMS    = "TT_POLICY_POLL_INTERVAL_MS"
	EnvExportFlushMS   = "TT_EXPORT_FLUSH_MS"
)

// TraceContextFunc returns the identifiers of the span that is active in ctx
// (32 and 16 lower-case hex digits). It is how an OpenTelemetry-aware
// application lets the SDK read, never create or change, the current span;
// see the otelctx module. ok is false when there is no valid active span.
type TraceContextFunc func(ctx context.Context) (traceID, spanID string, ok bool)

// Config configures an Agent. The zero value is an inert agent: with no
// EnrollURL (or Disabled) nothing is started and nothing is captured.
type Config struct {
	// EnrollURL and EnrollToken enroll the source with tt-core (token
	// "tte_<secret>.<CA pin>"). The token is only needed until the first
	// enrollment succeeds.
	EnrollURL   string
	EnrollToken string
	// ServiceName is the service name requested at enrollment (the one used
	// in events is the one tt-core assigns).
	ServiceName string
	// StateDir keeps the enrollment, the client key and the policy cache
	// (default ~/.traffic-twin/<id>, directory 0700, files 0600).
	StateDir string

	// HMACKeys is the content of TT_HMAC_KEY: lines "<kid>:<base64url>".
	// HMACKeyFile names a file with the same format. Both empty: the
	// agent reads TT_HMAC_KEY and TT_HMAC_KEY_FILE from the environment.
	// Without a usable key nothing is captured (key_missing).
	HMACKeys    string
	HMACKeyFile string

	// Disabled makes the agent inert.
	Disabled bool
	// Debug logs status codes and error classes (never values) to stderr when
	// Logger is nil.
	Debug  bool
	Logger *slog.Logger

	// TraceContext, when set, reads the active span of a context (see the
	// otelctx module). traceparent request headers are always read.
	TraceContext TraceContextFunc

	// Instance names this process in the source list (default hostname).
	Instance string

	// Capture bounds. When any bound is hit whole events are dropped and
	// counted; requests are never held back.
	Workers         int   // sanitizer workers (default min(4, GOMAXPROCS))
	QueueSize       int   // finished exchanges waiting for a worker (default 1024)
	MaxPendingBytes int64 // copied body bytes waiting or being sanitized (default 64 MiB)
	MaxInflight     int   // exchanges whose bodies are being copied at once (default 512)

	// Intervals override the ones given by tt-core (tests, TT_*_MS).
	HeartbeatInterval  time.Duration
	PolicyPollInterval time.Duration
	ExportFlushEvery   time.Duration
}

// ConfigFromEnv builds a Config from the TT_* variables.
//
//	TT_ENROLL_URL, TT_ENROLL_TOKEN     enrollment
//	TT_HMAC_KEY / TT_HMAC_KEY_FILE     local HMAC keys
//	TT_SERVICE_NAME                    (else OTEL_SERVICE_NAME, lower-cased)
//	TT_STATE_DIR                       local state
//	TT_DISABLED=1                      inert SDK
//	TT_DEBUG=1                         status codes on stderr
//	TT_HEARTBEAT_INTERVAL_MS, TT_POLICY_POLL_INTERVAL_MS, TT_EXPORT_FLUSH_MS   tests only
func ConfigFromEnv() Config {
	c := Config{
		EnrollURL:   strings.TrimSpace(os.Getenv(EnvEnrollURL)),
		EnrollToken: strings.TrimSpace(os.Getenv(EnvEnrollToken)),
		ServiceName: strings.TrimSpace(os.Getenv(EnvServiceName)),
		StateDir:    os.Getenv(EnvStateDir),
		HMACKeys:    os.Getenv(EnvHMACKey),
		HMACKeyFile: os.Getenv(EnvHMACKeyFile),
		Disabled:    truthy(os.Getenv(EnvDisabled)),
		Debug:       truthy(os.Getenv(EnvDebug)),

		HeartbeatInterval:  envMS(EnvHeartbeatMS),
		PolicyPollInterval: envMS(EnvPolicyPollMS),
		ExportFlushEvery:   envMS(EnvExportFlushMS),
	}
	if c.ServiceName == "" {
		c.ServiceName = strings.ToLower(strings.TrimSpace(os.Getenv(EnvOTelServiceName)))
	}
	return c
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envMS(name string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Millisecond
}
