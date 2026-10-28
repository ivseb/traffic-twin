package egress

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

// AliasRE is the grammar of an upstream alias (the first path segment).
var AliasRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Upstream is one external service reachable through the proxy at
// /<Alias>/...
type Upstream struct {
	Alias string `yaml:"alias"`
	// URL is the base URL of the real service, for example
	// https://api.carrier.example or https://host/api. http is accepted for
	// services inside a trusted network.
	URL string `yaml:"url"`
	// CaptureOrigin is the scheme://host[:port] the sanitizer sees for this
	// service (docs/spec/sanitizer.md section 3.1). Default: the origin of
	// URL. Set it when the policy names the service with another origin than
	// the one the proxy dials (for example the demo, where the carrier is a
	// plain-http container that stands for https://api.carrier.example).
	CaptureOrigin string `yaml:"capture_origin"`
	// CAFile is an extra PEM CA, added to the system roots, for this upstream.
	CAFile string `yaml:"ca_file"`
}

// CaptureConfig bounds the capture pipeline. When any bound is hit events are
// dropped and counted; traffic is never held back.
type CaptureConfig struct {
	Workers         int   // sanitizer workers (default min(4, GOMAXPROCS))
	QueueSize       int   // completed exchanges waiting for a worker (default 1024)
	MaxPendingBytes int64 // bytes of copied bodies waiting or being sanitized (default 64 MiB)
	MaxInflight     int   // exchanges whose bodies are being copied at once (default 512)
}

// Config configures the proxy.
type Config struct {
	Upstreams []Upstream

	// AliasFromPolicy also routes /<service>/ to the base URL of every
	// external service of the accepted policy (explicit upstreams win).
	// Off by default: a policy decides what leaves, not where the credentials
	// of the application are sent.
	AliasFromPolicy bool

	// Per-upstream connection pools and timeouts.
	DialTimeout           time.Duration // default 5s
	TLSHandshakeTimeout   time.Duration // default 10s
	ResponseHeaderTimeout time.Duration // default 60s; 0 after defaults = none
	IdleConnTimeout       time.Duration // default 90s
	MaxIdleConnsPerHost   int           // default 64

	// ExtraCAPEM are extra trust anchors (PEM) for every upstream, added to
	// the system roots.
	ExtraCAPEM []byte

	Capture CaptureConfig

	// Source is the Fleet source. nil means proxy only: nothing is captured.
	Source *sourceclient.Source

	Logger *slog.Logger
	// Version is shown by the health endpoint.
	Version string

	// OnSanitize is a test hook called by a worker before it sanitizes.
	OnSanitize func()
}

func (c *Config) defaults() {
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.TLSHandshakeTimeout <= 0 {
		c.TLSHandshakeTimeout = 10 * time.Second
	}
	if c.ResponseHeaderTimeout == 0 {
		c.ResponseHeaderTimeout = 60 * time.Second
	}
	if c.IdleConnTimeout <= 0 {
		c.IdleConnTimeout = 90 * time.Second
	}
	if c.MaxIdleConnsPerHost <= 0 {
		c.MaxIdleConnsPerHost = 64
	}
	if c.Capture.QueueSize <= 0 {
		c.Capture.QueueSize = 1024
	}
	if c.Capture.MaxPendingBytes <= 0 {
		c.Capture.MaxPendingBytes = 64 << 20
	}
	if c.Capture.MaxInflight <= 0 {
		c.Capture.MaxInflight = 512
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
}

// parseTarget validates an upstream base URL.
func parseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid url")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("url must be http(s)://host[:port][/path]")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("url must not carry credentials, query or fragment")
	}
	return u, nil
}

// Validate checks the upstream list.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	for _, u := range c.Upstreams {
		if !AliasRE.MatchString(u.Alias) {
			return fmt.Errorf("upstream alias %q: must match %s", u.Alias, AliasRE)
		}
		if seen[u.Alias] {
			return fmt.Errorf("upstream alias %q defined twice", u.Alias)
		}
		seen[u.Alias] = true
		if _, err := parseTarget(u.URL); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Alias, err)
		}
		if u.CaptureOrigin != "" {
			o, err := url.Parse(u.CaptureOrigin)
			if err != nil || o.Scheme == "" || o.Host == "" || (o.Path != "" && o.Path != "/") || o.User != nil || o.RawQuery != "" {
				return fmt.Errorf("upstream %q: capture_origin must be scheme://host[:port]", u.Alias)
			}
		}
	}
	if len(c.Upstreams) == 0 && !c.AliasFromPolicy {
		return errors.New("no upstream configured (use --upstream alias=url, or alias_from_policy)")
	}
	return nil
}

// ParseUpstreamFlag parses "alias=URL".
func ParseUpstreamFlag(s string) (Upstream, error) {
	alias, u, ok := strings.Cut(s, "=")
	if !ok || alias == "" || u == "" {
		return Upstream{}, fmt.Errorf("upstream %q: want alias=URL", s)
	}
	return Upstream{Alias: alias, URL: u}, nil
}
