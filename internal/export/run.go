package export

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Target names.
const (
	TargetWireMock = "wiremock"
	TargetMicrocks = "microcks"
	TargetPrism    = "prism"
)

// AllTargets lists the supported targets in output order.
var AllTargets = []string{TargetWireMock, TargetMicrocks, TargetPrism}

// Config drives Run.
type Config struct {
	// Source provides the verified pack content.
	Source Source
	// OutDir receives one directory per target. Each target directory is
	// removed and rewritten, so stale files never survive.
	OutDir string
	// Targets defaults to AllTargets.
	Targets []string
	// Services restricts the export to these services (default: all).
	Services []string

	WireMock WireMockOptions
	Microcks MicrocksOptions
	Prism    PrismOptions

	// Now is the clock used for the not_after check (default time.Now).
	// internal/pack already refuses expired packs; this is defence in depth
	// for sources that skip it. It never influences the output bytes.
	Now func() time.Time
}

// ErrPackExpired is returned when the clock is at or after manifest not_after.
var ErrPackExpired = errors.New("pack_expired")

func (in *Input) checkExpiry(now func() time.Time) error {
	if in.Manifest.NotAfter == "" {
		return nil
	}
	na, err := time.Parse(time.RFC3339, in.Manifest.NotAfter)
	if err != nil {
		return fmt.Errorf("export: manifest not_after %q: %w", in.Manifest.NotAfter, err)
	}
	if now == nil {
		now = time.Now
	}
	if !now().Before(na) {
		return fmt.Errorf("%w: not_after %s", ErrPackExpired, in.Manifest.NotAfter)
	}
	return nil
}

// WireMockOptions tunes the WireMock export.
type WireMockOptions struct {
	// Advance is "poll" (default: each read of the first exposing operation
	// moves the scenario one step) or "manual" (states change only through
	// PUT /__admin/scenarios/{name}/state).
	Advance string
	// FaultHeader selects fault stubs (default X-TT-Fault).
	FaultHeader string
	// ExampleHeader selects named example stubs (default X-TT-Example).
	ExampleHeader string
	// CustomerHeader carries the session customer for owner-scoped reads
	// (default X-TT-Customer).
	CustomerHeader string
}

// MicrocksOptions tunes the Microcks export.
type MicrocksOptions struct {
	// Delay is "median" (default: operation delay = median latency, ms) or "none".
	Delay string
	// Stateless disables the SCRIPT + store dispatcher for stateful chains:
	// only the state at the end of the observed history is served.
	Stateless bool
	// StateTTL is the lifetime in seconds of the store entries (default 3600).
	StateTTL int
}

// PrismOptions tunes the Prism export (reserved; no options yet).
type PrismOptions struct{}

// Result describes what Run wrote.
type Result struct {
	Reports map[string]*Report
	Files   []string // relative to OutDir, sorted
}

func (c *Config) defaults() error {
	if c.Source == nil {
		return errors.New("export: no source")
	}
	if c.OutDir == "" {
		return errors.New("export: no output directory")
	}
	if len(c.Targets) == 0 {
		c.Targets = AllTargets
	}
	for _, t := range c.Targets {
		if t != TargetWireMock && t != TargetMicrocks && t != TargetPrism {
			return fmt.Errorf("export: unknown target %q (want wiremock, microcks, prism)", t)
		}
	}
	if c.WireMock.Advance == "" {
		c.WireMock.Advance = "poll"
	}
	if c.WireMock.Advance != "poll" && c.WireMock.Advance != "manual" {
		return fmt.Errorf("export: wiremock advance %q (want poll or manual)", c.WireMock.Advance)
	}
	if c.WireMock.FaultHeader == "" {
		c.WireMock.FaultHeader = "X-TT-Fault"
	}
	if c.WireMock.ExampleHeader == "" {
		c.WireMock.ExampleHeader = "X-TT-Example"
	}
	if c.WireMock.CustomerHeader == "" {
		c.WireMock.CustomerHeader = "X-TT-Customer"
	}
	if c.Microcks.Delay == "" {
		c.Microcks.Delay = "median"
	}
	if c.Microcks.Delay != "median" && c.Microcks.Delay != "none" {
		return fmt.Errorf("export: microcks delay %q (want median or none)", c.Microcks.Delay)
	}
	if c.Microcks.StateTTL <= 0 {
		c.Microcks.StateTTL = 3600
	}
	return nil
}

// Run loads the pack, builds every requested target and writes the files plus
// one export-report.json per target. The same input always produces the same
// bytes.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	in, err := cfg.Source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("export: load pack: %w", err)
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	if err := in.checkExpiry(cfg.Now); err != nil {
		return nil, err
	}
	var only map[string]bool
	if len(cfg.Services) > 0 {
		only = map[string]bool{}
		known := map[string]bool{}
		for _, s := range in.Services {
			known[s.Name] = true
		}
		for _, s := range cfg.Services {
			if !known[s] {
				return nil, fmt.Errorf("export: unknown service %q", s)
			}
			only[s] = true
		}
	}
	res := &Result{Reports: map[string]*Report{}}
	targets := append([]string(nil), cfg.Targets...)
	sort.Strings(targets)
	for _, t := range dedupe(targets) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m := buildModel(in, only)
		var files []outFile
		var rep *Report
		switch t {
		case TargetWireMock:
			files, rep = exportWireMock(m, cfg.WireMock)
		case TargetMicrocks:
			files, rep = exportMicrocks(m, cfg.Microcks)
		case TargetPrism:
			files, rep = exportPrism(m, cfg.Prism)
		}
		files = append(files, outFile{Path: t + "/export-report.json", Data: marshalJSON(rep)})
		if err := writeTarget(cfg.OutDir, t, files); err != nil {
			return nil, err
		}
		res.Reports[t] = rep
		for _, f := range files {
			res.Files = append(res.Files, f.Path)
		}
	}
	sort.Strings(res.Files)
	return res, nil
}

func dedupe(s []string) []string {
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func writeTarget(out, target string, files []outFile) error {
	dir := filepath.Join(out, target)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, f := range files {
		p := filepath.Join(out, filepath.FromSlash(f.Path))
		if !strings.HasPrefix(p, filepath.Clean(dir)+string(filepath.Separator)) {
			return fmt.Errorf("export: refusing to write outside target dir: %s", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.Data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Flags binds the documented `tt export` flags. The caller (cmd/tt) registers
// them on its FlagSet, resolves --pack with internal/pack and then calls
// Config with the resulting Source.
type Flags struct {
	Pack          string
	Out           string
	Targets       string
	Services      string
	WMAdvance     string
	WMFaultHeader string
	WMExampleHdr  string
	WMCustomerHdr string
	MKDelay       string
	MKStateless   bool
	MKStateTTL    int
}

// Register adds the flags to fs.
func (f *Flags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Pack, "pack", "", "twin pack directory or .ttpack archive (verified by the caller)")
	fs.StringVar(&f.Out, "out", "tt-export", "output directory (one subdirectory per target)")
	fs.StringVar(&f.Targets, "target", "all", "comma separated: wiremock, microcks, prism, or all")
	fs.StringVar(&f.Services, "service", "", "comma separated service names (default: all)")
	fs.StringVar(&f.WMAdvance, "wiremock-advance", "poll", "wiremock scenario progress: poll (each read advances) or manual (admin API only)")
	fs.StringVar(&f.WMFaultHeader, "wiremock-fault-header", "X-TT-Fault", "request header that selects fault stubs")
	fs.StringVar(&f.WMExampleHdr, "wiremock-example-header", "X-TT-Example", "request header that selects named example stubs")
	fs.StringVar(&f.WMCustomerHdr, "wiremock-customer-header", "X-TT-Customer", "request header that carries the session customer for owner-scoped reads")
	fs.StringVar(&f.MKDelay, "microcks-delay", "median", "microcks operation delay: median or none")
	fs.BoolVar(&f.MKStateless, "microcks-stateless", false, "do not generate SCRIPT/store dispatchers for stateful chains")
	fs.IntVar(&f.MKStateTTL, "microcks-state-ttl", 3600, "seconds a scripted scenario position stays in the Microcks store")
}

// Config builds the Config for the given source.
func (f *Flags) Config(src Source) Config {
	c := Config{Source: src, OutDir: f.Out}
	if t := strings.TrimSpace(f.Targets); t != "" && t != "all" {
		c.Targets = splitList(t)
	}
	c.Services = splitList(f.Services)
	c.WireMock = WireMockOptions{Advance: f.WMAdvance, FaultHeader: f.WMFaultHeader, ExampleHeader: f.WMExampleHdr, CustomerHeader: f.WMCustomerHdr}
	c.Microcks = MicrocksOptions{Delay: f.MKDelay, Stateless: f.MKStateless, StateTTL: f.MKStateTTL}
	return c
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
