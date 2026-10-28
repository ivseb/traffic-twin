package pack_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

func build(t *testing.T) (*packtest.Built, pack.KeySet) {
	t.Helper()
	b, err := packtest.Build(filepath.Join(t.TempDir(), "pack"), packtest.DemoSpec())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := pack.ParseKeySet(b.Keys)
	if err != nil {
		t.Fatal(err)
	}
	return b, ks
}

func TestLoadOK(t *testing.T) {
	b, ks := build(t)
	p, err := pack.Load(b.Dir, pack.Options{Keys: ks, MaxAge: -1})
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.PackID != "pk-20261019-0001" || len(p.Contracts) != 2 {
		t.Fatalf("unexpected pack: %+v", p.Manifest.PackID)
	}
	if len(p.Rules.Causal) != 2 || len(p.Rules.Batch) != 1 || len(p.Rules.Entities) != 2 {
		t.Fatalf("rules not loaded: %+v", p.Rules)
	}
	if got := p.Rules.Causal[0].Effects[3].After; !got.Range || got.Min != time.Hour || got.Max != 6*time.Hour {
		t.Fatalf("delay = %+v", got)
	}
	if got := p.Rules.Causal[0].Effects[0].After; got.Range || got.Max != 0 {
		t.Fatalf("single delay = %+v", got)
	}
	if rb := p.Rules.Entities[0].ReadBy[1]; rb.By == nil || !rb.By.Owner || rb.List == nil || rb.List.Limit.Name != "limit" || rb.Foreign != "forbidden" {
		t.Fatalf("read_by = %+v", rb)
	}
	if len(p.World.Customers) != 3 || len(p.World.Entities) != 6 || len(p.World.History) != 7 || len(p.World.Pending) != 4 {
		t.Fatalf("world not loaded: %d %d %d %d", len(p.World.Customers), len(p.World.Entities), len(p.World.History), len(p.World.Pending))
	}
	if p.World.History[0].Outcome != "happy" || p.World.Pending[1].DueOffsetS != 3600 {
		t.Fatalf("world rows: %+v %+v", p.World.History[0], p.World.Pending[1])
	}
	if p.Scenarios == nil || len(p.Scenarios.Scenarios) != 2 || p.Scenarios.Scenarios[0].ID != "shipment-cancelled" {
		t.Fatalf("scenarios = %+v", p.Scenarios)
	}
	if p.Faults.Ops[0].Statuses[0].Status != 503 {
		t.Fatal("faults not loaded")
	}
}

func TestLoadArchive(t *testing.T) {
	b, ks := build(t)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	var names []string
	_ = filepath.Walk(b.Dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(b.Dir, p)
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(names)
	for _, n := range names {
		data, _ := os.ReadFile(filepath.Join(b.Dir, filepath.FromSlash(n)))
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	_ = tw.Close()
	_ = zw.Close()
	arc := filepath.Join(t.TempDir(), "p.ttpack")
	if err := os.WriteFile(arc, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.Load(arc, pack.Options{Keys: ks, MaxAge: -1}); err != nil {
		t.Fatal(err)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, b *packtest.Built)
		keys   func(b *packtest.Built) string
		opt    pack.Options
		want   error
	}{
		{name: "unsigned", want: pack.ErrUnsigned, mutate: func(t *testing.T, b *packtest.Built) {
			must(t, os.Remove(filepath.Join(b.Dir, "manifest.sig.json")))
		}},
		{name: "tampered manifest", want: pack.ErrBadSignature, mutate: func(t *testing.T, b *packtest.Built) {
			p := filepath.Join(b.Dir, "manifest.json")
			data, _ := os.ReadFile(p)
			must(t, os.WriteFile(p, bytes.Replace(data, []byte(`"seed":42`), []byte(`"seed":43`), 1), 0o644))
		}},
		{name: "unknown kid", want: pack.ErrUnknownKey, mutate: func(t *testing.T, b *packtest.Built) {
			m, _ := os.ReadFile(filepath.Join(b.Dir, "manifest.json"))
			must(t, os.WriteFile(filepath.Join(b.Dir, "manifest.sig.json"), b.Sign(m, "gate-other"), 0o644))
		}},
		{name: "wrong key", want: pack.ErrBadSignature, keys: func(*packtest.Built) string {
			_, k := packtest.NewKey("gate-test-1")
			return k
		}},
		{name: "file changed", want: pack.ErrFiles, mutate: func(t *testing.T, b *packtest.Built) {
			p := filepath.Join(b.Dir, "faults.json")
			data, _ := os.ReadFile(p)
			must(t, os.WriteFile(p, bytes.Replace(data, []byte("0.01"), []byte("0.02"), 1), 0o644))
		}},
		{name: "extra file", want: pack.ErrFiles, mutate: func(t *testing.T, b *packtest.Built) {
			must(t, os.WriteFile(filepath.Join(b.Dir, "extra.json"), []byte("{}\n"), 0o644))
		}},
		{name: "missing file", want: pack.ErrFiles, mutate: func(t *testing.T, b *packtest.Built) {
			must(t, os.Remove(filepath.Join(b.Dir, "rules.json")))
		}},
		{name: "expired", want: pack.ErrExpired, opt: pack.Options{
			MaxAge: time.Hour, Now: func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }}},
		{name: "no keys", want: pack.ErrNoKeys, keys: func(*packtest.Built) string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, ks := build(t)
			if tc.mutate != nil {
				tc.mutate(t, b)
			}
			opt := tc.opt
			opt.Keys = ks
			if opt.MaxAge == 0 {
				opt.MaxAge = -1 // the fixture is dated 2026-10-19: no age check
			}
			if tc.keys != nil {
				if s := tc.keys(b); s == "" {
					opt.Keys = nil
				} else {
					k, err := pack.ParseKeySet(s)
					must(t, err)
					opt.Keys = k
				}
			}
			_, err := pack.Load(b.Dir, opt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBadRules(t *testing.T) {
	spec := packtest.DemoSpec()
	spec.Files["rules.json"] = bytes.Replace(spec.Files["rules.json"], []byte(`"p":0.93`), []byte(`"p":0.5`), 1)
	b, err := packtest.Build(filepath.Join(t.TempDir(), "p"), spec)
	must(t, err)
	ks, _ := pack.ParseKeySet(b.Keys)
	if _, err := pack.Load(b.Dir, pack.Options{Keys: ks, MaxAge: -1}); !errors.Is(err, pack.ErrContent) {
		t.Fatalf("got %v", err)
	}
}

func TestParseKeySet(t *testing.T) {
	_, k1 := packtest.NewKey("a")
	_, k2 := packtest.NewKey("b")
	ks, err := pack.ParseKeySet(k1 + "," + k2)
	if err != nil || len(ks) != 2 {
		t.Fatalf("inline: %v %d", err, len(ks))
	}
	f := filepath.Join(t.TempDir(), "keys")
	must(t, os.WriteFile(f, []byte("# comment\n"+k1+"\n\n"+k2+"\n"), 0o644))
	ks, err = pack.ParseKeySet(f)
	if err != nil || len(ks) != 2 {
		t.Fatalf("file: %v %d", err, len(ks))
	}
	for _, bad := range []string{"", "nokey", "a:!!!", "a:AAAA", k1 + "," + k1} {
		if _, err := pack.ParseKeySet(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
