package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Report is the result of a run.
type Report struct {
	Label     string    `json:"label,omitempty"`
	Scale     Scale     `json:"scale"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	GoVersion string    `json:"go"`
	GOOS      string    `json:"goos"`
	GOARCH    string    `json:"goarch"`
	CPUs      int       `json:"cpus"`
	Error     string    `json:"error,omitempty"`
	// MemLimitMB is the memory of the emulated host (-memlimit).
	MemLimitMB float64 `json:"mem_limit_mb,omitempty"`

	Dataset   DatasetStats     `json:"dataset"`
	Endpoints []*EndpointStats `json:"endpoints"`
	Jobs      []*JobStats      `json:"jobs"`
	Queries   []*queryStat     `json:"queries"`
}

// DatasetStats describes the generated database.
type DatasetStats struct {
	GenerateSeconds float64          `json:"generate_seconds"`
	Templates       int              `json:"templates"`
	Rows            map[string]int64 `json:"rows"`
	FileBytes       int64            `json:"file_bytes"`
	WALBytes        int64            `json:"wal_bytes"`
	BytesPerEvent   float64          `json:"bytes_per_event"`
	StartupSeconds  float64          `json:"core_startup_seconds"`
}

// EndpointStats are the latencies of one GET endpoint.
type EndpointStats struct {
	Name   string  `json:"name"`
	Path   string  `json:"path"`
	Class  string  `json:"class"` // list, detail, heavy
	Status int     `json:"status"`
	N      int     `json:"n"`
	P50    float64 `json:"p50_ms"`
	P95    float64 `json:"p95_ms"`
	Max    float64 `json:"max_ms"`
	Bytes  int     `json:"bytes"`
	Note   string  `json:"note,omitempty"`
}

// JobStats describe one background job or heavy operation.
type JobStats struct {
	Name       string            `json:"name"`
	Seconds    float64           `json:"seconds"`
	HeapPeakMB float64           `json:"heap_peak_mb"`
	DBGrowthMB float64           `json:"db_growth_mb"`
	OK         bool              `json:"ok"`
	Detail     map[string]any    `json:"detail,omitempty"`
	Error      string            `json:"error,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

func writeReport(r *Report, base string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(base+".json", b, 0o600); err != nil {
		return err
	}
	return os.WriteFile(base+".md", []byte(markdown(r)), 0o600)
}

func markdown(r *Report) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# ttperf %s %s\n\n", r.Scale.Name, r.Label)
	fmt.Fprintf(&sb, "%s/%s, %d CPU, %s, %s → %s\n\n", r.GOOS, r.GOARCH, r.CPUs, r.GoVersion, r.Started.Format(time.RFC3339), r.Finished.Format(time.RFC3339))
	if r.Error != "" {
		fmt.Fprintf(&sb, "**error:** %s\n\n", r.Error)
	}
	d := r.Dataset
	fmt.Fprintf(&sb, "## Dataset\n\ngenerated in %.0f s from %d templates; file %.1f MB (WAL %.1f MB), %.0f B/event; core startup %.2f s\n\n",
		d.GenerateSeconds, d.Templates, mb(d.FileBytes), mb(d.WALBytes), d.BytesPerEvent, d.StartupSeconds)
	keys := make([]string, 0, len(d.Rows))
	for k := range d.Rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb.WriteString("| table | rows |\n|---|---:|\n")
	for _, k := range keys {
		fmt.Fprintf(&sb, "| %s | %d |\n", k, d.Rows[k])
	}
	sb.WriteString("\n## Endpoints (GET)\n\n| endpoint | class | status | p50 ms | p95 ms | max ms | bytes | note |\n|---|---|---:|---:|---:|---:|---:|---|\n")
	for _, e := range r.Endpoints {
		fmt.Fprintf(&sb, "| `%s` | %s | %d | %.1f | %.1f | %.1f | %d | %s |\n", e.Path, e.Class, e.Status, e.P50, e.P95, e.Max, e.Bytes, e.Note)
	}
	sb.WriteString("\n## Jobs\n\n| job | ok | seconds | heap peak MB | DB growth MB | detail |\n|---|---|---:|---:|---:|---|\n")
	for _, j := range r.Jobs {
		det, _ := json.Marshal(j.Detail)
		if j.Error != "" {
			det = []byte(j.Error)
		}
		s := string(det)
		if len(s) > 300 {
			s = s[:300] + "…"
		}
		fmt.Fprintf(&sb, "| %s | %v | %.2f | %.0f | %.1f | %s |\n", j.Name, j.OK, j.Seconds, j.HeapPeakMB, j.DBGrowthMB, strings.ReplaceAll(s, "|", "/"))
	}
	sb.WriteString("\n## SQL (top 40 by total time)\n\n| total ms | calls | max ms | rows | flags | statement |\n|---:|---:|---:|---:|---|---|\n")
	for i, q := range r.Queries {
		if i >= 40 {
			break
		}
		s := q.SQL
		if len(s) > 160 {
			s = s[:160] + "…"
		}
		fmt.Fprintf(&sb, "| %.0f | %d | %.1f | %d | %s | `%s` |\n", ms(q.Total), q.Count, ms(q.Max), q.Rows,
			strings.Join(q.Flags, "; "), strings.ReplaceAll(s, "|", "/"))
	}
	var flagged []*queryStat
	for _, q := range r.Queries {
		if len(q.Flags) > 0 {
			flagged = append(flagged, q)
		}
	}
	fmt.Fprintf(&sb, "\n## Plans with full scans or temporary sorts (%d)\n\n", len(flagged))
	for _, q := range flagged {
		fmt.Fprintf(&sb, "- `%s` (%d calls, %.0f ms total)\n", q.SQL, q.Count, ms(q.Total))
		for _, p := range q.Plan {
			fmt.Fprintf(&sb, "  - %s\n", p)
		}
	}
	return sb.String()
}

func mb(b int64) float64         { return float64(b) / (1 << 20) }
func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- budgets ----

// Budgets are the limits a run must meet (docs/PERFORMANCE.md).
type Budgets struct {
	// ClassP95 is the p95 limit in ms per endpoint class.
	ClassP95 map[string]float64 `json:"class_p95_ms"`
	// EndpointP95 overrides the class limit for one endpoint name.
	EndpointP95 map[string]float64 `json:"endpoint_p95_ms"`
	// Exempt endpoints are measured but not judged (with the reason).
	Exempt map[string]string `json:"exempt"`
	// JobSeconds and JobHeapMB limit the jobs by name.
	JobSeconds map[string]float64 `json:"job_seconds"`
	JobHeapMB  map[string]float64 `json:"job_heap_mb"`
	// JobDetailMax limits a numeric detail of a job: "job.detail" -> max.
	JobDetailMax map[string]float64 `json:"job_detail_max"`
	// JobDetailMin is the lower bound of a numeric detail (throughputs).
	JobDetailMin map[string]float64 `json:"job_detail_min"`
	// Scale limits apply only when the run used this scale ("" = any).
	Scale string `json:"scale"`
}

func loadBudgets(path string) (*Budgets, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("budgets: %w", err)
	}
	all := map[string]*Budgets{}
	for k, v := range raw {
		if strings.HasPrefix(k, "_") {
			continue // comments
		}
		var x Budgets
		if err := json.Unmarshal(v, &x); err != nil {
			return nil, fmt.Errorf("budgets %s: %w", k, err)
		}
		all[k] = &x
	}
	merged := &Budgets{ClassP95: map[string]float64{}, EndpointP95: map[string]float64{}, Exempt: map[string]string{},
		JobSeconds: map[string]float64{}, JobHeapMB: map[string]float64{}, JobDetailMax: map[string]float64{}, JobDetailMin: map[string]float64{}}
	for _, k := range []string{"default", os.Getenv("TTPERF_BUDGET_PROFILE")} {
		x := all[k]
		if x == nil {
			continue
		}
		for a, v := range x.ClassP95 {
			merged.ClassP95[a] = v
		}
		for a, v := range x.EndpointP95 {
			merged.EndpointP95[a] = v
		}
		for a, v := range x.Exempt {
			merged.Exempt[a] = v
		}
		for a, v := range x.JobSeconds {
			merged.JobSeconds[a] = v
		}
		for a, v := range x.JobHeapMB {
			merged.JobHeapMB[a] = v
		}
		for a, v := range x.JobDetailMax {
			merged.JobDetailMax[a] = v
		}
		for a, v := range x.JobDetailMin {
			merged.JobDetailMin[a] = v
		}
	}
	return merged, nil
}

func (b *Budgets) check(r *Report) []string {
	var v []string
	for _, e := range r.Endpoints {
		if _, ok := b.Exempt[e.Name]; ok {
			continue
		}
		if strings.HasPrefix(e.Note, "skipped") {
			continue
		}
		if e.Status >= 500 || e.Status == 0 {
			v = append(v, fmt.Sprintf("endpoint %s answered %d", e.Name, e.Status))
			continue
		}
		lim, ok := b.EndpointP95[e.Name]
		if !ok {
			lim, ok = b.ClassP95[e.Class]
		}
		if ok && e.P95 > lim {
			v = append(v, fmt.Sprintf("endpoint %s p95 %.1f ms > %.0f ms (%s)", e.Name, e.P95, lim, e.Class))
		}
	}
	for _, j := range r.Jobs {
		if _, ok := b.Exempt[j.Name]; ok {
			continue
		}
		if !j.OK {
			v = append(v, fmt.Sprintf("job %s failed: %s", j.Name, j.Error))
			continue
		}
		if lim, ok := b.JobSeconds[j.Name]; ok && j.Seconds > lim {
			v = append(v, fmt.Sprintf("job %s took %.2f s > %.1f s", j.Name, j.Seconds, lim))
		}
		if lim, ok := b.JobHeapMB[j.Name]; ok && j.HeapPeakMB > lim {
			v = append(v, fmt.Sprintf("job %s heap peak %.0f MB > %.0f MB", j.Name, j.HeapPeakMB, lim))
		}
		for k, lim := range b.JobDetailMax {
			name, field, ok := cutLast(k, ".")
			if !ok || name != j.Name {
				continue
			}
			if f, ok := toFloat(j.Detail[field]); ok && f > lim {
				v = append(v, fmt.Sprintf("job %s %s = %.1f > %.1f", j.Name, field, f, lim))
			}
		}
		for k, lim := range b.JobDetailMin {
			name, field, ok := cutLast(k, ".")
			if !ok || name != j.Name {
				continue
			}
			if f, ok := toFloat(j.Detail[field]); !ok || f < lim {
				v = append(v, fmt.Sprintf("job %s %s = %.1f < %.1f", j.Name, field, f, lim))
			}
		}
	}
	sort.Strings(v)
	return v
}

func toFloat(x any) (float64, bool) {
	switch n := x.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

// cutLast splits "job.name.field" at the last dot (job names have dots).
func cutLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
