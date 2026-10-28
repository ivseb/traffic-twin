package intake

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/event"
)

// TestSanitizerVectorsPassTheIntake closes the loop between the two sides of
// the contract: whatever the (reference) sanitizer produces for a vector,
// wrapped in an event and checked against the policy of that vector, must be
// accepted by the intake. A mismatch means the intake would drop legitimate
// data (or that the vector disagrees with the specification).
//
// Every vector with outcome "event" is used unchanged: its output must be a
// valid revision 1.1 event and must be accepted. Other outcomes are skipped.
func TestSanitizerVectorsPassTheIntake(t *testing.T) {
	root := filepath.Join("..", "..", "conformance")
	files, _ := filepath.Glob(filepath.Join(root, "vectors", "*.json"))
	if len(files) == 0 {
		t.Skip("no conformance vectors")
	}
	cfg := DefaultConfig()
	sort.Strings(files)
	var checked, skipped int
	var failures []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var vec struct {
			ID       string          `json:"id"`
			Policy   json.RawMessage `json:"policy"`
			Ref      string          `json:"policy_ref"`
			Now      string          `json:"now"`
			Group    string          `json:"source_group"`
			Input    map[string]any  `json:"input"`
			Expected struct {
				Outcome   string `json:"outcome"`
				Canonical string `json:"canonical"`
			} `json:"expected"`
			Envelope *struct {
				BodyB64 string `json:"body_b64"`
			} `json:"policy_envelope"`
		}
		if err := json.Unmarshal(raw, &vec); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if vec.Expected.Outcome != "event" {
			continue
		}
		body := []byte(vec.Policy)
		switch {
		case vec.Envelope != nil:
			body, _ = base64.RawURLEncoding.DecodeString(vec.Envelope.BodyB64)
		case vec.Ref != "":
			body, err = os.ReadFile(filepath.Join(root, vec.Ref))
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(body) == 0 {
			skipped++
			continue
		}
		pol, err := ParsePolicy(body)
		if err != nil {
			skipped++
			continue
		}

		// Wrap the sanitizer output into a full event.
		out, derr := event.ParseCanonical([]byte(vec.Expected.Canonical))
		if derr != nil {
			t.Fatalf("%s: expected.canonical is not tt-cjson: %v", vec.ID, derr)
		}
		add := func(k string, v event.Value) { out.O = append(out.O, event.Member{K: k, V: v}) }
		add("schema", event.Str(event.Schema))
		add("policy", event.Obj(
			event.Member{K: "id", V: event.Str(pol.ID)},
			event.Member{K: "version", V: event.Value{Kind: event.Number, S: "1"}},
			event.Member{K: "hash", V: event.Str(pol.Hash)}))
		add("source", event.Obj(
			event.Member{K: "kind", V: event.Str("sdk-go")},
			event.Member{K: "version", V: event.Str("0.0.0")},
			event.Member{K: "id", V: event.Str(testSource)}))
		ts := "2026-10-23T10:00:00.000Z"
		if vec.Now != "" {
			ts = strings.Replace(vec.Now, "Z", ".000Z", 1)
		}
		add("ts", event.Str(ts))
		add("latency_ms", event.Value{Kind: event.Number, S: "1"})
		dir, _ := vec.Input["dir"].(string)
		add("dir", event.Str(dir))
		if ne, ok := vec.Input["net_error"].(string); ok {
			add("net_error", event.Str(ne))
		} else if st, ok := vec.Input["status"].(float64); ok {
			add("status", event.Value{Kind: event.Number, S: itoaTest(int(st))})
		}
		if tr, ok := vec.Input["trace_id"].(string); ok {
			add("trace_id", event.Str(tr))
		}
		out.SortMembers()
		ev, derr := event.Decode(out.Canonical())
		if derr != nil {
			failures = append(failures, vec.ID+": not a valid event: "+derr.Error())
			continue
		}

		src := SourceInfo{ID: testSource, Group: vec.Group, AllowedServices: []string{ev.Service}}
		c := &checker{cfg: &cfg, pol: pol, src: &src, ev: ev}
		checked++
		if !c.run() {
			failures = append(failures, vec.ID+": "+c.rej.Reason.String()+": "+c.rej.Detail)
		}
	}
	t.Logf("%d vectors checked, %d skipped (no usable policy)", checked, skipped)
	if checked < 20 {
		t.Fatalf("only %d vectors were usable", checked)
	}
	if len(failures) > 0 {
		t.Errorf("%d sanitizer outputs rejected by the intake:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

func itoaTest(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
