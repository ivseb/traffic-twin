package sourceclient

import (
	"strings"
	"testing"
	"time"
)

// The intake compares timeUnixNano with the event's millisecond "ts": a
// sub-millisecond source clock must not make every event mismatch.
func TestOTLPTimeIsMillisecondPrecision(t *testing.T) {
	e := NewExporter(ExporterOptions{})
	ts := time.Date(2026, 10, 19, 10, 0, 0, 412_345_678, time.UTC)
	body, err := e.otlpBody([]Event{{JSON: []byte(`{}`), TS: ts}})
	if err != nil {
		t.Fatal(err)
	}
	want := `"timeUnixNano":"1792404000412000000"`
	if !strings.Contains(string(body), want) {
		t.Fatalf("body %s does not contain %s", body, want)
	}
}
