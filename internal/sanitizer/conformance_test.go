package sanitizer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/policy"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Runner for the conformance vectors (conformance/format.md,
// tt.conformance.vector/v1). Every vector in conformance/vectors/*.json is
// executed; the test is skipped only when the directory is absent. A
// mismatch reports the vector id and both byte strings.

const conformanceRoot = "../../conformance"

type vectorFile struct {
	Format         string            `json:"format"`
	ID             string            `json:"id"`
	Policy         json.RawMessage   `json:"policy"`
	PolicyRef      string            `json:"policy_ref"`
	PolicyEnvelope json.RawMessage   `json:"policy_envelope"`
	FleetKeys      map[string]string `json:"fleet_keys"`
	HMACKey        *string           `json:"hmac_key"`
	Now            string            `json:"now"`
	SourceGroup    string            `json:"source_group"`
	LastIssuedSeq  int64             `json:"last_issued_seq"`
	MinIssuedSeq   int64             `json:"min_issued_seq"`
	Input          json.RawMessage   `json:"input"`
	Expected       struct {
		Outcome   string `json:"outcome"`
		Canonical string `json:"canonical"`
		SampledBy string `json:"sampled_by"`
		Code      string `json:"code"`
	} `json:"expected"`
}

// vectorResult is what an implementation produces for one vector.
type vectorResult struct {
	outcome, canonical, sampledBy, code string
}

func TestConformanceVectors(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(conformanceRoot, "vectors", "*.json"))
	if len(files) == 0 {
		t.Skip("conformance/vectors not present")
	}
	sort.Strings(files)
	var failed []string
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".json")
		ok := t.Run(id, func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var v vectorFile
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("vector json: %v", err)
			}
			got, err := runVector(&v)
			if err != nil {
				t.Fatalf("runner: %v", err)
			}
			want := vectorResult{outcome: v.Expected.Outcome, canonical: v.Expected.Canonical, sampledBy: v.Expected.SampledBy, code: v.Expected.Code}
			if got != want {
				t.Errorf("mismatch\n got  %s %s%s%s\n want %s %s%s%s", got.outcome, got.code, got.sampledBy, got.canonical,
					want.outcome, want.code, want.sampledBy, want.canonical)
			}
		})
		if !ok {
			failed = append(failed, id)
		}
	}
	if len(failed) > 0 {
		t.Logf("%d/%d vectors failed: %s", len(failed), len(files), strings.Join(failed, " "))
	}
}

func refused(code string) vectorResult { return vectorResult{outcome: "refused", code: code} }

func runVector(v *vectorFile) (vectorResult, error) {
	var now time.Time
	if v.Now != "" {
		var err error
		if now, err = time.Parse(time.RFC3339Nano, v.Now); err != nil {
			return vectorResult{}, fmt.Errorf("now: %w", err)
		}
	}
	// 1. Policy (format.md "Executing a vector").
	var body []byte
	switch {
	case len(v.PolicyEnvelope) > 0:
		ring := policy.NewKeyRing()
		for kid, pub := range v.FleetKeys {
			if err := ring.PinEncoded(kid, "Ed25519", pub); err != nil {
				return refused("policy_rejected"), nil
			}
		}
		vf, err := policy.Verify(v.PolicyEnvelope, ring)
		if err != nil {
			return refused("policy_rejected"), nil
		}
		body = vf.Body
	case len(v.Policy) > 0:
		body = v.Policy
	case v.PolicyRef != "":
		var err error
		if body, err = os.ReadFile(filepath.Join(conformanceRoot, v.PolicyRef)); err != nil {
			return vectorResult{}, err
		}
	default:
		return refused("no_policy"), nil
	}
	pv, err := ttjson.Parse(body, ttjson.ParseOptions{RejectDuplicates: true})
	if err != nil {
		return refused("policy_rejected"), nil
	}
	p, err := policy.DecodeBodyValue(pv)
	if err != nil {
		if os.Getenv("TT_VECTOR_DEBUG") != "" {
			fmt.Println(v.ID, "policy:", err)
		}
		return refused("policy_rejected"), nil
	}
	switch err := policy.CheckAcceptance(p, v.SourceGroup, now, v.LastIssuedSeq, v.MinIssuedSeq); {
	case errors.Is(err, policy.ErrNotAfter):
		return refused("expired_policy"), nil
	case err != nil:
		return refused("policy_rejected"), nil
	}
	// 2. Key.
	if v.HMACKey == nil {
		return refused("key_missing"), nil
	}
	keys, err := ParseKeys(*v.HMACKey)
	if err != nil {
		return refused("key_missing"), nil
	}
	e, err := NewEngine(p, keys)
	switch {
	case errors.Is(err, ErrKeyMismatch):
		return refused("key_mismatch"), nil
	case errors.Is(err, ErrKeyMissing):
		return refused("key_missing"), nil
	case err != nil:
		return refused("policy_rejected"), nil
	}
	// 3-4. Sampling and sanitizing. Random sampling appears only with
	// rate_bp 0 or 10000, so any constant works.
	ex, err := vectorExchange(v.Input)
	if err != nil {
		return vectorResult{}, err
	}
	out, d, err := e.Capture(ex, now, func() int { return 0 })
	if err != nil {
		return vectorResult{}, fmt.Errorf("sanitize: %w", err)
	}
	if !d.Sampled {
		return vectorResult{outcome: "not_sampled", sampledBy: string(d.By)}, nil
	}
	b, err := out.Canonical()
	if err != nil {
		return vectorResult{}, err
	}
	return vectorResult{outcome: "event", canonical: string(b)}, nil
}

// vectorBytes decodes the bytes type: a JSON string (UTF-8) or
// {"b64": "<standard base64>", "text": ...}.
func vectorBytes(raw json.RawMessage) ([]byte, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s), true, nil
	}
	var o struct {
		B64 *string `json:"b64"`
	}
	if err := json.Unmarshal(raw, &o); err != nil || o.B64 == nil {
		return nil, false, fmt.Errorf("bytes: unknown shape %s", raw)
	}
	b, err := base64.StdEncoding.DecodeString(*o.B64)
	return b, true, err
}

func vectorHeaders(raw json.RawMessage) ([]Header, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var pairs [][2]json.RawMessage
	if err := json.Unmarshal(raw, &pairs); err != nil {
		return nil, err
	}
	var hs []Header
	for _, p := range pairs {
		var name string
		if err := json.Unmarshal(p[0], &name); err != nil {
			return nil, err
		}
		v, _, err := vectorBytes(p[1])
		if err != nil {
			return nil, err
		}
		if v == nil {
			v = []byte{}
		}
		hs = append(hs, Header{Name: name, Value: v})
	}
	return hs, nil
}

func vectorTotal(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "unknown" {
			return UnknownLength, nil
		}
		return 0, fmt.Errorf("body total %q", s)
	}
	var n int64
	err := json.Unmarshal(raw, &n)
	return n, err
}

func vectorExchange(raw json.RawMessage) (*Exchange, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	str := func(k string) string {
		var s string
		_ = json.Unmarshal(in[k], &s)
		return s
	}
	flag := func(k string, def bool) bool {
		b := def
		if r, ok := in[k]; ok {
			_ = json.Unmarshal(r, &b)
		}
		return b
	}
	var status int
	_ = json.Unmarshal(in["status"], &status)
	ex := &Exchange{
		Dir: Direction(str("dir")), ServiceName: str("service_name"), URLBase: str("url_base"), Method: str("method"),
		FrameworkRoute: str("framework_route"), Framework: str("framework"), TraceID: str("trace_id"), Status: status, NetError: str("net_error"),
		ReqBodyNotConsumed: !flag("req_body_consumed", true), ReqBodyDecoded: flag("req_body_decoded", false),
		RespBodyNotConsumed: !flag("resp_body_consumed", true), RespBodyDecoded: flag("resp_body_decoded", false),
	}
	if r, ok := in["inherited"]; ok {
		var b bool
		if err := json.Unmarshal(r, &b); err != nil {
			return nil, err
		}
		ex.Inherited = &b
	}
	var err error
	if ex.RawPath, _, err = vectorBytes(in["raw_path"]); err != nil {
		return nil, err
	}
	var present bool
	if ex.RawQuery, present, err = vectorBytes(in["raw_query"]); err != nil {
		return nil, err
	}
	if present && ex.RawQuery == nil {
		ex.RawQuery = []byte{}
	}
	if ex.ReqBody, _, err = vectorBytes(in["req_body"]); err != nil {
		return nil, err
	}
	if ex.RespBody, _, err = vectorBytes(in["resp_body"]); err != nil {
		return nil, err
	}
	if ex.ReqBodyTotal, err = vectorTotal(in["req_body_total"]); err != nil {
		return nil, err
	}
	if ex.RespBodyTotal, err = vectorTotal(in["resp_body_total"]); err != nil {
		return nil, err
	}
	if ex.ReqHeaders, err = vectorHeaders(in["req_headers"]); err != nil {
		return nil, err
	}
	if ex.RespHeaders, err = vectorHeaders(in["resp_headers"]); err != nil {
		return nil, err
	}
	if ex.Dir == "" {
		return nil, errors.New("input: missing dir")
	}
	return ex, nil
}
