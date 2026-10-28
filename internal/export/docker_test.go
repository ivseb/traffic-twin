package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests run the REAL third-party tools in containers (official images
// only) to prove that the exports load and answer as expected. They are slow
// and need Docker, so they run only with TT_EXPORT_DOCKER=1:
//
//	TT_EXPORT_DOCKER=1 go test ./internal/export -run Docker -v
//
// Images (override with the env vars in parentheses):
//
//	wiremock/wiremock:3.13.2        (TT_WIREMOCK_IMAGE)
//	microcks/microcks-uber:latest   (TT_MICROCKS_IMAGE)
//	stoplight/prism:5               (TT_PRISM_IMAGE)
func dockerOrSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("TT_EXPORT_DOCKER") != "1" {
		t.Skip("set TT_EXPORT_DOCKER=1 to run the container validation")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker not available: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startContainer runs an image detached and removes it when the test ends.
func startContainer(t *testing.T, port, inner int, mounts []string, image string, args ...string) string {
	t.Helper()
	name := fmt.Sprintf("tt-export-%d-%d", os.Getpid(), port)
	a := []string{"run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:%d", port, inner)}
	for _, m := range mounts {
		a = append(a, "-v", m)
	}
	a = append(a, image)
	a = append(a, args...)
	if out, err := exec.Command("docker", a...).CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
			t.Logf("container logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

func waitFor(t *testing.T, url string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s not ready after %s", url, d)
}

type hresp struct {
	Status int
	Body   string
}

func do(t *testing.T, method, url string, hdr map[string]string, body string) hresp {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return hresp{resp.StatusCode, strings.TrimSpace(string(b))}
}

func expect(t *testing.T, label string, got hresp, status int, contains string) {
	t.Helper()
	if got.Status != status || !strings.Contains(got.Body, contains) {
		t.Errorf("%s: got %d %q, want %d containing %q", label, got.Status, got.Body, status, contains)
	} else {
		t.Logf("ok   %-34s -> %d %s", label, got.Status, got.Body)
	}
}

func exportFixtureTo(t *testing.T, targets ...string) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := Run(context.Background(), Config{Source: DirSource{Dir: fixtureV12}, OutDir: dir, Targets: targets, Now: fixedNow}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDockerWireMock(t *testing.T) {
	dockerOrSkip(t)
	out := exportFixtureTo(t, TargetWireMock)
	abs, _ := filepath.Abs(filepath.Join(out, "wiremock", "shipping-ext", "mappings"))
	port := freePort(t)
	base := startContainer(t, port, 8080, []string{abs + ":/home/wiremock/mappings"},
		envOr("TT_WIREMOCK_IMAGE", "wiremock/wiremock:3.13.2"), "--verbose")
	waitFor(t, base+"/__admin/mappings", 90*time.Second)

	var list struct {
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(do(t, "GET", base+"/__admin/mappings", nil, "").Body), &list); err != nil {
		t.Fatal(err)
	}
	rep, _ := os.ReadFile(filepath.Join(out, "wiremock", "export-report.json"))
	var r Report
	_ = json.Unmarshal(rep, &r)
	// stubs counts both services; only shipping-ext is mounted.
	if list.Meta.Total == 0 {
		t.Fatal("WireMock loaded no mapping")
	}
	t.Logf("WireMock loaded %d mappings", list.Meta.Total)

	q := base + "/v1/shipments?orderId="
	expect(t, "PENDING is visible by id", do(t, "GET", base+"/v1/shipments/SHP-SYN-0091", nil, ""), 200, `"status":"PENDING"`)
	expect(t, "ORD-SYN-0042 poll 1 (PENDING hidden)", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `{"items":[]}`)
	expect(t, "ORD-SYN-0042 poll 2", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"CREATED"`)
	expect(t, "ORD-SYN-0042 poll 3", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"IN_TRANSIT"`)
	expect(t, "ORD-SYN-0042 poll 4", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"DELIVERED"`)
	expect(t, "ORD-SYN-0042 poll 5 (final is sticky)", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"DELIVERED"`)
	expect(t, "path read shares the scenario", do(t, "GET", base+"/v1/shipments/SHP-SYN-0091", nil, ""), 200, `"status":"DELIVERED"`)
	do(t, "GET", q+"ORD-SYN-0043", nil, "")
	do(t, "GET", q+"ORD-SYN-0043", nil, "")
	expect(t, "ORD-SYN-0043 cancelled", do(t, "GET", q+"ORD-SYN-0043", nil, ""), 200, `"status":"CANCELLED"`)
	expect(t, "ORD-SYN-0044 never shipped", do(t, "GET", q+"ORD-SYN-0044", nil, ""), 200, `{"items":[]}`)
	expect(t, "fault by status", do(t, "GET", q+"ORD-SYN-0042", map[string]string{"X-TT-Fault": "503"}, ""), 503, "CARRIER_UNAVAILABLE")
	expect(t, "fault by example name", do(t, "GET", q+"x", map[string]string{"X-TT-Fault": "carrier-unavailable"}, ""), 503, "CARRIER_UNAVAILABLE")
	// Normative network-fault mapping: the client must see a transport error.
	for _, kind := range []string{"reset", "refused", "dns", "tls", "other", "timeout"} {
		doFails(t, "net fault "+kind, q+"x", map[string]string{"X-TT-Fault": kind})
	}
	expect(t, "named example", do(t, "GET", q+"x", map[string]string{"X-TT-Example": "in-transit"}, ""), 200, "SHP-SYN-0100")
	expect(t, "contract default", do(t, "GET", q+"unknown", nil, ""), 200, `{"items":[]}`)
	expect(t, "POST default", do(t, "POST", base+"/v1/shipments", nil, `{"orderId":"x"}`), 202, "PENDING")

	// Reset puts every scenario back to Started (documented admin API).
	if r := do(t, "POST", base+"/__admin/scenarios/reset", nil, ""); r.Status != 200 {
		t.Fatalf("scenario reset: %+v", r)
	}
	expect(t, "after reset", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `{"items":[]}`)
	// Manual advance through the admin API.
	if r := do(t, "PUT", base+"/__admin/scenarios/r-0007-ORD-SYN-0042/state", nil, `{"state":"shipment-in-transit"}`); r.Status != 200 {
		t.Fatalf("set state: %+v", r)
	}
	expect(t, "after PUT state", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"IN_TRANSIT"`)

	// Latency: lognormal median 80 ms means answers take a measurable time.
	start := time.Now()
	do(t, "GET", q+"unknown", nil, "")
	t.Logf("delayed answer took %s (median 80ms)", time.Since(start).Round(time.Millisecond))

	// Owner scope on the shop (second instance): customer header decides.
	shopAbs, _ := filepath.Abs(filepath.Join(out, "wiremock", "shop-api", "mappings"))
	shop := startContainer(t, freePort(t), 8080, []string{shopAbs + ":/home/wiremock/mappings"},
		envOr("TT_WIREMOCK_IMAGE", "wiremock/wiremock:3.13.2"), "--verbose")
	waitFor(t, shop+"/__admin/mappings", 90*time.Second)
	c7 := map[string]string{"X-TT-Customer": "CUS-SYN-0007"}
	c8 := map[string]string{"X-TT-Customer": "CUS-SYN-0008"}
	expect(t, "order of the session customer", do(t, "GET", shop+"/orders/ORD-SYN-0042", c7, ""), 200, `"shipmentId":"SHP-SYN-0091"`)
	expect(t, "order of another customer -> 404", do(t, "GET", shop+"/orders/ORD-SYN-0042", c8, ""), 404, "ORDER_NOT_FOUND")
	expect(t, "order without session customer", do(t, "GET", shop+"/orders/ORD-SYN-0042", nil, ""), 200, `"id":"ORD-SYN-0042"`)
	expect(t, "own collection (sorted, count)", do(t, "GET", shop+"/customers/CUS-SYN-0007/orders", c7, ""), 200, `"count":2`)
	expect(t, "another customer's collection -> 403", do(t, "GET", shop+"/customers/CUS-SYN-0007/orders", c8, ""), 403, "FORBIDDEN")
	expect(t, "shipment of the order: hidden -> 404", do(t, "GET", shop+"/orders/ORD-SYN-0043/shipment", c7, ""), 404, "SHIPMENT_NOT_FOUND")
	expect(t, "shipment of the order: CREATED", do(t, "GET", shop+"/orders/ORD-SYN-0043/shipment", c7, ""), 200, `"status":"CREATED"`)
	expect(t, "shipment of another customer's order", do(t, "GET", shop+"/orders/ORD-SYN-0043/shipment", c8, ""), 404, "ORDER_NOT_FOUND")
	expect(t, "never shipped stays hidden", do(t, "GET", shop+"/orders/ORD-SYN-0044/shipment", c8, ""), 404, "SHIPMENT_NOT_FOUND")

	// The verbose log must show the requests that were served.
	var reqs struct {
		Requests []struct {
			WasMatched bool `json:"wasMatched"`
		} `json:"requests"`
	}
	_ = json.Unmarshal([]byte(do(t, "GET", base+"/__admin/requests", nil, "").Body), &reqs)
	for _, rq := range reqs.Requests {
		if !rq.WasMatched {
			t.Error("a request did not match any stub")
		}
	}
}

func microcksUpload(t *testing.T, base, file string, main bool) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", filepath.Base(file))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(b)
	_ = w.Close()
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/artifact/upload?mainArtifact=%t", base, main), &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		t.Fatalf("upload %s: %d %s", file, resp.StatusCode, rb)
	}
}

func TestDockerMicrocks(t *testing.T) {
	dockerOrSkip(t)
	out := exportFixtureTo(t, TargetMicrocks)
	port := freePort(t)
	base := startContainer(t, port, 8080, nil, envOr("TT_MICROCKS_IMAGE", "microcks/microcks-uber:latest"))
	waitFor(t, base+"/api/services", 180*time.Second)

	for _, svc := range []string{"shipping-ext", "shop-api"} {
		d := filepath.Join(out, "microcks", svc)
		microcksUpload(t, base, filepath.Join(d, svc+"-openapi.yaml"), true) // primary first
		microcksUpload(t, base, filepath.Join(d, svc+"-examples.yaml"), false)
		microcksUpload(t, base, filepath.Join(d, svc+"-metadata.yaml"), false)
	}
	var svcs []struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		Operations []struct {
			Name         string `json:"name"`
			Dispatcher   string `json:"dispatcher"`
			DefaultDelay int    `json:"defaultDelay"`
		} `json:"operations"`
	}
	if err := json.Unmarshal([]byte(do(t, "GET", base+"/api/services", nil, "").Body), &svcs); err != nil {
		t.Fatal(err)
	}
	disp := map[string]string{}
	for _, s := range svcs {
		for _, o := range s.Operations {
			disp[s.Name+" "+o.Name] = o.Dispatcher
		}
	}
	t.Logf("imported dispatchers: %v", disp)
	if disp["shop-api GET /orders/{id}/shipment"] != "SCRIPT" {
		t.Errorf("shop-api shipment chain not scripted: %v", disp)
	}
	if disp["shipping-ext GET /v1/shipments"] != "SCRIPT" || disp["shipping-ext POST /v1/shipments"] != "JSON_BODY" ||
		disp["shop-api GET /orders/{id}"] != "FALLBACK" {
		t.Errorf("dispatchers not applied by Microcks: %v", disp)
	}

	r := base + "/rest/shipping-ext/2026-10-19"
	q := r + "/v1/shipments?orderId="
	expect(t, "ORD-SYN-0042 call 1 (PENDING hidden)", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `{"items":[]}`)
	expect(t, "ORD-SYN-0042 call 2", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"CREATED"`)
	expect(t, "ORD-SYN-0042 call 3", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"IN_TRANSIT"`)
	expect(t, "ORD-SYN-0042 call 4", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"DELIVERED"`)
	expect(t, "ORD-SYN-0042 call 5 (sticky)", do(t, "GET", q+"ORD-SYN-0042", nil, ""), 200, `"status":"DELIVERED"`)
	expect(t, "path read shares the position", do(t, "GET", r+"/v1/shipments/SHP-SYN-0091", nil, ""), 200, `"status":"DELIVERED"`)
	do(t, "GET", q+"ORD-SYN-0043", nil, "")
	do(t, "GET", q+"ORD-SYN-0043", nil, "")
	expect(t, "ORD-SYN-0043 cancelled", do(t, "GET", q+"ORD-SYN-0043", nil, ""), 200, `"status":"CANCELLED"`)
	expect(t, "ORD-SYN-0044 never shipped", do(t, "GET", q+"ORD-SYN-0044", nil, ""), 200, `{"items":[]}`)
	expect(t, "KO example by trigger value", do(t, "GET", q+triggerValue("carrier-unavailable"), nil, ""), 503, "CARRIER_UNAVAILABLE")
	expect(t, "path KO by trigger value", do(t, "GET", r+"/v1/shipments/"+triggerValue("not-found"), nil, ""), 404, "SHIPMENT_NOT_FOUND")
	expect(t, "JSON_BODY KO", do(t, "POST", r+"/v1/shipments", nil, `{"orderId":"ORD-SYN-0077"}`), 503, "CARRIER_UNAVAILABLE")
	expect(t, "JSON_BODY OK", do(t, "POST", r+"/v1/shipments", nil, `{"orderId":"ORD-SYN-0050"}`), 202, "PENDING")

	s := base + "/rest/shop-api/2026-10-19"
	expect(t, "order snapshot", do(t, "GET", s+"/orders/ORD-SYN-0042", nil, ""), 200, "ORD-SYN-0042")
	expect(t, "order KO by trigger", do(t, "GET", s+"/orders/"+triggerValue("order-not-found"), nil, ""), 404, "ORDER_NOT_FOUND")
	expect(t, "order JSON_BODY KO", do(t, "POST", s+"/orders", nil, `{"sku":"SKU-NOPE"}`), 400, "UNKNOWN_SKU")
	expect(t, "customer collection", do(t, "GET", s+"/customers/CUS-SYN-0007/orders", nil, ""), 200, `"count":2`)
	sh := s + "/orders/ORD-SYN-0042/shipment"
	expect(t, "shop shipment call 1 (hidden)", do(t, "GET", sh, nil, ""), 404, "SHIPMENT_NOT_FOUND")
	expect(t, "shop shipment call 2", do(t, "GET", sh, nil, ""), 200, `"status":"CREATED"`)
	expect(t, "shop shipment call 3", do(t, "GET", sh, nil, ""), 200, `"status":"IN_TRANSIT"`)
	expect(t, "shop shipment call 4", do(t, "GET", sh, nil, ""), 200, `"status":"DELIVERED"`)

	start := time.Now()
	do(t, "GET", q+"unknown", nil, "")
	t.Logf("delayed answer took %s (delay 80 ms)", time.Since(start).Round(time.Millisecond))
}

func TestDockerPrism(t *testing.T) {
	dockerOrSkip(t)
	out := exportFixtureTo(t, TargetPrism)
	abs, _ := filepath.Abs(filepath.Join(out, "prism", "shipping-ext"))
	port := freePort(t)
	// --multiprocess=false: the amd64 image under emulation (Apple silicon)
	// crashes in cluster mode.
	base := startContainer(t, port, 4010, []string{abs + ":/specs:ro"}, envOr("TT_PRISM_IMAGE", "stoplight/prism:5"),
		"mock", "-h", "0.0.0.0", "--multiprocess=false", "/specs/shipping-ext.openapi.yaml")
	waitFor(t, base+"/v1/shipments?orderId=x", 120*time.Second)

	q := base + "/v1/shipments?orderId=ORD-SYN-0042"
	expect(t, "default example", do(t, "GET", q, nil, ""), 200, `{"items":[]}`)
	expect(t, "Prefer example (OK)", do(t, "GET", q, map[string]string{"Prefer": "example=r-0007-ORD-SYN-0042--shipment-in-transit"}, ""), 200, `"status":"IN_TRANSIT"`)
	expect(t, "Prefer example (OK, other state)", do(t, "GET", q, map[string]string{"Prefer": "example=r-0007-ORD-SYN-0042--shipment-delivered"}, ""), 200, `"status":"DELIVERED"`)
	expect(t, "Prefer code+example (KO)", do(t, "GET", q, map[string]string{"Prefer": "code=503, example=carrier-unavailable"}, ""), 503, "CARRIER_UNAVAILABLE")
	expect(t, "Prefer code (KO)", do(t, "GET", q, map[string]string{"Prefer": "code=503"}, ""), 503, "CARRIER_UNAVAILABLE")
	expect(t, "path example", do(t, "GET", base+"/v1/shipments/SHP-SYN-0091", map[string]string{"Prefer": "example=r-0007-ORD-SYN-0043--shipment-cancelled"}, ""), 200, "CANCELLED")
	expect(t, "path 404", do(t, "GET", base+"/v1/shipments/SHP-SYN-0091", map[string]string{"Prefer": "code=404, example=not-found"}, ""), 404, "SHIPMENT_NOT_FOUND")
}

// doFails expects a transport-level failure (reset, empty reply, garbage,
// timeout): the client must not get a normal HTTP answer.
func doFails(t *testing.T, label, url string, hdr map[string]string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Errorf("%s: got HTTP %d, want a transport error", label, resp.StatusCode)
		return
	}
	t.Logf("ok   %-34s -> %v", label, err)
}
