package core_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/mock"
)

// consoleMockTest runs `tt mock --console` against the real tt-core of the
// acceptance test: a mock token of group demo, the published pack fetched
// and verified, the report on the Mock page, a command, "Prepara e avvia il
// mock" publishing a new pack that the mock swaps in, the token useless on
// the admin API, and the mock stopping once its token is revoked.
func consoleMockTest(t *testing.T, ctx context.Context, base string, hc *http.Client, olga, ada, paul *session, gateKeys, packID string, now func() time.Time) {
	t.Helper()
	began := time.Now()
	lap := func(s string) { t.Logf("  console mock %5.2fs %s", time.Since(began).Seconds(), s) }
	defer lap("end")
	var nt struct {
		TokenID string `json:"token_id"`
		Token   string `json:"token"`
		Setup   struct {
			Docker string `json:"docker"`
		} `json:"setup"`
	}
	olga.json(201, "POST", "/api/v1/mocks/tokens", map[string]any{"group": "demo", "label": "e2e"}, &nt)
	if !strings.Contains(nt.Setup.Docker, nt.Token) || !strings.Contains(nt.Setup.Docker, "--console "+base) {
		t.Fatalf("setup snippet: %s", nt.Setup.Docker)
	}
	// The mock token is not a console credential.
	for _, p := range []string{"/api/v1/packs", "/api/v1/mocks", "/api/v1/packs/" + packID + "/download"} {
		req, _ := http.NewRequest("GET", base+p, nil)
		req.Header.Set("Authorization", "Bearer "+nt.Token)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("mock token on %s: %d", p, resp.StatusCode)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- mock.RunConsole(mctx, mock.Config{Listener: ln, GatePubKeys: gateKeys, Latency: "off", Faults: "off", Now: now},
			mock.ConsoleConfig{URL: base, Token: nt.Token, Group: "demo", Instance: "e2e-mock", Client: hc, Interval: 50 * time.Millisecond, TempDir: t.TempDir()})
	}()
	type mockView struct {
		MockID   string `json:"mock_id"`
		Online   bool   `json:"online"`
		Status   string `json:"status"`
		PackID   string `json:"pack_id"`
		UpToDate bool   `json:"up_to_date"`
		Services []struct {
			Name    string `json:"name"`
			MockURL string `json:"mock_url"`
		} `json:"services"`
	}
	var list struct {
		Mocks []mockView `json:"mocks"`
	}
	current := func() *mockView {
		olga.json(200, "GET", "/api/v1/mocks?group=demo", nil, &list)
		for i := range list.Mocks {
			if strings.HasSuffix(list.Mocks[i].MockID, ".e2e-mock") {
				return &list.Mocks[i]
			}
		}
		return nil
	}
	eventually(t, 10*time.Second, "the console mock serving the published pack", func() bool {
		m := current()
		return m != nil && m.Online && m.Status == "serving" && m.PackID == packID && m.UpToDate
	})
	lap("serving")
	m := current()
	if len(m.Services) == 0 || !strings.HasPrefix(m.Services[0].MockURL, "http://"+ln.Addr().String()+"/__svc/") {
		t.Fatalf("services: %+v", m.Services)
	}

	// A call to the mock appears in its journal on the console.
	resp, err := http.Get(m.Services[0].MockURL + "/no-such-path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	eventually(t, 10*time.Second, "the call on the console", func() bool {
		_, b := olga.do("GET", "/api/v1/mocks/"+m.MockID+"/calls", nil)
		return strings.Contains(string(b), "/no-such-path")
	})

	// A command (new session) runs on the mock.
	var cq struct {
		CommandID string `json:"command_id"`
	}
	olga.json(202, "POST", "/api/v1/mocks/"+m.MockID+"/commands", map[string]any{"method": "POST", "path": "/__tt/sessions", "body": map[string]any{"id": "e2e-s1", "seed": 3}}, &cq)
	eventually(t, 10*time.Second, "the command result", func() bool {
		_, b := olga.do("GET", "/api/v1/mocks/"+m.MockID+"/commands/"+cq.CommandID, nil)
		return strings.Contains(string(b), `"status":"done"`) && strings.Contains(string(b), `"status":201`)
	})

	// "Prepara e avvia il mock": an operator alone stops before the
	// publication; an administrator (with a reason) goes to the end and the
	// connected mock swaps the new pack in.
	type job struct {
		JobID  string `json:"job_id"`
		Status string `json:"status"`
		Error  string `json:"error"`
		Result struct {
			Result struct {
				PackID  string `json:"pack_id"`
				Waiting string `json:"waiting"`
			} `json:"result"`
			Steps []struct {
				ID, Status, Code string
			} `json:"steps"`
		} `json:"result"`
	}
	follow := func(s *session, j job) job {
		eventually(t, 60*time.Second, "prepare job", func() bool {
			j = job{JobID: j.JobID}
			s.json(200, "GET", "/api/v1/jobs/"+j.JobID, nil, &j)
			return j.Status != "running"
		})
		return j
	}
	lap("command done")
	var j job
	olga.json(202, "POST", "/api/v1/mocks/prepare", map[string]any{"group": "demo"}, &j)
	j = follow(olga, j)
	if j.Status != "done" || j.Result.Result.Waiting != "needs_publisher" {
		t.Fatalf("operator prepare: %+v", j)
	}
	j = job{}
	ada.json(202, "POST", "/api/v1/mocks/prepare", map[string]any{"group": "demo"}, &j)
	if j = follow(ada, j); j.Status != "failed" || j.Error != "admin_reason_required" {
		t.Fatalf("admin without a reason: %+v", j)
	}
	j = job{}
	ada.json(202, "POST", "/api/v1/mocks/prepare", map[string]any{"group": "demo", "reason": "e2e mock refresh"}, &j)
	j = follow(ada, j)
	if j.Status != "done" || j.Result.Result.PackID == "" || j.Result.Result.PackID == packID {
		t.Fatalf("admin prepare: %+v", j)
	}
	last := j.Result.Steps[len(j.Result.Steps)-1]
	if last.ID != "mock" || last.Status != "done" || last.Code != "connected" {
		t.Fatalf("mock step: %+v", j.Result.Steps)
	}
	lap("prepared")
	newPack := j.Result.Result.PackID
	eventually(t, 15*time.Second, "the mock on the new pack", func() bool {
		m := current()
		return m != nil && m.PackID == newPack && m.UpToDate
	})
	_ = paul
	lap("reloaded")

	// Revoked: the mock is refused and stops.
	olga.must(204, "DELETE", "/api/v1/mocks/tokens/"+nt.TokenID, nil)
	select {
	case err := <-done:
		if !errors.Is(err, mock.ErrTokenRefused) {
			t.Fatalf("console mock stopped with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the console mock kept running with a revoked token")
	}
}
