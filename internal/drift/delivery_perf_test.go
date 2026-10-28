package drift_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/drift"
)

// A slow endpoint must not hold back the notifications of the others: each
// webhook is served by its own worker within a delivery pass.
func TestSlowWebhookDoesNotBlockOthers(t *testing.T) {
	f := setup(t)
	var slowHits atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowHits.Add(1)
		time.Sleep(700 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer slow.Close()
	if _, err := f.mgr.CreateWebhook(f.ctx, drift.Webhook{Name: "slow", URL: slow.URL + "/hook", Events: []string{"contract.drift"}}); err != nil {
		t.Fatal(err)
	}
	// Every event goes to both webhooks: 3 of them cost the slow one 2.1 s.
	for i := 0; i < 3; i++ {
		if err := f.mgr.Emit(f.ctx, "contract.drift", map[string]any{"service": "shop-api", "severity": "breaking", "change": "x"}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { _, _ = f.mgr.DeliverDue(f.ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for len(f.rcv.all()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("fast webhook got %d of 3 notifications while the slow one was busy", len(f.rcv.all()))
		}
		time.Sleep(10 * time.Millisecond)
	}
	<-done // the pass waits at most a second for the slow worker
	for end := time.Now().Add(5 * time.Second); slowHits.Load() < 3 && time.Now().Before(end); {
		time.Sleep(20 * time.Millisecond)
	}
	if slowHits.Load() != 3 {
		t.Fatalf("slow webhook: %d attempts", slowHits.Load())
	}
	// While its worker was busy the slow webhook was not selected again:
	// exactly one attempt per delivery.
	time.Sleep(800 * time.Millisecond)
	if _, err := f.mgr.DeliverDue(f.ctx); err != nil || slowHits.Load() != 3 {
		t.Fatalf("after the worker: %d attempts (%v)", slowHits.Load(), err)
	}
}

// Finished deliveries older than the retention are dropped; pending ones stay.
func TestPruneDeliveries(t *testing.T) {
	f := setup(t)
	f.rcv.fail = 0
	for i := 0; i < 3; i++ {
		_ = f.mgr.Emit(f.ctx, "contract.drift", map[string]any{"service": "s"})
	}
	if n, _ := f.mgr.DeliverDue(f.ctx); n != 3 {
		t.Fatalf("delivered %d", n)
	}
	_ = f.mgr.Emit(f.ctx, "contract.drift", map[string]any{"service": "s"}) // stays pending
	f.clk.Advance(drift.DeliveryRetention + time.Hour)
	n, err := f.mgr.PruneDeliveries(f.ctx, f.clk.Now().Add(-drift.DeliveryRetention))
	if err != nil || n != 3 {
		t.Fatalf("pruned %d (%v), want 3", n, err)
	}
	log, _ := f.mgr.Deliveries(f.ctx, f.hid, 10)
	if len(log) != 1 || log[0].State != "pending" {
		t.Fatalf("left: %+v", log)
	}
}
