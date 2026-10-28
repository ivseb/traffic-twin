package keyguard

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Alert types (keyguard.md 5, policy.md 5).
const (
	AlertMatchPositive  = "match.positive"
	AlertPackPositive   = "pack.positive"
	AlertRateLimited    = "rate.limited"
	AlertBudgetExceeded = "budget.exceeded"
	AlertApprovalRefuse = "policy.approval_refused"
	AlertSignRefused    = "sign.refused"
	AlertAdminApproval  = "policy.admin_approval"
	AlertPackAdmin      = "pack.admin_approval"
)

// Alert is the webhook body: type, time and counts only, never values.
type Alert struct {
	Type   string           `json:"type"`
	At     time.Time        `json:"at"`
	Counts map[string]int64 `json:"counts,omitempty"`
}

// alerter delivers alerts to the configured webhook (the only outbound call
// keyguard makes) through a bounded queue; it always logs them.
type alerter struct {
	url    string
	client *http.Client
	log    *slog.Logger
	queue  chan Alert
	wg     sync.WaitGroup
	once   sync.Once
	mu     sync.Mutex
	closed bool
	// sent receives every alert (tests).
	sent func(Alert)
}

func newAlerter(url string, log *slog.Logger) *alerter {
	a := &alerter{url: url, log: log, client: &http.Client{Timeout: 5 * time.Second}, queue: make(chan Alert, 256)}
	a.wg.Add(1)
	go a.loop()
	return a
}

func (a *alerter) raise(al Alert) {
	a.log.Warn("keyguard alert", "alert_type", al.Type, "counts", al.Counts)
	if a.sent != nil {
		a.sent(al)
	}
	if a.url == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	select {
	case a.queue <- al:
	default:
		a.log.Error("keyguard alert queue full, webhook delivery dropped", "alert_type", al.Type)
	}
}

func (a *alerter) loop() {
	defer a.wg.Done()
	for al := range a.queue {
		b, _ := json.Marshal(al)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			var resp *http.Response
			resp, err = a.client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 300 {
					a.log.Error("keyguard alert webhook refused", "alert_type", al.Type, "status", resp.StatusCode)
				}
			}
		}
		if err != nil {
			a.log.Error("keyguard alert webhook failed", "alert_type", al.Type)
		}
		cancel()
	}
}

func (a *alerter) close() {
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.queue)
		a.mu.Unlock()
		a.wg.Wait()
	})
}
