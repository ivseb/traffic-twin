package drift

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KnownEvents are the event types of the admin API (Webhook.events).
var KnownEvents = []string{"contract.drift", "rule.stale", "quarantine.opened", "source.problem", "kill.changed", "keyguard.alert", "pack.published", "storage.high_watermark"}

// Webhook is a notification destination.
type Webhook struct {
	ID     string   `json:"webhook_id"`
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	// Enabled: a disabled webhook keeps its definition and log but receives
	// no new notifications. On input, nil keeps the current value (true on
	// create).
	Enabled   *bool     `json:"enabled,omitempty"`
	SecretSet bool      `json:"secret_set"`
	Secret    string    `json:"secret,omitempty"` // write-only; returned once when generated
	CreatedAt time.Time `json:"-"`
}

func boolp(b bool) *bool { return &b }

func webhookID(n int64) string { return fmt.Sprintf("wh-%08d", n) }

func parseWebhookID(s string) (int64, bool) {
	r, ok := strings.CutPrefix(s, "wh-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(r, 10, 64)
	return n, err == nil && n > 0 && webhookID(n) == s
}

// ErrInvalid reports a rejected webhook definition; the message is safe to
// show.
type ErrInvalid string

func (e ErrInvalid) Error() string { return string(e) }

// CheckURL validates a destination against the scheme rules and the allow
// list.
func (m *Manager) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return ErrInvalid("invalid url")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !m.cfg.AllowHTTP {
			return ErrInvalid("url must use https")
		}
	default:
		return ErrInvalid("url must use https")
	}
	host := strings.ToLower(u.Hostname())
	hostport := strings.ToLower(u.Host)
	for _, a := range m.cfg.Allow {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
		case a == host || a == hostport:
			return nil
		case strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]) && len(host) > len(a)-1:
			return nil
		}
	}
	return ErrInvalid("destination is not in the webhook allow list")
}

func (m *Manager) validate(w *Webhook) error {
	if w.Name == "" || len(w.Name) > 120 {
		return ErrInvalid("name is required (at most 120 characters)")
	}
	if len(w.Events) == 0 {
		return ErrInvalid("at least one event is required")
	}
	seen := map[string]bool{}
	for _, e := range w.Events {
		if !slices.Contains(KnownEvents, e) || seen[e] {
			return ErrInvalid("unknown or repeated event")
		}
		seen[e] = true
	}
	slices.Sort(w.Events)
	if len(w.Secret) > 0 && (len(w.Secret) < 16 || len(w.Secret) > 256) {
		return ErrInvalid("secret must be 16 to 256 characters")
	}
	return m.CheckURL(w.URL)
}

func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + base64.RawURLEncoding.EncodeToString(b)
}

// CreateWebhook stores a webhook. Without a secret one is generated and
// returned once in the result.
func (m *Manager) CreateWebhook(ctx context.Context, w Webhook) (Webhook, error) {
	if err := m.validate(&w); err != nil {
		return Webhook{}, err
	}
	generated := ""
	if w.Secret == "" {
		w.Secret = newSecret()
		generated = w.Secret
	}
	ev, _ := json.Marshal(w.Events)
	now := m.now().UnixMilli()
	enabled := w.Enabled == nil || *w.Enabled
	res, err := m.db.ExecContext(ctx, `INSERT INTO drift_webhooks (name, url, events, secret, enabled, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		w.Name, w.URL, string(ev), w.Secret, enabled, now, now)
	if err != nil {
		return Webhook{}, err
	}
	id, _ := res.LastInsertId()
	out := Webhook{ID: webhookID(id), Name: w.Name, URL: w.URL, Events: w.Events, Enabled: boolp(enabled), SecretSet: true, Secret: generated}
	return out, nil
}

// UpdateWebhook replaces name, url and events; the secret changes only when
// one is given.
func (m *Manager) UpdateWebhook(ctx context.Context, id string, w Webhook) (Webhook, error) {
	n, ok := parseWebhookID(id)
	if !ok {
		return Webhook{}, ErrNotFound
	}
	if err := m.validate(&w); err != nil {
		return Webhook{}, err
	}
	ev, _ := json.Marshal(w.Events)
	var res sql.Result
	var err error
	if w.Secret != "" {
		res, err = m.db.ExecContext(ctx, `UPDATE drift_webhooks SET name = ?, url = ?, events = ?, secret = ?, updated_ms = ? WHERE id = ?`,
			w.Name, w.URL, string(ev), w.Secret, m.now().UnixMilli(), n)
	} else {
		res, err = m.db.ExecContext(ctx, `UPDATE drift_webhooks SET name = ?, url = ?, events = ?, updated_ms = ? WHERE id = ?`,
			w.Name, w.URL, string(ev), m.now().UnixMilli(), n)
	}
	if err != nil {
		return Webhook{}, err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return Webhook{}, ErrNotFound
	}
	if w.Enabled != nil {
		return m.SetWebhookEnabled(ctx, id, *w.Enabled)
	}
	return m.GetWebhook(ctx, id)
}

// SetWebhookEnabled switches a webhook on or off without touching anything
// else. Notifications raised while it is off are not queued for it.
func (m *Manager) SetWebhookEnabled(ctx context.Context, id string, enabled bool) (Webhook, error) {
	n, ok := parseWebhookID(id)
	if !ok {
		return Webhook{}, ErrNotFound
	}
	res, err := m.db.ExecContext(ctx, `UPDATE drift_webhooks SET enabled = ?, updated_ms = ? WHERE id = ?`, enabled, m.now().UnixMilli(), n)
	if err != nil {
		return Webhook{}, err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return Webhook{}, ErrNotFound
	}
	return m.GetWebhook(ctx, id)
}

// DeleteWebhook removes a webhook and its delivery log.
func (m *Manager) DeleteWebhook(ctx context.Context, id string) error {
	n, ok := parseWebhookID(id)
	if !ok {
		return ErrNotFound
	}
	res, err := m.db.ExecContext(ctx, `DELETE FROM drift_webhooks WHERE id = ?`, n)
	if err != nil {
		return err
	}
	if c, _ := res.RowsAffected(); c == 0 {
		return ErrNotFound
	}
	return nil
}

func scanWebhook(sc interface{ Scan(...any) error }) (Webhook, string, error) {
	var w Webhook
	var n, created int64
	var ev, secret string
	var enabled bool
	if err := sc.Scan(&n, &w.Name, &w.URL, &ev, &secret, &created, &enabled); err != nil {
		return w, "", err
	}
	w.ID = webhookID(n)
	w.Enabled = boolp(enabled)
	w.SecretSet = secret != ""
	w.CreatedAt = time.UnixMilli(created).UTC()
	_ = json.Unmarshal([]byte(ev), &w.Events)
	return w, secret, nil
}

const webhookSelect = `SELECT id, name, url, events, secret, created_ms, enabled FROM drift_webhooks`

// GetWebhook returns a webhook without its secret.
func (m *Manager) GetWebhook(ctx context.Context, id string) (Webhook, error) {
	n, ok := parseWebhookID(id)
	if !ok {
		return Webhook{}, ErrNotFound
	}
	w, _, err := scanWebhook(m.db.QueryRowContext(ctx, webhookSelect+` WHERE id = ?`, n))
	if errors.Is(err, sql.ErrNoRows) {
		return w, ErrNotFound
	}
	return w, err
}

// ListWebhooks returns the webhooks without secrets.
func (m *Manager) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	rows, err := m.db.QueryContext(ctx, webhookSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Webhook{}
	for rows.Next() {
		w, _, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Queue

func (m *Manager) emit(ctx context.Context, eventType string, alertID int64, payload map[string]any) error {
	hooks, err := m.ListWebhooks(ctx)
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	now := m.now().UnixMilli()
	queued := false
	for _, h := range hooks {
		if !slices.Contains(h.Events, eventType) || (h.Enabled != nil && !*h.Enabled) {
			continue
		}
		n, _ := parseWebhookID(h.ID)
		if _, err := m.db.ExecContext(ctx, `INSERT INTO drift_deliveries (webhook_id, event_type, alert_id, payload, state, next_attempt_ms, created_ms)
			VALUES (?, ?, ?, ?, 'pending', ?, ?)`, n, eventType, alertID, body, now, now); err != nil {
			return err
		}
		queued = true
	}
	if queued {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Delivery is one entry of the delivery log. It contains no payload.
type Delivery struct {
	ID          int64     `json:"delivery_id"`
	WebhookID   string    `json:"webhook_id"`
	Event       string    `json:"event"`
	DriftID     string    `json:"drift_id,omitempty"`
	State       string    `json:"state"` // pending | delivered | failed
	Attempts    int       `json:"attempts"`
	LastStatus  int       `json:"last_status,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	NextAttempt time.Time `json:"next_attempt,omitempty"`
}

// Deliveries returns the delivery log of a webhook, newest first.
func (m *Manager) Deliveries(ctx context.Context, webhook string, limit int) ([]Delivery, error) {
	n, ok := parseWebhookID(webhook)
	if !ok {
		return nil, ErrNotFound
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := m.db.QueryContext(ctx, `SELECT id, event_type, alert_id, state, attempts, last_status, last_error, created_ms, next_attempt_ms
		FROM drift_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT ?`, n, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var alert, created, next int64
		if err := rows.Scan(&d.ID, &d.Event, &alert, &d.State, &d.Attempts, &d.LastStatus, &d.LastError, &created, &next); err != nil {
			return nil, err
		}
		d.WebhookID = webhook
		if alert > 0 {
			d.DriftID = alertID(alert)
		}
		d.CreatedAt = time.UnixMilli(created).UTC()
		if d.State == "pending" {
			d.NextAttempt = time.UnixMilli(next).UTC()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Run delivers queued notifications until ctx is done, and once an hour
// drops the delivery log older than DeliveryRetention.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	var lastPrune time.Time
	for {
		n, err := m.DeliverDue(ctx)
		if err != nil && ctx.Err() == nil {
			m.log.WarnContext(ctx, "drift: delivery pass failed", "err", err)
		}
		if now := m.now(); now.Sub(lastPrune) >= time.Hour {
			lastPrune = now
			if _, err := m.PruneDeliveries(ctx, now.Add(-DeliveryRetention)); err != nil && ctx.Err() == nil {
				m.log.WarnContext(ctx, "drift: delivery log prune failed", "err", err)
			}
		}
		if n >= dueBatch && err == nil {
			continue // a full batch: more are due, no wait for the tick
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

// dueBatch is the number of deliveries one pass takes.
const dueBatch = 100

// DeliveryRetention is how long finished deliveries (delivered or failed)
// stay in the log. Pending ones are never dropped.
const DeliveryRetention = 30 * 24 * time.Hour

// PruneDeliveries deletes the finished deliveries created before cutoff,
// a few thousand per transaction, and returns how many it deleted.
func (m *Manager) PruneDeliveries(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for {
		r, err := m.db.ExecContext(ctx, `DELETE FROM drift_deliveries WHERE id IN (SELECT id FROM drift_deliveries
			WHERE state IN ('delivered', 'failed') AND created_ms < ? ORDER BY id LIMIT 5000)`, cutoff.UnixMilli())
		if err != nil {
			return total, err
		}
		n, _ := r.RowsAffected()
		total += n
		if n < 5000 || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

type dueRow struct {
	id       int64
	webhook  int64
	event    string
	payload  []byte
	attempts int
}

// passWait is how long a delivery pass waits for its workers. A worker
// still sending after that (a slow endpoint) goes on in the background and
// its webhook is skipped by the next passes until it is done.
const passWait = time.Second

// DeliverDue attempts every delivery whose time has come and returns the
// number of deliveries taken. Each webhook gets one worker (its deliveries
// stay in order, one at a time), so that a slow or unreachable endpoint
// delays only its own notifications: the pass waits at most passWait for
// the workers, and webhooks whose worker is still busy are not selected.
func (m *Manager) DeliverDue(ctx context.Context) (int, error) {
	m.busyMu.Lock()
	skip := make([]int64, 0, len(m.busy))
	for id := range m.busy {
		skip = append(skip, id)
	}
	m.busyMu.Unlock()
	skipJSON, _ := json.Marshal(skip)
	rows, err := m.db.QueryContext(ctx, `SELECT id, webhook_id, event_type, payload, attempts FROM drift_deliveries
		WHERE state = 'pending' AND next_attempt_ms <= ? AND webhook_id NOT IN (SELECT value FROM json_each(?))
		ORDER BY id LIMIT ?`, m.now().UnixMilli(), string(skipJSON), dueBatch)
	if err != nil {
		return 0, err
	}
	var due []dueRow
	for rows.Next() {
		var d dueRow
		if err := rows.Scan(&d.id, &d.webhook, &d.event, &d.payload, &d.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, d)
	}
	rows.Close()
	var order []int64
	per := map[int64][]dueRow{}
	for _, d := range due {
		if per[d.webhook] == nil {
			order = append(order, d.webhook)
		}
		per[d.webhook] = append(per[d.webhook], d)
	}
	var wg sync.WaitGroup
	for _, wh := range order {
		ds := per[wh]
		m.busyMu.Lock()
		if m.busy[wh] {
			m.busyMu.Unlock()
			continue
		}
		m.busy[wh] = true
		m.busyMu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				m.busyMu.Lock()
				delete(m.busy, wh)
				m.busyMu.Unlock()
			}()
			for _, d := range ds {
				if ctx.Err() != nil {
					return
				}
				m.attempt(ctx, d)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTimer(passWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	return len(due), nil
}

func (m *Manager) backoff(attempts int) time.Duration {
	i := attempts - 1
	if i < 0 {
		i = 0
	}
	if i >= len(m.cfg.Backoff) {
		i = len(m.cfg.Backoff) - 1
	}
	d := m.cfg.Backoff[i]
	// +-20% jitter
	if j, err := rand.Int(rand.Reader, big.NewInt(401)); err == nil {
		d = time.Duration(float64(d) * (0.8 + float64(j.Int64())/1000))
	}
	return d
}

func (m *Manager) attempt(ctx context.Context, d dueRow) {
	w, secret, err := scanWebhook(m.db.QueryRowContext(ctx, webhookSelect+` WHERE id = ?`, d.webhook))
	if err != nil {
		_, _ = m.db.ExecContext(ctx, `UPDATE drift_deliveries SET state = 'failed', last_error = 'webhook_missing' WHERE id = ?`, d.id)
		return
	}
	if w.Enabled != nil && !*w.Enabled {
		_, _ = m.db.ExecContext(ctx, `UPDATE drift_deliveries SET state = 'failed', last_error = 'webhook_disabled' WHERE id = ?`, d.id)
		return
	}
	status, class := m.post(ctx, w.URL, secret, d.event, d.id, d.payload)
	attempts := d.attempts + 1
	now := m.now().UnixMilli()
	switch {
	case class == "":
		_, _ = m.db.ExecContext(ctx, `UPDATE drift_deliveries SET state = 'delivered', attempts = ?, last_status = ?, last_error = '', delivered_ms = ? WHERE id = ?`,
			attempts, status, now, d.id)
	case !retryable(status, class) || attempts >= m.cfg.MaxAttempts:
		_, _ = m.db.ExecContext(ctx, `UPDATE drift_deliveries SET state = 'failed', attempts = ?, last_status = ?, last_error = ? WHERE id = ?`,
			attempts, status, class, d.id)
	default:
		next := m.now().Add(m.backoff(attempts)).UnixMilli()
		_, _ = m.db.ExecContext(ctx, `UPDATE drift_deliveries SET attempts = ?, last_status = ?, last_error = ?, next_attempt_ms = ? WHERE id = ?`,
			attempts, status, class, next, d.id)
	}
}

func retryable(status int, class string) bool {
	switch class {
	case "allow_list", "bad_url":
		return false
	}
	if status == 0 {
		return true // network error or timeout
	}
	return status >= 500 || status == 429 || status == 408
}

// post sends one signed request. The returned class is "" on success, else a
// short machine code that never contains response data.
func (m *Manager) post(ctx context.Context, rawURL, secret, event string, deliveryID int64, payload []byte) (int, string) {
	if err := m.CheckURL(rawURL); err != nil {
		return 0, "allow_list"
	}
	ctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(payload))
	if err != nil {
		return 0, "bad_url"
	}
	ts := m.now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "traffic-twin-webhook/1")
	req.Header.Set("X-TT-Event", event)
	req.Header.Set("X-TT-Delivery", fmt.Sprintf("dl-%08d", deliveryID))
	req.Header.Set("X-TT-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-TT-Signature", Sign(secret, ts, payload))
	resp, err := m.cli.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return 0, "timeout"
		}
		return 0, "connection"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, "http_" + strconv.Itoa(resp.StatusCode)
}

// SendTest delivers a webhook.test notification synchronously (one attempt,
// no retry) and reports whether the receiver answered 2xx.
func (m *Manager) SendTest(ctx context.Context, id string) error {
	n, ok := parseWebhookID(id)
	if !ok {
		return ErrNotFound
	}
	w, secret, err := scanWebhook(m.db.QueryRowContext(ctx, webhookSelect+` WHERE id = ?`, n))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"type": "webhook.test", "webhook_id": w.ID, "sent_at": m.now().UTC().Format(time.RFC3339)})
	if status, class := m.post(ctx, w.URL, secret, "webhook.test", 0, body); class != "" {
		return fmt.Errorf("drift: test delivery failed: %s (status %d)", class, status)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Signatures

// Sign returns the X-TT-Signature header value for a body sent at unix time
// ts: "t=<ts>,v1=<hex HMAC-SHA256(secret, "<ts>." + body)>".
func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks an X-TT-Signature header against the body. It
// rejects timestamps further than tolerance from now (replay protection;
// tolerance <= 0 disables the check).
func VerifySignature(secret, header string, body []byte, now time.Time, tolerance time.Duration) bool {
	var ts int64
	var sig string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return false
			}
			ts = n
		case "v1":
			sig = v
		}
	}
	if ts == 0 || sig == "" {
		return false
	}
	if tolerance > 0 {
		d := now.Sub(time.Unix(ts, 0))
		if d < 0 {
			d = -d
		}
		if d > tolerance {
			return false
		}
	}
	want := Sign(secret, ts, body)
	return hmac.Equal([]byte(want), []byte("t="+strconv.FormatInt(ts, 10)+",v1="+sig))
}
