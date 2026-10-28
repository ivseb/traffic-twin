package main

import (
	"container/heap"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/demo/internal/simclock"
)

// Shipment states.
const (
	Pending   = "PENDING"
	Created   = "CREATED"
	InTransit = "IN_TRANSIT"
	Delivered = "DELIVERED"
	Cancelled = "CANCELLED"
)

// Outcomes drawn once per shipment at creation.
const (
	OutcomeHappy        = "happy"
	OutcomeCancelled    = "cancelled"
	OutcomeNeverShipped = "never_shipped"
)

type Shipment struct {
	ID           string
	OrderID      string
	Service      string
	Status       string
	Outcome      string
	CreatedAt    time.Time // simulated
	UpdatedAt    time.Time // simulated
	ETA          *time.Time
	CancelReason string
}

// event is a scheduled state change, in simulated time.
type event struct {
	at       time.Time
	seq      uint64
	shipID   string
	from, to string
}

type eventQueue []event

func (q eventQueue) Len() int { return len(q) }
func (q eventQueue) Less(i, j int) bool {
	if q[i].at.Equal(q[j].at) {
		return q[i].seq < q[j].seq
	}
	return q[i].at.Before(q[j].at)
}
func (q eventQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *eventQueue) Push(x any)   { *q = append(*q, x.(event)) }
func (q *eventQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}

// BatchRun records one execution of the nightly batch job.
type BatchRun struct {
	SimAt    time.Time `json:"sim_at"`
	RealAt   time.Time `json:"real_at"`
	Eligible int       `json:"eligible"`
	Moved    int       `json:"moved"`
}

// Store holds every shipment and the exact counts of what was produced.
type Store struct {
	mu        sync.Mutex
	truth     *Truth
	clock     *simclock.Clock
	shipments map[string]*Shipment
	byOrder   map[string]*Shipment
	queue     eventQueue
	seq       uint64
	nextBatch time.Time

	outcomes     map[string]int
	transitions  map[string]int
	deliveredBy  map[string]int
	withEta      int
	itemsServed  int
	itemsWithEta int
	batchRuns    []BatchRun
}

func NewStore(t *Truth, c *simclock.Clock) *Store {
	s := &Store{
		truth:       t,
		clock:       c,
		shipments:   map[string]*Shipment{},
		byOrder:     map[string]*Shipment{},
		outcomes:    map[string]int{},
		transitions: map[string]int{},
		deliveredBy: map[string]int{},
	}
	s.nextBatch = nextDaily(c.Now(), t.Batch.AtUTC)
	return s
}

// nextDaily returns the first hh:mm UTC strictly after t.
func nextDaily(t time.Time, hhmm string) time.Time {
	at, _ := time.Parse("15:04", hhmm)
	d := time.Date(t.Year(), t.Month(), t.Day(), at.Hour(), at.Minute(), 0, 0, time.UTC)
	if !d.After(t) {
		d = d.Add(24 * time.Hour)
	}
	return d
}

// shipmentRNG gives each order its own deterministic random stream, so the
// fate of an order depends only on (seed, orderId), never on arrival order.
func (s *Store) shipmentRNG(orderID string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(orderID))
	return rand.New(rand.NewPCG(s.truth.Seed, h.Sum64()))
}

// ErrDuplicate is returned when a shipment already exists for the order.
type ErrDuplicate struct{ ShipmentID string }

func (e ErrDuplicate) Error() string { return "shipment exists: " + e.ShipmentID }

// Create registers a new shipment in PENDING and schedules its future.
func (s *Store) Create(orderID, service string) (*Shipment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ex, ok := s.byOrder[orderID]; ok {
		return nil, ErrDuplicate{ex.ID}
	}
	t := s.truth
	rng := s.shipmentRNG(orderID)
	now := s.clock.Now()

	// Always draw in the same order so each value is stable per order.
	u := rng.Float64()
	hasEta := rng.Float64() < t.EtaPresence
	dCreated := t.Delays.Created.draw(rng)
	dTransit := t.Delays.InTransit.draw(rng)
	dDelivered := t.Delays.Delivered.draw(rng)
	dCancel := t.Delays.Cancelled.draw(rng)
	reason := t.CancelReasons[rng.IntN(len(t.CancelReasons))]
	id := fmt.Sprintf("SHP-%012X", rng.Uint64()&0xFFFFFFFFFFFF)
	for s.shipments[id] != nil { // astronomically rare; keep ids unique anyway
		id = fmt.Sprintf("SHP-%012X", rng.Uint64()&0xFFFFFFFFFFFF)
	}

	outcome := OutcomeNeverShipped
	switch {
	case u < t.Outcomes.Happy:
		outcome = OutcomeHappy
	case u < t.Outcomes.Happy+t.Outcomes.Cancelled:
		outcome = OutcomeCancelled
	}

	sh := &Shipment{ID: id, OrderID: orderID, Service: service, Status: Pending,
		Outcome: outcome, CreatedAt: now, UpdatedAt: now}
	if hasEta {
		// The carrier promises a delivery day; it is an estimate, not the truth.
		eta := now.Add(dCreated + dTransit + 48*time.Hour).Truncate(time.Hour)
		sh.ETA = &eta
		s.withEta++
	}
	s.shipments[id] = sh
	s.byOrder[orderID] = sh
	s.outcomes[outcome]++

	switch outcome {
	case OutcomeHappy:
		tc := now.Add(dCreated)
		tt := tc.Add(dTransit)
		s.schedule(tc, id, Pending, Created)
		s.schedule(tt, id, Created, InTransit)
		s.schedule(tt.Add(dDelivered), id, InTransit, Delivered)
	case OutcomeCancelled:
		tc := now.Add(dCreated)
		s.schedule(tc, id, Pending, Created)
		s.schedule(tc.Add(dCancel), id, Created, Cancelled)
		sh.CancelReason = reason
	}
	// never_shipped: nothing is scheduled; it stays PENDING and invisible.
	cp := *sh
	return &cp, nil
}

func (s *Store) schedule(at time.Time, id, from, to string) {
	s.seq++
	heap.Push(&s.queue, event{at: at, seq: s.seq, shipID: id, from: from, to: to})
}

// FindByOrder returns the shipments visible for an order. A shipment is
// visible once it left PENDING.
func (s *Store) FindByOrder(orderID string) []Shipment {
	s.mu.Lock()
	defer s.mu.Unlock()
	sh, ok := s.byOrder[orderID]
	if !ok || sh.Status == Pending {
		return nil
	}
	s.itemsServed++
	if sh.ETA != nil {
		s.itemsWithEta++
	}
	return []Shipment{*sh}
}

// Advance applies every event and batch run due at the current simulated
// time, strictly in simulated-time order.
func (s *Store) Advance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	for {
		batchDue := !s.nextBatch.After(now)
		eventDue := s.queue.Len() > 0 && !s.queue[0].at.After(now)
		switch {
		case batchDue && (!eventDue || !s.queue[0].at.Before(s.nextBatch)):
			s.runBatch(s.nextBatch)
			s.nextBatch = s.nextBatch.Add(24 * time.Hour)
		case eventDue:
			e := heap.Pop(&s.queue).(event)
			sh := s.shipments[e.shipID]
			if sh.Status != e.from {
				continue // already moved, e.g. delivered by the batch job
			}
			sh.Status, sh.UpdatedAt = e.to, e.at
			s.transitions[e.from+"->"+e.to]++
			if e.to == Delivered {
				s.deliveredBy["timer"]++
			}
		default:
			return
		}
	}
}

// runBatch moves exactly round(fraction * eligible) shipments, chosen by a
// seeded shuffle, from the batch "from" state to its "to" state.
func (s *Store) runBatch(at time.Time) {
	b := s.truth.Batch
	var ids []string
	for id, sh := range s.shipments {
		if sh.Status == b.From {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	rng := rand.New(rand.NewPCG(s.truth.Seed, uint64(at.Unix())))
	rng.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	k := int(math.Round(b.Fraction * float64(len(ids))))
	for _, id := range ids[:k] {
		sh := s.shipments[id]
		sh.Status, sh.UpdatedAt = b.To, at
		s.transitions[b.From+"->"+b.To]++
		s.deliveredBy["batch"]++
	}
	s.batchRuns = append(s.batchRuns, BatchRun{SimAt: at, RealAt: s.clock.ToReal(at).UTC(),
		Eligible: len(ids), Moved: k})
}

// Snapshot returns the exact counts produced so far.
func (s *Store) Snapshot() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := map[string]int{}
	for _, sh := range s.shipments {
		status[sh.Status]++
	}
	runs := append([]BatchRun{}, s.batchRuns...)
	return map[string]any{
		"shipments":       len(s.shipments),
		"outcomes_drawn":  copyMap(s.outcomes),
		"transitions":     copyMap(s.transitions),
		"delivered_by":    copyMap(s.deliveredBy),
		"current_status":  status,
		"eta":             map[string]int{"shipments_with_eta": s.withEta, "items_served": s.itemsServed, "items_with_eta": s.itemsWithEta},
		"batch_runs":      runs,
		"next_batch_sim":  s.nextBatch,
		"pending_effects": s.queue.Len(),
	}
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
