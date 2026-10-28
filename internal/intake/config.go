package intake

import (
	"errors"
	"fmt"
	"time"
)

// Config tunes the intake. The zero value is not valid: start from
// [DefaultConfig].
type Config struct {
	// MaxRequestBytes bounds an OTLP request, before and after gzip
	// (docs/spec/event.md 4.1: 4 MiB).
	MaxRequestBytes int64
	// MaxEventBytes bounds one event (512 KiB).
	MaxEventBytes int
	// MaxRecords bounds the log records of one request (512).
	MaxRecords int

	// QueueEvents and QueueBytes bound the ingestion queue between the
	// HTTP handlers and the single database writer. When either is
	// exceeded the intake answers 429 with Retry-After.
	QueueEvents int
	QueueBytes  int64
	// BatchSize is the largest number of events per database transaction;
	// BatchWait the longest the writer waits to fill a batch.
	BatchSize int
	BatchWait time.Duration
	// MaxInflightPerSource bounds concurrent requests of one source.
	MaxInflightPerSource int

	// Retention is how long events and token index rows are kept (by the
	// time of reception); the purge job runs every PurgeInterval.
	Retention     time.Duration
	PurgeInterval time.Duration

	// Cardinality thresholds of docs/spec/event.md 5.2: the element goes in
	// quarantine when its sketch estimates more distinct values than the
	// threshold.
	KeepDistinct    int // keep: values per (policy, service, op, part, path)
	NameDistinct    int // literal names per (service, op, part, parent path)
	SegmentDistinct int // literal path segments per (service, method, position)
	HostDistinct    int // registrable domains of host:<pattern> services per source
	// HostLabelDistinct: literal host labels per (registrable domain,
	// position) (spec v1.5, k = 50 by default).
	HostLabelDistinct int
	// MaxMonitors bounds the number of cardinality sketches kept (memory
	// bound against a source that invents unbounded field names). Events
	// that would need a new monitor beyond the bound are rejected.
	MaxMonitors int

	// ClockSkew is the tolerance used when comparing event time with policy
	// validity windows (not_after, discovery, automatic words).
	ClockSkew time.Duration

	// OutboxInterval is how often undelivered tokens are retried towards
	// the TokenSink (with exponential backoff up to 30 s on failure).
	OutboxInterval time.Duration
	// IndexTokens maintains the token index (rule mining by token/time).
	IndexTokens bool
	// FlushInterval is how often sketches and per-source counters are
	// persisted.
	FlushInterval time.Duration
	// RewriteChunk is the number of rows rewritten per transaction when a
	// quarantine rewrites stored events.
	RewriteChunk int
}

// DefaultConfig returns the defaults documented in docs/spec/event.md.
func DefaultConfig() Config {
	return Config{
		MaxRequestBytes: 4 << 20, MaxEventBytes: 512 << 10, MaxRecords: 512,
		QueueEvents: 50_000, QueueBytes: 128 << 20, BatchSize: 1000, BatchWait: 20 * time.Millisecond,
		MaxInflightPerSource: 16,
		Retention:            30 * 24 * time.Hour, PurgeInterval: time.Hour,
		KeepDistinct: 50, NameDistinct: 50, SegmentDistinct: 50, HostDistinct: 50, HostLabelDistinct: 50,
		MaxMonitors: 200_000,
		ClockSkew:   5 * time.Minute,
		IndexTokens: true, OutboxInterval: 5 * time.Second, FlushInterval: 30 * time.Second, RewriteChunk: 500,
	}
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("intake: config: "+format, a...)) }
	if c.MaxRequestBytes < 1024 {
		bad("MaxRequestBytes too small")
	}
	if c.MaxEventBytes < 1024 {
		bad("MaxEventBytes too small")
	}
	if c.MaxRecords < 1 {
		bad("MaxRecords must be positive")
	}
	if c.QueueEvents < c.MaxRecords {
		bad("QueueEvents must be at least MaxRecords")
	}
	if c.QueueBytes < c.MaxRequestBytes {
		bad("QueueBytes must be at least MaxRequestBytes")
	}
	if c.BatchSize < 1 || c.BatchWait <= 0 {
		bad("BatchSize and BatchWait must be positive")
	}
	if c.MaxInflightPerSource < 1 {
		bad("MaxInflightPerSource must be positive")
	}
	if c.Retention <= 0 || c.PurgeInterval <= 0 {
		bad("Retention and PurgeInterval must be positive")
	}
	if c.KeepDistinct < 1 || c.NameDistinct < 1 || c.SegmentDistinct < 1 || c.HostDistinct < 1 || c.HostLabelDistinct < 1 {
		bad("cardinality thresholds must be positive")
	}
	if c.MaxMonitors < 1 {
		bad("MaxMonitors must be positive")
	}
	if c.ClockSkew < 0 || c.FlushInterval <= 0 || c.OutboxInterval <= 0 || c.RewriteChunk < 1 {
		bad("ClockSkew, FlushInterval and RewriteChunk are out of range")
	}
	return errors.Join(errs...)
}
