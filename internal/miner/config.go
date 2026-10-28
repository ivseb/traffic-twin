package miner

import (
	"errors"
	"time"
)

// Config tunes the miner. The zero value is not valid: start from
// DefaultConfig.
type Config struct {
	// KMin is the k-anonymity threshold: link keys, rules and outcomes must
	// concern at least KMin distinct subjects (docs/spec/pack.md section 7).
	KMin int
	// MinDistinct is the least number of distinct tokens a location needs to
	// take part in a link key; MinDistinctRatio is the least ratio of
	// distinct tokens to occurrences. Below either the field is treated as
	// low-cardinality and never used as a key (status, currency, ...).
	MinDistinct      int
	MinDistinctRatio float64
	// MinKeyConfidence is the least share of the smaller side's tokens that
	// must be found on the other side for a link key.
	MinKeyConfidence float64
	// MinShare is the least share of instances for a structural finding
	// (an immediate effect, a relation, a selector).
	MinShare float64
	// MaxEvents bounds the events loaded by one run (memory guard).
	MaxEvents int
	// Window is the event-time window of a scheduled run (ending now).
	Window time.Duration
	// BatchSpikeRatio is how many times the mean hourly rate a clock hour
	// must reach on one day to count as a batch run; BatchMinDays is the
	// least share of observed days with a run at that hour.
	BatchSpikeRatio float64
	BatchMinDays    float64
	// StaleDrop is the relative confidence drop that marks an approved rule
	// stale; MinConfidence is the absolute floor.
	StaleDrop     float64
	MinConfidence float64
	// MinHorizon is the least completion horizon of a cause (and so the
	// least traffic coverage a run needs to decide anything): a cause younger
	// than the horizon has no decided outcome yet. Zero means DefaultMinHorizon.
	MinHorizon time.Duration
	// MinBirthShare is the least share of an entity's objects (the tokens
	// seen at the id location of its creator operation) whose creation
	// exchange was captured, judged by the lower bound of a Wilson interval
	// so that a small sample cannot pass by luck. Objects first seen without
	// a creation exchange (app restarts, retention cutoffs, sampling) are
	// "pre-existing": they are not evidence against the entity, only against
	// its completeness, hence this threshold is lower than MinShare.
	MinBirthShare float64
	// StaleRuns is the number of consecutive runs in which an approved rule
	// must fail (confidence drop, rule no longer mined) before it becomes
	// stale. One bad run never marks a rule stale.
	StaleRuns int
	// CandidateMaxEvents bounds the events of a group passed again with a
	// relaxed k to find the candidates below the threshold (rules v1.9,
	// C0); 0 turns the candidates off.
	CandidateMaxEvents int
}

// DefaultMinHorizon is the default Config.MinHorizon.
const DefaultMinHorizon = time.Hour

// Defaults of MinBirthShare and StaleRuns.
const (
	DefaultMinBirthShare = 0.6
	DefaultStaleRuns     = 3
	// DefaultCandidateMaxEvents is the default Config.CandidateMaxEvents.
	DefaultCandidateMaxEvents = 2_000_000
)

// MinCoverage is the least span of observed traffic a run needs to produce
// rules; below it the run reports insufficient data instead of nothing.
func (c Config) MinCoverage() time.Duration {
	if c.MinHorizon <= 0 {
		return DefaultMinHorizon
	}
	return c.MinHorizon
}

// DefaultConfig returns the defaults.
func DefaultConfig() Config {
	return Config{
		KMin:             20,
		MinDistinct:      20,
		MinDistinctRatio: 0.02,
		MinKeyConfidence: 0.5,
		MinShare:         0.9,
		MaxEvents:        5_000_000,
		Window:           14 * 24 * time.Hour,
		BatchSpikeRatio:  4,
		BatchMinDays:     0.5,
		StaleDrop:        0.2,
		MinConfidence:    0.5,
		MinHorizon:       DefaultMinHorizon,
		MinBirthShare:    DefaultMinBirthShare,
		StaleRuns:        DefaultStaleRuns,

		CandidateMaxEvents: DefaultCandidateMaxEvents,
	}
}

// Validate reports an unusable configuration.
func (c Config) Validate() error {
	switch {
	case c.KMin < 1, c.MinDistinct < 1, c.MaxEvents < 1:
		return errors.New("miner: KMin, MinDistinct and MaxEvents must be positive")
	case c.MinDistinctRatio < 0 || c.MinDistinctRatio > 1, c.MinKeyConfidence <= 0 || c.MinKeyConfidence > 1,
		c.MinShare <= 0 || c.MinShare > 1, c.BatchMinDays <= 0 || c.BatchMinDays > 1,
		c.StaleDrop <= 0 || c.StaleDrop >= 1, c.MinConfidence < 0 || c.MinConfidence > 1,
		c.MinBirthShare <= 0 || c.MinBirthShare > 1:
		return errors.New("miner: ratio out of range")
	case c.BatchSpikeRatio <= 1:
		return errors.New("miner: BatchSpikeRatio must exceed 1")
	case c.CandidateMaxEvents < 0:
		return errors.New("miner: CandidateMaxEvents must not be negative")
	case c.StaleRuns < 1:
		return errors.New("miner: StaleRuns must be at least 1")
	case c.Window <= 0:
		return errors.New("miner: Window must be positive")
	}
	return nil
}
