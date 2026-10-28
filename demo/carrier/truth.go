package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"time"
)

//go:embed truth.json
var defaultTruth []byte

// Duration is a time.Duration that reads and writes "90m"-style strings.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Range is a uniform distribution of simulated delays.
type Range struct {
	Min Duration `json:"min"`
	Max Duration `json:"max"`
}

func (r Range) draw(rng *rand.Rand) time.Duration {
	span := int64(r.Max.Duration - r.Min.Duration)
	if span <= 0 {
		return r.Min.Duration
	}
	return r.Min.Duration + time.Duration(rng.Int64N(span+1))
}

// LatencyDist is a log-normal latency distribution, in real milliseconds.
type LatencyDist struct {
	MedianMs float64 `json:"median_ms"`
	Sigma    float64 `json:"sigma"`
	MaxMs    int     `json:"max_ms"`
}

// Truth is the ground-truth behaviour of the carrier. It is the single
// source of every probability and delay the miner must rediscover.
type Truth struct {
	Seed     uint64 `json:"seed"`
	Outcomes struct {
		Happy        float64 `json:"happy"`
		Cancelled    float64 `json:"cancelled"`
		NeverShipped float64 `json:"never_shipped"`
	} `json:"outcomes"`
	Delays struct {
		Created   Range `json:"created"`
		InTransit Range `json:"in_transit"`
		Delivered Range `json:"delivered"`
		Cancelled Range `json:"cancelled"`
	} `json:"delays"`
	EtaPresence   float64  `json:"eta_presence"`
	CancelReasons []string `json:"cancel_reasons"`
	Faults        struct {
		UnavailableP float64 `json:"unavailable_p"`
		Status       int     `json:"status"`
		Code         string  `json:"code"`
	} `json:"faults"`
	Latency map[string]LatencyDist `json:"latency"`
	Batch   struct {
		AtUTC    string  `json:"at_utc"`
		Fraction float64 `json:"fraction"`
		From     string  `json:"from"`
		To       string  `json:"to"`
	} `json:"batch"`
}

// loadTruth reads TRUTH_FILE if set, otherwise the embedded truth.json.
// SEED overrides the seed of the file.
func loadTruth() (*Truth, error) {
	raw := defaultTruth
	if p := os.Getenv("TRUTH_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var t Truth
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("truth: %w", err)
	}
	if v := os.Getenv("SEED"); v != "" {
		if _, err := fmt.Sscan(v, &t.Seed); err != nil {
			return nil, fmt.Errorf("invalid SEED %q", v)
		}
	}
	sum := t.Outcomes.Happy + t.Outcomes.Cancelled + t.Outcomes.NeverShipped
	if sum < 0.999 || sum > 1.001 {
		return nil, fmt.Errorf("truth: outcome probabilities sum to %.3f", sum)
	}
	if _, err := time.Parse("15:04", t.Batch.AtUTC); err != nil {
		return nil, fmt.Errorf("truth: batch.at_utc: %w", err)
	}
	return &t, nil
}
