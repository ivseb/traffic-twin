// Package simclock implements the accelerated clock shared by every demo
// process. All processes compute simulated time from the same three inputs,
// so they agree without talking to each other:
//
//	sim = SIM_EPOCH + (realNow - CLOCK_ANCHOR) * TIME_SCALE
//
// TIME_SCALE is simulated seconds per real second (60 = 1 real second is
// 1 simulated minute). CLOCK_ANCHOR is a unix timestamp in seconds; when it
// is empty the start of the current UTC day is used, which every process on
// the same host computes identically. The shop (Node.js) mirrors this logic.
package simclock

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// DefaultEpoch is the simulated time at the anchor: a Monday morning.
const DefaultEpoch = "2026-10-19T06:00:00Z"

// Clock maps real time to simulated time.
type Clock struct {
	Scale  float64
	Epoch  time.Time
	Anchor time.Time
}

// FromEnv builds the clock from TIME_SCALE, SIM_EPOCH and CLOCK_ANCHOR.
func FromEnv() (*Clock, error) {
	c := &Clock{Scale: 60}
	if v := os.Getenv("TIME_SCALE"); v != "" {
		s, err := strconv.ParseFloat(v, 64)
		if err != nil || s <= 0 {
			return nil, fmt.Errorf("invalid TIME_SCALE %q", v)
		}
		c.Scale = s
	}
	epoch := os.Getenv("SIM_EPOCH")
	if epoch == "" {
		epoch = DefaultEpoch
	}
	e, err := time.Parse(time.RFC3339, epoch)
	if err != nil {
		return nil, fmt.Errorf("invalid SIM_EPOCH %q: %w", epoch, err)
	}
	c.Epoch = e.UTC()
	if v := os.Getenv("CLOCK_ANCHOR"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid CLOCK_ANCHOR %q", v)
		}
		c.Anchor = time.Unix(sec, 0).UTC()
	} else {
		now := time.Now().UTC()
		c.Anchor = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	return c, nil
}

// Now returns the current simulated time.
func (c *Clock) Now() time.Time { return c.ToSim(time.Now()) }

// ToSim converts a real instant to simulated time.
func (c *Clock) ToSim(real time.Time) time.Time {
	return c.Epoch.Add(time.Duration(float64(real.Sub(c.Anchor)) * c.Scale)).UTC()
}

// ToReal converts a simulated instant back to real time.
func (c *Clock) ToReal(sim time.Time) time.Time {
	return c.Anchor.Add(time.Duration(float64(sim.Sub(c.Epoch)) / c.Scale))
}

// RealDuration converts a simulated duration to the real time it takes.
func (c *Clock) RealDuration(sim time.Duration) time.Duration {
	return time.Duration(float64(sim) / c.Scale)
}
