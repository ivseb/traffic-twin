package mock

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// cronSpec is a 5-field cron expression evaluated in UTC (minute hour
// day-of-month month day-of-week). Names are not supported, matching the
// rules schema (digits and * , - / only).
type cronSpec struct {
	minute, hour, dom, month, dow uint64
	domStar, dowStar              bool
}

func parseCron(expr string) (*cronSpec, error) {
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("cron %q: want 5 fields", expr)
	}
	var c cronSpec
	var err error
	if c.minute, _, err = parseCronField(f[0], 0, 59); err != nil {
		return nil, err
	}
	if c.hour, _, err = parseCronField(f[1], 0, 23); err != nil {
		return nil, err
	}
	if c.dom, c.domStar, err = parseCronField(f[2], 1, 31); err != nil {
		return nil, err
	}
	if c.month, _, err = parseCronField(f[3], 1, 12); err != nil {
		return nil, err
	}
	if c.dow, c.dowStar, err = parseCronField(f[4], 0, 7); err != nil {
		return nil, err
	}
	if c.dow&(1<<7) != 0 { // 7 is Sunday too
		c.dow |= 1
	}
	return &c, nil
}

func parseCronField(s string, lo, hi int) (mask uint64, star bool, err error) {
	for _, part := range strings.Split(s, ",") {
		rng, stepStr, hasStep := strings.Cut(part, "/")
		step := 1
		if hasStep {
			step, err = strconv.Atoi(stepStr)
			if err != nil || step < 1 {
				return 0, false, fmt.Errorf("cron field %q: bad step", s)
			}
		}
		a, b := lo, hi
		switch {
		case rng == "*":
			if !hasStep && len(strings.Split(s, ",")) == 1 {
				star = true
			}
		case strings.Contains(rng, "-"):
			x, y, _ := strings.Cut(rng, "-")
			if a, err = strconv.Atoi(x); err != nil {
				return 0, false, fmt.Errorf("cron field %q: bad range", s)
			}
			if b, err = strconv.Atoi(y); err != nil {
				return 0, false, fmt.Errorf("cron field %q: bad range", s)
			}
		default:
			if a, err = strconv.Atoi(rng); err != nil {
				return 0, false, fmt.Errorf("cron field %q: bad value", s)
			}
			if hasStep {
				b = hi
			} else {
				b = a
			}
		}
		if a < lo || b > hi || a > b {
			return 0, false, fmt.Errorf("cron field %q: out of range", s)
		}
		for v := a; v <= b; v += step {
			mask |= 1 << uint(v)
		}
	}
	return mask, star, nil
}

func (c *cronSpec) dayMatches(t time.Time) bool {
	if c.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domOK := c.dom&(1<<uint(t.Day())) != 0
	dowOK := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return dowOK
	case c.dowStar:
		return domOK
	default:
		return domOK || dowOK // classic cron: either restriction may match
	}
}

// next returns the first schedule instant strictly after t (UTC), or false
// when none exists within about 9 years.
func (c *cronSpec) next(t time.Time) (time.Time, bool) {
	t = t.UTC().Truncate(time.Minute)
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	for i := 0; i < 366*9; i++ {
		d := day.AddDate(0, 0, i)
		if !c.dayMatches(d) {
			continue
		}
		for h := 0; h < 24; h++ {
			if c.hour&(1<<uint(h)) == 0 {
				continue
			}
			for m := 0; m < 60; m++ {
				if c.minute&(1<<uint(m)) == 0 {
					continue
				}
				cand := d.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute)
				if cand.After(t) {
					return cand, true
				}
			}
		}
	}
	return time.Time{}, false
}
