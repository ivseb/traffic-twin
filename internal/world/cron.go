package world

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// cron is a parsed 5-field cron expression (UTC): minute hour day-of-month
// month day-of-week, with *, lists, ranges and steps.
type cron struct {
	min, hour, dom, mon, dow [61]bool
	domAny, dowAny           bool
}

func parseCron(s string) (*cron, error) {
	f := strings.Fields(s)
	if len(f) != 5 {
		return nil, errors.New("schedule must have 5 fields")
	}
	c := &cron{}
	specs := []struct {
		dst    *[61]bool
		lo, hi int
	}{{&c.min, 0, 59}, {&c.hour, 0, 23}, {&c.dom, 1, 31}, {&c.mon, 1, 12}, {&c.dow, 0, 7}}
	for i, sp := range specs {
		if err := cronField(f[i], sp.lo, sp.hi, sp.dst); err != nil {
			return nil, err
		}
	}
	if c.dow[7] {
		c.dow[0] = true
	}
	c.domAny, c.dowAny = f[2] == "*", f[4] == "*"
	return c, nil
}

func cronField(s string, lo, hi int, dst *[61]bool) error {
	for _, part := range strings.Split(s, ",") {
		step := 1
		if a, b, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(b)
			if err != nil || n < 1 {
				return errors.New("bad cron step")
			}
			part, step = a, n
		}
		from, to := lo, hi
		if part != "*" {
			a, b, isRange := strings.Cut(part, "-")
			x, err := strconv.Atoi(a)
			if err != nil {
				return errors.New("bad cron value")
			}
			from, to = x, x
			if isRange {
				if to, err = strconv.Atoi(b); err != nil {
					return errors.New("bad cron range")
				}
			} else if step > 1 {
				to = hi
			}
		}
		if from < lo || to > hi || from > to {
			return errors.New("cron value out of range")
		}
		for v := from; v <= to; v += step {
			dst[v] = true
		}
	}
	return nil
}

func (c *cron) match(t time.Time) bool {
	if !c.min[t.Minute()] || !c.hour[t.Hour()] || !c.mon[int(t.Month())] {
		return false
	}
	dom, dow := c.dom[t.Day()], c.dow[int(t.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	default:
		return dom || dow
	}
}

// ticks returns the instants in [from, to) matching c, minute by minute.
func (c *cron) ticks(from, to time.Time) []time.Time {
	var out []time.Time
	t := from.UTC().Truncate(time.Minute)
	if t.Before(from) {
		t = t.Add(time.Minute)
	}
	for ; t.Before(to); t = t.Add(time.Minute) {
		if c.match(t) {
			out = append(out, t)
		}
	}
	return out
}
