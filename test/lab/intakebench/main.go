// Command intakebench measures how many sanitized events per second tt-core's
// intake accepts. It enrolls N sources (instances of the same service, as in a
// replicated deployment), generates sanitized demo-shop events at a fixed
// rate (real timestamps, unique span ids) and reports what the intake
// acknowledged, rejected and what the sources had to drop because the intake
// could not keep up.
//
// Test tool for the lab (demo host -> a throwaway tt-core on the core host); it is not
// part of the product. Secrets only from the environment / files:
//
//	TT_ENROLL_TOKEN=tte_... intakebench -enroll-url https://core.lab.example:4319 \
//	    -hmac-key-file /opt/tt-lab/secrets/hmac.shop.keys -sources 4 -rates 500,1000,2000,4000 -duration 20s
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ivseb/traffic-twin/internal/core/demosim"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/sourceclient"
)

func main() {
	enroll := flag.String("enroll-url", "", "intake URL of tt-core (https)")
	keyFile := flag.String("hmac-key-file", "", "HMAC key file (kid:base64url lines)")
	service := flag.String("service", "shop-api", "service name requested at enrollment")
	n := flag.Int("sources", 4, "number of enrolled sources (instances)")
	rates := flag.String("rates", "500,1000,2000,4000", "total target events/s, one step per value")
	dur := flag.Duration("duration", 20*time.Second, "duration of each step")
	state := flag.String("state", "", "state directory (default: a temporary one)")
	flag.Parse()
	tok := os.Getenv("TT_ENROLL_TOKEN")
	if *enroll == "" || *keyFile == "" || tok == "" {
		fmt.Fprintln(os.Stderr, "need -enroll-url, -hmac-key-file and TT_ENROLL_TOKEN")
		os.Exit(2)
	}
	kb, err := os.ReadFile(*keyFile)
	must(err)
	keys, err := sanitizer.ParseKeys(string(kb))
	must(err)
	kids := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(kb)), "\n") {
		if k, _, ok := strings.Cut(l, ":"); ok {
			kids = append(kids, k)
		}
	}
	dir := *state
	if dir == "" {
		dir, err = os.MkdirTemp("", "intakebench")
		must(err)
		defer os.RemoveAll(dir)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One simulated day of demo traffic is the pool of exchanges.
	sim := demosim.Run(demosim.Config{Seed: 7, Customers: 400, Days: 1, Start: time.Now().UTC().Truncate(24 * time.Hour)})
	pool := sim.Exchanges()
	fmt.Printf("pool: %d exchanges, %d sources\n", len(pool), *n)

	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	srcs := make([]*sourceclient.Source, *n)
	for i := range srcs {
		s, err := sourceclient.New(sourceclient.Config{
			EnrollURL: *enroll, Token: tok, StateDir: filepath.Join(dir, strconv.Itoa(i)),
			Kind: "sdk-go", Version: "0.1.0", ServiceName: *service, Instance: fmt.Sprintf("bench-%d", i),
			Keys: keys, KeyKids: kids, Logger: quiet,
			Exporter: sourceclient.ExporterOptions{MaxEvents: 20000, BatchEvents: 512, FlushInterval: 200 * time.Millisecond},
		})
		must(err)
		s.Start(ctx)
		srcs[i] = s
	}
	deadline := time.Now().Add(2 * time.Minute)
	for _, s := range srcs {
		for {
			if _, ok := s.Active(); ok {
				break
			}
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr, "source not capturing (state %s): is the policy approved for the group?\n", s.State())
				os.Exit(1)
			}
			s.Kick()
			time.Sleep(200 * time.Millisecond)
		}
	}
	fmt.Println("all sources capturing")

	fmt.Printf("%-10s %-10s %-10s %-10s %-10s %-10s\n", "target/s", "emitted/s", "accepted/s", "rejected", "dropped", "backlog")
	for _, rs := range strings.Split(*rates, ",") {
		rate, err := strconv.Atoi(strings.TrimSpace(rs))
		must(err)
		before := total(srcs)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var emitted int64
		var mu sync.Mutex
		for i, s := range srcs {
			wg.Add(1)
			go func(i int, s *sourceclient.Source) {
				defer wg.Done()
				per := float64(rate) / float64(len(srcs))
				start := time.Now()
				var sent int64
				for j := i; ; j += len(srcs) {
					select {
					case <-stop:
						mu.Lock()
						emitted += sent
						mu.Unlock()
						return
					default:
					}
					// pace: the k-th event is due at k/per seconds
					if due := start.Add(time.Duration(float64(sent) / per * float64(time.Second))); time.Until(due) > 0 {
						time.Sleep(time.Until(due))
					}
					emit(s, &pool[j%len(pool)])
					sent++
				}
			}(i, s)
		}
		time.Sleep(*dur)
		close(stop)
		wg.Wait()
		after := total(srcs)
		// let the queues drain for a moment so "accepted" counts the tail
		time.Sleep(2 * time.Second)
		final := total(srcs)
		sec := dur.Seconds()
		fmt.Printf("%-10d %-10.0f %-10.0f %-10d %-10d %-10d\n", rate, float64(emitted)/sec, float64(after.sent-before.sent)/sec,
			final.rejected-before.rejected, final.dropped-before.dropped, queued(srcs))
	}
	for _, s := range srcs {
		cctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.Close(cctx)
		c()
	}
}

type tot struct{ sent, rejected, dropped int64 }

func total(ss []*sourceclient.Source) tot {
	var t tot
	for _, s := range ss {
		c := s.Counters().Snapshot()
		t.sent += c.EventsSent
		t.rejected += c.EventsRejected
		t.dropped += c.EventsDroppedQueue
	}
	return t
}

func queued(ss []*sourceclient.Source) int {
	q := 0
	for _, s := range ss {
		q += s.Stats().QueueEvents
	}
	return q
}

func emit(s *sourceclient.Source, x *demosim.Exchange) {
	cp, ok := s.Active()
	if !ok {
		return
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	out, err := cp.Engine.Sanitize(&x.Ex, now, x.SampledBy())
	if err != nil {
		return
	}
	var sp [8]byte
	_, _ = rand.Read(sp[:])
	span := hex.EncodeToString(sp[:])
	meta := sanitizer.MetaFromVerified(sanitizer.EventMeta{SourceKind: "sdk-go", SourceVersion: "0.1.0", SourceID: cp.SourceID,
		TS: now, LatencyMS: x.Latency, Status: x.Ex.Status, TraceID: x.Trace, SpanID: span}, cp.Policy)
	ev, err := sanitizer.BuildEvent(meta, out)
	if err != nil {
		return
	}
	s.Emit(sourceclient.Event{JSON: ev, TS: now, TraceID: x.Trace, SpanID: span, PolicyHash: cp.Policy.Hash})
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "intakebench:", err)
		os.Exit(1)
	}
}
