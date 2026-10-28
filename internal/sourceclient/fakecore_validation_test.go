package sourceclient_test

import (
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/sourceclient/fakecore"
)

// Regression for the lab finding P1: sources keep nanosecond clocks, the
// event "ts" has millisecond precision and the real intake compares
// timeUnixNano with it. The fake core runs the intake's stateless checks, so
// an exporter that sends the nanosecond clock is rejected here too.
func TestExporterBatchPassesTheIntakeChecks(t *testing.T) {
	core := fakecore.New(t, "shop")
	s := exporterBatchSource(t, core, 3)
	for i := 0; i < 3; i++ {
		ev := fakecore.SampleEvent(s.Identity().SourceID, "egress", "0.1.0", time.Now())
		// the source's clock has sub-millisecond precision, the event JSON does not
		ev.TS = ev.TS.Add(time.Duration(123_456+i) * time.Nanosecond)
		s.Emit(ev)
	}
	core.WaitEvents(3, 5*time.Second)
	counterIs(t, core, "events sent", &s.Counters().EventsSent, 3)
	if got := core.RejectedByIntake(); len(got) != 0 {
		t.Fatalf("the intake would reject the exporter's batch: %v %v", got, core.RejectDetails())
	}
	if c := s.Counters().Snapshot(); c.EventsRejected != 0 {
		t.Fatalf("counters = %+v", c)
	}
}
