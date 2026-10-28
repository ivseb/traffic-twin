package intake

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/ivseb/traffic-twin/internal/event"
)

// ErrBadBatch is returned by [ValidateBatch] for a body that is not an OTLP
// logs request in the shape of docs/spec/event.md 4.2 (the intake answers
// 400 bad_request).
var ErrBadBatch = errors.New("intake: the body is not a valid OTLP logs request")

// Accepted is one log record that passed the stateless checks.
type Accepted struct {
	// Event is the event body (the log record body).
	Event []byte
	// Decoded is the event, decoded and validated against the event schema.
	Decoded *event.Event
}

// ValidateBatch runs, on a decompressed OTLP/JSON logs request, the checks
// of the intake that need no state: the request and log record shape, the
// event decoding (schema, token grammar, canonical bytes), the source
// identity and the agreement of the OTLP envelope with the event (resource
// attributes, trace and span ids, timeUnixNano). It does not look at
// policies, quarantines or quotas, which depend on the running core.
//
// Test doubles of tt-core use it so that an exporter bug the real intake
// would reject (a timestamp precision, a wrong resource attribute) fails in
// their unit tests too. src gives the certificate identity and the service
// assigned at enrollment (empty: not checked).
func ValidateBatch(body []byte, src SourceInfo) (accepted []Accepted, rejected []Reject, err error) {
	var req otlpRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&req); derr != nil || dec.More() {
		return nil, nil, ErrBadBatch
	}
	maxEvent := DefaultConfig().MaxEventBytes
	for i := range req.ResourceLogs {
		rl := &req.ResourceLogs[i]
		res := parseResource(rl.Resource.Attributes)
		resOK := res.ok && rl.Resource.DroppedAttributesCount == 0 && rl.SchemaURL == ""
		for j := range rl.ScopeLogs {
			sl := &rl.ScopeLogs[j]
			scopeOK := sl.Scope.Name == "traffic-twin" && len(sl.Scope.Attributes) == 0 && sl.Scope.DroppedAttributesCount == 0 && sl.SchemaURL == ""
			for k := range sl.LogRecords {
				rec := &sl.LogRecords[k]
				if !resOK || !scopeOK || rec.Body.StringValue == nil || !recordShapeOK(rec) {
					rejected = append(rejected, Reject{ReasonOTLPShape, "log record outside the shape of docs/spec/event.md 4.2"})
					continue
				}
				raw := *rec.Body.StringValue
				if len(raw) > maxEvent {
					rejected = append(rejected, Reject{ReasonTooLarge, "event larger than 512 KiB"})
					continue
				}
				ev, derr := event.Decode([]byte(raw))
				if derr != nil {
					rejected = append(rejected, rejectOf(derr))
					continue
				}
				if r := crossCheck(&src, &res, sl.Scope.Version, rec, ev); r.Reason != ReasonNone {
					rejected = append(rejected, r)
					continue
				}
				if ev.Source.ID != src.ID {
					rejected = append(rejected, Reject{ReasonSourceMismatch, "source.id differs from the certificate identity"})
					continue
				}
				accepted = append(accepted, Accepted{Event: []byte(raw), Decoded: ev})
			}
		}
	}
	return accepted, rejected, nil
}
