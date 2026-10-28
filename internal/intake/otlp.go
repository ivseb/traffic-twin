package intake

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/event"
	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Path is where the OTLP logs endpoint is mounted (docs/spec/event.md 4.1).
const Path = "/v1/logs"

// Mount serves the OTLP endpoint on the intake listener of srv, which
// requires a verified client certificate.
func (in *Intake) Mount(srv *server.Server) {
	srv.MountIntake(Path, in.Handler())
}

// SourceIDFromCert returns the enrollment id carried by a client
// certificate: the subject alternative name (a DNS name or a URI whose last
// path segment is the id) that has the form src-<alnum>. The certificate is
// refused if it carries none or more than one distinct id. The subject
// common name is never used.
func SourceIDFromCert(cert *x509.Certificate) (string, bool) {
	var id string
	set := func(c string) bool {
		if !event.ValidSourceID(c) {
			return true
		}
		if id != "" && id != c {
			return false
		}
		id = c
		return true
	}
	for _, d := range cert.DNSNames {
		if !set(d) {
			return "", false
		}
	}
	for _, u := range cert.URIs {
		c := u.Opaque
		if c == "" {
			c = u.Path[strings.LastIndexByte(u.Path, '/')+1:]
		}
		if c == "" {
			c = u.Host
		}
		if !set(c) {
			return "", false
		}
	}
	return id, id != ""
}

// OTLP/JSON request, restricted to the fields of docs/spec/event.md 4.2.
// Unknown fields are rejected: they would be another channel for data.
type otlpRequest struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type kvPair struct {
	Key   string `json:"key"`
	Value struct {
		StringValue *string `json:"stringValue"`
	} `json:"value"`
}

type resourceLogs struct {
	Resource struct {
		Attributes             []kvPair `json:"attributes"`
		DroppedAttributesCount int      `json:"droppedAttributesCount"`
	} `json:"resource"`
	ScopeLogs []scopeLogs `json:"scopeLogs"`
	SchemaURL string      `json:"schemaUrl"`
}

type scopeLogs struct {
	Scope struct {
		Name                   string   `json:"name"`
		Version                string   `json:"version"`
		Attributes             []kvPair `json:"attributes"`
		DroppedAttributesCount int      `json:"droppedAttributesCount"`
	} `json:"scope"`
	LogRecords []logRecord `json:"logRecords"`
	SchemaURL  string      `json:"schemaUrl"`
}

type logRecord struct {
	TimeUnixNano         string   `json:"timeUnixNano"`
	ObservedTimeUnixNano string   `json:"observedTimeUnixNano"`
	SeverityNumber       int      `json:"severityNumber"`
	SeverityText         string   `json:"severityText"`
	EventName            string   `json:"eventName"`
	TraceID              string   `json:"traceId"`
	SpanID               string   `json:"spanId"`
	Attributes           []kvPair `json:"attributes"`
	Body                 struct {
		StringValue *string `json:"stringValue"`
	} `json:"body"`
	DroppedAttributesCount int `json:"droppedAttributesCount"`
	Flags                  int `json:"flags"`
}

type partialSuccess struct {
	RejectedLogRecords string `json:"rejectedLogRecords"`
	ErrorMessage       string `json:"errorMessage"`
}

type otlpResponse struct {
	PartialSuccess *partialSuccess `json:"partialSuccess,omitempty"`
}

// resourceInfo are the validated resource attributes of a resourceLogs.
type resourceInfo struct {
	ok          bool
	serviceName string
	kind        string
	version     string
	sourceID    string
}

func parseResource(attrs []kvPair) resourceInfo {
	var r resourceInfo
	if len(attrs) != 4 {
		return r
	}
	seen := 0
	for _, a := range attrs {
		if a.Value.StringValue == nil {
			return resourceInfo{}
		}
		v := *a.Value.StringValue
		switch a.Key {
		case "service.name":
			r.serviceName = v
			seen |= 1
		case "tt.source.kind":
			r.kind = v
			seen |= 2
		case "tt.source.version":
			r.version = v
			seen |= 4
		case "tt.source.id":
			r.sourceID = v
			seen |= 8
		default:
			return resourceInfo{}
		}
	}
	r.ok = seen == 15
	return r
}

// Handler returns the OTLP/HTTP logs endpoint (POST /v1/logs). It must be
// served on a listener that verifies client certificates ([Intake.Mount]
// does); the handler itself refuses requests without a verified certificate.
func (in *Intake) Handler() http.Handler {
	return http.HandlerFunc(in.serveLogs)
}

func (in *Intake) failRequest(w http.ResponseWriter, status int, code, msg string) {
	in.stats.global.badRequests.Add(1)
	httpx.WriteError(w, status, code, msg)
}

func (in *Intake) pushBack(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Retry-After", strconv.Itoa(in.retryAfter()))
	if status == http.StatusTooManyRequests {
		in.stats.global.throttled.Add(1)
	} else {
		in.stats.global.unavailable.Add(1)
	}
	httpx.WriteError(w, status, code, msg)
}

func (in *Intake) serveLogs(w http.ResponseWriter, r *http.Request) {
	g := &in.stats.global
	g.requests.Add(1)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		in.failRequest(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
		return
	}
	if in.closed.Load() || in.writer.failing.Load() {
		in.pushBack(w, http.StatusServiceUnavailable, "unavailable", "the intake cannot store events right now")
		return
	}

	// Identity: the verified client certificate, then the source registry.
	cert := server.PeerCertificate(r)
	if cert == nil {
		in.failRequest(w, http.StatusForbidden, "client_certificate_required", "a verified client certificate is required")
		return
	}
	certID, ok := SourceIDFromCert(cert)
	if !ok {
		in.failRequest(w, http.StatusUnauthorized, "no_source_identity", "the client certificate carries no source identity")
		return
	}
	src, ok := in.sources.LookupSource(certID)
	if !ok {
		in.failRequest(w, http.StatusUnauthorized, "unknown_source", "unknown source")
		return
	}
	if src.Revoked {
		in.failRequest(w, http.StatusForbidden, "source_revoked", "source revoked")
		return
	}
	sc := in.stats.source(src.ID)
	sc.requests.Add(1)
	sc.lastSeen.Store(in.now().UnixMilli())
	if sc.inflight.Add(1) > int32(in.cfg.MaxInflightPerSource) {
		sc.inflight.Add(-1)
		in.pushBack(w, http.StatusTooManyRequests, "too_many_requests", "too many concurrent requests from this source")
		return
	}
	defer sc.inflight.Add(-1)

	// Backpressure before doing any work.
	if in.full() {
		in.pushBack(w, http.StatusTooManyRequests, "overloaded", "ingestion queue full")
		return
	}

	// Headers.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		in.failRequest(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	gz := false
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz = true
	default:
		in.failRequest(w, http.StatusUnsupportedMediaType, "unsupported_encoding", "Content-Encoding must be gzip or absent")
		return
	}

	// Body, bounded before and after decompression.
	max := in.cfg.MaxRequestBytes
	if r.ContentLength > max {
		in.failRequest(w, http.StatusRequestEntityTooLarge, "request_too_large", "request larger than 4 MiB")
		return
	}
	body, err := readLimited(http.MaxBytesReader(w, r.Body, max), max)
	if err != nil {
		in.failRequest(w, http.StatusRequestEntityTooLarge, "request_too_large", "request larger than 4 MiB")
		return
	}
	if gz {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			in.failRequest(w, http.StatusBadRequest, "bad_gzip", "invalid gzip body")
			return
		}
		body, err = readLimited(zr, max)
		if err != nil {
			if errors.Is(err, errTooLarge) {
				in.failRequest(w, http.StatusRequestEntityTooLarge, "request_too_large", "request larger than 4 MiB before compression")
			} else {
				in.failRequest(w, http.StatusBadRequest, "bad_gzip", "invalid gzip body")
			}
			return
		}
	}
	sc.bytes.Add(uint64(len(body)))

	var req otlpRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		in.failRequest(w, http.StatusBadRequest, "bad_request", "the body is not a valid OTLP logs request")
		return
	}
	n := 0
	var sumBytes int64
	for i := range req.ResourceLogs {
		for j := range req.ResourceLogs[i].ScopeLogs {
			for k := range req.ResourceLogs[i].ScopeLogs[j].LogRecords {
				n++
				if b := req.ResourceLogs[i].ScopeLogs[j].LogRecords[k].Body.StringValue; b != nil {
					sumBytes += int64(len(*b))
				}
			}
		}
	}
	if n > in.cfg.MaxRecords {
		in.failRequest(w, http.StatusRequestEntityTooLarge, "too_many_records", "more than 512 log records in one request")
		return
	}
	if n == 0 {
		writeOTLP(w, 0)
		return
	}
	if !in.reserve(n, sumBytes) {
		in.pushBack(w, http.StatusTooManyRequests, "overloaded", "ingestion queue full")
		return
	}

	accepted, rejected := 0, 0
	for i := range req.ResourceLogs {
		rl := &req.ResourceLogs[i]
		res := parseResource(rl.Resource.Attributes)
		resOK := res.ok && rl.Resource.DroppedAttributesCount == 0 && rl.SchemaURL == ""
		for j := range rl.ScopeLogs {
			sl := &rl.ScopeLogs[j]
			scopeOK := sl.Scope.Name == "traffic-twin" && len(sl.Scope.Attributes) == 0 && sl.Scope.DroppedAttributesCount == 0 && sl.SchemaURL == ""
			for k := range sl.LogRecords {
				rec := &sl.LogRecords[k]
				var rej Reject
				var size int64
				if rec.Body.StringValue != nil {
					size = int64(len(*rec.Body.StringValue))
				}
				switch {
				case !resOK || !scopeOK || rec.Body.StringValue == nil || !recordShapeOK(rec):
					rej = Reject{ReasonOTLPShape, "log record outside the shape of docs/spec/event.md 4.2"}
				default:
					rej = in.ingest(r.Context(), &src, *rec.Body.StringValue, func(ev *event.Event) Reject {
						return crossCheck(&src, &res, sl.Scope.Version, rec, ev)
					})
				}
				if rej.Reason != ReasonNone {
					rejected++
					in.release(1, size)
					in.countReject(sc, rej.Reason)
					continue
				}
				accepted++
			}
		}
	}
	if accepted > 0 {
		sc.accepted.Add(uint64(accepted))
		sc.dirty.Store(true)
	}
	writeOTLP(w, rejected)
}

var errTooLarge = errors.New("too large")

// readLimited reads at most max bytes and fails with errTooLarge beyond.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, max+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errTooLarge
		}
		return nil, err
	}
	if n > max {
		return nil, errTooLarge
	}
	return buf.Bytes(), nil
}

func writeOTLP(w http.ResponseWriter, rejected int) {
	resp := otlpResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &partialSuccess{RejectedLogRecords: strconv.Itoa(rejected), ErrorMessage: "some log records were rejected"}
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// recordShapeOK checks the fixed fields of a log record (event.md 4.2).
func recordShapeOK(rec *logRecord) bool {
	if rec.EventName != "tt.http.exchange" || rec.SeverityNumber != 9 || rec.SeverityText != "INFO" ||
		rec.DroppedAttributesCount != 0 || rec.Flags != 0 {
		return false
	}
	if rec.ObservedTimeUnixNano != "" && !digits(rec.ObservedTimeUnixNano, 19) {
		return false
	}
	if !digits(rec.TimeUnixNano, 19) {
		return false
	}
	if len(rec.Attributes) != 2 {
		return false
	}
	return true
}

func digits(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// crossCheck compares the OTLP envelope with the decoded event: whatever the
// envelope carries beyond the event is either redundant (and must agree) or
// a possible side channel (and is refused).
func crossCheck(src *SourceInfo, res *resourceInfo, scopeVersion string, rec *logRecord, ev *event.Event) Reject {
	if res.sourceID != ev.Source.ID || res.kind != ev.Source.Kind || res.version != ev.Source.Version || scopeVersion != ev.Source.Version {
		return Reject{ReasonResourceMismatch, "resource attributes differ from the event source"}
	}
	if src.ServiceName != "" && res.serviceName != src.ServiceName {
		return Reject{ReasonResourceMismatch, "service.name differs from the service assigned at enrollment"}
	}
	var gotSchema, gotHash bool
	for _, a := range rec.Attributes {
		if a.Value.StringValue == nil {
			return Reject{ReasonOTLPShape, "attribute without string value"}
		}
		switch a.Key {
		case "tt.schema":
			if *a.Value.StringValue != event.Schema {
				return Reject{ReasonResourceMismatch, "tt.schema differs from the event"}
			}
			gotSchema = true
		case "tt.policy.hash":
			if *a.Value.StringValue != ev.Policy.Hash {
				return Reject{ReasonResourceMismatch, "tt.policy.hash differs from the event"}
			}
			gotHash = true
		default:
			return Reject{ReasonOTLPShape, "unexpected log record attribute"}
		}
	}
	if !gotSchema || !gotHash {
		return Reject{ReasonOTLPShape, "missing log record attribute"}
	}
	if rec.TraceID != ev.TraceID || rec.SpanID != ev.SpanID {
		return Reject{ReasonResourceMismatch, "traceId or spanId differ from the event"}
	}
	if rec.TimeUnixNano != strconv.FormatInt(ev.Time.UnixMilli()*1_000_000, 10) {
		return Reject{ReasonResourceMismatch, "timeUnixNano differs from the event ts"}
	}
	return Reject{}
}
