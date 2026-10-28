package mock

import (
	"encoding/json"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/sanitizer"
	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

var sessionIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

const (
	hdrSession     = "X-TT-Session"
	hdrVirtualTime = "X-TT-Virtual-Time"
	hdrUnmatched   = "X-TT-Unmatched"
	svcPrefix      = "/__svc/"
)

// tlsFatalAlert is a TLS record carrying a fatal handshake_failure alert.
var tlsFatalAlert = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

// inbound is a data-plane request after reading its body.
type inbound struct {
	method   string
	host     string
	escPath  string
	rawQuery string
	header   http.Header
	body     []byte
	// the XML body, parsed once (soap.go)
	xmlDoc *sanitizer.XMLDoc
	xmlErr error
}

// result is what the data plane writes back.
type result struct {
	status  int
	header  http.Header
	body    []byte
	latency time.Duration
	netErr  string
}

func (m *Mock) serveData(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get(hdrSession)
	var sess *session
	if sid == "" {
		// X-TT-Session wins; without it the caller's identity, when
		// configured, chooses the session (docs/spec/mock.md 2.6).
		s, isid, err := m.identitySession(r)
		if err != nil {
			writeError(w, http.StatusTooManyRequests, "too_many_sessions", "session limit reached; delete unused sessions")
			return
		}
		if s != nil {
			sess, sid = s, isid
		} else {
			sid = defaultSession
		}
	}
	if !sessionIDRE.MatchString(sid) {
		writeError(w, http.StatusBadRequest, "bad_session_id", "X-TT-Session is malformed")
		return
	}
	if sess == nil {
		sess = m.lookup(sid)
	}
	if sess == nil {
		writeError(w, http.StatusNotFound, "session_not_found", "unknown session")
		return
	}
	// Go moves the Host header out of r.Header; put it back so lookups by
	// header name (rules, contract parameters) see it like a real server would.
	if r.Host != "" && r.Header.Get("Host") == "" {
		r.Header.Set("Host", r.Host)
	}
	in := &inbound{method: r.Method, host: r.Host, escPath: r.URL.EscapedPath(), rawQuery: r.URL.RawQuery, header: r.Header}
	if in.escPath == "" {
		in.escPath = "/"
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, m.cfg.MaxBodyBytes))
	if err != nil {
		sess.recordRejected(in, "payload_too_large", http.StatusRequestEntityTooLarge)
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "request body is too large")
		return
	}
	in.body = body
	res := sess.handle(in)

	if res.latency > 0 && m.cfg.Latency == LatencyReal {
		t := time.NewTimer(res.latency)
		select {
		case <-t.C:
		case <-r.Context().Done():
			t.Stop()
			return
		}
	}
	if res.netErr != "" {
		m.failConnection(w, r, res.netErr)
		return
	}
	for k, v := range res.header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.status)
	if len(res.body) > 0 && r.Method != http.MethodHead {
		_, _ = w.Write(res.body)
	}
}

// failConnection simulates a network failure (docs/spec/mock.md section 4).
func (m *Mock) failConnection(w http.ResponseWriter, r *http.Request, kind string) {
	switch kind {
	case "timeout":
		if m.cfg.Latency == LatencyReal {
			t := time.NewTimer(m.cfg.NetTimeout)
			defer t.Stop()
			select {
			case <-t.C:
			case <-r.Context().Done():
			}
		}
		dropConnection(w, nil, false)
	case "reset", "refused", "dns":
		dropConnection(w, nil, true)
	case "tls":
		dropConnection(w, tlsFatalAlert, false)
	default: // other
		dropConnection(w, nil, false)
	}
}

// dropConnection takes over the connection, optionally writes raw bytes, and
// closes it: with RST (linger 0) or a normal FIN. Where the connection cannot
// be taken over (HTTP/2) the handler aborts, which resets the stream.
func dropConnection(w http.ResponseWriter, raw []byte, rst bool) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			if len(raw) > 0 {
				_, _ = conn.Write(raw)
			}
			if tc, ok := conn.(*net.TCPConn); ok && rst {
				_ = tc.SetLinger(0)
			}
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// handle serves one data-plane call inside the session and journals it.
func (s *session) handle(in *inbound) *result {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.newEntry(in)
	res := s.dispatch(in, e)
	res.header.Set(hdrSession, s.id)
	res.header.Set(hdrVirtualTime, fmtTime(s.now))
	if res.netErr == "" {
		st := res.status
		e.Status = &st
		e.Response = map[string]any{"headers": recordedResponseHeaders(res.header)}
		if k := synthdoc.KindOfMedia(res.header.Get("Content-Type")); k != "" && len(res.body) > 0 {
			// a synthetic document: its description, not its bytes
			e.Response["body"] = "synthetic " + k + " document, " + strconv.Itoa(len(res.body)) + " bytes"
		} else if b := journalBody(res.body); b != nil {
			e.Response["body"] = b
		}
	}
	s.appendJournal(e)
	return res
}

func (s *session) newEntry(in *inbound) *journalEntry {
	e := &journalEntry{
		At: fmtTime(s.now), Wall: wallNow(s.m), Method: in.method, Path: in.escPath, Query: in.rawQuery,
		Request: map[string]any{},
	}
	if h := recordedRequestHeaders(in.header, s.m.identityHeader()); len(h) > 0 {
		e.Request["headers"] = h
	}
	if b := journalBody(in.body); b != nil {
		e.Request["body"] = b
	}
	return e
}

// recordRejected journals a call refused before dispatch (body too large).
func (s *session) recordRejected(in *inbound, reason string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.newEntry(in)
	if svc, _ := s.m.model.resolveService(in.escPath, in.host); svc != nil {
		e.Service = strp(svc.name)
	}
	e.Reason = reason
	e.Status = &status
	e.Response = map[string]any{}
	s.appendJournal(e)
}

func (s *session) dispatch(in *inbound, e *journalEntry) *result {
	mod := s.m.model
	svc, path := mod.resolveService(in.escPath, in.host)
	if svc == nil {
		return s.unmatched(e, "no-service", http.StatusNotFound, "no service matches the Host header or the /__svc/ prefix")
	}
	e.Service = strp(svc.name)
	// GraphQL endpoints first (graphql.go, docs/spec/mock.md 7).
	gq := s.graphqlRoute(svc, in, path, e)
	if gq != nil && gq.res != nil {
		return gq.res
	}
	// SOAP and XML endpoints with logical operations (soap.go, mock.md 10).
	var sq *soapCall
	if gq == nil {
		if sq = s.soapRoute(svc, in, path, e); sq != nil && sq.res != nil {
			return sq.res
		}
	}
	op, params, allowed := svc.c.match(in.method, path)
	if gq != nil {
		in, path = gq.in, gq.path
		op, params, allowed = gq.op, graphqlParams(gq.vars), nil
	}
	if sq != nil {
		path = sq.path
		op, params, allowed = sq.op, map[string]string{}, nil
	}
	if op == nil {
		e.NearestOp = svc.c.nearest(in.method, path)
		if len(allowed) > 0 {
			res := s.unmatched(e, "no-operation", http.StatusMethodNotAllowed, "method not allowed for this path")
			res.header.Set("Allow", strings.Join(allowed, ", "))
			return res
		}
		return s.unmatched(e, "no-operation", http.StatusNotFound, "no operation matches this method and path")
	}
	e.Op = strp(op.key)
	q, _ := url.ParseQuery(in.rawQuery)

	reqBody, viol := s.validateRequest(svc, op, params, q, in)
	if viol != nil {
		return s.invalid(e, svc, op, viol)
	}
	if gq != nil {
		reqBody = gq.reqBody
	}
	params = s.bodyParams(svc, op, params, reqBody)
	e.Matched = true

	b := s.newBuilder(svc, in, path)
	b.doc = func() synthdoc.Text { return s.docText(params) }
	d := s.decideFault(svc, op.key)
	if d.rule == "" && !(s.faults.Mode == "custom" && (d.status != 0 || d.netErr != "")) {
		// rules v1.8: a counter per key answers before the observed faults.
		exReq := &exchange{reqBody: reqBody, pathParams: params, query: q, reqHeader: in.header}
		if ud, rule, ok := s.untilFor(svc, op.key); ok {
			// rules v1.9: a precondition not yet lifted answers before the
			// counters.
			ud.latencyMs, ud.rule = d.latencyMs, rule
			d = ud
		} else if ld, rule, ok := s.limitFor(svc, op.key, exReq); ok {
			ld.latencyMs, ld.rule = d.latencyMs, rule
			d = ld
		}
	}
	if d.kind() != "" {
		f := map[string]any{}
		if d.status != 0 {
			f["status"] = d.status
		}
		if d.netErr != "" {
			f["net_error"] = d.netErr
		}
		if d.latencyMs > 0 {
			f["latency_ms"] = d.latencyMs
		}
		if d.rule != "" {
			f["rule"] = d.rule
		}
		e.Fault = f
	}
	latency := time.Duration(d.latencyMs) * time.Millisecond
	if d.netErr != "" {
		return &result{header: http.Header{}, netErr: d.netErr, latency: latency}
	}

	// docs/spec/rules.md section 6: decide the response; create the entity;
	// first draft; rules fire (bind from the draft) and their immediate effects
	// apply; rebuild the body when something changed.
	var status int
	var body any
	hdr := http.Header{}
	var render func() (int, any)
	if d.status != 0 {
		status = d.status
		if d.body != nil {
			body = cloneJSON(d.body) // typed by a person (mock.md 4.1)
		} else {
			body = s.errorBody(op, status, d.example, b, "")
		}
	} else {
		render = s.prepare(svc, op, params, q, in, reqBody, b, hdr)
		s.lastOV = optVal{}
		status, body = render()
		s.noteCall(svc, op.key, status)
		body = s.finishBody(svc, op, status, body, s.lastOV, params, q, in.header)
	}
	ex := &exchange{reqBody: reqBody, pathParams: params, query: q, reqHeader: in.header, respBody: body, respHeader: hdr}
	trig, changed := s.fire(svc, op.key, status, ex)
	e.Triggered = trig
	if changed && render != nil {
		s.lastOV = optVal{}
		status, body = render()
		body = s.finishBody(svc, op, status, body, s.lastOV, params, q, in.header)
	}
	if d.status == 0 && status >= 200 && status < 300 {
		s.pageLinks(svc, op, in, body) // third-party pages (mock.md 9)
	}

	res := &result{status: status, header: hdr, latency: latency}
	if body != nil && status != http.StatusNoContent {
		hdr.Set("Content-Type", "application/json")
		res.body = compactJSON(body)
	} else if r := op.responses[status]; body == nil && r != nil && r.doc != nil && status != http.StatusNoContent {
		res.body = s.documentResponse(r, hdr, s.docText(params))
	}
	if gq != nil {
		s.graphqlFinish(svc, gq, res, status, body)
	} else if x := op.xmlFor(status); x != nil {
		var typed any
		if d.status != 0 {
			typed = d.body
		}
		s.xmlFinish(op, x, res, status, body, typed, d.status != 0)
	}
	return res
}

func (s *session) unmatched(e *journalEntry, reason string, status int, msg string) *result {
	e.Matched = false
	e.Reason = reason
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set(hdrUnmatched, reason)
	return &result{status: status, header: hdr, body: compactJSON(errorEnvelope(reason, msg, ""))}
}

// invalid answers a request that violates the contract: with the 400 (or 422)
// response of the operation when it declares one, otherwise the envelope.
func (s *session) invalid(e *journalEntry, svc *service, op *operation, v *violation) *result {
	e.Matched = false
	e.Reason = "invalid-request"
	e.Pointer = v.ptr
	hdr := http.Header{}
	hdr.Set(hdrUnmatched, "invalid-request")
	hdr.Set("Content-Type", "application/json")
	for _, st := range []int{400, 422} {
		if r := op.responses[st]; r != nil {
			b := &builder{sc: svc.c.sc, now: s.now, seed: s.seed, key: op.key, prefixes: s.m.model.prefixesOf(svc.name), fmts: s.m.model.fmts}
			body := s.errorBody(op, st, "", b, "")
			res := &result{status: st, header: hdr}
			if body != nil {
				res.body = compactJSON(body)
			}
			if x := op.xmlFor(st); x != nil {
				s.xmlFinish(op, x, res, st, body, nil, true)
			}
			return res
		}
	}
	if x := op.xmlDefault(); x != nil {
		// a SOAP Fault (or an <error> element) the mock raises itself
		res := s.protocolFault(x, "invalid-request", v.msg, v.ptr)
		return res
	}
	return &result{status: http.StatusBadRequest, header: hdr, body: compactJSON(errorEnvelope("invalid-request", v.msg, v.ptr))}
}

func errorEnvelope(code, msg, pointer string) map[string]any {
	m := map[string]any{"code": code, "message": msg}
	if pointer != "" {
		m["pointer"] = pointer
	}
	return m
}

func strp(s string) *string { return &s }

// resolveService picks the service by "/__svc/{name}" path prefix, else by
// Host. It returns the path to match against the contract.
func (m *model) resolveService(escPath, host string) (*service, string) {
	if strings.HasPrefix(escPath, svcPrefix) {
		rest := escPath[len(svcPrefix):]
		name, tail, _ := strings.Cut(rest, "/")
		if n, err := url.PathUnescape(name); err == nil {
			name = n
		}
		svc := m.byName[name]
		if svc == nil {
			svc = m.byHost[strings.ToLower(name)]
		}
		if svc == nil {
			return nil, escPath
		}
		return svc, "/" + tail
	}
	return m.serviceForHost(host), escPath
}

// ---- validation ----

func (s *session) validateRequest(svc *service, op *operation, params map[string]string, q url.Values, in *inbound) (any, *violation) {
	sc := svc.c.sc
	// first violation in the order path, query, headers, cookies, body
	for _, loc := range []string{"path", "query", "header", "cookie"} {
		for _, p := range op.params {
			if p.in != loc {
				continue
			}
			if loc == "header" && isTransportHeader(p.name) {
				// Older packs may list transport headers (host, user-agent, ...)
				// as required; a client never has to send them.
				continue
			}
			if loc == "header" && op.reqXML != nil && strings.EqualFold(p.name, "soapaction") {
				// the operation was routed already (SOAPAction, the action of
				// the content type or the Body element, mock.md 10.1)
				continue
			}
			var raw string
			var present bool
			var ptr string
			switch loc {
			case "path":
				raw, present = params[p.name]
				ptr = "/path/" + escapePointer(p.name)
			case "query":
				if vals, ok := q[p.name]; ok {
					present = true
					if len(vals) > 0 {
						raw = vals[0]
					}
				}
				ptr = "/query/" + escapePointer(p.name)
			case "header":
				if vals := in.header.Values(p.name); len(vals) > 0 {
					raw, present = vals[0], true
				}
				ptr = "/headers/" + escapePointer(strings.ToLower(p.name))
			case "cookie":
				if c, err := (&http.Request{Header: in.header}).Cookie(p.name); err == nil {
					raw, present = c.Value, true
				}
				ptr = "/cookies/" + escapePointer(p.name)
			}
			if !present {
				if p.required {
					return nil, &violation{ptr, "required parameter is missing"}
				}
				continue
			}
			if p.schema != nil {
				if viol := sc.validate(p.schema, sc.coerceParam(p.schema, raw), ptr, 0); viol != nil {
					return nil, viol
				}
			}
		}
		if loc == "query" {
			// pagination parameters of list reads are query parameters of the contract too
			if viol := s.validatePaging(svc, op, params, q, in); viol != nil {
				return nil, viol
			}
		}
	}
	if !op.hasBody {
		return nil, nil
	}
	if len(in.body) == 0 {
		if op.bodyReq {
			return nil, &violation{"/body", "request body is required"}
		}
		return nil, nil
	}
	if op.reqXML != nil {
		return s.xmlRequest(sc, op, in) // soap.go, mock.md 10
	}
	if ct := in.header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || !(mt == "application/json" || strings.HasSuffix(mt, "+json")) {
			return nil, &violation{"/body", "content type must be JSON"}
		}
	}
	v, err := decodeJSON(in.body)
	if err != nil {
		return nil, &violation{"/body", "body is not valid JSON"}
	}
	if op.bodySchema != nil {
		if viol := sc.validate(op.bodySchema, v, "/body", 0); viol != nil {
			return nil, viol
		}
	}
	return v, nil
}

// ---- response building ----

func (s *session) newBuilder(svc *service, in *inbound, path string) *builder {
	return &builder{sc: svc.c.sc, now: s.now, seed: s.seed, key: in.method + " " + path + "?" + in.rawQuery, prefixes: s.m.model.prefixesOf(svc.name), fmts: s.m.model.fmts}
}

// errorBody builds the body of a non-success response from the contract: the
// named (or first) example, else generated from the schema, else the envelope
// with the given code ("http_<status>" when empty).
func (s *session) errorBody(op *operation, status int, example string, b *builder, code string) any {
	if r := op.responses[status]; r != nil {
		if v, ok := r.exampleBody(example); ok {
			return cloneJSON(v)
		}
		if example != "" {
			if v, ok := r.exampleBody(""); ok {
				return cloneJSON(v)
			}
		}
		if r.schema != nil {
			return b.generate(r.schema, "", 0)
		}
		if r.media == nil && status != http.StatusNoContent && len(r.node) > 0 {
			return nil // declared without JSON content: no body
		}
	}
	if code == "" {
		code = "http_" + strconv.Itoa(status)
	}
	return errorEnvelope(code, http.StatusText(status), "")
}

// overlay is the state of an entity plus the derived fields: the owner as
// customerId/customer_id, the virtual instants of creation and last change.
func (s *session) overlay(rec *entityRec) map[string]any {
	ov := cloneMap(rec.state)
	add := func(k string, v any) {
		if _, ok := ov[k]; !ok {
			ov[k] = v
		}
	}
	var cust any
	if rec.customerID != nil {
		cust = *rec.customerID
	}
	add("customerId", cust)
	add("customer_id", cust)
	add("createdAt", fmtTime(rec.created))
	add("created_at", fmtTime(rec.created))
	add("updatedAt", fmtTime(rec.updated))
	add("updated_at", fmtTime(rec.updated))
	return ov
}

func (s *session) entityOverlay(rec *entityRec) entOverlay {
	var rel map[string]bool
	if ed := s.m.model.entities[rec.entity]; ed != nil {
		rel = ed.relations
	}
	return entOverlay{vals: s.overlay(rec), rel: rel}
}

// prepare performs the side effects of a request (entity creation) and
// returns a function that renders the response from the current state. It
// may be called again after the immediate effects of a rule have applied.
func (s *session) prepare(svc *service, op *operation, params map[string]string, q url.Values, in *inbound, reqBody any, b *builder, hdr http.Header) func() (int, any) {
	mod := s.m.model
	status := op.successCode
	resp := op.responses[status]
	var ex optVal
	if resp != nil {
		if v, ok := resp.exampleBody(""); ok {
			ex = some(v)
		}
	}
	build := func(ov optVal) any {
		s.lastOV = ov
		if resp == nil {
			return nil
		}
		if resp.schema == nil {
			if ex.ok {
				return cloneJSON(ex.v)
			}
			return nil
		}
		return b.build(resp.schema, ov, ex, "", 0)
	}

	// entity creation
	for _, name := range mod.entOrder {
		ed := mod.entities[name]
		if ed.svc != svc || ed.createOp != op.key {
			continue
		}
		state := map[string]any{}
		if ed.hasState {
			if v, ok := first(evalPath(reqBody, ed.statePath)); ok {
				if mm, ok := v.(map[string]any); ok {
					state = cloneMap(mm)
				}
			}
		}
		if cb := ed.def.CreatedBy; cb != nil {
			for _, k := range sortedKeys(cb.Defaults) {
				setDotted(state, k, cloneJSON(cb.Defaults[k]))
			}
		}
		id := s.nextID(name, state)
		state[ed.def.IDField] = id
		s.putEnt(&entityRec{entity: name, id: id, customerID: copyStr(s.customer), state: state, created: s.now, updated: s.now})
		return func() (int, any) {
			rec := s.ents[name][id]
			var ov any = s.entityOverlay(rec)
			if n := len(ed.idSegs); n > 1 && op.reqXML != nil {
				// an XML answer: the entity is the element that holds the id
				// (the SOAP envelope wraps it, mock.md 10.3)
				if t, err := nest(ed.idSegs[:n-1], ov); err == nil {
					ov = t
				}
			}
			body := build(some(ov))
			if cb := ed.def.CreatedBy; cb != nil && body != nil {
				switch cb.ID.From {
				case "resp.body":
					setAtPath(body, ed.idSegs, id)
				case "resp.headers":
					hdr.Set(cb.ID.Name, id)
				}
			}
			s.responseHeaders(resp, hdr, id)
			return status, body
		}
	}

	// keyed writes (rules v1.6): the record of the key, created or replaced
	if rec := s.upsert(svc, op, params, q, in, reqBody); rec != nil {
		name, id := rec.entity, rec.id
		return func() (int, any) {
			s.responseHeaders(resp, hdr, "")
			if r := s.ents[name][id]; r != nil {
				return status, build(some(s.entityOverlay(r)))
			}
			return status, build(optVal{})
		}
	}

	// entity reads
	if rds := mod.reads[svc.name+"\x00"+op.key]; len(rds) > 0 {
		rd := rds[0]
		return func() (int, any) {
			s.responseHeaders(resp, hdr, "")
			if rd.ent.def.Key != nil {
				return s.renderKeyed(rd, status, params, q, in, build)
			}
			return s.renderRead(rd, op, resp, status, params, q, in, b, build)
		}
	}

	// deprecated (pack <= 1.1): operations with x-tt-entity and no read_by list
	// the session customer's entities
	if op.entityHint != "" && op.method == http.MethodGet && resp != nil && resp.schema != nil {
		if ed := mod.entities[op.entityHint]; ed != nil {
			if prop := listProperty(svc.c.sc, resp.schema); prop != "" {
				return func() (int, any) {
					arr := []any{}
					for _, r := range s.sortedEnts(ed.def.Name) {
						if s.customer != nil && (r.customerID == nil || *r.customerID != *s.customer) {
							continue
						}
						arr = append(arr, s.entityOverlay(r))
					}
					ov := map[string]any{prop: arr}
					if ps, ok := svc.c.sc.flat(resp.schema, 0)["properties"].(map[string]any); ok {
						for _, cnt := range []string{"count", "total"} {
							if _, ok := ps[cnt]; ok {
								ov[cnt] = intNumber(len(arr))
							}
						}
					}
					s.responseHeaders(resp, hdr, "")
					return status, build(some(ov))
				}
			}
		}
	}

	// static mode: no entity here (docs/spec/mock.md 2.5)
	if f := s.staticPrepare(svc, op, params, reqBody, b, hdr, build); f != nil {
		return f
	}
	return func() (int, any) {
		s.responseHeaders(resp, hdr, "")
		return status, build(optVal{})
	}
}

// ---- reads (docs/spec/rules.md sections 2.3 to 2.5) ----

// omitValue marks an overlay key that must not appear in the body.
type omitValue struct{}

func lookupParam(from, name string, params map[string]string, q url.Values, h http.Header) (string, bool) {
	switch from {
	case "req.path":
		v, ok := params[name]
		return v, ok
	case "req.query":
		if q.Has(name) {
			return q.Get(name), true
		}
	case "req.headers":
		if v := h.Values(name); len(v) > 0 {
			return v[0], true
		}
	case "req.cookies":
		if c, err := (&http.Request{Header: h}).Cookie(name); err == nil {
			return c.Value, true
		}
	case "req.body":
		// A GraphQL variable, put among the parameters by graphqlParams.
		v, ok := params[name]
		return v, ok
	}
	return "", false
}

func paramPointer(from, name string) string {
	switch from {
	case "req.path":
		return "/path/" + escapePointer(name)
	case "req.query":
		return "/query/" + escapePointer(name)
	case "req.headers":
		return "/headers/" + escapePointer(strings.ToLower(name))
	}
	return "/cookies/" + escapePointer(name)
}

var cursorRE = regexp.MustCompile(`^c([0-9]{1,12})$`)

type paging struct {
	offset, limit int
	hasLimit      bool
}

// parsePaging reads limit, offset, page and cursor of a list read. A value
// that is not an integer, or is negative, is an invalid request.
func parsePaging(rd *readDef, params map[string]string, q url.Values, h http.Header) (paging, *violation) {
	var pg paging
	l := rd.rb.List
	if l == nil {
		return pg, nil
	}
	intParam := func(nr *pack.NameRef, min int) (int, bool, *violation) {
		raw, ok := lookupParam(nr.From, nr.Name, params, q, h)
		if !ok {
			return 0, false, nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < min {
			return 0, true, &violation{paramPointer(nr.From, nr.Name), "must be an integer >= " + strconv.Itoa(min)}
		}
		return n, true, nil
	}
	if nr := l.Limit; nr != nil {
		n, ok, v := intParam(nr, 0)
		if v != nil {
			return pg, v
		}
		if ok {
			pg.limit, pg.hasLimit = n, true
		}
	}
	if !pg.hasLimit && l.DefaultLimit > 0 {
		pg.limit, pg.hasLimit = l.DefaultLimit, true
	}
	if l.MaxLimit > 0 && pg.hasLimit && pg.limit > l.MaxLimit {
		pg.limit = l.MaxLimit
	}
	if nr := l.Offset; nr != nil {
		n, ok, v := intParam(nr, 0)
		if v != nil {
			return pg, v
		}
		if ok {
			pg.offset = n
		}
	}
	if nr := l.Page; nr != nil {
		n, ok, v := intParam(nr, 1)
		if v != nil {
			return pg, v
		}
		if ok {
			if pg.hasLimit {
				pg.offset = (n - 1) * pg.limit
			} else if n > 1 {
				pg.offset = math.MaxInt32
			}
		}
	}
	if nr := l.Cursor; nr != nil {
		if raw, ok := lookupParam(nr.From, nr.Name, params, q, h); ok {
			m := cursorRE.FindStringSubmatch(raw)
			if m == nil {
				return pg, &violation{paramPointer(nr.From, nr.Name), "not a cursor of this mock"}
			}
			pg.offset, _ = strconv.Atoi(m[1])
		}
	}
	return pg, nil
}

func (s *session) validatePaging(svc *service, op *operation, params map[string]string, q url.Values, in *inbound) *violation {
	for _, rd := range s.m.model.reads[svc.name+"\x00"+op.key] {
		if rd.list {
			if _, v := parsePaging(rd, params, q, in.header); v != nil {
				return v
			}
		}
	}
	return nil
}

func hiddenBy(rd *readDef, rec *entityRec) bool {
	if len(rd.rb.HiddenWhen) == 0 {
		return false
	}
	for k, want := range rd.rb.HiddenWhen {
		got, ok := getDotted(rec.state, k)
		if !ok || !jsonEqual(got, want) {
			return false
		}
	}
	return true
}

func ownedBy(rec *entityRec, cust string) bool {
	return rec.customerID != nil && *rec.customerID == cust
}

func (s *session) renderRead(rd *readDef, op *operation, resp *response, status int, params map[string]string, q url.Values, in *inbound, b *builder, build func(optVal) any) (int, any) {
	cust := s.customer
	scoped := rd.scoped && cust != nil
	name := rd.ent.def.Name
	foreign := func() (int, any) {
		st, code := http.StatusNotFound, "not_found"
		if rd.forbid {
			st, code = http.StatusForbidden, "forbidden"
		}
		return st, s.errorBody(op, st, rd.rb.ForeignExample, b, code)
	}
	notFound := func() (int, any) {
		return http.StatusNotFound, s.errorBody(op, http.StatusNotFound, rd.rb.NotFoundExample, b, "not_found")
	}

	// 1. selection
	var sel []*entityRec
	ownerSel := copyStr(cust) // owner shown in the envelope of a list
	switch {
	case !rd.hasBy:
		for _, r := range s.sortedEnts(name) {
			if cust == nil || ownedBy(r, *cust) {
				sel = append(sel, r)
			}
		}
	case rd.owner:
		val, found := lookupParam(rd.by.ref.From, refParam(rd.by), params, q, in.header)
		if !found {
			break
		}
		ownerSel = &val
		if scoped && val != *cust {
			return foreign()
		}
		for _, r := range s.sortedEnts(name) {
			if ownedBy(r, val) {
				sel = append(sel, r)
			}
		}
	default:
		sel = s.selectBy(rd, params, q, in)
	}

	// 2. visibility
	vis := sel[:0:0]
	for _, r := range sel {
		if !hiddenBy(rd, r) {
			vis = append(vis, r)
		}
	}
	if !rd.list {
		if len(vis) == 0 {
			if st, body, ok := s.removedAnswer(rd, op, params, q, in, b); ok {
				return st, body
			}
			return notFound()
		}
		r := vis[0]
		if scoped && r.customerID != nil && *r.customerID != *cust {
			return foreign()
		}
		tree, err := nest(rd.at, s.entityOverlay(r))
		if err != nil {
			return notFound()
		}
		return status, build(some(tree))
	}
	if scoped {
		kept := vis[:0:0]
		for _, r := range vis {
			if r.customerID == nil || *r.customerID == *cust {
				kept = append(kept, r)
			}
		}
		vis = kept
	}
	vis = s.filterList(rd, vis, params, q, in.header) // rules v1.9

	// 3. order
	l := rd.rb.List
	if l != nil && l.OrderBy != "" {
		s.sortRecs(vis, l.OrderBy, l.Order == "desc")
	}
	total := len(vis)

	// 4. page
	pg, _ := parsePaging(rd, params, q, in.header)
	end := total
	if pg.hasLimit {
		end = pg.offset + pg.limit
		if end > total || end < 0 {
			end = total
		}
	}
	start := pg.offset
	if start > total {
		start = total
	}
	page := vis[start:end]

	// 5. body
	items := make([]any, 0, len(page))
	for _, r := range page {
		items = append(items, s.entityOverlay(r))
	}
	tree, err := nest(rd.at, items)
	if err != nil {
		return notFound()
	}
	if root, ok := tree.(map[string]any); ok {
		if l != nil {
			if rd.countSegs != nil {
				setOverlayPath(root, rd.countSegs, intNumber(len(page)))
			}
			if rd.totalSegs != nil {
				setOverlayPath(root, rd.totalSegs, intNumber(total))
			}
			if rd.nextSegs != nil {
				switch {
				case pg.hasLimit && end < total:
					setOverlayPath(root, rd.nextSegs, "c"+strconv.Itoa(end))
				case resp != nil && resp.schema != nil && nullableAt(b.sc, resp.schema, rd.nextSegs):
					setOverlayPath(root, rd.nextSegs, nil)
				default:
					setOverlayPath(root, rd.nextSegs, omitValue{})
				}
			}
		}
		var owner any
		if ownerSel != nil {
			owner = *ownerSel
		}
		for _, k := range []string{"customerId", "customer_id"} {
			if _, has := root[k]; !has {
				root[k] = owner
			}
		}
	}
	return status, build(some(tree))
}

// selectBy selects the entities designated by a parameter: the entity with
// that id, or the entities whose field equals it.
func (s *session) selectBy(rd *readDef, params map[string]string, q url.Values, in *inbound) []*entityRec {
	val, found := lookupParam(rd.by.ref.From, refParam(rd.by), params, q, in.header)
	if !found {
		return nil
	}
	field := rd.by.ref.Field
	if field == "" {
		field = rd.ent.def.IDField
	}
	name := rd.ent.def.Name
	if field == rd.ent.def.IDField {
		if r := s.ents[name][val]; r != nil {
			return []*entityRec{r}
		}
		return nil
	}
	var out []*entityRec
	for _, r := range s.sortedEnts(name) {
		if v, ok := getDotted(r.state, field); ok {
			if sv, ok := scalarString(v); ok && sv == val {
				out = append(out, r)
			}
		}
	}
	return out
}

// sortRecs orders by a dotted field (missing values last), then by id.
func (s *session) sortRecs(recs []*entityRec, field string, desc bool) {
	vals := make(map[*entityRec]any, len(recs))
	has := make(map[*entityRec]bool, len(recs))
	for _, r := range recs {
		v, ok := getDotted(s.overlay(r), field)
		vals[r], has[r] = v, ok && v != nil
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if has[a] != has[b] {
			return has[a]
		}
		if has[a] {
			if c := compareScalars(vals[a], vals[b]); c != 0 {
				if desc {
					return c > 0
				}
				return c < 0
			}
		}
		return a.id < b.id
	})
}

func compareScalars(a, b any) int {
	if fa, ok := numFloat(a); ok {
		if fb, ok := numFloat(b); ok {
			switch {
			case fa < fb:
				return -1
			case fa > fb:
				return 1
			}
			return 0
		}
		return -1 // numbers before other types
	}
	if _, ok := numFloat(b); ok {
		return 1
	}
	sa, oka := a.(string)
	sb, okb := b.(string)
	if oka && okb {
		return strings.Compare(sa, sb)
	}
	return strings.Compare(string(compactJSON(a)), string(compactJSON(b)))
}

// setOverlayPath sets a ".a.b" style path in an overlay tree, creating the
// intermediate objects.
func setOverlayPath(root map[string]any, segs []pathSeg, v any) {
	cur := root
	for i, sg := range segs {
		if sg.kind != segKey {
			return
		}
		if i == len(segs)-1 {
			cur[sg.key] = v
			return
		}
		next, ok := cur[sg.key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[sg.key] = next
		}
		cur = next
	}
}

// nullableAt reports whether the schema allows null at a ".a.b" path.
func nullableAt(sc *schemaCtx, schema any, segs []pathSeg) bool {
	cur := sc.flat(schema, 0)
	for _, sg := range segs {
		props, _ := cur["properties"].(map[string]any)
		ps, ok := props[sg.key]
		if sg.kind != segKey || !ok {
			return false
		}
		cur = sc.flat(ps, 0)
	}
	return allowsNullExplicit(cur)
}

func allowsNullExplicit(s map[string]any) bool {
	for _, t := range schemaTypes(s) {
		if t == "null" {
			return true
		}
	}
	return false
}

// listProperty names the array-of-objects property of an object schema
// (preferring "items").
func listProperty(sc *schemaCtx, schema any) string {
	s := sc.flat(schema, 0)
	props, _ := s["properties"].(map[string]any)
	var names []string
	for _, k := range sortedKeys(props) {
		ps := sc.flat(props[k], 0)
		if primaryType(ps) == "array" {
			names = append(names, k)
		}
	}
	for _, n := range names {
		if n == "items" {
			return n
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		return names[0]
	}
	return ""
}

var idPlaceholderRE = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*\}`)

// responseHeaders sets the headers declared with an example by the contract
// response; "{id}"-style placeholders take the created entity id.
func (s *session) responseHeaders(r *response, hdr http.Header, createdID string) {
	if r == nil {
		return
	}
	names := make([]string, 0, len(r.headers))
	for n := range r.headers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		hn, _ := r.headers[n].(map[string]any)
		ex, ok := hn["example"].(string)
		if !ok {
			continue
		}
		if createdID != "" {
			ex = idPlaceholderRE.ReplaceAllStringFunc(ex, func(string) string { return createdID })
		}
		hdr.Set(n, ex)
	}
}

func intNumber(n int) any { return json.Number(strconv.Itoa(n)) }

// ---- session registry ----

func (m *Mock) lookup(id string) *session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.sessions[id]
	if s != nil {
		s.lastUsed.Store(m.cfg.Wall().UnixNano())
	}
	return s
}

// EvictIdle deletes the sessions (except the default one) not used for
// SessionIdleTTL and returns how many went.
func (m *Mock) EvictIdle() int {
	if m.cfg.SessionIdleTTL <= 0 {
		return 0
	}
	cut := m.cfg.Wall().Add(-m.cfg.SessionIdleTTL).UnixNano()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.sessions {
		if id != defaultSession && s.lastUsed.Load() < cut {
			delete(m.sessions, id)
			n++
		}
	}
	return n
}
