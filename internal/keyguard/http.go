package keyguard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// Request body limits.
const (
	maxTokensBody = 8 << 20
	maxMatchBody  = 48 << 20
	maxSignBody   = 6 << 20
	maxSmallBody  = 1 << 20
)

// HeaderApproval carries, on POST /keyguard/v1/pack/sign, the optional
// approval of the person who asked to publish: base64url (no padding) of the
// JSON of an Approval. The pack body itself is the binary archive.
const HeaderApproval = "X-TT-Approval"

// Handler returns the keyguard HTTP API (api/keyguard-api.v1.openapi.yaml).
// Authentication is the transport's job (Unix socket or pinned mTLS).
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.wrap(pattern, h))
	}
	route("POST /keyguard/v1/tokens", s.handleTokens)
	route("POST /keyguard/v1/match", s.handleMatch)
	route("POST /keyguard/v1/policy/sign", s.handleSign)
	route("POST /keyguard/v1/policy/renew", s.handleRenew)
	route("POST /keyguard/v1/pack/sign", s.handlePack)
	route("GET /keyguard/v1/public-keys", s.handlePublicKeys)
	route("GET /keyguard/v1/status", s.handleStatus)
	route("GET /keyguard/v1/audit", s.handleAudit)
	route("GET /keyguard/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.Handle("/", s.wrap("not-found", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteError(w, 404, "not_found", "no such endpoint")
	}))
	return mux
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	return r.ResponseWriter.Write(b)
}

// wrap adds panic recovery and an access log with the route pattern only:
// never paths with values, bodies or headers.
func (s *Service) wrap(pattern string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("keyguard handler panic", "route", pattern)
				if rec.status == 0 {
					httpx.WriteError(rec, 500, "internal", "internal error")
				}
			}
			s.log.Info("keyguard request", "route", pattern, "status", rec.status, "duration_ms", time.Since(start).Milliseconds())
		}()
		h(rec, r)
	})
}

func (s *Service) writeErr(w http.ResponseWriter, err error) {
	var e *Error
	if errors.As(err, &e) {
		body := map[string]any{"code": e.Code, "message": e.Message}
		for k, v := range e.Extra {
			body[k] = v
		}
		if e.Status == 429 {
			w.Header().Set("Retry-After", "1")
		}
		httpx.WriteJSON(w, e.Status, body)
		return
	}
	s.log.Error("keyguard internal error", "error", err.Error())
	httpx.WriteError(w, 500, "internal", "internal error")
}

func (s *Service) decode(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	if err := httpx.DecodeJSON(w, r, limit, dst); err != nil {
		httpx.WriteError(w, 400, "invalid_request", err.Error())
		return false
	}
	return true
}

func (s *Service) handleTokens(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Epoch  *string  `json:"epoch"`
		Tokens []string `json:"tokens"`
	}
	if !s.decode(w, r, maxTokensBody, &req) {
		return
	}
	if req.Epoch == nil || req.Tokens == nil {
		httpx.WriteError(w, 400, "invalid_request", "epoch and tokens are required")
		return
	}
	if err := s.AddTokens(r.Context(), *req.Epoch, req.Tokens); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleMatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policies   []PolicyRef       `json:"policies"`
		Candidates []json.RawMessage `json:"candidates"`
	}
	if !s.decode(w, r, maxMatchBody, &req) {
		return
	}
	if req.Policies == nil || req.Candidates == nil {
		httpx.WriteError(w, 400, "invalid_request", "policies and candidates are required")
		return
	}
	cands := make([]Candidate, 0, len(req.Candidates))
	for _, raw := range req.Candidates {
		c, ok := parseCandidate(raw)
		if !ok {
			httpx.WriteError(w, 400, "invalid_request", "a candidate is not a string of at most 4096 characters or a number")
			return
		}
		cands = append(cands, c)
	}
	res, err := s.Match(r.Context(), req.Policies, cands)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, res)
}

// parseCandidate accepts a JSON string (at most 4096 characters) or a JSON
// number, keeping the number lexeme exactly as written.
func parseCandidate(raw json.RawMessage) (Candidate, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return Candidate{}, false
	}
	if raw[0] == '"' {
		v, err := ttjson.Parse(raw, ttjson.ParseOptions{MaxDepth: 1})
		if err != nil || v.Kind != ttjson.String || len([]rune(v.Str)) > 4096 {
			return Candidate{}, false
		}
		return Candidate{Value: v.Str}, true
	}
	if !ttjson.IsNumberLexeme(raw) {
		return Candidate{}, false
	}
	return Candidate{Value: string(raw), IsNumber: true}, true
}

func decodeB64(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) > 0
}

func (s *Service) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BodyB64   string     `json:"body_b64"`
		Proposer  string     `json:"proposer"`
		Approvals []Approval `json:"approvals"`
	}
	if !s.decode(w, r, maxSignBody, &req) {
		return
	}
	body, ok := decodeB64(req.BodyB64)
	if !ok {
		httpx.WriteError(w, 400, "invalid_request", "body_b64 is not base64url without padding")
		return
	}
	res, err := s.SignPolicy(r.Context(), body, req.Proposer, req.Approvals)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, res)
}

func (s *Service) handleRenew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BodyB64 string `json:"body_b64"`
	}
	if !s.decode(w, r, maxSignBody, &req) {
		return
	}
	body, ok := decodeB64(req.BodyB64)
	if !ok {
		httpx.WriteError(w, 400, "invalid_request", "body_b64 is not base64url without padding")
		return
	}
	res, err := s.RenewPolicy(r.Context(), body)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, res)
}

func (s *Service) handlePack(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/gzip" {
		httpx.WriteError(w, 400, "invalid_request", "Content-Type must be application/gzip")
		return
	}
	var requester *Approval
	if h := r.Header.Get(HeaderApproval); h != "" {
		raw, ok := decodeB64(h)
		var a Approval
		if !ok || len(raw) > maxSmallBody || json.Unmarshal(raw, &a) != nil {
			httpx.WriteError(w, 400, "invalid_request", HeaderApproval+" is not a base64url JSON approval")
			return
		}
		requester = &a
	}
	archive, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPackArchiveBytes))
	if err != nil {
		httpx.WriteError(w, 413, "too_large", "pack archive too large")
		return
	}
	res, err := s.SignPack(r.Context(), archive, requester)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, res)
}

func (s *Service) handlePublicKeys(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, 200, s.PublicKeys())
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Status(r.Context())
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, st)
}

func (s *Service) handleAudit(w http.ResponseWriter, r *http.Request) {
	var since int64
	if v := r.URL.Query().Get("since_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			httpx.WriteError(w, 400, "invalid_request", "since_seq must be a non-negative integer")
			return
		}
		since = n
	}
	entries, err := s.Audit(r.Context(), since, 1000)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, 200, entries)
}
