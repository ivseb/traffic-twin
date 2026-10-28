package fleet

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/server"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

const (
	maxEnrollBody    = 16 << 10
	maxHeartbeatBody = 64 << 10
)

// Enrollment is the 201 body of enroll (fleet-api Enrollment).
type Enrollment struct {
	SourceID            string           `json:"source_id"`
	Group               string           `json:"group"`
	ServiceName         string           `json:"service_name"`
	ClientCert          string           `json:"client_cert"`
	ClientKey           string           `json:"client_key,omitempty"`
	CAChain             string           `json:"ca_chain"`
	NotAfter            time.Time        `json:"not_after"`
	PolicySigningKeys   []SigningKeyJSON `json:"policy_signing_keys"`
	IntakeURL           string           `json:"intake_url"`
	FleetURL            string           `json:"fleet_url"`
	PolicyMaxAgeS       int64            `json:"policy_max_age_s"`
	HeartbeatIntervalS  int64            `json:"heartbeat_interval_s"`
	PolicyPollIntervalS int64            `json:"policy_poll_interval_s"`
}

// SigningKeyJSON is a policy signing key as sent to sources.
type SigningKeyJSON struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

func methodOnly(w http.ResponseWriter, r *http.Request, m string) bool {
	if r.Method != m {
		w.Header().Set("Allow", m)
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return false
	}
	return true
}

func (f *Fleet) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != PathEnroll {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !methodOnly(w, r, http.MethodPost) {
		return
	}
	if ok, wait := f.enrollIP.allow(ipKey(httpx.ClientIP(r)), f.now()); !ok {
		tooMany(w, wait)
		return
	}
	var req struct {
		Token  string     `json:"token"`
		CSR    string     `json:"csr,omitempty"`
		Source SourceInfo `json:"source"`
	}
	if err := httpx.DecodeJSON(w, r, maxEnrollBody, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	if len(req.CSR) > 8192 {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_csr", "csr too large")
		return
	}
	// Per token, keyed by the hash of the whole token string (never the
	// secret itself): bounds the damage of a leaked group token.
	if ok, wait := f.enrollTok.allow(hashSecret(req.Token), f.now()); !ok {
		tooMany(w, wait)
		return
	}
	res, err := f.Enroll(r.Context(), req.Token, req.CSR, req.Source)
	if err != nil {
		f.writeErr(w, r, err)
		return
	}
	f.mu.RLock()
	keys := make([]SigningKeyJSON, 0, len(f.keys))
	for _, k := range f.keys {
		keys = append(keys, SigningKeyJSON{Kid: k.Kid, Alg: "Ed25519", PublicKey: b64.EncodeToString(k.PublicKey)})
	}
	f.mu.RUnlock()
	httpx.WriteJSON(w, http.StatusCreated, Enrollment{
		SourceID: res.SourceID, Group: res.Group, ServiceName: res.Service,
		ClientCert: res.Cert.CertPEM, ClientKey: res.Cert.KeyPEM, CAChain: string(f.ca.pem), NotAfter: res.Cert.NotAfter,
		PolicySigningKeys: keys, IntakeURL: f.publicURL + "/v1/logs", FleetURL: f.publicURL,
		PolicyMaxAgeS:       int64(f.opts.PolicyMaxAge / time.Second),
		HeartbeatIntervalS:  int64(f.opts.HeartbeatInterval / time.Second),
		PolicyPollIntervalS: int64(f.opts.PolicyPollInterval / time.Second),
	})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int64(wait/time.Second) + 1
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	httpx.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many enrollment attempts; retry later")
}

// peerSource returns the enrolled, non-revoked source of an mTLS request.
func (f *Fleet) peerSource(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, ok := SourceIDFromCert(server.PeerCertificate(r))
	if !ok {
		httpx.WriteError(w, http.StatusForbidden, "no_source_identity", "the client certificate carries no source identity")
		return "", false
	}
	f.mu.RLock()
	s := f.sources[id]
	revoked := s == nil || s.revoked
	f.mu.RUnlock()
	if revoked {
		httpx.WriteError(w, http.StatusForbidden, "source_revoked", "source revoked")
		return "", false
	}
	return id, true
}

func (f *Fleet) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != PathPolicy {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !methodOnly(w, r, http.MethodGet) {
		return
	}
	id, ok := f.peerSource(w, r)
	if !ok {
		return
	}
	f.mu.RLock()
	group := f.sources[id].group
	f.mu.RUnlock()
	env, hash := f.CurrentEnvelope(group)
	if env == nil {
		httpx.WriteError(w, http.StatusNotFound, "no_policy", "no policy is assigned to this source's group yet")
		return
	}
	etag := `"` + hash + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		for _, t := range strings.Split(inm, ",") {
			t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "W/"))
			if t == etag || t == "*" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(env)
}

func (f *Fleet) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != PathHeartbeat {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !methodOnly(w, r, http.MethodPost) {
		return
	}
	id, ok := f.peerSource(w, r)
	if !ok {
		return
	}
	// The Heartbeat schema allows unknown fields (forward compatibility),
	// so decoding is not strict here; size and content type still are.
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "Content-Type must be application/json")
		return
	}
	var hb Heartbeat
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHeartbeatBody))
	if err := dec.Decode(&hb); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", "trailing data after JSON object")
		return
	}
	resp, err := f.HandleHeartbeat(r.Context(), id, &hb)
	if err != nil {
		f.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (f *Fleet) handleRenew(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != PathRenew {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	if !methodOnly(w, r, http.MethodPost) {
		return
	}
	id, ok := f.peerSource(w, r)
	if !ok {
		return
	}
	var req struct {
		CSR string `json:"csr,omitempty"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, maxEnrollBody, &req); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "bad_request", "invalid request body")
			return
		}
	}
	if len(req.CSR) > 8192 {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_csr", "csr too large")
		return
	}
	cert, err := f.RenewCert(r.Context(), id, req.CSR)
	if err != nil {
		f.writeErr(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct {
		ClientCert string    `json:"client_cert"`
		ClientKey  string    `json:"client_key,omitempty"`
		NotAfter   time.Time `json:"not_after"`
	}{cert.CertPEM, cert.KeyPEM, cert.NotAfter})
}
