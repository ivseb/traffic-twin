package sourceclient

import (
	"runtime"
	"time"
)

// Wire types of api/fleet-api.v1.openapi.yaml (source-facing endpoints).

// RuntimeInfo describes the runtime of the source.
type RuntimeInfo struct {
	Lang        string `json:"lang,omitempty"`
	LangVersion string `json:"lang_version,omitempty"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
}

// GoRuntime returns the RuntimeInfo of the running Go program.
func GoRuntime() *RuntimeInfo {
	return &RuntimeInfo{Lang: "go", LangVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
}

// SourceInfo is the "source" object of the enrollment request.
type SourceInfo struct {
	Kind        string       `json:"kind"`
	Version     string       `json:"version"`
	ServiceName string       `json:"service_name"`
	Instance    string       `json:"instance,omitempty"`
	Runtime     *RuntimeInfo `json:"runtime,omitempty"`
	HMACKids    []string     `json:"hmac_kids,omitempty"`
}

// SigningKey is a pinned policy signing key (Ed25519, raw base64url).
type SigningKey struct {
	Kid       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

// enrollmentResponse is the 201 body of /fleet/v1/enroll.
type enrollmentResponse struct {
	SourceID            string       `json:"source_id"`
	Group               string       `json:"group"`
	ServiceName         string       `json:"service_name"`
	ClientCert          string       `json:"client_cert"`
	ClientKey           string       `json:"client_key"`
	CAChain             string       `json:"ca_chain"`
	NotAfter            string       `json:"not_after"`
	PolicySigningKeys   []SigningKey `json:"policy_signing_keys"`
	IntakeURL           string       `json:"intake_url"`
	FleetURL            string       `json:"fleet_url"`
	PolicyMaxAgeS       int64        `json:"policy_max_age_s"`
	HeartbeatIntervalS  int64        `json:"heartbeat_interval_s"`
	PolicyPollIntervalS int64        `json:"policy_poll_interval_s"`
}

// PolicyRef identifies a policy in a heartbeat.
type PolicyRef struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	IssuedSeq int64  `json:"issued_seq"`
	Hash      string `json:"hash"`
}

// CounterSnapshot holds the monotonic counters of a heartbeat.
type CounterSnapshot struct {
	ExchangesSeen      int64 `json:"exchanges_seen"`
	ExchangesSampled   int64 `json:"exchanges_sampled"`
	EventsSent         int64 `json:"events_sent"`
	EventsDroppedQueue int64 `json:"events_dropped_queue"`
	EventsRejected     int64 `json:"events_rejected"`
	SendErrors         int64 `json:"send_errors"`
	SanitizerErrors    int64 `json:"sanitizer_errors"`
}

// OverheadUS is the time spent in tt per exchange, in microseconds.
type OverheadUS struct {
	P50 int64 `json:"p50"`
	P99 int64 `json:"p99"`
}

// QueueInfo describes the export queue.
type QueueInfo struct {
	Events int   `json:"events"`
	Bytes  int64 `json:"bytes"`
}

// LastError is an error code (never a payload value) with its time.
type LastError struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
}

// Heartbeat is the request body of /fleet/v1/heartbeat.
type Heartbeat struct {
	SourceID   string          `json:"source_id"`
	State      string          `json:"state"`
	Policy     *PolicyRef      `json:"policy,omitempty"`
	Counters   CounterSnapshot `json:"counters"`
	OverheadUS *OverheadUS     `json:"overhead_us,omitempty"`
	Queue      *QueueInfo      `json:"queue,omitempty"`
	LastErrors []LastError     `json:"last_errors,omitempty"`
	Runtime    *RuntimeInfo    `json:"runtime,omitempty"`
	// SigningKids are the policy signing kids the source trusts (pinned,
	// not revoked), sorted: tt-core waits for them before it allows the
	// revocation of an old key (policy.md 3.1).
	SigningKids []string `json:"signing_kids"`
}

// PolicyCurrent is the policy the source should be running.
type PolicyCurrent struct {
	PolicyID  string `json:"policy_id"`
	Version   int64  `json:"version"`
	IssuedSeq int64  `json:"issued_seq"`
	Hash      string `json:"hash"`
}

// AddSigningKey is a new signing key endorsed by a pinned one.
type AddSigningKey struct {
	Kid         string `json:"kid"`
	Alg         string `json:"alg"`
	PublicKey   string `json:"public_key"`
	EndorsedBy  string `json:"endorsed_by"`
	Endorsement string `json:"endorsement"`
}

// HeartbeatResponse is the 200 body of /fleet/v1/heartbeat.
type HeartbeatResponse struct {
	NextHeartbeatS     int64           `json:"next_heartbeat_s"`
	Kill               bool            `json:"kill"`
	MinIssuedSeq       int64           `json:"min_issued_seq"`
	PolicyCurrent      *PolicyCurrent  `json:"policy_current"`
	SamplingOverrideBP *int            `json:"sampling_override_bp"`
	RenewBefore        *time.Time      `json:"renew_before"`
	AddSigningKeys     []AddSigningKey `json:"add_signing_keys"`
	RevokeSigningKeys  []string        `json:"revoke_signing_keys"`
}

// renewResponse is the 200 body of /fleet/v1/renew.
type renewResponse struct {
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	NotAfter   string `json:"not_after"`
}
