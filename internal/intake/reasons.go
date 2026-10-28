package intake

// Reason is the stable code under which a rejected event (or record) is
// counted. The set is closed: counters are keyed by these names and carry no
// payload.
type Reason uint8

// Rejection reasons. The first block mirrors docs/spec/event.md 5.1.
const (
	ReasonNone Reason = iota
	// ReasonTooLarge: the event exceeds 512 KiB.
	ReasonTooLarge
	// ReasonJSON: the event is not valid JSON.
	ReasonJSON
	// ReasonNonCanonical: valid JSON but not exactly the canonical bytes (5.1 point 2).
	ReasonNonCanonical
	// ReasonSchema: not valid against the event schema or the token grammar (points 1 and 5).
	ReasonSchema
	// ReasonSourceMismatch: source.id differs from the certificate identity (point 4).
	ReasonSourceMismatch
	// ReasonPolicyUnknown: policy.hash is not a known signed policy (point 3).
	ReasonPolicyUnknown
	// ReasonPolicyMismatch: policy id or version do not match the policy with that hash.
	ReasonPolicyMismatch
	// ReasonPolicyGroup: the policy is not assigned to the group of the source (point 3).
	ReasonPolicyGroup
	// ReasonPolicyTime: event time outside the validity window of the policy.
	ReasonPolicyTime
	// ReasonServiceNotAllowed: service not among the names allowed for the group (point 4), or an
	// outbound service the policy does not declare.
	ReasonServiceNotAllowed
	// ReasonHostNotAllowed: host:<name> not in hosts_allow and discovery not active (point 6).
	ReasonHostNotAllowed
	// ReasonOpUnknown: op not declared by the policy for a policy or framework route.
	ReasonOpUnknown
	// ReasonPathShape: req.path inconsistent with op, template or base.
	ReasonPathShape
	// ReasonSegmentNotAllowed: a literal path segment on a raw route that the policy does not allow.
	ReasonSegmentNotAllowed
	// ReasonSubjectNotAllowed: a subject token although the policy has no identity.subject.
	ReasonSubjectNotAllowed
	// ReasonValueNotAllowed: a keep/tk1/num/time value where the effective rule is not of that
	// kind (point 6, S9).
	ReasonValueNotAllowed
	// ReasonDiscNotAllowed: disc present although discovery is not active.
	ReasonDiscNotAllowed
	// ReasonBodyShape: body structure inconsistent with the content type.
	ReasonBodyShape
	// ReasonLimits: arrays, keys or depth beyond the policy limits.
	ReasonLimits
	// ReasonOTLPShape: the log record envelope is not the one of docs/spec/event.md 4.2.
	ReasonOTLPShape
	// ReasonResourceMismatch: OTLP resource attributes disagree with the event or the source.
	ReasonResourceMismatch
	// ReasonMonitorOverflow: too many distinct fields to watch (memory bound).
	ReasonMonitorOverflow

	numReasons
)

var reasonNames = [numReasons]string{
	ReasonNone:              "none",
	ReasonTooLarge:          "event_too_large",
	ReasonJSON:              "invalid_json",
	ReasonNonCanonical:      "non_canonical",
	ReasonSchema:            "schema",
	ReasonSourceMismatch:    "source_mismatch",
	ReasonPolicyUnknown:     "policy_unknown",
	ReasonPolicyMismatch:    "policy_mismatch",
	ReasonPolicyGroup:       "policy_group",
	ReasonPolicyTime:        "policy_time",
	ReasonServiceNotAllowed: "service_not_allowed",
	ReasonHostNotAllowed:    "host_not_allowed",
	ReasonOpUnknown:         "op_unknown",
	ReasonPathShape:         "path_shape",
	ReasonSegmentNotAllowed: "segment_not_allowed",
	ReasonSubjectNotAllowed: "subject_not_allowed",
	ReasonValueNotAllowed:   "value_not_allowed",
	ReasonDiscNotAllowed:    "disc_not_allowed",
	ReasonBodyShape:         "body_shape",
	ReasonLimits:            "limits",
	ReasonOTLPShape:         "otlp_shape",
	ReasonResourceMismatch:  "resource_mismatch",
	ReasonMonitorOverflow:   "monitor_overflow",
}

// String returns the counter name of the reason.
func (r Reason) String() string {
	if int(r) < len(reasonNames) {
		return reasonNames[r]
	}
	return "unknown"
}

// AllReasons lists every rejection reason (excluding ReasonNone).
func AllReasons() []Reason {
	out := make([]Reason, 0, numReasons-1)
	for r := ReasonNone + 1; r < numReasons; r++ {
		out = append(out, r)
	}
	return out
}

// Reject is the outcome of a failed check: a reason and a static detail that
// names the check (never a payload value).
type Reject struct {
	Reason Reason
	Detail string
}

// Error implements error.
func (r Reject) Error() string { return "intake: rejected: " + r.Reason.String() + ": " + r.Detail }
