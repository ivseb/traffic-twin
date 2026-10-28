package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// StarterRequest is the body of POST /api/v1/fleet/groups/{group}/starter-policy.
type StarterRequest struct {
	// PolicyID defaults to the group's policy_id, or "p-<group>" when the
	// group has none (the group is then bound to it).
	PolicyID string `json:"policy_id,omitempty"`
	// HMACKid defaults to the first HMAC kid keyguard holds; Epoch to the
	// current month (YYYY-MM).
	HMACKid      string `json:"hmac_kid,omitempty"`
	Epoch        string `json:"epoch,omitempty"`
	SamplingRate string `json:"sampling_rate,omitempty"` // decimal, default DefaultObserveSampling
	// WindowHours of discovery and auto_words: default 72, at most 168.
	WindowHours int `json:"window_hours,omitempty"`
}

// CreateStarterPolicy creates the onboarding starter policy for a group
// (policy.md 6). It opens no value (structure only), so when keyguard signs
// observe-safe changes (policy.md 7, observe_auto) it is activated at once,
// without approvals; otherwise it is a draft that needs approvals.
// hmac_kid defaults to the first HMAC key keyguard holds, epoch to the
// current month, the sampling to DefaultObserveSampling.
func (f *Fleet) CreateStarterPolicy(ctx context.Context, p *auth.Principal, group string, req StarterRequest) (*PolicyVersion, error) {
	g, err := f.GetGroup(ctx, group)
	if err != nil {
		return nil, err
	}
	if req.WindowHours < 0 || req.WindowHours > int(policy.MaxOpenWindow/time.Hour) {
		return nil, invalid("invalid_window", "window_hours must be between 1 and 168")
	}
	window := DefaultStarterWindow
	if req.WindowHours > 0 {
		window = time.Duration(req.WindowHours) * time.Hour
	}
	pid := req.PolicyID
	switch {
	case g.PolicyID != nil && pid == "":
		pid = *g.PolicyID
	case g.PolicyID != nil && pid != *g.PolicyID:
		return nil, conflict("group_bound", "the group is bound to another policy")
	case pid == "":
		pid = "p-" + group
		if len(pid) > 63 {
			pid = pid[:63]
		}
	}
	if !policy.ValidPolicyID(pid) {
		return nil, invalid("invalid_policy_id", "policy_id must match ^[a-z0-9][a-z0-9-]{0,62}$")
	}
	if req.HMACKid == "" {
		st, _ := f.approvalSettings()
		if len(st.HMACKids) > 0 {
			req.HMACKid = st.HMACKids[0]
		}
	}
	if req.Epoch == "" {
		req.Epoch = f.now().UTC().Format("2006-01")
	}
	if req.SamplingRate == "" {
		req.SamplingRate = DefaultObserveSampling
	}
	if !policy.ValidKid(req.HMACKid) || !policy.ValidEpoch(req.Epoch) {
		return nil, invalid("invalid_hmac", "hmac_kid and epoch are required and must be valid")
	}
	y, err := StarterPolicyYAML(StarterOptions{PolicyID: pid, HMACKid: req.HMACKid, Epoch: req.Epoch, SamplingRate: req.SamplingRate,
		InboundServices: g.AllowedServiceNames, Now: f.now(), Window: window})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) {
			return nil, ae
		}
		return nil, invalid("invalid_policy", policyErrMsg(err))
	}
	if g.PolicyID == nil {
		g.PolicyID = &pid
		if _, err := f.UpdateGroup(ctx, p, group, *g); err != nil {
			return nil, err
		}
	}
	f.policyMu.Lock()
	defer f.policyMu.Unlock()
	return f.createDraft(ctx, p, []byte(y), OriginStarter, "onboarding starter policy")
}

// DefaultStarterWindow is how long the onboarding policy keeps discovery
// and automatic path words on (policy.md 6: 72 hours).
const DefaultStarterWindow = 72 * time.Hour

// StarterOptions configure the onboarding starter policy.
type StarterOptions struct {
	PolicyID string
	HMACKid  string // kid of the sources' HMAC key, e.g. "k1"
	Epoch    string // HMAC epoch, e.g. "2026-10"
	// SamplingRate is a decimal string, e.g. "0.05".
	SamplingRate string
	// InboundServices become services with match {inbound: true} and no
	// rules (usually the group's allowed service names).
	InboundServices []string
	// Now is the compilation time the windows start from.
	Now time.Time
	// Window defaults to DefaultStarterWindow; at most 7 days.
	Window time.Duration
}

// StarterPolicyYAML generates the onboarding starter policy (policy.md 6):
// default drop, no body rules, discovery and auto_words on for the window.
// Like every policy that opens data, it needs the opening number of
// approvals. The result is validated by compiling it.
func StarterPolicyYAML(o StarterOptions) (string, error) {
	if o.Window <= 0 {
		o.Window = DefaultStarterWindow
	}
	if o.Window > policy.MaxOpenWindow {
		return "", errors.New("fleet: the starter window cannot exceed 7 days")
	}
	if o.SamplingRate == "" {
		o.SamplingRate = "0.05"
	}
	if o.Now.IsZero() {
		return "", errors.New("fleet: StarterOptions.Now is required")
	}
	exp := o.Now.UTC().Truncate(time.Second).Add(o.Window).Format(time.RFC3339)
	var b strings.Builder
	fmt.Fprintf(&b, "# Onboarding starter policy: everything is dropped; discovery and automatic\n")
	fmt.Fprintf(&b, "# path words stay on until %s to fill the \"discovered services\" page.\n", exp)
	fmt.Fprintf(&b, "format: %s\npolicy_id: %s\ndefault: drop\n\n", policy.FormatAuthor, o.PolicyID)
	fmt.Fprintf(&b, "hmac:\n  kid: %s\n  epoch: %q\n\n", o.HMACKid, o.Epoch)
	fmt.Fprintf(&b, "sampling:\n  rate: %s\n\n", o.SamplingRate)
	fmt.Fprintf(&b, "segments:\n  auto_words: true\n  auto_words_expires_at: %q\n\n", exp)
	fmt.Fprintf(&b, "discovery:\n  enabled: true\n  expires_at: %q\n", exp)
	if len(o.InboundServices) > 0 {
		b.WriteString("\nservices:\n")
		for _, s := range normalizeNames(o.InboundServices) {
			if !reServiceName.MatchString(s) {
				return "", errors.New("fleet: invalid service name")
			}
			fmt.Fprintf(&b, "  %s:\n    match: { inbound: true }\n", s)
		}
	}
	out := b.String()
	a, err := ParseAuthor([]byte(out))
	if err != nil {
		return "", err
	}
	if _, _, err := policy.Compile(a, policy.CompileMeta{Version: 1, IssuedSeq: 1, CreatedAt: o.Now, Groups: []string{"starter-check"}}); err != nil {
		return "", fmt.Errorf("fleet: starter policy: %w", err)
	}
	return out, nil
}
