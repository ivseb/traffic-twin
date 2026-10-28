package fleet

import (
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/auth"
)

func TestKeyguardRollbackRefusalIsAConflict(t *testing.T) {
	for _, code := range []string{"issued_seq_not_increasing", "version_not_increasing"} {
		err := keyguardRefusal(&SignRefusedError{Code: code}, "keyguard refused to sign: ")
		if err.Status != 409 || err.Code != "keyguard_state_conflict" ||
			!strings.Contains(err.Message, "one tt-core per keyguard") || !strings.Contains(err.Message, code) {
			t.Errorf("%s: %+v", code, err)
		}
	}
	err := keyguardRefusal(&SignRefusedError{Code: "approvals_insufficient"}, "keyguard refused to sign: ")
	if err.Status != 502 || err.Code != "keyguard_refused" || !strings.Contains(err.Message, "approvals_insufficient") {
		t.Errorf("other refusals stay 502: %+v", err)
	}
}

func TestSecondCoreOnTheSameKeyguardGets409(t *testing.T) {
	e := newEnv(t, nil)
	e.setup()
	e.user("bob", auth.RolePolicyApprover)
	e.user("carol", auth.RolePolicyApprover)
	e.user("pat", auth.RolePolicyApprover, auth.RoleOperator)
	v := e.propose("pat", policyV1)
	e.must(e.approve("bob", v, nil), 200)
	// keyguard already signed a later issued_seq: another core owns it.
	e.signer.refuse = "issued_seq_not_increasing"
	if r := e.approve("carol", v, nil); r.code != 409 || r.errCode() != "keyguard_state_conflict" {
		t.Fatalf("approve against a keyguard owned by another core: %d %s", r.code, r.body)
	}
}
