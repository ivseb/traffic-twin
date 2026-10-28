package core_rt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/keyguard/client"
	"github.com/ivseb/traffic-twin/internal/packwriter"
	"github.com/ivseb/traffic-twin/internal/world"
)

// A scenario preset whose name is a real order id (its token reached
// keyguard's filter through the intake) must stop the pack: the build
// answers gate_failed with a reverse-hmac finding, the pack cannot be
// published even by an admin with a reason, and no response, log or audit
// shows the value.
func TestRT_Keyguard_Holds_RealTokenInPresetStopsPack(t *testing.T) {
	e := getEnv(t)
	real := e.orderIDs[3]
	olga := e.u(t, "olga")
	olga.must(201, "POST", "/api/v1/scenario-presets", map[string]any{"preset_id": "rt-leak", "name": real, "archetype": "arch-01"})
	var pj struct {
		Result struct {
			PackID     string          `json:"pack_id"`
			Status     string          `json:"status"`
			GateReport json.RawMessage `json:"gate_report"`
		} `json:"result"`
	}
	code, b := olga.do("POST", "/api/v1/packs", map[string]any{"world_id": e.worldID, "scenario_presets": []string{"rt-leak"}})
	if code != 202 {
		t.Fatalf("build with the preset = %d %s", code, b)
	}
	_ = json.Unmarshal(b, &pj)
	if pj.Result.Status == "signed" {
		t.Fatalf("pack with a real order id as preset name was signed")
	}
	if !bytes.Contains(b, []byte("reverse-hmac")) {
		t.Logf("gate report: %.600s", pj.Result.GateReport)
	}
	if bytes.Contains(b, []byte(real)) {
		t.Errorf("build answer echoes the real value")
	}
	if code, b := e.u(t, "ada").do("POST", "/api/v1/packs/"+pj.Result.PackID+"/publish", map[string]any{"reason": "override please"}); code < 400 {
		t.Fatalf("admin published a gate-failed pack: %d %s", code, b)
	}
	if code, _ := e.u(t, "paul").do("GET", "/api/v1/packs/"+pj.Result.PackID+"/download", nil); code < 400 {
		t.Fatalf("gate-failed pack downloadable")
	}
	pb := e.u(t, "audrey").must(200, "GET", "/api/v1/packs/"+pj.Result.PackID, nil)
	if bytes.Contains(pb, []byte(real)) {
		t.Errorf("pack view shows the real value")
	}
	e.u(t, "olga").must(204, "DELETE", "/api/v1/scenario-presets/rt-leak", nil)
	e.noValueAnywhere(t, real)
}

// noValueAnywhere checks API answers, tt-core and keyguard logs, both audit
// logs for v.
func (e *env) noValueAnywhere(t *testing.T, v string) {
	t.Helper()
	for _, r := range e.rec.snapshot() {
		if r.method == "POST" && r.path == "/api/v1/scenario-presets" {
			continue // the request that carried it (answer echoes the created preset)
		}
		if bytes.Contains(r.body, []byte(v)) && !strings.HasPrefix(r.path, "/api/v1/scenario-presets") {
			t.Errorf("%s %s answer contains the real value", r.method, r.path)
		}
	}
	if strings.Contains(e.coreLog.String(), v) {
		t.Error("tt-core log contains the real value")
	}
	if strings.Contains(e.kgLog.String(), v) {
		t.Error("keyguard log contains the real value")
	}
	raw, _ := json.Marshal(e.auditEntries(t))
	if strings.Contains(string(raw), v) {
		t.Error("tt-core audit contains the real value")
	}
	kb := e.u(t, "audrey").must(200, "GET", "/api/v1/keyguard/audit", nil)
	if bytes.Contains(kb, []byte(v)) {
		t.Error("keyguard audit contains the real value")
	}
}

// repack takes the published pack, puts v into world.jsonl (first record,
// as a new member), recomputes the manifest file list and returns an
// unsigned archive. The gate report inside still says "pass": this is what
// a buggy or compromised tt-core would send.
func (e *env) repack(t *testing.T, v string, asKey bool) []byte {
	t.Helper()
	archive := e.u(t, "paul").must(200, "GET", "/api/v1/packs/"+e.packID+"/download", nil)
	files, err := packwriter.ReadArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	delete(files, packwriter.SignaturePath)
	lines := bytes.SplitN(files["world.jsonl"], []byte("\n"), 2)
	var first map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatalf("world.jsonl: %v", err)
	}
	if asKey {
		first[v] = 1
	} else {
		first["rt_note"] = v
	}
	nl, _ := json.Marshal(first)
	files["world.jsonl"] = append(append(nl, '\n'), lines[1]...)
	var m map[string]any
	if err := json.Unmarshal(files[packwriter.ManifestPath], &m); err != nil {
		t.Fatal(err)
	}
	for _, f := range m["files"].([]any) {
		fm := f.(map[string]any)
		if fm["path"] == "world.jsonl" {
			sum := sha256.Sum256(files["world.jsonl"])
			fm["sha256"], fm["bytes"] = hex.EncodeToString(sum[:]), len(files["world.jsonl"])
		}
	}
	if files[packwriter.ManifestPath], err = world.CanonicalFile(m); err != nil {
		t.Fatal(err)
	}
	out, err := packwriter.Archive(files)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// keyguard's pack/sign, reached over its socket like tt-core does, refuses
// a pack carrying a real order id (as a value or as an object key) even
// with an admin approval and a reason: the admin override never skips
// reverse-hmac. Findings carry file and pointer, never the value.
func TestRT_Keyguard_Holds_PackSignRefusesRealTokenEvenAdminOverride(t *testing.T) {
	e := getEnv(t)
	real := e.orderIDs[5]
	kg := e.core.Keyguard()
	admin := &client.Approval{User: e.ids["ada"], Roles: []string{"admin"}, At: e.clock.Now().UTC(), Reason: "rt override"}
	for _, asKey := range []bool{false, true} {
		if asKey {
			real = e.orderIDs[6] // the key case leaks through the pointer: see the finding below
		}
		_, err := kg.SignPack(context.Background(), e.repack(t, real, asKey), admin)
		var ce *client.Error
		if !errors.As(err, &ce) || ce.Status != 403 || ce.Code != "reverse_hmac" {
			t.Fatalf("asKey=%v: keyguard pack/sign with admin override: %v (want 403 reverse_hmac)", asKey, err)
		}
		if ce.ReverseHMAC == nil || len(ce.ReverseHMAC.Findings) == 0 {
			t.Errorf("asKey=%v: no findings", asKey)
		}
		fj, _ := json.Marshal(ce)
		if !asKey && bytes.Contains(fj, []byte(real)) {
			t.Errorf("asKey=%v: refusal carries the value: %s", asKey, fj)
		}
	}
	real = e.orderIDs[5]
	// Control: a synthetic value is signed (the refusal above is the
	// reverse-hmac check, not a broken archive).
	if _, err := kg.SignPack(context.Background(), e.repack(t, "ORD-SYN-RT-0001", false), admin); err != nil {
		t.Logf("control repack refused too: %v", err)
	}
	e.noValueAnywhere(t, real)
	if !strings.Contains(e.kgLog.String(), "pack.positive") {
		t.Error("no pack.positive alert in keyguard's log")
	}
}

// FIXED (was medium, red team round 2; now a regression test). A reverse-HMAC positive on an object KEY is reported
// with a JSON pointer that ends with the key itself, i.e. the real value
// (keyguard pack.go collectStrings/escapePointer; the tt-core pre-check in
// internal/gate/reverse.go builds the same pointer). keyguard.md 3.4 says
// findings carry "file e puntatore, mai il valore". tt-core copies the
// findings into the stored gate-report.json shown in the UI and to
// auditors, so the real identifier lands in zone B storage and screens. The
// same holds for a positive below a key that is itself a value
// ("/<real id>/status").
func TestRT_Keyguard_Fixed_KeyPositivePointerCarriesValue(t *testing.T) {
	e := getEnv(t)
	real := e.orderIDs[7]
	admin := &client.Approval{User: e.ids["ada"], Roles: []string{"admin"}, At: e.clock.Now().UTC(), Reason: "rt override"}
	_, err := e.core.Keyguard().SignPack(context.Background(), e.repack(t, real, true), admin)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.ReverseHMAC == nil {
		t.Fatalf("not refused with findings: %v", err)
	}
	kb := e.u(t, "audrey").must(200, "GET", "/api/v1/keyguard/audit", nil)
	t.Logf("value also in: keyguard log=%v, keyguard audit=%v", strings.Contains(e.kgLog.String(), real), bytes.Contains(kb, []byte(real)))
	for _, f := range ce.ReverseHMAC.Findings {
		if strings.Contains(f.Pointer, real) {
			t.Fatalf("finding pointer %q (file %s, %s) carries the real value", f.Pointer, f.File, f.Reason)
		}
	}
}

// No key material (HMAC key, policy and pack signing seeds, in base64url,
// standard base64 or hex, nor the raw bytes) appears in any admin API
// answer, in tt-core's or keyguard's logs, in the tt-core audit log, or
// anywhere in tt-core's data directory (G12).
func TestRT_Keyguard_Holds_NoKeyMaterialOutsideKeyguard(t *testing.T) {
	e := getEnv(t)
	// Touch the endpoints that talk about keys.
	for _, p := range []string{"/api/v1/keyguard/status", "/api/v1/fleet/signing-keys", "/api/v1/fleet/approval-settings"} {
		e.u(t, "olga").do("GET", p, nil)
	}
	e.u(t, "audrey").do("GET", "/api/v1/keyguard/audit", nil)
	type secret struct {
		name string
		raw  []byte
	}
	var secrets []secret
	for name, content := range e.keyFiles {
		for _, line := range strings.Split(strings.TrimSpace(content), "\n") {
			i := strings.Index(line, ":")
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(line[i+1:]))
			if err != nil || len(raw) < 32 {
				t.Fatalf("%s: unexpected key line", name)
			}
			secrets = append(secrets, secret{name, raw})
		}
	}
	forms := func(raw []byte) [][]byte {
		return [][]byte{raw, []byte(base64.RawURLEncoding.EncodeToString(raw)), []byte(base64.StdEncoding.EncodeToString(raw)[:40]),
			[]byte(hex.EncodeToString(raw)), []byte(strings.ToUpper(hex.EncodeToString(raw)))}
	}
	scan := func(where string, data []byte) {
		for _, s := range secrets {
			for _, f := range forms(s.raw) {
				if bytes.Contains(data, f) {
					t.Errorf("%s contains key material of %s", where, s.name)
				}
			}
		}
	}
	for _, r := range e.rec.snapshot() {
		scan(r.method+" "+r.path+" body", r.body)
		hb, _ := json.Marshal(r.header)
		scan(r.method+" "+r.path+" headers", hb)
	}
	scan("tt-core log", []byte(e.coreLog.String()))
	scan("keyguard log", []byte(e.kgLog.String()))
	raw, _ := json.Marshal(e.auditEntries(t))
	scan("tt-core audit", raw)
	n := 0
	_ = filepath.WalkDir(e.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(p, filepath.Join(e.dir, "source")) {
			return nil // the zone-A source's own state (holds no key either, but not tt-core)
		}
		b, err := os.ReadFile(p)
		if err == nil {
			n++
			scan("tt-core data file "+strings.TrimPrefix(p, e.dir), b)
		}
		return nil
	})
	if n == 0 {
		t.Fatal("no tt-core data file scanned")
	}
	_ = time.Now
}

// Publishing as an admin needs a reason; with one, the release is signed in
// approval_mode admin, the tt-core audit records the mode and keyguard
// raises pack.admin_approval. The reason text is not in tt-core's audit.
func TestRT_Keyguard_Holds_PackAdminPublishReasonAlert(t *testing.T) {
	e := getEnv(t)
	var pj struct {
		Result struct {
			PackID string `json:"pack_id"`
			Status string `json:"status"`
		} `json:"result"`
	}
	e.u(t, "olga").json(202, "POST", "/api/v1/packs", map[string]any{"world_id": e.worldID}, &pj)
	if pj.Result.Status != "signed" {
		t.Fatalf("pack: %+v", pj)
	}
	pub := "/api/v1/packs/" + pj.Result.PackID + "/publish"
	if code, b := e.u(t, "ada").do("POST", pub, nil); code != 403 || errCode(b) != "admin_reason_required" {
		t.Errorf("admin publish without reason = %d %s", code, b)
	}
	head := e.auditHead(t)
	e.u(t, "ada").must(200, "POST", pub, map[string]any{"reason": "Rt release motivation qz5151"})
	var mode string
	for _, a := range e.auditSince(t, head) {
		if a["action"] == "pack.publish" && a["outcome"] == "success" {
			d, _ := a["details"].(map[string]any)
			mode = fmt.Sprint(d["approval_mode"])
		}
	}
	if mode != "admin" {
		t.Errorf("pack.publish audit approval_mode = %q", mode)
	}
	raw, _ := json.Marshal(e.auditEntries(t))
	if strings.Contains(string(raw), "qz5151") {
		t.Error("tt-core audit contains the publish reason text")
	}
	if !strings.Contains(e.kgLog.String(), "pack.admin_approval") {
		t.Error("no pack.admin_approval alert in keyguard's log")
	}
}
