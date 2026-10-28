package keyguard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/approvebind"
	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// Pack limits (same bounds as internal/pack's reader).
const (
	MaxPackArchiveBytes = 256 << 20
	maxPackFiles        = 4096
	maxPackFileBytes    = 256 << 20
	maxPackTotal        = 1 << 30
	maxFindings         = 100
)

var (
	relPathRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	packIDRE  = regexp.MustCompile(`^pk-[0-9A-Za-z-]{1,60}$`)
)

// PackSignature is manifest.sig.json (pack.md 3).
type PackSignature struct {
	Format         string `json:"format"`
	Alg            string `json:"alg"`
	Kid            string `json:"kid"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Sig            string `json:"sig"`
}

// Finding locates a reverse-HMAC positive: file and JSON pointer (for
// .jsonl files "<line>:<pointer>"), never the value.
type Finding struct {
	File    string `json:"file"`
	Pointer string `json:"pointer"`
	Reason  string `json:"reason"`
}

// ReverseHMAC is keyguard's own reverse-HMAC result for a pack.
type ReverseHMAC struct {
	Status         string    `json:"status"`
	StringsChecked int64     `json:"strings_checked"`
	Findings       []Finding `json:"findings,omitempty"`
}

// PackResult is the answer of SignPack.
type PackResult struct {
	Signature    PackSignature `json:"signature"`
	ReverseHMAC  ReverseHMAC   `json:"reverse_hmac"`
	ApprovalMode string        `json:"approval_mode"`
}

// SigFile renders the signature as manifest.sig.json: tt canonical JSON
// with a final newline.
func (p PackSignature) SigFile() []byte {
	v := ttjson.Obj(
		ttjson.Member{Key: "alg", Value: ttjson.Str(p.Alg)},
		ttjson.Member{Key: "format", Value: ttjson.Str(p.Format)},
		ttjson.Member{Key: "kid", Value: ttjson.Str(p.Kid)},
		ttjson.Member{Key: "manifest_sha256", Value: ttjson.Str(p.ManifestSHA256)},
		ttjson.Member{Key: "sig", Value: ttjson.Str(p.Sig)},
	)
	b, _ := ttjson.Encode(v)
	return append(b, '\n')
}

type packManifest struct {
	Format    string  `json:"format"`
	PackID    string  `json:"pack_id"`
	CreatedAt string  `json:"created_at"`
	NotAfter  *string `json:"not_after"`
	Source    struct {
		Policies []PolicyRef `json:"policies"`
	} `json:"source"`
	GateReport string `json:"gate_report"`
	Files      []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
	} `json:"files"`
}

type gateReport struct {
	Format  string `json:"format"`
	PackID  string `json:"pack_id"`
	Verdict string `json:"verdict"`
	Checks  []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"checks"`
}

// maxPackManifestBytes caps manifest.json, the only file read before the
// file list is known.
const maxPackManifestBytes = 4 << 20

// packExpansionSlack covers tar headers and padding on top of maxPackTotal.
const packExpansionSlack = 64 << 20

// boundedReader fails after n bytes: the decompressed size of an archive is
// bounded whatever its headers say (zip bomb).
type boundedReader struct {
	r io.Reader
	n int64
}

var errExpansion = errors.New("archive expands too far")

func (l *boundedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errExpansion
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// walkPackArchive iterates the regular entries of a .ttpack (gzip tar)
// with the structural checks (names, duplicates, no manifest.sig.json,
// declared sizes and counts, bounded decompression). fn may read the entry
// from tr; what it leaves unread is skipped without being buffered.
func walkPackArchive(archive []byte, fn func(name string, size int64, tr *tar.Reader) *Error) *Error {
	bad := func(msg string) *Error { return apiErr(403, "invalid_pack", msg) }
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return bad("not a gzip archive")
	}
	defer zr.Close()
	tr := tar.NewReader(&boundedReader{r: zr, n: maxPackTotal + packExpansionSlack})
	seen := map[string]bool{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if errors.Is(err, errExpansion) {
				return bad("pack is too large")
			}
			return bad("malformed tar archive")
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return bad("archive entry is not a regular file")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if !relPathRE.MatchString(name) {
			return bad("archive entry name is not allowed")
		}
		if name == "manifest.sig.json" {
			return bad("the archive must not contain manifest.sig.json")
		}
		if seen[name] {
			return bad("duplicate archive entry")
		}
		if len(seen) >= maxPackFiles || h.Size < 0 || h.Size > maxPackFileBytes || total+h.Size > maxPackTotal {
			return bad("pack is too large")
		}
		seen[name] = true
		total += h.Size
		if e := fn(name, h.Size, tr); e != nil {
			return e
		}
	}
}

// scanPackArchive is the first pass: the size of every entry and the bytes
// of manifest.json (size-capped); no other entry is read or kept.
func scanPackArchive(archive []byte) (map[string]int64, []byte, *Error) {
	sizes := map[string]int64{}
	var manifest []byte
	e := walkPackArchive(archive, func(name string, size int64, tr *tar.Reader) *Error {
		sizes[name] = size
		if name != "manifest.json" {
			return nil
		}
		if size > maxPackManifestBytes {
			return apiErr(403, "invalid_pack", "manifest.json is too large")
		}
		manifest = make([]byte, size)
		if _, err := io.ReadFull(tr, manifest); err != nil {
			return apiErr(403, "invalid_pack", "truncated archive entry")
		}
		return nil
	})
	if e != nil {
		return nil, nil, e
	}
	return sizes, manifest, nil
}

// readPackFiles is the second pass: only the files listed by the manifest,
// each into a buffer of its declared size.
func readPackFiles(archive []byte, m *packManifest) (map[string][]byte, *Error) {
	want := map[string]int64{}
	for _, f := range m.Files {
		want[f.Path] = f.Bytes
	}
	files := map[string][]byte{}
	e := walkPackArchive(archive, func(name string, size int64, tr *tar.Reader) *Error {
		if name == "manifest.json" {
			return nil
		}
		w, ok := want[name]
		if !ok {
			return nil
		}
		if size != w {
			return apiErr(403, "hash_mismatch", "a file does not match its manifest hash")
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(tr, b); err != nil {
			return apiErr(403, "invalid_pack", "truncated archive entry")
		}
		files[name] = b
		return nil
	})
	if e != nil {
		return nil, e
	}
	if len(files) != len(want) {
		return nil, apiErr(403, "invalid_pack", "archive changed while it was read")
	}
	return files, nil
}

func decodeStrictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// checkPackManifest validates manifest.json (keyguard.md 3.4 steps 1-2,
// pack.md 2.1) and its file list against the sizes found in the archive,
// before any listed file is read: canonical form (what keyguard signs is
// exactly what every reader parses), created_at not in the future,
// not_after after created_at, files present with their declared sizes, no
// unlisted files.
func checkPackManifest(mb []byte, sizes map[string]int64, now time.Time) (*packManifest, *Error) {
	bad := func(code, msg string) (*packManifest, *Error) { return nil, apiErr(403, code, msg) }
	if mb == nil {
		return bad("invalid_pack", "manifest.json is missing")
	}
	if err := pack.CheckManifestCanonical(mb); err != nil {
		return bad("invalid_pack", "manifest.json is not canonical tt JSON")
	}
	var m packManifest
	if err := decodeStrictJSON(mb, &m); err != nil {
		return bad("invalid_pack", "manifest.json is not valid")
	}
	if m.Format != "tt.pack/v1" || !packIDRE.MatchString(m.PackID) {
		return bad("invalid_pack", "manifest format or pack_id is not valid")
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return bad("invalid_pack", "manifest created_at is not a date-time")
	}
	if created.After(now.Add(pack.MaxClockSkew)) {
		return bad("invalid_pack", "manifest created_at is in the future")
	}
	if m.NotAfter != nil {
		na, err := time.Parse(time.RFC3339, *m.NotAfter)
		if err != nil || !na.After(created) {
			return bad("invalid_pack", "manifest not_after must follow created_at")
		}
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if !relPathRE.MatchString(f.Path) || !sha256RE.MatchString(f.SHA256) || f.Path == "manifest.json" || f.Path == "manifest.sig.json" || listed[f.Path] {
			return bad("hash_mismatch", "malformed or duplicate files entry")
		}
		listed[f.Path] = true
		size, ok := sizes[f.Path]
		if !ok {
			return bad("hash_mismatch", "a listed file is missing")
		}
		if size != f.Bytes {
			return bad("hash_mismatch", "a file does not match its manifest hash")
		}
	}
	for name := range sizes {
		if name != "manifest.json" && !listed[name] {
			return bad("hash_mismatch", "a file is not listed in the manifest")
		}
	}
	if !listed[m.GateReport] {
		return bad("gate_report", "gate-report.json is not listed")
	}
	if len(m.Source.Policies) == 0 {
		return bad("invalid_pack", "manifest lists no source policy")
	}
	return &m, nil
}

// checkPackContent verifies the SHA-256 of every listed file and the gate
// report.
func checkPackContent(m *packManifest, files map[string][]byte) *Error {
	bad := func(code, msg string) *Error { return apiErr(403, code, msg) }
	for _, f := range m.Files {
		sum := sha256.Sum256(files[f.Path])
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return bad("hash_mismatch", "a file does not match its manifest hash")
		}
	}
	var gr gateReport
	if err := decodeStrictJSON(files[m.GateReport], &gr); err != nil || gr.Format != "tt.gate-report/v1" || gr.PackID != m.PackID {
		return bad("gate_report", "gate report is not valid for this pack")
	}
	if gr.Verdict != "pass" {
		return bad("gate_report", "gate report verdict is not pass")
	}
	seen := map[string]bool{}
	for _, c := range gr.Checks {
		if seen[c.ID] {
			return bad("gate_report", "gate report has a duplicate check")
		}
		seen[c.ID] = true
		if c.Status != "pass" && !(c.Status == "warn" && c.ID == "rules-approved") {
			return bad("gate_report", "a gate check did not pass")
		}
	}
	for _, id := range []string{"provenance", "pii-detectors", "k-thresholds", "reverse-hmac"} {
		if !seen[id] {
			return bad("gate_report", "gate report lacks a required check")
		}
	}
	return nil
}

// packString is one string or number of a pack file and where it is.
type packString struct {
	file, pointer string
	key           bool
}

// collectStrings walks every JSON value of every file (object keys
// included) and groups locations by value. .jsonl files are read per line.
// A file that is not JSON cannot be checked: the pack is refused.
func collectStrings(files map[string][]byte) (map[string][]packString, int64, *Error) {
	out := map[string][]packString{}
	var total int64
	add := func(v string, loc packString) {
		total++
		if l := out[v]; len(l) < 4 {
			out[v] = append(l, loc)
		}
	}
	var walk func(v ttjson.Value, file, ptr string)
	walk = func(v ttjson.Value, file, ptr string) {
		switch v.Kind {
		case ttjson.String, ttjson.Number:
			add(v.Str, packString{file: file, pointer: ptr})
		case ttjson.Array:
			for i, e := range v.Arr {
				walk(e, file, ptr+"/"+strconv.Itoa(i))
			}
		case ttjson.Object:
			for i, m := range v.Obj {
				// Internal form "<escaped key>\x00<member index>": the key
				// is replaced by "@k<index>" when it is itself a positive
				// (renderPointer), so no finding carries a value.
				p := ptr + "/" + escapePointer(m.Key) + "\x00" + strconv.Itoa(i)
				add(m.Key, packString{file: file, pointer: p, key: true})
				walk(m.Value, file, p)
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	opts := ttjson.ParseOptions{MaxDepth: 128}
	for _, name := range names {
		data := files[name]
		if strings.HasSuffix(name, ".jsonl") {
			for i, line := range bytes.Split(data, []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				v, err := ttjson.Parse(line, opts)
				if err != nil {
					return nil, 0, apiErr(403, "invalid_pack", "a pack file is not valid JSON lines")
				}
				walk(v, name, strconv.Itoa(i+1)+":")
			}
			continue
		}
		v, err := ttjson.Parse(data, opts)
		if err != nil {
			return nil, 0, apiErr(403, "invalid_pack", "a pack file is not valid JSON")
		}
		walk(v, name, "")
	}
	return out, total, nil
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1"), "\x00", "~2")
}

// renderPointer turns an internal pointer of collectStrings into the
// pointer of a finding: every object key that is itself a positive becomes
// "@k<n>" (the n-th member, 0-based, of its parent object), so that neither
// a positive key nor a positive below it ("/<real id>/status") reaches the
// finding (keyguard.md 3.4: file and pointer, never the value).
func renderPointer(ptr string, positive map[string]bool) string {
	parts := strings.Split(ptr, "/")
	for i, seg := range parts {
		esc, idx, ok := strings.Cut(seg, "\x00")
		if !ok {
			continue
		}
		if positive[unescapePointer(esc)] {
			parts[i] = "@k" + idx
		} else {
			parts[i] = esc
		}
	}
	return strings.Join(parts, "/")
}

func unescapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "~2", "\x00"), "~1", "/"), "~0", "~")
}

// SignPack verifies and signs a pack (keyguard.md 3.4): hashes and file
// list, gate report, keyguard's own reverse-HMAC over every string, number
// and key of every file, then the signature over "tt.pack/v1" || 0x00 ||
// manifest bytes. A positive is never overridable. requester, when given, is
// the person asking to publish: a publisher, or an admin with a reason (the
// admin override of policy.md 5, which records approval_mode "admin" and
// raises an alert but bypasses no check).
func (s *Service) SignPack(ctx context.Context, archive []byte, requester *Approval) (*PackResult, error) {
	target := audit.Target{Type: "pack"}
	details := map[string]string{}
	refuse := func(e *Error, alertType string, counts map[string]int64) (*PackResult, error) {
		if _, err := s.record(ctx, "keyguard.pack_sign", audit.Denied, e.Code, target, details); err != nil {
			return nil, err
		}
		if alertType == "" {
			alertType = AlertSignRefused
		}
		s.alerts.raise(Alert{Type: alertType, At: s.now().UTC(), Counts: counts})
		return nil, e
	}
	if len(archive) > MaxPackArchiveBytes {
		return refuse(apiErr(403, "invalid_pack", "archive too large"), "", nil)
	}
	mode := ModeStandard
	if requester != nil {
		details["requested_by"] = audit.SafeValue(requester.User)
		switch {
		case slices.Contains(requester.Roles, RolePublisher):
		case slices.Contains(requester.Roles, RoleAdmin):
			if !s.cfg.AdminOverride {
				return refuse(apiErr(403, "admin_override_disabled", "admin approval is disabled on this keyguard"), "", nil)
			}
			if strings.TrimSpace(requester.Reason) == "" {
				return refuse(apiErr(403, "admin_reason_required", "an admin approval needs a reason"), "", nil)
			}
			mode = ModeAdmin
		default:
			return refuse(apiErr(403, "missing_role", "the requester is neither publisher nor admin"), "", nil)
		}
	}
	if !s.allow(&s.lastPack, s.cfg.PackInterval) {
		return refuse(apiErr(429, "rate_limited", "pack signing is limited to one call per interval"), AlertRateLimited, nil)
	}
	sizes, mb, e := scanPackArchive(archive)
	if e != nil {
		return refuse(e, "", nil)
	}
	m, e := checkPackManifest(mb, sizes, s.now())
	if e != nil {
		return refuse(e, "", nil)
	}
	files, e := readPackFiles(archive, m)
	if e != nil {
		return refuse(e, "", nil)
	}
	if e := checkPackContent(m, files); e != nil {
		return refuse(e, "", nil)
	}
	files["manifest.json"] = mb
	target.ID = m.PackID
	details["policies"] = refsDetail(m.Source.Policies)
	manifestSum := sha256.Sum256(files["manifest.json"])
	var tokenFPs []string
	if requester != nil {
		// With OIDC the requester's token must be bound to this pack and
		// manifest (approvebind.PackNonce) and carry the declared role.
		row, _, fps, e := s.checkApproval(ctx, *requester, approvebind.PackNonce(m.PackID, hex.EncodeToString(manifestSum[:])))
		if e != nil {
			return refuse(e, "", nil)
		}
		tokenFPs = fps
		if mode == ModeAdmin {
			details["admin_reason"] = audit.SafeValue(row.Reason)
		}
	}
	mc, err := s.resolve(ctx, m.Source.Policies)
	if err != nil {
		var ae *Error
		if errors.As(err, &ae) {
			return refuse(apiErr(403, ae.Code, ae.Message), "", nil)
		}
		return nil, err
	}
	strs, total, e := collectStrings(files)
	if e != nil {
		return refuse(e, "", nil)
	}
	details["strings_checked"] = itoa(total)
	details["unique_strings"] = strconv.Itoa(len(strs))
	if _, ok, err := consumeBudget(ctx, s.db, s.now(), int64(len(strs)), s.cfg.MatchBudget); err != nil {
		return nil, err
	} else if !ok {
		return refuse(apiErr(429, "budget_exceeded", "daily match budget exhausted"), AlertBudgetExceeded, map[string]int64{"strings": int64(len(strs))})
	}
	values := make([]string, 0, len(strs))
	for v := range strs {
		values = append(values, v)
	}
	sort.Strings(values)
	cands := make([]Candidate, len(values))
	for i, v := range values {
		cands[i] = Candidate{Value: v}
	}
	hits := s.check(mc, cands)
	rh := ReverseHMAC{Status: "pass", StringsChecked: total}
	positive := map[string]bool{}
	for i, hit := range hits {
		if hit {
			positive[values[i]] = true
		}
	}
	positives := 0
	for i, hit := range hits {
		if !hit {
			continue
		}
		positives++
		for _, loc := range strs[values[i]] {
			if len(rh.Findings) >= maxFindings {
				break
			}
			reason := "matches a real token"
			if loc.key {
				reason = "object key matches a real token"
			}
			rh.Findings = append(rh.Findings, Finding{File: loc.file, Pointer: renderPointer(loc.pointer, positive), Reason: reason})
		}
	}
	if positives > 0 {
		rh.Status = "fail"
		details["positives"] = strconv.Itoa(positives)
		e := apiErr(403, "reverse_hmac", "the pack contains values that match real tokens")
		e.Extra = map[string]any{"reverse_hmac": rh}
		return refuse(e, AlertPackPositive, map[string]int64{"positives": int64(positives), "strings": total})
	}
	manifest := files["manifest.json"]
	if err := recordTokens(ctx, s.db, tokenFPs, "pack_sign", m.PackID, s.now()); err != nil {
		if errors.Is(err, errTokenReused) {
			return refuse(apiErr(403, "approval_unverifiable", "an approval ID token was already used"), "", nil)
		}
		return nil, err
	}
	kid, sig := s.packKeys.Sign(append([]byte("tt.pack/v1\x00"), manifest...))
	sum := manifestSum
	res := &PackResult{
		Signature: PackSignature{Format: "tt.pack.sig/v1", Alg: "Ed25519", Kid: kid, ManifestSHA256: hex.EncodeToString(sum[:]),
			Sig: base64.RawURLEncoding.EncodeToString(sig)},
		ReverseHMAC:  rh,
		ApprovalMode: mode,
	}
	details["kid"] = kid
	details["approval_mode"] = mode
	details["manifest_sha256"] = res.Signature.ManifestSHA256
	if _, err := s.record(ctx, "keyguard.pack_sign", audit.Success, "", target, details); err != nil {
		return nil, err
	}
	if mode == ModeAdmin {
		s.alerts.raise(Alert{Type: AlertPackAdmin, At: s.now().UTC(), Counts: map[string]int64{"strings": total}})
	}
	return res, nil
}
