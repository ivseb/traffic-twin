package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/ivseb/traffic-twin/internal/idfmt"
)

// Sentinel errors, wrapped with detail by Load.
var (
	ErrUnsigned     = errors.New("pack is not signed")
	ErrBadSignature = errors.New("pack signature is invalid")
	ErrUnknownKey   = errors.New("pack is signed by an unknown key")
	ErrRevokedKey   = errors.New("pack is signed by a revoked key")
	ErrNoKeys       = errors.New("no trusted keys configured")
	ErrExpired      = errors.New("pack_expired")
	ErrManifest     = errors.New("invalid manifest")
	ErrFiles        = errors.New("pack files do not match the manifest")
	ErrContent      = errors.New("invalid pack content")
)

const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig.json"

	maxManifestBytes = 4 << 20
	maxSigBytes      = 16 << 10

	maxFiles     = 4096
	maxFileBytes = 256 << 20
	maxTotal     = 1 << 30

	sigDomain = "tt.pack/v1"
)

var (
	relPathRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	packIDRE  = regexp.MustCompile(`^pk-[0-9A-Za-z-]{1,60}$`)
	verRE     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)
	svcNameRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62}|host:[a-z0-9.-]{1,253}(:[0-9]{1,5})?|host:(\{\*\}|[a-z0-9-]{1,63})(\.(\{\*\}|[a-z0-9-]{1,63}))*(:[0-9]{1,5})?|host:ip:(private|public)(:[0-9]{1,5})?)$`)
	aliasRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	groupRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	ruleIDRE  = regexp.MustCompile(`^r-[0-9]{4,}$`)
	sigB64RE  = regexp.MustCompile(`^[A-Za-z0-9_-]{86}$`)
)

// DefaultMaxAge is the age limit of a pack that has no not_after, applied
// when Options.MaxAge is zero (pack.md 2.1).
const DefaultMaxAge = 90 * 24 * time.Hour

// MaxClockSkew is how far in the future a manifest created_at may be.
const MaxClockSkew = 5 * time.Minute

// Options controls Load.
type Options struct {
	// Keys are the trusted gate public keys. Required.
	Keys KeySet
	// RevokedKIDs are key ids that are no longer trusted even if they are in
	// Keys (TT_GATE_REVOKED_KIDS, see RevokedKIDsFromEnv): a pack signed by
	// one of them is refused with ErrRevokedKey.
	RevokedKIDs []string
	// Now is the clock used for the expiry and age checks (default time.Now).
	Now func() time.Time
	// MaxAge limits the age of a pack (now - created_at). Zero applies
	// DefaultMaxAge to packs that have no not_after (a pack with not_after
	// is governed by it); a positive value applies to every pack; a negative
	// value disables the age check. This is a local policy of the verifier.
	MaxAge time.Duration
}

// Load reads a pack from a directory or a .ttpack archive, verifies it and
// returns its parsed content. Verification order: the manifest and its
// signature are read first, with size caps, and the signature is verified
// before any other file is read; then manifest canonical form and schema
// checks, the file list, and only the listed files are read, each with its
// exact declared size, then file hashes and content.
func Load(path string, opt Options) (*Pack, error) {
	if len(opt.Keys) == 0 {
		return nil, ErrNoKeys
	}
	src, err := openSource(path)
	if err != nil {
		return nil, err
	}
	sc, err := src.scan()
	if err != nil {
		return nil, err
	}
	mBytes, sBytes := sc.manifest, sc.sig
	if mBytes == nil {
		return nil, fmt.Errorf("%w: %s is missing", ErrManifest, manifestName)
	}
	if sBytes == nil {
		return nil, fmt.Errorf("%w: %s is missing", ErrUnsigned, sigName)
	}
	sig, err := verifySignature(mBytes, sBytes, opt.Keys, opt.RevokedKIDs)
	if err != nil {
		return nil, err
	}
	// From here the manifest is authentic: its file list sizes the reads.
	if err := CheckManifestCanonical(mBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	var m Manifest
	if err := decodeStrict(mBytes, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	created, err := validateManifest(&m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	var notAfter time.Time
	if m.NotAfter != "" {
		if notAfter, err = time.Parse(time.RFC3339, m.NotAfter); err != nil {
			return nil, fmt.Errorf("%w: not_after is not a date-time", ErrManifest)
		}
		if !notAfter.After(created) {
			return nil, fmt.Errorf("%w: not_after must be later than created_at", ErrManifest)
		}
	}
	now := time.Now()
	if opt.Now != nil {
		now = opt.Now()
	}
	if created.After(now.Add(MaxClockSkew)) {
		return nil, fmt.Errorf("%w: created_at %s is in the future", ErrManifest, m.CreatedAt)
	}
	if !notAfter.IsZero() && !now.Before(notAfter) {
		return nil, fmt.Errorf("%w: valid until %s", ErrExpired, m.NotAfter)
	}
	maxAge := opt.MaxAge
	if maxAge == 0 && notAfter.IsZero() {
		maxAge = DefaultMaxAge
	}
	if maxAge > 0 && now.Sub(created) > maxAge {
		return nil, fmt.Errorf("%w: created %s, age limit %s (a pack without not_after is limited to %s by default)", ErrExpired, m.CreatedAt, maxAge, DefaultMaxAge)
	}
	if err := checkListing(&m, sc.sizes); err != nil {
		return nil, err
	}
	files, err := src.read(m.Files)
	if err != nil {
		return nil, err
	}
	if err := checkHashes(&m, files); err != nil {
		return nil, err
	}

	p := &Pack{Manifest: m, Signature: *sig, CreatedAt: created, NotAfter: notAfter, Contracts: map[string]map[string]any{}, Files: map[string][]byte{}}
	for _, f := range m.Files {
		p.Files[f.Path] = files[f.Path]
	}
	p.Files[manifestName] = mBytes

	svcs := map[string]bool{}
	for _, s := range m.Services {
		svcs[s.Name] = true
		doc, err := parseContract(files[s.Contract])
		if err != nil {
			return nil, fmt.Errorf("%w: contract %s: %v", ErrContent, s.Contract, err)
		}
		p.Contracts[s.Name] = doc
	}
	if p.Rules, err = parseRules(files[m.Rules.Path], m.Rules.Approved, svcs); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.Rules.Path, err)
	}
	if p.World, err = parseWorld(files[m.World.Path], m.World.Customers); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.World.Path, err)
	}
	fmts := map[string]*idfmt.Template{}
	for _, name := range sortedNames(p.Contracts) {
		for d, t := range idfmt.Templates(idfmt.Collect(p.Contracts[name])) {
			if fmts[d] == nil {
				fmts[d] = t
			}
		}
	}
	if err = checkWorld(p.World, p.Rules, fmts); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.World.Path, err)
	}
	if p.Faults, err = parseFaults(files[m.Faults], svcs); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.Faults, err)
	}
	if p.GateReport, err = parseGateReport(files[m.GateReport], &m); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.GateReport, err)
	}
	if m.Scenarios != "" {
		if p.Scenarios, err = parseScenarios(files[m.Scenarios], p.World, p.Rules, svcs); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrContent, m.Scenarios, err)
		}
	}
	return p, nil
}

// VerifySignature checks manifest.sig.json against the manifest bytes: format,
// algorithm, known kid, manifest hash and the Ed25519 signature over
// "tt.pack/v1" || 0x00 || manifest bytes.
func VerifySignature(manifest, sigJSON []byte, keys KeySet) (*Signature, error) {
	return verifySignature(manifest, sigJSON, keys, nil)
}

func verifySignature(manifest, sigJSON []byte, keys KeySet, revoked []string) (*Signature, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	var s Signature
	if err := decodeStrict(sigJSON, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if s.Format != "tt.pack.sig/v1" || s.Alg != "Ed25519" {
		return nil, fmt.Errorf("%w: unsupported format or algorithm", ErrBadSignature)
	}
	if !kidRE.MatchString(s.KID) || !sha256RE.MatchString(s.ManifestSHA256) || !sigB64RE.MatchString(s.Sig) {
		return nil, fmt.Errorf("%w: malformed fields", ErrBadSignature)
	}
	if slices.Contains(revoked, s.KID) {
		return nil, fmt.Errorf("%w: kid %q", ErrRevokedKey, s.KID)
	}
	pub, ok := keys[s.KID]
	if !ok {
		return nil, fmt.Errorf("%w: kid %q", ErrUnknownKey, s.KID)
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != s.ManifestSHA256 {
		return nil, fmt.Errorf("%w: manifest hash differs", ErrBadSignature)
	}
	raw, err := decodeB64URL(s.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: malformed signature", ErrBadSignature)
	}
	msg := make([]byte, 0, len(sigDomain)+1+len(manifest))
	msg = append(msg, sigDomain...)
	msg = append(msg, 0)
	msg = append(msg, manifest...)
	if !ed25519.Verify(pub, msg, raw) {
		return nil, ErrBadSignature
	}
	return &s, nil
}

func validateManifest(m *Manifest) (time.Time, error) {
	var zero time.Time
	if m.Format != "tt.pack/v1" {
		return zero, errors.New("format must be tt.pack/v1")
	}
	if !packIDRE.MatchString(m.PackID) {
		return zero, errors.New("pack_id is malformed")
	}
	created, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return zero, errors.New("created_at is not a date-time")
	}
	if !verRE.MatchString(m.TTVersion) {
		return zero, errors.New("tt_version is malformed")
	}
	if m.KMin < 2 {
		return zero, errors.New("k_min must be >= 2")
	}
	if len(m.Services) == 0 {
		return zero, errors.New("no services")
	}
	seen := map[string]bool{}
	for _, s := range m.Services {
		if !svcNameRE.MatchString(s.Name) || !relPathRE.MatchString(s.Contract) {
			return zero, errors.New("malformed service entry")
		}
		if s.UpstreamAlias != "" && !aliasRE.MatchString(s.UpstreamAlias) {
			return zero, errors.New("malformed upstream_alias")
		}
		for _, n := range []string{s.Name, s.UpstreamAlias} {
			if n == "" {
				continue
			}
			if seen[n] {
				return zero, fmt.Errorf("service name or alias %q is not unique", n)
			}
			seen[n] = true
		}
	}
	for _, r := range m.Rules.Approved {
		if !ruleIDRE.MatchString(r) {
			return zero, errors.New("malformed approved rule id")
		}
	}
	for _, p := range []string{m.Rules.Path, m.World.Path, m.Faults, m.GateReport} {
		if !relPathRE.MatchString(p) {
			return zero, errors.New("malformed file path")
		}
	}
	if m.Scenarios != "" && !relPathRE.MatchString(m.Scenarios) {
		return zero, errors.New("malformed scenarios path")
	}
	if m.World.Customers < 0 {
		return zero, errors.New("negative customers")
	}
	if m.Group != "" && !groupRE.MatchString(m.Group) {
		return zero, errors.New("malformed group")
	}
	return created, nil
}

// decodeStrict decodes exactly one JSON value, rejecting unknown fields and
// trailing data. Numbers inside any/map values are json.Number.
func decodeStrict(data []byte, v any) error {
	dec := newDecoder(data)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func newDecoder(data []byte) *json.Decoder {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	return d
}

// decodeStrictAny decodes one JSON value (unknown fields allowed) with
// json.Number numbers.
func decodeStrictAny(data []byte, v any) error {
	dec := newDecoder(data)
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func sortedNames(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
