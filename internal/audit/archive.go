package audit

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Segmented archiving (schema version 2).
//
// The audit log is append-only and hash-chained, and it grows forever. Old
// entries are never deleted silently: they leave the database only as a
// closed SEGMENT, after it was written to a verifiable archive file.
//
//  1. A segment is a run of consecutive entries of one calendar month (UTC),
//     at most SegmentEntries long, all older than the archive cutoff, and
//     never the newest entry (the chain head stays in the database).
//  2. Archive writes the entries as JSON Lines (gzip) to
//     audit-<first>-<last>.jsonl.gz and a manifest audit-<first>-<last>.json
//     with the range, the prev_hash of the first entry, the head hash (the
//     hash of the last entry), the SHA-256 of the file and an Ed25519
//     signature of the manifest. Both files are fsynced and renamed in place.
//  3. The segment is recorded in audit_segments (state exported) and an
//     audit.archive entry is appended to the live chain: the new head
//     commits to the archive (range, head hash, file digest).
//  4. The entries are deleted in chunks (the delete trigger refuses any
//     entry not covered by a segment row) and the segment becomes pruned.
//
// A crash anywhere resumes at the next run: an exported segment is checked
// against its file again and its deletion completed. [Log.Verify] proves the
// continuity of what is left: the segments link to each other (first_seq,
// prev hash) from the genesis, and the first remaining entry links to the
// head hash of the last pruned segment. [VerifyArchive] checks the files
// themselves: signatures, digests and the hash chain inside and across them.
//
// Keep the archive directory on WORM storage (object lock, append-only
// mount) and copy each new pair of files off the host: the signing key lives
// next to the database, so the signature proves integrity of the files, not
// that the host was honest; the chain anchored in the live log (and the head
// hash kept outside, see Head) does.

var archiveMigration = `
CREATE TABLE audit_segments (
	first_seq       INTEGER PRIMARY KEY,
	last_seq        INTEGER NOT NULL,
	entries         INTEGER NOT NULL,
	first_prev_hash TEXT    NOT NULL,
	head_hash       TEXT    NOT NULL,
	from_ts         TEXT    NOT NULL,
	to_ts           TEXT    NOT NULL,
	file            TEXT    NOT NULL,
	file_sha256     TEXT    NOT NULL,
	key_id          TEXT    NOT NULL,
	signature       TEXT    NOT NULL,
	created_at      TEXT    NOT NULL,
	state           TEXT    NOT NULL CHECK (state IN ('exported', 'pruned'))
) STRICT;
CREATE TRIGGER audit_segments_no_delete BEFORE DELETE ON audit_segments
BEGIN SELECT RAISE(ABORT, 'audit segments are permanent'); END;
CREATE TRIGGER audit_segments_only_prune BEFORE UPDATE ON audit_segments
WHEN NOT (OLD.state = 'exported' AND NEW.state = 'pruned' AND NEW.first_seq = OLD.first_seq AND NEW.last_seq = OLD.last_seq
	AND NEW.head_hash = OLD.head_hash AND NEW.first_prev_hash = OLD.first_prev_hash AND NEW.file_sha256 = OLD.file_sha256)
BEGIN SELECT RAISE(ABORT, 'audit segments only move from exported to pruned'); END;
DROP TRIGGER audit_entries_no_delete;
CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
WHEN NOT EXISTS (SELECT 1 FROM audit_segments WHERE OLD.seq BETWEEN first_seq AND last_seq)
BEGIN SELECT RAISE(ABORT, 'audit log is append-only: only entries of an archived segment can leave the database'); END;
`

// Segment is one archived range of the log.
type Segment struct {
	FirstSeq      int64     `json:"first_seq"`
	LastSeq       int64     `json:"last_seq"`
	Entries       int64     `json:"entries"`
	FirstPrevHash string    `json:"first_prev_hash"`
	HeadHash      string    `json:"head_hash"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	File          string    `json:"file"`
	FileSHA256    string    `json:"file_sha256"`
	KeyID         string    `json:"key_id"`
	CreatedAt     time.Time `json:"created_at"`
	// State is exported (file written, entries still in the database) or
	// pruned (entries removed).
	State string `json:"state"`
}

// SegmentManifest is the signed description of an archive file.
type SegmentManifest struct {
	Format        string `json:"format"`
	Log           string `json:"log"`
	FirstSeq      int64  `json:"first_seq"`
	LastSeq       int64  `json:"last_seq"`
	Entries       int64  `json:"entries"`
	FirstPrevHash string `json:"first_prev_hash"`
	HeadHash      string `json:"head_hash"`
	From          string `json:"from"`
	To            string `json:"to"`
	File          string `json:"file"`
	FileSHA256    string `json:"file_sha256"`
	CreatedAt     string `json:"created_at"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature,omitempty"`
}

// ManifestFormat identifies segment manifests.
const ManifestFormat = "tt.audit.segment/v1"

func (m SegmentManifest) signedBytes() []byte {
	m.Signature = ""
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return append([]byte("tt.audit.segment/v1\n"), b...)
}

// ArchiveKey signs segment manifests.
type ArchiveKey struct {
	priv ed25519.PrivateKey
}

// KeyID is "ed25519:" and the first 16 bytes of the SHA-256 of the public key, in hex.
func (k *ArchiveKey) KeyID() string {
	sum := sha256.Sum256(k.priv.Public().(ed25519.PublicKey))
	return "ed25519:" + hex.EncodeToString(sum[:16])
}

// LoadOrCreateArchiveKey reads the PKCS#8 PEM Ed25519 key at path, creating
// it (mode 0600) when missing.
func LoadOrCreateArchiveKey(path string) (*ArchiveKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		der, merr := x509.MarshalPKCS8PrivateKey(priv)
		if merr != nil {
			return nil, merr
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			return nil, fmt.Errorf("audit: create archive key: %w", oerr)
		}
		if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		return &ArchiveKey{priv: priv}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: archive key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("audit: archive key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit: archive key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("audit: archive key: not Ed25519")
	}
	return &ArchiveKey{priv: priv}, nil
}

// ArchiveOptions configure one archive run.
type ArchiveOptions struct {
	// Dir receives the archive files. Required: without it nothing is
	// archived (and nothing is ever deleted).
	Dir string
	// Key signs the manifests. Required.
	Key *ArchiveKey
	// Before: only entries older than this are archived.
	Before time.Time
	// SegmentEntries bounds a segment (default 50 000).
	SegmentEntries int
	// LogName names the log in the manifest ("tt-core", "keyguard").
	LogName string
	// Actor of the audit.archive entry (default system "audit").
	Actor Actor

	headSeq int64 // entries from this seq on stay (set by Archive)
}

// ArchiveResult reports an archive run.
type ArchiveResult struct {
	Segments []Segment `json:"segments"`
	// Entries is the number of entries removed from the database.
	Entries int64 `json:"entries"`
}

const deleteChunk = 5000

// Archive exports and removes the closed segments older than o.Before. It
// is idempotent and resumes an interrupted run.
func (l *Log) Archive(ctx context.Context, o ArchiveOptions) (ArchiveResult, error) {
	var res ArchiveResult
	if o.Dir == "" || o.Key == nil {
		return res, errors.New("audit: archive needs a directory and a key")
	}
	o.defaults()
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return res, fmt.Errorf("audit: archive dir: %w", err)
	}
	// First finish what a previous run left exported.
	segs, err := l.Segments(ctx)
	if err != nil {
		return res, err
	}
	for _, s := range segs {
		if s.State != "exported" {
			continue
		}
		if err := checkSegmentFile(o.Dir, s); err != nil {
			return res, fmt.Errorf("audit: exported segment %d-%d: %w (entries kept)", s.FirstSeq, s.LastSeq, err)
		}
		n, err := l.prune(ctx, s)
		res.Entries += n
		if err != nil {
			return res, err
		}
	}
	// Only the entries that existed when the run started: the run's own
	// audit.archive entries wait for the next run.
	if o.headSeq, _, err = l.Head(ctx); err != nil {
		return res, err
	}
	for ctx.Err() == nil {
		s, ok, err := l.nextSegment(ctx, o)
		if err != nil || !ok {
			return res, err
		}
		if err := l.writeSegment(ctx, o, &s); err != nil {
			return res, err
		}
		if _, err := l.db.ExecContext(ctx, `INSERT INTO audit_segments (first_seq, last_seq, entries, first_prev_hash, head_hash, from_ts, to_ts,
			file, file_sha256, key_id, signature, created_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'exported')`,
			s.FirstSeq, s.LastSeq, s.Entries, s.FirstPrevHash, s.HeadHash, s.From.Format(time.RFC3339Nano), s.To.Format(time.RFC3339Nano),
			s.File, s.FileSHA256, s.KeyID, s.sig, s.CreatedAt.Format(time.RFC3339Nano)); err != nil {
			return res, fmt.Errorf("audit: record segment: %w", err)
		}
		if _, err := l.Record(ctx, Event{Actor: o.Actor, Action: "audit.archive", Target: Target{Type: "audit_segment", ID: strconv.FormatInt(s.FirstSeq, 10) + "-" + strconv.FormatInt(s.LastSeq, 10)},
			Outcome: Success, Details: map[string]string{"entries": strconv.FormatInt(s.Entries, 10), "head_hash": s.HeadHash,
				"file_sha256": s.FileSHA256, "key_id": s.KeyID}}); err != nil {
			return res, err
		}
		n, err := l.prune(ctx, s.Segment)
		res.Entries += n
		if err != nil {
			return res, err
		}
		s.State = "pruned"
		res.Segments = append(res.Segments, s.Segment)
	}
	return res, ctx.Err()
}

func (o *ArchiveOptions) defaults() {
	if o.SegmentEntries <= 0 {
		o.SegmentEntries = 50_000
	}
	if o.LogName == "" {
		o.LogName = "tt-core"
	}
	if o.Actor.Kind == "" {
		o.Actor = Actor{Kind: ActorSystem, ID: "audit"}
	}
}

type pendingSegment struct {
	Segment
	sig     string
	entries []Entry
}

// nextSegment collects the next closed segment after the last recorded one.
func (l *Log) nextSegment(ctx context.Context, o ArchiveOptions) (pendingSegment, bool, error) {
	o.defaults()
	var s pendingSegment
	after := int64(0)
	prev := GenesisHash
	var lastSeq sql.NullInt64
	var lastHead sql.NullString
	if err := l.db.QueryRowContext(ctx, `SELECT last_seq, head_hash FROM audit_segments ORDER BY first_seq DESC LIMIT 1`).Scan(&lastSeq, &lastHead); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return s, false, err
	}
	if lastSeq.Valid {
		after, prev = lastSeq.Int64, lastHead.String
	}
	headSeq, _, err := l.Head(ctx)
	if err != nil {
		return s, false, err
	}
	if o.headSeq > 0 {
		headSeq = min(headSeq, o.headSeq)
	}
	closed := false
	var month string
	stop := errors.New("stop")
	err = l.Iterate(ctx, after, o.SegmentEntries+1, func(e Entry) error {
		m := e.Time.UTC().Format("2006-01")
		switch {
		case e.Seq >= headSeq:
			return stop // the head stays in the database
		case !e.Time.Before(o.Before):
			return stop // not old enough: the segment is still open
		case month != "" && m != month:
			closed = true // a new month starts: the segment is complete
			return stop
		case len(s.entries) == o.SegmentEntries:
			closed = true
			return stop
		}
		month = m
		s.entries = append(s.entries, e)
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return s, false, err
	}
	if len(s.entries) == 0 {
		return s, false, nil
	}
	// A partial month is archived only when the whole month is older than
	// the cutoff (the next entry, or the cutoff, is in a later month).
	if !closed {
		end := s.entries[len(s.entries)-1].Time.UTC()
		monthEnd := time.Date(end.Year(), end.Month()+1, 1, 0, 0, 0, 0, time.UTC)
		if monthEnd.After(o.Before) {
			return s, false, nil
		}
	}
	first, last := s.entries[0], s.entries[len(s.entries)-1]
	if first.Seq != after+1 || first.PrevHash != prev {
		return s, false, fmt.Errorf("%w: seq %d does not continue the last archived segment", ErrTampered, first.Seq)
	}
	s.Segment = Segment{FirstSeq: first.Seq, LastSeq: last.Seq, Entries: int64(len(s.entries)), FirstPrevHash: first.PrevHash,
		HeadHash: last.Hash, From: first.Time, To: last.Time, State: "exported"}
	return s, true, nil
}

func segmentBase(first, last int64) string { return fmt.Sprintf("audit-%012d-%012d", first, last) }

// writeSegment verifies the entries' chain, writes the archive file and its
// signed manifest.
func (l *Log) writeSegment(ctx context.Context, o ArchiveOptions, s *pendingSegment) error {
	prev := s.FirstPrevHash
	for i, e := range s.entries {
		if e.PrevHash != prev || e.computeHash() != e.Hash || (i > 0 && e.Seq != s.entries[i-1].Seq+1) {
			return fmt.Errorf("%w: seq %d (not archived)", ErrTampered, e.Seq)
		}
		prev = e.Hash
	}
	base := segmentBase(s.FirstSeq, s.LastSeq)
	s.File = base + ".jsonl.gz"
	sum, err := writeAtomic(filepath.Join(o.Dir, s.File), func(w io.Writer) error {
		zw := gzip.NewWriter(w)
		bw := bufio.NewWriter(zw)
		enc := json.NewEncoder(bw)
		for _, e := range s.entries {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		if err := bw.Flush(); err != nil {
			return err
		}
		return zw.Close()
	})
	if err != nil {
		return err
	}
	s.FileSHA256 = sum
	s.CreatedAt = l.now().UTC().Truncate(time.Microsecond)
	s.KeyID = o.Key.KeyID()
	m := SegmentManifest{Format: ManifestFormat, Log: o.LogName, FirstSeq: s.FirstSeq, LastSeq: s.LastSeq, Entries: s.Entries,
		FirstPrevHash: s.FirstPrevHash, HeadHash: s.HeadHash, From: s.From.UTC().Format(time.RFC3339Nano), To: s.To.UTC().Format(time.RFC3339Nano),
		File: s.File, FileSHA256: s.FileSHA256, CreatedAt: s.CreatedAt.Format(time.RFC3339Nano), KeyID: s.KeyID,
		PublicKey: base64.StdEncoding.EncodeToString(o.Key.priv.Public().(ed25519.PublicKey))}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(o.Key.priv, m.signedBytes()))
	s.sig = m.Signature
	_, err = writeAtomic(filepath.Join(o.Dir, base+".json"), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(m)
	})
	_ = ctx
	return err
}

// writeAtomic writes path through a temporary file, fsyncs and renames it,
// and returns the hex SHA-256 of the content. It refuses to replace a file
// with different content (an archive is never rewritten).
func writeAtomic(path string, fill func(io.Writer) error) (string, error) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if err := fill(io.MultiWriter(f, h)); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if old, err := fileSHA256(path); err == nil && old != sum {
		os.Remove(tmp)
		return "", fmt.Errorf("audit: %s exists with different content: not overwritten", filepath.Base(path))
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return sum, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkSegmentFile(dir string, s Segment) error {
	sum, err := fileSHA256(filepath.Join(dir, s.File))
	if err != nil {
		return err
	}
	if sum != s.FileSHA256 {
		return errors.New("archive file digest mismatch")
	}
	return nil
}

// prune deletes the entries of an exported segment, in chunks, and marks it
// pruned. It checks first that the entries still in the database end at the
// segment's head hash.
func (l *Log) prune(ctx context.Context, s Segment) (int64, error) {
	var head sql.NullString
	if err := l.db.QueryRowContext(ctx, `SELECT hash FROM audit_entries WHERE seq = ?`, s.LastSeq).Scan(&head); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if head.Valid && head.String != s.HeadHash {
		return 0, fmt.Errorf("%w: seq %d does not match its archived segment", ErrTampered, s.LastSeq)
	}
	var n int64
	for lo := s.FirstSeq; lo <= s.LastSeq; lo += deleteChunk {
		hi := min(lo+deleteChunk-1, s.LastSeq)
		r, err := l.db.ExecContext(ctx, `DELETE FROM audit_entries WHERE seq BETWEEN ? AND ?`, lo, hi)
		if err != nil {
			return n, fmt.Errorf("audit: prune segment: %w", err)
		}
		k, _ := r.RowsAffected()
		n += k
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
	}
	_, err := l.db.ExecContext(ctx, `UPDATE audit_segments SET state = 'pruned' WHERE first_seq = ?`, s.FirstSeq)
	return n, err
}

// Segments lists the archived segments in seq order.
func (l *Log) Segments(ctx context.Context) ([]Segment, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT first_seq, last_seq, entries, first_prev_hash, head_hash, from_ts, to_ts, file, file_sha256,
		key_id, created_at, state FROM audit_segments ORDER BY first_seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Segment
	for rows.Next() {
		var s Segment
		var from, to, created string
		if err := rows.Scan(&s.FirstSeq, &s.LastSeq, &s.Entries, &s.FirstPrevHash, &s.HeadHash, &from, &to, &s.File, &s.FileSHA256,
			&s.KeyID, &created, &s.State); err != nil {
			return nil, err
		}
		s.From, _ = time.Parse(time.RFC3339Nano, from)
		s.To, _ = time.Parse(time.RFC3339Nano, to)
		s.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, s)
	}
	return out, rows.Err()
}

// anchor returns the newest pruned segment (zero when none): the remaining
// chain must continue from its head.
func (l *Log) anchor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (int64, string, error) {
	var seq int64
	var hash string
	err := q.QueryRowContext(ctx, `SELECT last_seq, head_hash FROM audit_segments ORDER BY first_seq DESC LIMIT 1`).Scan(&seq, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, GenesisHash, nil
	}
	return seq, hash, err
}

// verifySegments checks the segment rows link to each other from the
// genesis and returns the seq after which the database entries must start
// (the last pruned segment), its head hash, and the exported segments whose
// entries are (partly) still in the database.
func verifySegments(segs []Segment) (int64, string, map[int64]Segment, error) {
	prevSeq, prevHash := int64(0), GenesisHash
	exported := map[int64]Segment{}
	for _, s := range segs {
		if s.FirstSeq != prevSeq+1 || s.FirstPrevHash != prevHash || s.LastSeq < s.FirstSeq || s.Entries != s.LastSeq-s.FirstSeq+1 {
			return 0, "", nil, fmt.Errorf("%w: archived segment %d-%d does not continue the previous one", ErrTampered, s.FirstSeq, s.LastSeq)
		}
		if s.State == "exported" {
			exported[s.LastSeq] = s
		}
		prevSeq, prevHash = s.LastSeq, s.HeadHash
	}
	return prevSeq, prevHash, exported, nil
}

// ArchiveReport is the result of VerifyArchive.
type ArchiveReport struct {
	Segments int      `json:"segments"`
	Entries  int64    `json:"entries"`
	FirstSeq int64    `json:"first_seq"`
	LastSeq  int64    `json:"last_seq"`
	HeadHash string   `json:"head_hash"`
	KeyIDs   []string `json:"key_ids"`
}

// VerifyArchive checks every segment manifest in dir: its signature, the
// digest of its file, the hash chain of the entries inside, and that the
// segments follow each other from the genesis without a gap. trustedKeys
// (optional) restricts the accepted key ids.
func VerifyArchive(dir string, trustedKeys ...string) (ArchiveReport, error) {
	var rep ArchiveReport
	names, err := filepath.Glob(filepath.Join(dir, "audit-*-*.json"))
	if err != nil {
		return rep, err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return rep, errors.New("audit: no segment manifest in the archive directory")
	}
	keys := map[string]bool{}
	prevSeq, prevHash := int64(0), GenesisHash
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return rep, err
		}
		var m SegmentManifest
		if err := json.Unmarshal(b, &m); err != nil || m.Format != ManifestFormat {
			return rep, fmt.Errorf("audit: %s: not a segment manifest", filepath.Base(n))
		}
		pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
		sig, err2 := base64.StdEncoding.DecodeString(m.Signature)
		if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, m.signedBytes(), sig) {
			return rep, fmt.Errorf("%w: %s: bad signature", ErrTampered, filepath.Base(n))
		}
		sum := sha256.Sum256(pub)
		if kid := "ed25519:" + hex.EncodeToString(sum[:16]); kid != m.KeyID {
			return rep, fmt.Errorf("%w: %s: key id does not match the key", ErrTampered, filepath.Base(n))
		}
		if len(trustedKeys) > 0 && !contains(trustedKeys, m.KeyID) {
			return rep, fmt.Errorf("audit: %s: signed by untrusted key %s", filepath.Base(n), m.KeyID)
		}
		keys[m.KeyID] = true
		if m.FirstSeq != prevSeq+1 || m.FirstPrevHash != prevHash {
			return rep, fmt.Errorf("%w: segment %d-%d does not continue the previous one (gap or reorder)", ErrTampered, m.FirstSeq, m.LastSeq)
		}
		if strings.ContainsAny(m.File, `/\`) {
			return rep, fmt.Errorf("audit: %s: invalid file name", filepath.Base(n))
		}
		fsum, err := fileSHA256(filepath.Join(dir, m.File))
		if err != nil {
			return rep, err
		}
		if fsum != m.FileSHA256 {
			return rep, fmt.Errorf("%w: %s: digest mismatch", ErrTampered, m.File)
		}
		head, count, err := verifySegmentFile(filepath.Join(dir, m.File), m.FirstSeq, m.FirstPrevHash)
		if err != nil {
			return rep, err
		}
		if count != m.Entries || head != m.HeadHash || m.FirstSeq+count-1 != m.LastSeq {
			return rep, fmt.Errorf("%w: %s: content does not match the manifest", ErrTampered, m.File)
		}
		rep.Segments++
		rep.Entries += count
		if rep.FirstSeq == 0 {
			rep.FirstSeq = m.FirstSeq
		}
		rep.LastSeq, rep.HeadHash = m.LastSeq, m.HeadHash
		prevSeq, prevHash = m.LastSeq, m.HeadHash
	}
	for k := range keys {
		rep.KeyIDs = append(rep.KeyIDs, k)
	}
	sort.Strings(rep.KeyIDs)
	return rep, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func verifySegmentFile(path string, firstSeq int64, prev string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %s: %v", ErrTampered, filepath.Base(path), err)
	}
	dec := json.NewDecoder(zr)
	want := firstSeq
	var n int64
	for {
		var e Entry
		if err := dec.Decode(&e); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", 0, fmt.Errorf("%w: %s: %v", ErrTampered, filepath.Base(path), err)
		}
		if e.Seq != want || e.PrevHash != prev || e.computeHash() != e.Hash {
			return "", 0, fmt.Errorf("%w: %s: seq %d", ErrTampered, filepath.Base(path), e.Seq)
		}
		prev = e.Hash
		want++
		n++
	}
	return prev, n, nil
}
