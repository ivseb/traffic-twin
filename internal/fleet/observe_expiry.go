package fleet

import (
	"bytes"
	"context"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// noteWindowsClosed is the note of the version that removes the discovery
// and automatic path words windows once they expired.
const noteWindowsClosed = "observe phase: expired discovery and automatic path words removed"

// stripExpiredWindows removes, from an author policy, the discovery block and
// the automatic path words when their window ended before now (policy.md 7):
// a closing change. ok is false when nothing expired.
func stripExpiredWindows(doc []byte, now time.Time) ([]byte, bool, error) {
	a, err := ParseAuthor(doc)
	if err != nil {
		return nil, false, err
	}
	expired := func(s string) bool {
		t, err := time.Parse(time.RFC3339Nano, s)
		return err == nil && !t.After(now)
	}
	disc := a.Discovery != nil && a.Discovery.Enabled && expired(a.Discovery.ExpiresAt)
	words := a.Segments.AutoWords && expired(a.Segments.AutoWordsExpiresAt)
	if !disc && !words {
		return nil, false, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(doc, &root); err != nil || root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, false, invalid("invalid_policy", "the policy document cannot be edited")
	}
	top := root.Content[0]
	if disc {
		mapDel(top, "discovery")
	}
	if seg := mapGet(top, "segments"); words && seg != nil && seg.Kind == yaml.MappingNode {
		mapDel(seg, "auto_words")
		mapDel(seg, "auto_words_expires_at")
		if len(seg.Content) == 0 {
			mapDel(top, "segments")
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, false, err
	}
	if err := enc.Close(); err != nil {
		return nil, false, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n") + "\n"), true, nil
}

// closeExpiredWindows replaces an active version whose discovery or
// automatic path words window ended (it cannot be renewed as is: the
// windows must lie within 7 days of the compilation) with a version
// without them. It is a closing change: with observe_auto it applies at
// once; otherwise it is a draft (1 approval). done reports that a version
// was created (or one is already pending). Caller holds policyMu.
func (f *Fleet) closeExpiredWindows(ctx context.Context, ap *activePolicy, now time.Time) (bool, error) {
	var author string
	if err := f.db.QueryRowContext(ctx, `SELECT author FROM fleet_policy_versions WHERE policy_id = ? AND version = ?`, ap.policyID, ap.version).Scan(&author); err != nil {
		return false, err
	}
	doc, ok, err := stripExpiredWindows([]byte(author), now)
	if err != nil || !ok {
		return false, err
	}
	var pending int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleet_policy_versions WHERE policy_id = ? AND status = ? AND note = ?`,
		ap.policyID, StatusDraft, noteWindowsClosed).Scan(&pending); err != nil || pending > 0 {
		return pending > 0, err
	}
	_, err = f.createDraftFolding(ctx, systemPrincipal(), doc, OriginObserveAuto, noteWindowsClosed, nil)
	return err == nil, err
}
