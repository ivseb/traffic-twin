package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ivseb/traffic-twin/internal/audit"
)

// runAudit: "tt audit verify-archive -dir DIR [-key ID,...] [-head SEQ:HASH]"
// checks the archived segments of an audit log offline (signatures, file
// digests, the hash chain inside and across the segments), for example on
// the WORM copy. With -head it also checks that the archive ends where the
// live log's anchor says (GET /api/v1/store/usage audit_archive.last_seq and
// head_hash).
func runAudit(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify-archive" {
		fmt.Fprintln(stderr, "Usage: tt audit verify-archive -dir DIR [-key ed25519:ID,...] [-head SEQ:HASH]")
		return 2
	}
	fs := newFlagSet("audit verify-archive", stderr)
	dir := fs.String("dir", "", "directory of the archived segments (audit-*.json + audit-*.jsonl.gz)")
	keys := fs.String("key", "", "accepted signing key ids, comma separated (default: any key, reported)")
	head := fs.String("head", "", "expected last segment as SEQ:HASH (from the live log's anchor)")
	if code, ok := parseFlags(fs, args[1:]); !ok {
		return code
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "tt audit verify-archive: -dir is required")
		return 2
	}
	var trusted []string
	for _, k := range strings.Split(*keys, ",") {
		if k = strings.TrimSpace(k); k != "" {
			trusted = append(trusted, k)
		}
	}
	rep, err := audit.VerifyArchive(*dir, trusted...)
	if err != nil {
		fmt.Fprintf(stderr, "tt audit verify-archive: %v\n", err)
		return 1
	}
	if *head != "" {
		if want := fmt.Sprintf("%d:%s", rep.LastSeq, rep.HeadHash); want != *head {
			fmt.Fprintf(stderr, "tt audit verify-archive: the archive ends at %s, expected %s (segments missing or the anchor is of another log)\n", want, *head)
			return 1
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"ok": true, "report": rep})
	return 0
}
