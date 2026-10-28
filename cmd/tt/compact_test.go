package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCompactRefusesWithoutConfirmation(t *testing.T) {
	var out, errb bytes.Buffer
	db := filepath.Join(t.TempDir(), "x.db")
	if code := runCompact(context.Background(), []string{"-db", db}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "confirm-core-stopped") {
		t.Fatalf("code %d: %s", code, errb.String())
	}
}

func TestCompactConvertsALegacyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB); INSERT INTO t (b) VALUES (zeroblob(100000))`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()
	var out, errb bytes.Buffer
	if code := runCompact(context.Background(), []string{"-db", path, "-confirm-core-stopped"}, &out, &errb); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "converted") {
		t.Errorf("output: %s", out.String())
	}
	out.Reset()
	if code := runCompact(context.Background(), []string{"-db", path, "-confirm-core-stopped"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "already incremental") {
		t.Errorf("second run: %d %s %s", code, out.String(), errb.String())
	}
}
