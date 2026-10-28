package mock

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFlagsS3AndPages(t *testing.T) {
	c, err := ParseFlags([]string{"--pack", "x.ttpack", "--s3-host", "s3.mock.test, storage.test", "--s3-buckets", "docs,uploads"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.S3 == nil || !c.S3.Enabled || len(c.S3.Hosts) != 2 || c.S3.Hosts[1] != "storage.test" || len(c.S3.Buckets) != 2 || c.S3.MaxObjectBytes != 16<<20 {
		t.Fatalf("s3: %+v", c.S3)
	}
	if _, err := ParseFlags([]string{"--pack", "x", "--s3-buckets", "Not_Valid"}, io.Discard); err == nil {
		t.Fatal("invalid bucket accepted")
	}
	if c, _ := ParseFlags([]string{"--pack", "x"}, io.Discard); c.S3 != nil {
		t.Fatal("s3 on by default")
	}
	f := filepath.Join(t.TempDir(), "pages.json")
	b, _ := json.Marshal(payPage("https://app.test"))
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = ParseFlags([]string{"--pack", "x", "--pages", f}, io.Discard)
	if err != nil || c.Pages == nil || c.Pages.Pages[0].ID != "pay" {
		t.Fatalf("pages: %v %+v", err, c.Pages)
	}
	if err := os.WriteFile(f, []byte(`{"pages":[{"id":"p","title":"t","buttons":[],"oops":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFlags([]string{"--pack", "x", "--pages", f}, io.Discard); err == nil {
		t.Fatal("invalid pages file accepted")
	}
}
