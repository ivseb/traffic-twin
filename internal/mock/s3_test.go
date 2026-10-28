package mock

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/pack/packtest"
)

func withConfig(f func(*Config)) envOpt { return func(_ *packtest.Spec, c *Config) { f(c) } }

// s3req sends a raw S3 request with a (never checked) SigV4 header.
func (e *env) s3req(method, path, host string, body []byte, hdr map[string]string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261028/eu-south-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef")
	req.Header.Set("X-Amz-Date", "20261028T000000Z")
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func TestS3PathAndVirtualHost(t *testing.T) {
	e := newEnv(t, withConfig(func(c *Config) {
		c.S3 = &S3Config{Enabled: true, Hosts: []string{"s3.mock.test"}, Buckets: []string{"docs"}, MaxObjectBytes: 1 << 10, MaxSessionBytes: 3 << 10}
	}))
	sid := e.newSession(map[string]any{"seed": 1})
	h := map[string]string{"X-TT-Session": sid, "Content-Type": "application/pdf", "X-Amz-Meta-Origin": "upload"}

	r := e.s3req("PUT", "/__s3/docs/a/one.pdf", "", []byte("%PDF-1.4 one"), h)
	if r.status != 200 || r.header.Get("ETag") != `"`+md5hex("%PDF-1.4 one")+`"` {
		t.Fatalf("put: %d %v %s", r.status, r.header, r.body)
	}
	// virtual-host style, same session
	r = e.s3req("GET", "/a/one.pdf", "docs.s3.mock.test", nil, h)
	if r.status != 200 || string(r.body) != "%PDF-1.4 one" || r.header.Get("Content-Type") != "application/pdf" || r.header.Get("X-Amz-Meta-Origin") != "upload" {
		t.Fatalf("get: %d %v %q", r.status, r.header, r.body)
	}
	// path style on the S3 host
	if r := e.s3req("HEAD", "/docs/a/one.pdf", "s3.mock.test:9000", nil, h); r.status != 200 || r.header.Get("Content-Length") != "12" || len(r.body) != 0 {
		t.Fatalf("head: %d %v", r.status, r.header)
	}
	if r := e.s3req("GET", "/__s3/docs/a/one.pdf", "", nil, map[string]string{"X-TT-Session": sid, "Range": "bytes=0-3"}); r.status != 206 || string(r.body) != "%PDF" {
		t.Fatalf("range: %d %q", r.status, r.body)
	}
	// other sessions do not see the object
	if r := e.s3req("GET", "/__s3/docs/a/one.pdf", "", nil, nil); r.status != 404 || !strings.Contains(string(r.body), "<Code>NoSuchKey</Code>") {
		t.Fatalf("default session: %d %s", r.status, r.body)
	}
	// only the configured buckets exist
	if r := e.s3req("PUT", "/__s3/other/x", "", []byte("x"), h); r.status != 404 || !strings.Contains(string(r.body), "NoSuchBucket") {
		t.Fatalf("unknown bucket: %d %s", r.status, r.body)
	}
	if r := e.s3req("PUT", "/__s3/other", "", nil, h); r.status != 403 {
		t.Fatalf("create bucket: %d %s", r.status, r.body)
	}
	// limits
	if r := e.s3req("PUT", "/__s3/docs/big", "", bytes.Repeat([]byte("x"), 2<<10), h); r.status != 400 || !strings.Contains(string(r.body), "EntityTooLarge") {
		t.Fatalf("object limit: %d %s", r.status, r.body)
	}
	for i := 0; i < 3; i++ {
		e.s3req("PUT", fmt.Sprintf("/__s3/docs/f%d", i), "", bytes.Repeat([]byte("y"), 1000), h)
	}
	if r := e.s3req("PUT", "/__s3/docs/f3", "", bytes.Repeat([]byte("y"), 1000), h); r.status != 403 || !strings.Contains(string(r.body), "QuotaExceeded") {
		t.Fatalf("session limit: %d %s", r.status, r.body)
	}
	// list v2 with delimiter and pagination
	r = e.s3req("GET", "/__s3/docs?list-type=2&delimiter=/&max-keys=2", "", nil, h)
	if r.status != 200 || !strings.Contains(string(r.body), "<CommonPrefixes><Prefix>a/</Prefix></CommonPrefixes>") ||
		!strings.Contains(string(r.body), "<IsTruncated>true</IsTruncated>") || !strings.Contains(string(r.body), "<NextContinuationToken>f0</NextContinuationToken>") {
		t.Fatalf("list: %s", r.body)
	}
	r = e.s3req("GET", "/__s3/docs?list-type=2&delimiter=/&continuation-token=f0", "", nil, h)
	if !strings.Contains(string(r.body), "<Key>f1</Key>") || strings.Contains(string(r.body), "<Key>f0</Key>") || !strings.Contains(string(r.body), "<KeyCount>2</KeyCount>") {
		t.Fatalf("list page 2: %s", r.body)
	}
	// delete
	if r := e.s3req("DELETE", "/__s3/docs/a/one.pdf", "", nil, h); r.status != 204 {
		t.Fatalf("delete: %d", r.status)
	}
	// the journal has the calls, not the bytes
	j := e.ctl("GET", "/sessions/"+sid+"/journal", nil)
	if !strings.Contains(string(j.body), `"service":"s3"`) || !strings.Contains(string(j.body), `"op":"PutObject"`) || strings.Contains(string(j.body), "%PDF-1.4 one") {
		t.Fatalf("journal: %.600s", j.body)
	}
	// reset forgets the objects
	e.ctl("POST", "/sessions/"+sid+"/reset", nil)
	if r := e.s3req("GET", "/__s3/docs/f0", "", nil, h); r.status != 404 {
		t.Fatalf("after reset: %d", r.status)
	}
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestS3ChunkedAndMultipart(t *testing.T) {
	e := newEnv(t, withConfig(func(c *Config) { c.S3 = &S3Config{Enabled: true} }))
	// streaming SigV4 (aws-chunked) as the SDKs send it over http
	chunked := "5;chunk-signature=aaaa\r\nhello\r\n6;chunk-signature=bbbb\r\n world\r\n0;chunk-signature=cccc\r\n\r\n"
	r := e.s3req("PUT", "/__s3/any-bucket/greeting.txt", "", []byte(chunked), map[string]string{
		"X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "Content-Encoding": "aws-chunked", "X-Amz-Decoded-Content-Length": "11"})
	if r.status != 200 {
		t.Fatalf("chunked put: %d %s", r.status, r.body)
	}
	if r := e.s3req("GET", "/__s3/any-bucket/greeting.txt", "", nil, nil); string(r.body) != "hello world" {
		t.Fatalf("chunked body: %q", r.body)
	}
	// unsigned trailer variant
	trailer := "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"
	if r := e.s3req("PUT", "/__s3/any-bucket/t", "", []byte(trailer), map[string]string{"X-Amz-Content-Sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER"}); r.status != 200 {
		t.Fatalf("trailer put: %d %s", r.status, r.body)
	}
	// multipart upload
	r = e.s3req("POST", "/__s3/any-bucket/big.bin?uploads", "", nil, map[string]string{"Content-Type": "application/zip"})
	id := between(string(r.body), "<UploadId>", "</UploadId>")
	if r.status != 200 || id == "" {
		t.Fatalf("create upload: %d %s", r.status, r.body)
	}
	p1 := e.s3req("PUT", "/__s3/any-bucket/big.bin?partNumber=1&uploadId="+id, "", []byte("part-one|"), nil)
	p2 := e.s3req("PUT", "/__s3/any-bucket/big.bin?partNumber=2&uploadId="+id, "", []byte("part-two"), nil)
	if p1.status != 200 || p2.status != 200 {
		t.Fatalf("parts: %d %d", p1.status, p2.status)
	}
	complete := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + p1.header.Get("ETag") + `</ETag></Part><Part><PartNumber>2</PartNumber><ETag>` + p2.header.Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	r = e.s3req("POST", "/__s3/any-bucket/big.bin?uploadId="+id, "", []byte(complete), nil)
	if r.status != 200 || !strings.Contains(string(r.body), "-2&#34;</ETag>") && !strings.Contains(string(r.body), `-2"</ETag>`) {
		t.Fatalf("complete: %d %s", r.status, r.body)
	}
	if r := e.s3req("GET", "/__s3/any-bucket/big.bin", "", nil, nil); string(r.body) != "part-one|part-two" || r.header.Get("Content-Type") != "application/zip" {
		t.Fatalf("assembled: %q %v", r.body, r.header)
	}
	// list buckets
	if r := e.s3req("GET", "/__s3/", "", nil, nil); !strings.Contains(string(r.body), "<Name>any-bucket</Name>") {
		t.Fatalf("buckets: %s", r.body)
	}
	// delete many
	del := `<Delete><Object><Key>t</Key></Object><Object><Key>greeting.txt</Key></Object></Delete>`
	if r := e.s3req("POST", "/__s3/any-bucket?delete", "", []byte(del), nil); r.status != 200 || strings.Count(string(r.body), "<Deleted>") != 2 {
		t.Fatalf("delete many: %d %s", r.status, r.body)
	}
	// S3 off: the prefix is an ordinary data-plane path
	e2 := newEnv(t)
	if r := e2.s3req("GET", "/__s3/any-bucket/x", "", nil, nil); r.header.Get("X-Amz-Request-Id") != "" {
		t.Fatal("S3 answered while off")
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	j := strings.Index(s, b)
	if j < 0 {
		return ""
	}
	return s[:j]
}
