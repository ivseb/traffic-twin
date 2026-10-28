package mock

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A minimal S3-compatible API (docs/spec/mock.md 8): the applications that
// upload documents to an object store can run against the mock. Objects live
// in the session, in memory, within size limits; every call is journaled
// with service "s3". The signature (SigV4 header or presigned query) is
// accepted without any check: the mock does not authenticate, it is a test
// tool.

// S3Config configures the S3-compatible API (nil or Enabled false: off).
type S3Config struct {
	Enabled bool
	// Hosts are the endpoint host names (without port): a request to one of
	// them is path-style (/bucket/key), a request to <bucket>.<host> is
	// virtual-host style. The path prefix /__s3/ of the mock's own address
	// is always path-style.
	Hosts []string
	// Buckets are the bucket names that exist in every session; empty: any
	// valid name, created on first use.
	Buckets []string
	// MaxObjectBytes bounds one object (default 16 MiB); MaxSessionBytes
	// the objects of a session (default 256 MiB).
	MaxObjectBytes  int64
	MaxSessionBytes int64
}

const s3Prefix = "/__s3"

func (c *S3Config) applyDefaults() error {
	if c.MaxObjectBytes <= 0 {
		c.MaxObjectBytes = 16 << 20
	}
	if c.MaxSessionBytes <= 0 {
		c.MaxSessionBytes = 256 << 20
	}
	for i, h := range c.Hosts {
		c.Hosts[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if c.Hosts[i] == "" || strings.ContainsAny(c.Hosts[i], "/: ") {
			return fmt.Errorf("mock: s3 host %q is not a host name", h)
		}
	}
	for _, b := range c.Buckets {
		if !s3BucketRE.MatchString(b) {
			return fmt.Errorf("mock: s3 bucket %q is not a valid bucket name", b)
		}
	}
	return nil
}

var s3BucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ---- storage ----

type s3Object struct {
	data     []byte
	etag     string // quoted
	ctype    string
	meta     map[string]string // x-amz-meta-* (lower case)
	modified time.Time
}

type s3Bucket struct {
	created time.Time
	objects map[string]*s3Object
}

type s3Upload struct {
	bucket, key string
	ctype       string
	meta        map[string]string
	parts       map[int][]byte
}

type s3Store struct {
	buckets map[string]*s3Bucket
	uploads map[string]*s3Upload
	bytes   int64
}

func (s *session) s3store() *s3Store {
	if s.s3 == nil {
		s.s3 = &s3Store{buckets: map[string]*s3Bucket{}, uploads: map[string]*s3Upload{}}
		if c := s.m.cfg.S3; c != nil {
			for _, b := range c.Buckets {
				s.s3.buckets[b] = &s3Bucket{created: s.t0, objects: map[string]*s3Object{}}
			}
		}
	}
	return s.s3
}

// ---- routing ----

// s3Target tells whether a request is for the S3 API and splits it into
// bucket and key ("" when absent).
func (m *Mock) s3Target(r *http.Request) (bucket, key string, ok bool) {
	c := m.cfg.S3
	if c == nil || !c.Enabled {
		return "", "", false
	}
	path := r.URL.Path
	if path == s3Prefix || strings.HasPrefix(path, s3Prefix+"/") {
		b, k := splitBucketKey(strings.TrimPrefix(path, s3Prefix))
		return b, k, true
	}
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, h := range c.Hosts {
		if host == h {
			b, k := splitBucketKey(path)
			return b, k, true
		}
		if b, found := strings.CutSuffix(host, "."+h); found && s3BucketRE.MatchString(b) {
			return b, strings.TrimPrefix(path, "/"), true
		}
	}
	return "", "", false
}

func splitBucketKey(p string) (string, string) {
	p = strings.TrimPrefix(p, "/")
	b, k, _ := strings.Cut(p, "/")
	return b, k
}

// requestSession is the session of a data-plane request: X-TT-Session, else
// the caller's identity, else the default session. It writes the error and
// returns nil when there is none.
func (m *Mock) requestSession(w http.ResponseWriter, r *http.Request) *session {
	sid := r.Header.Get(hdrSession)
	if sid == "" {
		s, _, err := m.identitySession(r)
		if err != nil {
			writeError(w, http.StatusTooManyRequests, "too_many_sessions", "session limit reached; delete unused sessions")
			return nil
		}
		if s != nil {
			return s
		}
		sid = defaultSession
	}
	if !sessionIDRE.MatchString(sid) {
		writeError(w, http.StatusBadRequest, "bad_session_id", "X-TT-Session is malformed")
		return nil
	}
	s := m.lookup(sid)
	if s == nil {
		writeError(w, http.StatusNotFound, "session_not_found", "unknown session")
	}
	return s
}

// ---- answers ----

type s3Error struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
	RequestID  string   `xml:"RequestId"`
	status     int
}

func s3err(status int, code, msg string) *s3Error {
	return &s3Error{Code: code, Message: msg, status: status}
}

// s3Reply is the answer of one S3 call.
type s3Reply struct {
	status int
	header http.Header
	body   []byte
	op     string
	// desc replaces the body in the journal (object data is not journaled)
	desc string
}

func xmlBody(v any) []byte {
	b, _ := xml.Marshal(v)
	return append([]byte(xml.Header), b...)
}

func requestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strings.ToUpper(hex.EncodeToString(b[:]))
}

// serveS3 serves one S3 call in its session and journals it.
func (m *Mock) serveS3(w http.ResponseWriter, r *http.Request, bucket, key string) {
	sess := m.requestSession(w, r)
	if sess == nil {
		return
	}
	body, err := readS3Body(r, m.cfg.S3.MaxObjectBytes)
	var rep *s3Reply
	if err != nil {
		e := s3err(http.StatusBadRequest, "IncompleteBody", err.Error())
		if errors.Is(err, errS3TooLarge) {
			e = s3err(http.StatusBadRequest, "EntityTooLarge", "the object is larger than the limit of the mock")
		}
		rep = sess.s3Fail(e, bucket, key, "")
	} else {
		rep = sess.s3Handle(r, bucket, key, body)
	}
	rid := requestID()
	rep.header.Set("X-Amz-Request-Id", rid)
	rep.header.Set(hdrSession, sess.id)
	if rep.header.Get("Content-Type") == "" && len(rep.body) > 0 {
		rep.header.Set("Content-Type", "application/xml")
	}
	if r.Method != http.MethodHead || rep.header.Get("Content-Length") == "" {
		rep.header.Set("Content-Length", strconv.Itoa(len(rep.body)))
	}
	for k, v := range rep.header {
		w.Header()[k] = v
	}
	w.WriteHeader(rep.status)
	if r.Method != http.MethodHead && len(rep.body) > 0 {
		_, _ = w.Write(rep.body)
	}
}

func (s *session) s3Fail(e *s3Error, bucket, key, op string) *s3Reply {
	e.BucketName, e.Key, e.RequestID = bucket, key, requestID()
	return &s3Reply{status: e.status, header: http.Header{}, body: xmlBody(e), op: op}
}

var errS3TooLarge = errors.New("object too large")

// readS3Body reads the body, decoding the aws-chunked encoding of the SDKs
// (streaming SigV4, signed or unsigned, with trailers); signatures are not
// checked.
func readS3Body(r *http.Request, max int64) ([]byte, error) {
	limit := max + max/8 + 64<<10
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errS3TooLarge
	}
	sha := r.Header.Get("X-Amz-Content-Sha256")
	if strings.HasPrefix(sha, "STREAMING-") || strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") {
		dec, err := decodeAWSChunked(raw)
		if err != nil {
			return nil, err
		}
		if dl := r.Header.Get("X-Amz-Decoded-Content-Length"); dl != "" {
			if n, err := strconv.Atoi(dl); err != nil || n != len(dec) {
				return nil, errors.New("decoded length does not match x-amz-decoded-content-length")
			}
		}
		raw = dec
	}
	if int64(len(raw)) > max {
		return nil, errS3TooLarge
	}
	return raw, nil
}

func decodeAWSChunked(b []byte) ([]byte, error) {
	rd := bufio.NewReader(bytes.NewReader(b))
	var out bytes.Buffer
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil, errors.New("malformed aws-chunked body")
		}
		line = strings.TrimRight(line, "\r\n")
		sizeHex, _, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(strings.TrimSpace(sizeHex), 16, 64)
		if err != nil || n < 0 {
			return nil, errors.New("malformed aws-chunked size")
		}
		if n == 0 {
			// trailers (x-amz-checksum-*, x-amz-trailer-signature) until an
			// empty line or the end
			for {
				t, err := rd.ReadString('\n')
				if strings.TrimRight(t, "\r\n") == "" || err != nil {
					return out.Bytes(), nil
				}
			}
		}
		if _, err := io.CopyN(&out, rd, n); err != nil {
			return nil, errors.New("truncated aws-chunked body")
		}
		if crlf, err := rd.ReadString('\n'); err != nil || strings.TrimRight(crlf, "\r\n") != "" {
			return nil, errors.New("malformed aws-chunked chunk end")
		}
	}
}

// s3Handle dispatches one call (under the session lock) and journals it.
func (s *session) s3Handle(r *http.Request, bucket, key string, body []byte) *s3Reply {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUsed.Store(s.m.cfg.Wall().UnixNano())
	rep := s.s3Dispatch(r, bucket, key, body)
	svc := "s3"
	e := &journalEntry{At: fmtTime(s.now), Wall: wallNow(s.m), Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		Service: &svc, Op: strp(rep.op), Matched: rep.status < 400, Request: map[string]any{}}
	if h := recordedRequestHeaders(r.Header, s.m.identityHeader()); len(h) > 0 {
		e.Request["headers"] = h
	}
	if len(body) > 0 {
		e.Request["body"] = "object data, " + strconv.Itoa(len(body)) + " bytes"
	}
	st := rep.status
	e.Status = &st
	e.Response = map[string]any{"headers": recordedResponseHeaders(rep.header)}
	switch {
	case rep.desc != "":
		e.Response["body"] = rep.desc
	case len(rep.body) > 0:
		e.Response["body"] = journalBody(rep.body)
	}
	if rep.status >= 400 {
		e.Reason = "s3_error"
	}
	s.appendJournal(e)
	return rep
}

func (s *session) s3Dispatch(r *http.Request, bucket, key string, body []byte) *s3Reply {
	q := r.URL.Query()
	st := s.s3store()
	cfg := s.m.cfg.S3
	if bucket == "" {
		if r.Method != http.MethodGet {
			return s.s3Fail(s3err(http.StatusMethodNotAllowed, "MethodNotAllowed", "method not allowed"), "", "", "")
		}
		return s.s3ListBuckets()
	}
	if !s3BucketRE.MatchString(bucket) {
		return s.s3Fail(s3err(http.StatusBadRequest, "InvalidBucketName", "the bucket name is not valid"), bucket, "", "")
	}
	b := st.buckets[bucket]
	if key == "" {
		switch r.Method {
		case http.MethodPut:
			if b != nil {
				return &s3Reply{status: 200, header: http.Header{"Location": {"/" + bucket}}, op: "CreateBucket"}
			}
			if len(cfg.Buckets) > 0 {
				return s.s3Fail(s3err(http.StatusForbidden, "AccessDenied", "the mock serves only its configured buckets"), bucket, "", "CreateBucket")
			}
			st.buckets[bucket] = &s3Bucket{created: s.now, objects: map[string]*s3Object{}}
			return &s3Reply{status: 200, header: http.Header{"Location": {"/" + bucket}}, op: "CreateBucket"}
		}
	}
	if b == nil {
		if len(cfg.Buckets) == 0 && (r.Method == http.MethodPut || (r.Method == http.MethodPost && q.Has("uploads"))) {
			// without a configured list a bucket exists on first write
			b = &s3Bucket{created: s.now, objects: map[string]*s3Object{}}
			st.buckets[bucket] = b
		} else {
			return s.s3Fail(s3err(http.StatusNotFound, "NoSuchBucket", "the bucket does not exist"), bucket, key, "")
		}
	}
	if key == "" {
		switch r.Method {
		case http.MethodHead:
			return &s3Reply{status: 200, header: http.Header{}, op: "HeadBucket"}
		case http.MethodDelete:
			if len(b.objects) > 0 {
				return s.s3Fail(s3err(http.StatusConflict, "BucketNotEmpty", "the bucket is not empty"), bucket, "", "DeleteBucket")
			}
			delete(st.buckets, bucket)
			return &s3Reply{status: 204, header: http.Header{}, op: "DeleteBucket"}
		case http.MethodGet:
			if q.Has("location") {
				return &s3Reply{status: 200, header: http.Header{}, op: "GetBucketLocation",
					body: []byte(xml.Header + `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)}
			}
			return s.s3List(bucket, b, q)
		case http.MethodPost:
			if q.Has("delete") {
				return s.s3DeleteMany(bucket, b, body)
			}
		}
		return s.s3Fail(s3err(http.StatusNotImplemented, "NotImplemented", "this bucket operation is not served by the mock"), bucket, "", "")
	}
	if len(key) > 1024 {
		return s.s3Fail(s3err(http.StatusBadRequest, "KeyTooLongError", "the key is too long"), bucket, "", "")
	}
	switch r.Method {
	case http.MethodPut:
		if q.Has("uploadId") {
			return s.s3UploadPart(bucket, key, q, body)
		}
		if src := r.Header.Get("X-Amz-Copy-Source"); src != "" {
			return s.s3Copy(bucket, key, src)
		}
		return s.s3Put(bucket, b, key, r, body)
	case http.MethodGet, http.MethodHead:
		if q.Has("uploadId") {
			return s.s3ListParts(bucket, key, q)
		}
		return s.s3Get(bucket, b, key, r)
	case http.MethodDelete:
		if q.Has("uploadId") {
			if u := st.uploads[q.Get("uploadId")]; u == nil || u.bucket != bucket || u.key != key {
				return s.s3Fail(s3err(http.StatusNotFound, "NoSuchUpload", "the upload does not exist"), bucket, key, "AbortMultipartUpload")
			}
			delete(st.uploads, q.Get("uploadId"))
			return &s3Reply{status: 204, header: http.Header{}, op: "AbortMultipartUpload"}
		}
		if o := b.objects[key]; o != nil {
			st.bytes -= int64(len(o.data))
			delete(b.objects, key)
		}
		return &s3Reply{status: 204, header: http.Header{}, op: "DeleteObject"}
	case http.MethodPost:
		if q.Has("uploads") {
			return s.s3CreateUpload(bucket, key, r)
		}
		if q.Has("uploadId") {
			return s.s3Complete(bucket, b, key, q, body)
		}
	}
	return s.s3Fail(s3err(http.StatusNotImplemented, "NotImplemented", "this object operation is not served by the mock"), bucket, key, "")
}

func etagOf(data []byte) string {
	h := md5.Sum(data)
	return `"` + hex.EncodeToString(h[:]) + `"`
}

func metaOf(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			out[lk] = v[0]
		}
	}
	return out
}

// store puts an object, within the size limit of the session.
func (s *session) s3Store(bucket string, b *s3Bucket, key string, o *s3Object, op string) *s3Reply {
	st := s.s3store()
	old := int64(0)
	if prev := b.objects[key]; prev != nil {
		old = int64(len(prev.data))
	}
	if st.bytes-old+int64(len(o.data)) > s.m.cfg.S3.MaxSessionBytes {
		return s.s3Fail(s3err(http.StatusForbidden, "QuotaExceeded", "the objects of this session exceed the limit of the mock"), bucket, key, op)
	}
	st.bytes += int64(len(o.data)) - old
	b.objects[key] = o
	return &s3Reply{status: 200, header: http.Header{"Etag": {o.etag}}, op: op}
}

func (s *session) s3Put(bucket string, b *s3Bucket, key string, r *http.Request, body []byte) *s3Reply {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "binary/octet-stream"
	}
	return s.s3Store(bucket, b, key, &s3Object{data: body, etag: etagOf(body), ctype: ct, meta: metaOf(r.Header), modified: s.now}, "PutObject")
}

func (s *session) s3Copy(bucket, key, src string) *s3Reply {
	st := s.s3store()
	if u, err := url.PathUnescape(src); err == nil {
		src = u
	}
	src, _, _ = strings.Cut(src, "?")
	sb, sk := splitBucketKey(src)
	b := st.buckets[sb]
	if b == nil || b.objects[sk] == nil {
		return s.s3Fail(s3err(http.StatusNotFound, "NoSuchKey", "the copy source does not exist"), bucket, key, "CopyObject")
	}
	o := *b.objects[sk]
	o.data = append([]byte(nil), o.data...)
	o.modified = s.now
	rep := s.s3Store(bucket, st.buckets[bucket], key, &o, "CopyObject")
	if rep.status == 200 {
		rep.body = xmlBody(struct {
			XMLName      xml.Name `xml:"CopyObjectResult"`
			ETag         string   `xml:"ETag"`
			LastModified string   `xml:"LastModified"`
		}{ETag: o.etag, LastModified: o.modified.UTC().Format("2006-01-02T15:04:05.000Z")})
	}
	return rep
}

func (s *session) s3Get(bucket string, b *s3Bucket, key string, r *http.Request) *s3Reply {
	op := "GetObject"
	if r.Method == http.MethodHead {
		op = "HeadObject"
	}
	o := b.objects[key]
	if o == nil {
		rep := s.s3Fail(s3err(http.StatusNotFound, "NoSuchKey", "the key does not exist"), bucket, key, op)
		if r.Method == http.MethodHead {
			rep.body = nil
		}
		return rep
	}
	h := http.Header{"Etag": {o.etag}, "Content-Type": {o.ctype}, "Last-Modified": {o.modified.UTC().Format(http.TimeFormat)}, "Accept-Ranges": {"bytes"}}
	for k, v := range o.meta {
		h.Set(k, v)
	}
	data, status := o.data, 200
	if rg := r.Header.Get("Range"); rg != "" {
		lo, hi, ok := parseRange(rg, len(o.data))
		if !ok {
			return s.s3Fail(s3err(http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "the range is not satisfiable"), bucket, key, op)
		}
		data, status = o.data[lo:hi+1], http.StatusPartialContent
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", lo, hi, len(o.data)))
	}
	h.Set("Content-Length", strconv.Itoa(len(data)))
	rep := &s3Reply{status: status, header: h, op: op, desc: "object data, " + strconv.Itoa(len(data)) + " bytes"}
	if r.Method != http.MethodHead {
		rep.body = data
	}
	return rep
}

// parseRange parses a single "bytes=a-b", "bytes=a-" or "bytes=-n" range.
func parseRange(h string, size int) (int, int, bool) {
	spec, ok := strings.CutPrefix(h, "bytes=")
	if !ok || strings.Contains(spec, ",") || size == 0 {
		return 0, 0, false
	}
	a, b, _ := strings.Cut(spec, "-")
	switch {
	case a == "":
		n, err := strconv.Atoi(b)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		return max(0, size-n), size - 1, true
	default:
		lo, err := strconv.Atoi(a)
		if err != nil || lo >= size {
			return 0, 0, false
		}
		hi := size - 1
		if b != "" {
			if hi, err = strconv.Atoi(b); err != nil || hi < lo {
				return 0, 0, false
			}
			hi = min(hi, size-1)
		}
		return lo, hi, true
	}
}

func (s *session) s3ListBuckets() *s3Reply {
	type bkt struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	out := struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Xmlns   string   `xml:"xmlns,attr"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets []bkt `xml:"Buckets>Bucket"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/"}
	out.Owner.ID, out.Owner.DisplayName = "tt-mock", "tt-mock"
	st := s.s3store()
	names := make([]string, 0, len(st.buckets))
	for n := range st.buckets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out.Buckets = append(out.Buckets, bkt{Name: n, CreationDate: st.buckets[n].created.UTC().Format("2006-01-02T15:04:05.000Z")})
	}
	return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "ListBuckets"}
}

// s3List serves ListObjectsV2 (list-type=2) and ListObjects (v1).
func (s *session) s3List(bucket string, b *s3Bucket, q url.Values) *s3Reply {
	v2 := q.Get("list-type") == "2"
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	maxKeys := 1000
	if mk := q.Get("max-keys"); mk != "" {
		n, err := strconv.Atoi(mk)
		if err != nil || n < 0 {
			return s.s3Fail(s3err(http.StatusBadRequest, "InvalidArgument", "max-keys is not a number"), bucket, "", "ListObjects")
		}
		maxKeys = min(n, 1000)
	}
	after := q.Get("start-after")
	if v2 && q.Get("continuation-token") != "" {
		after = q.Get("continuation-token")
	}
	if !v2 {
		after = q.Get("marker")
	}
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	type content struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int    `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	type cp struct {
		Prefix string `xml:"Prefix"`
	}
	var contents []content
	var prefixes []cp
	seenP := map[string]bool{}
	truncated, next := false, ""
	n := 0
	for _, k := range keys {
		if delim != "" {
			if i := strings.Index(k[len(prefix):], delim); i >= 0 {
				p := k[:len(prefix)+i+len(delim)]
				if seenP[p] {
					continue
				}
				if n >= maxKeys {
					truncated = true
					break
				}
				seenP[p] = true
				prefixes = append(prefixes, cp{p})
				n++
				next = k
				continue
			}
		}
		if n >= maxKeys {
			truncated = true
			break
		}
		o := b.objects[k]
		contents = append(contents, content{Key: k, LastModified: o.modified.UTC().Format("2006-01-02T15:04:05.000Z"), ETag: o.etag, Size: len(o.data), StorageClass: "STANDARD"})
		n++
		next = k
	}
	if v2 {
		out := struct {
			XMLName               xml.Name  `xml:"ListBucketResult"`
			Xmlns                 string    `xml:"xmlns,attr"`
			Name                  string    `xml:"Name"`
			Prefix                string    `xml:"Prefix"`
			Delimiter             string    `xml:"Delimiter,omitempty"`
			MaxKeys               int       `xml:"MaxKeys"`
			KeyCount              int       `xml:"KeyCount"`
			IsTruncated           bool      `xml:"IsTruncated"`
			ContinuationToken     string    `xml:"ContinuationToken,omitempty"`
			NextContinuationToken string    `xml:"NextContinuationToken,omitempty"`
			StartAfter            string    `xml:"StartAfter,omitempty"`
			Contents              []content `xml:"Contents"`
			CommonPrefixes        []cp      `xml:"CommonPrefixes"`
		}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: bucket, Prefix: prefix, Delimiter: delim, MaxKeys: maxKeys, KeyCount: n,
			IsTruncated: truncated, ContinuationToken: q.Get("continuation-token"), StartAfter: q.Get("start-after"), Contents: contents, CommonPrefixes: prefixes}
		if truncated {
			out.NextContinuationToken = next
		}
		return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "ListObjectsV2"}
	}
	out := struct {
		XMLName        xml.Name  `xml:"ListBucketResult"`
		Xmlns          string    `xml:"xmlns,attr"`
		Name           string    `xml:"Name"`
		Prefix         string    `xml:"Prefix"`
		Marker         string    `xml:"Marker"`
		NextMarker     string    `xml:"NextMarker,omitempty"`
		Delimiter      string    `xml:"Delimiter,omitempty"`
		MaxKeys        int       `xml:"MaxKeys"`
		IsTruncated    bool      `xml:"IsTruncated"`
		Contents       []content `xml:"Contents"`
		CommonPrefixes []cp      `xml:"CommonPrefixes"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: bucket, Prefix: prefix, Marker: q.Get("marker"), Delimiter: delim, MaxKeys: maxKeys,
		IsTruncated: truncated, Contents: contents, CommonPrefixes: prefixes}
	if truncated {
		out.NextMarker = next
	}
	return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "ListObjects"}
}

func (s *session) s3DeleteMany(bucket string, b *s3Bucket, body []byte) *s3Reply {
	var req struct {
		Quiet   bool `xml:"Quiet"`
		Objects []struct {
			Key string `xml:"Key"`
		} `xml:"Object"`
	}
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Objects) > 1000 {
		return s.s3Fail(s3err(http.StatusBadRequest, "MalformedXML", "the delete request is not valid"), bucket, "", "DeleteObjects")
	}
	type deleted struct {
		Key string `xml:"Key"`
	}
	out := struct {
		XMLName xml.Name  `xml:"DeleteResult"`
		Xmlns   string    `xml:"xmlns,attr"`
		Deleted []deleted `xml:"Deleted"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/"}
	st := s.s3store()
	for _, o := range req.Objects {
		if obj := b.objects[o.Key]; obj != nil {
			st.bytes -= int64(len(obj.data))
			delete(b.objects, o.Key)
		}
		if !req.Quiet {
			out.Deleted = append(out.Deleted, deleted{o.Key})
		}
	}
	return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "DeleteObjects"}
}

func (s *session) s3CreateUpload(bucket, key string, r *http.Request) *s3Reply {
	st := s.s3store()
	if len(st.uploads) >= 1000 {
		return s.s3Fail(s3err(http.StatusForbidden, "QuotaExceeded", "too many open uploads in this session"), bucket, key, "CreateMultipartUpload")
	}
	id := "tt-" + strings.ToLower(requestID())
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "binary/octet-stream"
	}
	st.uploads[id] = &s3Upload{bucket: bucket, key: key, ctype: ct, meta: metaOf(r.Header), parts: map[int][]byte{}}
	out := struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Xmlns    string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: bucket, Key: key, UploadID: id}
	return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "CreateMultipartUpload"}
}

func (s *session) s3UploadPart(bucket, key string, q url.Values, body []byte) *s3Reply {
	st := s.s3store()
	u := st.uploads[q.Get("uploadId")]
	if u == nil || u.bucket != bucket || u.key != key {
		return s.s3Fail(s3err(http.StatusNotFound, "NoSuchUpload", "the upload does not exist"), bucket, key, "UploadPart")
	}
	n, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || n < 1 || n > 10000 {
		return s.s3Fail(s3err(http.StatusBadRequest, "InvalidArgument", "partNumber must be 1 to 10000"), bucket, key, "UploadPart")
	}
	total := int64(len(body))
	for i, p := range u.parts {
		if i != n {
			total += int64(len(p))
		}
	}
	if total > s.m.cfg.S3.MaxObjectBytes {
		return s.s3Fail(s3err(http.StatusBadRequest, "EntityTooLarge", "the object is larger than the limit of the mock"), bucket, key, "UploadPart")
	}
	u.parts[n] = append([]byte(nil), body...)
	return &s3Reply{status: 200, header: http.Header{"Etag": {etagOf(body)}}, op: "UploadPart"}
}

func (s *session) s3ListParts(bucket, key string, q url.Values) *s3Reply {
	u := s.s3store().uploads[q.Get("uploadId")]
	if u == nil || u.bucket != bucket || u.key != key {
		return s.s3Fail(s3err(http.StatusNotFound, "NoSuchUpload", "the upload does not exist"), bucket, key, "ListParts")
	}
	type part struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
		Size       int    `xml:"Size"`
	}
	out := struct {
		XMLName  xml.Name `xml:"ListPartsResult"`
		Xmlns    string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
		Parts    []part   `xml:"Part"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: bucket, Key: key, UploadID: q.Get("uploadId")}
	nums := make([]int, 0, len(u.parts))
	for n := range u.parts {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		out.Parts = append(out.Parts, part{n, etagOf(u.parts[n]), len(u.parts[n])})
	}
	return &s3Reply{status: 200, header: http.Header{}, body: xmlBody(out), op: "ListParts"}
}

func (s *session) s3Complete(bucket string, b *s3Bucket, key string, q url.Values, body []byte) *s3Reply {
	st := s.s3store()
	id := q.Get("uploadId")
	u := st.uploads[id]
	if u == nil || u.bucket != bucket || u.key != key {
		return s.s3Fail(s3err(http.StatusNotFound, "NoSuchUpload", "the upload does not exist"), bucket, key, "CompleteMultipartUpload")
	}
	var req struct {
		Parts []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Parts) == 0 {
		return s.s3Fail(s3err(http.StatusBadRequest, "MalformedXML", "the part list is not valid"), bucket, key, "CompleteMultipartUpload")
	}
	var data []byte
	var sums []byte
	last := 0
	for _, p := range req.Parts {
		part, ok := u.parts[p.PartNumber]
		if !ok || p.PartNumber <= last || (p.ETag != "" && strings.Trim(p.ETag, `"`) != strings.Trim(etagOf(part), `"`)) {
			return s.s3Fail(s3err(http.StatusBadRequest, "InvalidPart", "a listed part was not uploaded, is out of order or has another ETag"), bucket, key, "CompleteMultipartUpload")
		}
		last = p.PartNumber
		data = append(data, part...)
		h := md5.Sum(part)
		sums = append(sums, h[:]...)
	}
	h := md5.Sum(sums)
	etag := `"` + hex.EncodeToString(h[:]) + "-" + strconv.Itoa(len(req.Parts)) + `"`
	rep := s.s3Store(bucket, b, key, &s3Object{data: data, etag: etag, ctype: u.ctype, meta: u.meta, modified: s.now}, "CompleteMultipartUpload")
	if rep.status != 200 {
		return rep
	}
	delete(st.uploads, id)
	rep.body = xmlBody(struct {
		XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
		Xmlns   string   `xml:"xmlns,attr"`
		Bucket  string   `xml:"Bucket"`
		Key     string   `xml:"Key"`
		ETag    string   `xml:"ETag"`
	}{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Bucket: bucket, Key: key, ETag: etag})
	return rep
}
