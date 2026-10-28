package ttsdk

import (
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// capBuf keeps the first limit bytes of a body and counts the rest
// (docs/spec/sanitizer.md sections 9.0 and 22.5: policy CaptureLimit). It never holds
// more than limit bytes.
type capBuf struct {
	limit int

	mu  sync.Mutex
	buf []byte
	n   int64 // bytes that went through
	eof bool
}

func (c *capBuf) add(p []byte) {
	if len(p) == 0 {
		return
	}
	c.mu.Lock()
	c.n += int64(len(p))
	if room := c.limit - len(c.buf); room > 0 {
		take := min(len(p), room)
		c.reserve(take)
		c.buf = append(c.buf, p[:take]...)
	}
	c.mu.Unlock()
}

func (c *capBuf) markEOF() {
	c.mu.Lock()
	c.eof = true
	c.mu.Unlock()
}

// reserve grows the buffer geometrically but never past limit.
func (c *capBuf) reserve(extra int) {
	need := len(c.buf) + extra
	if need <= cap(c.buf) {
		return
	}
	nc := min(max(2*cap(c.buf), need, 512), c.limit)
	nb := make([]byte, len(c.buf), nc)
	copy(nb, c.buf)
	c.buf = nb
}

// snapshot returns the kept prefix, the total length and whether the body
// was read to its end.
func (c *capBuf) snapshot() (b []byte, total int64, eof bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf, c.n, c.eof
}

// teeReader copies what the application reads from a body into a capBuf.
type teeReader struct {
	rc      io.ReadCloser
	cb      *capBuf
	spent   atomic.Int64 // nanoseconds spent copying
	onEOF   func()       // called once, when the body reaches its end
	onClose func()       // called once, when the body is closed
	eofOnce sync.Once
	clsOnce sync.Once
}

func (t *teeReader) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 || err != nil {
		t0 := time.Now()
		t.cb.add(p[:n])
		if err == io.EOF {
			t.cb.markEOF()
		}
		t.spent.Add(int64(time.Since(t0)))
		if err == io.EOF && t.onEOF != nil {
			t.eofOnce.Do(t.onEOF)
		}
	}
	return n, err
}

func (t *teeReader) Close() error {
	err := t.rc.Close()
	if t.onClose != nil {
		t.clsOnce.Do(t.onClose)
	}
	return err
}
