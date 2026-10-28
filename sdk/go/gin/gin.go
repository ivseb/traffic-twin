// Package ttgin is the Gin adapter of the traffic-twin Go SDK. It lives in
// its own module so that applications that do not use Gin never depend on it.
//
//	r := gin.New()
//	r.Use(ttgin.Middleware())
//
// The route template (framework_route) is c.FullPath(), which Gin builds
// with the prefixes of the route groups ("/api/orders/:id"); a catch-all
// ("/files/*path") can not be turned into a template and the sanitizer uses
// the templates of the policy instead (docs/spec/sanitizer.md section 3.4).
//
// Put the middleware after gin.Recovery(): a request that panics is
// abandoned (no event).
package ttgin

import (
	"bufio"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	ttsdk "github.com/ivseb/traffic-twin/sdk/go"
)

// Middleware captures the requests of the router with the default agent
// (configured by the TT_* environment variables). With the SDK inert it is a
// no-op.
func Middleware() gin.HandlerFunc { return MiddlewareFor(nil) }

// MiddlewareFor is Middleware with an explicit agent (nil: the default one).
func MiddlewareFor(a *ttsdk.Agent) gin.HandlerFunc {
	if a == nil {
		a = ttsdk.Default()
	}
	if !a.Enabled() {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		in, r := a.Begin(c.Request)
		c.Request = r // carries the sampling decision for the outbound calls
		if in == nil {
			c.Next()
			return
		}
		w := &writer{ResponseWriter: c.Writer, in: in}
		c.Writer = w
		completed := false
		defer func() {
			if !completed { // panic in a handler
				in.Abandon()
			}
		}()
		c.Next()
		completed = true
		w.start()
		in.SetRoute("gin", c.FullPath())
		in.End()
	}
}

// writer observes what Gin sends without changing it. Gin commits the
// status late (WriteHeaderNow), so the status is read from the Gin writer
// when the first byte is written, or at the end.
type writer struct {
	gin.ResponseWriter
	in *ttsdk.Inbound
}

func (w *writer) start() { w.in.ResponseStarted(w.ResponseWriter.Status(), w.ResponseWriter.Header()) }

func (w *writer) WriteHeaderNow() {
	w.start()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *writer) Write(p []byte) (int, error) {
	w.start()
	n, err := w.ResponseWriter.Write(p)
	w.in.ResponseBytes(p[:n])
	return n, err
}

func (w *writer) WriteString(s string) (int, error) {
	w.start()
	n, err := w.ResponseWriter.WriteString(s)
	w.in.ResponseBytes([]byte(s[:n]))
	return n, err
}

func (w *writer) Flush() {
	w.start()
	w.ResponseWriter.Flush()
}

func (w *writer) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.in.Abandon()
	return w.ResponseWriter.Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }
