package sanitizer

import "testing"

func TestConcurrentUse(t *testing.T) {
	e := engine(t, benchAuthor)
	ex := benchExchange(orderJSON(8))
	want := canon(t, e, ex, t0)
	done := make(chan string, 8)
	for g := 0; g < 8; g++ {
		go func() {
			out, err := e.Sanitize(ex, t0, ByRandom)
			if err != nil {
				done <- err.Error()
				return
			}
			b, _ := out.Canonical()
			done <- string(b)
		}()
	}
	for g := 0; g < 8; g++ {
		if got := <-done; got != want {
			t.Fatalf("concurrent result differs: %s", got)
		}
	}
}
