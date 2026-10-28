package miner

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refused approval says why (lab: drafts of a team whose traffic left the
// mining window answered only "invalid rule change").
func TestBadEditSaysWhy(t *testing.T) {
	w := httptest.NewRecorder()
	(&Service{}).writeRepoError(w, fmt.Errorf("%w: effect assignment-created: unknown entity", ErrBadEdit))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid rule change: effect assignment-created: unknown entity") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	(&Service{}).writeRepoError(w, ErrBadEdit)
	if !strings.Contains(w.Body.String(), `"invalid rule change"`) {
		t.Fatalf("bare: %s", w.Body)
	}
}
