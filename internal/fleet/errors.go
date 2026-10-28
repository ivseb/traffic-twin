package fleet

import (
	"context"
	"errors"
	"net/http"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

// APIError is an error with an HTTP status and a stable code. Messages are
// fixed strings chosen by tt-core: they never echo request values.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

func apiErr(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Message: msg}
}

var (
	errNotFound = apiErr(http.StatusNotFound, "not_found", "not found")
	errInternal = apiErr(http.StatusInternalServerError, "internal", "internal error")
)

func invalid(code, msg string) *APIError { return apiErr(http.StatusUnprocessableEntity, code, msg) }

func conflict(code, msg string) *APIError { return apiErr(http.StatusConflict, code, msg) }

// writeErr maps err to a JSON error response; unexpected errors are logged
// and returned as 500 without details.
func (f *Fleet) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *APIError
	if errors.As(err, &ae) {
		httpx.WriteError(w, ae.Status, ae.Code, ae.Message)
		return
	}
	f.log.ErrorContext(r.Context(), "fleet: request failed", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal", "internal error")
}

// record writes an audit entry; failures are logged (the action already
// happened). Callers that must fail closed use recordStrict.
func (f *Fleet) record(ctx context.Context, e audit.Event) {
	if e.RequestID == "" {
		e.RequestID = httpx.RequestID(ctx)
	}
	if _, err := f.audit.Record(ctx, e); err != nil {
		f.log.ErrorContext(ctx, "fleet: audit write failed", "action", e.Action, "err", err)
	}
}
