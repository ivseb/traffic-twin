package core

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/export"
	"github.com/ivseb/traffic-twin/internal/gate"
	"github.com/ivseb/traffic-twin/internal/intake"
	"github.com/ivseb/traffic-twin/internal/miner"
	"github.com/ivseb/traffic-twin/internal/pack"
	"github.com/ivseb/traffic-twin/internal/server/httpx"
)

func mapGateErr(err error) error {
	var ge *gate.APIError
	if errors.As(err, &ge) {
		return apiErr(ge.Status, ge.Code, ge.Message)
	}
	return err
}

// gateKeys returns keyguard's pack signing public keys as a pack.KeySet.
func (c *Core) gateKeys(ctx context.Context) (pack.KeySet, error) {
	pk, err := c.kg.PublicKeys(ctx)
	if err != nil {
		return nil, apiErr(http.StatusBadGateway, "keyguard_unreachable", "keyguard did not answer")
	}
	return pack.ParseKeySet(pk.GatePubKeys())
}

// apiRunExport converts a published pack with internal/export (the same
// code as `tt export`), after verifying it with internal/pack and
// keyguard's keys, and keeps a zip of the target directory for download.
func (c *Core) apiRunExport(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		PackID string `json:"pack_id"`
		Target string `json:"target"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if !slices.Contains(export.AllTargets, req.Target) {
		return apiErr(http.StatusBadRequest, "invalid_target", "target must be wiremock, microcks or prism")
	}
	ctx := r.Context()
	archive, err := c.packs.PackArchive(ctx, p, req.PackID)
	if err != nil {
		return mapGateErr(err)
	}
	j := c.startJob(r.Context(), "pack.export", p.UserID)
	exportID := "ex_" + j.ID[len("job_"):]
	c.jobs.setMeta(j, "export_id", exportID)
	ev := audit.Event{Actor: p.AuditActor(), Action: "pack.export", Target: audit.Target{Type: "pack", ID: req.PackID}, Outcome: audit.Success,
		Details: overrideDetail(p, map[string]string{"target": req.Target, "export_id": exportID}, auth.RolePublisher)}
	rep, err := c.exportPack(ctx, j, archive, req.Target)
	if err != nil {
		c.jobs.fail(j, "export_failed")
		ev.Outcome, ev.Reason = audit.Failure, "export_failed"
		c.record(ctx, ev)
		var ae *apiError
		if errors.As(err, &ae) {
			return err
		}
		c.log.Warn("pack export failed", "pack", req.PackID, "target", req.Target, "err", err)
		return apiErr(http.StatusUnprocessableEntity, "export_failed", "the pack could not be exported")
	}
	c.record(ctx, ev)
	c.jobs.done(j, map[string]any{"export_id": exportID, "pack_id": req.PackID, "target": req.Target, "status": "done", "report": rep,
		"download": "/api/v1/exports/" + exportID + "/download"})
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

func (c *Core) exportPack(ctx context.Context, j *Job, archive []byte, target string) (*export.Report, error) {
	keys, err := c.gateKeys(ctx)
	if err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(filepath.Join(c.dataDir, "tmp"), "export-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	src := filepath.Join(work, "pack.ttpack")
	if err := os.WriteFile(src, archive, 0o600); err != nil {
		return nil, err
	}
	pk, err := pack.Load(src, pack.Options{Keys: keys, Now: c.now})
	if err != nil {
		return nil, fmt.Errorf("verify pack: %w", err)
	}
	out := filepath.Join(work, "out")
	res, err := export.Run(ctx, export.Config{Source: export.PackSource{Pack: pk}, OutDir: out, Targets: []string{target}, Now: c.now})
	if err != nil {
		return nil, err
	}
	dst, err := c.jobs.artifactPath(j, ".zip")
	if err != nil {
		return nil, err
	}
	if err := zipDir(filepath.Join(out, target), target, dst); err != nil {
		return nil, err
	}
	return res.Reports[target], nil
}

// zipDir writes the files under dir into a new zip at dst, under prefix/.
func zipDir(dir, prefix, dst string) (err error) {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	zw := zip.NewWriter(f)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return errors.New("export: unexpected non-regular file")
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hw, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(filepath.Join(prefix, rel)), Method: zip.Deflate,
			Modified: time.Unix(0, 0).UTC()})
		if err != nil {
			return err
		}
		rf, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(hw, rf)
		rf.Close()
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

func (c *Core) exportJob(id string) *Job {
	return c.jobs.find("pack.export", "export_id", id)
}

func (c *Core) apiGetExport(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	j := c.exportJob(r.PathValue("export_id"))
	if j == nil {
		return apiErr(http.StatusNotFound, "not_found", "export not found")
	}
	out := map[string]any{"export_id": r.PathValue("export_id"), "status": j.Status}
	if m, ok := j.Result.(map[string]any); ok {
		for _, k := range []string{"pack_id", "target", "report"} {
			out[k] = m[k]
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (c *Core) apiDownloadExport(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("export_id")
	j := c.exportJob(id)
	if j == nil || j.Status != "done" || j.file == "" {
		return apiErr(http.StatusNotFound, "not_found", "export not found")
	}
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "export.download", Target: audit.Target{Type: "export", ID: id}, Outcome: audit.Success,
		Details: overrideDetail(p, nil, auth.RolePublisher)})
	return serveFile(w, j.file, "application/zip", id+".zip")
}

func serveFile(w http.ResponseWriter, path, ctype, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return apiErr(http.StatusNotFound, "not_found", "the file has expired")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
	return nil
}

// ---------------------------------------------------------------------------
// Event export (zone B only, pseudonymous personal data)

func (c *Core) apiExportEvents(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		From    time.Time `json:"from"`
		To      time.Time `json:"to"`
		Service string    `json:"service"`
		Format  string    `json:"format"`
	}
	if err := decode(w, r, &req); err != nil {
		return err
	}
	if req.From.IsZero() || req.To.IsZero() || !req.From.Before(req.To) {
		return apiErr(http.StatusBadRequest, "invalid_input", "from and to are required and from must be before to")
	}
	if req.Format != "ocel2-json" && req.Format != "jsonl" {
		return apiErr(http.StatusBadRequest, "invalid_input", "format must be ocel2-json or jsonl")
	}
	ctx := r.Context()
	c.policies.Refresh()
	j := c.startJob(r.Context(), "events.export", p.UserID)
	ext := map[string]string{"ocel2-json": ".json", "jsonl": ".jsonl"}[req.Format]
	ev := audit.Event{Actor: p.AuditActor(), Action: "events.export", Target: audit.Target{Type: "events", ID: j.ID}, Outcome: audit.Success,
		Details: overrideDetail(p, map[string]string{"format": req.Format, "from": req.From.UTC().Format(time.RFC3339), "to": req.To.UTC().Format(time.RFC3339)},
			auth.RoleEventExporter)}
	if req.Service != "" {
		ev.Details["service"] = audit.SafeValue(req.Service)
	}
	n, size, err := c.writeEvents(ctx, j, ext, req.Format, req.From, req.To, req.Service)
	if err != nil {
		c.jobs.fail(j, "export_failed")
		ev.Outcome, ev.Reason = audit.Failure, "export_failed"
		c.record(ctx, ev)
		c.log.Warn("event export failed", "err", err)
		return apiErr(http.StatusInternalServerError, "export_failed", "the event export failed")
	}
	ev.Details["bytes"] = strconv.FormatInt(size, 10)
	if n >= 0 {
		ev.Details["events"] = strconv.Itoa(n)
	}
	// Every export is audited and announced to the admins' webhooks
	// (identifiers and counts only); an export by an admin without
	// event-exporter is marked admin_override in both.
	c.record(ctx, ev)
	alert := map[string]any{"alert": "events.export", "by": p.UserID, "format": req.Format, "bytes": size}
	if ev.Details["admin_override"] == "true" {
		alert["admin_override"] = true
	}
	c.alerts.emit(ctx, "keyguard.alert", alert)
	res := map[string]any{"format": req.Format, "bytes": size, "download": "/api/v1/events/export/" + j.ID + "/download",
		"notice": "pseudonymous personal data: it must not leave zone B"}
	if n >= 0 {
		res["events"] = n
	}
	c.jobs.done(j, res)
	httpx.WriteJSON(w, http.StatusAccepted, c.jobs.get(j.ID))
	return nil
}

func (c *Core) writeEvents(ctx context.Context, j *Job, ext, format string, from, to time.Time, service string) (n int, size int64, err error) {
	path, err := c.jobs.artifactPath(j, ext)
	if err != nil {
		return 0, 0, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			if st, serr := os.Stat(path); serr == nil {
				size = st.Size()
			}
		}
	}()
	bw := bufio.NewWriterSize(f, 256<<10)
	switch format {
	case "ocel2-json":
		mcfg := miner.DefaultConfig()
		mcfg.KMin, mcfg.MaxEvents = c.cfg.Miner.KMin, c.minerMaxEvents()
		n = -1
		err = miner.ExportOCEL(ctx, c.intake.Store(), miner.ExportQuery{From: from, To: to, Service: service}, c.policies.Domains(), mcfg, bw)
	default:
		err = c.intake.Store().Scan(ctx, intake.Query{From: from, To: to, Service: service}, func(e *intake.StoredEvent) error {
			n++
			b := e.Event.Canonical()
			if _, err := bw.Write(b); err != nil {
				return err
			}
			return bw.WriteByte('\n')
		})
	}
	if err != nil {
		return 0, 0, err
	}
	return n, 0, bw.Flush()
}

func (c *Core) apiDownloadEvents(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	j := c.jobs.get(r.PathValue("job_id"))
	// Only the person who ran the export downloads it, or an admin (admin
	// override: audited, and alerted when the export is someone else's).
	if j == nil || j.Kind != "events.export" || (j.owner != p.UserID && !p.IsAdmin()) || j.Status != "done" || j.file == "" {
		return apiErr(http.StatusNotFound, "not_found", "export not found")
	}
	det := overrideDetail(p, nil, auth.RoleEventExporter)
	if j.owner != p.UserID {
		if det == nil {
			det = map[string]string{}
		}
		det["admin_override"], det["owner"] = "true", audit.SafeValue(j.owner)
	}
	c.record(r.Context(), audit.Event{Actor: p.AuditActor(), Action: "events.download", Target: audit.Target{Type: "events", ID: j.ID}, Outcome: audit.Success, Details: det})
	if j.owner != p.UserID {
		c.alerts.emit(r.Context(), "keyguard.alert", map[string]any{"alert": "events.admin_download", "job": j.ID, "owner": j.owner, "by": p.UserID})
	}
	ctype := "application/json"
	if filepath.Ext(j.file) == ".jsonl" {
		ctype = "application/x-ndjson"
	}
	return serveFile(w, j.file, ctype, j.ID+filepath.Ext(j.file))
}

// overrideDetail adds admin_override=true to det (allocating it if needed)
// when p acts as one of roles only because it is admin.
func overrideDetail(p *auth.Principal, det map[string]string, roles ...auth.Role) map[string]string {
	if !p.AdminOverride(roles...) {
		return det
	}
	if det == nil {
		det = map[string]string{}
	}
	det["admin_override"] = "true"
	return det
}
