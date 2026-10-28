package mockreg

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivseb/traffic-twin/internal/audit"
	"github.com/ivseb/traffic-twin/internal/auth"
)

// ManagedView is a mock tt-core runs in Kubernetes for a group.
type ManagedView struct {
	Group     string           `json:"group"`
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	TokenID   string           `json:"token_id"`
	URL       string           `json:"url"`
	CreatedBy string           `json:"created_by"`
	UpdatedAt time.Time        `json:"updated_at"`
	Pods      DeploymentStatus `json:"pods"`
	// Error is set when the Kubernetes API could not be read.
	Error string `json:"error,omitempty"`
}

// Environment says how mocks can be started from this console.
type Environment struct {
	// Kubernetes is true when tt-core can start mocks itself (mock.kubernetes).
	Kubernetes bool   `json:"kubernetes"`
	Namespace  string `json:"namespace,omitempty"`
	ConsoleURL string `json:"console_url"`
	Image      string `json:"image"`
	// ReportIntervalS is how often the mocks report.
	ReportIntervalS int `json:"report_interval_s"`
}

func (g *Registry) environment(consoleURL string) Environment {
	e := Environment{ConsoleURL: consoleURL, Image: g.o.Image, ReportIntervalS: int(g.o.ReportInterval / time.Second)}
	if g.o.Kube != nil {
		e.Kubernetes, e.Namespace = true, g.o.Kube.Namespace()
	}
	return e
}

func (g *Registry) managedList(ctx context.Context) ([]ManagedView, error) {
	rows, err := g.o.DB.QueryContext(ctx, `SELECT grp, name, token_id, url, created_by, updated_at FROM mockreg_managed ORDER BY grp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ManagedView{}
	for rows.Next() {
		var v ManagedView
		var at int64
		if err := rows.Scan(&v.Group, &v.Name, &v.TokenID, &v.URL, &v.CreatedBy, &at); err != nil {
			return nil, err
		}
		v.UpdatedAt = time.Unix(at, 0).UTC()
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if g.o.Kube != nil {
		for i := range out {
			out[i].Namespace = g.o.Kube.Namespace()
			sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			st, err := g.o.Kube.Status(sctx, out[i].Group)
			cancel()
			if err != nil {
				out[i].Error = "kubernetes_unreachable"
				continue
			}
			out[i].Pods = st
		}
	}
	return out, nil
}

func (g *Registry) managed(ctx context.Context, group string) (*ManagedView, error) {
	var v ManagedView
	var at int64
	err := g.o.DB.QueryRowContext(ctx, `SELECT grp, name, token_id, url, created_by, updated_at FROM mockreg_managed WHERE grp = ?`, group).
		Scan(&v.Group, &v.Name, &v.TokenID, &v.URL, &v.CreatedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.UpdatedAt = time.Unix(at, 0).UTC()
	return &v, nil
}

var errNoKube = apiErr(http.StatusConflict, "kubernetes_disabled",
	"this console cannot start mocks itself (mock.kubernetes is not enabled): run the mock container or the Helm chart with a mock token")

// StartManaged starts the mock of a group in Kubernetes, or refreshes it
// (new token, new pods with the latest pack).
func (g *Registry) StartManaged(ctx context.Context, p *auth.Principal, group string) (*ManagedView, error) {
	return g.applyManaged(ctx, p, group, false)
}

// RestartManaged restarts the pods of a group's managed mock.
func (g *Registry) RestartManaged(ctx context.Context, p *auth.Principal, group string) (*ManagedView, error) {
	return g.applyManaged(ctx, p, group, true)
}

func (g *Registry) applyManaged(ctx context.Context, p *auth.Principal, group string, restart bool) (*ManagedView, error) {
	if g.o.Kube == nil {
		return nil, errNoKube
	}
	if !GroupRE.MatchString(group) {
		return nil, apiErr(http.StatusUnprocessableEntity, "invalid_group", "malformed group name")
	}
	action := "mock.start"
	if restart {
		action = "mock.restart"
	}
	ev := audit.Event{Actor: p.AuditActor(), Action: action, Target: audit.Target{Type: "mock", ID: ObjectName(group)}, Outcome: audit.Failure,
		Details: map[string]string{"group": group, "namespace": g.o.Kube.Namespace()}}
	prev, err := g.managed(ctx, group)
	if err != nil {
		return nil, err
	}
	if restart && prev == nil {
		return nil, apiErr(http.StatusNotFound, "not_found", "no managed mock for this group: start it first")
	}
	keys := ""
	if g.o.GatePubKeys != nil {
		if keys, err = g.o.GatePubKeys(ctx); err != nil || keys == "" {
			ev.Reason = "no_gate_keys"
			g.record(ctx, ev)
			return nil, apiErr(http.StatusServiceUnavailable, "no_gate_keys", "keyguard did not give the public keys of the gate: the mock could not verify the packs")
		}
	}
	tok, err := g.CreateToken(ctx, p, group, "managed by tt-core", MaxTokenDays, true)
	if err != nil {
		return nil, err
	}
	var ctl [24]byte
	_, _ = rand.Read(ctl[:])
	spec := ManagedSpec{Group: group, MockToken: tok.Token, ControlToken: hex.EncodeToString(ctl[:]), GatePubKeys: keys}
	if restart {
		spec.Restart = g.o.Now()
	}
	kctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	url, err := g.o.Kube.Apply(kctx, spec)
	if err != nil {
		g.log.Error("mockreg: managed mock not applied", "group", group, "err", err)
		_, _ = g.o.DB.ExecContext(ctx, `UPDATE mockreg_tokens SET revoked = 1 WHERE id = ?`, tok.TokenID)
		ev.Reason = "kubernetes_failed"
		g.record(ctx, ev)
		var ke *KubeError
		if errors.As(err, &ke) && (ke.Status == http.StatusForbidden || ke.Status == http.StatusUnauthorized) {
			return nil, apiErr(http.StatusBadGateway, "kubernetes_forbidden", "Kubernetes refused: the service account of tt-core needs the Role of the chart (secrets, services, deployments, routes) in namespace "+g.o.Kube.Namespace())
		}
		return nil, apiErr(http.StatusBadGateway, "kubernetes_failed", "the Kubernetes API did not accept the mock: see the tt-core log")
	}
	now := g.o.Now().UTC().Truncate(time.Second)
	if _, err := g.o.DB.ExecContext(ctx, `INSERT INTO mockreg_managed (grp, name, token_id, url, created_by, updated_at) VALUES (?,?,?,?,?,?)
		ON CONFLICT(grp) DO UPDATE SET name = excluded.name, token_id = excluded.token_id, url = excluded.url, created_by = excluded.created_by, updated_at = excluded.updated_at`,
		group, ObjectName(group), tok.TokenID, url, principalName(p), now.Unix()); err != nil {
		return nil, err
	}
	if prev != nil && prev.TokenID != tok.TokenID {
		_, _ = g.o.DB.ExecContext(ctx, `UPDATE mockreg_tokens SET revoked = 1 WHERE id = ?`, prev.TokenID)
	}
	ev.Outcome = audit.Success
	ev.Details["token_id"] = tok.TokenID
	g.record(ctx, ev)
	return g.managed(ctx, group)
}

// EnsureManaged starts the managed mock of a group when it is not running;
// a running one is left as it is (it switches to the newest pack itself).
func (g *Registry) EnsureManaged(ctx context.Context, p *auth.Principal, group string) (*ManagedView, error) {
	if g.o.Kube == nil {
		return nil, errNoKube
	}
	prev, err := g.managed(ctx, group)
	if err != nil {
		return nil, err
	}
	if prev != nil {
		sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := g.o.Kube.Status(sctx, group)
		cancel()
		if err == nil && st.Found {
			return prev, nil
		}
	}
	return g.StartManaged(ctx, p, group)
}

// ConnectedCode says whether mocks of the group report to the console:
// "connected" (they switch to the new pack by themselves) or "none_connected".
func (g *Registry) ConnectedCode(group string) string {
	now := g.o.Wall()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, in := range g.instances {
		if in.Group == group && g.online(in, now) {
			return "connected"
		}
	}
	return "none_connected"
}

// StopManaged deletes the Kubernetes objects of a group's mock and revokes its token.
func (g *Registry) StopManaged(ctx context.Context, p *auth.Principal, group string) error {
	if g.o.Kube == nil {
		return errNoKube
	}
	prev, err := g.managed(ctx, group)
	if err != nil {
		return err
	}
	if prev == nil {
		return errNotFound
	}
	ev := audit.Event{Actor: p.AuditActor(), Action: "mock.stop", Target: audit.Target{Type: "mock", ID: prev.Name}, Outcome: audit.Failure,
		Details: map[string]string{"group": group, "namespace": g.o.Kube.Namespace()}}
	kctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := g.o.Kube.Delete(kctx, group); err != nil {
		g.log.Error("mockreg: managed mock not deleted", "group", group, "err", err)
		ev.Reason = "kubernetes_failed"
		g.record(ctx, ev)
		return apiErr(http.StatusBadGateway, "kubernetes_failed", "the Kubernetes API did not delete the mock: see the tt-core log")
	}
	if _, err := g.o.DB.ExecContext(ctx, `UPDATE mockreg_tokens SET revoked = 1 WHERE id = ?`, prev.TokenID); err != nil {
		return err
	}
	if _, err := g.o.DB.ExecContext(ctx, `DELETE FROM mockreg_managed WHERE grp = ?`, group); err != nil {
		return err
	}
	g.mu.Lock()
	for _, in := range g.instances {
		if in.TokenID == prev.TokenID {
			in.revoked = true
		}
	}
	g.mu.Unlock()
	ev.Outcome = audit.Success
	g.record(ctx, ev)
	return nil
}

// Setup holds what a user needs to run a mock himself, the token filled in.
type Setup struct {
	ConsoleURL  string `json:"console_url"`
	Group       string `json:"group"`
	Image       string `json:"image"`
	GatePubKeys string `json:"gate_pubkeys"`
	Env         string `json:"env"`
	Docker      string `json:"docker"`
	// CLI runs the mock with the tt binary of the kit (console mode): the
	// same command without a container.
	CLI string `json:"cli"`
	// Version is the tag of the image: the tt of the kit should be the same
	// version (a newer console may need a newer mock).
	Version    string `json:"version"`
	HelmValues string `json:"helm_values"`
	Helm       string `json:"helm"`
	OpenShift  string `json:"openshift"`
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// setup renders the snippets of a token. With an https console the
// commands pass the CA of its certificate (--console-ca): an installation
// usually has a certificate of the company CA, which the mock does not
// trust otherwise (usability test #4, m1).
func setup(consoleURL, group, image, keys, token string) *Setup {
	s := &Setup{ConsoleURL: consoleURL, Group: group, Image: image, GatePubKeys: keys}
	_, s.Version, _ = strings.Cut(image, ":")
	tls := strings.HasPrefix(consoleURL, "https://")
	s.Env = fmt.Sprintf("TT_MOCK_CONSOLE=%s\nTT_MOCK_GROUP=%s\nTT_MOCK_TOKEN=%s\nTT_GATE_PUBKEYS=%s\n", consoleURL, group, token, keys)
	if tls {
		s.Env += "TT_MOCK_CONSOLE_CA=./console-ca.pem\n"
	}
	var docker, cli strings.Builder
	if tls {
		docker.WriteString("# console-ca.pem: the CA of the console certificate (PEM). With a certificate of a\n# public CA, drop the -v line and --console-ca.\n")
	}
	docker.WriteString("docker run --rm -p 8480:8480 \\\n")
	if tls {
		docker.WriteString("  -v \"$PWD/console-ca.pem:/etc/tt/console-ca.pem:ro\" \\\n")
	}
	fmt.Fprintf(&docker, "  -e TT_MOCK_TOKEN=%s \\\n  -e TT_GATE_PUBKEYS=%s \\\n  %s mock --console %s --group %s \\\n", shellQuote(token), shellQuote(keys), image, consoleURL, group)
	if tls {
		docker.WriteString("  --console-ca /etc/tt/console-ca.pem \\\n")
	}
	docker.WriteString("  --addr 0.0.0.0:8480 --public-url http://localhost:8480\n")
	s.Docker = docker.String()

	if s.Version == "" || s.Version == "latest" {
		cli.WriteString("# tt of the traffic-twin kit, the same version as the console (tt version)\n")
	} else {
		fmt.Fprintf(&cli, "# tt of the traffic-twin kit, version %s like the console (tt version)\n", s.Version)
	}
	fmt.Fprintf(&cli, "export TT_MOCK_TOKEN=%s\nexport TT_GATE_PUBKEYS=%s\n", shellQuote(token), shellQuote(keys))
	fmt.Fprintf(&cli, "tt mock --console %s --group %s \\\n", consoleURL, group)
	if tls {
		cli.WriteString("  --console-ca ./console-ca.pem \\\n")
	}
	cli.WriteString("  --addr 127.0.0.1:8480\n")
	s.CLI = cli.String()
	repo, tag, _ := strings.Cut(image, ":")
	s.HelmValues = fmt.Sprintf(`image:
  repository: %s
  tag: %q
console:
  url: %s
  group: %s
  # Secret with the mock token (key "token"), created below.
  tokenSecret: tt-mock-token
  # PEM of the console CA when its certificate is not from a public CA:
  # caConfigMap: tt-console-ca
gatePubKeys: %q
`, repo, tag, consoleURL, group, keys)
	s.Helm = fmt.Sprintf(`kubectl create secret generic tt-mock-token --from-literal=token=%s
# the chart is deploy/helm/tt-mock of the traffic-twin repository (or release archive)
helm install tt-mock deploy/helm/tt-mock -f values-mock.yaml
`, shellQuote(token))
	s.OpenShift = fmt.Sprintf(`oc project <your-test-namespace>
oc create secret generic tt-mock-token --from-literal=token=%s
helm install tt-mock deploy/helm/tt-mock -f values-mock.yaml --set route.enabled=true
oc get route tt-mock -o jsonpath='{.spec.host}'   # the mock URL, also shown on the Mock page
`, shellQuote(token))
	return s
}
