package mockreg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Managed mocks: when tt-core runs in Kubernetes with mock.kubernetes
// enabled, it creates in one namespace, for each group, a Secret (mock
// token, control token, console CA), a Service, an OpenShift Route when the
// cluster has routes, and a Deployment running `tt mock --console`. It
// talks to the Kubernetes REST API directly with its in-cluster service
// account (no client library): server-side apply for create/update, DELETE
// for stop. The RBAC it needs is a Role in that namespace only, on
// secrets, services, deployments and routes (deploy/helm/tt-core,
// mockManager).

// In-cluster service account files.
const (
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount"
	saTokenFile = saDir + "/token"
	saCAFile    = saDir + "/ca.crt"
	saNSFile    = saDir + "/namespace"
	fieldMgr    = "tt-core"
	mockPort    = 8480
)

// KubeConfig configures managed mocks (config mock.kubernetes).
type KubeConfig struct {
	// Namespace where the mocks run (default: the namespace of tt-core).
	Namespace string
	// Image of the mock container (the tt image).
	Image           string
	ImagePullPolicy string
	// ServiceAccount of the mock pods (its token is not mounted; "" = default).
	ServiceAccount string
	CPURequest     string
	MemoryRequest  string
	CPULimit       string
	MemoryLimit    string
	// Route: "auto" (when the cluster has OpenShift routes), "on" or "off".
	Route string
	// ConsoleURL is the URL of tt-core seen from the mock pods (required).
	ConsoleURL string
	// ConsoleCA is the PEM of the CA of tt-core's admin certificate, given
	// to the mocks ("" = public CA).
	ConsoleCA []byte
	// APIServer, Token, CA replace the in-cluster configuration (tests).
	APIServer string
	Token     string
	CA        []byte
	// Client replaces the HTTP client (tests).
	Client *http.Client
}

// Kube talks to the Kubernetes API.
type Kube struct {
	cfg  KubeConfig
	hc   *http.Client
	base string

	mu     sync.Mutex
	routes *bool
}

// NewKube builds the Kubernetes client from the in-cluster configuration
// (or the overrides of cfg).
func NewKube(cfg KubeConfig) (*Kube, error) {
	if cfg.ConsoleURL == "" {
		return nil, errors.New("mock.kubernetes: mock.console_url is required (the URL of tt-core seen from the mock pods)")
	}
	if cfg.Image == "" {
		return nil, errors.New("mock.kubernetes: image is required")
	}
	base := cfg.APIServer
	if base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("mock.kubernetes: not running in Kubernetes (KUBERNETES_SERVICE_HOST is not set)")
		}
		base = "https://" + net.JoinHostPort(host, port)
	}
	if cfg.Namespace == "" {
		b, err := os.ReadFile(saNSFile)
		if err != nil {
			return nil, errors.New("mock.kubernetes: namespace is not set and the service account namespace cannot be read")
		}
		cfg.Namespace = strings.TrimSpace(string(b))
	}
	if !dnsLabelRE.MatchString(cfg.Namespace) {
		return nil, errors.New("mock.kubernetes: malformed namespace")
	}
	switch cfg.Route {
	case "":
		cfg.Route = "auto"
	case "auto", "on", "off":
	default:
		return nil, errors.New("mock.kubernetes.route must be auto, on or off")
	}
	if cfg.ImagePullPolicy == "" {
		cfg.ImagePullPolicy = "IfNotPresent"
	}
	hc := cfg.Client
	if hc == nil {
		ca := cfg.CA
		if ca == nil {
			b, err := os.ReadFile(saCAFile)
			if err != nil {
				return nil, fmt.Errorf("mock.kubernetes: service account CA: %w", err)
			}
			ca = b
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("mock.kubernetes: no certificate in the cluster CA")
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, Proxy: nil,
			TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
		hc = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	return &Kube{cfg: cfg, hc: hc, base: strings.TrimSuffix(base, "/")}, nil
}

// Namespace is where the managed mocks run.
func (k *Kube) Namespace() string { return k.cfg.Namespace }

func (k *Kube) token() (string, error) {
	if k.cfg.Token != "" {
		return k.cfg.Token, nil
	}
	// Projected tokens rotate: read it at every call.
	b, err := os.ReadFile(saTokenFile)
	if err != nil {
		return "", errors.New("mock.kubernetes: the service account token cannot be read (automountServiceAccountToken?)")
	}
	return strings.TrimSpace(string(b)), nil
}

// KubeError is an answer of the Kubernetes API.
type KubeError struct {
	Status int
	Reason string
}

func (e *KubeError) Error() string { return fmt.Sprintf("kubernetes api: %d %s", e.Status, e.Reason) }

func (k *Kube) do(ctx context.Context, method, path, ctype string, body []byte, out any) error {
	tok, err := k.token()
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var st struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(data, &st)
		if st.Reason == "" {
			st.Reason = http.StatusText(resp.StatusCode)
		}
		return &KubeError{Status: resp.StatusCode, Reason: st.Reason}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func isNotFound(err error) bool {
	var ke *KubeError
	return errors.As(err, &ke) && ke.Status == http.StatusNotFound
}

// apply creates or updates an object with server-side apply.
func (k *Kube) apply(ctx context.Context, path string, obj map[string]any, out any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return k.do(ctx, http.MethodPatch, path+"?fieldManager="+fieldMgr+"&force=true", "application/apply-patch+yaml", b, out)
}

func (k *Kube) nsPath(group, version, resource, name string) string {
	prefix := "/api/" + version
	if group != "" {
		prefix = "/apis/" + group + "/" + version
	}
	p := prefix + "/namespaces/" + url.PathEscape(k.cfg.Namespace) + "/" + resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

// hasRoutes reports whether the cluster serves OpenShift routes (cached).
func (k *Kube) hasRoutes(ctx context.Context) bool {
	switch k.cfg.Route {
	case "on":
		return true
	case "off":
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.routes != nil {
		return *k.routes
	}
	err := k.do(ctx, http.MethodGet, "/apis/route.openshift.io/v1", "", nil, nil)
	ok := err == nil
	if err == nil || isNotFound(err) {
		k.routes = &ok
	}
	return ok
}

var (
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	nonDNS     = regexp.MustCompile(`[^a-z0-9-]+`)
)

// ObjectName is the name of the Kubernetes objects of a group's mock:
// tt-mock-<group>, made a DNS label (a short hash keeps two groups that
// differ only by . or _ apart).
func ObjectName(group string) string {
	s := nonDNS.ReplaceAllString(strings.ToLower(group), "-")
	s = strings.Trim(s, "-")
	if s != group || len(s) > 40 {
		sum := sha256.Sum256([]byte(group))
		if len(s) > 40 {
			s = strings.Trim(s[:40], "-")
		}
		s += "-" + hex.EncodeToString(sum[:3])
	}
	return "tt-mock-" + s
}

// ManagedSpec is what a managed mock needs.
type ManagedSpec struct {
	Group        string
	MockToken    string
	ControlToken string
	GatePubKeys  string
	// Restart forces new pods (an annotation of the pod template).
	Restart time.Time
}

func (k *Kube) labels(name, group string) map[string]any {
	return map[string]any{
		"app.kubernetes.io/name":       "tt-mock",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/part-of":    "traffic-twin",
		"app.kubernetes.io/managed-by": "tt-core",
		"traffic-twin.io/group":        groupLabel(group),
	}
}

// groupLabel is the group as a label value: the DNS part of ObjectName
// (at most 47 bytes, starts and ends with an alphanumeric, hash suffix when
// the group is not already a DNS label). A raw replacement would turn
// "team." or a 63-byte group into a value the API server rejects.
func groupLabel(group string) string { return strings.TrimPrefix(ObjectName(group), "tt-mock-") }

func meta(name, ns string, labels map[string]any) map[string]any {
	return map[string]any{"name": name, "namespace": ns, "labels": labels}
}

// SecretObject, ServiceObject, RouteObject and DeploymentObject are the
// objects of a managed mock (exported for the tests).
func (k *Kube) SecretObject(name string, s ManagedSpec) map[string]any {
	b64 := base64.StdEncoding.EncodeToString
	data := map[string]any{"mock-token": b64([]byte(s.MockToken)), "control-token": b64([]byte(s.ControlToken))}
	if len(k.cfg.ConsoleCA) > 0 {
		data["console-ca.crt"] = b64(k.cfg.ConsoleCA)
	}
	return map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": meta(name, k.cfg.Namespace, k.labels(name, s.Group)),
		"type": "Opaque", "data": data}
}

func (k *Kube) ServiceObject(name, group string) map[string]any {
	l := k.labels(name, group)
	return map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": meta(name, k.cfg.Namespace, l),
		"spec": map[string]any{"type": "ClusterIP", "selector": map[string]any{"app.kubernetes.io/name": "tt-mock", "app.kubernetes.io/instance": name},
			"ports": []any{map[string]any{"name": "http", "port": mockPort, "targetPort": "http", "protocol": "TCP"}}}}
}

func (k *Kube) RouteObject(name, group string) map[string]any {
	return map[string]any{"apiVersion": "route.openshift.io/v1", "kind": "Route", "metadata": meta(name, k.cfg.Namespace, k.labels(name, group)),
		"spec": map[string]any{"to": map[string]any{"kind": "Service", "name": name, "weight": 100}, "port": map[string]any{"targetPort": "http"},
			"tls": map[string]any{"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}}}
}

func (k *Kube) DeploymentObject(name, publicURL string, s ManagedSpec) map[string]any {
	c := k.cfg
	secretRef := func(key string) map[string]any {
		return map[string]any{"valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": name, "key": key}}}
	}
	env := []any{
		withName("TT_MOCK_TOKEN", secretRef("mock-token")),
		withName("TT_CONTROL_TOKEN", secretRef("control-token")),
		map[string]any{"name": "TT_GATE_PUBKEYS", "value": s.GatePubKeys},
	}
	args := []any{"mock", "--console", c.ConsoleURL, "--group", s.Group, "--addr", fmt.Sprintf("0.0.0.0:%d", mockPort), "--public-url", publicURL}
	mounts := []any{map[string]any{"name": "tmp", "mountPath": "/tmp"}}
	vols := []any{map[string]any{"name": "tmp", "emptyDir": map[string]any{"sizeLimit": "1Gi"}}}
	if len(c.ConsoleCA) > 0 {
		args = append(args, "--console-ca", "/etc/tt-mock/console-ca.crt")
		mounts = append(mounts, map[string]any{"name": "console-ca", "mountPath": "/etc/tt-mock", "readOnly": true})
		vols = append(vols, map[string]any{"name": "console-ca", "secret": map[string]any{"secretName": name, "defaultMode": 0o444,
			"items": []any{map[string]any{"key": "console-ca.crt", "path": "console-ca.crt"}}}})
	}
	res := map[string]any{}
	req, lim := map[string]any{}, map[string]any{}
	for k, v := range map[string]string{"cpu": c.CPURequest, "memory": c.MemoryRequest} {
		if v != "" {
			req[k] = v
		}
	}
	for k, v := range map[string]string{"cpu": c.CPULimit, "memory": c.MemoryLimit} {
		if v != "" {
			lim[k] = v
		}
	}
	if len(req) > 0 {
		res["requests"] = req
	}
	if len(lim) > 0 {
		res["limits"] = lim
	}
	probe := func(delay, period int) map[string]any {
		return map[string]any{"httpGet": map[string]any{"path": "/__tt/health", "port": "http"}, "initialDelaySeconds": delay, "periodSeconds": period, "timeoutSeconds": 3}
	}
	container := map[string]any{
		"name": "tt-mock", "image": c.Image, "imagePullPolicy": c.ImagePullPolicy, "args": args, "env": env,
		"ports":          []any{map[string]any{"name": "http", "containerPort": mockPort, "protocol": "TCP"}},
		"livenessProbe":  probe(2, 10),
		"readinessProbe": probe(1, 5),
		"resources":      res,
		"volumeMounts":   mounts,
		"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "runAsNonRoot": true,
			"capabilities": map[string]any{"drop": []any{"ALL"}}, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
	}
	pod := map[string]any{
		"automountServiceAccountToken": false,
		"enableServiceLinks":           false,
		"containers":                   []any{container},
		"volumes":                      vols,
		"securityContext":              map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
	}
	if c.ServiceAccount != "" {
		pod["serviceAccountName"] = c.ServiceAccount
	}
	// The token's fingerprint in the template rolls the pod when the
	// Secret changes (a refresh issues a new token).
	sum := sha256.Sum256([]byte(s.MockToken))
	ann := map[string]any{"traffic-twin.io/token": hex.EncodeToString(sum[:8])}
	if !s.Restart.IsZero() {
		ann["traffic-twin.io/restarted-at"] = s.Restart.UTC().Format(time.RFC3339)
	}
	sel := map[string]any{"app.kubernetes.io/name": "tt-mock", "app.kubernetes.io/instance": name}
	return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta(name, c.Namespace, k.labels(name, s.Group)),
		"spec": map[string]any{"replicas": 1, "strategy": map[string]any{"type": "Recreate"},
			"selector": map[string]any{"matchLabels": sel},
			"template": map[string]any{"metadata": map[string]any{"labels": k.labels(name, s.Group), "annotations": ann}, "spec": pod}}}
}

func withName(name string, m map[string]any) map[string]any {
	m["name"] = name
	return m
}

// Apply creates or updates the objects of a group's mock and returns the
// URL the tests use to reach it.
func (k *Kube) Apply(ctx context.Context, s ManagedSpec) (string, error) {
	name := ObjectName(s.Group)
	if err := k.apply(ctx, k.nsPath("", "v1", "secrets", name), k.SecretObject(name, s), nil); err != nil {
		return "", fmt.Errorf("secret: %w", err)
	}
	if err := k.apply(ctx, k.nsPath("", "v1", "services", name), k.ServiceObject(name, s.Group), nil); err != nil {
		return "", fmt.Errorf("service: %w", err)
	}
	public := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", name, k.cfg.Namespace, mockPort)
	if k.hasRoutes(ctx) {
		var rt struct {
			Spec struct {
				Host string `json:"host"`
			} `json:"spec"`
		}
		if err := k.apply(ctx, k.nsPath("route.openshift.io", "v1", "routes", name), k.RouteObject(name, s.Group), &rt); err != nil {
			return "", fmt.Errorf("route: %w", err)
		}
		if rt.Spec.Host != "" {
			public = "https://" + rt.Spec.Host
		}
	}
	if err := k.apply(ctx, k.nsPath("apps", "v1", "deployments", name), k.DeploymentObject(name, public, s), nil); err != nil {
		return "", fmt.Errorf("deployment: %w", err)
	}
	return public, nil
}

// Delete removes the objects of a group's mock (missing ones are fine).
func (k *Kube) Delete(ctx context.Context, group string) error {
	name := ObjectName(group)
	paths := []string{k.nsPath("apps", "v1", "deployments", name), k.nsPath("", "v1", "services", name)}
	if k.hasRoutes(ctx) {
		paths = append(paths, k.nsPath("route.openshift.io", "v1", "routes", name))
	}
	paths = append(paths, k.nsPath("", "v1", "secrets", name))
	var errs []error
	for _, p := range paths {
		if err := k.do(ctx, http.MethodDelete, p+"?propagationPolicy=Background", "", nil, nil); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DeploymentStatus is the state of a managed mock's Deployment.
type DeploymentStatus struct {
	Found bool `json:"found"`
	Ready int  `json:"ready_replicas"`
	Want  int  `json:"replicas"`
}

// Status reads the Deployment of a group's mock.
func (k *Kube) Status(ctx context.Context, group string) (DeploymentStatus, error) {
	var d struct {
		Spec struct {
			Replicas int `json:"replicas"`
		} `json:"spec"`
		Status struct {
			ReadyReplicas int `json:"readyReplicas"`
		} `json:"status"`
	}
	err := k.do(ctx, http.MethodGet, k.nsPath("apps", "v1", "deployments", ObjectName(group)), "", nil, &d)
	if isNotFound(err) {
		return DeploymentStatus{}, nil
	}
	if err != nil {
		return DeploymentStatus{}, err
	}
	return DeploymentStatus{Found: true, Ready: d.Status.ReadyReplicas, Want: d.Spec.Replicas}, nil
}
