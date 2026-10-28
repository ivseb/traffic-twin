package injector

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---- Admission API types (admission.k8s.io/v1), only what is needed ----

// AdmissionReview is the envelope exchanged with the API server.
type AdmissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *AdmissionRequest  `json:"request,omitempty"`
	Response   *AdmissionResponse `json:"response,omitempty"`
}

// AdmissionRequest is the part of the request the webhook reads.
type AdmissionRequest struct {
	UID         string           `json:"uid"`
	Kind        groupVersionKind `json:"kind"`
	Namespace   string           `json:"namespace,omitempty"`
	Operation   string           `json:"operation"`
	SubResource string           `json:"subResource,omitempty"`
	Object      json.RawMessage  `json:"object,omitempty"`
}

type groupVersionKind struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

// AdmissionResponse is the webhook answer. Patch is a JSON Patch (RFC 6902).
type AdmissionResponse struct {
	UID       string   `json:"uid"`
	Allowed   bool     `json:"allowed"`
	Status    *Status  `json:"status,omitempty"`
	Patch     []byte   `json:"patch,omitempty"` // base64 on the wire
	PatchType string   `json:"patchType,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Status is the denial reason.
type Status struct {
	Code    int32  `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// ---- Minimal pod model ----

type pod struct {
	Metadata struct {
		Name            string            `json:"name"`
		GenerateName    string            `json:"generateName"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		Annotations     map[string]string `json:"annotations"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		Containers     []container `json:"containers"`
		InitContainers []container `json:"initContainers"`
		Volumes        []struct {
			Name string `json:"name"`
		} `json:"volumes"`
	} `json:"spec"`
}

type container struct {
	Name string   `json:"name"`
	Env  []envVar `json:"env"`
	// VolumeMounts is decoded to know whether the array exists and which names are taken.
	VolumeMounts []struct {
		Name string `json:"name"`
	} `json:"volumeMounts"`
}

type envVar struct {
	Name      string          `json:"name"`
	Value     string          `json:"value"`
	ValueFrom json.RawMessage `json:"valueFrom,omitempty"`
}

// JSON Patch operation.
type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Mutator turns pod admission requests into JSON patches.
type Mutator struct {
	cfg Config
}

// NewMutator validates cfg and returns a Mutator.
func NewMutator(cfg Config) (*Mutator, error) {
	if cfg.SDKImages == nil {
		cfg.SDKImages = map[string]string{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Mutator{cfg: cfg}, nil
}

// Outcome describes what happened to a request, for logging (names only).
type Outcome struct {
	Namespace, Pod, Language string
	Result                   string // "skipped", "injected", "unchanged", "refused", "error"
	Reason                   string
}

// Review answers one AdmissionReview. It never returns an error: whatever
// goes wrong the pod is allowed unmodified, so the webhook can never be the
// reason an application does not start (except Config.DenyUnknown).
func (m *Mutator) Review(in *AdmissionReview) (*AdmissionReview, Outcome) {
	out := &AdmissionReview{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"}
	if in == nil || in.Request == nil {
		out.Response = &AdmissionResponse{Allowed: true, Warnings: []string{"traffic-twin: empty admission request"}}
		return out, Outcome{Result: "error", Reason: "empty request"}
	}
	req := in.Request
	resp := &AdmissionResponse{UID: req.UID, Allowed: true}
	out.Response = resp

	if req.Operation != "CREATE" || req.Kind.Kind != "Pod" || req.Kind.Group != "" || req.SubResource != "" || len(req.Object) == 0 {
		return out, Outcome{Result: "skipped", Reason: "not a pod creation"}
	}
	var p pod
	if err := json.Unmarshal(req.Object, &p); err != nil {
		resp.Warnings = append(resp.Warnings, "traffic-twin: pod not understood, left unchanged")
		return out, Outcome{Result: "error", Reason: "undecodable pod"}
	}
	ns := p.Metadata.Namespace
	if ns == "" {
		ns = req.Namespace
	}
	oc := Outcome{Namespace: ns, Pod: firstNonEmpty(p.Metadata.Name, p.Metadata.GenerateName)}

	raw, ok := p.Metadata.Annotations[AnnotationInject]
	if !ok {
		oc.Result, oc.Reason = "skipped", "no annotation"
		return out, oc
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "false", "none", "disabled", "no":
		oc.Result, oc.Reason = "skipped", "injection disabled"
		return out, oc
	}
	oc.Language = raw
	lang, known := lookupLanguage(raw)
	if !known {
		msg := fmt.Sprintf("refused: unknown language %q (supported: %s)", raw, strings.Join(SupportedLanguages(), ", "))
		return m.refuse(out, &p, oc, msg, m.cfg.DenyUnknown)
	}
	oc.Language = lang.name
	image := m.cfg.SDKImages[lang.name]
	if lang.mode == modeAuto && image == "" {
		return m.refuse(out, &p, oc, fmt.Sprintf("refused: no SDK image configured for %s in this cluster", lang.name), false)
	}

	pl := newPlan(m.cfg, &p, lang, image)
	if !pl.selectContainers() {
		return m.refuse(out, &p, oc, "refused: "+pl.warnings[len(pl.warnings)-1], false)
	}
	pl.build()
	resp.Warnings = append(resp.Warnings, prefixAll("traffic-twin: ", pl.warnings)...)
	if len(pl.ops) == 0 {
		oc.Result, oc.Reason = "unchanged", "already injected"
		return out, oc
	}
	data, err := json.Marshal(pl.ops)
	if err != nil { // cannot happen: every value was marshalled already
		resp.Warnings = append(resp.Warnings, "traffic-twin: internal error, pod left unchanged")
		oc.Result, oc.Reason = "error", "marshal"
		return out, oc
	}
	resp.Patch, resp.PatchType = data, "JSONPatch"
	oc.Result = "injected"
	return out, oc
}

// refuse leaves the pod alone, explains why in a warning and in the status
// annotation, or denies it when deny is set.
func (m *Mutator) refuse(out *AdmissionReview, p *pod, oc Outcome, msg string, deny bool) (*AdmissionReview, Outcome) {
	resp := out.Response
	oc.Result, oc.Reason = "refused", msg
	if deny {
		resp.Allowed = false
		resp.Status = &Status{Code: 403, Message: "traffic-twin: " + msg}
		return out, oc
	}
	resp.Warnings = append(resp.Warnings, "traffic-twin: "+msg)
	pl := &plan{pod: p, hasAnnotations: p.Metadata.Annotations != nil}
	pl.setStatus(msg)
	if len(pl.ops) > 0 {
		if data, err := json.Marshal(pl.ops); err == nil {
			resp.Patch, resp.PatchType = data, "JSONPatch"
		}
	}
	return out, oc
}

// ---- Planner ----

type plan struct {
	cfg   Config
	pod   *pod
	lang  language
	image string

	ops      []patchOp
	warnings []string

	targets []int // indexes into pod.Spec.Containers
	// Mutable views of what the patch has already created.
	hasVolumes     bool
	volumes        map[string]bool
	hasInit        bool
	hasAnnotations bool
	env            map[int][]envVar
	hasEnv         map[int]bool
	hasMounts      map[int]bool
	mounts         map[int]map[string]bool
}

func newPlan(cfg Config, p *pod, lang language, image string) *plan {
	pl := &plan{
		cfg: cfg, pod: p, lang: lang, image: image,
		volumes:   map[string]bool{},
		env:       map[int][]envVar{},
		hasEnv:    map[int]bool{},
		hasMounts: map[int]bool{},
		mounts:    map[int]map[string]bool{},
	}
	pl.hasVolumes = p.Spec.Volumes != nil
	for _, v := range p.Spec.Volumes {
		pl.volumes[v.Name] = true
	}
	pl.hasInit = p.Spec.InitContainers != nil
	pl.hasAnnotations = p.Metadata.Annotations != nil
	for i, c := range p.Spec.Containers {
		pl.env[i] = append([]envVar(nil), c.Env...)
		pl.hasEnv[i] = c.Env != nil
		pl.hasMounts[i] = c.VolumeMounts != nil
		pl.mounts[i] = map[string]bool{}
		for _, vm := range c.VolumeMounts {
			pl.mounts[i][vm.Name] = true
		}
	}
	return pl
}

func (pl *plan) selectContainers() bool {
	cs := pl.pod.Spec.Containers
	if len(cs) == 0 {
		pl.warnings = append(pl.warnings, "the pod has no containers")
		return false
	}
	names := strings.TrimSpace(pl.pod.Metadata.Annotations[AnnotationContainerNames])
	if names == "" {
		pl.targets = []int{0}
		return true
	}
	seen := map[int]bool{}
	for _, n := range strings.Split(names, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		found := false
		for i, c := range cs {
			if c.Name == n {
				found = true
				if !seen[i] {
					seen[i] = true
					pl.targets = append(pl.targets, i)
				}
			}
		}
		if !found {
			pl.warnings = append(pl.warnings, fmt.Sprintf("container %q listed in %s does not exist, skipped", n, AnnotationContainerNames))
		}
	}
	if len(pl.targets) == 0 {
		pl.warnings = append(pl.warnings, fmt.Sprintf("none of the containers in %s exists", AnnotationContainerNames))
		return false
	}
	return true
}

func (pl *plan) ann(key string) string {
	return strings.TrimSpace(pl.pod.Metadata.Annotations[key])
}

func (pl *plan) build() {
	if pl.lang.mode == modeAuto {
		pl.addVolume(SDKVolumeName, map[string]any{"emptyDir": map[string]any{"sizeLimit": "64Mi"}})
		pl.addInitContainer()
	}
	pl.addVolume(StateVolumeName, map[string]any{"emptyDir": map[string]any{"sizeLimit": "16Mi"}})
	hmacSecret := firstNonEmpty(pl.ann(AnnotationHMACSecret), pl.cfg.HMACSecret)
	pl.addVolume(HMACVolumeName, map[string]any{"secret": map[string]any{
		"secretName":  hmacSecret,
		"optional":    true, // a missing Secret must not keep the pod from starting
		"defaultMode": pl.cfg.HMACMode,
		"items":       []any{map[string]any{"key": HMACFileName, "path": HMACFileName}},
	}})

	enrollSecret := firstNonEmpty(pl.ann(AnnotationEnrollSecret), pl.cfg.EnrollSecret)
	for _, i := range pl.targets {
		if pl.lang.mode == modeAuto {
			pl.addMount(i, SDKVolumeName, SDKMountPath, true)
		}
		pl.addMount(i, StateVolumeName, StateMountPath, false)
		pl.addMount(i, HMACVolumeName, HMACMountPath, true)

		pl.addEnvIfAbsent(i, envVar{Name: "TT_ENROLL_URL", ValueFrom: secretRef(enrollSecret, "url")})
		pl.addEnvIfAbsent(i, envVar{Name: "TT_ENROLL_TOKEN", ValueFrom: secretRef(enrollSecret, "token")})
		if !pl.hasEnvVar(i, "TT_SERVICE_NAME") && !pl.hasEnvVar(i, "OTEL_SERVICE_NAME") {
			pl.addEnv(i, envVar{Name: "TT_SERVICE_NAME", Value: pl.serviceName(i)})
		}
		if !pl.hasEnvVar(i, "TT_HMAC_KEY") {
			pl.addEnvIfAbsent(i, envVar{Name: "TT_HMAC_KEY_FILE", Value: HMACMountPath + "/" + HMACFileName})
		}
		pl.addEnvIfAbsent(i, envVar{Name: "TT_STATE_DIR", Value: StateDir})

		switch pl.lang.name {
		case "node":
			pl.appendEnv(i, "NODE_OPTIONS", SDKMountPath+"/node/", " ", "--import "+SDKMountPath+"/node/dist/esm/register.js", false)
		case "python":
			pl.appendEnv(i, "PYTHONPATH", SDKMountPath+"/python/", ":", SDKMountPath+"/python/bootstrap:"+SDKMountPath+"/python/site", true)
		case "java":
			pl.javaEnv(i)
		case "dotnet":
			pl.dotnetEnv(i)
		}
	}

	if pl.lang.mode == modeManual {
		pl.setStatus("env-only: " + pl.lang.note)
	} else {
		pl.setStatus("injected")
	}
}

// ---- Java ----

// javaAgentJar is the zero-code entry point (sdk-agent); javaAgentMarker is how an existing
// JAVA_TOOL_OPTIONS is recognised as already carrying it.
const (
	javaAgentJar    = SDKMountPath + "/java/agent/traffic-twin-agent.jar"
	javaAgentMarker = "traffic-twin-agent.jar"
)

// foreignJavaAgent reports whether options contain a -javaagent that is not ours.
func foreignJavaAgent(options string) bool {
	for _, tok := range strings.Fields(options) {
		if strings.HasPrefix(tok, "-javaagent:") && !strings.Contains(tok, javaAgentMarker) {
			return true
		}
	}
	return false
}

func (pl *plan) javaEnv(i int) {
	ext := SDKMountPath + "/java/ext/sdk-otel-extension.jar"
	jto, hasJTO := pl.envVarOf(i, "JAVA_TOOL_OPTIONS")
	agentSeen := hasJTO && len(jto.ValueFrom) == 0 && foreignJavaAgent(jto.Value)
	if agentSeen || strings.EqualFold(pl.ann(AnnotationJavaOTelExtension), "true") {
		switch {
		case pl.hasEnvVar(i, "OTEL_JAVAAGENT_EXTENSIONS") ||
			(hasJTO && strings.Contains(jto.Value, "otel.javaagent.extensions")):
			pl.warnings = append(pl.warnings, "OTel Java agent extensions already configured, the traffic-twin extension was not added")
		default:
			pl.appendEnv(i, "JAVA_TOOL_OPTIONS", ext, " ", "-Dotel.javaagent.extensions="+ext, false)
		}
	}
	if strings.EqualFold(pl.ann(AnnotationJavaClasspath), "true") {
		// Library mode: the application registers the SDK itself (or the servlet container finds the
		// initializer on the class path). The agent would start a second SDK, so it is not added.
		lib := SDKMountPath + "/java/lib/*"
		pl.appendEnv(i, "CLASSPATH", SDKMountPath+"/java/lib/", ":", lib, false)
		return
	}
	// Zero-code mode: our -javaagent goes at the END of JAVA_TOOL_OPTIONS. An existing -javaagent (the
	// OpenTelemetry Operator's, a vendor APM) is never replaced or reordered, and a value that already
	// carries ours is left alone, so reinvocation is harmless.
	pl.appendEnv(i, "JAVA_TOOL_OPTIONS", javaAgentMarker, " ", "-javaagent:"+javaAgentJar, false)
}

// ---- .NET ----

// The zero-code entry points of the .NET SDK: a DOTNET_STARTUP_HOOKS assembly (copied by the init
// image) and the name of the hosting startup assembly it makes loadable. Both variables are extended
// at the end, so a hook that is already there (OpenTelemetry .NET automatic instrumentation) keeps
// running first. The pod is Linux, hence ':' between startup hooks.
const (
	dotnetHookMarker    = "TrafficTwin.StartupHook.dll"
	dotnetHostingMarker = "TrafficTwin.Sdk.AspNetCore"
)

func (pl *plan) dotnetEnv(i int) {
	pl.appendEnv(i, "DOTNET_STARTUP_HOOKS", dotnetHookMarker, ":", SDKMountPath+"/dotnet/"+dotnetHookMarker, false)
	pl.appendEnv(i, "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES", dotnetHostingMarker, ";", dotnetHostingMarker, false)
}

// ---- Helpers on the plan ----

func (pl *plan) envVarOf(i int, name string) (envVar, bool) {
	for _, e := range pl.env[i] {
		if e.Name == name {
			return e, true
		}
	}
	return envVar{}, false
}

func (pl *plan) hasEnvVar(i int, name string) bool {
	_, ok := pl.envVarOf(i, name)
	return ok
}

func (pl *plan) cpath(i int) string { return fmt.Sprintf("/spec/containers/%d", i) }

func (pl *plan) add(path string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	pl.ops = append(pl.ops, patchOp{Op: "add", Path: path, Value: b})
}

func (pl *plan) replace(path string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	pl.ops = append(pl.ops, patchOp{Op: "replace", Path: path, Value: b})
}

func (pl *plan) addVolume(name string, body map[string]any) {
	if pl.volumes[name] {
		return
	}
	body["name"] = name
	if pl.hasVolumes {
		pl.add("/spec/volumes/-", body)
	} else {
		pl.add("/spec/volumes", []any{body})
		pl.hasVolumes = true
	}
	pl.volumes[name] = true
}

func (pl *plan) addMount(i int, volume, path string, readOnly bool) {
	if pl.mounts[i][volume] {
		return
	}
	m := map[string]any{"name": volume, "mountPath": path}
	if readOnly {
		m["readOnly"] = true
	}
	if pl.hasMounts[i] {
		pl.add(pl.cpath(i)+"/volumeMounts/-", m)
	} else {
		pl.add(pl.cpath(i)+"/volumeMounts", []any{m})
		pl.hasMounts[i] = true
	}
	pl.mounts[i][volume] = true
}

func (pl *plan) addInitContainer() {
	for _, c := range pl.pod.Spec.InitContainers {
		if c.Name == InitContainerName {
			return
		}
	}
	uid := int64(65532)
	c := map[string]any{
		"name":            InitContainerName,
		"image":           pl.image,
		"imagePullPolicy": pl.cfg.PullPolicy,
		"volumeMounts":    []any{map[string]any{"name": SDKVolumeName, "mountPath": SDKMountPath}},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": "10m", "memory": "16Mi"},
			"limits":   map[string]any{"cpu": "100m", "memory": "64Mi"},
		},
		"securityContext": map[string]any{
			"runAsNonRoot":             true,
			"runAsUser":                uid,
			"runAsGroup":               uid,
			"allowPrivilegeEscalation": false,
			"readOnlyRootFilesystem":   true,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
			"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
		},
		"terminationMessagePolicy": "FallbackToLogsOnError",
	}
	if pl.hasInit {
		pl.add("/spec/initContainers/-", c)
	} else {
		pl.add("/spec/initContainers", []any{c})
		pl.hasInit = true
	}
}

// addEnv appends a variable that is known to be absent.
func (pl *plan) addEnv(i int, e envVar) {
	body := map[string]any{"name": e.Name}
	if len(e.ValueFrom) > 0 {
		body["valueFrom"] = e.ValueFrom
	} else {
		body["value"] = e.Value
	}
	if pl.hasEnv[i] {
		pl.add(pl.cpath(i)+"/env/-", body)
	} else {
		pl.add(pl.cpath(i)+"/env", []any{body})
		pl.hasEnv[i] = true
	}
	pl.env[i] = append(pl.env[i], e)
}

func (pl *plan) addEnvIfAbsent(i int, e envVar) {
	if !pl.hasEnvVar(i, e.Name) {
		pl.addEnv(i, e)
	}
}

// appendEnv adds value to a list-like variable: the variable is created when
// absent, extended (at the end, or at the front when prepend) when it holds a
// plain value that does not already contain marker, and left alone with a
// warning when it comes from valueFrom (it cannot be extended safely).
func (pl *plan) appendEnv(i int, name, marker, sep, value string, prepend bool) {
	cur, ok := pl.envVarOf(i, name)
	if !ok {
		pl.addEnv(i, envVar{Name: name, Value: value})
		return
	}
	if len(cur.ValueFrom) > 0 {
		pl.warnings = append(pl.warnings, fmt.Sprintf("%s is set from valueFrom in container %q: not modified, add the traffic-twin entry by hand", name, pl.pod.Spec.Containers[i].Name))
		return
	}
	if strings.Contains(cur.Value, marker) {
		return // already wired: idempotent
	}
	var nv string
	switch {
	case strings.TrimSpace(cur.Value) == "":
		nv = value
	case prepend:
		nv = value + sep + cur.Value
	default:
		nv = cur.Value + sep + value
	}
	for j, e := range pl.env[i] {
		if e.Name == name {
			pl.env[i][j].Value = nv
			// The index in the original array is the same as in pl.env only
			// while variables are appended, which is the only thing we do.
			pl.replace(fmt.Sprintf("%s/env/%d/value", pl.cpath(i), j), nv)
			return
		}
	}
}

func (pl *plan) setStatus(status string) {
	cur, exists := pl.pod.Metadata.Annotations[AnnotationStatus]
	if exists && cur == status {
		return
	}
	key := "/metadata/annotations/" + escapePointer(AnnotationStatus)
	switch {
	case !pl.hasAnnotations && !exists:
		pl.add("/metadata/annotations", map[string]string{AnnotationStatus: status})
		pl.hasAnnotations = true
	case exists:
		pl.replace(key, status)
	default:
		pl.add(key, status)
	}
}

func escapePointer(s string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(s)
}

func secretRef(name, key string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"secretKeyRef": map[string]any{"name": name, "key": key, "optional": true}})
	return b
}

// ---- Service name ----

var (
	hashSuffix   = regexp.MustCompile(`-[a-z0-9]{5,10}$`)
	digitsSuffix = regexp.MustCompile(`-[0-9]{6,}$`)
	badNameChars = regexp.MustCompile(`[^a-z0-9._-]+`)
)

// serviceName derives TT_SERVICE_NAME: annotation, then the labels
// app.kubernetes.io/name and app, then the workload that owns the pod, then
// the container name.
func (pl *plan) serviceName(i int) string {
	p := pl.pod
	candidates := []string{
		p.Metadata.Annotations[AnnotationServiceName],
		p.Metadata.Labels["app.kubernetes.io/name"],
		p.Metadata.Labels["app"],
	}
	for _, o := range p.Metadata.OwnerReferences {
		switch o.Kind {
		case "ReplicaSet":
			candidates = append(candidates, hashSuffix.ReplaceAllString(o.Name, ""))
		case "Job":
			candidates = append(candidates, digitsSuffix.ReplaceAllString(o.Name, ""))
		default:
			candidates = append(candidates, o.Name)
		}
	}
	candidates = append(candidates, strings.TrimRight(p.Metadata.GenerateName, "-"), p.Spec.Containers[i].Name)
	for _, c := range candidates {
		if n := sanitizeName(c); n != "" {
			return n
		}
	}
	return "unknown"
}

func sanitizeName(s string) string {
	s = badNameChars.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	s = strings.Trim(s, "-._")
	if len(s) > 63 {
		s = strings.Trim(s[:63], "-._")
	}
	return s
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func prefixAll(prefix string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = prefix + s
	}
	return out
}
