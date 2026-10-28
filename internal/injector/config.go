package injector

import (
	"fmt"
	"sort"
	"strings"
)

// Annotations read from the pod (or written back by the webhook).
const (
	// AnnotationInject selects the language: node, python, java, dotnet, go, php.
	AnnotationInject = "traffic-twin.io/inject"
	// AnnotationContainerNames lists the containers to instrument, comma
	// separated. Default: the first container of the pod.
	AnnotationContainerNames = "traffic-twin.io/container-names"
	// AnnotationServiceName overrides the service name derived from the labels.
	AnnotationServiceName = "traffic-twin.io/service-name"
	// AnnotationEnrollSecret names the Secret (same namespace as the pod) that
	// holds the keys "url" and "token". Default Config.EnrollSecret.
	AnnotationEnrollSecret = "traffic-twin.io/enroll-secret"
	// AnnotationHMACSecret names the Secret that holds the key "hmac-key"
	// (lines "<kid>:<base64url>"). Default Config.HMACSecret.
	AnnotationHMACSecret = "traffic-twin.io/hmac-secret"
	// AnnotationJavaClasspath ("true") also appends the SDK jars to CLASSPATH.
	// Off by default: it replaces a CLASSPATH baked in the image.
	AnnotationJavaClasspath = "traffic-twin.io/java-classpath"
	// AnnotationJavaOTelExtension ("true") forces the OpenTelemetry Java agent
	// extension even when no -javaagent is visible in JAVA_TOOL_OPTIONS (for
	// instance because the OpenTelemetry Operator injects it later).
	AnnotationJavaOTelExtension = "traffic-twin.io/java-otel-extension"
	// AnnotationStatus is written by the webhook: "injected", "refused: ..." or
	// "env-only: ...".
	AnnotationStatus = "traffic-twin.io/inject-status"
)

// Names of the objects the webhook adds to the pod.
const (
	InitContainerName = "tt-sdk-init"
	SDKVolumeName     = "tt-sdk"
	StateVolumeName   = "tt-state"
	HMACVolumeName    = "tt-hmac"

	SDKMountPath   = "/tt/sdk"
	StateMountPath = "/tt/state"
	// StateDir is a subdirectory the SDK creates itself (mode 0700, owned by
	// the application user): an emptyDir root is owned by root.
	StateDir      = StateMountPath + "/agent"
	HMACMountPath = "/var/run/secrets/traffic-twin"
	HMACFileName  = "hmac-key"
)

// Defaults for Config.
const (
	DefaultEnrollSecret = "tt-enroll"
	DefaultHMACSecret   = "tt-hmac"
	DefaultHMACMode     = 0o444
	DefaultPullPolicy   = "IfNotPresent"
)

// Config configures the webhook.
type Config struct {
	// SDKImages maps a language to the SDK init image (deploy/images/sdk-<lang>).
	// Languages without an image are refused. go and php need none.
	SDKImages map[string]string
	// PullPolicy of the init container: Always, IfNotPresent or Never.
	PullPolicy string
	// EnrollSecret and HMACSecret are the default Secret names.
	EnrollSecret string
	HMACSecret   string
	// HMACMode is the file mode of the HMAC key volume (decimal value of the
	// octal mode, for example 0o444). The default is readable by any user of the
	// container because the application may run with any uid; tighten it to
	// 0o440 together with a pod fsGroup.
	HMACMode int32
	// DenyUnknown makes an unknown language a denial instead of a warning.
	// Off by default: the webhook must never block an application deployment.
	DenyUnknown bool
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	switch c.PullPolicy {
	case "Always", "IfNotPresent", "Never":
	default:
		return fmt.Errorf("injector: pull policy %q must be Always, IfNotPresent or Never", c.PullPolicy)
	}
	if !validName(c.EnrollSecret) || !validName(c.HMACSecret) {
		return fmt.Errorf("injector: secret names must be DNS-1123 subdomains")
	}
	if c.HMACMode < 0 || c.HMACMode > 0o777 {
		return fmt.Errorf("injector: hmac mode %o out of range", c.HMACMode)
	}
	for lang, img := range c.SDKImages {
		l, ok := lookupLanguage(lang)
		if !ok || l.mode != modeAuto {
			return fmt.Errorf("injector: no SDK image can be configured for language %q", lang)
		}
		if lang != l.name {
			return fmt.Errorf("injector: use the canonical language name %q, not %q", l.name, lang)
		}
		if strings.TrimSpace(img) == "" || strings.ContainsAny(img, " \t\n") {
			return fmt.Errorf("injector: invalid image for %q", lang)
		}
	}
	return nil
}

// DefaultConfig returns the defaults, without images.
func DefaultConfig() Config {
	return Config{
		SDKImages:    map[string]string{},
		PullPolicy:   DefaultPullPolicy,
		EnrollSecret: DefaultEnrollSecret,
		HMACSecret:   DefaultHMACSecret,
		HMACMode:     DefaultHMACMode,
	}
}

type langMode int

const (
	// modeAuto: SDK copied by the init container and started by the runtime.
	modeAuto langMode = iota
	// modeManual: the SDK has no zero-code start-up; the webhook only injects the
	// TT_* environment and the state/key volumes.
	modeManual
)

type language struct {
	name string
	mode langMode
	// note is shown to the user for manual languages.
	note string
}

var languages = []language{
	{name: "node", mode: modeAuto},
	{name: "python", mode: modeAuto},
	{name: "java", mode: modeAuto},
	{name: "dotnet", mode: modeAuto},
	{name: "go", mode: modeManual, note: "the Go SDK is linked into the binary: the TT_* environment is injected"},
	{name: "php", mode: modeManual, note: "the PHP SDK needs composer and a tt-shipper process: the TT_* environment is injected"},
}

var languageAliases = map[string]string{"nodejs": "node", "py": "python", "jvm": "java", ".net": "dotnet", "golang": "go"}

func lookupLanguage(name string) (language, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if a, ok := languageAliases[name]; ok {
		name = a
	}
	for _, l := range languages {
		if l.name == name {
			return l, true
		}
	}
	return language{}, false
}

// SupportedLanguages lists the accepted values of AnnotationInject.
func SupportedLanguages() []string {
	out := make([]string, 0, len(languages))
	for _, l := range languages {
		out = append(out, l.name)
	}
	sort.Strings(out)
	return out
}

// validName reports whether s is a DNS-1123 subdomain (Secret names).
func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, r := range label {
			alnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !alnum && !(r == '-' && i > 0 && i < len(label)-1) {
				return false
			}
		}
	}
	return true
}
