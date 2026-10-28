package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ivseb/traffic-twin/internal/injector"
	"github.com/ivseb/traffic-twin/internal/server"
)

// Environment variables of tt injector (flags win).
const (
	envInjectorListen     = "TT_INJECTOR_LISTEN"
	envInjectorTLSCert    = "TT_INJECTOR_TLS_CERT_FILE"
	envInjectorTLSKey     = "TT_INJECTOR_TLS_KEY_FILE"
	envInjectorImages     = "TT_INJECTOR_SDK_IMAGES" // node=ref,python=ref,java=ref
	envInjectorPullPolicy = "TT_INJECTOR_PULL_POLICY"
	envInjectorEnroll     = "TT_INJECTOR_ENROLL_SECRET"
	envInjectorHMAC       = "TT_INJECTOR_HMAC_SECRET"
	envInjectorHMACMode   = "TT_INJECTOR_HMAC_MODE"
	envInjectorLogLevel   = "TT_INJECTOR_LOG_LEVEL"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// runInjector runs the mutating admission webhook that adds the SDK to pods
// annotated traffic-twin.io/inject.
func runInjector(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("injector", stderr)
	listen := fs.String("listen", envOr(envInjectorListen, ":8443"), "listen address of the TLS webhook (env "+envInjectorListen+")")
	cert := fs.String("tls-cert-file", os.Getenv(envInjectorTLSCert), "webhook server certificate, PEM (env "+envInjectorTLSCert+")")
	key := fs.String("tls-key-file", os.Getenv(envInjectorTLSKey), "webhook server key, PEM (env "+envInjectorTLSKey+")")
	var images multiFlag
	fs.Var(&images, "sdk-image", "SDK init image as language=reference, repeatable (env "+envInjectorImages+" as comma separated list)")
	pull := fs.String("pull-policy", envOr(envInjectorPullPolicy, injector.DefaultPullPolicy), "imagePullPolicy of the init container")
	enroll := fs.String("enroll-secret", envOr(envInjectorEnroll, injector.DefaultEnrollSecret), "default Secret with the keys url and token (looked up in the pod namespace)")
	hmac := fs.String("hmac-secret", envOr(envInjectorHMAC, injector.DefaultHMACSecret), "default Secret with the key hmac-key (looked up in the pod namespace)")
	mode := fs.String("hmac-mode", envOr(envInjectorHMACMode, "0444"), "octal file mode of the HMAC key volume")
	deny := fs.Bool("deny-unknown", false, "deny pods whose traffic-twin.io/inject language is unknown (default: allow unmodified with a warning)")
	level := fs.String("log-level", envOr(envInjectorLogLevel, "info"), "debug, info, warn or error")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: tt injector -tls-cert-file CERT -tls-key-file KEY -sdk-image node=REF [-sdk-image python=REF ...] [flags]")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg := injector.DefaultConfig()
	cfg.PullPolicy, cfg.EnrollSecret, cfg.HMACSecret, cfg.DenyUnknown = *pull, *enroll, *hmac, *deny
	m, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil {
		fmt.Fprintf(stderr, "tt injector: -hmac-mode: %v\n", err)
		return 2
	}
	cfg.HMACMode = int32(m)
	all := append([]string(nil), images...)
	if v := os.Getenv(envInjectorImages); v != "" && len(images) == 0 {
		all = strings.Split(v, ",")
	}
	for _, kv := range all {
		lang, ref, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || lang == "" || ref == "" {
			fmt.Fprintf(stderr, "tt injector: -sdk-image %q: want language=reference\n", kv)
			return 2
		}
		cfg.SDKImages[lang] = ref
	}
	mut, err := injector.NewMutator(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "tt injector: %v\n", err)
		return 2
	}
	if *cert == "" || *key == "" {
		fmt.Fprintln(stderr, "tt injector: -tls-cert-file and -tls-key-file are required (the API server only calls webhooks over TLS)")
		return 2
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "tt injector: %v\n", err)
		return 1
	}
	logger := server.NewLogger(stderr, *level, "json")
	fmt.Fprintf(stdout, "tt injector %s listening on %s\n", version, ln.Addr())
	if err := injector.Serve(ctx, ln, *cert, *key, injector.Handler(mut, logger)); err != nil {
		fmt.Fprintf(stderr, "tt injector: %v\n", err)
		return 1
	}
	return 0
}
