// Package injector implements the traffic-twin Kubernetes mutating admission
// webhook (ARCHITECTURE section 3.4, "tt injector").
//
// A pod annotated traffic-twin.io/inject: <language> gets the matching SDK
// through an init container that copies it into a shared emptyDir, plus the
// language specific start-up wiring and the TT_* environment (enrollment URL
// and token from a Secret, service name from the labels). The same idea as the
// OpenTelemetry Operator injection, and the two coexist: the webhook only
// appends to NODE_OPTIONS, PYTHONPATH, JAVA_TOOL_OPTIONS (our -javaagent goes
// last, an existing -javaagent is never replaced), DOTNET_STARTUP_HOOKS and
// ASPNETCORE_HOSTINGSTARTUPASSEMBLIES, never touches an OTEL_* variable, and is
// idempotent so that reinvocation after another webhook is harmless.
//
// The webhook is built to be registered with failurePolicy: Ignore. It never
// denies a pod by itself (a malformed or unknown request is allowed
// unmodified, with an admission warning and a pod annotation); only
// Config.DenyUnknown turns an unknown language into a denial.
//
// Only the standard library is used. Nothing in this package logs values from
// the pod specification other than names.
package injector
