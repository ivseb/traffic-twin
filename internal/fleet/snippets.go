package fleet

import (
	"fmt"
	"strings"
)

// Snippet is a ready-to-paste install instruction for the onboarding
// wizard (ARCHITECTURE 3.4 step 2). ID is stable: the console translates the
// title (and the comment lines) by it.
type Snippet struct {
	ID       string `json:"id,omitempty"`
	Title    string `json:"title"`
	Language string `json:"language"` // bash | yaml | dockerfile | text
	Text     string `json:"text"`
}

// KindK8sInject is the enrollment token kind for the Kubernetes injection
// webhook: unlike the sdk-* kinds it enrolls the SDK of any language, since
// the language is chosen per workload by the pod annotation.
const KindK8sInject = "k8s-inject"

// injectLang maps an SDK kind to the value of the Kubernetes injection
// annotation traffic-twin.io/inject.
var injectLang = map[string]string{
	"sdk-node": "node", "sdk-python": "python", "sdk-java": "java",
	"sdk-dotnet": "dotnet", "sdk-go": "go", "sdk-php": "php",
}

// HMACKeyPath is where the snippets expect the installation-wide HMAC key
// file (docs/USER_GUIDE.md, "La chiave HMAC").
const HMACKeyPath = "/etc/traffic-twin/hmac.key"

// Comment lines shared by the snippets (the console translates them by
// their exact text, ui/src/lib/api/rest/map.ts).
const (
	commentKey1   = "# HMAC key: the installation-wide file from your platform team (one line <kid>:<base64url>,"
	commentKey2   = "# same kid as the policy hmac.kid, e.g. k1, and the same key keyguard holds). Never commit it."
	commentTgz    = "# Until the SDK is on your registry, install the file of the kit: npm install ./traffic-twin-sdk-<version>.tgz"
	commentSecret = "# Pass TT_ENROLL_TOKEN at run time (secret), never bake it into the image."
	commentMount  = "# Mount the HMAC key file at run time (e.g. -v /etc/traffic-twin:/etc/traffic-twin:ro)."
	commentEgress = "# then point the application's external base URLs (or HTTPS_PROXY) at tt-egress"
	commentJar    = "# download traffic-twin-agent.jar from your internal artifact registry"
	commentHook1  = "# publish the hook once (it brings TrafficTwin.Sdk and TrafficTwin.Sdk.AspNetCore) from sdk/dotnet, or copy it"
	commentHook2  = "# from your internal artifact registry:"
	commentNuget  = "# Program.cs: builder.Services.AddTrafficTwin(); ... app.UseTrafficTwin();"
	commentLangs  = "# node | python | java | dotnet | go | php: one token serves all of them"
	commentWheel  = "# Install the wheel of the kit (once the SDK is on your registry: pip install traffic-twin)"
	commentPyRun  = "# Use your own server command: gunicorn app:app | flask --app app run | python manage.py runserver"
	commentPyIn   = "# Inbound capture is automatic for Flask, FastAPI/Starlette, Django and apps loaded by uvicorn or gunicorn;"
	commentPyOut  = "# requests and httpx calls are captured too (TT_OUTBOUND=off turns the outgoing side off)."
)

// SnippetComments lists every comment the snippets use; the console has a
// translation for each (ui/src/lib/api/rest/snippets.ts, checked by a test).
var SnippetComments = []string{commentKey1, commentKey2, commentTgz, commentSecret, commentMount, commentEgress,
	commentJar, commentHook1, commentHook2, commentNuget, commentLangs, commentWheel, commentPyRun, commentPyIn, commentPyOut}

// Snippets returns the install snippets for a source kind, already filled
// with the enrollment URL and token. service is the proposed service name
// (the first allowed name of the group; empty if none).
func Snippets(kind, fleetURL, token, service string) []Snippet {
	if service == "" {
		service = "my-service"
	}
	env := fmt.Sprintf("TT_ENROLL_URL=%s TT_ENROLL_TOKEN=%s TT_SERVICE_NAME=%s TT_HMAC_KEY_FILE=%s", fleetURL, token, service, HMACKeyPath)
	key := commentKey1 + "\n" + commentKey2 + "\n"
	var out []Snippet
	add := func(id, title, lang, text string) {
		out = append(out, Snippet{id, title, lang, strings.TrimLeft(text, "\n")})
	}
	switch kind {
	case "sdk-node":
		add("node", "Node.js (20+; full fetch body capture on 24+)", "bash", fmt.Sprintf(`
%s
npm install @traffic-twin/sdk
%s%s node --import @traffic-twin/sdk/register app.js
`, commentTgz, key, env))
		add("node-docker", "Dockerfile", "dockerfile", fmt.Sprintf(`
RUN npm install @traffic-twin/sdk
ENV TT_ENROLL_URL=%s TT_SERVICE_NAME=%s TT_HMAC_KEY_FILE=%s
%s
%s
%sCMD ["node", "--import", "@traffic-twin/sdk/register", "app.js"]
`, fleetURL, service, HMACKeyPath, commentSecret, commentMount, key))
	case "sdk-python":
		add("python", "Python (3.9+): FastAPI, Flask, Django, zero code", "bash", fmt.Sprintf(`
%s
pip install ./traffic_twin-<version>-py3-none-any.whl
%s
%s
%s%s python -m traffic_twin run -- uvicorn app:app
%s
`, commentWheel, commentPyIn, commentPyOut, key, env, commentPyRun))
		add("python-code", "Python: wrap the app in code (only if the console says inbound is not captured)", "text", `
import traffic_twin

app = traffic_twin.install(app)   # Flask, FastAPI/Starlette, any WSGI/ASGI app
# Django: application = traffic_twin.install(get_wsgi_application())
`)
	case "sdk-java":
		add("java", "Java (17+)", "bash", fmt.Sprintf(`
%s
%s%s java -javaagent:traffic-twin-agent.jar -jar app.jar
`, commentJar, key, env))
	case "sdk-dotnet":
		add("dotnet-hook", ".NET (8+): zero code", "bash", fmt.Sprintf(`
%s
%s
#   dotnet publish src/TrafficTwin.StartupHook -c Release -o /opt/traffic-twin
%s%s \
DOTNET_STARTUP_HOOKS=/opt/traffic-twin/TrafficTwin.StartupHook.dll \
ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore \
  dotnet app.dll
`, commentHook1, commentHook2, key, env))
		add("dotnet-nuget", ".NET (8+): in code (NuGet)", "bash", fmt.Sprintf(`
dotnet add package TrafficTwin.Sdk.AspNetCore
%s
%s%s dotnet run
`, commentNuget, key, env))
	case "sdk-go":
		add("go", "Go (1.25+)", "bash", fmt.Sprintf(`
go get github.com/ivseb/traffic-twin/sdk/go
%s%s go run .
`, key, env))
		add("go-code", "Go: wrap the HTTP handler and client", "text", `
import tt "github.com/ivseb/traffic-twin/sdk/go"

tt.Start(context.Background())          // reads TT_ENROLL_URL / TT_ENROLL_TOKEN / TT_HMAC_KEY_FILE
http.ListenAndServe(":8080", tt.Handler(mux))
client := &http.Client{Transport: tt.Transport(http.DefaultTransport)}
`)
	case "sdk-php":
		add("php", "PHP (8.1+)", "bash", fmt.Sprintf(`
composer require traffic-twin/sdk
%s%s php -d auto_prepend_file=vendor/traffic-twin/sdk/register.php -S 0.0.0.0:8080
`, key, env))
	case "egress":
		add("egress-helm", "Kubernetes (Helm)", "bash", fmt.Sprintf(`
helm install tt-egress traffic-twin/egress --set enroll.url=%s --set enroll.token=%s --set serviceName=%s
`, fleetURL, token, service))
		add("egress-docker", "Docker", "bash", fmt.Sprintf(`
%sdocker run -d --name tt-egress -p 3128:3128 -v /etc/traffic-twin:/etc/traffic-twin:ro -e %s traffic-twin/egress
%s
`, key, strings.ReplaceAll(env, " ", " -e "), commentEgress))
	case "obi":
		add("obi", "OBI adapter", "yaml", fmt.Sprintf(`
env:
  - { name: TT_ENROLL_URL, value: "%s" }
  - { name: TT_ENROLL_TOKEN, valueFrom: { secretKeyRef: { name: tt-enroll, key: token } } }
  - { name: TT_SERVICE_NAME, value: "%s" }
  - { name: TT_HMAC_KEY_FILE, value: "/var/run/secrets/traffic-twin/hmac-key" }
`, fleetURL, service))
		add("obi-secret", "Kubernetes secret", "bash", fmt.Sprintf("kubectl create secret generic tt-enroll --from-literal=token=%s\n%skubectl create secret generic tt-hmac --from-file=hmac-key=./hmac.key\n", token, key))
	case "import-har", "import-otlp":
		what := strings.TrimPrefix(kind, "import-")
		add("import", "Import "+strings.ToUpper(what), "bash", fmt.Sprintf(`
%s%s tt import %s capture.%s
`, key, env, what, map[string]string{"har": "har", "otlp": "json"}[what]))
	}
	if lang, ok := injectLang[kind]; ok {
		k8sSnippets(add, lang, fleetURL, token, service)
	}
	if kind == KindK8sInject {
		k8sSnippets(add, "node", fleetURL, token, service)
	}
	return out
}

// k8sSnippets are the instructions for the Kubernetes injection webhook
// (deploy/README.md, "Iniezione dell'SDK"): the Secrets it reads (keys url
// and token; hmac-key) and the pod annotations. For a k8s-inject token the
// language is the one of each workload, so the annotation lists them all.
func k8sSnippets(add func(id, title, lang, text string), lang, fleetURL, token, service string) {
	add("k8s-secret", "Kubernetes secrets (namespace of the application)", "bash", fmt.Sprintf(
		"kubectl -n <namespace> create secret generic tt-enroll --from-literal=url=%s --from-literal=token=%s\n%s%s\n",
		fleetURL, token, commentKey1+"\n"+commentKey2+"\n", "kubectl -n <namespace> create secret generic tt-hmac --from-file=hmac-key=./hmac.key"))
	choices := ""
	if lang == "node" {
		choices = "          " + commentLangs
	}
	add("k8s-annotations", "Pod template annotations (injection webhook)", "yaml", fmt.Sprintf(`
spec:
  template:
    metadata:
      annotations:
        traffic-twin.io/inject: %s%s
        traffic-twin.io/enroll-secret: tt-enroll
        traffic-twin.io/hmac-secret: tt-hmac
        traffic-twin.io/service-name: %s
`, lang, choices, service))
}
