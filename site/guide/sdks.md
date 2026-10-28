---
description: "traffic-twin capture SDKs for Go, Node.js, Python, Java, .NET and PHP: install, frameworks supported and how values are sanitized in process."
---

# SDKs

Six native capture SDKs observe the inbound and outbound HTTP calls of a process, **sanitize them in the process** according to the signed policy, and send `tt-core` only shapes, HMAC tokens and the values the policy allows, as OTLP/HTTP JSON over mTLS. Each SDK has a detailed README in its folder (Italian), linked below.

## What every SDK has in common

- **No runtime dependencies** beyond the standard library (and, for ASP.NET Core, the shared framework). No OpenTelemetry packages, no YAML parser, no cryptography libraries: the policy arrives already compiled to JSON.
- **The same sanitizer, proved equal.** The conformance vectors in [`conformance/`](https://github.com/ivseb/traffic-twin/tree/main/conformance) must be reproduced byte for byte by every SDK in CI.
- **Fail-closed.** Without a valid signed policy, the HMAC key and a first successful heartbeat in the current process, nothing is captured and the app works normally.
- **Does not change your traffic.** No `traceparent` is injected. The only exception, optional and decided by the policy, is the `tt.s` baggage member towards the internal hosts in `sampling.propagate_to`, never towards an external service.
- **Does not slow the app down.** On the request path there is only the sampling decision and a copy of the first bytes of the bodies; sanitizing and sending run in the background with bounded queues. When a queue is full, events are dropped and counted, never requests.
- **Coexists with OpenTelemetry.** It reads the current trace context, never registers a global tracer provider or propagator, and exports through its own private exporter.
- **Never logs payloads.** With `TT_DEBUG=1` it writes only state and error codes to stderr.

## Configuration

The same environment variables everywhere; usually they are all you need.

| Variable | Meaning |
|---|---|
| `TT_ENROLL_URL` | URL of tt-core's Fleet/intake listener (always `https`) |
| `TT_ENROLL_TOKEN` | Enrollment token `tte_<secret>.<CA fingerprint>`, single use or per group; it pins tt-core's CA |
| `TT_HMAC_KEY_FILE` / `TT_HMAC_KEY` | The local HMAC key, one or more `<kid>:<base64url>` lines. It never travels to tt-core |
| `TT_SERVICE_NAME` | Service name requested at enrollment (otherwise `OTEL_SERVICE_NAME`); the name used in events is the one tt-core assigns |
| `TT_STATE_DIR` | Local state: certificate, private key, signed policy, kill switch (`0700` folder, `0600` files) |
| `TT_DISABLED` | `1` turns the SDK off completely |
| `TT_DEBUG` | `1` prints state and error codes to stderr, never values |

## Per language

| Language | Package | Minimum | Start without code changes | Frameworks and clients |
|---|---|---|---|---|
| [Go](https://github.com/ivseb/traffic-twin/blob/main/sdk/go/README.md) | `github.com/ivseb/traffic-twin/sdk/go` | Go 1.25 | wrap with `ttsdk.Handler(mux)` and `ttsdk.Transport(nil)` | `net/http`, Gin, chi |
| [Node.js](https://github.com/ivseb/traffic-twin/blob/main/sdk/node/README.md) | `@traffic-twin/sdk` | Node 20 (full `fetch` bodies from 24) | `node --import @traffic-twin/sdk/register app.js` | `node:http`, Express, Fastify, `fetch`/undici |
| [Python](https://github.com/ivseb/traffic-twin/blob/main/sdk/python/README.md) | `traffic-twin` | Python 3.9 | `python -m traffic_twin run -- uvicorn app:app` | Flask, FastAPI/Starlette, Django, any WSGI/ASGI; `requests`, `httpx`, `urllib` |
| [Java](https://github.com/ivseb/traffic-twin/blob/main/sdk/java/README.md) | `io.github.ivseb.traffictwin:sdk` (+ `sdk-servlet-javax`, `sdk-otel-extension`, `sdk-agent`) | Java 17 | `java -javaagent:traffic-twin-agent.jar -jar app.jar` | Jakarta and javax servlets, `HttpClient`, Spring `RestTemplate`/`RestClient`, OkHttp, JAX-RS |
| [.NET](https://github.com/ivseb/traffic-twin/blob/main/sdk/dotnet/README.md) | `TrafficTwin.Sdk`, `TrafficTwin.Sdk.AspNetCore` | .NET 8 | `DOTNET_STARTUP_HOOKS` + `ASPNETCORE_HOSTINGSTARTUPASSEMBLIES` | ASP.NET Core, `HttpClient` |
| [PHP](https://github.com/ivseb/traffic-twin/blob/main/sdk/php/README.md) | `traffic-twin/sdk` | PHP 8.1 with ext-sodium | middleware plus the `tt-shipper` process | PSR-15, Laravel, Symfony, Guzzle |

PHP shares nothing between requests, so its SDK has two halves: the workers sanitize and append to a local spool, and a long-running `tt-shipper` (systemd, sidecar or cron with `--once`) handles enrollment, heartbeats, policies and sending.

### Node.js

```sh
npm install @traffic-twin/sdk
TT_ENROLL_URL=https://tt-core.internal:4318 \
TT_ENROLL_TOKEN=tte_… \
TT_HMAC_KEY_FILE=/run/secrets/tt-hmac-key \
TT_SERVICE_NAME=shop-api \
  node --import @traffic-twin/sdk/register app.js
```

### Go

```go
import ttsdk "github.com/ivseb/traffic-twin/sdk/go"

srv := &http.Server{Addr: ":8080", Handler: ttsdk.Handler(mux)} // inbound
client := &http.Client{Transport: ttsdk.Transport(nil)}          // outbound (nil = DefaultTransport)
```

Without `TT_ENROLL_URL` (or with `TT_DISABLED=1`) both functions return their argument unchanged.

### Python

```sh
pip install traffic-twin
python -m traffic_twin run -- uvicorn app:app      # or gunicorn, flask run, manage.py runserver…
```

Or in code: `app = traffic_twin.install(app)` for Flask, FastAPI/Starlette, Django or any WSGI/ASGI app.

### .NET

```csharp
builder.Services.AddTrafficTwin();   // reads TT_* from the environment
var app = builder.Build();
app.UseTrafficTwin();                // first in the pipeline
```

## No SDK for your stack

- **`tt egress`**, an outbound reverse proxy with the same sanitizer: change the external service's base URL (usually an environment variable), no certificates and no code changes. For a given outbound call use either an SDK or `tt egress`, never both: Fleet flags `double_capture`.
- **OBI (eBPF)**, optional: Linux only, on a privileged host or VM, JSON bodies of a few KB.
- **Kubernetes**: Helm charts include an injector webhook that adds the SDK to annotated pods ([`deploy/README.md`](https://github.com/ivseb/traffic-twin/blob/main/deploy/README.md)).

## Read more (Italian)

- [Sanitizer specification](/it/docs/spec/sanitizer), normative for every source.
- [User manual, §3](/it/docs/user-guide#3-collegare-il-proprio-servizio): connecting your service step by step.
- [Runtime requirements](/it/docs/operations#41-sdk).
