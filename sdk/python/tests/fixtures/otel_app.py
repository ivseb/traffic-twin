"""An app that already uses OpenTelemetry (SDK, in-memory exporter) and, when TT_* is in the
environment, traffic-twin. Serves a few requests through a WSGI server, each making an
outbound call, and prints the spans it exported plus the state of the global OpenTelemetry
objects. Invented data only."""

import json
import os
import sys
import threading
import urllib.request
import wsgiref.simple_server
from http.server import BaseHTTPRequestHandler, HTTPServer

from opentelemetry import trace
from opentelemetry.propagate import get_global_textmap
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind

exporter = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(exporter))
trace.set_tracer_provider(provider)
propagator_before = get_global_textmap()
tracer = trace.get_tracer("shop")


class Down(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b'{"stock":3}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


down = HTTPServer(("127.0.0.1", 0), Down)
threading.Thread(target=down.serve_forever, daemon=True).start()
DOWN = "http://127.0.0.1:%d" % down.server_address[1]


def app(environ, start_response):
    # an OpenTelemetry-instrumented app: server span around the handler, client span around the call
    with tracer.start_as_current_span("GET /work", kind=SpanKind.SERVER, attributes={"http.route": "/work"}):
        with tracer.start_as_current_span("GET stock", kind=SpanKind.CLIENT, attributes={"http.url": DOWN}):
            data = urllib.request.urlopen(DOWN + "/stock?sku=TSHIRT-RED-M").read()
        out = json.dumps({"stock": json.loads(data)["stock"]}).encode()
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(out)))])
        return [out]


if os.environ.get("TT_ENROLL_URL"):
    import traffic_twin

    app = traffic_twin.install(app, outbound="urllib")
    traffic_twin.get_agent()._ready.wait(30)


class Quiet(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, *a):
        pass


srv = wsgiref.simple_server.make_server("127.0.0.1", 0, app, handler_class=Quiet)
threading.Thread(target=srv.serve_forever, daemon=True).start()
if os.environ.get("TT_ENROLL_URL"):
    import time

    end = time.time() + 20
    while time.time() < end and traffic_twin.get_agent().state != "capturing":
        time.sleep(0.05)

import http.client

for _ in range(3):
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    c.request("GET", "/work")
    r = c.getresponse()
    assert r.status == 200 and json.loads(r.read()) == {"stock": 3}
    c.close()

if os.environ.get("TT_ENROLL_URL"):
    traffic_twin.get_agent().flush()

spans = [{
    "name": s.name, "kind": s.kind.name, "trace_id": "%032x" % s.context.trace_id, "span_id": "%016x" % s.context.span_id,
    "parent": ("%016x" % s.parent.span_id) if s.parent else None, "attributes": sorted(s.attributes),
    "status": s.status.status_code.name,
} for s in exporter.get_finished_spans()]
json.dump({
    "spans": spans,
    "provider_is_same": trace.get_tracer_provider() is provider,
    "provider": type(trace.get_tracer_provider()).__name__,
    "propagator_same": get_global_textmap() is propagator_before,
}, sys.stdout)
