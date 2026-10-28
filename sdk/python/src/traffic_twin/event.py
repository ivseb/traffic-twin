"""Event assembly (event.md 1) and the OTLP/HTTP JSON logs body (event.md 4.2), by hand."""

from __future__ import annotations

import datetime
import json
import re
from typing import Any, Dict, List, Optional

from ._version import SDK_VERSION, SOURCE_KIND
from .jsonlex import write_canonical
from .sanitizer import MAX_EVENT_BYTES, compose_canonical

_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX16 = re.compile(r"[0-9a-f]{16}")


def iso_ms(ts_ms: int) -> str:
    """RFC 3339 UTC with milliseconds (``2026-10-19T10:00:00.412Z``)."""
    d = datetime.datetime.fromtimestamp(ts_ms // 1000, datetime.timezone.utc)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (d.year, d.month, d.day, d.hour, d.minute, d.second, ts_ms % 1000)


def build_event(parts_in: Dict[str, str], policy_id: str, policy_version: int, policy_hash: str, source_id: str,
                dir: str, ts_ms: int, latency_ms: int, status: Optional[int], net_error: Optional[str],
                trace_id: Optional[str], span_id: Optional[str], parent_span_id: Optional[str]) -> Optional[str]:
    """Full canonical event from the serialized top-level members of the sanitizer output
    and the fields the source fills. None if invalid or over 512 KiB (counted as a
    sanitizer error)."""
    parts = dict(parts_in)
    w = write_canonical
    parts["schema"] = w("tt.http.exchange/v1")
    parts["policy"] = '{"hash":%s,"id":%s,"version":%d}' % (w(policy_hash), w(policy_id), policy_version)
    parts["source"] = '{"id":%s,"kind":%s,"version":%s}' % (w(source_id), w(SOURCE_KIND), w(SDK_VERSION))
    parts["ts"] = w(iso_ms(ts_ms))
    parts["latency_ms"] = str(max(0, int(latency_ms)))
    parts["dir"] = w(dir)
    if net_error:
        parts["net_error"] = w(net_error)
        parts.pop("resp", None)
    elif isinstance(status, int) and 100 <= status <= 599:
        parts["status"] = str(status)
    else:
        return None
    if trace_id and _HEX32.fullmatch(trace_id):
        parts["trace_id"] = w(trace_id)
    if span_id and _HEX16.fullmatch(span_id):
        parts["span_id"] = w(span_id)
    if parent_span_id and _HEX16.fullmatch(parent_span_id):
        parts["parent_span_id"] = w(parent_span_id)
    s = compose_canonical(parts)
    return None if len(s) > MAX_EVENT_BYTES else s


class QueuedEvent:
    __slots__ = ("json", "ts_ms", "trace_id", "span_id", "policy_hash")

    def __init__(self, json_: str, ts_ms: int, trace_id: Optional[str], span_id: Optional[str], policy_hash: str) -> None:
        self.json = json_
        self.ts_ms = ts_ms
        self.trace_id = trace_id
        self.span_id = span_id
        self.policy_hash = policy_hash


def _attr(key: str, value: str) -> Dict[str, Any]:
    return {"key": key, "value": {"stringValue": value}}


def otlp_body(events: List[QueuedEvent], service_name: str, source_id: str, now_ms: int) -> bytes:
    observed = str(now_ms * 1_000_000)
    records = []
    for e in events:
        r: Dict[str, Any] = {
            "timeUnixNano": str(e.ts_ms * 1_000_000),
            "observedTimeUnixNano": observed,
            "severityNumber": 9,
            "severityText": "INFO",
            "eventName": "tt.http.exchange",
        }
        if e.trace_id and _HEX32.fullmatch(e.trace_id):
            r["traceId"] = e.trace_id
        if e.span_id and _HEX16.fullmatch(e.span_id):
            r["spanId"] = e.span_id
        r["attributes"] = [_attr("tt.schema", "tt.http.exchange/v1"), _attr("tt.policy.hash", e.policy_hash)]
        r["body"] = {"stringValue": e.json}
        records.append(r)
    doc = {"resourceLogs": [{
        "resource": {"attributes": [
            _attr("service.name", service_name), _attr("tt.source.kind", SOURCE_KIND),
            _attr("tt.source.version", SDK_VERSION), _attr("tt.source.id", source_id),
        ]},
        "scopeLogs": [{"scope": {"name": "traffic-twin", "version": SDK_VERSION}, "logRecords": records}],
    }]}
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
