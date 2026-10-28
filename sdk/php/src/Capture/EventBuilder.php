<?php

declare(strict_types=1);

namespace TrafficTwin\Capture;

use TrafficTwin\Sanitizer\CNum;
use TrafficTwin\Sanitizer\Json;
use TrafficTwin\Sanitizer\Obj;
use TrafficTwin\Sanitizer\Policy;
use TrafficTwin\Sanitizer\Sanitizer;
use TrafficTwin\Sanitizer\Time;
use TrafficTwin\Version;

/** Event assembly (event.md 1) and the OTLP/HTTP JSON logs body (event.md 4.2), written by hand. */
final class EventBuilder
{
    /**
     * Full canonical event from the serialized sanitizer members and the fields the source
     * fills. Null if it cannot be a valid event or exceeds 512 KiB (counted as a sanitizer error).
     *
     * @param array<string, string> $parts Result::$parts
     */
    public static function build(
        array $parts,
        Policy $policy,
        string $sourceId,
        string $dir,
        int $tsMs,
        int $latencyMs,
        ?int $status,
        ?string $netError,
        ?string $traceId,
        ?string $spanId,
        ?string $parentSpanId,
    ): ?string {
        $set = static function (string $k, mixed $v) use (&$parts): void {
            $parts[$k] = Json::write($v);
        };
        $set('schema', 'tt.http.exchange/v1');
        $set('policy', new Obj(['id' => $policy->policyId, 'version' => new CNum((string) $policy->version), 'hash' => $policy->hash]));
        $set('source', new Obj(['kind' => Version::SOURCE_KIND, 'version' => Version::SDK, 'id' => $sourceId]));
        $set('ts', Time::iso($tsMs));
        $set('latency_ms', new CNum((string) max(0, $latencyMs)));
        $set('dir', $dir);
        if ($netError !== null) {
            $set('net_error', $netError);
            unset($parts['resp']);
        } elseif ($status !== null && $status >= 100 && $status <= 599) {
            $set('status', new CNum((string) $status));
        } else {
            return null;
        }
        if ($traceId !== null && preg_match('/^[0-9a-f]{32}$/D', $traceId) === 1) {
            $set('trace_id', $traceId);
        }
        if ($spanId !== null && preg_match('/^[0-9a-f]{16}$/D', $spanId) === 1) {
            $set('span_id', $spanId);
        }
        if ($parentSpanId !== null && preg_match('/^[0-9a-f]{16}$/D', $parentSpanId) === 1) {
            $set('parent_span_id', $parentSpanId);
        }
        $s = Sanitizer::compose($parts);
        return strlen($s) > Sanitizer::MAX_EVENT_BYTES ? null : $s;
    }

    /** One spool line: tsMs TAB trace TAB span TAB policy hash TAB event JSON. */
    public static function spoolLine(string $json, int $tsMs, ?string $traceId, ?string $spanId, string $policyHash): string
    {
        return $tsMs . "\t" . ($traceId ?? '-') . "\t" . ($spanId ?? '-') . "\t" . $policyHash . "\t" . $json;
    }

    /**
     * OTLP/HTTP JSON body for a batch of spool records.
     *
     * @param list<array{ts: int, trace: ?string, span: ?string, hash: string, json: string}> $events
     */
    public static function otlpBody(array $events, string $serviceName, string $sourceId, int $nowMs): string
    {
        $attr = static fn (string $k, string $v): array => ['key' => $k, 'value' => ['stringValue' => $v]];
        $observed = (string) ($nowMs * 1_000_000);
        $records = [];
        foreach ($events as $e) {
            $r = [
                'timeUnixNano' => (string) ($e['ts'] * 1_000_000),
                'observedTimeUnixNano' => $observed,
                'severityNumber' => 9,
                'severityText' => 'INFO',
                'eventName' => 'tt.http.exchange',
            ];
            if ($e['trace'] !== null && preg_match('/^[0-9a-f]{32}$/D', $e['trace']) === 1) {
                $r['traceId'] = $e['trace'];
            }
            if ($e['span'] !== null && preg_match('/^[0-9a-f]{16}$/D', $e['span']) === 1) {
                $r['spanId'] = $e['span'];
            }
            $r['attributes'] = [$attr('tt.schema', 'tt.http.exchange/v1'), $attr('tt.policy.hash', $e['hash'])];
            $r['body'] = ['stringValue' => $e['json']];
            $records[] = $r;
        }
        return json_encode([
            'resourceLogs' => [[
                'resource' => ['attributes' => [
                    $attr('service.name', $serviceName),
                    $attr('tt.source.kind', Version::SOURCE_KIND),
                    $attr('tt.source.version', Version::SDK),
                    $attr('tt.source.id', $sourceId),
                ]],
                'scopeLogs' => [['scope' => ['name' => 'traffic-twin', 'version' => Version::SDK], 'logRecords' => $records]],
            ]],
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
