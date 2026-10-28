<?php

declare(strict_types=1);

namespace TrafficTwin\Sanitizer;

/**
 * Per-exchange state of the sanitizer: service and template choice (3), path (4), named parts
 * (8), bodies (9) and the discovery map (15).
 *
 * @internal use Sanitizer::run()
 */
final class Run
{
    private const MAX_SEGMENTS = 32;
    private const MAX_NAMES = 64;
    private const MAX_DISC = 4096;
    private const CT_RE = '/^[a-z0-9.+-]{1,64}\/[a-z0-9.+-]{1,64}$/D';

    private Policy $p;
    /** @var array<string, string>|null path => lowest value bytes */
    private ?array $disc;
    private bool $autoWords;
    private ?Service $svc = null;
    private ?Op $op = null;
    /** limits.max_array, raised for a response body with the introspection gate open (5.7.2). */
    private int $maxArray;
    // GraphQL (5.7, spec v1.14): $resp is set while the response is sanitized; $gqlSeen and $gqlNonIntro record the
    // request values with a graphql rule (introspection gate).
    private bool $resp = false;
    private bool $gqlSeen = false;
    private bool $gqlNonIntro = false;

    public function __construct(private Sanitizer $s, private Exchange $ex, ?int $now)
    {
        $this->p = $s->policy;
        $this->disc = $this->p->discoveryActive($now) ? [] : null;
        $this->autoWords = $this->p->autoWordsActive($now);
        $this->maxArray = $this->p->maxArray;
    }

    // --- header normalization (8.0) ----------------------------------------------------

    /**
     * @param list<array{0: string, 1: string}> $list
     * @return array{0: list<string>, 1: array<string, array{values: list<string>, origs: array<string, true>}>}
     */
    public static function normalizeHeaders(array $list): array
    {
        $order = [];
        $map = [];
        foreach ($list as [$name, $value]) {
            if ($name !== '' && $name[0] === ':') {
                continue;
            }
            $lower = Utf8::lower($name);
            $out = Formats::headerOutName($lower);
            if (!isset($map[$out])) {
                $map[$out] = ['values' => [], 'origs' => []];
                $order[] = $out;
            }
            $map[$out]['values'][] = trim($value, " \t");
            $map[$out]['origs'][$lower] = true;
        }
        return [$order, $map];
    }

    /** @param array{values: list<string>, origs: array<string, true>} $e */
    private static function joined(array $e, string $out): string
    {
        return count($e['values']) === 1 ? $e['values'][0] : implode($out === 'cookie' ? '; ' : ', ', $e['values']);
    }

    /** 8.1.5: `ct` from the normalized content-type value; null without the header. */
    private static function contentType(array $map): ?string
    {
        if (!isset($map['content-type'])) {
            return null;
        }
        $v = self::joined($map['content-type'], 'content-type');
        $semi = strpos($v, ';');
        if ($semi !== false) {
            $v = substr($v, 0, $semi);
        }
        $s = Utf8::lower(trim($v, " \t"));
        return preg_match(self::CT_RE, $s) === 1 ? $s : 'invalid';
    }

    private static function contentEncoding(array $map): ?string
    {
        if (!isset($map['content-encoding'])) {
            return null;
        }
        return Utf8::lower(trim(self::joined($map['content-encoding'], 'content-encoding'), " \t"));
    }

    // --- url base (3.1) ------------------------------------------------------------------

    /**
     * 3.1 normalization of `url_base` (with the IPv6 literals of spec v1.5). `host`, `port` ('' when absent or default)
     * and `ip6` (16 bytes of a bracketed literal, else null) feed the pattern of 3.5.
     *
     * @return array{invalid: bool, origin: string, hostport: string, host: string, port: string, ip6: list<int>|null}
     */
    public static function normalizeUrlBase(?string $u): array
    {
        $bad = ['invalid' => true, 'origin' => '', 'hostport' => '', 'host' => '', 'port' => '', 'ip6' => null];
        if ($u === null || preg_match('/^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.*)$/Ds', $u, $m) !== 1) {
            return $bad;
        }
        $scheme = Utf8::lower($m[1]);
        $rest = $m[2];
        if (preg_match('/[@\/?#]/', $rest) === 1) {
            return $bad;
        }
        $portText = null;
        $ip6 = null;
        if (str_starts_with($rest, '[')) {
            $end = strpos($rest, ']');
            if ($end === false) {
                return $bad;
            }
            $inner = Utf8::lower(substr($rest, 1, $end - 1));
            $after = substr($rest, $end + 1);
            $ip6 = HostPattern::parseIpv6($inner);
            if ($ip6 === null) {
                return $bad;
            }
            if (str_starts_with($after, ':')) {
                $portText = substr($after, 1);
            } elseif ($after !== '') {
                return $bad;
            }
            $host = '[' . $inner . ']';
        } else {
            $host = $rest;
            $c = strpos($rest, ':');
            if ($c !== false) {
                $host = substr($rest, 0, $c);
                $portText = substr($rest, $c + 1);
            }
            $host = Utf8::lower($host);
            if (preg_match('/^[a-z0-9.-]{1,253}$/D', $host) !== 1) {
                return $bad;
            }
        }
        $port = '';
        if ($portText !== null) {
            if (preg_match('/^[0-9]{1,5}$/D', $portText) !== 1) {
                return $bad;
            }
            $pn = (int) $portText;
            if ($pn < 1 || $pn > 65535) {
                return $bad;
            }
            $port = (string) $pn;
            if (($scheme === 'http' && $pn === 80) || ($scheme === 'https' && $pn === 443)) {
                $port = '';
            }
        }
        $hostport = $port !== '' ? $host . ':' . $port : $host;
        return ['invalid' => false, 'origin' => $scheme . '://' . $hostport, 'hostport' => $hostport, 'host' => $host, 'port' => $port, 'ip6' => $ip6];
    }

    // --- build -----------------------------------------------------------------------------

    public function build(string $by, ?string $subject): Obj
    {
        $ex = $this->ex;
        $p = $this->p;
        $method = Utf8::upper($ex->method);
        if (preg_match('/^[A-Z]{1,16}$/D', $method) !== 1) {
            $method = 'OTHER';
        }

        // 4.1 decomposition
        $segs = [];
        $truncated = false;
        foreach (explode('/', $ex->rawPath) as $raw) {
            if ($raw === '') {
                continue;
            }
            if (count($segs) === self::MAX_SEGMENTS) {
                $truncated = true;
                break;
            }
            $segs[] = Utf8::decode(Utf8::pctDecode($raw, false));
        }

        // 3.1 service
        $baseCount = 0;
        if ($ex->dir === 'inbound') {
            $service = $ex->serviceName ?? '';
            $this->svc = $p->inbound[$service] ?? null;
        } else {
            $ub = self::normalizeUrlBase($ex->urlBase);
            $best = null;
            if (!$ub['invalid']) {
                foreach ($p->services as $svc) {
                    if ($svc->base === null || $svc->base[0] !== $ub['origin']) {
                        continue;
                    }
                    $bs = $svc->base[1];
                    if (count($bs) > count($segs)) {
                        continue;
                    }
                    $ok = true;
                    foreach ($bs as $i => $b) {
                        if ($segs[$i] !== $b) {
                            $ok = false;
                            break;
                        }
                    }
                    if ($ok && ($best === null || count($bs) > count($best->base[1]))) {
                        $best = $svc;
                    }
                }
            }
            if ($best !== null) {
                $this->svc = $best;
                $service = $best->name;
                $baseCount = count($best->base[1]);
            } elseif ($ub['invalid']) {
                $service = 'host:invalid';
            } elseif (isset($p->hostsAllow[$ub['hostport']])) {
                $service = 'host:' . $ub['hostport'];
            } elseif ($p->hostsAuto || $this->disc !== null) {
                // 3.1, 3.5 (v1.5): the pattern, never the host; also in discovery mode (15)
                $pat = HostPattern::pattern($ub['host'], $ub['port'], $ub['ip6']);
                $service = $pat !== null ? 'host:' . $pat : 'host:invalid';
            } else {
                $service = 'host:unlisted';
            }
        }

        // 3.3 template
        $opSegs = array_slice($segs, $baseCount);
        $routeSource = 'raw';
        if ($this->svc !== null && $method !== 'OTHER' && !$truncated) {
            if ($ex->dir === 'inbound' && $ex->frameworkRoute !== null && $ex->framework !== null) {
                $fr = Frameworks::normalize($ex->frameworkRoute, $ex->framework);
                if ($fr !== null && count($fr) === count($opSegs)) {
                    foreach ($this->svc->ops as $op) {
                        if ($op->method !== $method || count($op->segs) !== count($fr)) {
                            continue;
                        }
                        $same = true;
                        foreach ($op->segs as $i => $t) {
                            if ($t[0] !== null ? $fr[$i][0] !== $t[0] : $fr[$i][1] === null) {
                                $same = false;
                                break;
                            }
                        }
                        if ($same) {
                            $this->op = $op;
                            $routeSource = 'framework';
                            break;
                        }
                    }
                }
            }
            if ($this->op === null) {
                $best = null;
                foreach ($this->svc->ops as $op) {
                    if ($op->method !== $method || count($op->segs) !== count($opSegs)) {
                        continue;
                    }
                    $ok = true;
                    foreach ($op->segs as $i => $t) {
                        $sd = $opSegs[$i];
                        if ($t[0] !== null ? $sd !== $t[0] : $sd === null) {
                            $ok = false;
                            break;
                        }
                    }
                    if (!$ok) {
                        continue;
                    }
                    if ($best === null || $op->literals > $best->literals || ($op->literals === $best->literals && strcmp($op->key, $best->key) < 0)) {
                        $best = $op;
                    }
                }
                if ($best !== null) {
                    $this->op = $best;
                    $routeSource = 'policy';
                }
            }
        }

        // 4.2 path
        $outSegs = [];
        foreach ($segs as $i => $dec) {
            if ($dec === null) {
                $outSegs[] = '{drop:bytes}';
                continue;
            }
            if ($i < $baseCount) {
                $outSegs[] = $dec;
                continue;
            }
            if ($this->op !== null) {
                $t = $this->op->segs[$i - $baseCount];
                if ($t[0] !== null) {
                    $outSegs[] = $t[0];
                    continue;
                }
                $action = $this->op->request?->path[$t[1]] ?? null;
                $outSegs[] = '{' . $this->strAction($dec, $action, true, 'req.path.' . $i) . '}';
                continue;
            }
            if (isset($p->allow[$dec]) || ($this->autoWords && preg_match(Formats::AUTO_WORD, $dec) === 1 && strlen($dec) <= 40)) {
                $outSegs[] = $dec;
                continue;
            }
            $outSegs[] = '{' . $this->strAction($dec, null, true, 'req.path.' . $i) . '}';
        }
        if ($truncated) {
            $outSegs[] = '{trunc}';
        }
        $path = '/' . implode('/', $outSegs);
        $opKey = $this->op !== null ? $this->op->key : $method . ' /' . implode('/', array_slice($outSegs, $baseCount));

        $out = new Obj([
            'service' => $service,
            'op' => $opKey,
            'route_source' => $routeSource,
            'sampled_by' => $by,
        ]);

        // request
        $req = new Obj(['path' => $path]);
        $reqGroups = $this->groups('req', null);
        if ($ex->rawQuery !== null) {
            $q = $this->namedMap(self::parseUrlencoded($ex->rawQuery), $reqGroups, 'query', 'req.query');
            if ($q->m !== []) {
                $req->m['query'] = $q;
            }
        }
        [$order, $map] = self::normalizeHeaders($ex->reqHeaders);
        $this->side($req, 'req', $order, $map, $reqGroups, $ex->reqBody, $ex->reqBodyTotal, $ex->reqBodyConsumed, $ex->reqBodyDecoded);
        $out->m['req'] = $req;

        $this->resp = true;
        if ($ex->netError === null) {
            $resp = new Obj();
            $respGroups = $this->groups('resp', $ex->status);
            [$order, $map] = self::normalizeHeaders($ex->respHeaders);
            $this->side($resp, 'resp', $order, $map, $respGroups, $ex->respBody, $ex->respBodyTotal, $ex->respBodyConsumed, $ex->respBodyDecoded);
            $out->m['resp'] = $resp;
        }
        if ($subject !== null) {
            $out->m['subject'] = $this->s->token('subject', $subject);
        }
        if ($this->disc !== null && $this->disc !== []) {
            $keys = array_map('strval', array_keys($this->disc));
            sort($keys, SORT_STRING);
            $d = [];
            foreach (array_slice($keys, 0, self::MAX_DISC) as $k) {
                $mac = $this->s->mac('discovery', $k . "\0" . $this->disc[$k]);
                $d[$k] = 'tkd:' . Utf8::b64url(substr($mac, 0, 4));
            }
            $out->m['disc'] = new Obj($d);
        }
        return $out;
    }

    /** @return list<?Part> */
    private function groups(string $side, ?int $status): array
    {
        $err = $side === 'resp' && $status !== null && $status >= 400;
        $p = $this->p;
        if ($side === 'req') {
            return [$this->op?->request, null, null, $this->svc?->request, $p->globalRequest];
        }
        return [$this->op?->response, $err ? $this->svc?->errors : null, $err ? $p->globalErrors : null, $this->svc?->response, $p->globalResponse];
    }

    /**
     * @param list<string> $order
     * @param array<string, array{values: list<string>, origs: array<string, true>}> $map
     * @param list<?Part> $groups
     * @param int|string|null $total
     */
    private function side(Obj $dst, string $side, array $order, array $map, array $groups, string $body, int|string|null $total, ?bool $consumed, ?bool $decoded): void
    {
        // 8.1 headers (cookie / set-cookie never appear)
        $hdr = [];
        foreach ($order as $name) {
            if ($name === 'cookie' || $name === 'set-cookie') {
                continue;
            }
            $e = $map[$name];
            $hdr[] = [
                'orig' => count($e['origs']) === 1 ? (string) array_key_first($e['origs']) : null,
                'out' => $name,
                'value' => self::joined($e, $name),
                'noEq' => false,
            ];
        }
        $hm = $this->namedMap($hdr, $groups, 'headers', $side . '.headers');
        if ($hm->m !== []) {
            $dst->m['headers'] = $hm;
        }

        // 8.2 cookies
        $ck = [];
        if ($side === 'req') {
            if (isset($map['cookie'])) {
                foreach (explode(';', self::joined($map['cookie'], 'cookie')) as $part) {
                    self::cookiePart(trim($part, " \t"), $ck);
                }
            }
        } elseif (isset($map['set-cookie'])) {
            foreach ($map['set-cookie']['values'] as $v) {
                $semi = strpos($v, ';');
                self::cookiePart(trim($semi !== false ? substr($v, 0, $semi) : $v, " \t"), $ck);
            }
        }
        $cm = $this->namedMap($ck, $groups, 'cookies', $side . '.cookies');
        if ($cm->m !== []) {
            $dst->m['cookies'] = $cm;
        }

        $ct = self::contentType($map);
        if ($ct !== null) {
            $dst->m['ct'] = $ct;
        }
        $kind = $this->treatment($ct);
        $ctRaw = isset($map['content-type']) ? self::joined($map['content-type'], 'content-type') : null;
        if ($side === 'req' && $kind === 'xml') {
            // 22.2 point 11: SOAPAction header (SOAP 1.1), else the action parameter of the content-type (SOAP 1.2)
            if (isset($map['soapaction'])) {
                $sa = Utf8::decode(self::joined($map['soapaction'], 'soapaction')) ?? '{*}';
            } else {
                $sa = Bodies::mediaParams($ctRaw)['action'] ?? null;
            }
            if ($sa !== null) {
                $name = $sa === '{*}' ? '{*}' : Bodies::soapActionName($sa);
                if ($name !== null) {
                    $dst->m['soap_action'] = $name;
                }
            }
        }
        $saved = $this->maxArray;
        if ($this->resp && $this->gqlGate()) {
            // 5.7.2: an introspection result keeps its arrays.
            $this->maxArray = max($saved, GraphQL::INTROSPECTION_MAX_ARRAY);
        }
        $this->body($dst, $side, $ct, $kind, $ctRaw, self::contentEncoding($map), $groups, $body, $total, $consumed, $decoded);
        $this->maxArray = $saved;
        if (array_key_exists('body', $dst->m) && ($kind === 'xml' || $kind === 'multipart') && !isset($dst->m['fmt'])) {
            $dst->m['fmt'] = $kind; // 22.1: whenever a body leaves under the XML or multipart treatment
        }
    }

    /** 9.1 and 22.1: json, form, xml, multipart or null (not parsed). */
    private function treatment(?string $ct): ?string
    {
        if ($ct === null) {
            return null;
        }
        if ($ct === 'application/json' || str_ends_with($ct, '+json')) {
            return 'json';
        }
        if ($ct === 'application/x-www-form-urlencoded') {
            return 'form';
        }
        if ($this->p->xml && ($ct === 'application/xml' || $ct === 'text/xml' || str_ends_with($ct, '+xml'))) {
            return 'xml';
        }
        if ($this->p->multipart && $ct === 'multipart/form-data') {
            return 'multipart';
        }
        return null;
    }

    /** @param list<array{orig: ?string, out: string, value: string, noEq: bool}> $out */
    private static function cookiePart(string $piece, array &$out): void
    {
        $eq = strpos($piece, '=');
        if ($eq === false) {
            return;
        }
        $name = Utf8::decode(substr($piece, 0, $eq));
        $out[] = [
            'orig' => $name,
            'out' => $name !== null && Formats::isLiteralName($name) ? $name : '{*}',
            'value' => substr($piece, $eq + 1),
            'noEq' => false,
        ];
    }

    /**
     * 8.3 / 9.1: query string or form body into named entries.
     *
     * @return list<array{orig: ?string, out: string, value: string, noEq: bool}>
     */
    public static function parseUrlencoded(string $raw): array
    {
        $out = [];
        foreach (explode('&', $raw) as $part) {
            if ($part === '') {
                continue;
            }
            $eq = strpos($part, '=');
            if ($eq === false) {
                $out[] = ['orig' => null, 'out' => '{*}', 'value' => Utf8::pctDecode($part, true), 'noEq' => true];
                continue;
            }
            $name = Utf8::decode(Utf8::pctDecode(substr($part, 0, $eq), true));
            $out[] = [
                'orig' => $name,
                'out' => $name !== null && Formats::isLiteralName($name) ? $name : '{*}',
                'value' => Utf8::pctDecode(substr($part, $eq + 1), true),
                'noEq' => false,
            ];
        }
        return $out;
    }

    // --- body (9) ----------------------------------------------------------------------------

    /**
     * 9.0, 9.1 and 20 (spec v1.19): size, body and, for XML, fmt and xmlns.
     *
     * @param ?string $ct normalized media type (8.4)
     * @param ?string $kind treatment of 9.1 (json, form, xml, multipart) or null
     * @param ?string $ctRaw normalized content-type value (for the multipart boundary)
     * @param list<?Part> $groups
     * @param int|string|null $total
     */
    private function body(Obj $dst, string $side, ?string $ct, ?string $kind, ?string $ctRaw, ?string $ce, array $groups, string $data, int|string|null $total, ?bool $consumed, ?bool $decoded): void
    {
        $p = $this->p;
        $max = $p->maxBodyBytes;
        $tot = $total ?? strlen($data);
        if ($consumed === false || $tot === 'unknown') {
            $dst->m['body'] = 'trunc:size';
            $dst->m['size'] = 'lmax';
            return;
        }
        if ($tot === 0) {
            $dst->m['size'] = 'l8';
            return;
        }
        if ($ce !== null && $ce !== 'identity') {
            if ($ce !== 'gzip' && $ce !== 'x-gzip' && $ce !== 'deflate') {
                $dst->m['body'] = 'drop:bytes';
                return;
            }
            if ($decoded !== true) {
                // 22.5: the decoding cap includes the large-body limit
                $r = self::decodeBody($data, $ce === 'deflate', max($max, $p->maxLargeBodyBytes) + 1);
                if ($r === 'cap') {
                    $dst->m['body'] = 'trunc:size';
                    $dst->m['size'] = 'lmax';
                    return;
                }
                if ($r === null) {
                    $dst->m['body'] = 'drop:bytes';
                    return;
                }
                $data = $r;
                $tot = strlen($data);
            }
        }
        /** @var int $tot */
        $large = false;
        if ($tot > $max) {
            if ($kind === null || $tot > $p->maxLargeBodyBytes) {
                $dst->m['body'] = 'trunc:size';
                $dst->m['size'] = 'lmax';
                return;
            }
            $large = true; // 22.5
        }
        $dst->m['size'] = Utf8::lenClass($tot);
        if ($kind !== null && strlen($data) < $tot) {
            $dst->m['body'] = 'trunc:size'; // 9.1: only a prefix of a parsed body, it cannot be analysed
            return;
        }
        if ($ct === 'application/graphql' && strlen($data) === $tot) {
            // 9.1 (v1.14): with a graphql rule winning for $, the whole body is one string leaf at $.
            $a = self::rootRule($groups);
            if ($a !== null && $a->action === 'graphql') {
                if (!Utf8::valid($data)) {
                    $this->gqlUnusable($a);
                    $dst->m['body'] = 'drop:str:invalid';
                    return;
                }
                $dst->m['body'] = $this->strAction($data, $a, false, null);
                return;
            }
        }
        $dpath = $this->disc !== null ? $side . '.body' : null;
        switch ($kind) {
            case 'json':
                try {
                    $root = Json::parse($data, $p->maxDepth);
                } catch (JsonError) {
                    $dst->m['body'] = 'trunc:invalid-json';
                    return;
                }
                $dst->m['body'] = $this->walk($root, 0, self::alive($groups), $dpath, false, $large);
                return;
            case 'form':
                $dst->m['body'] = $this->namedMap(self::parseUrlencoded($data), $groups, 'form', $side . '.body');
                return;
            case 'xml':
                try {
                    $root = XmlParser::parse($data);
                } catch (BodyError) {
                    $dst->m['body'] = 'trunc:invalid-xml';
                    return;
                }
                [$tree, $entries, $fmt] = Bodies::xmlTree($root, $p->maxDepth);
                $dst->m['fmt'] = $fmt;
                $dst->m['body'] = $this->walk($tree, 0, self::alive($groups), $dpath, true, $large);
                if ($entries !== []) {
                    $xmlns = array_slice($entries, 0, self::MAX_NAMES, true);
                    if (count($entries) > self::MAX_NAMES) {
                        $xmlns['{trunc}'] = 'trunc:keys:' . Utf8::lenClass(count($entries));
                    }
                    $dst->m['xmlns'] = new Obj($xmlns);
                }
                return;
            case 'multipart':
                try {
                    $parts = Bodies::parseMultipart($data, Bodies::mediaParams($ctRaw)['boundary'] ?? null);
                } catch (BodyError) {
                    $dst->m['body'] = 'trunc:invalid-multipart';
                    return;
                }
                $named = [];
                foreach ($parts as $part) {
                    $named[] = [
                        'orig' => $part['name'],
                        'out' => Formats::isLiteralName($part['name']) ? $part['name'] : '{*}',
                        'value' => $part['content'],
                        'noEq' => false,
                        // 22.3 point 5: a file part always leaves as its shape, whatever the rule
                        'tok' => $part['file'] ? Bodies::fileToken($part['content'], $part['ct']) : null,
                    ];
                }
                $dst->m['body'] = $this->namedMap($named, $groups, 'form', $side . '.body');
                return;
            default:
                $dst->m['body'] = 'drop:bytes:' . Utf8::lenClass($tot);
        }
    }

    /**
     * @param list<?Part> $groups
     * @return list<array<int, BodyRule>>
     */
    private static function alive(array $groups): array
    {
        $alive = [];
        foreach ($groups as $g) {
            $alive[] = $g?->body ?? [];
        }
        return $alive;
    }

    /**
     * Action of the rule that wins for the body path `$` (5.0): the first group with one.
     *
     * @param list<?Part> $groups
     */
    private static function rootRule(array $groups): ?Action
    {
        foreach ($groups as $g) {
            foreach ($g?->body ?? [] as $r) {
                if ($r->steps === []) {
                    return $r->action;
                }
            }
        }
        return null;
    }

    /**
     * 9.0 decoding, one level, with an output cap (A-GZIP-STRICT): returns the decoded bytes,
     * 'cap' when the output reaches $cap bytes, or null on any error (truncated stream, bytes
     * after the end of the stream, corrupt data, ext-zlib missing).
     */
    public static function decodeBody(string $data, bool $zlibFormat, int $cap): string|null
    {
        if (!function_exists('inflate_init')) {
            return null;
        }
        $ctx = @inflate_init($zlibFormat ? ZLIB_ENCODING_DEFLATE : ZLIB_ENCODING_GZIP);
        if ($ctx === false) {
            return null;
        }
        $out = '';
        $len = strlen($data);
        for ($off = 0; $off < $len; $off += 512) {
            $chunk = @inflate_add($ctx, substr($data, $off, 512), ZLIB_SYNC_FLUSH);
            if ($chunk === false) {
                return null;
            }
            $out .= $chunk;
            if (strlen($out) >= $cap) {
                return 'cap';
            }
            if (inflate_get_status($ctx) === ZLIB_STREAM_END) {
                break;
            }
        }
        if (inflate_get_status($ctx) !== ZLIB_STREAM_END || inflate_get_read_len($ctx) !== $len) {
            return null;
        }
        return strlen($out) >= $cap ? 'cap' : $out;
    }

    /**
     * @param list<array<int, array>> $alive rules still matching, one list per precedence group
     */
    private function walk(object $node, int $pos, array $alive, ?string $dpath, bool $xml = false, bool $large = false, int $arrLevel = 0): mixed
    {
        if ($node instanceof JObj || $node instanceof JArr || $node instanceof JDeep) {
            if ($pos + 1 > $this->p->maxDepth) {
                return 'trunc:depth';
            }
            // 5.0 explicit drop on a container
            foreach ($alive as $g => $rs) {
                $has = false;
                foreach ($rs as $r) {
                    if (count($r->steps) === $pos && $r->action->action === 'drop') {
                        $has = true;
                        break;
                    }
                }
                if (!$has) {
                    continue;
                }
                $reach = false;
                for ($h = 0; $h <= $g && !$reach; $h++) {
                    foreach ($alive[$h] as $r) {
                        if (count($r->steps) > $pos) {
                            $reach = true;
                            break;
                        }
                    }
                }
                if (!$reach) {
                    if ($node instanceof JArr) {
                        return 'drop:arr:' . Utf8::lenClass(count($node->a));
                    }
                    return 'drop:obj:' . Utf8::lenClass(count(self::dedupe($node->m)));
                }
                break;
            }
            $anyAlive = false;
            foreach ($alive as $rs) {
                if ($rs !== []) {
                    $anyAlive = true;
                    break;
                }
            }
            $lim = $this->p;
            if ($node instanceof JArr) {
                $res = [];
                // 22.5: in a large body, arrays keep large_array elements, or large_nested_array below another array
                $cap = $large ? ($arrLevel === 0 ? $lim->largeArray : $lim->largeNestedArray) : $this->maxArray;
                $n = min(count($node->a), $cap);
                $child = $alive;
                if ($anyAlive) {
                    $child = [];
                    foreach ($alive as $rs) {
                        $child[] = array_values(array_filter($rs, static fn (BodyRule $r): bool => count($r->steps) > $pos && $r->steps[$pos][0] === BodyRule::IDX));
                    }
                }
                for ($i = 0; $i < $n; $i++) {
                    $res[] = $this->walk($node->a[$i], $pos + 1, $child, $dpath === null ? null : $dpath . '[*]', $xml, $large, $arrLevel + 1);
                }
                if (count($node->a) > $cap) {
                    $res[] = 'trunc:n:' . Utf8::lenClass(count($node->a));
                }
                return $res;
            }
            $members = self::dedupe($node->m);
            $res = [];
            $dyn = [];
            $kept = count($members) > $lim->maxKeys ? array_slice($members, 0, $lim->maxKeys) : $members;
            foreach ($kept as [$k, $v]) {
                $literal = !$k->bad && ($xml ? self::xmlKeyLiteral($k->s) : Formats::isLiteralName($k->s));
                $child = $alive;
                if ($anyAlive) {
                    $child = [];
                    foreach ($alive as $rs) {
                        $child[] = array_values(array_filter($rs, static function (BodyRule $r) use ($pos, $k): bool {
                            if (count($r->steps) <= $pos) {
                                return false;
                            }
                            $st = $r->steps[$pos];
                            return $st[0] === BodyRule::ANY || ($st[0] === BodyRule::NAME && !$k->bad && $st[1] === $k->s);
                        }));
                    }
                }
                $o = $this->walk($v, $pos + 1, $child, $dpath === null ? null : $dpath . ($literal ? '.' . $k->s : '.*'), $xml, $large, $arrLevel);
                if ($literal) {
                    $res[$k->s] = $o;
                } else {
                    $dyn[] = $o;
                }
            }
            if ($dyn !== []) {
                $keyed = [];
                foreach ($dyn as $o) {
                    $keyed[] = [Json::write($o), $o];
                }
                usort($keyed, static fn (array $a, array $b): int => strcmp($a[0], $b[0]));
                $res['{*}'] = array_map(static fn (array $x): mixed => $x[1], $keyed);
            }
            if (count($members) > $lim->maxKeys) {
                $res['{trunc}'] = 'trunc:keys:' . Utf8::lenClass(count($members));
            }
            return new Obj($res);
        }
        // leaf
        foreach ($alive as $rs) {
            $best = null;
            foreach ($rs as $r) {
                if (count($r->steps) !== $pos) {
                    continue;
                }
                if ($best === null || $r->names > $best->names || ($r->names === $best->names && strcmp($r->path, $best->path) < 0)) {
                    $best = $r;
                }
            }
            if ($best !== null) {
                return $this->leaf($node, $best->action, null);
            }
        }
        return $this->leaf($node, null, $dpath);
    }

    /** 22.2 point 8: keys of an XML tree; "#text" is literal, "@" + name follows the name rule on the name. */
    private static function xmlKeyLiteral(string $k): bool
    {
        if ($k === '#text') {
            return true;
        }
        return Formats::isLiteralName(str_starts_with($k, '@') ? substr($k, 1) : $k);
    }

    private function leaf(object $node, ?Action $a, ?string $dpath): mixed
    {
        if (!$node instanceof JStr || $node->bad) {
            $this->gqlUnusable($a); // graphql applies to valid strings only
        }
        if ($node instanceof JNull) {
            if ($a !== null && $a->action === 'keep') {
                return null;
            }
            if ($a === null && $dpath !== null) {
                $this->discAdd($dpath, 'null');
            }
            return 'drop:null';
        }
        if ($node instanceof JBool) {
            if ($a !== null && $a->action === 'keep') {
                return $node->v;
            }
            if ($a === null && $dpath !== null) {
                $this->discAdd($dpath, $node->v ? 'true' : 'false');
            }
            return 'drop:bool';
        }
        if ($node instanceof JNum) {
            $within = Json::lexemeWithinLimits($node->lex);
            $shape = Json::isIntLexeme($node->lex) ? 'drop:int' : 'drop:dec';
            if ($a === null) {
                if ($dpath !== null && $within) {
                    $this->discAdd($dpath, Json::canonicalNumber($node->lex));
                }
                return $shape;
            }
            if (!$within) {
                return $shape;
            }
            if ($a->action === 'keep') {
                return new CNum(Json::canonicalNumber($node->lex));
            }
            if ($a->action === 'hmac') {
                return $this->s->token($a->domain ?? 'id', Json::canonicalNumber($node->lex));
            }
            if ($a->action === 'bucket' && $a->kind === 'num') {
                return Buckets::num($node->lex, $a);
            }
            return $shape;
        }
        if ($node instanceof JStr) {
            if ($node->bad) {
                return 'drop:str:invalid';
            }
            return $this->strAction($node->s, $a, false, $dpath);
        }
        return 'drop:null';
    }

    /** Action on a string value (named parts, path segments, JSON strings). null = not UTF-8. */
    private function strAction(?string $s, ?Action $a, bool $pathParam, ?string $dpath): string
    {
        if ($s === null) {
            $this->gqlUnusable($a);
            return 'drop:bytes';
        }
        if ($a === null) {
            if ($dpath !== null && $this->disc !== null) {
                $this->discAdd($dpath, $s);
            }
            return $this->shape($s);
        }
        switch ($a->action) {
            case 'keep':
                if (strlen($s) <= $this->p->keepMaxBytes && (!$pathParam || preg_match(Formats::PATH_TOKEN, $s) === 1)) {
                    return 'keep:' . $s;
                }
                return $this->shape($s);
            case 'code':
                // 5.6 (spec v1.11): only a code-shaped string within keep_max_bytes leaves.
                // v1.19: the shape alnum allows digits and dots, 1 to 16 bytes.
                if (preg_match($a->shape === 'alnum' ? Formats::CODE_ALNUM : Formats::CODE, $s) === 1 && strlen($s) <= $this->p->keepMaxBytes) {
                    return 'keep:' . $s;
                }
                return $this->shape($s);
            case 'graphql':
                return $this->graphql($s) ?? $this->shape($s);
            case 'hmac':
                return $this->s->token($a->domain ?? 'id', $s);
            case 'bucket':
                if ($a->kind === 'time' && (!$pathParam || preg_match(Formats::PATH_TOKEN, $s) === 1)) {
                    return Buckets::time($s, $a->unit ?? '') ?? $this->shape($s);
                }
                return $this->shape($s);
            default:
                return $this->shape($s);
        }
    }

    /** 6.2 for a valid UTF-8 string, with the document shape of 22.4 when bodies.docs is on. */
    private function shape(string $s): string
    {
        if ($this->p->docs && Formats::detect($s) === null) {
            $d = Bodies::base64Doc($s);
            if ($d !== null) {
                return $d;
            }
        }
        return Formats::strShape($s);
    }

    /**
     * 5.7 graphql on a valid string; null means the drop form. Request: gql: and the shape of an executable
     * document; every request value with a graphql rule is recorded for the gate. Response: with the gate open, a
     * GraphQL name passing the name rule leaves as gql: and the name.
     */
    private function graphql(string $s): ?string
    {
        if (!$this->resp) {
            $this->gqlSeen = true;
            $r = GraphQL::shape($s);
            if ($r === null || !$r[1]) {
                $this->gqlNonIntro = true;
            }
            return $r !== null ? 'gql:' . $r[0] : null;
        }
        if ($this->gqlGate() && GraphQL::nameSafe($s)) {
            return 'gql:' . $s;
        }
        return null;
    }

    /** 5.7.2: the introspection gate is open. */
    private function gqlGate(): bool
    {
        return $this->gqlSeen && !$this->gqlNonIntro;
    }

    /** A request value under a graphql rule without usable text (not a string, not UTF-8): closes the gate. */
    private function gqlUnusable(?Action $a): void
    {
        if ($a !== null && $a->action === 'graphql' && !$this->resp) {
            $this->gqlSeen = true;
            $this->gqlNonIntro = true;
        }
    }

    private function discAdd(string $path, string $value): void
    {
        if ($this->disc === null) {
            return;
        }
        if (!isset($this->disc[$path]) || strcmp($value, $this->disc[$path]) < 0) {
            $this->disc[$path] = $value;
        }
    }

    // --- named parts (8.1-8.3, 9.1 form) ---------------------------------------------------------

    /** @param list<?Part> $groups */
    private function namedRule(array $groups, string $section, ?string $name): ?Action
    {
        if ($name === null) {
            return null;
        }
        foreach ($groups as $g) {
            if ($g === null) {
                continue;
            }
            if ($section === 'form') {
                $best = null;
                foreach ($g->body as $r) {
                    if (count($r->steps) !== 1) {
                        continue;
                    }
                    $st = $r->steps[0];
                    if (!($st[0] === BodyRule::ANY || ($st[0] === BodyRule::NAME && $st[1] === $name))) {
                        continue;
                    }
                    if ($best === null || $r->names > $best->names || ($r->names === $best->names && strcmp($r->path, $best->path) < 0)) {
                        $best = $r;
                    }
                }
                if ($best !== null) {
                    return $best->action;
                }
                continue;
            }
            $a = $g->{$section}[$name] ?? null;
            if ($a !== null) {
                return $a;
            }
        }
        return null;
    }

    /**
     * @param list<array{orig: ?string, out: string, value: string, noEq: bool}> $entries
     * @param list<?Part> $groups
     */
    private function namedMap(array $entries, array $groups, string $section, string $disc): Obj
    {
        $order = [];
        $byName = [];
        foreach ($entries as $e) {
            if (!isset($byName[$e['out']])) {
                $byName[$e['out']] = [];
                $order[] = $e['out'];
            }
            $byName[$e['out']][] = $e;
        }
        $res = [];
        // After 8.0 every header name has exactly one value: max_array applies to cookies,
        // query and form values only (8.2, 8.3).
        $maxArr = $section === 'headers' ? PHP_INT_MAX : $this->maxArray;
        foreach (array_slice($order, 0, self::MAX_NAMES) as $name) {
            $list = $byName[$name];
            $vals = [];
            $dpath = $this->disc !== null ? $disc . '.' . ($section === 'form' && $name === '{*}' ? '*' : $name) : null;
            $m = min(count($list), $maxArr);
            for ($i = 0; $i < $m; $i++) {
                $e = $list[$i];
                if (isset($e['tok'])) {
                    $vals[] = $e['tok']; // a ready token (multipart file part, 22.3)
                    continue;
                }
                // Parts without "=" have no name: always drop (no rule can select them).
                $a = $e['noEq'] ? null : $this->namedRule($groups, $section, $e['orig']);
                $vals[] = $this->strAction(Utf8::decode($e['value']), $a, false, $dpath);
            }
            if (count($list) > $maxArr) {
                $vals[] = 'trunc:n:' . Utf8::lenClass(count($list));
            }
            $res[$name] = $vals;
        }
        if (count($order) > self::MAX_NAMES) {
            $res['{trunc}'] = ['trunc:keys:' . Utf8::lenClass(count($order))];
        }
        return new Obj($res);
    }

    /**
     * @param list<array{0: JStr, 1: object}> $m
     * @return list<array{0: JStr, 1: object}>
     */
    private static function dedupe(array $m): array
    {
        if (count($m) < 2) {
            return $m;
        }
        $last = [];
        foreach ($m as $i => [$k]) {
            $last[$k->s] = $i;
        }
        if (count($last) === count($m)) {
            return $m;
        }
        $r = [];
        foreach ($m as $i => $pair) {
            if ($last[$pair[0]->s] === $i) {
                $r[] = $pair;
            }
        }
        return $r;
    }
}
