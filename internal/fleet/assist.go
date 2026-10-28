package fleet

import (
	"regexp"
	"strings"

	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/policy"
)

// Policy assistant (ARCHITECTURE 3.4 step 5, admin-api policyAssistant).
// It proposes an action per field seen in discovery mode, computed only
// from shapes and distinct-count sketches: no value ever reaches it.
// Proposals are never applied: a person writes the policy, which then goes
// through the normal approval flow.

// SetDiscoverySource installs the discovery sketches provider.
func (f *Fleet) SetDiscoverySource(d DiscoverySource) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discovery = d
}

// Suggestion is one proposal of the policy assistant.
type Suggestion struct {
	Service          string `json:"service"`
	Op               string `json:"op"`
	Part             string `json:"part"`  // request | response
	Path             string `json:"path"`  // "$.status", "query.orderId", "headers.x-tenant", "path.1"
	Shape            string `json:"shape"` // observed shape, never a value
	Observed         int64  `json:"observed"`
	DistinctEstimate int    `json:"distinct_estimate"`
	Suggestion       string `json:"suggestion"` // keep | hmac(<domain>) | bucket(...) | drop
	Reason           string `json:"reason"`
	// ReasonCode names the heuristic (the UI translates it): dynamic_name,
	// credential, trace, personal_format, personal_name, few, flag, time,
	// path_id, id, amount, quantity, number, enum_name, path_word, enum, free.
	ReasonCode string `json:"reason_code"`
}

// Thresholds of the heuristics.
const (
	assistMinObserved = 20 // below: not enough evidence, stay drop
	assistEnumMax     = 20 // distinct values for an enum
	assistIDRatio     = 0.5
)

var (
	// Field names that carry personal data or free text: they stay drop
	// whatever their shape (matched on the last name segment, lower case).
	rePersonalName = regexp.MustCompile(`(^|[_-])(e?mail|phone|mobile|tel|fax|name|firstname|lastname|surname|fullname|username|user|login|address|addr|street|city|zip|postcode|postal|birth|dob|birthday|age|gender|iban|card|pan|cvv|ssn|tax|vat|fiscal|passport|password|passwd|secret|token|note|notes|comment|comments|description|desc|message|msg|text|body|title|subject|ip|lat|lon|lng|location|geo)([_-]|$)`)
	reCamel        = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	reDomainClean  = regexp.MustCompile(`[^a-z0-9_-]`)
)

// personalShapes are recognized formats that identify people or carry
// credentials.
var personalShapes = map[string]bool{"email": true, "phone": true, "jwt": true, "url": true, "ipv4": true}

func lastName(path string) string {
	p := strings.TrimSuffix(path, "[*]")
	if i := strings.LastIndexAny(p, ".["); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, "]")
}

func normName(n string) string {
	return strings.ToLower(reCamel.ReplaceAllString(n, "${1}_${2}"))
}

// idSuffixes are the name endings of identifiers (on normName).
var idSuffixes = []string{"_id", "-id", "_ids", "_uuid", "_ref", "_key", "_code", "_no", "_number"}

// idName reports whether a field name says it is an identifier: id, uuid,
// orderId, shipment_id, order_ref...
func idName(name string) bool {
	n := normName(name)
	if n == "id" || n == "uuid" || n == "ids" {
		return true
	}
	for _, suf := range idSuffixes {
		if strings.HasSuffix(n, suf) && len(n) > len(suf) {
			return true
		}
	}
	return false
}

// resourceOf names the resource of an operation after its last path word:
// "POST /orders" -> order, "GET /customers/{id}/orders" -> order.
func resourceOf(op string) string {
	_, segs, ok := policy.ParseOpKey(op)
	if !ok {
		return ""
	}
	for i := len(segs) - 1; i >= 0; i-- {
		if l := segs[i].Literal; l != "" && !reVersion.MatchString(l) {
			return singular(strings.ToLower(l))
		}
	}
	return ""
}

var reVersion = regexp.MustCompile(`^v[0-9]{1,3}$`)

// hmacDomain proposes an HMAC domain from a field name: orderId → order,
// shipment_id → shipment; a bare id takes the resource of the operation
// (POST /orders: $.id → order), then the service name.
func hmacDomain(name, service, op string) string {
	n := normName(name)
	for _, suf := range idSuffixes {
		if strings.HasSuffix(n, suf) && len(n) > len(suf) {
			n = strings.TrimSuffix(n, suf)
			break
		}
	}
	if n == "id" || n == "uuid" || n == "ids" || n == "" {
		n = resourceOf(op)
	}
	if n == "" {
		n = strings.TrimSuffix(strings.TrimSuffix(normName(service), "-api"), "-ext")
	}
	n = reDomainClean.ReplaceAllString(n, "_")
	if len(n) > 32 {
		n = n[:32]
	}
	if n == "" || n[0] < 'a' || n[0] > 'z' || !policy.ValidDomain(n) || policy.ReservedDomains[n] {
		return "id"
	}
	return n
}

// traceHeaders carry trace context or request ids: unique per call, they
// link nothing a twin needs.
var traceHeaders = map[string]bool{
	"traceparent": true, "tracestate": true, "baggage": true, "x-request-id": true, "x-correlation-id": true,
	"x-amzn-trace-id": true, "x-cloud-trace-context": true, "sentry-trace": true, "b3": true, "uber-trace-id": true,
}

// personalPath reports whether a name along the path suggests personal
// data or free text ($.shippingAddress.line1: the whole address).
func personalPath(path string) bool {
	p := strings.TrimPrefix(path, "$")
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '.' || r == '[' || r == ']' || r == '*' }) {
		if rePersonalName.MatchString(normName(part)) {
			return true
		}
	}
	return false
}

// shapeFormat returns the format or length class of a string shape
// ("drop:str:uuid" → "uuid"), the kind for others ("drop:int" → "int").
func shapeKind(shape string) (kind, detail string) {
	parts := strings.SplitN(shape, ":", 3)
	if len(parts) < 2 || parts[0] != "drop" {
		return "", ""
	}
	if len(parts) == 3 {
		return parts[1], parts[2]
	}
	return parts[1], ""
}

// splitDiscPath maps a discovery key to the admin API part and path.
func splitDiscPath(p string) (part, path string, ok bool) {
	side, rest, found := strings.Cut(p, ".")
	if !found && p != "req" && p != "resp" {
		return "", "", false
	}
	switch side {
	case "req":
		part = "request"
	case "resp":
		part = "response"
	default:
		return "", "", false
	}
	switch {
	case rest == "body":
		return part, "$", true
	case strings.HasPrefix(rest, "body.") || strings.HasPrefix(rest, "body["):
		return part, "$" + strings.TrimPrefix(rest, "body"), true
	}
	return part, rest, true
}

// segmentName names a path parameter after the literal before it in the
// operation template ("GET /orders/{id}" -> orderId), for its HMAC domain.
func segmentName(op, param string) string {
	_, segs, ok := policy.ParseOpKey(op)
	if !ok {
		return param
	}
	for i, sg := range segs {
		if sg.Param != param {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if segs[j].Literal != "" {
				return singular(segs[j].Literal) + "Id"
			}
		}
	}
	return param
}

// reEnumName: names of states and codes with few values.
var reEnumName = regexp.MustCompile(`(^|_)(status|state|currency|type|kind|method|mode|level|tier|plan|category|reason|channel|service|stage|phase|priority|severity|unit|lang|locale|format)$`)

var (
	reAmountName   = regexp.MustCompile(`(^|_)(amount|price|total|subtotal|cost|fee|tax|balance|cents|value)(_cents)?$`)
	reQuantityName = regexp.MustCompile(`(^|_)(qty|quantity|count|parcels|items|pieces|units|size|seats|nights|guests)$`)
)

// numberBounds proposes bucket bounds from the name of a number: tt-core
// never sees its value, only that it is an integer or a decimal. Amounts
// that are integers are most often cents.
func numberBounds(name, kind string) (code, bounds string) {
	n := normName(name)
	switch {
	case reAmountName.MatchString(n) && (kind == "int" || strings.HasSuffix(n, "cents")):
		return "amount", "0, 1000, 5000, 10000, 50000"
	case reAmountName.MatchString(n):
		return "amount", "0, 10, 50, 100, 500"
	case reQuantityName.MatchString(n):
		return "quantity", "0, 1, 2, 5, 10"
	}
	return "number", "0, 10, 100, 1000"
}

var (
	// reTimestampName: times of the exchange itself (unique per call).
	reTimestampName = regexp.MustCompile(`(^|_)(created|updated|modified|deleted|sent|received|processed|timestamp|ts|time|at|seen|last|now|requested|issued)(_at|_on|_ts)?$|_at$`)
	// reDateName: business dates whose day matters (due dates, periods).
	reDateName = regexp.MustCompile(`(^|_)(due|deadline|expires|expiry|expiration|valid|until|from|to|start|end|period|day|date|month|checkin|checkout|departure|arrival|delivery|return|booking|loan)(_date|_day|_on)?$|_date$|_day$`)
)

// dateWorthBucketing reports whether a date field is worth bucketing to the
// day: a date without time, or a business date (due, start, end...) with
// few distinct values. Timestamps of the exchange (createdAt) stay drop.
func dateWorthBucketing(name, detail string, distinct int) bool {
	n := normName(name)
	if reTimestampName.MatchString(n) {
		return false
	}
	if distinct > 5*assistEnumMax {
		return false // a new value at almost every call
	}
	return detail == "date" || reDateName.MatchString(n)
}

// suggest applies the heuristics to one field.
func suggest(df DiscoveredField) Suggestion {
	part, path, _ := splitDiscPath(df.Path)
	s := Suggestion{Service: df.Service, Op: df.Op, Part: part, Path: path, Shape: df.Shape, Observed: df.Observed, DistinctEstimate: df.Distinct, Suggestion: "drop"}
	name := lastName(path)
	kind, detail := shapeKind(df.Shape)
	isHeader := strings.HasPrefix(path, "headers.")
	isSegment := strings.HasPrefix(path, "path.")
	obs := df.Observed
	if obs == 0 {
		obs = int64(df.Distinct) // unknown: assume every value seen once
	}
	isID := idName(name) && (kind == "str" || kind == "int" || detail == "digits")
	why := func(code, text string) { s.ReasonCode, s.Reason = code, text }
	propose := func(action, code, text string) { s.Suggestion = action; why(code, text) }
	switch {
	case strings.Contains(path, "{*}") || strings.HasSuffix(path, ".*") || strings.Contains(path, ".*."):
		why("dynamic_name", "dynamic name: the field has no stable name, it stays drop")
	case isHeader && policy.ForbiddenKeepHeaders[name]:
		why("credential", "credential header: never kept")
	case isHeader && (traceHeaders[name] || strings.HasPrefix(name, "x-b3-")):
		why("trace", "trace context or request id: unique per call, it stays drop")
	case isHeader && contract.IsTransportHeader(name):
		// host carries the internal host:port, user-agent the client
		// software: neither describes the API, a mock never needs them.
		why("transport", "transport header (host, user-agent, accept...): describes the connection, not the API; it stays drop")
	case personalShapes[detail]:
		why("personal_format", "format "+detail+" identifies people or carries credentials: stays drop")
	case !isSegment && !isHeader && personalPath(path), isHeader && rePersonalName.MatchString(normName(name)):
		why("personal_name", "the field name suggests personal data or free text: stays drop")
	case df.Observed > 0 && df.Observed < assistMinObserved:
		why("few", "not enough observations yet")
	case kind == "bool" || kind == "null":
		propose("keep", "flag", "boolean flag")
	case (detail == "datetime" || detail == "date") && dateWorthBucketing(name, detail, df.Distinct):
		propose("bucket(time, day)", "time", "date: keep only the day (choose hour, month or year if needed)")
	case detail == "datetime" || detail == "date":
		why("timestamp", "timestamp of the call (created, updated...): unique per call, the mock generates times itself; it stays drop (choose bucket(time, day) only if the day matters to the business)")
	case isSegment && (isID || detail == "uuid" || detail == "hex" || df.Distinct > assistEnumMax):
		propose("hmac("+hmacDomain(segmentName(df.Op, name), df.Service, df.Op)+")", "path_id", "identifier in the path: tokenize the parameter (same domain on related fields links them)")
	case !isSegment && kind == "str" && (detail == "l8" || detail == "l32") && reEnumName.MatchString(normName(name)) && df.Distinct <= 2*assistEnumMax:
		propose("keep", "enum_name", "the name says it is a state or a code with few values (an enum)")
	case isID || detail == "uuid" || detail == "hex" ||
		(float64(df.Distinct) >= assistIDRatio*float64(obs) && df.Distinct > assistEnumMax && (kind == "str" || detail == "digits")):
		propose("hmac("+hmacDomain(name, df.Service, df.Op)+")", "id", "identifier: tokenize it (same domain on related fields links them)")
	case kind == "int" || kind == "dec" || detail == "digits":
		code, bounds := numberBounds(name, kind)
		propose("bucket(num, ["+bounds+"])", code, "numeric value: bucket it (adjust the bounds to the business ranges)")
	case kind == "str" && (detail == "l8" || detail == "l32") && df.Distinct <= assistEnumMax && obs >= int64(5*max(df.Distinct, 1)):
		if isSegment {
			propose("keep", "path_word", "few distinct path words: they can be kept")
		} else {
			propose("keep", "enum", "low-cardinality short string, likely an enum (check it is not free text)")
		}
	default:
		why("free", "free text or not enough evidence: stays drop")
	}
	return s
}
