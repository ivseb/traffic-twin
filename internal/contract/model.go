package contract

import (
	"time"

	"github.com/ivseb/traffic-twin/internal/dateoff"
)

// Config tunes inference, snapshots and diffs. Start from [DefaultConfig].
type Config struct {
	// KMin is the minimum number of distinct subjects for a keep value or a
	// bucket band to be published (docs/spec/pack.md section 4.1, gate check
	// k-thresholds). Default 20.
	KMin int
	// MinSamples is N: a field is required only when it is present in every
	// observed object and at least MinSamples objects were observed. It is
	// also the minimum number of calls for an operation to be diffed and not
	// reported as having few samples. Default 20.
	MinSamples int
	// SampleCap bounds the events decoded per (service, op, status) group;
	// bigger groups are sampled with a fixed stride. Exact counts and status
	// frequencies still come from the store summaries. Default 50 000.
	SampleCap int
	// MaxEnumValues bounds the distinct keep values tracked per field; a
	// field above it is not an enum. Default 64.
	MaxEnumValues int
	// MaxProps bounds the properties tracked per object schema. Default 256.
	MaxProps int
	// MaxDepth bounds the schema depth. Default 32.
	MaxDepth int

	// Window is the snapshot window. Default 24 h. Windows are aligned to
	// multiples of Window since the Unix epoch (UTC days for 24 h).
	Window time.Duration
	// Grace is how long after a window ends the snapshot runs, so that late
	// events are included. Default 5 min.
	Grace time.Duration
	// KeepSnapshots is the number of snapshots kept per service (older ones
	// are deleted). Default 400.
	KeepSnapshots int

	// Diff thresholds.
	Diff DiffConfig

	// IncludeRaw renders operations whose route came from "raw" path
	// sanitization (no template) in the OpenAPI document. Default false.
	IncludeRaw bool
}

// DiffConfig sets the thresholds of the diff engine.
type DiffConfig struct {
	// FrequentStatus is the frequency from which a new error status counts
	// as frequent (breaking). Default 0.01.
	FrequentStatus float64
	// FrequencyShift is the absolute frequency change reported as a
	// non-breaking change. Default 0.05.
	FrequencyShift float64
	// PresenceDrop is the absolute drop of the presence of an optional
	// field reported as a (non-breaking) change. Default 0.2.
	PresenceDrop float64
	// PresenceVanish: an optional field whose presence falls from at least
	// 0.5 to at most this value is considered removed (breaking). Default 0.05.
	PresenceVanish float64
	// MinCalls is the minimum number of calls of an operation (in both
	// snapshots) for field-level changes to be reported. Default 20.
	MinCalls int64
}

// DefaultConfig returns the documented defaults.
func DefaultConfig() Config {
	return Config{
		KMin: 20, MinSamples: 20, SampleCap: 50_000, MaxEnumValues: 64, MaxProps: 256, MaxDepth: 32,
		Window: 24 * time.Hour, Grace: 5 * time.Minute, KeepSnapshots: 400,
		Diff: DiffConfig{FrequentStatus: 0.01, FrequencyShift: 0.05, PresenceDrop: 0.2, PresenceVanish: 0.05, MinCalls: 20},
	}
}

func (c *Config) setDefaults() {
	d := DefaultConfig()
	if c.KMin <= 0 {
		c.KMin = d.KMin
	}
	if c.MinSamples <= 0 {
		c.MinSamples = d.MinSamples
	}
	if c.SampleCap <= 0 {
		c.SampleCap = d.SampleCap
	}
	if c.MaxEnumValues <= 0 {
		c.MaxEnumValues = d.MaxEnumValues
	}
	if c.MaxProps <= 0 {
		c.MaxProps = d.MaxProps
	}
	if c.MaxDepth <= 0 {
		c.MaxDepth = d.MaxDepth
	}
	if c.Window <= 0 {
		c.Window = d.Window
	}
	if c.Grace < 0 {
		c.Grace = 0
	}
	if c.KeepSnapshots <= 0 {
		c.KeepSnapshots = d.KeepSnapshots
	}
	if c.Diff.FrequentStatus <= 0 {
		c.Diff.FrequentStatus = d.Diff.FrequentStatus
	}
	if c.Diff.FrequencyShift <= 0 {
		c.Diff.FrequencyShift = d.Diff.FrequencyShift
	}
	if c.Diff.PresenceDrop <= 0 {
		c.Diff.PresenceDrop = d.Diff.PresenceDrop
	}
	if c.Diff.PresenceVanish <= 0 {
		c.Diff.PresenceVanish = d.Diff.PresenceVanish
	}
	if c.Diff.MinCalls <= 0 {
		c.Diff.MinCalls = int64(c.MinSamples)
	}
}

// Window is a half-open time interval [From, To).
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Contract is the inferred contract of one service over a window. It is the
// model stored in snapshots; [Contract.OpenAPI] renders it.
type Contract struct {
	Service string `json:"service"`
	// Group is the group whose traffic the contract describes ("" for the
	// traffic of every group): two teams calling the same host pattern have
	// two contracts.
	Group  string `json:"group,omitempty"`
	Window Window `json:"window"`
	KMin   int    `json:"k_min"`
	// MinSamples is N of Config at inference time (required needs it).
	MinSamples int   `json:"min_samples"`
	Ops        []*Op `json:"ops"`
	// GraphQL holds the introspection results captured for the GraphQL
	// endpoints of the service (sanitizer.md 5.7.2), one per endpoint.
	GraphQL []*GraphQLSchema `json:"graphql,omitempty"`
}

// Calls is the total number of calls of all operations.
func (c *Contract) Calls() int64 {
	var n int64
	for _, o := range c.Ops {
		n += o.Calls
	}
	return n
}

// Op returns the operation with the given key ("GET /orders/{id}").
func (c *Contract) Op(key string) *Op {
	for _, o := range c.Ops {
		if o.Key == key {
			return o
		}
	}
	return nil
}

// Latency holds latency quantiles in milliseconds.
type Latency struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

// Op is one operation of a service.
type Op struct {
	// Key is the event op: "METHOD /template".
	Key    string `json:"key"`
	Method string `json:"method"`
	Path   string `json:"path"`
	// Dir is inbound or outbound.
	Dir string `json:"dir"`
	// RouteSource is the most frequent route source of the events.
	RouteSource string    `json:"route_source"`
	Calls       int64     `json:"calls"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Latency     *Latency  `json:"latency,omitempty"`
	// NetErrors counts exchanges that ended in a network error, by kind.
	NetErrors map[string]int64 `json:"net_errors,omitempty"`

	PathParams []*Param `json:"path_params,omitempty"`
	Query      []*Param `json:"query,omitempty"`
	Headers    []*Param `json:"headers,omitempty"`
	Cookies    []*Param `json:"cookies,omitempty"`
	// Body is the request body by content type; BodyCalls counts the calls
	// that had a body.
	Body      []*Media `json:"body,omitempty"`
	BodyCalls int64    `json:"body_calls,omitempty"`
	// ReqCalls is the number of exchanges the request side was inferred
	// from (those that did not end with status >= 400).
	ReqCalls int64 `json:"req_calls,omitempty"`

	Responses []*Response `json:"responses,omitempty"`
	// GraphQL describes a logical GraphQL operation (event.md 6); nil for
	// any other operation.
	GraphQL *GraphQLOp `json:"graphql,omitempty"`
}

// Response returns the response with the given status.
func (o *Op) Response(status int) *Response {
	for _, r := range o.Responses {
		if r.Status == status {
			return r
		}
	}
	return nil
}

// Param is a path, query, header or cookie parameter.
type Param struct {
	Name string `json:"name"`
	// Count is the number of exchanges that carried the parameter.
	Count    int64   `json:"count"`
	Presence float64 `json:"presence"`
	Required bool    `json:"required"`
	// Multi is true when some exchange carried more than one value.
	Multi  bool    `json:"multi,omitempty"`
	Schema *Schema `json:"schema"`
}

// Media is a body for one content type. Schema is nil for opaque bodies
// (non JSON, dropped, truncated).
type Media struct {
	CT     string  `json:"ct"`
	Calls  int64   `json:"calls"`
	Schema *Schema `json:"schema,omitempty"`
	// Opaque counts the bodies without a schema by marker
	// ("drop:bytes:l128", "trunc:size").
	Opaque map[string]int64 `json:"opaque,omitempty"`
	// XML describes an XML or SOAP body (sanitizer.md 22.2, spec v1.19):
	// rendered as x-tt-xml on the media type.
	XML *XMLInfo `json:"xml,omitempty"`
}

// XMLInfo is the envelope of an XML body: the most frequent fmt (xml,
// soap11 or soap12) and, per element path, the most frequent namespace
// pattern (ns:<pattern>, ns:{none} or ns:{*}). The element names are the
// keys of the schema; attributes are the "@name" properties and mixed text
// the "#text" property.
type XMLInfo struct {
	Format     string            `json:"format"`
	Namespaces map[string]string `json:"namespaces,omitempty"`
}

// Response is one status of an operation.
type Response struct {
	Status int   `json:"status"`
	Calls  int64 `json:"calls"`
	// Frequency is Calls over all the calls of the operation (network
	// errors included).
	Frequency float64  `json:"frequency"`
	Latency   *Latency `json:"latency,omitempty"`
	Headers   []*Param `json:"headers,omitempty"`
	Cookies   []*Param `json:"cookies,omitempty"`
	Body      []*Media `json:"body,omitempty"`
	// BodyCalls counts the exchanges that had a body.
	BodyCalls int64 `json:"body_calls,omitempty"`
}

// Schema is the inferred schema of a value.
type Schema struct {
	// Types is the sorted union of JSON types ("string", "null"...).
	Types []string `json:"types,omitempty"`
	// Count is the number of times the value was observed.
	Count int64 `json:"count"`

	// Kind is the x-tt-value kind: id, enum, bucket or shape ("" for
	// containers and values without sanitizer information).
	Kind     string `json:"kind,omitempty"`
	Domain   string `json:"domain,omitempty"`
	LenClass string `json:"len_class,omitempty"`
	// Shape is the token format (email, uuid, datetime, date, url, ipv4,
	// phone, digits, hex, jwt).
	Shape string `json:"shape,omitempty"`
	// Format is the JSON Schema format derived from Shape.
	Format string `json:"format,omitempty"`
	// DocType and DocClass describe a document (Shape "doc"): the type and
	// the size class of the sanitizer shape drop:doc:<type>:<class>.
	DocType  string `json:"doc_type,omitempty"`
	DocClass string `json:"doc_class,omitempty"`

	// Enum lists every tracked keep value; Published says which ones passed
	// the k threshold.
	Enum []EnumValue `json:"enum,omitempty"`
	// EnumPartial is true when a keep value was left out (below k or over
	// the tracking bound).
	EnumPartial bool `json:"enum_partial,omitempty"`

	Bounds  []string  `json:"bounds,omitempty"`
	BucketP []float64 `json:"bucket_p,omitempty"`
	Unit    string    `json:"unit,omitempty"`
	// DateOffset is the range of offsets between a time bucket and the
	// instant of the exchange (relative dates, docs/spec/pack.md 4.4).
	DateOffset *dateoff.Range `json:"date_offset,omitempty"`

	// Objects is the number of object instances observed (the denominator of
	// the presence of the properties).
	Objects    int64   `json:"objects,omitempty"`
	Props      []*Prop `json:"props,omitempty"`
	Additional *Schema `json:"additional,omitempty"`
	Items      *Schema `json:"items,omitempty"`
	MinItems   *int    `json:"min_items,omitempty"`
	MaxItems   *int    `json:"max_items,omitempty"`
	// Opaque is true when the container was collapsed by the policy
	// (drop:obj, drop:arr) or truncated: nothing is known about its content.
	Opaque bool `json:"opaque,omitempty"`
	// Deps are the field dependencies of an object schema: which values of
	// two of its low-cardinality properties were seen together
	// (x-tt-dependencies, docs/spec/pack.md section 4.2).
	Deps []*Dependency `json:"deps,omitempty"`
}

// Dependency lists the combinations of values of Fields (two sibling
// properties, keep or bucket) seen in the same object for at least KMin
// distinct subjects.
type Dependency struct {
	Fields []string `json:"fields"`
	Combos []Combo  `json:"combos"`
	// Partial is true when some observed combination was left out (below
	// k, or a value that is not published).
	Partial bool `json:"partial,omitempty"`
}

// Combo is one published combination, one value per field.
type Combo struct {
	Values []DepValue `json:"values"`
	// Count is the number of objects seen with it (published as a size
	// class, never exactly).
	Count int64 `json:"count"`
	// Subjects is the number of distinct subjects, capped at KMin.
	Subjects int `json:"subjects"`
	// AtLeast is the published size class (see AtLeast).
	AtLeast int64 `json:"at_least"`
}

// DepValue is a value of a combination: a keep value (Type string,
// integer, number; Value its lexeme) or a bucket band (Type band, Value the
// num: token).
type DepValue struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Prop is a property of an object schema.
type Prop struct {
	Name     string  `json:"name"`
	Count    int64   `json:"count"`
	Presence float64 `json:"presence"`
	Required bool    `json:"required"`
	Schema   *Schema `json:"schema"`
	// When, set on an optional property, says it is present only in objects
	// whose sibling When.Prop (an enum) holds one of When.In (published
	// values): a cancelReason that exists only for status CANCELLED.
	When *When `json:"when,omitempty"`
}

// When is a conditional presence (see Prop.When).
type When struct {
	Prop string   `json:"prop"`
	In   []string `json:"in"`
}

// EnumValue is a keep value with its support.
type EnumValue struct {
	// Type is the JSON type of the value: string, integer, number, boolean.
	Type  string `json:"type"`
	Value string `json:"value"`
	Count int64  `json:"count"`
	// Subjects is the number of distinct subjects seen, capped at KMin.
	Subjects int `json:"subjects"`
	// Published is true when Subjects reached KMin.
	Published bool `json:"published"`
}

// Prop returns the property with the given name.
func (s *Schema) Prop(name string) *Prop {
	if s == nil {
		return nil
	}
	for _, p := range s.Props {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// HasType reports whether t is in the union.
func (s *Schema) HasType(t string) bool {
	if s == nil {
		return false
	}
	for _, x := range s.Types {
		if x == t {
			return true
		}
	}
	return false
}

// PublishedEnum returns the enum values that passed the k threshold, sorted.
func (s *Schema) PublishedEnum() []EnumValue {
	var out []EnumValue
	for _, e := range s.Enum {
		if e.Published {
			out = append(out, e)
		}
	}
	return out
}
