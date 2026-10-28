package miner

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"time"
)

// OCEL 2.0 JSON export of the object-centric log (the public OCEL 2.0
// standard: objectTypes, eventTypes, objects, events). Objects are tokens
// typed by HMAC domain (subjects have type "subject"), events are exchanges
// typed "<service> <op>", event-to-object qualifiers are the event fields,
// object-to-object relationships come from ids that share a record
// (qualifier: the member name), and object attributes are the keep-valued
// fields of the records the object is the own id of, with their time.
//
// The file is pseudonymous personal data of zone B: it must not leave it.
// The admin API exposes it only to the event-exporter role (POST
// /api/v1/events/export, implemented by tt-core's job runner on top of
// ExportOCEL) and every export is audited.

// ExportQuery selects what ExportOCEL writes.
type ExportQuery struct {
	From, To time.Time
	Service  string
}

type ocelAttrType struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ocelType struct {
	Name       string         `json:"name"`
	Attributes []ocelAttrType `json:"attributes"`
}

type ocelRel struct {
	ObjectID  string `json:"objectId"`
	Qualifier string `json:"qualifier"`
}

type ocelObjAttr struct {
	Name  string `json:"name"`
	Time  string `json:"time"`
	Value string `json:"value"`
}

type ocelObject struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"`
	Attributes    []ocelObjAttr `json:"attributes"`
	Relationships []ocelRel     `json:"relationships"`
}

type ocelEvAttr struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ocelEvent struct {
	ID            string       `json:"id"`
	Type          string       `json:"type"`
	Time          string       `json:"time"`
	Attributes    []ocelEvAttr `json:"attributes"`
	Relationships []ocelRel    `json:"relationships"`
}

// ExportOCEL loads the events of q and writes them as OCEL 2.0 JSON.
func ExportOCEL(ctx context.Context, src EventSource, q ExportQuery, res DomainResolver, cfg Config, w io.Writer) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	l, err := Load(ctx, src, q.From, q.To, q.Service, res, cfg.MaxEvents)
	if err != nil {
		return err
	}
	m := newMiner(&cfg, l)
	m.discoverEntities()
	return m.writeOCEL(w)
}

func (m *miner) writeOCEL(w io.Writer) error {
	l := m.l
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	const tf = "2006-01-02T15:04:05.000Z"

	// Object attributes and relationships.
	attrs := make([][]ocelObjAttr, len(l.toks))
	attrNames := map[string]map[string]bool{}
	rels := make([]map[ocelRel]bool, len(l.toks))
	for ei := range l.evs {
		ev := &l.evs[ei]
		for ri := range ev.recs {
			r := &ev.recs[ri]
			own := int32(-1)
			if _, f, ok := m.recEntity(r); ok {
				own = f.tok
			} else if len(r.ids) == 1 {
				own = r.ids[0].tok
			}
			if own >= 0 {
				typ := l.tokDom[own]
				for _, a := range r.attrs {
					attrs[own] = append(attrs[own], ocelObjAttr{Name: a.name, Time: ev.at(r.side).Format(tf), Value: a.val.S})
					if attrNames[typ] == nil {
						attrNames[typ] = map[string]bool{}
					}
					attrNames[typ][a.name] = true
				}
				for _, f := range r.ids {
					if f.tok == own || l.tokDom[f.tok] == "" {
						continue
					}
					if rels[own] == nil {
						rels[own] = map[ocelRel]bool{}
					}
					rels[own][ocelRel{ObjectID: l.toks[f.tok], Qualifier: f.name}] = true
				}
			}
		}
	}
	// Types.
	objTypes := map[string]bool{}
	for t := range l.toks {
		typ := l.tokDom[t]
		if l.subj[int32(t)] && typ == "" {
			typ = "subject"
		}
		if typ != "" {
			objTypes[typ] = true
		}
	}
	evTypes := map[string]bool{}
	for _, o := range l.ops {
		evTypes[o.service+" "+o.op] = true
	}
	if _, err := bw.WriteString(`{"objectTypes":[`); err != nil {
		return err
	}
	for i, name := range sortedKeys(objTypes) {
		ot := ocelType{Name: name, Attributes: []ocelAttrType{}}
		for _, a := range sortedKeys(attrNames[name]) {
			ot.Attributes = append(ot.Attributes, ocelAttrType{Name: a, Type: "string"})
		}
		if err := writeElem(bw, enc, i, ot); err != nil {
			return err
		}
	}
	bw.WriteString(`],"eventTypes":[`)
	evAttrTypes := []ocelAttrType{{"service", "string"}, {"dir", "string"}, {"status", "integer"}}
	for i, name := range sortedKeys(evTypes) {
		if err := writeElem(bw, enc, i, ocelType{Name: name, Attributes: evAttrTypes}); err != nil {
			return err
		}
	}
	bw.WriteString(`],"objects":[`)
	n := 0
	for t := range l.toks {
		typ := l.tokDom[t]
		if l.subj[int32(t)] && typ == "" {
			typ = "subject"
		}
		if typ == "" {
			continue
		}
		o := ocelObject{ID: l.toks[t], Type: typ, Attributes: attrs[t], Relationships: []ocelRel{}}
		if o.Attributes == nil {
			o.Attributes = []ocelObjAttr{}
		}
		for r := range rels[t] {
			o.Relationships = append(o.Relationships, r)
		}
		sort.Slice(o.Relationships, func(a, b int) bool {
			if o.Relationships[a].ObjectID != o.Relationships[b].ObjectID {
				return o.Relationships[a].ObjectID < o.Relationships[b].ObjectID
			}
			return o.Relationships[a].Qualifier < o.Relationships[b].Qualifier
		})
		if err := writeElem(bw, enc, n, o); err != nil {
			return err
		}
		n++
	}
	bw.WriteString(`],"events":[`)
	for ei := range l.evs {
		ev := &l.evs[ei]
		op := l.ops[ev.op]
		dir := "outbound"
		if ev.inbound {
			dir = "inbound"
		}
		oe := ocelEvent{ID: "e" + strconv.FormatInt(ev.id, 10), Type: op.service + " " + op.op, Time: ev.ts.Format(tf),
			Attributes:    []ocelEvAttr{{"service", op.service}, {"dir", dir}, {"status", strconv.Itoa(ev.status)}},
			Relationships: []ocelRel{}}
		seen := map[ocelRel]bool{}
		if ev.subject >= 0 {
			oe.Relationships = append(oe.Relationships, ocelRel{ObjectID: l.toks[ev.subject], Qualifier: "subject"})
		}
		for _, t := range ev.toks {
			if l.tokDom[t.tok] == "" {
				continue
			}
			r := ocelRel{ObjectID: l.toks[t.tok], Qualifier: l.locs[t.loc].field}
			if !seen[r] {
				seen[r] = true
				oe.Relationships = append(oe.Relationships, r)
			}
		}
		if err := writeElem(bw, enc, ei, oe); err != nil {
			return err
		}
	}
	bw.WriteString("]}\n")
	return bw.Flush()
}

func writeElem(bw *bufio.Writer, enc *json.Encoder, i int, v any) error {
	if i > 0 {
		if err := bw.WriteByte(','); err != nil {
			return err
		}
	}
	return enc.Encode(v) // the trailing newline is valid JSON whitespace
}
