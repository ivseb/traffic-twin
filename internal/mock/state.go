package mock

import (
	"net/http"
	"net/url"
	"sort"
)

// Keyed records, removals and body selectors (rules v1.6,
// docs/spec/rules.md 2.8-2.10 and 3.7).
//
//   - A keyed entity has no id of its own: its record is the one of the
//     session customer (key.owner) whose key fields equal the values the
//     request carries (read_by.key, upserted_by.key). A write of
//     upserted_by creates it or replaces the members it sends (the part of
//     the request at upserted_by.state); a read finds it, or answers from
//     the contract when there is none (the service's default state).
//   - A remove effect deletes the entity from the session: it leaves the
//     lists and counts, and a single read selecting it by id answers
//     read_by.removed_status when set, otherwise as an entity that does not
//     exist.
//   - A read may select with a member of the request body (by, key): the
//     mock exposes its value to the selection as a parameter named by its
//     path, like a GraphQL variable.

func refKeys(m map[string]compiledRef) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// bodyParams adds to the parameters the values of the request body members
// the operation selects or keys with (scalars only).
func (s *session) bodyParams(svc *service, op *operation, params map[string]string, reqBody any) map[string]string {
	refs := s.m.model.bodyRefs[svc.name+"\x00"+op.key]
	if len(refs) == 0 || reqBody == nil {
		return params
	}
	out := make(map[string]string, len(params)+len(refs))
	for k, v := range params {
		out[k] = v
	}
	for _, r := range refs {
		if _, ok := out[r.ref.Path]; ok {
			continue
		}
		if v, ok := first(evalPath(reqBody, r.segs)); ok {
			if sv, ok := scalarString(v); ok {
				out[r.ref.Path] = sv
			}
		}
	}
	return out
}

// keyValues reads the values of a key from the request; ok is false when
// one is missing.
func keyValues(key map[string]compiledRef, params map[string]string, q url.Values, h http.Header) (map[string]string, bool) {
	out := map[string]string{}
	for _, f := range refKeys(key) {
		v, ok := lookupParam(key[f].ref.From, refParam(key[f]), params, q, h)
		if !ok {
			return nil, false
		}
		out[f] = v
	}
	return out, true
}

// keyedRecords returns the records of a keyed entity of the session
// customer (when the key has the owner) whose fields equal vals.
func (s *session) keyedRecords(ed *entityDef, vals map[string]string) []*entityRec {
	return s.keyedRecordsOf(ed, vals, s.customer, ed.def.Key != nil && ed.def.Key.Owner)
}

// keyedRecordsOf is keyedRecords for customer cust (rules v1.8: the
// customer of a rule's cause).
func (s *session) keyedRecordsOf(ed *entityDef, vals map[string]string, cust *string, owner bool) []*entityRec {
	var out []*entityRec
	for _, r := range s.sortedEnts(ed.def.Name) {
		if owner && !sameOwner(r.customerID, cust) {
			continue
		}
		match := true
		for f, want := range vals {
			got, ok := getDotted(r.state, f)
			if sv, isScalar := scalarString(got); !ok || !isScalar || sv != want {
				match = false
				break
			}
		}
		if match {
			out = append(out, r)
		}
	}
	return out
}

func sameOwner(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// upsert applies the keyed writes of an operation (step 1 of rules.md 6, as
// a creation): the record of the key is created or its members replaced.
// It returns the record of the first write, nil when none applies.
func (s *session) upsert(svc *service, op *operation, params map[string]string, q url.Values, in *inbound, reqBody any) *entityRec {
	var firstRec *entityRec
	for _, ud := range s.m.model.upserts[svc.name+"\x00"+op.key] {
		vals, ok := keyValues(ud.key, params, q, in.header)
		if !ok {
			continue
		}
		var src map[string]any
		if ud.hasState {
			if v, ok := first(evalPath(reqBody, ud.statePath)); ok {
				src, _ = v.(map[string]any)
			}
		}
		name := ud.ent.def.Name
		var rec *entityRec
		if rs := s.keyedRecords(ud.ent, vals); len(rs) > 0 {
			rec = rs[0]
		} else {
			state := map[string]any{}
			for f, v := range vals {
				setDotted(state, f, v)
			}
			rec = &entityRec{entity: name, id: s.nextID(name, state), customerID: copyStr(s.customer), state: state, created: s.now}
			s.putEnt(rec)
		}
		for k, v := range src {
			rec.state[k] = cloneJSON(v)
		}
		for f, v := range vals {
			setDotted(rec.state, f, v) // the key stays the key
		}
		rec.updated = s.now
		if firstRec == nil {
			firstRec = rec
		}
	}
	return firstRec
}

// renderKeyed answers a read of a keyed entity: its record (or the matching
// records for a list), the contract answer when there is none.
func (s *session) renderKeyed(rd *readDef, status int, params map[string]string, q url.Values, in *inbound, build func(optVal) any) (int, any) {
	vals, ok := keyValues(rd.key, params, q, in.header)
	if !ok {
		vals = nil
	}
	recs := s.keyedRecords(rd.ent, vals)
	vis := recs[:0:0]
	for _, r := range recs {
		if !hiddenBy(rd, r) {
			vis = append(vis, r)
		}
	}
	if rd.list {
		items := make([]any, 0, len(vis))
		for _, r := range vis {
			items = append(items, s.entityOverlay(r))
		}
		tree, err := nest(rd.at, items)
		if err != nil {
			return status, build(optVal{})
		}
		if root, ok := tree.(map[string]any); ok && rd.countSegs != nil {
			setOverlayPath(root, rd.countSegs, intNumber(len(items)))
		}
		if root, ok := tree.(map[string]any); ok && rd.totalSegs != nil {
			setOverlayPath(root, rd.totalSegs, intNumber(len(items)))
		}
		return status, build(some(tree))
	}
	if len(vis) == 0 {
		return status, build(optVal{})
	}
	tree, err := nest(rd.at, s.entityOverlay(vis[0]))
	if err != nil {
		return status, build(optVal{})
	}
	return status, build(some(tree))
}

// removeEntity deletes an entity of the session (a remove effect) and
// remembers it for the reads by id.
func (s *session) removeEntity(entity, id string) bool {
	byID := s.ents[entity]
	if byID == nil || byID[id] == nil {
		return false
	}
	delete(byID, id)
	if s.removed == nil {
		s.removed = map[string]bool{}
	}
	s.removed[entity+"\x00"+id] = true
	return true
}

// removedAnswer is the answer of a single read by id of an entity removed
// in the session, when the read declares one.
func (s *session) removedAnswer(rd *readDef, op *operation, params map[string]string, q url.Values, in *inbound, b *builder) (int, any, bool) {
	if rd.rb.RemovedStatus == 0 || !rd.hasBy || rd.owner || rd.by.ref.Field != "" {
		return 0, nil, false
	}
	val, ok := lookupParam(rd.by.ref.From, refParam(rd.by), params, q, in.header)
	if !ok || !s.removed[rd.ent.def.Name+"\x00"+val] {
		return 0, nil, false
	}
	st := rd.rb.RemovedStatus
	return st, s.errorBody(op, st, "", b, "gone"), true
}
