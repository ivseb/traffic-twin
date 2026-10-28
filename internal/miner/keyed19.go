package miner

import (
	"strconv"
	"strings"
)

// Keyed records with a key of several fields (rules v1.9). Wave 3 learned
// the effects of a write on a keyed record whose key is the user, or the
// user and one field; a key of several fields (the consent of a document
// in a version, the setting of a device for an app) was left to a person.
// The record is now any tuple of the read's selector tokens; a call of the
// same subject is a cause when its request carries every token of the
// tuple (each at some request location, path, query or body member outside
// arrays); each key field of the effect's target_key is bound to the
// request location that carries it most often among the calls of the
// operation. A call that misses one of the tokens is not a cause.

// recordKey is the map key of a keyed record of subject s.
func recordKey(s int32, tks []int32) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(s)))
	for _, t := range tks {
		b.WriteByte('/')
		b.WriteString(strconv.Itoa(int(t)))
	}
	return b.String()
}

// matchRecord finds the record of subject s whose key tokens the request of
// call w carries, all of them; it returns the record and, per key field,
// the request location that carries its token (-1, nil when none).
func matchRecord(l *Log, w *evt, s int32, keyOf map[int32][]int32, byTok map[[2]int32][]int32) (int32, []int32) {
	reqLoc := map[int32]int32{} // token → first eligible request location
	var order []int32
	for _, t := range w.toks {
		lc := &l.locs[t.loc]
		if lc.side != sideReq || !lc.refOK || (lc.ref.Path != "" && !keyRefOK(lc.ref)) {
			continue
		}
		if _, ok := reqLoc[t.tok]; !ok {
			reqLoc[t.tok] = t.loc
			order = append(order, t.tok)
		}
	}
	for _, tok := range order {
		for _, o := range byTok[[2]int32{s, tok}] {
			key := keyOf[o]
			locs := make([]int32, len(key))
			whole := true
			for f, kt := range key {
				lc, ok := reqLoc[kt]
				if !ok {
					whole = false
					break
				}
				locs[f] = lc
			}
			if whole {
				return o, locs
			}
		}
	}
	return -1, nil
}

// keyBinds binds the key fields after the first of a key of several fields
// to the request location that carries them most often among insts, and
// returns field → bind name (nil for the other targets).
func keyBinds(l *Log, kt *keyTarget, insts []upInst, binds map[string]Ref) map[string]string {
	if kt == nil || len(kt.fields) < 2 {
		return nil
	}
	out := map[string]string{}
	for f := 1; f < len(kt.fields); f++ {
		n := map[int32]int{}
		for _, in := range insts {
			if f < len(in.klocs) {
				n[in.klocs[f]]++
			}
		}
		var best int32 = -1
		for lc, c := range n {
			if best < 0 || c > n[best] || (c == n[best] && lc < best) {
				best = lc
			}
		}
		if best < 0 {
			return nil
		}
		ref := l.locs[best].ref
		name := ""
		for k, r := range binds {
			if r == ref {
				name = k
			}
		}
		if name == "" {
			name = freeBind(kt.fields[f], binds)
			binds[name] = ref
		}
		out[kt.fields[f]] = name
	}
	return out
}
