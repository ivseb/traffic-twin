package mock

import "github.com/ivseb/traffic-twin/internal/pack"

// shareHiddenWhen returns the reads of an entity with hidden_when inherited
// across reads that locate it through the same field. Visibility belongs to
// the entity state and to the way it is selected: a front API that wraps the
// carrier's (shop GET /orders/{id}/shipment over carrier GET /v1/shipments)
// hides the same states, even in packs mined before the miner shared them.
func shareHiddenWhen(in []pack.ReadBy) []pack.ReadBy {
	out := make([]pack.ReadBy, len(in))
	copy(out, in)
	for i := range out {
		by := out[i].By
		if out[i].HiddenWhen != nil || by == nil || by.Owner || by.Field == "" {
			continue
		}
		for j := range in {
			if in[j].HiddenWhen != nil && in[j].By != nil && !in[j].By.Owner && in[j].By.Field == by.Field {
				out[i].HiddenWhen = in[j].HiddenWhen
				break
			}
		}
	}
	return out
}
