package export

import (
	"context"
	"fmt"

	"github.com/ivseb/traffic-twin/internal/pack"
)

// PackSource is the production Source: it serves the files of a pack that
// internal/pack has already verified (signature, manifest, hashes).
type PackSource struct{ Pack *pack.Pack }

// Load implements Source.
func (s PackSource) Load(ctx context.Context) (*Input, error) {
	if s.Pack == nil {
		return nil, fmt.Errorf("export: nil pack")
	}
	return loadFrom(ctx, func(rel string) ([]byte, error) {
		b, ok := s.Pack.Files[rel]
		if !ok {
			return nil, fmt.Errorf("export: %s is not a verified file of the pack", rel)
		}
		return b, nil
	})
}
