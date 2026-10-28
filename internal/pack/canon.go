package pack

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/ivseb/traffic-twin/internal/sanitizer/ttjson"
)

// CheckManifestCanonical refuses a manifest.json that is not exactly one
// canonical tt JSON document with a final newline (pack.md section 1): the
// bytes must equal the canonical re-encoding of what they parse to, with
// duplicate object keys rejected, and every object key must be spelled
// exactly like a field of the manifest (encoding/json would also match
// "PACK_ID" to pack_id, so two readers could read different manifests out
// of the same signed bytes). Unknown keys are refused. Both the loader and
// keyguard's pack/sign call it, so what keyguard signs is what the loader
// reads.
func CheckManifestCanonical(b []byte) error {
	body, ok := bytes.CutSuffix(b, []byte("\n"))
	if !ok {
		return errors.New("manifest.json must end with a newline")
	}
	v, err := ttjson.Parse(body, ttjson.ParseOptions{MaxDepth: 32, RejectDuplicates: true})
	if err != nil {
		return fmt.Errorf("manifest.json is not canonical JSON: %v", err)
	}
	out, err := ttjson.Encode(v)
	if err != nil || !bytes.Equal(out, body) {
		return errors.New("manifest.json is not in canonical tt JSON form")
	}
	if err := exactKeys(v, reflect.TypeOf(Manifest{}), ""); err != nil {
		return fmt.Errorf("manifest.json: %v", err)
	}
	return nil
}

// exactKeys walks v along the Go type t and requires every object key to
// be the exact json tag name of a field.
func exactKeys(v ttjson.Value, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch v.Kind {
	case ttjson.Array:
		if t.Kind() != reflect.Slice {
			return nil
		}
		for i, e := range v.Arr {
			if err := exactKeys(e, t.Elem(), fmt.Sprintf("%s/%d", path, i)); err != nil {
				return err
			}
		}
	case ttjson.Object:
		if t.Kind() != reflect.Struct {
			return nil
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			if name != "" && name != "-" {
				fields[name] = t.Field(i).Type
			}
		}
		for _, m := range v.Obj {
			ft, ok := fields[m.Key]
			if !ok {
				return fmt.Errorf("unknown or mis-cased key at %s/%s", path, m.Key)
			}
			if err := exactKeys(m.Value, ft, path+"/"+m.Key); err != nil {
				return err
			}
		}
	}
	return nil
}
