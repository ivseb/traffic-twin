package packwriter

import "testing"

func TestManifestVersion(t *testing.T) {
	for in, want := range map[string]string{
		"":              "0.1.0",
		"0.1.0":         "0.1.0",
		"v1.2.3":        "1.2.3",
		"0.1.0-3-gabc":  "0.1.0-3-gabc",
		"faa01eb":       "0.0.0+faa01eb",
		"faa01eb-dirty": "0.0.0+faa01eb-dirty",
		"dev":           "0.0.0+dev",
		"a b/c":         "0.0.0+a-b-c",
		"///":           "0.1.0",
	} {
		if got := manifestVersion(in); got != want {
			t.Errorf("manifestVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
