package gate

import (
	"context"
	"strings"
	"testing"

	"github.com/ivseb/traffic-twin/internal/synthdoc"
)

const docContract = `{"openapi":"3.1.0","paths":{"/invoices/{id}/pdf":{"get":{"operationId":"invoicePdf","responses":{"200":{"description":"ok","content":{"application/pdf":{"schema":{"type":"string","format":"binary","x-tt-value":{"doc_class":"l16k","doc_type":"pdf","format":"doc","kind":"shape"}}}}}}}}}}`

func docInput(world string) *Input {
	in := input(world, &fakeMatcher{})
	in.Files["contracts/shop-api.openapi.json"] = []byte(docContract)
	return in
}

// The text of the synthetic documents (mock.md 2.9) uses the world's
// synthetic customers: a clean pack passes.
func TestDocumentTextPasses(t *testing.T) {
	res, err := Run(context.Background(), docInput(okWorld))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Passed() {
		t.Fatalf("pack with documents failed: %+v", res.Report.Checks)
	}
}

// A customer name without synthetic provenance, or one the detectors flag,
// fails the pii-detectors check with file "documents" and no value.
func TestDocumentTextFindings(t *testing.T) {
	world := strings.Replace(okWorld, `"name":"Anna Rossi"`, `"name":"Mario Bianchi"`, 1)
	res, _ := Run(context.Background(), docInput(world))
	found := false
	for _, c := range res.Report.Checks {
		for _, f := range c.Findings {
			if strings.Contains(f.Reason+f.Pointer, "Mario") {
				t.Fatal("finding leaks the value")
			}
			if c.ID == CheckPII && f.File == "documents" && f.Pointer == "/2" {
				found = true
			}
		}
	}
	if !found || res.Passed() {
		t.Fatalf("unsynthetic document text passed: %+v", res.Report.Checks)
	}
	// without a document in the contracts the check does not apply
	in := input(world, &fakeMatcher{})
	in.Prov.Synthetic["Mario Bianchi"] = true
	if res, _ := Run(context.Background(), in); !res.Passed() {
		t.Fatalf("%+v", res.Report.Checks)
	}
}

// The base64 examples of the contracts (contract.docExample) do not trip
// the detectors for any document type.
func TestDocumentExamplesAreClean(t *testing.T) {
	for _, k := range synthdoc.Kinds {
		for _, c := range []string{"", "l16k"} {
			b, err := synthdoc.Generate(k, c, synthdoc.Text{Refs: []string{"DOC-SYN-0001"}})
			if err != nil {
				t.Fatal(err)
			}
			if r := detect(b64(b)); len(r) > 0 {
				t.Fatalf("%s %s: %v", k, c, r)
			}
		}
	}
}
