package pack

import (
	"strings"
	"testing"
)

// rules19Doc is a valid rules 1.9 document; the tests break one member at a
// time.
const rules19Doc = `{"format":"tt.rules/v1",
 "attributes":[{"name":"segment","values":{"GOLD":0.5,"STANDARD":0.5},"subjects":40,
   "fields":[{"service":"app","op":"GET /me","at":{"from":"resp.body","path":"$.segment"}}]}],
 "aggregates":[
   {"service":"app","op":"GET /me","at":{"from":"resp.body","path":"$.unread"},"count":{"entity":"note","where":{"read":false}}},
   {"service":"app","op":"GET /me","at":{"from":"resp.body","path":"$.due"},"sum":{"entity":"note","field":"amount"}},
   {"service":"app","op":"GET /me","at":{"from":"resp.body","path":"$.sent"},"delta":[{"op":"POST /messages","by":1}]}],
 "lists":[{"service":"app","op":"GET /catalog","at":{"from":"resp.body","path":"$.items[*]"},"list":{"page":{"from":"req.query","name":"page"}}}],
 "entities":[{"name":"note","service":"app","id_domain":"note","id_field":"id","id_prefix":"NTE-SYN-",
   "seed":{"per_customer":[{"n":"1","share":1}],"subjects":40},
   "read_by":[{"op":"GET /notes","at":{"from":"resp.body","path":"$.items[*]"},"list":{"filters":[{"param":{"from":"req.query","name":"read"},"field":"read"}]}}]}],
 "rules":[
  {"id":"r-0001","kind":"causal","status":"approved","title":"t",
   "cause":{"service":"app","op":"POST /orders","when":{"status":[201],"match":[{"at":{"from":"req.headers","name":"x-channel"},"in":["APP"]}]}},
   "effects":[{"id":"all-read","entity":"note","target_all":true,"where":{"read":false},"set":{"read":true},"after":"0s"},
     {"id":"gate","respond":{"service":"app","op":"POST /checkout","status":409,"until":true},"after":"0s"}],
   "outcomes":[{"name":"a","p":0.5,"effects":["all-read","gate"],"when":[{"customer":"segment","in":["GOLD"]}]},
     {"name":"b","p":0.5,"effects":["gate"],"when":[{"at":{"from":"req.body","path":"$.amount"},"min":100,"max":500}]}],
   "evidence":{"counts":{"causes":0,"distinct_subjects":0,"outcomes":{}}}}]}`

func parse19(doc string) error {
	_, err := parseRules([]byte(doc), []string{"r-0001"}, map[string]bool{"app": true})
	return err
}

func TestRules19Valid(t *testing.T) {
	r, err := parseRules([]byte(rules19Doc), []string{"r-0001"}, map[string]bool{"app": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Attributes) != 1 || len(r.Aggregates) != 3 || len(r.Lists) != 1 || len(r.Causal[0].Outcomes[0].When) != 1 ||
		!r.Causal[0].Effects[0].TargetAll || !r.Causal[0].Effects[1].Respond.Until || len(r.Entities[0].ReadBy[0].List.Filters) != 1 {
		t.Fatalf("v1.9 members not kept: %+v", r)
	}
}

func TestRules19Invalid(t *testing.T) {
	for name, c := range map[string][2]string{
		"unknown customer attribute":           {`"customer":"segment"`, `"customer":"tier"`},
		"condition on the response":            {`"from":"req.headers","name":"x-channel"`, `"from":"resp.headers","name":"x-channel"`},
		"condition without values":             {`"in":["APP"]`, `"in":[]`},
		"condition with in and range":          {`"min":100,"max":500`, `"min":100,"max":500,"in":[1]`},
		"empty range":                          {`"min":100,"max":500`, `"min":500,"max":100`},
		"condition inside an array":            {`"path":"$.amount"`, `"path":"$.items[*].amount"`},
		"target_all with target_id":            {`"target_all":true,`, `"target_all":true,"target_id":"${x}",`},
		"target_all with a reference in where": {`"where":{"read":false},"set"`, `"where":{"read":"${x}"},"set"`},
		"target_all without set":               {`,"set":{"read":true},"after":"0s"},`, `,"after":"0s"},`},
		"until with times":                     {`"until":true`, `"until":true,"times":1`},
		"until with p":                         {`"until":true`, `"until":true,"p":0.5`},
		"target of a target_all":               {`{"id":"gate","respond"`, `{"id":"x","entity":"note","target":"all-read","set":{"read":false},"after":"0s"},{"id":"gate","respond"`},
		"attribute with one value":             {`{"GOLD":0.5,"STANDARD":0.5}`, `{"GOLD":1}`},
		"attribute shares":                     {`{"GOLD":0.5,"STANDARD":0.5}`, `{"GOLD":0.5,"STANDARD":0.6}`},
		"attribute in an array":                {`"path":"$.segment"`, `"path":"$.items[*].segment"`},
		"attribute of an unknown service":      {`"fields":[{"service":"app"`, `"fields":[{"service":"other"`},
		"aggregate of an unknown entity":       {`"count":{"entity":"note"`, `"count":{"entity":"nope"`},
		"aggregate with two kinds":             {`"count":{"entity":"note","where":{"read":false}}`, `"count":{"entity":"note"},"sum":{"entity":"note","field":"amount"}`},
		"aggregate delta of zero":              {`"by":1`, `"by":0`},
		"aggregate where with a reference":     {`"where":{"read":false}}}`, `"where":{"read":"${x}"}}}`},
		"list not an items path":               {`"path":"$.items[*]"},"list":{"page"`, `"path":"$.items"},"list":{"page"`},
		"list filter on the body":              {`"param":{"from":"req.query","name":"read"}`, `"param":{"from":"req.body","name":"read"}`},
	} {
		if !strings.Contains(rules19Doc, c[0]) {
			t.Fatalf("%s: fixture lacks %q", name, c[0])
		}
		if err := parse19(strings.Replace(rules19Doc, c[0], c[1], 1)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
