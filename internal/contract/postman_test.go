package contract_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ivseb/traffic-twin/internal/auth"
	"github.com/ivseb/traffic-twin/internal/contract"
	"github.com/ivseb/traffic-twin/internal/contract/contracttest"
)

// Invented contract: a tiny orders API.
const miniOpenAPI = `{
 "openapi":"3.1.0","info":{"title":"orders-demo","version":"1"},
 "paths":{
  "/orders":{
   "post":{"summary":"Create an order","requestBody":{"content":{"application/json":{"schema":{"type":"object"},
      "examples":{"typical":{"value":{"items":[{"sku":"SKU-1","qty":2}]}},"minimal":{"value":{"items":[]}}}}}},
     "responses":{"201":{"description":"Created","content":{"application/json":{"examples":{"typical":{"value":{"id":"ORD-1"}}}}}},
                  "422":{"description":"Unprocessable Entity","content":{"application/json":{"examples":{"bad":{"value":{"error":{"code":"bad_sku"}}}}}}}}},
   "get":{"parameters":[{"name":"status","in":"query","required":false,"schema":{"enum":["open","closed"]}},
                        {"name":"page","in":"query","required":true,"schema":{"type":"integer"}}],
     "responses":{"200":{"description":"OK"}}}},
  "/orders/{id}":{
   "get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
                        {"name":"X-Trace","in":"header","required":false,"schema":{"type":"string"}}],
     "responses":{"200":{"description":"OK","content":{"application/json":{"examples":{"typical":{"value":{"id":"ORD-1","status":"open"}}}}}},"404":{"description":"Not Found"}}}},
  "/health":{"get":{"responses":{"200":{"description":"OK"}}}}
 }}`

func TestPostmanCollectionFromOpenAPI(t *testing.T) {
	out, err := contract.PostmanCollection([]byte(miniOpenAPI), contract.PostmanOptions{Name: "orders-demo"})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Info struct {
			Name   string `json:"name"`
			Schema string `json:"schema"`
		} `json:"info"`
		Variable []struct{ Key, Value string } `json:"variable"`
		Item     []struct {
			Name string `json:"name"`
			Item []struct {
				Name    string `json:"name"`
				Request struct {
					Method string `json:"method"`
					Header []struct{ Key, Value string }
					Body   *struct {
						Mode, Raw string
					} `json:"body"`
					URL struct {
						Raw   string `json:"raw"`
						Host  []string
						Path  []string
						Query []struct {
							Key      string
							Value    string
							Disabled bool
						}
						Variable []struct{ Key, Value string }
					} `json:"url"`
				} `json:"request"`
				Response []struct {
					Code int
					Body string
				} `json:"response"`
			} `json:"item"`
		} `json:"item"`
	}
	if err := json.Unmarshal(out, &c); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if c.Info.Schema != contract.PostmanSchemaURL || c.Info.Name != "orders-demo" {
		t.Fatalf("info: %+v", c.Info)
	}
	if len(c.Variable) != 1 || c.Variable[0].Key != "baseUrl" || c.Variable[0].Value != contract.DefaultPostmanBaseURL {
		t.Fatalf("variable: %+v", c.Variable)
	}
	// Folders by first path segment, in path order.
	if len(c.Item) != 2 || c.Item[0].Name != "/health" || c.Item[1].Name != "/orders" {
		t.Fatalf("folders: %+v", c.Item)
	}
	orders := c.Item[1].Item
	if len(orders) != 3 {
		t.Fatalf("orders requests: %d", len(orders))
	}
	// GET before POST; the required query parameter is enabled, the optional one is not.
	get, post, byIDReq := orders[0], orders[1], orders[2]
	if get.Name != "GET /orders" || post.Name != "POST /orders" || byIDReq.Name != "GET /orders/{id}" {
		t.Fatalf("order of requests: %q %q %q", get.Name, post.Name, byIDReq.Name)
	}
	if !strings.HasSuffix(get.Request.URL.Raw, "{{baseUrl}}/orders?page=1") {
		t.Errorf("raw url: %s", get.Request.URL.Raw)
	}
	for _, q := range get.Request.URL.Query {
		if q.Key == "status" && (!q.Disabled || q.Value != "open") || q.Key == "page" && q.Disabled {
			t.Errorf("query %+v", q)
		}
	}
	// The body is the typical example.
	if post.Request.Body == nil || post.Request.Body.Mode != "raw" || !strings.Contains(post.Request.Body.Raw, `"sku": "SKU-1"`) {
		t.Fatalf("body: %+v", post.Request.Body)
	}
	hasCT := false
	for _, h := range post.Request.Header {
		hasCT = hasCT || h.Key == "Content-Type" && h.Value == "application/json"
	}
	if !hasCT {
		t.Errorf("no Content-Type header: %+v", post.Request.Header)
	}
	if len(post.Response) != 2 || post.Response[0].Code != 201 || !strings.Contains(post.Response[0].Body, "ORD-1") {
		t.Errorf("saved responses: %+v", post.Response)
	}
	// Path parameters become :id variables.
	if byIDReq.Request.URL.Raw != "{{baseUrl}}/orders/:id" || len(byIDReq.Request.URL.Variable) != 1 || byIDReq.Request.URL.Variable[0].Key != "id" {
		t.Errorf("path variable: %+v", byIDReq.Request.URL)
	}
	if byIDReq.Request.URL.Host[0] != "{{baseUrl}}" {
		t.Errorf("host: %v", byIDReq.Request.URL.Host)
	}
}

func TestPostmanCollectionBaseURLAndErrors(t *testing.T) {
	out, err := contract.PostmanCollection([]byte(miniOpenAPI), contract.PostmanOptions{BaseURL: "https://mock.example.test"})
	if err != nil || !strings.Contains(string(out), `"https://mock.example.test"`) || !strings.Contains(string(out), `"name": "orders-demo"`) {
		t.Fatalf("base url / default name: %v %.200s", err, out)
	}
	if _, err := contract.PostmanCollection([]byte(`{"openapi":"3.1.0","paths":{}}`), contract.PostmanOptions{}); err == nil {
		t.Error("a document without paths must be refused")
	}
	if _, err := contract.PostmanCollection([]byte(`not json`), contract.PostmanOptions{}); err == nil {
		t.Error("garbage must be refused")
	}
}

func TestPostmanEndpoint(t *testing.T) {
	h := contracttest.New(t)
	h.DemoDay(day1, 700, contracttest.Variant{})
	h.Wait()
	now := day1.Add(48 * time.Hour)
	eng, err := contract.New(contract.DefaultConfig(), contract.Deps{DB: h.DB, Events: h.Store, Hints: contract.PolicyHints(h.Policy), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	api := contract.Handler(contract.APIDeps{Engine: eng})
	op := asRoles(api, auth.RoleOperator)

	rec := get(t, op, "GET", "/api/v1/contracts/shipping-ext/postman")
	if rec.Code != 200 {
		t.Fatalf("postman: %d %s", rec.Code, rec.Body)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="shipping-ext.postman_collection.json"` {
		t.Errorf("Content-Disposition: %q", cd)
	}
	var coll map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &coll); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if info := coll["info"].(map[string]any); info["schema"] != contract.PostmanSchemaURL || info["name"] != "shipping-ext" {
		t.Errorf("info: %v", info)
	}
	if !strings.Contains(rec.Body.String(), "{{baseUrl}}") || !strings.Contains(rec.Body.String(), "/v1/shipments") {
		t.Errorf("collection lacks the base URL variable or the carrier operations: %.300s", rec.Body)
	}

	// Without base_url: the service on a locally started mock (tt mock, port 8480).
	if !strings.Contains(rec.Body.String(), `"http://localhost:8480/__svc/shipping-ext"`) {
		t.Errorf("default base URL is not the local mock of the service: %.300s", rec.Body)
	}

	rec = get(t, op, "GET", "/api/v1/contracts/shipping-ext/postman?base_url=https://mock.example.test")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"https://mock.example.test"`) {
		t.Errorf("base_url: %d", rec.Code)
	}
	if rec = get(t, op, "GET", `/api/v1/contracts/shipping-ext/postman?base_url=a"b`); rec.Code != 422 {
		t.Errorf("a base_url with quotes: %d", rec.Code)
	}
	if rec = get(t, op, "GET", "/api/v1/contracts/nope/postman"); rec.Code != 404 {
		t.Errorf("unknown service: %d", rec.Code)
	}
	if rec = get(t, asRoles(api, auth.RolePublisher), "GET", "/api/v1/contracts/shipping-ext/postman"); rec.Code != 200 {
		t.Errorf("publisher reads contracts: %d", rec.Code)
	}
	if rec = get(t, asRoles(api, auth.RoleEventExporter), "GET", "/api/v1/contracts/shipping-ext/postman"); rec.Code != 403 {
		t.Errorf("event-exporter alone must be refused: %d", rec.Code)
	}
}
