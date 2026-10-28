package packtest

import "strings"

// DemoSpec returns the demo carrier pack (demo/GROUND_TRUTH.md): an order on
// shop-api answers with the shipmentId of the shipment that rule r-0007
// creates (PENDING, invisible) at once, and then moves it through CREATED,
// IN_TRANSIT and DELIVERED (or CANCELLED, or never) with delays drawn from
// ranges; r-0008 does the same when the mock plays the carrier; r-0012 delivers
// 60% of the in-transit shipments every night. shipping-ext answers 503 on 1%
// of its calls. The world has three customers, three orders with their
// shipments, and pending effects at t0.
func DemoSpec() Spec { return demoSpec(false) }

// ExactDemoSpec is DemoSpec with degenerate ranges (min == max): created after
// 5m, in transit 4h later, delivered 2d later, cancelled 1h after creation,
// so tests know every instant. The ranges still draw from the generator.
func ExactDemoSpec() Spec { return demoSpec(true) }

func demoSpec(exact bool) Spec {
	files := map[string][]byte{
		"contracts/shop-api.openapi.json":     Canon(shopContract),
		"contracts/shipping-ext.openapi.json": Canon(carrierContract),
		"rules.json":                          Canon(demoRules(exact)),
		"faults.json":                         Canon(demoFaults),
		"gate-report.json":                    Canon(demoGateReport),
		"scenarios.json":                      Canon(demoScenarios),
		"world.jsonl":                         demoWorld(),
	}
	manifest := map[string]any{
		"format":     "tt.pack/v1",
		"pack_id":    "pk-20261019-0001",
		"created_at": "2026-10-19T03:20:00Z",
		"tt_version": "0.1.0",
		"seed":       JSON("42"),
		"k_min":      20,
		"source": JSON(`{"window":{"from":"2026-10-05T00:00:00Z","to":"2026-10-19T00:00:00Z"},
			"policies":[{"id":"p-shop","version":7}]}`),
		"services": JSON(`[
			{"name":"shop-api","contract":"contracts/shop-api.openapi.json","upstream_alias":"shop"},
			{"name":"shipping-ext","contract":"contracts/shipping-ext.openapi.json","upstream_alias":"carrier"}]`),
		"rules":       JSON(`{"path":"rules.json","approved":["r-0007","r-0008","r-0012"]}`),
		"world":       JSON(`{"path":"world.jsonl","customers":3}`),
		"faults":      "faults.json",
		"gate_report": "gate-report.json",
		"scenarios":   "scenarios.json",
	}
	return Spec{Manifest: manifest, Files: files}
}

func demoWorld() []byte {
	order := func(id, cust, shipment, created string) any {
		return JSON(`{"customer_id":"` + cust + `","entity":"order","id":"` + id + `","state":{"createdAt":"` + created +
			`","currency":"EUR","email":"giulia.neri@example.com","id":"` + id + `","items":[{"qty":1,"sku":"SKU-AAAA0001"}],"shipmentId":"` +
			shipment + `","status":"CONFIRMED","total":19.9},"type":"entity"}`)
	}
	ship := func(id, cust, order, status string) any {
		return JSON(`{"customer_id":"` + cust + `","entity":"shipment","id":"` + id + `","state":{"orderId":"` + order +
			`","service":"STANDARD","shipmentId":"` + id + `","status":"` + status + `"},"type":"entity"}`)
	}
	hist := func(id, order, at string, seq int, effect, status string) any {
		n := map[int]string{1: "1", 2: "2", 3: "3"}[seq]
		return JSON(`{"at":"` + at + `","effect_id":"` + effect + `","entity":"shipment","id":"` + id + `","outcome":"happy","rule_id":"r-0007","seq":` + n +
			`,"state":{"orderId":"` + order + `","shipmentId":"` + id + `","status":"` + status + `"},"type":"history"}`)
	}
	pend := func(due, seq, effect, id, cust string) any {
		return JSON(`{"customer_id":"` + cust + `","due_offset_s":` + due + `,"effect_id":"` + effect + `","entity":"shipment","id":"` + id +
			`","outcome":"happy","rule_id":"r-0007","seq":` + seq + `,"type":"pending"}`)
	}
	return Lines(
		JSON(`{"format":"tt.world/v1","seed":42,"t0":"2026-10-19T00:00:00Z","type":"meta"}`),
		JSON(`{"archetype":"arch-01","id":"CUS-SYN-0001","profile":{"email":"anna.rossi@example.com","name":"Anna Rossi"},"type":"customer"}`),
		JSON(`{"archetype":"arch-03","id":"CUS-SYN-0007","profile":{"email":"giulia.neri@example.com","name":"Giulia Neri"},"type":"customer"}`),
		JSON(`{"archetype":"arch-03","id":"CUS-SYN-0009","profile":{"email":"marco.bianchi@example.com","name":"Marco Bianchi"},"type":"customer"}`),
		order("ORD-SYN-0042", "CUS-SYN-0007", "SHP-SYN-0091", "2026-10-18T09:00:00Z"),
		order("ORD-SYN-0060", "CUS-SYN-0009", "SHP-SYN-0092", "2026-10-18T20:00:00Z"),
		order("ORD-SYN-0070", "CUS-SYN-0001", "SHP-SYN-0093", "2026-10-18T23:55:00Z"),
		ship("SHP-SYN-0091", "CUS-SYN-0007", "ORD-SYN-0042", "IN_TRANSIT"),
		ship("SHP-SYN-0092", "CUS-SYN-0009", "ORD-SYN-0060", "IN_TRANSIT"),
		ship("SHP-SYN-0093", "CUS-SYN-0001", "ORD-SYN-0070", "PENDING"),
		hist("SHP-SYN-0091", "ORD-SYN-0042", "2026-10-18T09:00:00Z", 1, "shipment-requested", "PENDING"),
		hist("SHP-SYN-0091", "ORD-SYN-0042", "2026-10-18T09:06:00Z", 2, "shipment-created", "CREATED"),
		hist("SHP-SYN-0091", "ORD-SYN-0042", "2026-10-18T12:30:00Z", 3, "shipment-in-transit", "IN_TRANSIT"),
		hist("SHP-SYN-0092", "ORD-SYN-0060", "2026-10-18T20:00:00Z", 1, "shipment-requested", "PENDING"),
		hist("SHP-SYN-0092", "ORD-SYN-0060", "2026-10-18T20:05:00Z", 2, "shipment-created", "CREATED"),
		hist("SHP-SYN-0092", "ORD-SYN-0060", "2026-10-18T22:00:00Z", 3, "shipment-in-transit", "IN_TRANSIT"),
		hist("SHP-SYN-0093", "ORD-SYN-0070", "2026-10-18T23:55:00Z", 1, "shipment-requested", "PENDING"),
		pend("300", "1", "shipment-created", "SHP-SYN-0093", "CUS-SYN-0001"),
		pend("3600", "2", "shipment-delivered", "SHP-SYN-0092", "CUS-SYN-0009"),
		pend("7500", "3", "shipment-in-transit", "SHP-SYN-0093", "CUS-SYN-0001"),
		pend("90000", "4", "shipment-delivered", "SHP-SYN-0093", "CUS-SYN-0001"),
	)
}

const demoGateReport = `{
  "format":"tt.gate-report/v1","pack_id":"pk-20261019-0001","verdict":"pass","k_min":20,
  "checks":[
    {"id":"provenance","status":"pass","findings":[],"by":"tt-core"},
    {"id":"reverse-hmac","status":"pass","findings":[],"strings_checked":10,"by":"keyguard"},
    {"id":"pii-detectors","status":"pass","findings":[],"by":"tt-core"},
    {"id":"k-thresholds","status":"pass","findings":[],"by":"tt-core"}]}`

const demoScenarios = `{
  "format":"tt.scenarios/v1",
  "scenarios":[
    {"id":"shipment-cancelled","name":"Shipment cancelled","description":"The shipment is cancelled after creation.",
     "customer":"CUS-SYN-0007","seed":7,"outcomes":[{"rule":"r-0007","outcome":"cancelled","times":2}]},
    {"id":"tracking-down","name":"Carrier unavailable","archetype":"arch-03",
     "faults":{"mode":"custom","rules":[{"service":"shipping-ext","op":"GET /v1/shipments","status":503,"p":1,"times":1}]}}]}`

const demoFaults = `{
  "format":"tt.faults/v1",
  "ops":[
    {"service":"shipping-ext","op":"GET /v1/shipments",
     "statuses":[{"status":503,"p":0.01,"example":"upstream-unavailable"}],
     "latency_ms":{"p50":80,"p95":215,"p99":323,"lognormal":{"median":80,"sigma":0.6}}},
    {"service":"shipping-ext","op":"POST /v1/shipments",
     "statuses":[{"status":503,"p":0.01,"example":"upstream-unavailable"}],
     "latency_ms":{"p50":140,"p95":318,"p99":448,"lognormal":{"median":140,"sigma":0.5}}},
    {"service":"shop-api","op":"GET /orders/{id}/shipment",
     "statuses":[{"status":503,"p":0.01,"example":"tracking-unavailable"}]}]}`

// demoRules renders rules.json; exact collapses every delay range to a point.
func demoRules(exact bool) string {
	d := map[string]string{
		"@CREATED@":   `{"min":"2m","max":"10m"}`,
		"@TRANSIT@":   `{"min":"1h","max":"6h"}`,
		"@DELIVERED@": `{"min":"6h","max":"36h"}`,
		"@CANCELLED@": `{"min":"30m","max":"4h"}`,
	}
	if exact {
		d = map[string]string{
			"@CREATED@":   `{"min":"5m","max":"5m"}`,
			"@TRANSIT@":   `{"min":"4h","max":"4h"}`,
			"@DELIVERED@": `{"min":"2d","max":"2d"}`,
			"@CANCELLED@": `{"min":"1h","max":"1h"}`,
		}
	}
	var pairs []string
	for k, v := range d {
		pairs = append(pairs, k, v)
	}
	return strings.NewReplacer(pairs...).Replace(rulesTemplate)
}

const rulesTemplate = `{
  "format":"tt.rules/v1",
  "entities":[
    {"name":"order","service":"shop-api","id_domain":"order","id_field":"id","id_prefix":"ORD-SYN-",
     "created_by":{"op":"POST /orders","id":{"from":"resp.body","path":"$.id"},
                   "state":{"from":"req.body","path":"$"},
                   "defaults":{"status":"CONFIRMED","currency":"EUR","total":19.9}},
     "relations":[{"field":"shipmentId","entity":"shipment"}],
     "read_by":[
       {"op":"GET /orders/{id}","by":{"from":"req.path","name":"id"},"at":{"from":"resp.body","path":"$"},
        "scope":"owner","foreign":"not_found","not_found_example":"order-not-found"},
       {"op":"GET /customers/{id}/orders","by":{"from":"req.path","name":"id","owner":true},
        "at":{"from":"resp.body","path":"$.items[*]"},"scope":"owner","foreign":"forbidden","foreign_example":"forbidden",
        "list":{"count":"$.count","order_by":"createdAt","order":"asc",
                "limit":{"from":"req.query","name":"limit"},"offset":{"from":"req.query","name":"offset"},
                "default_limit":50,"max_limit":100}}]},
    {"name":"shipment","service":"shipping-ext","id_domain":"shipment","id_field":"shipmentId","id_prefix":"SHP-SYN-",
     "created_by":{"op":"POST /v1/shipments","id":{"from":"resp.body","path":"$.shipmentId"},
                   "state":{"from":"req.body","path":"$"},"defaults":{"status":"PENDING"}},
     "relations":[{"field":"orderId","entity":"order"}],
     "read_by":[
       {"op":"GET /v1/shipments","by":{"from":"req.query","name":"orderId","field":"orderId"},
        "at":{"from":"resp.body","path":"$.items[*]"},"hidden_when":{"status":"PENDING"}},
       {"op":"GET /orders/{id}/shipment","service":"shop-api","by":{"from":"req.path","name":"id","field":"orderId"},
        "at":{"from":"resp.body","path":"$"},"hidden_when":{"status":"PENDING"},
        "scope":"owner","foreign":"not_found","foreign_example":"order-not-found","not_found_example":"shipment-not-found"}]}],
  "rules":[
    {"id":"r-0007","kind":"causal","status":"approved","title":"An order creates a shipment",
     "cause":{"service":"shop-api","op":"POST /orders","when":{"status":[201]},
              "bind":{"order":{"from":"resp.body","path":"$.id"}}},
     "effects":[
       {"id":"shipment-requested","entity":"shipment","create":{"orderId":"${order}","status":"PENDING"},"after":"0s"},
       {"id":"order-linked","entity":"order","target_id":"${order}","set":{"shipmentId":"${effect:shipment-requested}"},
        "after_effect":"shipment-requested","after":"0s"},
       {"id":"shipment-created","entity":"shipment","target":"shipment-requested","set":{"status":"CREATED"},
        "after_effect":"shipment-requested","after":@CREATED@},
       {"id":"shipment-in-transit","entity":"shipment","target":"shipment-requested","set":{"status":"IN_TRANSIT"},
        "after_effect":"shipment-created","after":@TRANSIT@},
       {"id":"shipment-delivered","entity":"shipment","target":"shipment-requested","set":{"status":"DELIVERED"},
        "after_effect":"shipment-in-transit","after":@DELIVERED@},
       {"id":"shipment-cancelled","entity":"shipment","target":"shipment-requested","set":{"status":"CANCELLED","cancelReason":"ADDRESS_UNREACHABLE"},
        "after_effect":"shipment-created","after":@CANCELLED@}],
     "outcomes":[
       {"name":"happy","p":0.93,"effects":["shipment-requested","order-linked","shipment-created","shipment-in-transit","shipment-delivered"]},
       {"name":"cancelled","p":0.04,"effects":["shipment-requested","order-linked","shipment-created","shipment-cancelled"]},
       {"name":"never-shipped","p":0.03,"effects":["shipment-requested","order-linked"]}],
     "evidence":{"counts":{"causes":4120,"distinct_subjects":1310,"outcomes":{"happy":3832,"cancelled":165,"never-shipped":123}},
       "keys":[{"domain":"order","from":{"service":"shop-api","op":"POST /orders","at":{"from":"resp.body","path":"$.id"}},
                "to":{"service":"shipping-ext","op":"POST /v1/shipments","at":{"from":"req.body","path":"$.orderId"}},"matches":4120}]},
     "review":{"by":["a","b"],"at":"2026-10-19T03:00:00Z","note":""}},
    {"id":"r-0008","kind":"causal","status":"approved","title":"A shipment asked to the carrier becomes visible and is delivered",
     "cause":{"service":"shipping-ext","op":"POST /v1/shipments","when":{"status":[202]},
              "bind":{"shipment":{"from":"resp.body","path":"$.shipmentId"}}},
     "effects":[
       {"id":"shipment-created","entity":"shipment","target_id":"${shipment}","set":{"status":"CREATED"},"after":@CREATED@},
       {"id":"shipment-in-transit","entity":"shipment","target":"shipment-created","set":{"status":"IN_TRANSIT"},
        "after_effect":"shipment-created","after":@TRANSIT@},
       {"id":"shipment-delivered","entity":"shipment","target":"shipment-created","set":{"status":"DELIVERED"},
        "after_effect":"shipment-in-transit","after":@DELIVERED@},
       {"id":"shipment-cancelled","entity":"shipment","target":"shipment-created","set":{"status":"CANCELLED","cancelReason":"DAMAGED_IN_WAREHOUSE"},
        "after_effect":"shipment-created","after":@CANCELLED@}],
     "outcomes":[
       {"name":"happy","p":0.93,"effects":["shipment-created","shipment-in-transit","shipment-delivered"]},
       {"name":"cancelled","p":0.04,"effects":["shipment-created","shipment-cancelled"]},
       {"name":"never-shipped","p":0.03,"effects":[]}],
     "evidence":{"counts":{"causes":4120,"distinct_subjects":1310,"outcomes":{"happy":3832,"cancelled":165,"never-shipped":123}}}},
    {"id":"r-0012","kind":"batch","status":"approved","title":"Nightly delivery consolidation",
     "schedule":"0 2 * * *","entity":"shipment","where":{"status":"IN_TRANSIT"},"set":{"status":"DELIVERED"},"fraction":0.6,
     "evidence":{"counts":{"runs":14,"entities_changed":9800}}}]}`

const errorSchema = `{"type":"object","required":["error"],"properties":{"error":{"type":"object","required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"},"field":{"type":"string"},"retryable":{"type":"boolean"}}}}}`

const shopContract = `{
  "openapi":"3.1.0","info":{"title":"shop-api","version":"1.0.0"},
  "paths":{
    "/orders":{"post":{"operationId":"createOrder",
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/OrderRequest"}}}},
      "responses":{
        "201":{"description":"created","x-tt-frequency":0.96,
          "headers":{"Location":{"schema":{"type":"string"},"example":"/orders/{id}"}},
          "content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}},
        "400":{"description":"invalid","x-tt-frequency":0.03,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"validation-error":{"value":{"error":{"code":"VALIDATION_ERROR","message":"invalid request","field":"email"}}}}}}},
        "503":{"description":"unavailable","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"carrier-unavailable":{"value":{"error":{"code":"CARRIER_UNAVAILABLE","message":"carrier unavailable"}}}}}}}}}},
    "/orders/{id}":{"get":{"operationId":"getOrder",
      "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
      "responses":{
        "200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Order"}}}},
        "404":{"description":"not found","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"order-not-found":{"value":{"error":{"code":"ORDER_NOT_FOUND","message":"order not found"}}}}}}}}}},
    "/orders/{id}/shipment":{"get":{"operationId":"getOrderShipment",
      "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
      "responses":{
        "200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/TrackedShipment"}}}},
        "404":{"description":"not found","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"shipment-not-found":{"value":{"error":{"code":"SHIPMENT_NOT_FOUND","message":"shipment not found"}}},
                      "order-not-found":{"value":{"error":{"code":"ORDER_NOT_FOUND","message":"order not found"}}}}}}},
        "503":{"description":"unavailable","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"tracking-unavailable":{"value":{"error":{"code":"TRACKING_UNAVAILABLE","message":"tracking unavailable","retryable":true}}}}}}}}}},
    "/customers/{id}/orders":{"get":{"operationId":"listCustomerOrders",
      "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},
                    {"name":"limit","in":"query","schema":{"type":"integer","minimum":1}},
                    {"name":"offset","in":"query","schema":{"type":"integer","minimum":0}}],
      "responses":{
        "200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/OrderList"}}}},
        "403":{"description":"forbidden","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
          "examples":{"forbidden":{"value":{"error":{"code":"FORBIDDEN","message":"not your orders"}}}}}}}}}},
    "/ping":{"get":{"operationId":"ping","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","required":["status","at"],
      "properties":{"status":{"type":"string","enum":["up"]},"at":{"type":"string","format":"date-time"}}},
      "example":{"status":"up","at":"2026-01-01T00:00:00Z"}}}}}}}
  },
  "components":{"schemas":{
    "Error":` + errorSchema + `,
    "OrderRequest":{"type":"object","required":["items","email"],"properties":{
      "items":{"type":"array","minItems":1,"items":{"type":"object","required":["sku","qty"],"properties":{
        "sku":{"type":"string"},"qty":{"type":"integer","minimum":1,"maximum":3}}}},
      "email":{"type":"string","x-tt-value":{"kind":"shape","format":"email"}},
      "phone":{"type":"string"},
      "note":{"type":"string"},
      "giftWrap":{"type":"boolean"}}},
    "Order":{"type":"object","required":["id","customerId","status","items","currency","total","email","shipmentId","createdAt"],"properties":{
      "id":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
      "customerId":{"type":["string","null"]},
      "status":{"type":"string","enum":["CREATED","CONFIRMED"]},
      "items":{"type":"array","items":{"type":"object","properties":{"sku":{"type":"string"},"qty":{"type":"integer"}}}},
      "currency":{"type":"string"},
      "total":{"type":"number"},
      "email":{"type":"string"},
      "phone":{"type":"string"},
      "note":{"type":"string"},
      "giftWrap":{"type":"boolean"},
      "shipmentId":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
      "createdAt":{"type":"string","format":"date-time"}}},
    "OrderSummary":{"type":"object","required":["id","status","total","currency","createdAt"],"properties":{
      "id":{"type":"string"},"status":{"type":"string"},"total":{"type":"number"},"currency":{"type":"string"},
      "createdAt":{"type":"string","format":"date-time"}}},
    "OrderList":{"type":"object","required":["customerId","count","items"],"properties":{
      "customerId":{"type":["string","null"]},
      "count":{"type":"integer"},
      "items":{"type":"array","items":{"$ref":"#/components/schemas/OrderSummary"}}}},
    "TrackedShipment":{"type":"object","required":["orderId","shipmentId","status","updatedAt"],"properties":{
      "orderId":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
      "shipmentId":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
      "status":{"type":"string","enum":["CREATED","IN_TRANSIT","DELIVERED","CANCELLED"]},
      "eta":{"type":"string","format":"date-time"},
      "cancelReason":{"type":"string"},
      "updatedAt":{"type":"string","format":"date-time"}}}
  }}}`

const carrierContract = `{
  "openapi":"3.1.0","info":{"title":"shipping-ext","version":"1.0.0"},
  "paths":{
    "/v1/shipments":{
      "post":{"operationId":"createShipment",
        "requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ShipmentRequest"}}}},
        "responses":{
          "202":{"description":"accepted","x-tt-frequency":0.99,
            "headers":{"Location":{"schema":{"type":"string"},"example":"/v1/shipments/{id}"}},
            "content":{"application/json":{"schema":{"$ref":"#/components/schemas/ShipmentAccepted"}}}},
          "400":{"description":"invalid","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
            "examples":{"invalid-request":{"value":{"error":{"code":"INVALID_REQUEST","message":"invalid request","field":"orderId"}}}}}}},
          "409":{"description":"exists","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
            "examples":{"shipment-exists":{"value":{"error":{"code":"SHIPMENT_EXISTS","message":"shipment exists"}}}}}}},
          "503":{"description":"unavailable","x-tt-frequency":0.01,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
            "examples":{"upstream-unavailable":{"value":{"error":{"code":"CARRIER_UNAVAILABLE","message":"carrier unavailable"}}}}}}}}},
      "get":{"operationId":"listShipments",
        "x-tt-latency-ms":{"p50":80,"p95":215,"p99":323},
        "parameters":[{"name":"orderId","in":"query","required":true,"schema":{"type":"string"}},
          {"name":"host","in":"header","required":true,"schema":{"type":"string"}},
          {"name":"user-agent","in":"header","required":true,"schema":{"type":"string"}}],
        "responses":{
          "200":{"description":"ok","x-tt-frequency":0.99,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ShipmentList"}}}},
          "503":{"description":"unavailable","x-tt-frequency":0.01,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"},
            "examples":{"upstream-unavailable":{"value":{"error":{"code":"CARRIER_UNAVAILABLE","message":"carrier unavailable"}}}}}}}}}}
  },
  "components":{"schemas":{
    "Error":` + errorSchema + `,
    "ShipmentRequest":{"type":"object","required":["orderId","service","parcels","recipient","address"],"properties":{
      "orderId":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
      "service":{"type":"string","enum":["STANDARD","EXPRESS"]},
      "parcels":{"type":"integer","minimum":1},
      "recipient":{"type":"object","required":["fullName","email"],"properties":{"fullName":{"type":"string"},"email":{"type":"string"},"phone":{"type":"string"}}},
      "address":{"type":"object","required":["line1","city","postcode","country"],"properties":{
        "line1":{"type":"string"},"line2":{"type":"string"},"city":{"type":"string"},"postcode":{"type":"string"},"country":{"type":"string"}}}}},
    "ShipmentAccepted":{"type":"object","required":["shipmentId","orderId","status","service","createdAt"],"properties":{
      "shipmentId":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
      "orderId":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
      "status":{"type":"string","enum":["PENDING"]},
      "service":{"type":"string","enum":["STANDARD","EXPRESS"]},
      "createdAt":{"type":"string","format":"date-time"}}},
    "ShipmentList":{"type":"object","required":["items"],"properties":{"items":{"type":"array","items":{"$ref":"#/components/schemas/Shipment"}}}},
    "Shipment":{"type":"object","required":["shipmentId","orderId","status","updatedAt"],"properties":{
      "shipmentId":{"type":"string","x-tt-value":{"kind":"id","domain":"shipment"}},
      "orderId":{"type":"string","x-tt-value":{"kind":"id","domain":"order"}},
      "status":{"type":"string","enum":["CREATED","IN_TRANSIT","DELIVERED","CANCELLED"]},
      "service":{"type":"string","enum":["STANDARD","EXPRESS"]},
      "eta":{"type":"string","format":"date-time"},
      "cancelReason":{"type":"string"},
      "updatedAt":{"type":"string","format":"date-time"}}}
  }}}`
