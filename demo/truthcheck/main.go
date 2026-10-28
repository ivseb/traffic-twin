// Command truthcheck reads /__truth from the carrier and the shop and checks
// that the produced counts match the ground truth within statistical
// tolerance, and that every outcome actually occurred. Exit code 1 on failure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/http"
	"os"
)

type carrierTruth struct {
	Config struct {
		Outcomes    map[string]float64 `json:"outcomes"`
		EtaPresence float64            `json:"eta_presence"`
		Faults      struct {
			UnavailableP float64 `json:"unavailable_p"`
			Status       int     `json:"status"`
		} `json:"faults"`
		Latency map[string]struct {
			MedianMs float64 `json:"median_ms"`
		} `json:"latency"`
		Batch struct {
			Fraction float64 `json:"fraction"`
		} `json:"batch"`
	} `json:"config"`
	Counts struct {
		Shipments     int                       `json:"shipments"`
		OutcomesDrawn map[string]int            `json:"outcomes_drawn"`
		Transitions   map[string]int            `json:"transitions"`
		DeliveredBy   map[string]int            `json:"delivered_by"`
		CurrentStatus map[string]int            `json:"current_status"`
		Eta           map[string]int            `json:"eta"`
		Requests      map[string]map[string]int `json:"requests"`
		LatencyMs     map[string]map[string]int `json:"latency_ms"`
		BatchRuns     []struct {
			Eligible int `json:"eligible"`
			Moved    int `json:"moved"`
		} `json:"batch_runs"`
	} `json:"counts"`
}

type shopTruth struct {
	Requests     map[string]map[string]int `json:"requests"`
	CarrierCalls map[string]map[string]int `json:"carrier_calls"`
	Presence     map[string]map[string]int `json:"presence"`
}

var failed int

func check(ok bool, name, format string, args ...any) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		failed++
	}
	fmt.Printf("  [%s] %-44s %s\n", mark, name, fmt.Sprintf(format, args...))
}

// binom checks k successes out of n against probability p, allowing
// z standard deviations (plus one unit for tiny samples).
func binom(name string, k, n int, p, z float64) {
	exp := float64(n) * p
	tol := z*math.Sqrt(float64(n)*p*(1-p)) + 1
	ratio := 0.0
	if n > 0 {
		ratio = float64(k) / float64(n)
	}
	check(math.Abs(float64(k)-exp) <= tol, name, "%d/%d = %.4f (expected %.4f, ±%.0f)", k, n, ratio, p, tol)
}

func fetch(url string, v any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func main() {
	carrierURL := flag.String("carrier", envOr("CARRIER_TRUTH_URL", "http://localhost:8080"), "carrier base URL")
	shopURL := flag.String("shop", envOr("SHOP_TRUTH_URL", "http://localhost:3000"), "shop base URL")
	minShipments := flag.Int("min-shipments", 500, "minimum sample size to judge")
	z := flag.Float64("z", 4, "tolerance in standard deviations")
	flag.Parse()

	var ct carrierTruth
	var st shopTruth
	if err := fetch(*carrierURL+"/__truth", &ct); err != nil {
		fmt.Println("truthcheck:", err)
		os.Exit(2)
	}
	if err := fetch(*shopURL+"/__truth", &st); err != nil {
		fmt.Println("truthcheck:", err)
		os.Exit(2)
	}
	c, cfg := ct.Counts, ct.Config
	n := c.Shipments

	fmt.Println("carrier: outcomes and state chain")
	check(n >= *minShipments, "enough shipments", "%d (min %d)", n, *minShipments)
	for _, o := range []string{"happy", "cancelled", "never_shipped"} {
		check(c.OutcomesDrawn[o] > 0, "outcome occurred: "+o, "%d", c.OutcomesDrawn[o])
		binom("outcome rate: "+o, c.OutcomesDrawn[o], n, cfg.Outcomes[o], *z)
	}
	for _, t := range []string{"PENDING->CREATED", "CREATED->IN_TRANSIT", "CREATED->CANCELLED", "IN_TRANSIT->DELIVERED"} {
		check(c.Transitions[t] > 0, "transition occurred: "+t, "%d", c.Transitions[t])
	}
	check(c.DeliveredBy["timer"] > 0, "delivered by per-shipment timer", "%d", c.DeliveredBy["timer"])
	check(c.DeliveredBy["batch"] > 0, "delivered by nightly batch", "%d", c.DeliveredBy["batch"])
	check(c.CurrentStatus["PENDING"] >= c.OutcomesDrawn["never_shipped"], "never_shipped stay PENDING",
		"pending=%d never_shipped=%d", c.CurrentStatus["PENDING"], c.OutcomesDrawn["never_shipped"])
	check(c.Transitions["CREATED->CANCELLED"] <= c.OutcomesDrawn["cancelled"], "cancellations only from cancelled outcome",
		"%d <= %d", c.Transitions["CREATED->CANCELLED"], c.OutcomesDrawn["cancelled"])

	fmt.Println("carrier: nightly batch")
	movedRuns, exact := 0, true
	for _, r := range c.BatchRuns {
		if r.Moved > 0 {
			movedRuns++
		}
		if r.Moved != int(math.Round(cfg.Batch.Fraction*float64(r.Eligible))) {
			exact = false
		}
	}
	check(movedRuns >= 1, "batch runs that moved shipments", "%d of %d runs", movedRuns, len(c.BatchRuns))
	check(exact, "batch moved exactly round(fraction*eligible)", "fraction=%.2f", cfg.Batch.Fraction)

	fmt.Println("carrier: contract facts")
	binom("eta presence per shipment", c.Eta["shipments_with_eta"], n, cfg.EtaPresence, *z)
	items := c.Eta["items_served"]
	itemRatio := float64(c.Eta["items_with_eta"]) / math.Max(1, float64(items))
	check(math.Abs(itemRatio-cfg.EtaPresence) <= 0.05, "eta presence per GET item (±0.05)", "%d/%d = %.4f", c.Eta["items_with_eta"], items, itemRatio)
	totalReq, unavailable := 0, 0
	for _, byStatus := range c.Requests {
		totalReq += sum(byStatus)
		unavailable += byStatus[fmt.Sprint(cfg.Faults.Status)]
	}
	check(unavailable > 0, "503 CARRIER_UNAVAILABLE occurred", "%d", unavailable)
	binom("503 rate over all carrier calls", unavailable, totalReq, cfg.Faults.UnavailableP, *z)
	for op, d := range cfg.Latency {
		p50 := float64(c.LatencyMs[op]["p50"])
		check(math.Abs(p50-d.MedianMs) <= 0.15*d.MedianMs, "latency p50 "+op, "%.0f ms (truth median %.0f ms)", p50, d.MedianMs)
	}

	fmt.Println("shop vs carrier consistency")
	accepted := st.CarrierCalls["POST /v1/shipments"]["202"]
	check(accepted == n, "every accepted shipment is one shop order", "shop saw 202=%d, carrier shipments=%d", accepted, n)
	check(c.Requests["POST /v1/shipments"]["202"] == n, "carrier 202 count == shipments", "%d", c.Requests["POST /v1/shipments"]["202"])
	for op, codes := range map[string][]string{
		"POST /orders":               {"201", "400", "409"},
		"GET /orders/{id}":           {"200", "404"},
		"GET /orders/{id}/shipment":  {"200", "404", "503"},
		"GET /customers/{id}/orders": {"200", "401", "403"},
	} {
		for _, code := range codes {
			check(st.Requests[op][code] > 0, fmt.Sprintf("shop %s -> %s", op, code), "%d", st.Requests[op][code])
		}
	}

	if failed > 0 {
		fmt.Printf("\ntruthcheck: %d check(s) FAILED\n", failed)
		os.Exit(1)
	}
	fmt.Println("\ntruthcheck: all checks passed")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
