// Package world builds k-anonymous archetypes from stored events and
// generates synthetic worlds (world.jsonl, docs/spec/pack.md 5) from
// contracts, approved rules, archetypes and a seed.
//
// Profiles: every real subject (a token, zone B only) becomes a vector of
// generalized features (orders per month, active hours, error rate,
// primary operation, dominant outcome). Vectors are grouped into
// archetypes of at least k_min distinct subjects; smaller groups are merged
// into a near group or dropped. Tokens are never stored or returned.
//
// Worlds: the generator simulates the approved rules forward in time with
// its own seeded RNG (rules.md 6.1): invented customers (it/en names,
// reserved e-mail domains), entities created by the customers' creation
// operations, rule outcomes drawn by probability, interval delays drawn in
// [min, max], relations and target_id honoured, history rows with outcome,
// pending rows for effects due after t0. Same seed and inputs, same bytes.
// Every invented string is reported in Output.Synthetic: the provenance
// tags used by the publication gate.
//
// Inputs are small interfaces (ContractsSource, RulesSource, EventSource,
// OutcomeSource) implemented by internal/contract, the rule store/miner and
// internal/intake. See Mount for the admin API and the cmd/tt wiring.
package world
