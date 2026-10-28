// Package miner discovers link keys, entities, cause-to-effect rules,
// alternative outcomes and batch rules from stored events, and keeps them as
// draft rules (tt.rules/v1, docs/spec/rules.md) for human review.
//
// Pipeline (docs/ARCHITECTURE.md 7.2), all on zone B data (tokens, shapes,
// kept enums):
//
//  1. Object-centric log (olog.go): objects are HMAC tokens typed by their
//     domain (from the signed policies through a [DomainResolver], or
//     guessed from field names and shared tokens), events are exchanges,
//     nested by trace. Exportable as OCEL 2.0 JSON ([ExportOCEL]).
//  2. Link keys (keys.go): correlation-condition discovery between service
//     messages; low-cardinality locations and evidence below k_min distinct
//     subjects are rejected.
//  3. Entities (entities.go): a domain minted by a write operation is an
//     entity; its records give relations, read_by (by id, by field, by
//     owner), hidden_when, scope/foreign and list counts. An id returned
//     again by later creations (the requesting member in every POST /loans)
//     existed before them: a reference, never an entity, never a warning.
//     Before that, relay.go recovers identifiers minted by an external call
//     and returned by the own service under another HMAC domain
//     (notificationId and the notifications API's message id).
//  4. Lifecycles (lifecycle.go): the state field, a precedence order of
//     states learned as declarative constraints (Hasse diagram), estimated
//     transition instants used only for magnitude hints (decision D1: no
//     measured delays are ever published).
//  5. Causal rules (causal.go): immediate effects in the cause's trace,
//     state chains, outcomes as exact counts over decided causes (observed
//     longer than the decision horizon, learned from the completions: twice
//     their 99th percentile, at least a minute, at most MinHorizon unless
//     the percentile is longer) with proportions.
//     Before them, updates (updates.go, rules v1.7): a write (or a read)
//     that cites an existing object and after which a field of the object
//     takes a value it explains (a literal, a copy of a clear member or of
//     an id of the request, a toggle) becomes a target_id + set rule; the
//     state transitions it explains leave the creation's outcomes, whose
//     remaining spontaneous steps are guarded with where.
//  6. Batch rules (batch.go): spontaneous changes concentrated at the same
//     clock hour every day → cron schedule and fraction.
//
// Teams (names.go, LoadGroups): with Deps.Groups the events of each group
// (the group of their source) are mined apart, so no entity, reference,
// relayed identifier or rule mixes two teams. An entity is the one a
// service creates in a domain within a group: the first creator keeps the
// bare name, a later one gets a qualified name (order-orders-api) and an
// id prefix of its own; the names are stored (miner_entity_names) and stay
// across runs (docs/spec/rules.md 2.7).
//
// Rule lifecycle (repo.go): drafts are stored in SQLite with ids stable
// across runs (by signature); drafts are refreshed in place keeping the
// reviewer's edits; approved and rejected rules are never modified by the
// miner (a changed structure becomes a new draft with supersedes); an
// approved rule that fails (confidence drop, no longer mined although its
// cause is seen) in Config.StaleRuns consecutive runs becomes stale, with the
// reason stored, and the [StalenessSink] is told; one bad run, or a run with
// too little traffic, never does. Nothing is ever approved automatically.
//
// Robustness to capture gaps (diag.go): objects first seen without their
// creation exchange (app restarts, retention cutoffs, sampling) are
// pre-existing, not evidence against an entity. An entity is accepted when
// enough objects were seen being created and the Wilson lower bound of the
// share of births reaches Config.MinBirthShare (default 0.6, lower than the
// MinShare of structural findings). Every run explains itself: Result.Diag
// holds one EntityDiag per candidate and one RuleDiag per rule, stored with
// the run and served by the status endpoint.
//
// The PM4Py library (AGPL) is not used; the algorithms are written from the
// public literature on web-service log correlation and declarative process
// constraints.
//
// # Wiring in cmd/tt
//
// In mountComponents (cmd/tt/wire.go), once the intake and the policy
// registry exist:
//
//	doms := miner.NewPolicyDomains()
//	for each signed compiled policy body: doms.AddBody(body)   // or Add(hash, *policy.Policy)
//	ms, err := miner.Mount(srv, miner.Deps{
//		DB:        db,                // the tt-core store (migrations registered in init)
//		Events:    in.Store(),        // *intake.Store
//		Domains:   doms,
//		Audit:     auditLog,
//		Staleness: driftAlerts,       // optional: implements miner.StalenessSink
//		Logger:    logger,
//	})
//	if err != nil { return err }
//	ms.Start(ctx, 6*time.Hour)        // scheduled mining job (window: Config.Window, 14 days)
//
// Mount serves /api/v1/rules (list, get, PATCH title/after, approve, reject)
// for rule-reviewer, operator and auditor; changes need rule-reviewer and are
// audited (rule.edit, rule.approve, rule.reject; the job writes rule.mine and
// rule.stale). The pack builder reads approved rules with
// ms.Repo().Document(ctx, miner.StatusApproved, now); the drift detector
// calls ms.Repo().MarkStale(ctx, id, "contract_changed", now). The event
// export job (POST /api/v1/events/export, format ocel2-json, role
// event-exporter) calls miner.ExportOCEL.
package miner
