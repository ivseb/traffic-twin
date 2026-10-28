// Package pack reads and verifies twin packs (tt.pack/v1, docs/spec/pack.md).
//
// It only reads: writing and signing packs belongs to the gate and keyguard.
// Load never returns data from a pack whose signature does not verify against
// a trusted key (TT_GATE_PUBKEYS), whose files do not match the manifest hashes,
// or that contains files the manifest does not list.
package pack
