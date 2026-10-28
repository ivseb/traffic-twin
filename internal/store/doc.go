// Package store persists tokenized events and derived artifacts in zone B,
// using SQLite through a pure-Go (cgo-free) driver (modernc.org/sqlite).
//
// The package provides the framework every other component builds on:
//
//   - [Open] opens (or creates, with file mode 0600) the database, enables WAL,
//     a busy timeout and foreign keys on every connection, then applies all
//     registered migrations.
//   - A migration registry: each package registers its own ordered migrations
//     under its own namespace with [Register] (usually from an init function),
//     so many packages can add tables without editing a shared file.
//     Migrations are plain SQL, applied in a transaction each, and recorded
//     with a SHA-256 checksum: editing an applied migration is detected and
//     refused at start-up.
//
// Conventions for migration authors:
//
//   - Namespace = package name (e.g. "audit", "auth", "fleet"); table and
//     index names start with "<namespace>_" so namespaces never collide.
//   - Versions start at 1 and are contiguous. Never edit or reorder an applied
//     migration: add a new one.
//   - Cross-namespace foreign keys require DependsOn so the referenced
//     namespace is migrated first.
//
// Encryption at rest is not provided by SQLite itself. Put the database on an
// encrypted volume (LUKS, dm-crypt, an encrypted cloud disk or an encrypted
// Kubernetes PersistentVolume). The database file, its WAL and SHM files and
// the parent directory are created with owner-only permissions.
package store
