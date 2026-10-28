package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/ivseb/traffic-twin/internal/config"
	"github.com/ivseb/traffic-twin/internal/store"
)

// runCompact converts a database created before incremental auto_vacuum to
// it, once, and compacts it. The rewrite needs about the database size of
// free disk space and blocks every writer: the core must be stopped.
func runCompact(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("compact", stderr)
	cfgPath := fs.String("config", os.Getenv(config.EnvConfigPath), "path of the core YAML configuration (storage.path is compacted; env "+config.EnvConfigPath+")")
	dbPath := fs.String("db", "", "path of the SQLite database (instead of -config)")
	stopped := fs.Bool("confirm-core-stopped", false, "required: tt-core is stopped (the rewrite blocks all writers and the disk needs room for a second copy)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: tt compact -confirm-core-stopped [-config core.yaml | -db tt-core.db]")
		fmt.Fprintln(stderr, "       one-time maintenance: switches an existing database to incremental auto_vacuum (VACUUM),")
		fmt.Fprintln(stderr, "       after which purges give the disk space back online. New databases need nothing.")
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	path := *dbPath
	if path == "" {
		if *cfgPath == "" {
			fmt.Fprintln(stderr, "tt compact: -db or -config is required")
			return 2
		}
		cfg, err := config.Load(*cfgPath, os.Environ())
		if err != nil {
			fmt.Fprintf(stderr, "tt compact: %v\n", err)
			return 1
		}
		path = cfg.Storage.Path
	}
	if !*stopped {
		fmt.Fprintln(stderr, "tt compact: refusing to run without -confirm-core-stopped (stop tt-core first)")
		return 2
	}
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "tt compact: %v\n", err)
		return 1
	}
	db, err := store.Open(ctx, path)
	if err != nil {
		fmt.Fprintf(stderr, "tt compact: %v\n", err)
		return 1
	}
	defer db.Close()
	before, err := db.Space(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "tt compact: %v\n", err)
		return 1
	}
	if before.AutoVacuum == store.AutoVacuumIncremental {
		// Already convertible online: just hand the free pages back.
		freed, err := db.Reclaim(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "tt compact: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "already incremental; reclaimed %d bytes\n", freed)
		return 0
	}
	if err := db.ConvertToIncrementalVacuum(ctx); err != nil {
		fmt.Fprintf(stderr, "tt compact: %v\n", err)
		return 1
	}
	after, _ := db.Space(ctx)
	fmt.Fprintf(stdout, "converted to incremental auto_vacuum: file %d -> %d bytes\n", before.FileBytes, after.FileBytes)
	return 0
}
