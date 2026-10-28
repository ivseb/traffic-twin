# Go SDK: the package is part of the main module, the adapters are nested
# modules (they have their own go.mod, so `go test ./...` at the repository
# root does not run them).

MODULES := gin chi otelctx

.PHONY: test bench vet
test:
	cd ../.. && go test -race -count=1 ./sdk/go/...
	@for m in $(MODULES); do (cd $$m && go test -race -count=1 ./...) || exit 1; done

vet:
	cd ../.. && go vet ./sdk/go/...
	@for m in $(MODULES); do (cd $$m && go vet ./...) || exit 1; done

bench:
	go test . -run xxx -bench . -benchmem
