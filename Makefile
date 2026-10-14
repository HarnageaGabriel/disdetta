BINARY_EXT := $(if $(filter Windows_NT,$(OS)),.exe,)
.PHONY: build test test-race lint vuln cover tidy fmt
build:
	go build -trimpath -o bin/disdetta$(BINARY_EXT) ./cmd/disdetta
test:
	go test ./...
test-race:
	go test -race ./...
lint:
	golangci-lint run ./...
vuln:
	govulncheck ./...
cover:
	go test -race -covermode=atomic -coverprofile=coverage.out ./...
tidy:
	go mod tidy
fmt:
	gofmt -w $$(find cmd internal -type f -name '*.go')
