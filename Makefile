BINARY_EXT := $(if $(filter Windows_NT,$(OS)),.exe,)
VERSION_PKG := github.com/HarnageaGabriel/disdetta/internal/version
LDFLAGS := -s -w -X $(VERSION_PKG).Version=$${VERSION:-dev} -X $(VERSION_PKG).Commit=$${COMMIT:-unknown} -X $(VERSION_PKG).Date=$${DATE:-unknown}
.PHONY: build test test-race lint vuln cover tidy fmt
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/disdetta$(BINARY_EXT) ./cmd/disdetta
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
	sh scripts/cover-floors.sh
tidy:
	go mod tidy
fmt:
	gofmt -w $$(find cmd internal -type f -name '*.go')
