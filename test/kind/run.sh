#!/usr/bin/env bash
# Runs the kind integration test for the cluster scan (docs/spec/v0.2-cluster.md
# section 6). Requires docker, kind, helm and Go on PATH; used by
# .github/workflows/kind.yml. The Go test creates and deletes its own cluster, so
# there is nothing to clean up here.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec go test -tags kind -count=1 -v ./test/kind/
