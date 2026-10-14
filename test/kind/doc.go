// Package kind holds the kind-based integration test for the cluster scan
// (docs/spec/v0.2-cluster.md section 6). The test is behind the `kind` build
// tag, so the default build, vet and test runs never need docker, kind, helm or
// a network; run it with `go test -tags kind ./test/kind/` or
// `bash test/kind/run.sh`.
package kind
