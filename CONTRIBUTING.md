# Contributing

Thank you for improving disdetta. By contributing, you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Developer Certificate of Origin

All commits must carry a Developer Certificate of Origin sign-off. Sign commits
with:

```sh
git commit -s
```

The `Signed-off-by` line certifies the contribution under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).

## Governance

Roles, decisions, and releases are described in [docs/governance.md](docs/governance.md).
The release procedure is in [docs/releasing.md](docs/releasing.md).

## Development

Install Go 1.26+, `golangci-lint`, and `govulncheck`, then run:

```sh
make tidy
make fmt
make test
make lint
make vuln
```

`make build` writes the CLI to `bin/disdetta`. `make cover` writes
`coverage.out`.

Keep packages small, pass `context.Context` explicitly, wrap errors with useful
context, add table-driven tests, and preserve stdout for command data. Logs and
diagnostics belong on stderr. New exported identifiers need doc comments.

## Provenance rule

Every value mapping and every catalog entry must cite a public source in its
`source:` field. A key without a certain mapping is listed as unmapped, never
guessed. Contributions without verifiable provenance are not accepted.
