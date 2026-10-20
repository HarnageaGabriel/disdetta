# Conventions

Mandatory for every contributor, human or AI agent.

- Layering: `cmd/` wires, `internal/cli` adapts, pure packages (`imageref`, `detect/*`, `diag`, `yamlx`, `plan`) do no I/O (depguard).
- Diagnostics are `diag.Diagnostic` with a registered stable `DSD-` code; wrap errors with `%w`.
- Deterministic output: no map iteration in output paths; sort explicitly. Time only via an injected clock.
- Concurrency: the walk stays sequential and decides the order; reading and parsing runs in a bounded worker pool (`DISDETTA_WORKERS`, one worker means sequential) and the results are merged in walk order, so the report never depends on the worker count; a panic in a worker is recovered and raised again on the goroutine of the caller, so a failed scan never returns a partial report.
- `context.Context` first for anything doing I/O; never `io.ReadAll` an unbounded body.
- Secrets never reach output, logs or reports; redact at the boundary (Helm values may hold passwords).
- Read-only: no write calls to clusters or repositories, ever.
- Tests: table-driven, `go-cmp`, goldens under `testdata/` updated with `-update`; every semantic case cites its `source`. Fuzz every parser.
- Catalog and mappings are data with a mandatory `source`. Unverified claims are marked `VERIFY:`.
- New third-party modules need a written reason in the PR.
- Never use `git stash`; use a temporary WIP commit.
