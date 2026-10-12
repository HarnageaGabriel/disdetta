# Plan

Smallest useful command first: `disdetta scan .` lists every Bitnami reference with file and line. Everything else grows from it.

## Principles (family rules)
Go single binary, Apache-2.0, read-only, deterministic (no AI in the main path), no telemetry, secrets never in output, stable diagnostics `DSD-*` with docs pages, table output + versioned JSON + SARIF, documented exit codes, no shared library with sibling tools until three tools duplicate it.

## Severity (stable IDs)
- `DSD-SEV-1 allowInsecureImages`: `global.security.allowInsecureImages=true` -- workaround still active.
- `DSD-SEV-2 bitnamilegacy`: frozen images (`docker.io/bitnamilegacy/*` or mirror path).
- `DSD-SEV-3 bitnami`: `docker.io/bitnami/*` / `bitnamisecure/*` (now `latest`, dev only) and Bitnami chart sources (`charts.bitnami.com`, `bitnamicharts`).
Ordering rule: highest severity per finding wins; stateful components flagged `stateful: true` and sorted first.

## Milestones
- M0 (this repo scaffold): module, CLI skeleton (cobra), `diag` codes registry, CI, lint config, docs.
- M1 `scan` repo front: file walker, YAML parser with line numbers, image-reference parser, detectors (values, Chart.yaml deps, Flux, Argo CD, Dockerfile, CI), table + JSON output, golden tests, fuzz on parsers.
- M2 `scan` cluster front: client-go read-only; Pod images; Helm release Secrets (chart origin + values). Test with kind.
- M3 catalog as data (`catalog/*.yaml`, each entry with `source:`), JSON schema, validation tool, `stateful` priority.
- M4 `plan <release>`: values translation for the 5 charts where mapping is verified; unmapped list; migration checklist; goldens per plan.
- M5 SARIF, exit codes, GoReleaser, Homebrew, krew, Scorecard, coverage floors.

## Package layout (initial)
`cmd/disdetta`, `internal/cli`, `internal/diag`, `internal/imageref` (pure), `internal/scan/{repo,cluster}`, `internal/detect/*` (pure detectors over parsed docs), `internal/catalog` (embedded data), `internal/plan`, `internal/report/{table,json,sarif}`, `internal/yamlx` (YAML with positions). Pure packages do no I/O (depguard).

## Testing
Table tests citing the source of each case; `testdata/repos/{helm,flux,argocd}`; kind cluster test (CI only, build tag); golden file per generated plan; fuzz `imageref` and YAML position handling.

## Decisions to record (ADR)
0001 record decisions; 0002 diagnostics (`DSD-`); 0003 severity model; 0004 catalog-as-data with mandatory sources; 0005 no template rendering (unresolved values are reported, not guessed).
