# Plan

Smallest useful command first: `disdetta scan .` lists every Bitnami reference with file and line. Everything else grows from it.

Revision 2 (2026-10-14): revised after the scan MVP review and a second look at the study notes. Changes are listed in [Review of revision 1](#review-of-revision-1).

## Decisions (2026-10-14)
After an external audit of the repository (ChatGPT, on `main` only) and the scan MVP review:
1. v0.1.0 contract fixed in [spec/v0.1.md](spec/v0.1.md): rule IDs by category (`DSD-CFG-*`, `DSD-IMG-*`, `DSD-CHT-*`), scanner diagnostics `DSD-SCN-*`, separate severity / confidence / migration impact, fingerprints, summary, exit code 3 for incomplete scans. The never-released `DSD-001..006` codes are dropped. This supersedes the severity model below.
2. Severity stays signal-based (high/medium/low). No CVE or exposure scoring: it would need external data and break determinism.
3. `plan`: PostgreSQL -> CloudNativePG is the first plan verified end to end. Redis/Valkey, Kafka, MongoDB, Keycloak ship as route + checklist, and gain value mappings only as each mapping is verified.
4. The repository stays private until the v0.1.0 release; `go install` in the README works from then on.
5. Cluster scan uses a flag (`scan --cluster`), not a subcommand, so a directory named `cluster` stays scannable.
6. Later, when the cluster scan lands: group evidence by component and release (one operational problem, N evidences), using plain Go structures, no graph database.
7. A threat model document (`docs/threat-model.md`) before the cluster scan: Helm Secret decoding, decompression limits, filesystem boundaries, minimal RBAC.

## Principles (family rules)
Go single binary, Apache-2.0, read-only, deterministic (no AI in the main path), no telemetry, secrets never in output, stable diagnostics `DSD-*` with docs pages, table output + versioned JSON + SARIF, documented exit codes, no shared library with sibling tools until three tools duplicate it.

## Severity model
Stable IDs (ADR 0003). One finding gets the highest applicable severity.
- `DSD-SEV-1 allowInsecureImages`: `global.security.allowInsecureImages=true` -- the workaround is still active.
- `DSD-SEV-2 bitnamilegacy`: frozen images (`bitnamilegacy/*`, also under a mirror registry).
- `DSD-SEV-3 bitnami`: `bitnami/*` and `bitnamisecure/*` images, Bitnami chart sources.

Orthogonal attributes (not severities): `stateful` (PostgreSQL, Redis, Valkey, Kafka, MongoDB, Keycloak), `pull-risk` (`bitnami/*` with a non-`latest` tag: the versioned image is gone from that path, so a fresh pull can fail even though the finding is "only" SEV-3), `unresolved` (templated reference), `mirror` (registry is not docker.io). Sort: stateful, severity, path, line. VERIFY: whether `pull-risk` should raise the severity; decide with a first real-world sample.

## Milestones (revised order)
- M0 scaffold: module, CLI skeleton, `diag` registry, CI, lint, docs. **Done** (PR feat/scan-mvp).
- M1a `scan` repo, first cut + security hardening. **Done**, in review.
- M1b `scan` repo coverage: partial templates (`bitnami/redis:{{ .tag }}` still classified), `${VAR}` in Dockerfile/CI, `ARG` defaults, `COPY --from`, line continuations, GitLab/Azure/Kustomize/compose, YAML aliases, `--fail-on <severity>`, baseline/ignore file with expiry. *Before any cluster work: false negatives here undermine trust in everything else.*
- M1c Real-world corpus: anonymized fixtures from public GitOps repositories (license-checked), measuring recall. Prerequisite for claiming coverage.
- M2 `scan` cluster, read-only, three tiers by privilege:
  1. workload pod templates (Deployment, StatefulSet, DaemonSet, Job, CronJob), not only running Pods, so scaled-to-zero and CronJobs are not missed; `status.imageID` to expose mirrors;
  2. Helm release metadata from labels (`owner=helm`) and chart origin;
  3. **opt-in** (`--read-helm-secrets`): decode release Secrets for chart origin and user values. These Secrets can contain credentials: redact at decode time, never print values, document the RBAC needed.
- M3 catalog as data: `catalog/*.yaml`, JSON schema, validator, every entry and mapping with `source:` and `verified:` date; mappings keyed by **Bitnami chart major version range** (keys change between majors); per-chart maturity label (`verified` / `partial` / `route-only`).
- M4 `plan`: see below.
- M5 SARIF (rule id = `DSD-*`), exit-code doc, GoReleaser, Homebrew, krew, Scorecard, coverage floors, published JSON schema.

## `plan` design
- **Input.** `plan` needs the user's values, which are not in the chart. Two sources: `--from-repo <path> --release <name>` (HelmRelease / Argo / values file) and `--from-cluster <release>` (needs the opt-in Secret read). Without values it can only emit the generic route and checklist.
- **Output.** `values.<target>.yaml`, `unmapped.json`/table (every key with the reason: no mapping, ambiguous, dropped by design), `checklist.md`. Stdout stays data; nothing is applied.
- **Mapping kinds** (all data, all with a source): `rename`, `constant`, `drop` (with documented reason), `manual` (user decision required). Bitnami `resourcesPreset` maps to nothing certain by default: the preset table lives in the Bitnami `common` chart and can be a sourced `transform`.
- **Bundled subcharts.** A release with a bundled dependency (Keycloak + PostgreSQL) produces one plan per component and a dependency order in the checklist.
- **Golden files** per generated plan, plus a "coverage" figure (mapped / total keys in the user's values) in the report so partial plans are visibly partial.
- **Honest scope.** MongoDB and Valkey have the weakest sources today (see research notes). Ship those as `route-only` until their mappings are verified; do not fill the gap with inferences.

## Package layout
`cmd/disdetta`, `internal/cli`, `internal/diag`, `internal/imageref` (pure), `internal/scan/{repo,cluster}`, `internal/detect/*` (pure detectors over parsed docs), `internal/catalog` (embedded data), `internal/plan`, `internal/report/{table,json,sarif}`, `internal/yamlx`. Pure packages do no I/O (depguard). The Kubernetes client lives only in `internal/scan/cluster`, behind an interface defined by its consumer, so detectors are tested without a cluster.

## Testing
Table tests citing the source of each case; `testdata/repos/{helm,flux,argocd}`; golden per scan and per plan; fuzz `imageref`, YAML position handling and the Dockerfile scanner; adversarial regression tests per review finding. **Cluster tests:** most logic runs on recorded API objects (fixtures); the kind cluster test (images `bitnamilegacy`) runs in a separate CI job on `main` and nightly, not on every push, to keep PR feedback fast. Windows: symlink tests skip without privilege and run on Linux CI; normalize path separators in goldens.

## Risks
1. False negatives (the worst failure for a scanner): mitigated by M1b/M1c and by reporting unparsed files as diagnostics, never skipping silently.
2. Bitnami URLs and policy keep changing: detection patterns are data, with `VERIFY:` items tracked in the research notes.
3. Mappings drift from Bitnami chart releases: version-ranged mappings and a CI job that diffs upstream `values.yaml` keys against the catalog (M3).
4. Source gaps for MongoDB/Valkey/Keycloak destinations: route-only until verified.
5. Reading Helm Secrets is a privilege escalation in some clusters: opt-in, redacted, documented.

## Review of revision 1
What changed and why:
- Cluster scan moved after repo coverage work (review findings 4-6 were false negatives).
- Cluster scan widened to workload templates and image IDs; Pod-only scanning misses CronJobs and scaled-to-zero apps.
- Helm release Secret decoding became opt-in and tiered (secrets in `config`).
- Added `pull-risk`, `mirror`, `unresolved` attributes; `bitnami/<versioned tag>` is not just "latest for development".
- Mappings are version-ranged and carry maturity labels.
- `plan` inputs defined (repo or cluster values); bundled subcharts get separate plans.
- Added `--fail-on`, baseline/ignore with expiry (needed for CI adoption) and a real-world corpus milestone.
- Kind tests moved out of the per-PR path.

## Decisions to record (ADR)
0001 record decisions (done); 0002 diagnostics `DSD-` (done); 0003 severity model + attributes; 0004 catalog-as-data with mandatory sources and version ranges; 0005 no template rendering (done); 0006 non-fatal scan diagnostics (done); 0007 cluster read tiers and opt-in Secret access; 0008 plan inputs and unmapped-key policy.
