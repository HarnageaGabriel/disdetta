<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/disdetta-logo-dark.svg">
    <img src="docs/assets/disdetta-logo.svg" alt="disdetta" width="420">
  </picture>
</p>

<h3 align="center">An open-source tool, in the making, to find and close Bitnami dependencies<br>
in Kubernetes clusters and GitOps repositories. Read-only and reviewable by design.</h3>

<p align="center">
  <a href="https://github.com/HarnageaGabriel/disdetta/actions/workflows/ci.yml">
    <img src="https://github.com/HarnageaGabriel/disdetta/actions/workflows/ci.yml/badge.svg?branch=main"
      alt="CI"></a>
  <a href="go.mod">
    <img src="https://img.shields.io/github/go-mod/go-version/HarnageaGabriel/disdetta"
      alt="Go version"></a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/HarnageaGabriel/disdetta">
    <img src="https://api.scorecard.dev/projects/github.com/HarnageaGabriel/disdetta/badge"
      alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/status-pre--alpha-orange.svg" alt="Status: pre-alpha">
</p>

<p align="center">
  <a href="#try-it-now-prova-subito">Try it now</a> ·
  <a href="#why">Why</a> ·
  <a href="#design-goals">Design goals</a> ·
  <a href="#status">Status</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#contributing">Contributing</a>
</p>

**disdetta** (Italian for "notice of termination", as in cancelling a
contract) finds every Bitnami image and chart your clusters and repositories
still depend on, and plans the way out, one component at a time. It reads; it
never changes anything.

> [!WARNING]
> **Pre-alpha.** `scan` (repositories and clusters) works; `plan` covers
> PostgreSQL only, with partial mappings. See [Status](#status). Interfaces may
> change before v0.1.0.

## Try it now (Prova subito)

```sh
go install github.com/HarnageaGabriel/disdetta/cmd/disdetta@latest
disdetta scan .
disdetta rules
disdetta scan . --format sarif
```

Every Bitnami reference, with file, line and column, most urgent first:

```text
LOCATION           RULE         SEVERITY  CONFIDENCE  IMPACT   REFERENCE
Dockerfile:1:1     DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
values.yaml:6:15   DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16.4.0
values.yaml:4:26   DSD-CFG-001  high      confirmed   unknown  true
Chart.yaml:7:17    DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
values.yaml:10:17  DSD-IMG-003  medium    confirmed   low      docker.io/bitnami/postgres-exporter:latest
scanned 3 files, skipped 0, findings 5 (high 3, medium 2, low 0), diagnostics 0, unresolved 0
```

Exit status 0 means no findings, 1 means findings (tune with `--fail-on`), 2
means a usage or fatal error, 3 means the scan was incomplete. Rules and codes:
[docs/diagnostics](docs/diagnostics/README.md); contract: [docs/spec/v0.1.md](docs/spec/v0.1.md). `--format json` gives a stable, versioned document for CI; `--format sarif` gives code-scanning output.

GitHub Action: [docs/usage/github-action.md](docs/usage/github-action.md) runs the same scan in a workflow and gates a pull request on it.

## Why

On 2025-08-28 Bitnami moved its versioned images from `docker.io/bitnami` to
`docker.io/bitnamilegacy`, an archive with no updates and no support
([bitnami/charts#35164](https://github.com/bitnami/charts/issues/35164)). The
stopgap Bitnami suggested was to point charts at that archive and set
`global.security.allowInsecureImages=true`. Anyone who did that and never went
back is running images that no longer receive security patches. That is who
disdetta is for.

The chart and image sources stay on GitHub under Apache-2.0, so the way out is
always possible. What is missing is a neutral tool that also reads GitOps
repositories (not only the cluster) and that translates chart values, not just
image names. For some components an in-place upgrade does not exist: Valkey
needs a side-by-side deployment and a data migration.

## Design goals

What disdetta is being built to do; the [status table](#status) shows what
exists today.

- **Find everything.** Images in Pods, source charts of Helm releases, and in
  repositories `values.yaml`, `Chart.yaml` dependencies, Flux `HelmRelease`,
  Argo CD `Application`, Dockerfile `FROM`, CI files.
- **Three severities.** `bitnami` (now only `latest`, for development),
  `bitnamilegacy` (frozen), and `allowInsecureImages=true` (the workaround is
  still active).
- **Stateful first.** PostgreSQL, Redis, Kafka, MongoDB and Keycloak lead the
  report, because leaving them means migrating data.
- **Plan, never apply.** `plan <release>` writes values for the destination
  chart where the mapping is known, lists the keys it could not map, and
  produces a migration checklist. It does not run the migration or dump data.
- **Evidence, not guesses.** Every value mapping and every catalog entry is
  data with a public source. A key without a certain mapping goes to the
  unmapped list.
- **Deterministic.** The same input gives the same output. No AI in the main
  path.
- **Local and private.** One Go binary, no container runtime, no telemetry, no
  external service. Secrets never appear in output or logs.

## Status

| Capability | State |
| --- | --- |
| `scan` on repositories (Helm values and templates, `Chart.yaml`, Flux, Argo CD, Kustomize, compose, GitHub Actions, GitLab CI, Azure Pipelines, Dockerfile) | Implemented; recall measured on a [public corpus](docs/corpus.md) |
| `scan --cluster` (workloads, Helm releases, opt-in release Secrets) | Implemented, tested on kind |
| Catalog of exit routes (data, each entry with a source) | PostgreSQL -> CloudNativePG (`partial`) |
| `plan` ([docs](docs/usage/plan.md)) | PostgreSQL; Redis, Kafka, MongoDB, Keycloak need research (issues #3-#6) |
| SARIF output, `rules`, GoReleaser, Homebrew, krew | SARIF and `rules` implemented; releases planned |

## How it works

```text
repo files ─┐                                   ┌─ table (people)
            ├─► detectors ─► findings ─► sort ──┼─ JSON (CI, versioned)
cluster ────┘   (pure)        severity,        └─ SARIF (code scanning)
                               stateful first
                                  │
                                  └─► catalog (data + source) ─► plan: values, unmapped keys, checklist
```

Detectors are pure functions over parsed YAML with line numbers. They do not
render Helm templates: an unresolved value is reported as unresolved, never
guessed ([ADR 0005](docs/adr/0005-no-template-rendering.md)). Problems have
stable `DSD-*` codes ([docs/diagnostics](docs/diagnostics/README.md)).

## Roadmap

See [docs/PLAN.md](docs/PLAN.md). Study notes with sources and open
`VERIFY:` items: [docs/research/RESEARCH-NOTES.md](docs/research/RESEARCH-NOTES.md).
Scan benchmarks and how to reproduce them: [docs/performance.md](docs/performance.md).

1. Repository scan hardening and wider coverage (templates, GitLab, Azure, Kustomize, Dockerfile `ARG`).
2. Cluster scan (read-only).
3. Catalog and `plan` for the five first charts.
4. SARIF, releases, Homebrew, krew.

## Contributing

- **Start here**: [good first issues](https://github.com/HarnageaGabriel/disdetta/labels/good%20first%20issue)
  and [help wanted](https://github.com/HarnageaGabriel/disdetta/labels/help%20wanted). Many need
  no Go at all: verifying a value mapping against the official docs of CloudNativePG, Valkey,
  Strimzi, MongoDB or Keycloak ([kind/research](https://github.com/HarnageaGabriel/disdetta/labels/kind%2Fresearch))
  is one of the most useful contributions.
- **Try `scan` on your repositories** and tell us what it misses. Anonymized
  real-world values files that break detection are the most valuable
  contribution.
- **Contribute code**: read [CONTRIBUTING.md](CONTRIBUTING.md) and
  [CONVENTIONS.md](CONVENTIONS.md); every commit needs a DCO sign-off
  (`git commit -s`). This project follows the
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Report vulnerabilities privately**, as described in
  [SECURITY.md](SECURITY.md), never in public issues.

## FAQ

<details>
<summary><b>Is disdetta free?</b></summary>

Yes, always: Apache-2.0, no paid edition, no feature gates.
</details>

<details>
<summary><b>Does it change my cluster or repositories?</b></summary>

No. Every command is read-only. `plan` writes a proposal you review; applying
it is up to you.
</details>

<details>
<summary><b>Does it send data anywhere?</b></summary>

No. No telemetry and no required external service.
</details>

<details>
<summary><b>Does it migrate my data?</b></summary>

No. It produces a checklist. The dump and restore stay under your control.
</details>

## License

[Apache-2.0](LICENSE). disdetta is not affiliated with Bitnami or Broadcom.
Third-party licenses: [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES/README.md). Trademarks: [TRADEMARKS.md](TRADEMARKS.md).
