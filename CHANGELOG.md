# Changelog

## [0.1.0] - Unreleased

- Repository scan: rules, sources, and ignore-file support.
- Cluster scan: tiered analysis with opt-in Helm Secret reads.
- PostgreSQL migration plan: partial support.
- Corpus of repository and cluster fixtures for coverage.
- Helmfile: repositories and releases of `helmfile.yaml`, `helmfile.d/` and `*.yaml.gotmpl`.
- Kustomize: `helmCharts[]` entries and `HelmChartInflationGenerator` documents, with their values.
- Shell commands in CI scripts: `docker run`, `helm repo add` and `helm upgrade` lines are read.
- Terraform: `helm_release` resources of the `*.tf` files.
- SARIF output: `disdetta scan --format sarif` for code scanning.
- Rules command: `disdetta rules` lists every rule and every diagnostic.
- Performance: benchmarks for the repository scan ([docs/performance.md](docs/performance.md)).
- Security and governance: [SECURITY.md](SECURITY.md), release verification and [docs/governance.md](docs/governance.md).
