# DSD-CHT-002: Vendored Bitnami chart

Medium-severity finding: a `Chart.yaml` vendors the Bitnami chart. Its `sources` or `home` point to `github.com/bitnami/charts`, or its `annotations.images` list Bitnami images. One finding per vendored chart; migrate the images it pins.

Source: camunda/camunda-platform-helm `charts/web-modeler-postgresql-15/Chart.yaml`.

## How to fix

1. Inspect the vendored chart `Chart.yaml` and identify the component and every Bitnami image pinned by `annotations.images`.
2. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
3. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
4. Replace the vendored chart with the maintained destination and migrate each image it pins; vendoring does not remove the image exit requirement.
5. Remove the stale vendored copy and rescan.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
