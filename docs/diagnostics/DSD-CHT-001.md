# DSD-CHT-001: Bitnami chart source

Medium-severity finding: a Helm chart is sourced from a Bitnami chart repository.

## How to fix

1. Identify the chart and component; the Bitnami OCI chart catalog remains available but is no longer updated.
2. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
3. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
4. Replace the Bitnami chart source with the maintained destination chart for the component.
5. Ensure required images are replaced with maintained images rather than relying on the old chart defaults, then rescan.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
