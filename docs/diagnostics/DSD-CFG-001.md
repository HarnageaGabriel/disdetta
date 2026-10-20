# DSD-CFG-001: allowInsecureImages enabled

High-severity finding: `global.security.allowInsecureImages` is the YAML boolean `true`. Re-enable image verification and migrate the referenced images.

## How to fix

1. Remove `global.security.allowInsecureImages: true` so the chart image guard is active again.
2. Rescan and fix every image finding the guard was hiding; start with [DSD-IMG-001](DSD-IMG-001.md).
3. Identify the affected component and run [`disdetta plan`](../usage/plan.md) to generate its migration checklist.
4. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
5. Rescan after the images are migrated and the setting remains removed.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
