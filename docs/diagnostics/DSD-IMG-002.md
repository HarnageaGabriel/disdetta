# DSD-IMG-002: Versioned Bitnami image

High-severity finding: a versioned or unresolved-tag image uses `bitnami` or `bitnamisecure` and may no longer pull from the public path.

## How to fix

1. Identify the image and its component; versioned tags left the public path on 2025-08-28, so a pull may fail and a cached copy is unpatched.
2. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
3. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
4. Replace the versioned or unresolved-tag image with the maintained destination; do not rely on a successful pull from the old public path.
5. Rescan after the replacement is configured.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
