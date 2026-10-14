# DSD-IMG-003: Community Bitnami image

Medium-severity finding: an untagged or `latest` image uses the development-only community tier.

## How to fix

1. Identify the image and its component; the `latest`, untagged, and `bitnamisecure` cases belong to a community tier intended for development only.
2. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
3. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
4. Replace the development-tier reference with the maintained destination image.
5. Rescan after the replacement is configured.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
