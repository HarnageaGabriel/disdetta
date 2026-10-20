# DSD-IMG-001: Legacy Bitnami image

High-severity finding: an image uses the frozen `bitnamilegacy` namespace. Migrate to a maintained image.

## How to fix

1. Identify the image and its component; legacy images are frozen and receive no updates or support.
2. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
3. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
4. For a short-term mitigation, pin the current legacy image by digest and accept the unpatched risk consciously; this does not replace the exit.
5. Replace the legacy image with the maintained destination and rescan.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
