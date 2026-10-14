# DSD-IMG-004: Bitnami image from another registry

Low-severity finding: an image under `bitnami/` or `bitnamisecure/` is pulled from a registry other than Docker Hub. It is either a mirror (frozen unless refreshed) or a rebuild from the Bitnami sources, a recommended exit. Attribute `mirror`, confidence `inferred`. A `bitnamilegacy/` image under another registry stays `DSD-IMG-001`.

## How to fix

1. Record the registry, repository, and component, then determine whether the image is a mirror or a rebuild from the Bitnami sources.
2. If it is a mirror, verify where the content comes from and when it was last synchronized; a mirror is frozen unless its refresh process updates it.
3. Run [`disdetta plan`](../usage/plan.md) to produce the component migration checklist.
4. Follow the component exit route: PostgreSQL [#2](https://github.com/HarnageaGabriel/disdetta/issues/2), Redis/Valkey [#3](https://github.com/HarnageaGabriel/disdetta/issues/3), Kafka [#4](https://github.com/HarnageaGabriel/disdetta/issues/4), MongoDB [#5](https://github.com/HarnageaGabriel/disdetta/issues/5), or Keycloak [#6](https://github.com/HarnageaGabriel/disdetta/issues/6).
5. Prefer a rebuild from the Bitnami sources or the maintained destination for the component, then rescan.

## Suppressing a finding

If the finding is accepted temporarily, add it to the scan ignore file with a documented `reason` and an `expires` date. Expired entries stop suppressing and report [DSD-SCN-006](DSD-SCN-006.md).
