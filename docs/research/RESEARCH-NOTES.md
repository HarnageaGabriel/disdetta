# Study notes (2026-10-12)

Status: first pass. `VERIFY:` marks anything not yet confirmed against an official source; each becomes a tracked issue.

## 1. What Bitnami changed

Source: https://github.com/bitnami/charts/issues/35164

- 2025-08-28: the public catalog `docker.io/bitnami` became a limited community tier. Deletion was postponed to 2025-09-29, with 24h brownouts on Aug 28-29, Sep 2-3, Sep 17-19.
- `docker.io/bitnamisecure`: small hardened subset, `latest` tag only, for development.
- `docker.io/bitnamilegacy`: versioned/older images moved here. No updates, no support. Not copied: debian-8/9/10, centos-7, ol-7 tags.
- `docker.io/bitnamicharts` (OCI charts): still available, no longer updated; default images will not deploy unless overridden (except community-tier images).
- Chart and image sources stay on GitHub under Apache-2.0.
- Not affected: Sealed Secrets, charts-syncer, minideb (still `docker.io/bitnami`).
- VERIFY: later changes (e.g. distribution channels retiring 2026-06-10, Broadcom chart repo URLs) -- check current announcements before fixing detection patterns.

## 2. The `allowInsecureImages` guard (exact behavior)

Source: `bitnami/common/templates/_errors.tpl`, template `common.errors.insecureImages`
(https://raw.githubusercontent.com/bitnami/charts/main/bitnami/common/templates/_errors.tpl).

- Compares each rendered image against the chart's `Chart.Annotations.images` list.
- "relocated": registry/repository not in the annotations; "replaced": registry listed, repository differs; `docker.io/bitnamilegacy/` replacements are also counted as bitnamiLegacy; "retagged": repository:tag not in annotations.
- If `global.security.allowInsecureImages: true`: prints SECURITY WARNING, continues.
- If unset and all replaced images are bitnamilegacy: prints a WARNING, continues. Fails only if the original images came from `docker.io/bitnami/`, `bitnamiprem/` or `bitnamisecure/` (error text links https://github.com/bitnami/charts/issues/30850).
- Value key path: `global.security.allowInsecureImages` (default `false`, e.g. in the postgresql chart values).
- Consequence for the scanner: `allowInsecureImages=true` is the strongest signal of an active workaround. Detect it in values files, HelmRelease `spec.values`, Argo `helm.values`/`valuesObject`, and in the cluster via release values (see section 5).
- VERIFY: exact error text and behavior across chart generations (older charts predate this guard).

## 3. Image reference forms

Bitnami `common.images.image` renders `registry/repository[:tag|@digest]`; `global.imageRegistry` overrides when `image.registry` is unset; digest wins over tag. Values keys per chart: `image.registry`, `image.repository`, `image.tag`, `image.digest`; extra images use `<component>.image.*` (e.g. `sentinel.image`, `keycloakConfigCli.image`, `volumePermissions.image`, `metrics.image`).

Edge cases the parser must handle (all deterministic, table-tested):
- implicit registry (`bitnami/redis` = `docker.io/bitnami/redis`), `index.docker.io`, `registry-1.docker.io`, `library/` prefix.
- digest + tag together (`repo:tag@sha256:...`), registry with port, uppercase/mixed case.
- registry split across `registry` + `repository` keys (must be joined before classification).
- Helm templating (`{{ .Values.x }}`) -- cannot be resolved: report as `unresolved`, never guess.
- mirrors: a private registry mirroring `bitnami/*` repositories (repository path still starts with `bitnami/` or `bitnamilegacy/`): classify by repository prefix, mark registry as non-docker.io. VERIFY policy for mirrored legacy images.

## 4. Where references hide

- values.yaml / values-*.yaml: `image.*`, `global.imageRegistry`, `global.security.allowInsecureImages`.
- Chart.yaml `dependencies[].repository`: `https://charts.bitnami.com/bitnami`, `oci://registry-1.docker.io/bitnamicharts`. VERIFY: Broadcom-hosted repo URLs.
- Flux: `HelmRepository` (`spec.url`, `spec.type: oci`), `HelmRelease` (`spec.chart.spec.sourceRef`, `spec.chartRef`, `spec.values`, `spec.valuesFrom`), `OCIRepository`.
- Argo CD: `Application`/`ApplicationSet` `spec.source(s).repoURL`, `chart`, `targetRevision`, `helm.values`, `helm.valuesObject`, `helm.parameters`.
- Dockerfile: `FROM` (including `ARG`-expanded, multi-stage `AS`), `COPY --from`.
- CI: GitHub Actions (`container.image`, `services.*.image`, `docker://`), GitLab CI (`image:`, `services:`), Azure Pipelines (`container:`, `resources.containers`), docker-compose, Kustomize `images:`.
- Cluster: Pod `spec.containers/initContainers/ephemeralContainers[].image` and `status.containerStatuses[].image/imageID`; Helm release Secrets `sh.helm.release.v1.<name>.v<rev>` (type `helm.sh/release.v1`): `data.release` = base64(base64?)(gzip(JSON)) with `chart.metadata`, `chart.values`, `config`, `manifest`. VERIFY: layout (double base64 in Secret `data`, gzip magic check) against helm source `pkg/storage/driver/util.go`.

## 5. Destinations per stateful component

All value mappings below are CANDIDATES; each row needs a verified `source` before it ships in the catalog. Until then it goes in the unmapped list.

### PostgreSQL (Bitnami `postgresql`) -> CloudNativePG
- Docs: https://cloudnative-pg.io/documentation/current/ (VERIFY exact import pages; old URL redirects to https://cloudnative-pg.io/docs/devel/database_import).
- Bitnami keys observed (defaults from chart `values.yaml`): `architecture` (standalone|replication), `auth.postgresPassword`, `auth.username/password/database`, `auth.existingSecret`, `primary.persistence.{enabled,size,storageClass,existingClaim}`, `primary.resources(Preset)`, `readReplicas.replicaCount`, `primary.configuration`, `primary.extendedConfiguration`, `primary.pgHbaConfiguration`, `primary.initdb.scripts`, `postgresqlSharedPreloadLibraries`, `tls.*`, `metrics.enabled`, `backup.*`.
- Candidate targets (CNPG `Cluster`): `spec.instances`, `spec.storage.{size,storageClass}`, `spec.postgresql.parameters`, `spec.postgresql.pg_hba`, `spec.postgresql.shared_preload_libraries`, `spec.bootstrap.initdb.{database,owner,secret}`, `spec.resources`, `spec.monitoring`. VERIFY each.
- Data migration: no in-place path. Side-by-side + `bootstrap.initdb.import` (microservice/monolith) or `pg_dump`/`pg_restore`. VERIFY.

### Redis (Bitnami `redis`) -> Valkey chart / Redis alternatives
- Official Valkey charts: https://github.com/valkey-io/valkey-helm (charts `valkey`, `valkey-operator`, `valkey-resources`; repo `https://valkey.io/valkey-helm/`). Values keys and any Bitnami migration doc: VERIFY (not on the README).
- Bitnami keys observed: `architecture`, `auth.{enabled,password,existingSecret,acl.*}`, `master.count`, `master.persistence.*`, `replica.replicaCount`, `replica.persistence.*`, `sentinel.enabled`, `commonConfiguration`, `master.configuration`, `tls.enabled`, `metrics.enabled`, `resourcesPreset`.
- Data migration: side-by-side with replication or RDB/AOF copy. VERIFY.

### Kafka (Bitnami `kafka`) -> Strimzi
- Docs: https://strimzi.io/docs/operators/latest/deploying.html. Target CRs: `Kafka`, `KafkaNodePool` (`roles`, `replicas`, `storage`), `KafkaUser`, `KafkaTopic`.
- Bitnami keys observed: `controller.replicaCount`, `controller.controllerOnly`, `broker.replicaCount`, `controller.persistence.*`, `listeners.*` (SASL_PLAINTEXT by default), `sasl.*`, `tls.*`, `kraftVersion`, `clusterId`, `config`, `provisioning.*` (VERIFY).
- Caveat: Strimzi listeners and auth model differ (e.g. plaintext/SASL PLAIN not equivalent). VERIFY before claiming client impact.
- Data migration: MirrorMaker 2 (Strimzi docs mention it for DR, not as a Bitnami migration guide). VERIFY.

### MongoDB (Bitnami `mongodb`) -> operator
- Candidates: MongoDB Community Kubernetes Operator, Percona Operator. Status/support: VERIFY (not researched yet).
- Bitnami keys observed: `architecture`, `auth.{enabled,rootUser,rootPassword,usernames,passwords,databases,replicaSetKey,existingSecret}`, `replicaCount`, `replicaSetName`, `arbiter.enabled`, `persistence.*`, `tls.*`, `externalAccess.*`, `configuration`.
- Data migration: `mongodump`/`mongorestore`. VERIFY.

### Keycloak (Bitnami `keycloak`) -> Keycloak Operator
- Docs: https://www.keycloak.org/operator/installation (VERIFY). Camunda's guide describes replacing a Bitnami Keycloak StatefulSet with an Operator CR with an external PostgreSQL: https://docs.camunda.io/docs/self-managed/deployment/helm/operational-tasks/migration-from-bitnami/ (returned 404 on 2026-10-12; find current URL).
- Bitnami keys observed: `auth.adminUser/adminPassword/existingSecret`, `replicaCount`, `production`, `proxyHeaders`, `httpRelativePath`, `hostnameStrict`, `httpEnabled`, `tls.*`, `cache.{enabled,stack}`, `ingress.*`, `postgresql.*` (bundled subchart: becomes a PostgreSQL migration), `externalDatabase.*`, `keycloakConfigCli.*`, `extraEnvVars`.
- Data: realm export or DB-level move of the external PostgreSQL. VERIFY.

## 6. Competitors / gap

Not yet researched in depth. Search results (2026-10-12) point to AWS/EKS-oriented guides and vendor material (Chainguard guide https://www.chainguard.dev/supply-chain-security-101/a-practical-guide-to-migrating-helm-charts-from-bitnami , Camunda, NATS blog https://nats.io/blog/bitnami-helm-charts-deprecated/ , VSHN ADR https://kb.vshn.ch/app-catalog/adr/0038-appcat-redis-alternative.html ). VERIFY: open-source scanners; confirm the gap claim before using it in the README.

## 7. Open questions
1. Which Broadcom-hosted Bitnami chart URLs exist today.
2. Exact Valkey chart values and a verified Bitnami->valkey-helm mapping.
3. Which MongoDB operator to recommend (license/maintenance).
4. Helm release Secret layout (verify from helm source).
5. Mirrored-registry policy (private mirror of bitnamilegacy).
6. Does the guard fail for charts older than the guard introduction.
