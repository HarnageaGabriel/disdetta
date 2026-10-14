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

## 8. PostgreSQL -> CloudNativePG (study for the first verified plan, 2026-10-14)

Sources:
- CNPG API: https://cloudnative-pg.io/docs/devel/cloudnative-pg.v1 (Cluster, StorageConfiguration, PostgresConfiguration, MonitoringConfiguration, BackupConfiguration).
- CNPG import: https://cloudnative-pg.io/docs/devel/database_import
- Bitnami postgresql values: https://raw.githubusercontent.com/bitnami/charts/main/bitnami/postgresql/values.yaml
VERIFY before shipping: pin both to versions (CNPG release, Bitnami chart major) and record the date.

### Candidate mapping (each row becomes a catalog entry with its own source)

| Bitnami key | CNPG field | Kind | Note |
| --- | --- | --- | --- |
| `architecture: standalone` | `spec.instances: 1` | constant | `instances` counts all instances, primary included. |
| `architecture: replication` + `readReplicas.replicaCount: N` | `spec.instances: N+1` | transform | Bitnami read replicas are separate StatefulSets; CNPG instances are one cluster with automated failover (behavior change: list in checklist). |
| `primary.persistence.size` | `spec.storage.size` | rename | Size cannot be decreased in CNPG. |
| `primary.persistence.storageClass` | `spec.storage.storageClass` | rename | |
| `primary.resources` | `spec.resources` | rename | Both core `ResourceRequirements`. |
| `primary.resourcesPreset` | - | manual | Preset table lives in Bitnami `common`; only map with a sourced preset table. |
| `primary.configuration` / `primary.extendedConfiguration` | `spec.postgresql.parameters` | transform | Parse `key = value` lines. Some parameters are operator-managed: VERIFY the fixed-parameter list in CNPG docs; those go to unmapped. |
| `primary.pgHbaConfiguration` | `spec.postgresql.pg_hba` | transform | CNPG appends rules to its own; review required. |
| `postgresqlSharedPreloadLibraries` (default `pgaudit`) | `spec.postgresql.shared_preload_libraries` | transform | Split on comma; added to CNPG defaults. VERIFY the extension exists in the CNPG operand image. |
| `auth.database` | `spec.bootstrap.initdb.database` | rename | CNPG default `app`. |
| `auth.username` | `spec.bootstrap.initdb.owner` | rename | |
| `auth.existingSecret` | `spec.bootstrap.initdb.secret` | manual | Secret layout differs (CNPG: basic-auth username/password); checklist item, never copy values. |
| `auth.enablePostgresUser`, `auth.postgresPassword` | `spec.enableSuperuserAccess`, `spec.superuserSecret` | manual | Default false in CNPG. |
| `primary.initdb.scripts` | `spec.bootstrap.initdb.postInitApplicationSQL` | manual | Only SQL; shell scripts have no equivalent. |
| `metrics.enabled` | - | manual | `monitoring.enablePodMonitor` is deprecated in CNPG; checklist: create a PodMonitor. |
| `backup.*` (pg_dump CronJob) | `spec.backup` | unmapped | Different model (barman object store / volume snapshots). |
| `tls.*` | `spec.certificates` | manual | |
| `image.*` | `spec.imageName` | unmapped (by design) | Use the CNPG operand image of the same or newer major. |

### Data migration (checklist inputs)
- Import via `spec.bootstrap.initdb.import` (`microservice`: one database, roles not imported, `postImportApplicationSQL` supported; `monolith`: several databases, roles imported without SUPERUSER, `postgres` db skipped).
- Offline: stop writes on the source before the final import; later changes are not copied.
- Destination major >= source major; the destination's `pg_dump` is used.
- Dumps are staged in the PGDATA volume: size storage for dump + data + indexes.
- Source reachable from the new cluster; a user able to run `pg_dump` and read roles.

## 9. Helm release storage (for the cluster scan)

Source: https://github.com/helm/helm/blob/main/pkg/storage/driver/util.go
- Release = JSON, gzip (best compression), then base64 (StdEncoding). Stored in Secret `data.release` (so the raw Secret payload is base64 of that string) with type `helm.sh/release.v1`, name `sh.helm.release.v1.<name>.v<revision>`.
- Decoding checks the gzip magic `1f 8b 08`; uncompressed legacy payloads are plain JSON.
- Implication: decompression must be bounded (zip-bomb defense) and the decoded JSON holds user values (`config`) that may contain credentials.

### 8.1 Verified on 2026-10-14 (CloudNativePG docs `devel`; pin to a release before shipping)

Sources: https://cloudnative-pg.io/docs/devel/postgresql_conf and https://github.com/cloudnative-pg/postgres-containers

- **Fixed parameters** (rejected by the webhook in `spec.postgresql.parameters`): `allow_alter_system`, `allow_system_table_mods`, `archive_cleanup_command`, `archive_command`, `archive_mode`, `bonjour`, `bonjour_name`, `cluster_name`, `config_file`, `data_directory`, `data_sync_retry`, `event_source`, `external_pid_file`, `hba_file`, `hot_standby`, `ident_file`, `jit_provider`, `listen_addresses`, `log_destination`, `log_directory`, `log_file_mode`, `log_filename`, `log_rotation_age`, `log_rotation_size`, `log_truncate_on_rotation`, `logging_collector`, `port`, `primary_conninfo`, `primary_slot_name`, `promote_trigger_file`, `recovery_end_command`, `recovery_min_apply_delay`, `recovery_target*` (all), `restart_after_crash`, `restore_command`, `shared_preload_libraries`, `ssl`, `ssl_ca_file`, `ssl_cert_file`, `ssl_crl_file`, `ssl_dh_params_file`, `ssl_key_file`, `ssl_passphrase_command`, `ssl_passphrase_command_supports_reload`, `ssl_prefer_server_ciphers`, `stats_temp_directory`, `synchronous_standby_names`, `syslog_*` (all), `unix_socket_directories`, `unix_socket_group`, `unix_socket_permissions`. Mapping rule: a user `postgresql.conf` line with one of these keys goes to `unmapped` with the note "managed by CloudNativePG"; never copied.
- **Operator defaults users may override**: `archive_timeout`, `dynamic_shared_memory_type`, `full_page_writes`, `max_parallel_workers`, `max_replication_slots`, `max_worker_processes`, `shared_memory_type`, `ssl_max_protocol_version`, `ssl_min_protocol_version` (default TLSv1.3: a checklist item if clients need TLS 1.2), `wal_keep_size`, `wal_level`, `wal_log_hints`, `wal_sender_timeout`, `wal_receiver_timeout`.
- **`shared_preload_libraries`**: correction to section 8. `pgaudit`, `pg_stat_statements`, `auto_explain`, `pg_failover_slots` are **managed automatically** when parameters with their prefix (`pgaudit.`, `pg_stat_statements.`, ...) are set; other libraries go in `spec.postgresql.shared_preload_libraries` (a missing library prevents startup). Bitnami's default `postgresqlSharedPreloadLibraries: pgaudit` therefore maps to: nothing, unless the user set `pgaudit.*` parameters, in which case they are copied as parameters and pgaudit is loaded by the operator. Checklist: pgaudit is only in the **standard** operand images (`ghcr.io/cloudnative-pg/postgresql:<MM.mm>-standard-<os>`), not in minimal ones.
- **`pg_hba`**: user rules come after fixed rules (local peer, `streaming_replica`, `cnpg_pooler_pgbouncer`) and before the default catch-all (`scram-sha-256` on 14+). Bitnami `pgHbaConfiguration` lines that duplicate fixed rules are redundant; `md5` rules on 14+ are a checklist item.

### 8.2 Pins (2026-10-14)
- CloudNativePG: latest release **v1.30.1** (GitHub releases). The 1.30 docs (https://cloudnative-pg.io/docs/1.30/postgresql_conf) list the same fixed parameters, managed libraries (`auto_explain`, `pg_stat_statements`, `pgaudit`, `pg_failover_slots`) and `ssl_min_protocol_version` default (TLSv1.3) as section 8.1. Catalog sources use `https://cloudnative-pg.io/docs/1.30/...`.
- Bitnami `postgresql` chart: keys used by the mappings (`architecture`, `auth.username`, `auth.database`, `primary.configuration`, `primary.extendedConfiguration`, `primary.pgHbaConfiguration`, `postgresqlSharedPreloadLibraries`, `primary.persistence.size`, `primary.persistence.storageClass`, `primary.resources`, `readReplicas.replicaCount`) are present in the values of tags `postgresql/16.0.0` and `postgresql/17.1.2` (the last tag in git; `main` is 17.1.2). Verified range: `>=16.0.0 <18.0.0`. Later chart versions exist only as OCI artifacts in `bitnamicharts` and need a separate check before widening the range.
