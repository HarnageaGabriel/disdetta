# `disdetta plan`

`plan` proposes the exit from one Bitnami release. It reads the values you set,
translates the keys whose mapping is verified, lists everything else with a
reason, and writes a migration checklist. It never applies anything and never
moves data.

```sh
# from a GitOps repository (Flux HelmRelease or Argo CD Application named "pg")
disdetta plan --release pg --from-repo .

# Flux valuesFrom stand-ins, in list order (later files win; inline values win last)
disdetta plan --release pg --from-repo . --values values.yaml --values values-prod.yaml

# from a live release (reads the Helm release Secret: needs --read-helm-secrets)
disdetta plan --release pg --from-cluster --namespace db --read-helm-secrets

# write the three files to a directory instead of stdout
disdetta plan --release pg --from-repo . --out ./exit-pg
```

## Output

| Part | Content |
| --- | --- |
| `target.yaml` | The destination resource (today: a CloudNativePG `Cluster`), built only from verified mappings of keys you actually set. |
| `unmapped` | Every key not translated directly, with its kind (`manual`: you decide; `unmapped`: no equivalent; `unknown`: not in the catalog; `handled`: satisfied automatically and not incomplete) and a note. |
| `checklist.md` | Ordered migration steps, each with its source, plus one item per `manual` key. |
| coverage | `mapped N of M user-set keys`. |

Exit status: 0 every key mapped; 4 the plan has unmapped or manual keys, or no
user values were found (a signal for CI, not an error); 2 usage or input error
(release not found, chart version not covered by the catalog, or unresolved
Flux `valuesFrom`). An empty values map produces a checklist item to review the
chart defaults and exits 4.

For Flux, `spec.valuesFrom` is never fetched. Pass each referenced values file
with `--values` in the same order. These files are merged first, then inline
`spec.values` is merged last. A `valuesFrom.targetPath` cannot be reproduced
from whole values files and is rejected.

## Secrets

Passwords, tokens and any value under `auth.*` (except `auth.username` and
`auth.database`) are never copied. The plan tells you which Secret to create
instead.

Copied values use catalog allow-lists: Kubernetes quantities, DNS labels,
PostgreSQL identifiers, integers, explicit enums, or resource requirements.
Resource requirements accept only `limits`/`requests`, then `cpu`, `memory`,
`ephemeral-storage`, or `hugepages-*`, with quantity values. A value outside
its declared shape is listed for manual review and is not copied. Configuration
and pg_hba transforms also drop credential-bearing parameters and rules.

## Maturity

| Chart | Destination | Maturity |
| --- | --- | --- |
| `postgresql` | CloudNativePG | `partial`: only rows verified against the CloudNativePG docs are translated; the rest is listed as manual. Verification is tracked in [#2](https://github.com/HarnageaGabriel/disdetta/issues/2). |
| `redis`, `kafka`, `mongodb`, `keycloak` | see issues #3-#6 | not in the catalog yet |

Every mapping is data with a public source in [`catalog/routes`](../../catalog/routes);
a key without a certain mapping is listed, never guessed.
