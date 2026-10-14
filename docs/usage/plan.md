# `disdetta plan`

`plan` proposes the exit from one Bitnami release. It reads the values you set,
translates the keys whose mapping is verified, lists everything else with a
reason, and writes a migration checklist. It never applies anything and never
moves data.

```sh
# from a GitOps repository (Flux HelmRelease or Argo CD Application named "pg")
disdetta plan --release pg --from-repo .

# from plain values files, in Helm order (later files win)
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
| `unmapped` | Every key you set that was not translated, with its kind (`manual`: you decide; `unmapped`: no equivalent, by design; `unknown`: not in the catalog yet) and a note. |
| `checklist.md` | Ordered migration steps, each with its source, plus one item per `manual` key. |
| coverage | `mapped N of M user-set keys`. |

Exit status: 0 every key mapped; 4 the plan has unmapped or manual keys (a
signal for CI, not an error); 2 usage or input error (release not found, chart
version not covered by the catalog).

## Secrets

Passwords, tokens and any value under `auth.*` (except `auth.username` and
`auth.database`) are never copied. The plan tells you which Secret to create
instead.

## Maturity

| Chart | Destination | Maturity |
| --- | --- | --- |
| `postgresql` | CloudNativePG | `partial`: only rows verified against the CloudNativePG docs are translated; the rest is listed as manual. Verification is tracked in [#2](https://github.com/HarnageaGabriel/disdetta/issues/2). |
| `redis`, `kafka`, `mongodb`, `keycloak` | see issues #3-#6 | not in the catalog yet |

Every mapping is data with a public source in [`catalog/routes`](../../catalog/routes);
a key without a certain mapping is listed, never guessed.
