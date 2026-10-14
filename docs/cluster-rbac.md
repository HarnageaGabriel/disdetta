# Cluster scan RBAC

`disdetta scan --cluster` reads a cluster with two least-privilege roles
(spec [v0.2](spec/v0.2-cluster.md) section 4). The scan only ever issues
`list` calls, so the roles grant only `list` (review 03 m9); nothing in the scan
writes, and no build fetches a single object by name.

- **Tiers 1-2** read pod templates and Pod status, so they need `list` on the
  workload kinds and Pods in every namespace you scan.
- **Tier 3** (`--read-helm-secrets`) reads Helm release Secrets, so it needs
  `list` on Secrets. Keep it in a separate role and grant it only when you opt
  in.

## Tiers 1-2

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: disdetta-read-tiers-1-2
rules:
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets", "daemonsets", "replicasets"]
    verbs: ["list"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
```

Bind it to the identity the scan runs as. A ClusterRoleBinding grants the read
across every namespace, which is what the default (all namespaces) scan needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: disdetta-read-tiers-1-2
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: disdetta-read-tiers-1-2
subjects:
  - kind: ServiceAccount
    name: disdetta
    namespace: disdetta
```

To stay narrower, bind the same ClusterRole with a namespaced RoleBinding and
pass the matching `--namespace` flags, so the identity can read only those
namespaces.

## Tier 3

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: disdetta-read-tier-3-helm-secrets
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
```

### Risk: RBAC cannot restrict by Secret type

Kubernetes RBAC keys on the resource (`secrets`), not on a Secret's `type` or
labels. A role that allows `list secrets` lets the identity read **every**
Secret in scope, not only the Helm release Secrets (`type:
helm.sh/release.v1`, label `owner=helm`) that tier 3 actually wants. A Secret
carrying a planted credential must therefore never be reachable by a tier 3
grant unless that is already acceptable for the identity.

Mitigations:

- Prefer a **namespaced RoleBinding** for the tier 3 ClusterRole (a RoleBinding
  may reference a ClusterRole but limits the grant to its own namespace) and run
  the scan with `--namespace` for exactly the namespaces that store Helm
  releases, instead of a cluster-wide binding.
- Use a **dedicated ServiceAccount** for tier 3 runs, separate from the tiers
  1-2 identity, so an accidental `--read-helm-secrets` cannot read Secrets that
  the repository identity was never meant to see.
- Leave tier 3 off (the default) when you only need the image and chart rules;
  the `global.security.allowInsecureImages` and chart-metadata rules
  (`DSD-CFG-001`, `DSD-CHT-002`) are the only findings tier 3 adds.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: disdetta-read-helm-secrets
  namespace: db            # one binding per namespace you scan
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: disdetta-read-tier-3-helm-secrets
subjects:
  - kind: ServiceAccount
    name: disdetta-tier3
    namespace: disdetta
```

With only namespaced bindings, list of a namespace outside the grant fails and
the scan reports `DSD-SCN-010` for it and continues (spec v0.2 sections 4 and 5).
