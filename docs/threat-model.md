# Threat model

Status: accepted (2026-10-14). Covers the repository scan (v0.1) and the cluster scan (v0.2). Scope: `disdetta scan` (repository and cluster) and `disdetta plan`.

## Assets
1. **Confidentiality of what disdetta reads**: values files and Helm release payloads can contain passwords, tokens, connection strings.
2. **Integrity of the user's systems**: disdetta must never change a repository, a cluster or a registry.
3. **Integrity of the report**: a report that looks clean while the scan was incomplete is a security failure, not a cosmetic one.
4. **The user's machine**: disdetta runs with the user's filesystem and kubeconfig privileges.

## Trust boundaries
- Repository content is **untrusted input** (it may come from a pull request of a stranger in CI).
- Cluster API responses are trusted for authenticity (TLS, kubeconfig) but **untrusted in content** (any tenant can create objects with hostile names, labels, values).
- The embedded catalog is trusted (reviewed data, shipped in the binary).

## Threats and controls

| # | Threat | Control | Status |
| --- | --- | --- | --- |
| T1 | Secret leaked to stdout, CI logs, JSON or SARIF | Only the reference itself is printed; nothing under a Kubernetes `Secret`; userinfo stripped; template bodies replaced by `{{...}}`; redaction tests per rule | Done (repo scan) |
| T2 | Helm release Secrets read with broad RBAC, payload exposed | Opt-in `--read-helm-secrets`; server-side selectors (`owner=helm,status=deployed`, field `type=helm.sh/release.v1`) plus a client-side type check; payloads decoded in memory, processed per page and dropped; diagnostics carry fixed messages only; never cached to disk; RBAC documented in `docs/cluster-rbac.md` (Kubernetes RBAC cannot restrict by Secret type: prefer namespace-scoped bindings). Tests plant a password and a token and assert they appear in no output | Done (v0.2) |
| T3 | Decompression bomb in a Helm release payload | Encoded-length check before base64 decoding, 4 MiB compressed cap, 32 MiB decompressed cap, 100:1 ratio cap, single gzip member; over a cap is `DSD-SCN-009` and the scan is incomplete. List calls are bounded by a timeout across all pages | Done (v0.2) |
| T4 | Hostile YAML: deep nesting, alias explosion ("billion laughs"), huge files | File size cap (16 MiB), depth cap (256), alias node budget with cycle guard, per-file errors are diagnostics | Done |
| T5 | Filesystem escape through symlinks, special files, path traversal in reported paths | Symlinks and non-regular files skipped and reported; paths reported relative to the root, slash-separated; no file is ever written | Done |
| T6 | Terminal injection through file names or values (ANSI escapes, newlines forging rows) | Control characters escaped in every table cell; JSON encoding escapes by construction | Done |
| T7 | Incomplete scan reported as clean | Exit code 3 on error-level diagnostics; summary always printed with `complete`; in the cluster scan a forbidden tier 1-2 list, or a forbidden tier 3 list when `--read-helm-secrets` was requested, makes the scan incomplete | Done |
| T8 | Accidental write to the cluster | Only `list` calls are issued; no watch, discovery or SelfSubjectAccessReview; a fake-clientset reactor fails the test on any other verb | Done (v0.2) |
| T9 | Supply chain of disdetta itself | Pinned CI tools, govulncheck, minimal dependencies with written reasons, reproducible builds, signed release checksums and provenance (M5) | Partial |
| T10 | Network egress / telemetry | No network code outside the Kubernetes client; no telemetry; depguard forbids `net/http` in pure packages | Done |
| T11 | Ignore file abused to hide findings | Reason and expiry required; expired entries do not suppress and are reported; ignored count in the summary | Done |

## Out of scope
Compromised kubeconfig or workstation; malicious catalog entries (they go through review); availability of the scanned systems (disdetta is read-only and bounded).

## Review triggers
Any change to: Secret handling, decompression, the Kubernetes client, redaction, output encoders, the ignore file. Such changes need the adversarial review and a maintainer read (CONVENTIONS.md).
