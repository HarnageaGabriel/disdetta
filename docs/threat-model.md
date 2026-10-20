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

## Hostile repositories

This section details T4, T5, T6 and T10 for the repository scan. The repository
scan reads files that a stranger may have written: a pull request, a
dependency, a copied template. The scan never changes the repository and never
runs anything it finds, but a hostile repository can still try to make the
scan slow, make it use a lot of memory, or make it print something that is not
what it looks like. Every one of those attempts has a bound, and every bound
is reported as a diagnostic, so a scan that hit a bound is never reported as a
clean scan.

### Bounds

| Threat | What bounds it | Diagnostic | Backing code or test |
| --- | --- | --- | --- |
| A file too large to hold in memory | 16 MiB per file | `DSD-SCN-008`, error, the scan is incomplete | `internal/scan/repo/repo.go`, `MaxFileSize`; `internal/scan/repo/read.go`, `ErrFileTooLarge` |
| Deeply nested YAML | 256 levels of nesting | `DSD-SCN-005`, warning | `internal/detect/detect.go`, `maxYAMLDepth`; `internal/detect/yamlguard.go`, `GuardYAML` |
| An alias bomb (the "billion laughs" shape) | 10000 alias expansions per file, and a cycle guard that stops an anchor that refers to itself | `DSD-SCN-005`, warning | `internal/detect/sources.go`, `maxAliasNodes`; `internal/detect/yamlguard.go`, `GuardYAML` |
| A hostile Terraform file | 256 levels of HCL nesting, 100000 visited nodes, 16 MiB per file | `DSD-SCN-005` for the nesting and the node budget, `DSD-SCN-008` for the size | `internal/detect/terraform.go`, `maxTerraformDepth`, `maxTerraformNodes`, `maxTerraformBytes` |
| A scan that takes quadratic time | The scan is linear in the number of YAML documents, in the number of CI script steps and in the number of Dockerfile continuation lines | none: the bound is the shape of the code, and it is proved by tests | `internal/detect/limits_test.go`, `TestManyDocumentsAreScannedInLinearTime`; `internal/detect/shellcmd_test.go`, `TestShellScanManySteps`; `internal/detect/dockerfile_limit_test.go`, `TestDockerfileContinuationChainUnderLimit` |
| Unbounded output and unbounded memory | 10000 findings per file, 100000 findings per repository | `DSD-SCN-005`, warning, once per file or per repository | `internal/diag/diag.go`, `MaxFindingsPerFile`, `MaxFindingsPerRepository`; `internal/detect/detect.go`; `internal/scan/repo/repo.go` |
| A Dockerfile with a very long continuation chain | 10000 continuation lines per logical instruction | `DSD-SCN-005`, warning, once per chain; the instructions after the chain are still scanned | `internal/detect/detect.go`, `MaxDockerfileContinuationLines` |
| A symlink or a Windows junction in the repository | The link is never followed, wherever it points. The path is skipped and counted in `summary.filesSkipped` | `DSD-SCN-002`, warning | `internal/scan/repo/read.go`, `walkRepository`, `readRegularFile`; `internal/scan/repo/repo.go` |
| A values file reference that leaves the scan root | An absolute path, a path that escapes the root with `..`, a path that reaches a symbolic link and a path whose parent directory is a symbolic link or a Windows junction are all refused | `DSD-SCN-004`, error, the scan is incomplete | `internal/scan/repo/values.go`, `resolveValuesFile`, `plainAncestors`, `contained`; `internal/scan/repo/values_test.go`, `TestValuesFileSymlinkIsNotFollowed`, `TestValuesFileBelowSymlinkedParentIsRefused`, `TestValuesFileBelowJunctionIsRefused` |
| A Kubernetes Secret manifest | Nothing under a `Secret` is scanned or printed, at any depth | none: nothing from a Secret is ever reported | `internal/detect/detect.go`, `isSecretMapping`; `internal/detect/sources.go`; `internal/detect/terraform.go` |
| A terminal escape in a file name or in a value | Every table cell escapes the control characters and the Unicode format characters; the JSON encoder escapes by construction | none: the escape is part of the output | `internal/report/report.go`, `SafeText` |
| Execution of the content of the repository | Nothing is executed. The detectors are pure functions over bytes, and the linter forbids `os`, `os/exec` and `net/http` in the pure packages | none | `internal/detect`; `.golangci.yml`, the `depguard` rule `pure` |
| A write in the scanned repository | The scan only opens files for reading. The only write of the tool is the output directory of `disdetta plan` | none | `internal/scan/repo/read.go`, `readRegularFile`; `internal/cli/plan.go` |
| A network call during a repository scan | The repository scan opens no socket. The only network code of the tool is the Kubernetes client of the cluster scan | none | `internal/scan/repo`; `internal/scan/cluster/kube.go`; `.golangci.yml`, the `depguard` rule `pure` |

The contract of these bounds is the spec:
[docs/spec/v0.1.md](spec/v0.1.md) section 3 for the limits and the findings
caps, and section 9 for the Dockerfile continuations and the values file
references. Each diagnostic has its own page in `docs/diagnostics/`:
[DSD-SCN-002](diagnostics/DSD-SCN-002.md),
[DSD-SCN-004](diagnostics/DSD-SCN-004.md),
[DSD-SCN-005](diagnostics/DSD-SCN-005.md) and
[DSD-SCN-008](diagnostics/DSD-SCN-008.md). The cost of the limits is in
[docs/performance.md](performance.md).

### How the time bounds are tested

The scan must stay linear in the size of its input, and a test is the only
thing that keeps it that way. The tests generate the hostile input, they run
the scan in a goroutine, and a timeout guard ends the test if the scan does
not finish. A quadratic implementation therefore fails the test instead of
running for minutes.

- `internal/detect/limits_test.go`, `TestManyDocumentsAreScannedInLinearTime`:
  50000 YAML documents in one file, with a 30 second guard.
- `internal/detect/shellcmd_test.go`, `TestShellScanManySteps`: 20000 script
  steps, for GitHub Actions, GitLab CI and Azure Pipelines, with a 60 second
  guard and a 5 second budget.
- `internal/detect/dockerfile_limit_test.go`, `TestDockerfileContinuationChainUnderLimit`:
  9000 continuation lines, with a 30 second guard.

The output of the scan did not change when the time bounds were fixed: the
golden files stayed the same, so the fix changed the cost and not the report.

### Residual risks

These are known and are not fixed.

- **The parser uses a lot of memory on a large file.** A YAML file is decoded
  into a node tree before any rule runs, so the memory cost is a multiple of
  the size of the file. The adversarial audit measured a 16 MiB YAML file at
  on the order of 100 MB of memory. A repository of large manifests needs that
  much memory per worker.
- **A repository with a very large number of files is slow.** The audit
  measured about 18 s for a repository of 200000 empty files. There is no
  limit on the number of files in a repository, and none is planned.
- **The worker pool multiplies the peak memory.** The files are parsed by up
  to eight workers at the same time, so the peak memory of a scan is about
  the peak memory of one file times the number of workers. The count is
  `internal/scan/repo/parallel.go`, `MaxWorkers`, and it can be raised with
  `DISDETTA_WORKERS`.
- **The walk has no depth limit.** A repository with very deep directories is
  walked to the end. The scan is bounded in time by the number of files, not
  by the depth of the tree.

## Out of scope
Compromised kubeconfig or workstation; malicious catalog entries (they go through review); availability of the scanned systems (disdetta is read-only and bounded).

## Review triggers
Any change to: Secret handling, decompression, the Kubernetes client, redaction, output encoders, the ignore file. Such changes need the adversarial review and a maintainer read (CONVENTIONS.md).
