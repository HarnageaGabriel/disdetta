# Security policy

disdetta is a read-only scanner: it reads repositories and clusters and prints
reports. This page says what we treat as a vulnerability in a tool like this,
how to report one, and how to check that the release you downloaded is the one
we published.

## Supported versions

| Version | Supported | Notes |
| --- | --- | --- |
| `main` (pre-alpha) | Yes | The only supported line. Security fixes land on `main`. |
| Release tags | No | No release tag has been published yet, so there is no released version to support. |

Published support windows will be documented before the first stable release.

## Scope

### In scope

A vulnerability is a flaw that lets someone do something they should not, using
disdetta, while the read-only promise is in place. For a read-only scanner that
means:

- **Reading outside the scan root.** Path traversal through the scanned
  repository: a file that is not under the root being scanned gets read, gets
  reported as part of the scan, or gets reached through a symlink.
- **Secret leakage in output.** A password, token, connection string or
  Kubernetes Secret value that shows up in stdout, in the JSON report, in the
  SARIF output, in a diagnostic or in a log.
- **Unsafe parsing.** Hostile input (YAML today: deep nesting, alias
  expansion, oversized files; the same class applies to any format the tool
  parses) that crashes the tool, exhausts memory, or makes the scan silently
  incomplete.
- **Misleading results.** A scan that is incomplete but reported as clean, or a
  finding dropped without a diagnostic.
- **Writes.** Any write to the repository, to the cluster or to a registry.
  disdetta must never change what it inspects.
- **Supply chain of the releases.** Release artifacts that cannot be verified:
  a missing or wrong checksum, a signature that does not verify, a provenance
  attestation that does not match the artifact, or a published artifact that
  the release workflow did not build.

The Helm release payloads of a cluster are read only when you ask for them with
`--read-helm-secrets`. Not passing that flag, or a cluster where the
permissions are missing, is not a vulnerability.

### Out of scope

- Vulnerabilities in the code you scan. A vulnerable dependency in your
  repositories is your project's problem, not disdetta's.
- Vulnerabilities in Kubernetes, Helm, container registries or the cluster API
  server.
- Findings reported by disdetta. A wrong or missing detection is a bug:
  report it as an issue unless it also breaks one of the guarantees above.
- Denial of service of the scanned systems. disdetta is read-only and
  bounded; it does not defend the systems it scans from their own
  availability problems.
- A compromised workstation, kubeconfig or GitHub account. The machine you
  run disdetta on is trusted.
- Malicious entries in the embedded catalog. The catalog is reviewed data
  shipped in the binary.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** for this repository. Do not
open a public issue or disclose details before a coordinated release. Include
affected versions, impact, reproduction steps, and any proposed mitigation.

We target acknowledgement within 3 business days, initial triage within 7
calendar days, and a remediation plan within 14 calendar days. Severity,
complexity, and coordinated-disclosure needs can change the release date. We
will credit reporters unless they request anonymity.

The project follows coordinated vulnerability disclosure and maintains an
EU Cyber Resilience Act-aligned vulnerability intake, assessment, remediation,
and disclosure process. These targets are project goals, not a warranty or a
statement that a particular CRA legal role applies.

## Safe harbor

If you make a good-faith effort to find and report a vulnerability without
harming users, data or systems, without accessing data beyond what is needed
to reproduce the issue, without degrading the availability of the service, and
without social engineering or physical attacks, we will not pursue legal
action against you.

In return we ask for two things: report the issue through the private channel
above, and give us reasonable time to publish a fix before any public
disclosure.

## Release integrity

Releases are built by `.github/workflows/release.yml`, which runs when a
version tag (`vX.Y.Z`) is pushed. GoReleaser builds the archives and a
`checksums.txt` file with the SHA-256 of the release artifacts. The same job
also produces, for every release:

- **A keyless cosign signature** over `checksums.txt`, stored next to it as
  `checksums.txt.sigstore.json`. The signer is the GitHub Actions OIDC
  identity of the release workflow in this repository
  (`https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/<tag>`),
  and the signature is recorded in the public Sigstore transparency log. No
  long-lived private key is used.
- **A GitHub build provenance attestation** for every archive, created by
  `actions/attest-build-provenance` in the same job.
- **An SPDX JSON SBOM** for every archive.

The step-by-step commands to check all of this are in
[docs/security/verifying-releases.md](docs/security/verifying-releases.md).
Those instructions apply from the first release onwards: no release tag
exists yet.

The threats disdetta addresses and the controls it implements are described in
the [threat model](docs/threat-model.md).
