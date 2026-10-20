# Verifying releases

This page shows how to check that the archive you downloaded is the one the
disdetta release workflow published, and that nothing changed on the way.

Status: no release tag exists yet, so there is nothing to verify today. The
instructions below apply from the first release onwards. Every `vX.Y.Z` is a
placeholder: replace it with the tag you downloaded, for example `v0.1.0`, and
replace `linux_amd64` with the target you downloaded.

## What a release contains

| Item | What it is |
| --- | --- |
| `disdetta_vX.Y.Z_linux_amd64.tar.gz` (`.zip` on Windows) | The archive with the `disdetta` binary, `LICENSE`, `NOTICE` and `README.md`. |
| `checksums.txt` | SHA-256 sums of the release artifacts. |
| `checksums.txt.sigstore.json` | Keyless cosign signature (Sigstore bundle) over `checksums.txt`. |
| `disdetta_vX.Y.Z_linux_amd64.tar.gz.spdx.json` | SPDX JSON SBOM of the archive contents. |
| Attestation | GitHub build provenance for each archive, kept in the GitHub attestation store and checked with `gh attestation verify`. |

The archive name carries the tag, the operating system and the architecture.
Built targets are `linux` and `darwin` on `amd64` and `arm64`, and `windows` on
`amd64`.

## 1. Download the archive, the checksums and the signature

From the release page of the tag you want:

```bash
gh release download vX.Y.Z --repo HarnageaGabriel/disdetta --pattern "disdetta_vX.Y.Z_linux_amd64.tar.gz" --dir .
```

```bash
gh release download vX.Y.Z --repo HarnageaGabriel/disdetta --pattern "checksums.txt*" --dir .
```

The second command picks up both `checksums.txt` and
`checksums.txt.sigstore.json`.

Without the GitHub CLI, use the release page of the tag and download the same
files. The download URLs follow this shape:

```text
https://github.com/HarnageaGabriel/disdetta/releases/download/vX.Y.Z/disdetta_vX.Y.Z_linux_amd64.tar.gz
```

## 2. Verify the checksums

Verify the archive you downloaded against the checksum file:

```bash
grep 'disdetta_vX.Y.Z_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
```

Expected output:

```text
disdetta_vX.Y.Z_linux_amd64.tar.gz: OK
```

The trailing `$` keeps the match on the archive itself, so a line for the SBOM
of the same archive is not picked up.

If you downloaded every file listed in `checksums.txt`, check them all at once:

```bash
sha256sum -c checksums.txt
```

On macOS, `sha256sum` is not installed by default: use `shasum -a 256` with the
same checksum file. On Windows PowerShell, compare the output of
`Get-FileHash -Algorithm SHA256 disdetta_vX.Y.Z_linux_amd64.tar.gz` with the
line for the same file in `checksums.txt`.

## 3. Verify the signature of the checksums

The signature is keyless: it is bound to the GitHub Actions identity of the
release workflow, and the entry is in the public Sigstore transparency log.

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

Expected output ends with `Verified OK` and the details of the signing
certificate.

Two values have to match exactly:

- `certificate-identity`: the tag you downloaded, as `refs/tags/vX.Y.Z`. A
  signature made for another tag does not verify here.
- `certificate-oidc-issuer`: `https://token.actions.githubusercontent.com`, the
  issuer of the GitHub Actions OIDC token used by the workflow.

The release workflow signs with cosign v3.0.6, installed by
`sigstore/cosign-installer` v4.1.2. If your cosign version does not accept the
bundle it was given, check that it reads the bundle format of that version
before treating the failure as a problem with the release.

## 4. Verify the build provenance

Each archive carries a GitHub build provenance attestation, produced by the
release workflow:

```bash
gh attestation verify disdetta_vX.Y.Z_linux_amd64.tar.gz --repo HarnageaGabriel/disdetta
```

Expected output lists the digest of the file, the source repository and the
signing workflow (`.github/workflows/release.yml`).

The attestation covers the archives. `checksums.txt` and the SBOM are not
attested: the checksum file is covered by the signature you verified in the
previous step.

## 5. Inspect the SBOM

The SBOM lists the packages found in the archive, including the Go modules
compiled into the binary:

```bash
jq -r '.packages[] | "\(.name) \(.versionInfo)"' disdetta_vX.Y.Z_linux_amd64.tar.gz.spdx.json
```

Without `jq`:

```bash
python -c "import json;d=json.load(open('disdetta_vX.Y.Z_linux_amd64.tar.gz.spdx.json'));print('\n'.join(sorted(p['name']+' '+p.get('versionInfo','') for p in d['packages'])))"
```

Compare the list with the dependencies of the tag in `go.mod`. Anything you do
not expect is a reason to stop and report it.

## If a check fails

- **The checksum does not match.** The file is not the one we published. Do
  not run it. Download it again from the release page.
- **The signature does not verify.** The checksum file was not signed by the
  release workflow of this repository. Check the tag in the identity first, and
  report it if it is the right tag.
- **The attestation does not verify.** The archive was not built by the release
  workflow of this repository, or it was modified after the build.

Report any of these through the private channel described in
[SECURITY.md](../../SECURITY.md), not in a public issue. The threats
disdetta addresses are described in the
[threat model](../threat-model.md).
