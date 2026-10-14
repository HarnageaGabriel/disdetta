# Install disdetta

## Go install

Once the repository is public:

```sh
go install github.com/HarnageaGabriel/disdetta/cmd/disdetta@latest
```

## Release archives

Download an archive, `checksums.txt`, and `checksums.txt.sigstore.json` from the
[release page](https://github.com/HarnageaGabriel/disdetta/releases). Verify the
checksum signature before extracting:

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
grep 'disdetta_v0.1.0_linux_amd64.tar.gz' checksums.txt | sha256sum -c -
gh attestation verify disdetta_v0.1.0_linux_amd64.tar.gz --repo HarnageaGabriel/disdetta
tar -xzf disdetta_v0.1.0_linux_amd64.tar.gz
```

Windows releases are ZIP archives; use `Get-FileHash -Algorithm SHA256` and
`Expand-Archive` after the same cosign and attestation checks.

## Krew

After index submission, install with `kubectl krew install disdetta`.

## Homebrew

Homebrew: coming soon.

## Container

None; disdetta is a single binary.
