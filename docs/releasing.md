# Release runbook

For maintainers releasing from `main`. **ASK THE OWNER FIRST** means stop for an owner decision. This covers the first `v0.1.0` tag, krew submission, a Homebrew tap, and any spending.

## Pre-release

- [ ] Clean `main`, green CI, and owner-approved version.
- [ ] Turn CHANGELOG.md `Unreleased` into `vX.Y.Z - YYYY-MM-DD`.
- [ ] Complete spec acceptance, including tests, fuzz, security tests, determinism, CI, and coverage.
- [ ] Measure recall and precision with the current binary using [docs/corpus.md](corpus.md); record date, commit, and results there. Before v0.1.0: recall >= 90 percent and precision >= 95 percent.
- [ ] Run fuzzing and govulncheck; confirm Scorecard is green.
- [ ] Confirm THIRD_PARTY_LICENSES matches go.mod.
- [ ] Check placeholders in [verifying-releases.md](security/verifying-releases.md) still name release.yml and tag refs. Check .krew.yaml placeholders.
- [ ] Confirm rulesets and no open security advisories.

```bash
git switch main
git status --short
git pull --ff-only origin main
git log -1 --oneline
```

```bash
make test
make test-race
make lint
make cover
make fuzz
make vuln
```

```bash
disdetta scan <repo> --format json > <repo>.json
python tools/corpus/recall.py other
```

```bash
gh run list --workflow scorecard.yml --branch main --limit 1
gh api repos/HarnageaGabriel/disdetta/rulesets
gh api repos/HarnageaGabriel/disdetta/security-advisories
```

A permission error from the advisory command is a stop, not proof of no advisories.

## Cutting the release

The workflow triggers on pushed tags matching `v*.*.*`; validation requires three numeric components. **ASK THE OWNER FIRST:** confirm tag, changelog, and commit.

Use one of these, not both:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git show --stat --oneline vX.Y.Z
git push origin vX.Y.Z
```

```bash
git tag -s vX.Y.Z -m "Release vX.Y.Z"
git show --stat --oneline vX.Y.Z
git push origin vX.Y.Z
```

The workflow checks out full history, validates the tag, installs Go, Syft, and cosign, then GoReleaser builds Linux, macOS, and Windows archives, checksums, SBOM inputs, and the GitHub release. Cosign keylessly signs checksums.txt. GitHub attests provenance for each archive. It normally takes a few minutes; allow about 15 minutes.

```bash
gh run list --workflow release.yml --limit 1
gh run watch --repo HarnageaGabriel/disdetta --exit-status
```

Never recreate, move, or delete a published tag.

## Verify

Follow [verifying-releases.md](security/verifying-releases.md):

```bash
gh release download vX.Y.Z --repo HarnageaGabriel/disdetta --pattern "disdetta_vX.Y.Z_linux_amd64.tar.gz" --dir .
gh release download vX.Y.Z --repo HarnageaGabriel/disdetta --pattern "checksums.txt*" --dir .
```

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/vX.Y.Z" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" checksums.txt
```

```bash
grep 'disdetta_vX.Y.Z_linux_amd64.tar.gz$' checksums.txt | sha256sum -c -
```

```bash
gh attestation verify disdetta_vX.Y.Z_linux_amd64.tar.gz --repo HarnageaGabriel/disdetta
```

```bash
tar -xzf disdetta_vX.Y.Z_linux_amd64.tar.gz
./disdetta version
./disdetta scan path/to/fixture --format text
```

Version must match the tag and the fixture must have the expected result.

## Floating major tag

**ASK THE OWNER FIRST:** double check release page, verification, commit, and action smoke test. Moving `v0` is deliberate and manual. The ruleset protects `v*.*.*`; `v0` does not match it.

```bash
git tag -f v0 vX.Y.Z
git push --force origin v0
```

## Distribution

For krew, .krew.yaml is a GoReleaser template: `{{ .TagName }}` fills the version and `addURIAndSha` fills each archive URI and SHA-256. No submission automation exists here. **ASK THE OWNER FIRST:** choose submission, then render/review and make the manual PR to the krew-index fork, or use the krew release bot if chosen. Do not invent automation.

No Homebrew tap exists. **ASK THE OWNER FIRST** before creating one or spending money. It needs a repository, formula, macOS URLs and SHA-256 values, ownership, and updates. No container image exists.

## After release

- [ ] Scratch repository: test exact `@vX.Y.Z`.
- [ ] Test commit SHA plus `version: vX.Y.Z`.
- [ ] After moving it, test `@v0`.
- [ ] Announce with release and verification links.
- [ ] Update stale pre-release text.

```bash
grep -rn 'no release' docs README.md SECURITY.md
```

Review `docs/security/verifying-releases.md`, `docs/usage/github-action.md`, and `SECURITY.md` when found.

## Failure

Yank a bad release by deleting the GitHub release, not the tag. A published tag is never moved or deleted; publish fixed `vX.Y.(Z+1)`.

```bash
gh release delete vX.Y.Z --repo HarnageaGabriel/disdetta
```

Stop using suspect files. Report checksum, signature, or attestation failures privately via [SECURITY.md](../SECURITY.md). Report vulnerabilities through private reporting, not a public issue, until coordinated remediation. The owner decides trust revocation and disclosure.

