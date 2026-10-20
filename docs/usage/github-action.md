# GitHub Action

`HarnageaGabriel/disdetta@v0.1.0` runs the scanner in a workflow, so a pull
request can be gated on the Bitnami references it still holds. The action
downloads the release archive, verifies it, and runs the same
`disdetta scan` you would run locally.

Status: no release tag exists yet, so the action cannot run until the first
`v0.1.0` is tagged and published. The action, the archives and the signature
all come from the same release pipeline described in
[verifying releases](../security/verifying-releases.md).

Use an exact tag such as `@v0.1.0`, or a commit SHA with the `version` input,
so the workflow always runs the same release. The floating `@v0` tag also
works, once it exists: see [the floating `v0` tag](#the-floating-v0-tag).

## Usage

### Basic scan

```yaml
name: disdetta
on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: HarnageaGabriel/disdetta@v0.1.0
        with:
          path: .
          fail-on: high
```

The job fails when the scan finds a reference at or above the threshold. The
log ends with the exit code of the scanner and what it means.

### SARIF upload to code scanning

```yaml
name: disdetta
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: HarnageaGabriel/disdetta@v0.1.0
        with:
          format: sarif
          upload-sarif: 'true'
```

The report is written to a file under the runner temp directory and uploaded
with `github/codeql-action/upload-sarif`, pinned by commit SHA. The upload
step runs even when the scan fails the policy, so the findings show up in
code scanning.

### Pinning by commit SHA

A commit SHA does not say which release to download. Set the `version` input
to the release you want:

```yaml
      - uses: HarnageaGabriel/disdetta@1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
        with:
          version: v0.1.0
```

Without the `version` input the action stops with a clear message instead of
guessing.

### The floating `v0` tag

`uses: HarnageaGabriel/disdetta@v0` names a major version, not a release.
The maintainer creates the `v0` tag by hand when the first `v0.x.y` release
is published, and moves it to the commit of that release at every `v0.x.y`
release. The tag does not exist before the first release: a workflow that
uses it fails until then, the same way a workflow pinned to `v0.1.0` fails
until `v0.1.0` is published.

`@v0` selects the action code at the tag the maintainer moved by hand.
That code always queries the GitHub releases API and downloads the highest
stable `v0.x.y` release. While the maintainer lags behind, the commit of
the action code and the release that is downloaded can be different. See
[how a floating tag is resolved](#how-a-floating-tag-is-resolved).

An exact tag (`@v0.1.0`) or a commit SHA with the `version` input is the
better choice for a workflow that must always run the same release.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | File or directory to scan. |
| `fail-on` | `high` | Failure threshold: `none`, `low`, `medium` or `high`. It becomes the `--fail-on` flag of the scanner. |
| `format` | `text` | Output format: `text`, `json` or `sarif`. `text` is the table report of the scanner, `json` the versioned document, `sarif` the code scanning report. |
| `version` | the tag of the action | Release to download: `vMAJOR.MINOR.PATCH`, or `vMAJOR` for the latest release of that major. |
| `upload-sarif` | `false` | Upload the SARIF report to GitHub code scanning. Needs the `security-events: write` permission. |

The action runs `disdetta scan --format <format> --fail-on <fail-on> -- <path>`.
The path is always passed after a double dash, so a path that starts with a
dash is scanned as a path. The action never changes the repository, and it
never writes in it.

## Exit codes

The exit code of the scanner is passed through unchanged, so a workflow can
tell the outcomes apart. The action prints the same table in the log.

| Code | Meaning |
| --- | --- |
| 0 | Scan complete, no finding at or above the threshold. |
| 1 | Policy failed: at least one finding at or above the threshold. |
| 2 | Usage error or fatal error. |
| 3 | Policy passed but the scan is incomplete (at least one error level diagnostic). |

Two exit codes belong to the action itself, and never come from the scanner:

| Code | Meaning |
| --- | --- |
| 64 | Invalid input: unknown format, unknown threshold, empty path, or a commit SHA pin without the `version` input. |
| 70 | The action could not run the scanner: download failed, checksum or signature verification failed, a release list that cannot be read, unsupported platform, or a setup step failed (the work directory, the archive, the SARIF report or the scanner itself). |

A failure of the action never ends with the code of the command that failed:
it ends with 64 or 70, so a broken run never looks like a finding.

## What is verified

Nothing is downloaded and run without a check.

1. The archive is taken from the release page of the exact tag:
   `disdetta_<tag>_<os>_<arch>.tar.gz`, a `.zip` on Windows.
2. `checksums.txt` is verified with the keyless cosign signature published
   next to it (`checksums.txt.sigstore.json`). The certificate identity must
   be
   `https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/<tag>`
   and the issuer must be `https://token.actions.githubusercontent.com`. A
   signature made for another tag, another repository or another issuer is
   refused.
3. The archive is compared with the SHA-256 sum that the signed
   `checksums.txt` publishes for it. The entry has to name the archive
   exactly: an entry of another file, an entry with another word after the
   name, and an entry that is written twice for the same file are refused.
   The sum is compared in lower case, so a checksum file that writes the
   hash in upper case is accepted.
4. The members of the archive are listed and checked before anything is
   extracted. The archive has to hold the scanner of its platform exactly
   once (`disdetta`, or `disdetta.exe` on Windows), and the scanner of the
   other platform is refused. `LICENSE`, `NOTICE` and `README.md` are
   allowed, once each. A member that is not one of those, that appears
   more than once, that is a link, that carries an absolute path or a
   `..` component stops the run. A member whose name holds a newline and
   a member behind a `./` prefix are refused as well: the names are
   compared exactly, and the extraction names the member exactly. Only the
   scanner is extracted.

If any of the four fails, the action stops before the scanner runs.

Every command of the checks has its status read where it is run: a tool
that prints an answer and then fails never passes for a tool that answered.
The action never trusts a partial answer. The listings of the members of
the archive are written to files of the work directory, never read from a
process substitution: the failure of the command that produced a listing
would otherwise be hidden, and a listing that stops in the middle would
hide the members that come after it.

Every call to `curl` starts with `-q`: `curl` reads its configuration file
(`.curlrc`, in `CURL_HOME` or in `HOME`) unless `-q` is the very first
argument, and an inherited configuration can turn the tracing on and print
the `Authorization` header of the API call in the log.

The `github.token` of the workflow is used for one thing only: the GitHub API
call that resolves a floating tag. It never reaches the scanner, it never
appears in the logs, and the release assets are downloaded without any
credential.

## How a floating tag is resolved

A floating tag is a major version such as `v0`: the tag of the action when
it is `v0`, or the `version` input when it is `v0`. The action then asks the
GitHub releases API of this repository for the release list, keeps the
stable releases that match `v0.<minor>.<patch>`, and picks the highest one.
Drafts and prereleases are skipped.

The list is read strictly, and the action fails closed. Every record of the
page has to be an object with a `tag_name` that is a string and with a
`draft` and a `prerelease` that are booleans. A page that is not a list, a
record that is not an object, a field that is missing and a field that has
another type refuse the whole page, and the action stops with 70: a record
read as a stable release because one of its fields was malformed would name
an archive that nobody signed.

The API call always happens for a floating tag, not only when the
maintainer has not moved the tag yet. The maintainer creates the `v0` tag
by hand at the first release and moves it to the commit of the release at
every `v0.x.y` release; while that move lags behind, the commit of the
action code and the release that is downloaded can be different. The API
call needs the workflow token, so it counts against the API rate limit of
the repository.

The floating tag does not exist before the first release: the action cannot
be used through `@v0` until the maintainer creates it.

## Limits

- There is no release yet: the action fails until `v0.1.0` is published, and
  the floating `@v0` tag does not exist until then.
- The action scans a path in the checkout. Cluster scans are not part of it.
- Archives exist for `linux` and `darwin` on `amd64` and `arm64`, and for
  `windows` on `amd64`. There is no `windows/arm64` archive.
- The action needs network access to `github.com` and `api.github.com`, and
  cosign reaches the Sigstore transparency log to check the signature.
- The SARIF upload needs the `security-events: write` permission. Without
  it, the scan still runs and the report is still written, but nothing is
  uploaded.
- The scanner reads the checkout as it is at the time of the step. Use
  `actions/checkout` before it.

## Tests

The shell tests of the action run offline, with `curl`, `cosign`, `tar`,
`unzip` and the scanner replaced by stubs:

```sh
bash action/run_test.sh
```

They cover the checksum mismatch, the missing signature, the exit code
pass-through, the version resolution, the unsupported platforms and the SHA
pin without a version. They also cover the failures of the action itself
(the work directory, the archive, the SARIF report) and the archives that
hold a member that escapes the extraction directory, an absolute path, a
link, a name with a newline, a name behind a `./` prefix or a directory
entry. The tools that print an answer and then fail are checked too: `curl`,
`tar`, `unzip`, `awk` and the runtimes that read JSON have to be refused
when they fail after they printed, and the action has to stop before the
scanner runs. Every call to `curl` has to start with `-q`, and the real
`curl` is checked against a `.curlrc` that turns the tracing on: the token
of the API call must never reach the log. The archives are also built with
the real `tar` and read with the real `unzip`, so the members of a real
archive are checked and not only the ones of the stubs.

The release list of the API is read strictly: a page that is not a list, a
record that is not an object, a `tag_name` that is not a string and a
`draft` or a `prerelease` that is not a boolean are refused by every
runtime of the machine that can read them, and a valid page still resolves
the highest stable `v0.x.y` release. The output of the action is checked
too: a function that cannot write its answer returns a failure, and never
a success.

The tests need `bash`, `tar`, `unzip`, a `python` with the `zipfile`
module, `curl` and a `python` or `node` runtime that can read JSON. The
script prints that list when it starts, and a missing tool fails the run
with a message that names it: a case that cannot run would hide a problem
of the action. The tests run on Linux, on macOS and on Windows under Git
Bash. Only the cases that need a real symbolic or hard link are skipped,
and only on a machine that cannot create one: Git Bash for Windows copies
the file instead of linking it. A failed output is checked with
`/dev/full` when the machine has that device, and with a `printf` that
fails on the answer of the function on every machine.
