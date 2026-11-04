# Using disdetta in CI

This page is a task guide. It says what to gate on, how to run the scanner
in each CI system, how to read the report and how to suppress a finding you
accept for now.

The rules and the diagnostic codes are in
[docs/diagnostics](../diagnostics/README.md). The contract is in
[docs/spec/v0.1.md](../spec/v0.1.md). The sources the scanner reads are in
[docs/usage/sources.md](sources.md).

Status: there is no release yet. Every `v0.1.0` in this page is a placeholder
for the first release. The release page does not exist, so the download and
verification commands below fail today and were not run: there is nothing to
download. Every other command in this page was run against the fixtures of
this repository, and the output shown is the real output. The few steps
that need a CI agent are marked where they appear.

## 1. What to gate on

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scan is complete and no finding is at or above the threshold. |
| 1 | The policy failed: at least one finding is at or above the threshold. |
| 2 | Usage error or fatal error: an unknown flag value, a missing root, an unreadable root, an invalid ignore file. |
| 3 | The policy passed but the scan is incomplete: at least one error level diagnostic. |

Code 1 wins over code 3. A scan that found a finding and was incomplete
exits 1.

The commands below use the fixtures of this repository. The exit code after
each command is the real one. The binary is built first, because `go run`
does not pass the exit code through:

```sh
go build -o disdetta ./cmd/disdetta
```

```sh
./disdetta scan testdata/repos/helm --fail-on high; echo $?
```

```text
1
```

```sh
./disdetta scan testdata/repos/helm --fail-on none; echo $?
```

```text
0
```

```sh
./disdetta scan testdata/repos/helm --fail-on bogus; echo $?
```

```text
disdetta: invalid --fail-on \"bogus\" (want high, medium, low, or none)
2
```

### Build the binary, do not use `go run`

`go run` does not pass the exit code through. It prints the real code on
stderr as `exit status N` and exits with 1 for every failure, so a usage
error (2) and an incomplete scan (3) both look like a policy failure (1):

```sh
go run ./cmd/disdetta scan testdata/repos/helm --fail-on bogus; echo $?
```

```text
exit status 2
1
```

The exit codes of this page were checked with the built binary, which
returns them unchanged. Build the binary once and run the binary in CI.
The rest of this page uses `./disdetta` for that reason.

### The threshold

`--fail-on` decides which findings fail the policy. The default of the
command is `low`, so every finding fails by default.

| Value | Fails when |
| --- | --- |
| `high` | A finding of severity `high` exists. |
| `medium` | A finding of severity `high` or `medium` exists. |
| `low` | A finding of any severity exists. This is the default. |
| `none` | Never. The policy always passes. |

The value is a threshold, not an exact match: `--fail-on medium` also fails
on a `high` finding.

### Three outcomes that are not the same

Exit 0 covers two different outcomes, and CI usually wants to tell them
apart.

1. **No findings.** The scan is complete and nothing was found.
2. **Findings below the threshold.** The scan is complete and found
   something, but nothing at or above the threshold. The exit code is still
   0. The findings are listed in the report and in the summary line, so the
   report is the place to read them, not the exit code.
3. **Incomplete scan.** The scan could not read or parse everything. The
   exit code is 3.

Outcome 2, a file with a single chart finding and the threshold `high`:

```sh
./disdetta scan testdata/repos/helm/Chart.yaml --fail-on high; echo $?
```

```text
LOCATION         RULE         SEVERITY  CONFIDENCE  IMPACT  REFERENCE
Chart.yaml:7:17  DSD-CHT-001  medium    confirmed   high    https://charts.bitnami.com/bitnami
scanned 1 files, skipped 0, findings 1 (high 0, medium 1, low 0), diagnostics 0, unresolved 0, ignored 0
0
```

Outcome 3, a file the scanner cannot parse:

```sh
printf 'a: [1, 2\nb: }\n' > values.yaml
./disdetta scan values.yaml --fail-on none; echo $?
```

```text
LOCATION     RULE         SEVERITY  CONFIDENCE  IMPACT  REFERENCE
values.yaml  DSD-SCN-001  error     -           -       malformed YAML
scanned 1 files, skipped 0, findings 0 (high 0, medium 0, low 0), diagnostics 1, unresolved 0, ignored 0
3
```

### Why CI must treat 3 as a failure

Exit 3 means the scan is not trustworthy. A file that could not be parsed
may hold findings that were never reported, so a green job on exit 3 says
"nothing was found" when the truth is "part of the tree was not read".

The error level diagnostics that make a scan incomplete are
[DSD-SCN-001](../diagnostics/DSD-SCN-001.md) (malformed file),
[DSD-SCN-004](../diagnostics/DSD-SCN-004.md) (read error),
[DSD-SCN-008](../diagnostics/DSD-SCN-008.md) (file over the size limit) and
[DSD-SCN-009](../diagnostics/DSD-SCN-009.md) (Helm release payload over a
cap). A warning, such as [DSD-SCN-002](../diagnostics/DSD-SCN-002.md) or
[DSD-SCN-005](../diagnostics/DSD-SCN-005.md), does not make the scan
incomplete.

A CI job must therefore fail on 1 and on 3. Failing on 2 as well is right:
a usage error means the scan never ran.

## 2. GitHub Actions

### The action

The repository ships a composite action that downloads the release, verifies
it and runs the scan. The full reference is in
[docs/usage/github-action.md](github-action.md).

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

The action passes the exit code of the scanner through unchanged. Two codes
belong to the action itself and never come from the scanner: 64 for an
invalid input and 70 for a failure of the action, such as a download or a
verification that did not pass. See
[the exit codes of the action](github-action.md#exit-codes).

The action defaults to `fail-on: high`, while the command defaults to
`--fail-on low`. The threshold is set in the `fail-on` input of the action
and in the `--fail-on` flag of the command.

### The binary, without the action

If you do not want the action, download the release, verify it and run the
binary. The verification steps are the ones of
[docs/security/verifying-releases.md](../security/verifying-releases.md):
the checksum file is checked against the archive and the checksum file is
checked against the keyless cosign signature of the release workflow.

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
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2 (cosign v3.0.6)
      - name: Download and verify disdetta
        run: |
          set -euo pipefail
          version=v0.1.0
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/disdetta_${version}_linux_amd64.tar.gz"
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/checksums.txt"
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/checksums.txt.sigstore.json"
          grep "disdetta_${version}_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
          cosign verify-blob --bundle checksums.txt.sigstore.json \
            --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/${version}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            checksums.txt
          tar -xzf "disdetta_${version}_linux_amd64.tar.gz" disdetta
      - name: Scan
        run: ./disdetta scan . --fail-on high --format sarif > disdetta.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: disdetta.sarif
```

The download block was not run: there is no release yet. The scan step was
run with the binary of this repository in place of the downloaded one: it
writes the SARIF file and exits with the code of the scanner. The upload
step was not run, because it needs a GitHub runner.

The report goes to stdout and the exit code comes after it, so the SARIF
file is written even when the scan fails the policy. The upload step uses
`if: always()` so the findings reach code scanning anyway.

### SARIF and code scanning

`--format sarif` writes one deterministic SARIF 2.1.0 run. The format is
described in [docs/usage/sarif.md](sarif.md).

The upload needs the `security-events: write` permission. Without it the
scan still runs and the report is still written, but nothing is uploaded.
A pull request from a fork gets a read-only token, so the upload does not
happen there either.

## 3. GitLab CI

```yaml
stages:
  - test

disdetta:
  stage: test
  image: ubuntu:24.04
  variables:
    DISDETTA_VERSION: v0.1.0
  before_script:
    - apt-get update
    - apt-get install -y --no-install-recommends curl ca-certificates
    - curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${DISDETTA_VERSION}/disdetta_${DISDETTA_VERSION}_linux_amd64.tar.gz"
    - curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${DISDETTA_VERSION}/checksums.txt"
    - curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${DISDETTA_VERSION}/checksums.txt.sigstore.json"
    - grep "disdetta_${DISDETTA_VERSION}_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
    - cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/${DISDETTA_VERSION}" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" checksums.txt
    - tar -xzf "disdetta_${DISDETTA_VERSION}_linux_amd64.tar.gz" disdetta
  script:
    - |
      set +e
      ./disdetta scan . --fail-on high --format json > disdetta-report.json
      code=$?
      set -e
      echo "disdetta exit code $code"
      if [ "$code" -ne 0 ]; then exit "$code"; fi
  artifacts:
    when: always
    paths:
      - disdetta-report.json
```

The download block was not run: there is no release yet. The script block
was run with the binary of this repository. It exits 1 when the policy
fails and 0 when the tree is clean, and it writes the report in both cases.

The runner image needs `curl`, `sha256sum` and `cosign`. The first two are
in the `ubuntu:24.04` image, `cosign` is not: install it on the runner
before the verification step.

The job fails on the exit code of the scanner. `artifacts: when: always`
keeps the report of a failed job, because the report is written before the
exit code.

### The Code Quality widget

The tool does not write the GitLab Code Quality format. The JSON report is
the versioned report document of
[schemas/report-v1.json](../../schemas/report-v1.json), not the array of
code quality entries GitLab expects, so the Code Quality widget stays
empty. Publish the report as a plain artifact and read it with `jq`, as in
the section "Reading the output".

## 4. Azure Pipelines and Jenkins

### Azure Pipelines

```yaml
trigger:
  - main

jobs:
  - job: disdetta
    pool:
      vmImage: ubuntu-latest
    steps:
      - bash: |
          set -euo pipefail
          version=v0.1.0
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/disdetta_${version}_linux_amd64.tar.gz"
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/checksums.txt"
          curl -q -fsSLO "https://github.com/HarnageaGabriel/disdetta/releases/download/${version}/checksums.txt.sigstore.json"
          grep "disdetta_${version}_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
          cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity "https://github.com/HarnageaGabriel/disdetta/.github/workflows/release.yml@refs/tags/${version}" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" checksums.txt
          tar -xzf "disdetta_${version}_linux_amd64.tar.gz" disdetta
        displayName: Download and verify disdetta
      - bash: |
          set +e
          ./disdetta scan . --fail-on high --format json > disdetta-report.json
          code=$?
          set -e
          echo "##vso[task.logissue type=error]disdetta exit code $code"
          exit $code
        displayName: disdetta scan
      - task: PublishPipelineArtifact@1
        condition: always()
        inputs:
          targetPath: disdetta-report.json
```

The download step was not run: there is no release yet. The scan step was
run with the binary of this repository: it exits with the code of the
scanner and writes the report. The publish task was not run, because it
needs an Azure Pipelines agent.

The runner image needs `curl`, `sha256sum` and `cosign`. The first two are
in the `ubuntu-latest` image, `cosign` is not: install it before the
verification step.

Azure Pipelines fails a step whose script exits with a non-zero code, so
the `exit $code` at the end of the scan step is what gates the job. The
`##vso[task.logissue]` line adds the code to the error list of the step.

### Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('disdetta') {
      steps {
        sh 'disdetta scan . --fail-on high --format json > disdetta-report.json'
      }
      post {
        always {
          archiveArtifacts artifacts: 'disdetta-report.json', allowEmptyArchive: true
        }
      }
    }
  }
}
```

The shell command was run with the binary of this repository: it exits with
the code of the scanner and the report is written before that code is
returned. The step itself was not run in Jenkins, because no agent was
available.

To tell "policy failed" from "scan incomplete", capture the code:

```groovy
        script {
          def code = sh(returnStatus: true, script: 'disdetta scan . --fail-on high --format json > disdetta-report.json')
          if (code == 1) {
            error('disdetta: findings at or above the threshold')
          }
          if (code == 3) {
            error('disdetta: the scan was incomplete')
          }
          if (code != 0) {
            error("disdetta: failed with exit code ${code}")
          }
        }
```

This block was not run: it needs a Jenkins agent.

A `Jenkinsfile` is not a YAML file, so the scanner never reads it.

## 5. Pre-commit and local use

### Run on the staged files

The command takes one path, so the staged files are scanned one by one.
This runs in the root of the repository:

```sh
git diff --cached --name-only --diff-filter=ACM | while read -r f; do
  disdetta scan "$f" --fail-on high || exit 1
done
```

The loop was run in a scratch repository with one staged file that holds a
finding: it exits 1 and prints the finding. With a staged file that holds
no finding it exits 0.

`--diff-filter=ACM` keeps the added, copied and modified files. A deleted
file is not scanned. The loop stops at the first file that fails, and the
exit code of the pipeline is the exit code of the loop.

### Scan one subtree of a monorepo

The path argument is the root of the scan, and the paths of the report are
relative to it:

```sh
disdetta scan services/api --fail-on high
```

The same command against a fixture subtree of this repository:

```sh
./disdetta scan testdata/repos/helm --fail-on high; echo $?
```

```text
scanned 3 files, skipped 0, findings 5 (high 3, medium 2, low 0), diagnostics 0, unresolved 0, ignored 0
1
```

A path that does not exist is a fatal error and exits 2.

### Exclude a directory

`--exclude` takes a glob that is relative to the root of the scan and uses
forward slashes. `*` stays inside one path segment and `**` crosses
segments. The pattern is anchored: `helm/**` matches `helm/values.yaml` but
not `charts/helm/values.yaml`, and `**/helm/**` matches
`charts/helm/values.yaml` but not `helm/values.yaml`. Use both patterns
when both shapes are possible.

```sh
disdetta scan . --exclude 'helm/**' --exclude '**/helm/**' --exclude 'vendor/**'
```

The flag is repeatable. An excluded file is not scanned and is not counted
as scanned or skipped. Against the fixtures of this repository the two
`helm` patterns removed three files: 43 files scanned without them, 40 with
them.

### The ignore file

The ignore file suppresses findings that are accepted for now. It is read
from `.disdetta.yaml` in the root of the scan, or from the file given with
`--config`. The section "Suppressing a finding" below has the schema and an
example.

### Performance

The scan reads the files with a pool of workers. The number of workers is
the number of CPUs, capped at eight. `DISDETTA_WORKERS` sets it:

```sh
DISDETTA_WORKERS=1 disdetta scan .
```

A value of 1 makes the scan sequential. Use it on a machine with little
memory: the pool multiplies the peak memory of a scan by the number of
workers, because up to eight files are parsed at the same time. A positive
value above eight is taken as it is.

The report does not depend on the number of workers. The same tree scanned
with 1 and with 4 workers gave byte for byte the same report.

The cost of a scan and the limits are described in
[docs/performance.md](../performance.md).

## 6. Reading the output

The JSON report is the versioned document of
[schemas/report-v1.json](../../schemas/report-v1.json). Write it with
`--format json`:

```sh
disdetta scan . --fail-on none --format json > disdetta-report.json
```

The report is written before the exit code, so the file is there even when
the policy fails.

The examples below were run against the report of the fixtures of this
repository (`disdetta scan testdata/repos --fail-on none --format json`).

### Count the findings by rule

```sh
jq -r '.findings | group_by(.ruleId)[] | "\(.[0].ruleId) \(length)"' disdetta-report.json
```

```text
DSD-CFG-001 6
DSD-CHT-001 23
DSD-CHT-002 1
DSD-IMG-001 19
DSD-IMG-002 18
DSD-IMG-003 6
DSD-IMG-004 1
```

### List the files that hold a high severity finding

```sh
jq -r '.findings[] | select(.severity == "high") | .location.path' disdetta-report.json | sort -u
```

```text
actions/.github/workflows/ci.yml
argocd/application.yaml
azure/azure-pipelines.yml
compose/compose.yaml
corpus-fallback/values.yaml
dockerfile/Dockerfile.test
flux/repository.yaml
gitlab/.gitlab-ci.yml
helm-template/templates/helpers.tpl
helm/Dockerfile
helm/values.yaml
helmfile/helmfile.yaml
helmfile/helmfile.yaml.gotmpl
kustomize/base/Kustomization
kustomize/helm-chart-inflation-generator.yaml
kustomize/kustomization.yaml
kustomize/overrides.yaml
kustomize/values.yaml
nested-values/values.yaml
shellcmds/.gitlab-ci.yml
terraform/main.tf
yaml-default/deploy/anything.yml
yaml-default/postgresql.yaml
```

### List the unresolved references

A finding with the confidence `unresolved` holds a templated reference:

```sh
jq -r '.findings[] | select(.confidence == "unresolved") | "\(.location.path):\(.location.line) \(.reference)"' disdetta-report.json
```

```text
terraform/main.tf:64 docker.io/bitnami/redis:{{...}}
terraform/main.tf:95 docker.io/bitnami/redis:{{...}}
terraform/main.tf:60 oci://registry-1.docker.io/bitnamicharts/{{...}}
```

The scanner prints one ellipsis character inside the braces for the
templated part of the reference. It is written as `...` here, because this
page is ASCII only.

A reference with no static Bitnami evidence is not a finding: it is the
diagnostic `DSD-SCN-003`:

```sh
jq -r '.diagnostics[] | select(.code == "DSD-SCN-003") | "\(.location.path):\(.location.line) \(.message)"' disdetta-report.json
```

```text
helm-template/templates/restart-job.yaml:19 unresolved reference without Bitnami evidence
terraform/main.tf:37 unresolved reference without Bitnami evidence
terraform/main.tf:39 unresolved reference without Bitnami evidence
```

The summary counts the diagnostics, not the unresolved findings:

```sh
jq -r '.summary | "files=\(.filesScanned) findings=\(.findings.high + .findings.medium + .findings.low) complete=\(.complete) unresolved=\(.unresolved)"' disdetta-report.json
```

```text
files=37 findings=74 complete=true unresolved=3
```

Two checks are useful in a pipeline. The first fails when the scan was not
complete, the second when a high severity finding exists:

```sh
jq -e '.summary.complete' disdetta-report.json > /dev/null
```

```sh
jq -e '[.findings[] | select(.severity == "high")] | length == 0' disdetta-report.json > /dev/null
```

### What the confidence levels mean

| Confidence | Meaning |
| --- | --- |
| `confirmed` | The whole reference is literal and its namespace is on Docker Hub. |
| `inferred` | The namespace is under another registry, so the image is a mirror or a rebuild, or the reference was found as a whole scalar under a key the scanner does not know. |
| `unresolved` | Part of the reference is templated and the static part names a Bitnami namespace. |

The confidence says how sure the scanner is, not how urgent the finding is.
The severity says the urgency and the impact says how hard the migration is.
The rules are described in [docs/spec/v0.1.md](../spec/v0.1.md) section 2.

## 7. Suppressing a finding

The only supported way to suppress a finding is the ignore file. The file
is `.disdetta.yaml` in the root of the scan, or the file given with
`--config`.

The file holds a list of entries under the key `ignores`. Each entry selects
a finding in one of two ways, and the two ways cannot be mixed in one
entry:

- `fingerprint`: the 16 hexadecimal characters of the fingerprint of one
  finding. It selects that finding and nothing else.
- `rule` and `path`: the rule ID and the path of the file, with `*`, `**`
  and `?` as in the `--exclude` flag. It selects every finding of that rule
  in the files that match.

The path is anchored, like the `--exclude` glob. `values.yaml` matches a
file in the root of the scan and `**/values.yaml` matches a file in a
directory, but neither matches both. Use the path as the report prints it.

Every entry needs a `reason` and an `expires` date in the `YYYY-MM-DD`
form. An expired entry stops suppressing the finding and is reported as the
warning `DSD-SCN-006`. An entry without a reason, without a date, with an
unknown rule or with a path that uses backslashes is refused, and the scan
exits 2. An entry that names both a fingerprint and a rule is refused too.

The schema is:

```yaml
ignores:
  - fingerprint: ff1cf778c8835376
    reason: migration scheduled for Q4
    expires: 2026-12-31
  - rule: DSD-IMG-001
    path: charts/legacy/values.yaml
    reason: frozen archive, reviewed with the platform team
    expires: 2026-12-31
```

The fingerprint of a finding is in the report:

```sh
jq -r '.findings[] | select(.ruleId == "DSD-IMG-001") | "\(.fingerprint) \(.location.path):\(.location.line) \(.reference)"' disdetta-report.json
```

```text
f97ceb5c87102d56 argocd/application.yaml:12 docker.io/bitnamilegacy/redis:7
1e5022b0f0dc9fe2 corpus-fallback/values.yaml:4 registry.example.internal/mirror/bitnamilegacy/redis:7.2
```

A worked example, on a tree with one finding:

```sh
printf 'image:\n  repository: bitnamilegacy/postgresql\n  tag: "16.4.0"\n' > values.yaml
disdetta scan . --fail-on high; echo $?
```

```text
LOCATION          RULE         SEVERITY  CONFIDENCE  IMPACT  REFERENCE
values.yaml:2:15  DSD-IMG-001  high      confirmed   high    docker.io/bitnamilegacy/postgresql:16.4.0
scanned 1 files, skipped 0, findings 1 (high 1, medium 0, low 0), diagnostics 0, unresolved 0, ignored 0
1
```

With the ignore file, written as `.disdetta.yaml` in the root of the scan:

```yaml
ignores:
  - rule: DSD-IMG-001
    path: values.yaml
    reason: migration scheduled for Q4
    expires: 2026-12-31
```

```sh
disdetta scan . --fail-on high; echo $?
```

```text
LOCATION  RULE  SEVERITY  CONFIDENCE  IMPACT  REFERENCE
scanned 1 files, skipped 0, findings 0 (high 0, medium 0, low 0), diagnostics 0, unresolved 0, ignored 1
0
```

The suppressed findings are counted in `ignored` and are not in the report.
The same entry with an expired date suppresses nothing and is reported:

```text
LOCATION          RULE         SEVERITY  CONFIDENCE  IMPACT  REFERENCE
values.yaml:2:15  DSD-IMG-001  high      confirmed   high    docker.io/bitnamilegacy/postgresql:16.4.0
.disdetta.yaml    DSD-SCN-006  warning   -           -       ignore entry expired
scanned 1 files, skipped 0, findings 1 (high 1, medium 0, low 0), diagnostics 1, unresolved 0, ignored 0
1
```

### What to do instead of suppressing

An ignore entry is a promise with a date, not a fix. When the migration of
a component is known, `disdetta plan` writes the values of the destination
chart and the checklist of the steps. The advice is in
[docs/usage/plan.md](plan.md).

## Related pages

- [GitHub Action](github-action.md)
- [SARIF output](sarif.md)
- [Sources scanned](sources.md)
- [Verifying releases](../security/verifying-releases.md)
- [Performance and limits](../performance.md)
- [Findings and scan diagnostics](../diagnostics/README.md)
