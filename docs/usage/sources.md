# Sources scanned

`disdetta scan [path]` reads a repository file by file. This page lists every
source it reads, the rule IDs each source can report, and what it deliberately
does not report.

Rule IDs and their meaning: [docs/diagnostics](../diagnostics/README.md).
The contract: [docs/spec/v0.1.md](../spec/v0.1.md) section 9.

Every example below is copied from a fixture in `testdata/repos/` or in
`testdata/cluster/`, and from the finding the scanner reports on it. The output
blocks show only the lines of the quoted input, not the whole scan.

Only these files are opened: `*.yaml`, `*.yml`, `*.tpl`, `*.yaml.gotmpl`,
`*.tf`, `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, and the Kustomization
files `kustomization.yaml`, `kustomization.yml` and `Kustomization`. Every
other file is visited by the walk but never read. The ignore file
`.disdetta.yaml` is read as configuration, never scanned.

## Helm values files

Any `*.yaml` or `*.yml` file is read as YAML and scanned with the values
rules.

Detected:

- `DSD-CFG-001`: `global.security.allowInsecureImages: true`, at the top level
  or under a subchart key.
- `DSD-IMG-001`, `DSD-IMG-002`, `DSD-IMG-003`, `DSD-IMG-004`: images of the
  Bitnami namespaces, whatever the key that holds them.
- An image triple is recognized wherever a mapping has a `repository` whose
  value is image-shaped, not only under a key named `image`. The sibling keys
  `registry`, `tag` and `digest` are joined to it.

Not detected:

- Values are never rendered. A reference whose static part names a Bitnami
  namespace is reported with confidence `unresolved`; a reference with no
  static Bitnami evidence is only the info diagnostic `DSD-SCN-003`.
- A value under a `Secret` is never printed.

Input (`testdata/repos/helm/values.yaml`):

```yaml
global:
  imageRegistry: docker.io
  security:
    allowInsecureImages: true
image:
  repository: bitnamilegacy/postgresql
  tag: 16.4.0
```

Output:

```text
values.yaml:6:15   DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16.4.0
values.yaml:4:26   DSD-CFG-001  high      confirmed   unknown  true
```

A subchart key and a non-`image` key are read too
(`testdata/repos/nested-values/values.yaml`):

```text
values.yaml:6:28   DSD-CFG-001  high      confirmed   unknown  true
values.yaml:10:17  DSD-IMG-001  high      confirmed   low      docker.io/bitnamilegacy/os-shell
```

## Helm chart dependencies

A `Chart.yaml` is read as a chart definition.

Detected:

- `DSD-CHT-001`: a dependency on a Bitnami chart source, in
  `https://charts.bitnami.com/bitnami` form or in the two OCI forms.
- `DSD-CHT-002`: a Bitnami chart vendored in the repository, that is a
  `Chart.yaml` whose `sources` or `home` point to `github.com/bitnami/charts`,
  or whose `annotations.images` list Bitnami images. One finding per vendored
  chart.

Input (`testdata/repos/helm/Chart.yaml`):

```yaml
dependencies:
  - name: postgresql
    version: 16.0.0
    repository: https://charts.bitnami.com/bitnami
```

Output:

```text
Chart.yaml:7:17    DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
```

A vendored chart (`testdata/repos/chart-vendored/Chart.yaml`):

```text
Chart.yaml:14:5  DSD-CHT-002  medium    confirmed   high    https://github.com/bitnami/charts/tree/main/bitnami/postgresql
```

## Helm templates

Templates are not YAML, so they are read line by line instead of being
reported as malformed. A file is read as template text when it is under the
`templates/` directory of a chart, when it ends with `.tpl` or
`.yaml.gotmpl`, or when it does not parse as YAML and contains `{{`.

Detected:

- The scalar after an `image:` or a `repository:` key, quoted or not.
- A quoted image literal inside `{{ }}`, for example
  `default "bitnami/kubectl:1.30"`, with confidence `inferred`.

Not detected:

- Comment lines, both `#` and `{{/* */}}`.
- A templated registry or repository: the static part is kept and the finding
  has confidence `unresolved`.

Each template file adds one info diagnostic `DSD-SCN-007` ("file read as
template text"). The scan stays complete.

Input (`testdata/repos/helm-template/templates/helpers.tpl`):

```gotmpl
{{ .Values.kubectlImage | default "bitnami/kubectl:1.30" }}
```

Output:

```text
templates/helpers.tpl:2:1  DSD-IMG-002  high  inferred  low  docker.io/bitnami/kubectl:1.30
```

## Plain Kubernetes manifests

Every pod spec of a plain manifest is read, whatever the workload kind.

Detected: the image of every `containers`, `initContainers` and
`ephemeralContainers` entry, with the `DSD-IMG-*` rules.

Input (`testdata/cluster/basic/objects.yaml`, read as a plain manifest):

```yaml
      containers:
        - name: postgresql
          image: bitnami/postgresql:16.4.0-debian-12-r2
```

Output:

```text
objects.yaml:60:18  DSD-IMG-002  high  confirmed  high  docker.io/bitnami/postgresql:16.4.0-debian-12-r2
```

## Flux

Detected:

- `DSD-CHT-001`: the `spec.url` of a `HelmRepository`, and the `spec.url` of an
  `OCIRepository`.
- The `spec.values` of a `HelmRelease`, with the `DSD-IMG-*` rules and with
  `DSD-CFG-001`.

Input (`testdata/repos/flux/repository.yaml`):

```yaml
kind: HelmRepository
spec:
  type: oci
  url: oci://registry-1.docker.io/bitnamicharts
```

Output:

```text
repository.yaml:7:8   DSD-CHT-001  medium    confirmed   unknown  oci://registry-1.docker.io/bitnamicharts
repository.yaml:16:19  DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
```

## Argo CD

Detected, in an `Application` or an `ApplicationSet`:

- `DSD-CHT-001`: the `spec.source.repoURL`.
- The `spec.source.helm.values` and `spec.source.helm.valuesObject`, with the
  `DSD-IMG-*` rules and with `DSD-CFG-001`.
- The `spec.source.chart` gives the component of the chart finding.

Input (`testdata/repos/argocd/application.yaml`):

```yaml
spec:
  source:
    repoURL: https://charts.bitnami.com/bitnami
    chart: redis
    helm:
      values: |
        image:
          repository: bitnamilegacy/redis
          tag: 7
```

Output:

```text
application.yaml:12:15  DSD-IMG-001  high      confirmed   high    docker.io/bitnamilegacy/redis:7
application.yaml:7:14   DSD-CHT-001  medium    confirmed   high    https://charts.bitnami.com/bitnami
application.yaml:17:25  DSD-IMG-003  medium    confirmed   high    docker.io/bitnami/redis-exporter
```

## Kustomize

A Kustomization file is `kustomization.yaml`, `kustomization.yml` or the
extensionless `Kustomization`, matched case-insensitively. A
`HelmChartInflationGenerator` document is detected by its kind, in any file.

Detected:

- `DSD-IMG-*`: the `images[].newName` of a Kustomization, with its `newTag`.
- `DSD-CHT-001`: the `repo` of a `helmCharts[]` entry and the `repo` of a
  `HelmChartInflationGenerator`.
- The `valuesInline` images of both, and the `valuesFile` of both.

Not detected:

- A `valuesFile` that leaves the scan root is refused: an absolute path, a
  path that escapes the root with `..`, and a path that reaches a symbolic
  link are all refused. The refusal is reported as `DSD-SCN-004` (read error)
  and the scan stays incomplete.
- Known difference from kustomize: the `valuesFile` of a generator is resolved
  relative to the directory of the generator file, while kustomize resolves it
  relative to the kustomization root.

Input (`testdata/repos/kustomize/kustomization.yaml`):

```yaml
images:
  - name: example/redis
    newName: bitnami/redis
    newTag: "7"
helmCharts:
  - name: postgresql
    repo: https://charts.bitnami.com/bitnami
    version: 12.5.6
    valuesInline:
      image:
        repository: bitnamilegacy/postgresql
        tag: "16.4.0"
    valuesFile: values.yaml
```

Output:

```text
kustomization.yaml:3:14   DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
kustomization.yaml:12:21  DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16.4.0
kustomization.yaml:8:11   DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
```

The `valuesFile` is read as chart values
(`testdata/repos/kustomize/values.yaml`):

```text
values.yaml:2:15   DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16.4.0
```

A generator (`testdata/repos/kustomize/helm-chart-inflation-generator.yaml`):

```text
helm-chart-inflation-generator.yaml:10:17  DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16.4.0
helm-chart-inflation-generator.yaml:5:7    DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
```

## Helmfile

The Helmfile files are `helmfile.yaml`, `helmfile.yml`, the `*.yaml` files of
a `helmfile.d` directory, and the `*.yaml.gotmpl` files.

Detected:

- `DSD-CHT-001`: a repository whose `url` is a Bitnami chart source, and a
  release whose `chart` uses it.
- The image rules on the inline values of a release.

One dependency is one finding:

- A release that uses the Bitnami chart repository is reported on its `chart:`
  entry, and the repository URL is not reported a second time.
- A repository that no release uses is reported on its `url:` entry.
- A release may name the OCI chart source directly, as
  `chart: oci://registry-1.docker.io/bitnamicharts/<chart>`.
- The repositories and the releases of a file are resolved together, whatever
  their order, and a `---` separated document of the same file counts too.

Not detected:

- Layers and bases are not followed. The `helmfiles:` and `bases:` includes are
  not read, so a repository alias declared in another file is unknown in the
  file that uses it and the release is not reported.
- A templated `chart:`, `version:` or `values:` entry names no repository
  alias, and a templated repository URL is never certain: neither is a finding.
- A gotmpl file is read line by line, not as YAML. A flow-style entry written
  on one line inside a list is not read, and a template action line with a
  trailing comment ends the section of the file.

Input (`testdata/repos/helmfile/helmfile.yaml`):

```yaml
repositories:
  - name: bitnami
    url: https://charts.bitnami.com/bitnami
  - name: oci-unused
    url: oci://registry-1.docker.io/bitnamicharts
    oci: true
releases:
  - name: db
    chart: bitnami/postgresql
    values:
      - image: {repository: bitnamilegacy/postgresql}
```

Output:

```text
helmfile.yaml:16:29  DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql
helmfile.yaml:14:12  DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
helmfile.yaml:8:10   DSD-CHT-001  medium    confirmed   unknown  oci://registry-1.docker.io/bitnamicharts
```

The include is not followed (`testdata/repos/helmfile/helmfile.d/includes.yaml`),
so its release is not reported:

```yaml
helmfiles:
  - path: ../shared/helmfile.yaml
bases:
  - ../shared/base
releases:
  - name: db
    chart: bitnami/postgresql
```

A gotmpl file (`testdata/repos/helmfile/helmfile.yaml.gotmpl`) is read line by
line, and adds one info diagnostic `DSD-SCN-007`:

```gotmpl
repositories:
- name: bitnami
  url: https://charts.bitnami.com/bitnami
releases:
- name: cache
  chart: bitnami/redis
  values:
  - image: {repository: bitnamilegacy/redis}
```

Output:

```text
helmfile.yaml.gotmpl:8:25  DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/redis
helmfile.yaml.gotmpl:6:10  DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
```

## Dockerfile

Detected:

- `FROM`, with the platform flag, the `ARG` defaults of the build stage and
  the line continuations.
- `COPY --from`, whether the stage is a name or an image.
- `RUN` commands, with the rules of the shell commands section below.

Not detected: comment lines.

Input (`testdata/repos/dockerfile/Dockerfile.test`):

```dockerfile
ARG REGISTRY=docker.io
FROM --platform=linux/amd64 \
  ${REGISTRY}/bitnami/redis:7 AS build
COPY --from=build /tmp/x /tmp/x
COPY --from=bitnamilegacy/postgresql:16 /tmp/y /tmp/y
# FROM bitnami/comment:1
```

Output:

```text
Dockerfile.test:2:1  DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
Dockerfile.test:5:1  DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql:16
```

## Docker Compose

Detected: the `image` of every service, with the `DSD-IMG-*` rules.

Not detected: an `image` key outside `services`.

Input (`testdata/repos/compose/compose.yaml`):

```yaml
services:
  database:
    image: bitnami/postgresql:16
x-unrelated:
  image: bitnami/not-a-service:1
```

Output:

```text
compose.yaml:3:12  DSD-IMG-002  high      confirmed   high     docker.io/bitnami/postgresql:16
```

## GitHub Actions

The workflow files under `.github/workflows/` are read.

Detected:

- The `container` of a job, as a string or as a mapping with an `image`.
- The `image` of a service.
- A step that uses `uses: docker://<image>`.

Input (`testdata/repos/actions/.github/workflows/ci.yml`):

```yaml
jobs:
  test:
    container: bitnami/go:1
    services:
      redis:
        image: bitnami/redis:7
    steps:
      - uses: docker://bitnami/kubectl:1
```

Output:

```text
.github/workflows/ci.yml:6:16  DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
.github/workflows/ci.yml:3:16  DSD-IMG-002  high      confirmed   medium   docker.io/bitnami/go:1
.github/workflows/ci.yml:8:15  DSD-IMG-002  high      confirmed   low      docker.io/bitnami/kubectl:1
```

## GitLab CI

The files `.gitlab-ci.yml`, `.gitlab-ci.yaml` and the files ending with
`.gitlab-ci.yml` or `.gitlab-ci.yaml` are read.

Detected:

- The `image` of `default` and of a job, both the string form and the `name:`
  form.
- The `services` of a job.

Not detected: an `image` key under `variables`, which is not a container.

Input (`testdata/repos/gitlab/.gitlab-ci.yml`):

```yaml
default:
  image:
    name: bitnami/base:1
build:
  services:
    - bitnami/redis:7
variables:
  image: bitnami/not-a-container:1
```

Output:

```text
.gitlab-ci.yml:6:7   DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
.gitlab-ci.yml:3:11  DSD-IMG-002  high      confirmed   medium   docker.io/bitnami/base:1
```

## Azure Pipelines

The files whose name starts with `azure-pipelines` and ends with `.yaml` or
`.yml` are read.

Detected:

- The `container` of a job and the `image` of `resources.containers[]`.
- The services of a job.

Input (`testdata/repos/azure/azure-pipelines.yml`):

```yaml
resources:
  containers:
    - container: tools
      image: bitnami/kubectl:1
jobs:
  - job: test
    services:
      redis: bitnami/redis:7
```

Output:

```text
azure-pipelines.yml:8:14  DSD-IMG-002  high      confirmed   high     docker.io/bitnami/redis:7
azure-pipelines.yml:4:14  DSD-IMG-002  high      confirmed   low      docker.io/bitnami/kubectl:1
```

## Terraform

The `*.tf` files are parsed, never evaluated.

Detected, in a `helm_release` resource:

- `DSD-CHT-001`: the `repository` attribute and a `chart` that names the OCI
  chart source.
- The image rules on the `values` attribute, read as embedded YAML documents
  and as `yamlencode` objects.
- The image rules on a `set`, `set_list` or `set_sensitive` block, read as
  single values.

Not detected:

- No function, variable, file or environment value is ever resolved. A
  component that is not a literal, the tag or the registry of an image triple
  or the name of a chart, keeps only its static part: the finding is reported
  with confidence `unresolved`, and a reference without static Bitnami
  evidence stays the info diagnostic `DSD-SCN-003`.
- The arguments of `file(...)` are ignored: the referenced file is scanned on
  its own as a repository file, never through the expression that names it.
- Terraform JSON configuration, `.tf.json`, is out of scope and is not
  scanned.

Input (`testdata/repos/terraform/main.tf`):

```hcl
resource "helm_release" "postgres" {
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "postgresql"

  values = [yamlencode({
    image = {
      repository = "bitnamilegacy/postgresql"
    }
  })]
}
```

Output:

```text
main.tf:8:20   DSD-IMG-001  high      confirmed   high     docker.io/bitnamilegacy/postgresql
main.tf:2:16   DSD-CHT-001  medium    confirmed   high     https://charts.bitnami.com/bitnami
```

A value that is not a literal stays an info diagnostic:

```hcl
resource "helm_release" "custom" {
  repository = var.chart_repository
  chart      = "postgresql"
  values = ["image: {{ .Values.image.repository }}"]
}
```

```json
{
  "code": "DSD-SCN-003",
  "level": "info",
  "message": "unresolved reference without Bitnami evidence",
  "location": {"path": "main.tf", "line": 37, "column": 16}
}
```

## Shell commands in CI scripts

CI files carry commands as strings: `script:`, `before_script:`, `run:`,
`steps[].script`, `bash:`, `pwsh:`, the Azure `script:` and the Dockerfile
`RUN`. The command line is tokenized, with POSIX-like quoting, line
continuations and the `&&`, `;` and `|` separators. Nothing is evaluated and no
variable is expanded.

Detected:

- The first non-option argument that is an image reference with a Bitnami
  namespace, after `docker`, `podman` or `nerdctl` with `run`, `create`,
  `pull` or `exec`, and after `docker build --from`. The options that take a
  value, such as `-v SRC:DST`, `-e K=V` and `--name N`, are skipped.
- `--image bitnami/...` and `--image=bitnami/...`, for example on `kubectl run`
  and on `docker buildx`.
- `helm repo add <name> <url>`, when the url is a Bitnami chart source.
- `helm install`, `upgrade`, `template` or `pull <release> <alias>/<chart>`,
  only when the same script block or the same file declared
  `helm repo add <alias> <Bitnami url>`. The component comes from `<chart>`.
- `helm ... oci://registry-1.docker.io/bitnamicharts/<chart>`.
- `--set image.repository=bitnamilegacy/...` and
  `--set global.security.allowInsecureImages=true` on a `helm` command line.

These findings have confidence `inferred`: a command line is not
configuration.

Not detected:

- Commented lines, and the arguments of `echo` or `printf`.
- `docker run busybox echo bitnami/kubectl`.
- `docker build -t bitnami/mycustom .`: a tag is created there, no image is
  pulled.

Only the reference is printed, never the rest of the command line.

Input (`testdata/repos/shellcmds/.gitlab-ci.yml`):

```yaml
build:
  script: docker run --rm -v /builds/${CI_PROJECT_PATH}/config:/.kube/config bitnami/kubectl:1.17.4 set image deployment/api api=bitnami/kubectl:1.17.4
```

Output:

```text
.gitlab-ci.yml:120:78  DSD-IMG-002  high      inferred    low      docker.io/bitnami/kubectl:1.17.4
```

Input (`testdata/repos/shellcmds/azure-pipelines.yml`):

```yaml
steps:
  - script: >-
      true && helm repo add bitnami https://charts.bitnami.com/bitnami
```

Output:

```text
azure-pipelines.yml:24:37  DSD-CHT-001  medium    inferred    unknown  https://charts.bitnami.com/bitnami
```

The release of a later `helm upgrade` is reported because the same file
declared the repository:

```yaml
  script: helm upgrade metrics-server-1617042143 bitnami/metrics-server
```

```text
azure-pipelines.yml:72:50  DSD-CHT-001  medium    inferred    medium   bitnami/metrics-server
```

## Whole-scalar fallback

Detected, in any YAML file:

- A scalar whose entire value is an image reference with a Bitnami namespace
  is a finding with confidence `inferred`, even under an unknown key.
- A scalar that contains a Bitnami chart repository URL is a chart finding, in
  any file: a chart-testing `ct.yaml` `chart-repos` list or a custom
  dependency list, for example.

Not detected: a partial match inside longer text, such as a path
`/opt/bitnami/...`, prose, or a URL to `github.com/bitnami`.

Input (`testdata/repos/corpus-fallback/values.yaml`):

```yaml
mirrored: registry.example.internal/mirror/bitnamilegacy/redis:7.2
kubectl: bitnamilegacy/kubectl:latest
```

Output:

```text
values.yaml:4:11  DSD-IMG-001  high      inferred    high     registry.example.internal/mirror/bitnamilegacy/redis:7.2
values.yaml:5:10  DSD-IMG-001  high      inferred    low      docker.io/bitnamilegacy/kubectl:latest
```

Input (`testdata/repos/corpus-fallback/ct.yaml`):

```yaml
chart-repos:
  - bitnami=https://charts.bitnami.com/bitnami/
```

Output:

```text
ct.yaml:3:5  DSD-CHT-001  medium    confirmed   unknown  https://charts.bitnami.com/bitnami/
```

## Cluster scan

`disdetta scan --cluster` reads a live cluster instead of a repository, and
reports the same rule IDs.

- Tiers 1 and 2 read the pod templates of the workloads and the Pod status.
- Tier 3 (`--read-helm-secrets`) reads the Helm release Secrets, and adds the
  `DSD-CFG-001` and `DSD-CHT-002` findings.
- A namespace outside the granted permissions is reported as `DSD-SCN-010`, and
  the scan continues.

Input (`testdata/cluster/basic/objects.yaml`):

```yaml
      containers:
        - name: postgresql
          image: bitnami/postgresql:16.4.0-debian-12-r2
```

Output:

```text
cluster/db/StatefulSet/pg            DSD-IMG-002  high      confirmed   high     docker.io/bitnami/postgresql:16.4.0-debian-12-r2
cluster/db/Secret/pg                  DSD-CHT-002  medium    confirmed   high     https://github.com/bitnami/charts/tree/main/bitnami/postgresql
```

The second line comes from the Helm release Secret, so it needs tier 3.

The contract is [docs/spec/v0.2-cluster.md](../spec/v0.2-cluster.md) and the
permissions are in [docs/cluster-rbac.md](../cluster-rbac.md).

## Limits

The scan of a hostile repository is bounded. A file larger than 16 MiB is not
scanned and the scan is incomplete (`DSD-SCN-008`). The YAML nesting depth is
256 levels and the alias expansion budget is 10000 nodes (`DSD-SCN-005`). A
Dockerfile instruction holds at most 10000 continuation lines. One file
reports at most 10000 findings and one repository scan at most 100000
(`DSD-SCN-005`). The time of a scan is linear in the number of YAML
documents, CI script steps and Dockerfile continuation lines it reads. The
full table of the limits, the cost of the worst cases and the threats they
answer are in [docs/performance.md](../performance.md) and in
[docs/threat-model.md](../threat-model.md).

## Related pages

- [SARIF output](sarif.md)
- [Rules command](rules.md)
- [`plan`](plan.md)
- [Findings and scan diagnostics](../diagnostics/README.md)
- [Performance and limits](../performance.md)
- [Threat model](../threat-model.md)
