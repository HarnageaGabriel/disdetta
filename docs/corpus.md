# Real-world corpus

disdetta's recall is measured on public repositories, pinned by commit, listed in
[tools/corpus/repos.txt](../tools/corpus/repos.txt) (repository, commit, license).
The corpus is not vendored: clone it locally and run the measurement.

```sh
# clone each repository at its pinned commit into a scratch directory, then:
disdetta scan <repo> --format json > <repo>.json   # one per repository
python tools/corpus/recall.py other                  # or: templates
```

`recall.py` compares disdetta's findings with a deliberately broad `rg` search
for Bitnami namespaces, chart sources and `allowInsecureImages: true`. The
broad search over-matches (container paths such as `/opt/bitnami/...`, URLs to
the Bitnami GitHub repository), so a "miss" is a lead to inspect, not a bug.
Ground truth is curated by hand in the review notes; the scanner author does not
label the corpus (differential authorship, see CONVENTIONS.md).

## Results

| Date | Commit | YAML/Dockerfile hits | `templates/` hits | Notes |
| --- | --- | --- | --- | --- |
| 2026-10-14 | task 06 | 430 / 900 broad matches | 0 / 2 image-shaped | Precision: 25/25 sampled findings true. Every `templates/` file reported malformed (exit 3 everywhere). Real misses: template text, subchart `global.security.allowInsecureImages`, `repository` under non-`image` keys (`sysctlImage`), vendored Bitnami charts. The broad pattern counted `/opt/bitnami/...` paths: replaced by an image-shaped pattern. |
| 2026-10-14 | task 07 | 427 / 438 image-shaped | 2 / 2 | No exit 3. Remaining misses: chart repo URLs in non-standard files (`ct.yaml`, custom dependency lists), image under an arbitrary key, Bitnami namespace below a registry path (`ghcr.io/org` + `bitnami/x`). Correct non-findings: `bitnami/sealed-secrets-controller`, `bitnami/minideb` (excluded by spec). |
| 2026-10-14 | review 02 fixes | 435 / 438 image-shaped | 2 / 2 | The 3 misses are excluded by spec (`bitnami/sealed-secrets-controller`, `bitnami/minideb` x2): effective recall 100% on this corpus. 25/25 sampled findings true. No repository exits 3 after raising the file size limit to 16 MiB (a 6.7 MB rendered Kubeflow manifest hit the old 5 MiB limit). Runs byte-identical. |
| 2026-10-15 | corpus v2 (28 repositories: + GitLab CI, Kustomize, Azure Pipelines, Argo CD, GitHub Actions) | 491 / 512 image-shaped | 2 / 2 | 3 misses are spec exclusions (`bitnami/sealed-secrets-controller`, `bitnami/minideb` x2). 18 real misses, all one class: Bitnami inside shell commands of CI scripts (`docker run bitnami/kubectl:1.17.4 ...` in GitLab CI, `helm repo add bitnami https://charts.bitnami.com/bitnami` in Azure Pipelines). Specified in docs/spec/v0.1.md 9.2. |
