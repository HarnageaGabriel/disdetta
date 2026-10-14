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
| 2026-10-14 | 67b-dev (task 06) | 430 / 900 raw matches | 0 / 1480 | Precision: 25/25 sampled findings true. Real misses: Helm template text, subchart `global.security.allowInsecureImages`, `repository` under non-`image` keys (`sysctlImage`), vendored Bitnami charts. |
