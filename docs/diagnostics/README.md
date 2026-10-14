# Findings and scan diagnostics

`disdetta scan [path]` reports Bitnami dependencies as findings and input problems as separate diagnostics. Finding rules use `DSD-CFG-*`, `DSD-IMG-*`, and `DSD-CHT-*`; scan diagnostics use `DSD-SCN-*`.

The default table ends with a summary. `--format json` emits schema version `1`, described by `schemas/report-v1.json`. `--fail-on` controls the policy threshold and `--rule` filters findings without filtering diagnostics.

Exit code `0` means the policy passed and the scan is complete; `1` means the finding policy failed; `2` means invalid usage or a fatal root error; `3` means the policy passed but an error-level diagnostic made the scan incomplete. Policy failure takes precedence over incompleteness.

Symlinks and non-regular files are skipped with `DSD-SCN-002`; a file larger than 16 MiB is not scanned and is reported as the error `DSD-SCN-008`, which makes the scan incomplete. YAML nesting is limited to 256 levels, as is the alias expansion budget (`DSD-SCN-005`). The scanner does not render templates, access the network, or emit Kubernetes Secret values.
