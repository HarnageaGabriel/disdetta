# ADR 0006: Non-fatal scan diagnostics

Status: accepted

Per-file failures are data-quality results, not fatal process errors. The scan
report therefore keeps findings and diagnostics separate. JSON schema version
`1` gains an additive `diagnostics` array; table output includes diagnostic rows.
A scan with either findings or diagnostics exits `1`. Exit `2` is reserved for
invalid usage and fatal root-level errors.

Files larger than 5 MiB and YAML deeper than 100 nodes are skipped with DSD-006.
Repository entries that are symbolic links or non-regular files are never read.
When the explicitly supplied scan root is a symbolic link to a directory, it is
resolved exactly once before walking; symbolic links encountered below that root
remain rejected.
