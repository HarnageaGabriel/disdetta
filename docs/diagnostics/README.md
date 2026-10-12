# Scanner diagnostics and CLI contract

`disdetta scan [path]` reads YAML and Dockerfiles beneath `path` (default `.`),
skipping `.git`, `node_modules`, and `vendor`. It never renders templates, uses
the network, changes files, or emits surrounding values. `--format table` is the
default; `--format json` emits schema version `1`.

Exit codes are `0` when no findings exist, `1` when findings exist, and `2` for
invalid usage or runtime errors. Findings are sorted with stateful components
first, then by severity, path, and line.

The YAML v3 dependency is intentional: `yaml.Node` preserves source line
numbers needed for actionable diagnostics.
