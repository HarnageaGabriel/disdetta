# SARIF output

`disdetta scan --format sarif` emits one deterministic SARIF 2.1.0 run for repository scans. `--cluster` accepts the same flag; cluster findings use `logicalLocations`, while file findings use `physicalLocation` with `uriBaseId: "%SRCROOT%"`. Scanner diagnostics appear in `toolExecutionNotifications`, never as results, and ignored findings are omitted from `results`.

Validate and upload the file from a GitHub Actions job:

```yaml
- name: Scan
  run: disdetta scan . --format sarif --fail-on none > disdetta.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: disdetta.sarif
```

`plan` rejects `--format sarif` as a usage error with exit code 2.