# Rules command

`disdetta rules` lists every finding rule and scanner diagnostic from the `internal/diag` registry, sorted by code. The table columns are `CODE`, `KIND`, `SEVERITY`, `LEVEL`, `TITLE`, and `DOCS`; the JSON form uses schema version `1` in `schemas/rules-v1.json`.

```sh
disdetta rules
disdetta rules --format json
```

Both formats are deterministic and exit 0.