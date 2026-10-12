# disdetta

Find and close Bitnami dependencies. Pre-alpha.

Since 2025-08-28 versioned Bitnami images live in `docker.io/bitnamilegacy`: an archive with no updates and no support. Anyone who pointed charts there (often with `global.security.allowInsecureImages=true`) is running unpatched images. disdetta finds those references in repositories and clusters, and plans the exit per component.

## Prova subito

```sh
go install github.com/HarnageaGabriel/disdetta/cmd/disdetta@latest
disdetta scan .
```

Lists every Bitnami reference with file and line.

## Status

Study phase done, scaffold in progress. See [docs/PLAN.md](docs/PLAN.md) and [docs/research/RESEARCH-NOTES.md](docs/research/RESEARCH-NOTES.md).

## Rules

Read-only, deterministic, no telemetry, Apache-2.0. A value mapping always has a public source; anything uncertain is listed as unmapped, never guessed.
