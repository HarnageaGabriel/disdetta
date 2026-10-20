# Performance

This page records how the repository scan behaves on large trees and how to
measure it again. The numbers below are indicative: they come from one
machine, one file system and one Go version. Re-measure on your own hardware
before quoting them.

## How to run the benchmarks

With GNU make:

```sh
make bench
```

Without make, the same command:

```sh
go test -run=^$ -bench=. -benchmem -count=3 ./internal/...
```

`-run=^$` skips the tests, `-bench=.` runs every benchmark, `-benchmem` adds
the allocation counters and `-count=3` repeats the measurement three times.
For a quick check use `-benchtime=1x`, which runs each benchmark once.

The benchmarks write their fixtures under the temporary directory of the
operating system and remove them when the run ends. Nothing is left in the
repository.

## Machine used for the numbers below

| item | value |
| --- | --- |
| OS and architecture | `windows/amd64` (`go env GOOS GOARCH`) |
| CPU | 12 logical processors (6 cores) |
| Go | go1.26.5 |
| Storage | local disk |

No machine name is recorded on purpose.

## What the benchmarks measure

### Repository scan tiers (`internal/scan/repo`)

The three tiers hold the same kind of file and differ only in file count, so
they can be compared with each other. Every file is a Helm values file, a
Helm template, a Dockerfile, a Kustomization or a compose file, plus one
`Chart.yaml`. The tree is written to disk before the measurement starts, so
only the scan itself is timed.

| tier | benchmark | files | tree size |
| --- | --- | --- | --- |
| small | `BenchmarkScanRepoSmall` | 20 | about 118 KiB |
| medium | `BenchmarkScanRepoMedium` | 200 | about 1.05 MiB |
| large | `BenchmarkScanRepoLarge` | 2000 | about 10.5 MiB |

Two benchmarks sit outside the tiers on purpose:

- `BenchmarkScanRepoBigFiles`: 3 YAML manifests of 5, 7 and 9 MiB, 21 MiB in
  total. It measures the cost of big files, not the cost of many files.
- `BenchmarkScanRepoOversizedFile`: 1 file of 17 MiB, above the per file
  limit. The scanner rejects it on its metadata and never reads it.

### Detector benchmarks (`internal/detect`)

- `BenchmarkImageRefParse`: parses 5 image references, no file involved.
- `BenchmarkDetectValues`: one `values.yaml` of 4 MiB with about 66000 list
  entries.
- `BenchmarkTemplateText`: one template file of 4 MiB with about 22000 YAML
  documents.

## Results

Median of 3 runs of `go test -run=^$ -bench=. -benchmem -count=3 ./internal/...`.
`ns/op` is the time of one scan, `MB/s` is the input read per second and
`files/s` is the number of scanned files per second. `files/s` counts every
file scanned during the whole run, so it stays consistent with `ns/op`:
`files/s` is `files * 1e9 / ns/op`.

| benchmark | files | ns/op | MB/s | files/s | B/op | allocs/op |
| --- | --- | --- | --- | --- | --- | --- |
| `ScanRepoSmall` | 20 | 4 998 548 | 24.11 | 4001 | 3 328 048 | 49 958 |
| `ScanRepoMedium` | 200 | 54 726 479 | 20.08 | 3655 | 30 494 929 | 455 248 |
| `ScanRepoLarge` | 2000 | 551 098 550 | 19.94 | 3629 | 303 414 124 | 4 549 269 |
| `ScanRepoBigFiles` | 3 | 121 736 889 | 180.88 | 24.64 | 181 448 285 | 610 |
| `ScanRepoOversizedFile` | 1 (skipped) | 97 307 | n/a | n/a | 3 415 | 41 |
| `ImageRefParse` | n/a | 1 471 | n/a | n/a | 1 416 | 41 |
| `DetectValues` | 1 | 125 925 625 | 33.31 | n/a | 77 882 131 | 1 464 752 |
| `TemplateText` | 1 | 92 757 792 | 45.22 | n/a | 53 781 114 | 1 207 819 |

What the table says:

- The scan is close to linear in the number of files: between 0.25 and
  0.28 ms per file for the tree used here, with no visible fixed cost at this
  scale.
- Throughput per byte is much lower than the file size suggests (about 20 to
  25 MB/s for the tiers) because these fixtures are dense YAML: a values file
  holds 96 groups of 4 keys each.
- `ScanRepoBigFiles` reaches about 180 MB/s because a large block scalar is
  cheap to parse. A large file made of many small documents is not cheap:
  `TemplateText` runs at about 45 MB/s on a file with 22000 documents.
- `ScanRepoOversizedFile` reads nothing. A file above the limit costs one
  directory entry and one metadata lookup.
- `DetectValues` allocates about 78 MB to read a 4 MiB file, mostly in the
  YAML node tree.

## Limits enforced by the scanner

These limits are part of the contract, so they shape the cost of a scan. They
are read from the code and from the spec (`docs/spec/v0.1.md`).

| limit | value | source | effect |
| --- | --- | --- | --- |
| file size | 16 MiB | `internal/scan/repo/repo.go`, `MaxFileSize` | larger files are not scanned, `DSD-SCN-008` error, the scan is incomplete |
| YAML nesting depth | 256 levels | `internal/detect/detect.go`, `maxYAMLDepth` | deeper subtrees are not scanned, `DSD-SCN-005` warning |
| alias expansion budget | 10000 nodes | `internal/detect/sources.go`, `maxAliasNodes` | the rest of the file is not scanned, `DSD-SCN-005` warning |
| Dockerfile line length | 1 MiB | `internal/detect/detect.go`, `maxDockerfileLine` | the rest of the file is not scanned, `DSD-SCN-005` warning |
| directory depth | no limit | `internal/scan/repo/repo.go`, `walkRepository` | every directory is visited |

The walk skips the `.git`, `node_modules` and `vendor` directories
(`internal/scan/repo/repo.go`, `skippedDirectories`). Symlinks and other non
regular files are skipped with `DSD-SCN-002`. Only `.yaml`, `.yml`,
`.tpl`, `Dockerfile` and `Dockerfile.*` files are read and parsed; other
files are visited by the walk but never opened.

## Known cost drivers

1. YAML parsing. Every candidate file is decoded into a node tree before any
   rule runs. This is the dominant cost of a scan and it grows with the
   number of documents and keys, not only with the number of bytes.
2. Allocation. The node tree is built in memory and thrown away file by
   file. A 4 MiB values file costs about 78 MB of allocations, so a large
   repository also means a large allocation rate.
3. Reading. Each file is read whole into memory, up to the 16 MiB limit, and
   the bytes are then parsed, so the memory traffic is roughly twice the
   size of the repository.
4. Walking. The repository walk is a single traversal with one metadata
   lookup per entry. On a large monorepo the walk itself is not the
   bottleneck, but it is also not free.
5. Findings. Findings are de-duplicated, sorted and given a SHA-256
   fingerprint at the end of the scan. The cost grows with the number of
   findings, not with the number of files.
6. Big files. A single 9 MiB manifest is parsed as one document. Files that
   hold many small documents are the expensive case.

## Parallel scanning is not implemented yet

The scan is single threaded: one directory walk, one file at a time, on one
core. Nothing in the numbers above uses more than one core, and the 12
logical processors of the machine were idle.

Adding parallel scanning is the second half of issue 17 and is tracked
separately. Until it lands, these numbers describe the cost of the current
serial scanner, not the cost of the best scanner this design could reach.
