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
| CPU | 12 logical processors (6 cores), AMD Ryzen 5 9600X |
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

These numbers were measured with the sequential scanner. The section
"Parallel scanning" below holds the before and after comparison of the
sequential and the parallel scanner.

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

## Limits and worst cases

These limits are part of the contract, so they shape the cost of a scan. They
are read from the code and from the spec (`docs/spec/v0.1.md` section 3), and
each of them produces a diagnostic, so a scan that reached a limit is never
reported as a clean scan.

| limit | value | diagnostic | enforced in | documented in |
| --- | --- | --- | --- | --- |
| file size | 16 MiB | `DSD-SCN-008`, error | `internal/scan/repo/repo.go`, `MaxFileSize` | [spec](spec/v0.1.md) section 3, [DSD-SCN-008](diagnostics/DSD-SCN-008.md) |
| YAML nesting depth | 256 levels | `DSD-SCN-005`, warning | `internal/detect/detect.go`, `maxYAMLDepth` | [spec](spec/v0.1.md) section 3, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| alias expansion budget | 10000 nodes | `DSD-SCN-005`, warning | `internal/detect/sources.go`, `maxAliasNodes` | [spec](spec/v0.1.md) section 3, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| Dockerfile line length | 1 MiB | `DSD-SCN-005`, warning | `internal/detect/detect.go`, `maxDockerfileLine` | [spec](spec/v0.1.md) section 3, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| Dockerfile continuation lines per instruction | 10000 lines | `DSD-SCN-005`, warning | `internal/detect/detect.go`, `MaxDockerfileContinuationLines` | [spec](spec/v0.1.md) sections 3 and 9, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| Terraform file size | 16 MiB | `DSD-SCN-008`, error | `internal/detect/terraform.go`, `maxTerraformBytes` | [DSD-SCN-008](diagnostics/DSD-SCN-008.md) |
| Terraform HCL depth | 256 levels | `DSD-SCN-005`, warning | `internal/detect/terraform.go`, `maxTerraformDepth` | [spec](spec/v0.1.md) sections 3 and 9, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| Terraform node budget | 100000 nodes | `DSD-SCN-005`, warning | `internal/detect/terraform.go`, `maxTerraformNodes` | [spec](spec/v0.1.md) sections 3 and 9, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| findings per file | 10000 findings | `DSD-SCN-005`, warning | `internal/diag/diag.go`, `MaxFindingsPerFile` | [spec](spec/v0.1.md) section 3, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| findings per repository | 100000 findings | `DSD-SCN-005`, warning | `internal/diag/diag.go`, `MaxFindingsPerRepository` | [spec](spec/v0.1.md) section 3, [DSD-SCN-005](diagnostics/DSD-SCN-005.md) |
| scan workers | 8 workers | none | `internal/scan/repo/parallel.go`, `MaxWorkers` | [Parallel scanning](#parallel-scanning) below |
| directory depth | no limit | none | `internal/scan/repo/repo.go`, `walkRepository` | this section |

The walk skips the `.git`, `node_modules` and `vendor` directories
(`internal/scan/repo/repo.go`, `skippedDirectories`). Symlinks and other non
regular files are skipped with `DSD-SCN-002`. Only `.yaml`, `.yml`,
`.tpl`, `Dockerfile` and `Dockerfile.*` files are read and parsed; other
files are visited by the walk but never opened.

The threats each limit answers are in
[docs/threat-model.md](threat-model.md), in the section "Hostile
repositories".

### What the audit fixed

An adversarial audit built hostile inputs and measured them. Three of them
made the scan quadratic and one left the number of findings unbounded. They
are fixed now. The times below were measured once, on one machine, and they
are here to show the size of the change, not as a promise for your hardware.

| hostile input | before | after |
| --- | --- | --- |
| one YAML file with 20000 documents | 42 s | well under a second |
| one CI file with 20000 script steps | 13 s (Azure Pipelines), 15 s (GitHub Actions), 25 s (GitLab CI) | 0.06 s |
| one Dockerfile with 1000000 continuation lines | over 60 s | 29 ms |

The output of the scan did not change: the golden files stayed the same, so
the fix changed the cost and not the report. The scan is now linear in the
number of YAML documents, in the number of CI script steps and in the number
of Dockerfile continuation lines.

The bounds are kept by tests that generate the hostile input and end the
test with a timeout guard, so a quadratic implementation fails the test
instead of running for minutes:

- `internal/detect/limits_test.go`, `TestManyDocumentsAreScannedInLinearTime`:
  50000 documents, 30 second guard.
- `internal/detect/shellcmd_test.go`, `TestShellScanManySteps`: 20000 steps
  for GitHub Actions, GitLab CI and Azure Pipelines, 60 second guard and a
  5 second budget.
- `internal/detect/dockerfile_limit_test.go`, `TestDockerfileContinuationChainUnderLimit`:
  9000 continuation lines, 30 second guard.

The audit also found that the number of findings was unbounded: one 14 MiB
file with 400000 image lines produced 180 MB of output and about 1 GB of
memory. The findings limits above bound that, and the limit is reported as
`DSD-SCN-005` and never as a silent truncation.

### Worst cases that remain

- **A large file costs a lot of memory.** A YAML file is decoded into a node
  tree before any rule runs, so the memory cost is a multiple of the size of
  the file: the audit measured on the order of 100 MB for a 16 MiB YAML file.
  The `DetectValues` row above shows the same thing for a 4 MiB file, at
  about 78 MB of allocations.
- **A repository with a very large number of files is slow.** The audit
  measured about 18 s for a repository of 200000 empty files. The cost is
  linear in the number of files, and there is no limit on that number.
- **The worker pool multiplies the peak memory.** Up to eight files are
  parsed at the same time, so the peak memory of a scan is about the peak
  memory of one file times the number of workers. `DISDETTA_WORKERS=1` makes
  the scan sequential and removes that multiplication.

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

## Parallel scanning

The scan reads and parses the files with a bounded pool of workers. The walk
stays sequential and decides the order of the files: the files are then read
and parsed by at most eight workers by default, the number of CPUs capped at
eight, and the results are merged in walk order. The report is therefore the
same for every worker count, byte for byte. The environment variable
`DISDETTA_WORKERS` sets the worker count for tests and debugging, and a value
of 1 makes the scan fully sequential. A positive override is taken as it is:
it can raise the worker count above eight.

Two parts of the scan stay sequential on purpose:

- the walk, because it decides the order of the files and the scan limits;
- the values file pre-pass, because it resolves the values files a document
  claims, and the claim decides whether a file is scanned as a plain document
  or as chart values.

A cancelled scan still fails in the walk, before any file is handed to a
worker, exactly like it did with the sequential scanner.

### Before and after

Both columns come from the same command, run on the same machine:

```sh
go test -run=^$ -bench=. -benchmem -count=3 ./internal/scan/repo/
```

The before column is the sequential scanner and the after column the parallel
one. The numbers are the median of three runs.

| benchmark | files | before ns/op | after ns/op | speedup | before files/s | after files/s |
| --- | --- | --- | --- | --- | --- | --- |
| `ScanRepoSmall` | 20 | 6 040 715 | 4 293 725 | 1.41x | 3 311 | 4 658 |
| `ScanRepoMedium` | 200 | 68 359 085 | 39 577 930 | 1.73x | 2 926 | 5 053 |
| `ScanRepoLarge` | 2000 | 708 185 750 | 371 093 300 | 1.91x | 2 824 | 5 389 |
| `ScanRepoBigFiles` | 3 | 203 377 000 | 136 355 112 | 1.49x | 14.75 | 22.00 |
| `ScanRepoOversizedFile` | 1 (skipped) | 104 287 | 102 333 | 1.02x | n/a | n/a |

What the table says:

- The large tier, 2000 files, is 1.91x faster. The target of issue 17, at
  least 1.5x on the large tier, is met on this machine.
- The medium tier is 1.73x faster and the small tier 1.41x. The smaller the
  tree, the smaller the share of the scan the pool can take over: the walk,
  the values file pre-pass and the final sort stay sequential.
- `ScanRepoOversizedFile` reads no file at all: the scanner rejects the file
  on its metadata, so there is nothing to parallelize and the two columns are
  the same number.
- `ScanRepoBigFiles` reads 21 MiB in three files. Three files cannot fill
  eight workers: the concurrency there is limited to three workers.

The machine was not idle during the measurements: the background load of the
processors was between 10 and 50 per cent during the runs, and the absolute
numbers move by about ten per cent between two runs for that reason. Three
runs of the parallel scanner gave 335 to 371 ms/op on the large tier, and
that spread is the load of the machine. The control run below measures both
paths of the same binary, one after the other, so it does not depend on the
load between two sessions.

### Control run

A second run of the parallel code with `DISDETTA_WORKERS=1` measures the
sequential path of the same binary, so the comparison does not depend on the
load of the machine between two sessions.

| benchmark | 1 worker ns/op | 8 workers ns/op | speedup |
| --- | --- | --- | --- |
| `ScanRepoSmall` | 6 512 454 | 4 293 725 | 1.52x |
| `ScanRepoMedium` | 80 484 600 | 39 577 930 | 2.03x |
| `ScanRepoLarge` | 810 409 200 | 371 093 300 | 2.18x |
| `ScanRepoBigFiles` | 180 466 100 | 136 355 112 | 1.32x |
| `ScanRepoOversizedFile` | 99 582 | 102 333 | 0.97x |

### When the parallelism does not help

- Small trees. Below a few hundred files the sequential walk and the final
  sort are a large part of the scan, and the pool only takes a small share of
  it.
- Input bound scans. When the files come from a slow disk, from a network
  share or from a cold cache, the reads are the bottleneck. The workers
  overlap the waits, but they cannot make the device faster.
- Work that stays sequential. The values file pre-pass reads every YAML file
  again, one file at a time, to find the values files the documents claim. It
  stays sequential on purpose, so a tree of many YAML files keeps a serial
  part, and the pre-pass is one reason the small tiers gain the least.
- Big files. One file is parsed by one worker, so a tree of a few very large
  files gains less than a tree of many small ones.
