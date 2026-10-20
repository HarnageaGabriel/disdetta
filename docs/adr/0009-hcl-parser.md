# ADR 0009: Parse Terraform HCL Without Evaluation

Status: accepted

## Context

Terraform `helm_release` resources must be inspected without changing
behavior elsewhere in the scanner. The input can contain quoted strings,
heredocs, nested blocks, comments, and expressions that are not statically
knowable. A line-oriented heuristic can accidentally treat a comment, heredoc
body, or nested block as a resource attribute.

## Decision

Use `github.com/hashicorp/hcl/v2/hclsyntax.ParseConfig` in parse-only mode
for `*.tf` files. The detector walks the resulting syntax tree and takes only
literal expressions; it never evaluates expressions, calls functions, reads
files, or reads environment variables. Templated or otherwise computed values
are reported according to the unresolved-reference contract in specification
v0.1 section 2.2. A bounded lexer precheck enforces the repository file depth
limit before parsing, and a node budget bounds the walk: both are reported as
`DSD-SCN-005`.

Arguments of `file(...)` are ignored: the referenced file is scanned on its own
as a repository file, never through the expression that names it.

## Alternatives

A line scanner was rejected because correct handling of heredoc markers,
escaped strings, comments, nested blocks, and precise line/column positions
would require reimplementing part of the HCL grammar. HCL evaluation was
rejected because configuration files must remain pure inputs and may contain
variables, functions, file references, or other side effects.

## Consequences

The dependency adds `github.com/hashicorp/hcl/v2` to the binary, but it gives
deterministic syntax-only parsing with source ranges and removes ad-hoc parser
state. The added dependency weight is accepted for correct line mapping and
heredoc handling. The detector remains a pure package and does not import `os`
or `net`.

Known limitation: Terraform JSON configuration (`.tf.json`) is out of scope for
v0.1.0 and is not scanned. It is documented in specification v0.1 section 9.
