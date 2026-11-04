# Working in micro-tasks

Work on disdetta is cut into small tasks that can be done at the same time by
different people or tools without stepping on each other. This page is the
method. It applies to maintainers and contributors alike.

## The rule

**One micro-task is one issue, one branch and one pull request.** The pull
request says `Closes #N`, so merging it closes the issue. Nobody closes an
issue by hand unless it needs no code (research, a decision).

## What makes a good micro-task

An issue is ready to start when it has all of these:

| Part | What it says |
| --- | --- |
| Goal | One sentence: the result, not the steps. |
| Touches | The files or directories the change may edit. Everything else is read-only. |
| Acceptance | Checkable statements: a test that fails before and passes after, a command and its output. |
| Verify | The exact commands (`go vet ./...`, `go test ./...`, lint, coverage floors). |
| Depends on | Issues that must be merged first, or `none`. |
| Size | A `size/` label. |

Sizes, counted in changed lines of a pull request (tests and goldens included):

| Label | Size | Typical review |
| --- | --- | --- |
| `size/XS` | under 30 lines, one file or a docs page | read the diff |
| `size/S` | under 150 lines | read the diff and run it |
| `size/M` | under 400 lines | needs an independent review |

Anything bigger is split before it starts. If a change cannot be split, say why
in the issue.

## Doing tasks at the same time

Tasks run in parallel when they do not touch the same files.

1. Before starting, compare the **Touches** of the issues you want to run
   together. Two issues that share a file are not parallel: the second one gets
   `Depends on #first` and the label `status/blocked`.
2. Every task works in its own `git worktree` outside the repository folder,
   on its own branch cut from the current `main`. Never switch branches in a
   checkout that another task is using, and never keep generated files (large
   test trees, profiles, logs) inside a worktree.
3. Keep the number of tasks in flight low enough to review them. Three to five
   at a time is a good limit; more only helps when the tasks are documentation
   or independent areas.
4. Push the branch early. A branch that exists only on one machine can be lost.

Labels show where an issue is:

| Label | Meaning |
| --- | --- |
| `status/ready` | scoped and unblocked, can start now |
| `status/blocked` | waits for another issue |
| `status/in-review` | a pull request is open |
| `status/needs-owner` | needs a decision of the maintainer (a release, a tag, a new repository, spending) |

Area labels (`area/detection`, `area/cluster`, `area/output`, `area/ci`,
`area/docs`, `area/security`, `area/catalog`) say who is likely to care.

## Definition of done

A pull request is ready to merge when:

- it closes exactly one issue and stays inside that issue's **Touches**;
- the verify commands pass on Linux, Windows and macOS in CI;
- there is a test that fails without the change; a finding changes only with a
  golden file updated on purpose, and every new finding in a golden is a true
  Bitnami reference (say why in the description);
- the spec, the diagnostics pages and the user documentation that the change
  affects are updated in the same pull request;
- the output stays deterministic: no dependence on map order or time;
- commits carry a DCO sign-off and the pull request is squash-merged.

### Review

Changes that touch credentials, parsing of untrusted input, the cluster scan,
the release or the supply chain need an **independent review** by a reviewer
who did not write the change (a different person or a different model). Other
changes need either an independent review or **objective evidence** written in
the pull request: for example a comparison of the reports of the old and the
new binary on the corpus and the fixtures (zero differences, or each difference
explained). A performance change is accepted only with the same evidence that
the reports are byte-identical.

### Merging in parallel

Tasks that were fine alone can break `main` together (a test that expects the
old behaviour of a file another task changed). Therefore, before merging a
pull request:

1. merge the current `main` into the branch;
2. run the verify commands again;
3. merge pull requests one at a time, and look at the next one again.

## What to do with each kind of issue

- **Code or docs task:** a pull request with `Closes #N`.
- **Research task** (`kind/research`): the result is a documentation change
  with its sources; the pull request closes the issue.
- **Follow-up found while working:** open a new issue with the reproduction,
  the file and a proposed fix, instead of growing the current pull request.
- **Decision for the maintainer** (`status/needs-owner`): the issue states the
  question and the options; the maintainer answers in the issue.
- **Parked work:** keep the issue open, say why it is parked and what must be
  true to resume it.

## Starting a task

```sh
git fetch origin
git worktree add ../disdetta-wt/<slug> -b <type>/<N>-<slug> origin/main
cd ../disdetta-wt/<slug>
# work, then:
go vet ./... && go test ./... && golangci-lint run ./...
git commit -s
git push -u origin <type>/<N>-<slug>
gh pr create --fill
```

Use `fix/`, `feat/`, `docs/`, `test/`, `perf/` or `chore/` for `<type>`.
