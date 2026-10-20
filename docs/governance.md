# Governance

disdetta is an Apache-2.0 project in pre-alpha development. It is maintained by
one person, HarnageaGabriel, with contributions from the community.

## Roles

**Contributor.** Anyone who opens an issue, comments, or sends a pull request.
Contributors follow the [Code of Conduct](../CODE_OF_CONDUCT.md) and the
[contributing guide](../CONTRIBUTING.md). Every commit carries a DCO sign-off
(`git commit -s`).

**Maintainer.** A contributor with write access to the repository. A
maintainer reviews and merges pull requests, decides what goes into a release,
and is accountable for the rules in this document.

## How decisions are made

The maintainer makes the final decision. Discussion happens in issues and pull
requests, and a change is accepted when the maintainer merges it.

The rationale for architecturally significant decisions is recorded as an ADR
under `docs/adr/`, in the format of
[ADR 0001](adr/0001-record-architecture-decisions.md). A change to the
output contract, the rule codes, or the exit codes is a specification change:
it lands as a pull request that touches the files under `docs/spec/`, together
with the code and the tests that implement it.

Disagreement does not block the work. The maintainer may decide and record the
reasoning in an ADR. Anyone can propose a different direction by opening an
issue.

## How to become a maintainer

Maintainers are invited, not self-appointed. The path is:

1. Contribute sustained, high quality work: pull requests that are tested,
   documented, and reviewed without repeated rework.
2. Show judgement on the project: review other people's changes, help
   newcomers, keep the documentation and the catalog accurate.
3. Get invited by an existing maintainer.

There is no fixed number of commits and no fixed time limit. Quality and
sustained involvement are what count.

## Stepping down and inactivity

A maintainer can step down at any time by telling the other maintainers. While
the project has a single maintainer, stepping down means handing over the
ownership of the repository.

A maintainer who has been inactive for six months can be removed by the
remaining maintainers. Removal is decided in the open, the reason is recorded,
and the removed maintainer can appeal privately to the remaining maintainers.

## Conflicts and code of conduct reports

Code of conduct reports go through GitHub's private reporting features, as
described in the [Code of Conduct](../CODE_OF_CONDUCT.md). Reports are handled
confidentlyially, and the identity of the reporter is not disclosed without
their consent.

Conflicts of interest are declared in the pull request or the issue where they
apply, and the maintainer steps aside from that decision.

## Releases

Only maintainers tag releases. A release tag matches `v*.*.*`, for example
`v0.1.0`. Tags in this form are protected: only maintainers can create them,
and a published tag is not moved or deleted.

The release pipeline runs on the tag and publishes the release artifacts. The
changes of each release are listed in [CHANGELOG.md](../CHANGELOG.md).

## Security reports

Security problems are reported through GitHub's private vulnerability
reporting, as described in [SECURITY.md](../SECURITY.md). Do not open a public
issue for a vulnerability.

## Changing this document

This document changes through a pull request. The maintainer approves the pull
request before it merges. A change that affects roles, decision making, or
release authority is recorded as an ADR under `docs/adr/`.
