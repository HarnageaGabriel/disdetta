# DSD-SCN-010: Cluster list failed

Diagnostic: a `list` call for the cluster scan did not succeed (spec v0.2
section 4). Level `warning` when RBAC forbids the list, level `error` for any
other API error. The message names the tier, the resource and the namespace; the
scan continues with the objects it did read and no object content is echoed.

A forbidden tier 1 or 2 list (a mandatory tier) leaves the report incomplete
(`summary.complete` is false, exit code 3 when the finding policy passes). A
forbidden tier 3 list is a warning, but when tier 3 was requested with
`--read-helm-secrets` it also leaves the report incomplete, because the requested
scan did not read the Secrets it was asked to (review 03 M2); without the flag
tier 3 is not attempted and nothing changes. Any other list failure is an error
and makes the report incomplete. The message still states which tier was not
fully scanned.
