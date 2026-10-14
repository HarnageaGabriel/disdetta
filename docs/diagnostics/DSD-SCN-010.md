# DSD-SCN-010: Cluster list failed

Diagnostic: a `list` call for the cluster scan did not succeed (spec v0.2
section 4). Level `warning` when RBAC forbids the list, level `error` for any
other API error. The message names the tier, the resource and the namespace; the
scan continues with the objects it did read and no object content is echoed.

A forbidden tier 1 or 2 list (a mandatory tier) leaves the report incomplete
(`summary.complete` is false). A forbidden tier 3 list is a warning because tier
3 is opt-in (`--read-helm-secrets`) and its absence is the documented default;
the message still states that the tier was not fully scanned.
