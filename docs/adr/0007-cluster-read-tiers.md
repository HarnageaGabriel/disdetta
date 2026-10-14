# 7. Cluster read tiers and Kubernetes client

Status: accepted (2026-10-14)

## Context
The cluster scan must find Bitnami images in workloads and the `allowInsecureImages` workaround, which only exists in Helm user values stored in release Secrets. Reading Secrets is a privilege many users will not (and should not) grant, and the payload can hold credentials.

## Decision
- Three read tiers ([spec v0.2](../spec/v0.2-cluster.md) section 2). Secrets are read only with `--read-helm-secrets`.
- Use `k8s.io/client-go` (typed clientset, fake clientset for tests). Reason: kubeconfig and auth-plugin compatibility with kubectl, pagination and the fake client for verb assertions; writing a client by hand would re-implement auth providers badly.
- The client lives only in `internal/scan/cluster`, behind a consumer-defined interface; detectors stay pure.

## Consequences
Bigger binary and dependency tree (client-go, apimachinery, api); govulncheck covers them. Tier 3 adds bounded decompression (threat model T3).
