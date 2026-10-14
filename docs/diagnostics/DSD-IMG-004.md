# DSD-IMG-004: Bitnami image from another registry

Low-severity finding: an image under `bitnami/` or `bitnamisecure/` is pulled from a registry other than Docker Hub. It is either a mirror (frozen unless refreshed) or a rebuild from the Bitnami sources, a recommended exit. Attribute `mirror`, confidence `inferred`. A `bitnamilegacy/` image under another registry stays `DSD-IMG-001`.
