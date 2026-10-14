# DSD-CHT-002: Vendored Bitnami chart

Medium-severity finding: a `Chart.yaml` vendors the Bitnami chart. Its `sources` or `home` point to `github.com/bitnami/charts`, or its `annotations.images` list Bitnami images. One finding per vendored chart; migrate the images it pins.

Source: camunda/camunda-platform-helm `charts/web-modeler-postgresql-15/Chart.yaml`.
