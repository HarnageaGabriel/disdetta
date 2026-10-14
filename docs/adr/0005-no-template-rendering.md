# ADR 0005: Do not render templates

Status: accepted

The repository scanner is offline, deterministic, and read-only. It does not
execute Helm, Go templates, shell expansion, or user code. Image values
containing `{{ ... }}` produce DSD-005 and retain their source location. Users
can scan rendered manifests separately when resolution is required.
