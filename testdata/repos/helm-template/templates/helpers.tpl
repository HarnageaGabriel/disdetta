{{/* Defaults used by the restart job. */}}
{{ .Values.kubectlImage | default "bitnami/kubectl:1.30" }}