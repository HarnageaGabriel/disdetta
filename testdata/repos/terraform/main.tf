resource "helm_release" "postgres" {
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "postgresql"
  version    = "16.4.0"

  values = [file("values.yaml"), yamlencode({
    image = {
      repository = "bitnamilegacy/postgresql"
    }
    global = {
      security = {
        allowInsecureImages = "true"
      }
    }
  }), <<-EOT
    image:
      repository: bitnamilegacy/postgresql
  EOT
  ]

  set {
    name  = "image.repository"
    value = "bitnamilegacy/postgresql"
  }

  set_list {
    name  = "extra"
    value = ["a", "b"]
  }
}

resource "helm_release" "redis_oci" {
  chart = "oci://registry-1.docker.io/bitnamicharts/redis"
}

resource "helm_release" "custom" {
  repository = var.chart_repository
  chart      = "postgresql"
  values = ["image: {{ .Values.image.repository }}"]
}

resource "helm_release" "redis" {
  chart = "redis"

  values = [yamlencode({
    global = {
      security = {
        allowInsecureImages = true
      }
    }
    image = {
      registry   = "mirror.example.com"
      repository = "bitnami/redis"
      tag        = "7.2.0"
    }
  })]
}

resource "helm_release" "redis_dynamic" {
  chart = "oci://registry-1.docker.io/bitnamicharts/${var.name}"

  values = [yamlencode({
    image = {
      repository = "bitnami/redis"
      tag        = var.tag
    }
  })]
}

resource "helm_release" "fallback" {
  chart = "postgresql"

  values = [yamlencode({
    customImage = "bitnami/redis"
    chartSource = "https://charts.bitnami.com/bitnami"
  })]
}

resource "helm_release" "alias" {
  chart = "postgresql"

  values = [<<-EOT
    base: &base
      repository: bitnami/redis
    image: *base
  EOT
  ]
}

resource "helm_release" "templated" {
  chart = "postgresql"

  values = [<<-EOT
    image:
      repository: "bitnami/redis"
      tag: "{{ .Values.image.tag }}"
  EOT
  ]
}

resource "helm_release" "collection" {
  chart = "postgresql"

  values = [yamlencode({
    customImages = ["bitnami/redis"]
  })]
}

resource "helm_release" "scalar_alias" {
  chart = "postgresql"

  values = [<<-EOT
    img: &img bitnami/redis:7
    image: *img
  EOT
  ]
}
