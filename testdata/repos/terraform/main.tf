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
