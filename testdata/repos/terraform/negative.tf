# repository = "https://charts.bitnami.com/bitnami"

resource "helm_release" "external" {
  repository = "https://charts.example.invalid"
  chart      = "postgresql"
}

resource "helm_release" "local" {
  chart = "./charts/local"
}

resource "helm_release" "prose" {
  chart = "local"
  values = ["note: see bitnami/redis documentation"]
}

resource "helm_release" "other_image" {
  chart = "postgresql"
  values = [yamlencode({ customImage = "acme/redis:1.0.0" })]
}

resource "helm_release" "other_image_list" {
  chart = "postgresql"
  values = [yamlencode({ customImages = ["acme/redis:1.0.0"] })]
}