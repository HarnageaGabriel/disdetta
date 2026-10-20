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