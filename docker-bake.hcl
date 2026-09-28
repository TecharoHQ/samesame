variable "REGISTRY" {
  default = "ghcr.io/techarohq"
}

variable "VERSION" {
  default = "devel"
}

group "default" {
  targets = ["samesame"]
}

# Tags for manual builds. In CI, docker/metadata-action writes a bake file
# that redefines this target with tags for the branch, release, and commit.
target "docker-metadata-action" {
  tags = ["${REGISTRY}/samesame:${VERSION}"]
}

# Multi-platform image. Build and push manually with:
#   VERSION=v1.2.3 docker buildx bake --push
target "samesame" {
  inherits   = ["docker-metadata-action"]
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  labels = {
    "org.opencontainers.image.title"       = "samesame"
    "org.opencontainers.image.description" = "Serves a Web Bot Auth key directory from a folder of keys"
    "org.opencontainers.image.source"      = "https://github.com/TecharoHQ/samesame"
    "org.opencontainers.image.licenses"    = "AGPL-3.0"
  }
}

# Single-platform image loaded into the local Docker daemon for testing:
#   docker buildx bake local
target "local" {
  inherits  = ["samesame"]
  platforms = []
  tags      = ["samesame:local"]
  output    = ["type=docker"]
}
