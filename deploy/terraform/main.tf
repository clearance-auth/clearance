terraform {
  required_version = "= 1.5.7"
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.9.0"
    }
  }
}

provider "docker" {}

# Cross-variable validation belongs in check blocks on Terraform 1.5; variable
# validation expressions may reference only their own variable.
check "social_provider_pairs" {
  assert {
    condition     = (var.github_client_id == null) == (var.github_client_secret == null)
    error_message = "github_client_id and github_client_secret must be supplied together."
  }
  assert {
    condition     = (var.google_client_id == null) == (var.google_client_secret == null)
    error_message = "google_client_id and google_client_secret must be supplied together."
  }
}

check "unique_host_ports" {
  assert {
    condition     = length(distinct([var.api_port, var.console_port, var.sample_port])) == 3
    error_message = "api_port, console_port, and sample_port must be unique."
  }
}

locals {
  database_url = "postgres://${var.postgres_user}:${urlencode(var.postgres_password)}@postgres:5432/${var.postgres_database}"
  api_url      = "http://localhost:${var.api_port}"
  console_url  = "http://localhost:${var.console_port}"
  sample_url   = "http://localhost:${var.sample_port}"
  social_env = compact([
    var.github_client_id == null ? "" : "CLEARANCE_GITHUB_CLIENT_ID=${var.github_client_id}",
    var.github_client_secret == null ? "" : "CLEARANCE_GITHUB_CLIENT_SECRET=${var.github_client_secret}",
    var.google_client_id == null ? "" : "CLEARANCE_GOOGLE_CLIENT_ID=${var.google_client_id}",
    var.google_client_secret == null ? "" : "CLEARANCE_GOOGLE_CLIENT_SECRET=${var.google_client_secret}",
  ])
}

resource "docker_network" "clearance" {
  name = var.network_name
}

resource "docker_volume" "postgres" {
  name = var.postgres_volume_name
}

resource "docker_volume" "backups" {
  name = var.backup_volume_name
}

resource "docker_image" "postgres" {
  name         = "postgres:16-alpine"
  keep_locally = true
}

resource "docker_image" "clearance" {
  name         = var.clearance_image
  keep_locally = true
}

resource "docker_container" "postgres" {
  name    = "${var.name_prefix}-postgres"
  image   = docker_image.postgres.image_id
  restart = "unless-stopped"

  env = [
    "POSTGRES_USER=${var.postgres_user}",
    "POSTGRES_PASSWORD=${var.postgres_password}",
    "POSTGRES_DB=${var.postgres_database}",
  ]

  networks_advanced {
    name    = docker_network.clearance.name
    aliases = ["postgres"]
  }

  volumes {
    volume_name    = docker_volume.postgres.name
    container_path = "/var/lib/postgresql/data"
  }

  healthcheck {
    test         = ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
    interval     = "3s"
    timeout      = "5s"
    retries      = 20
    start_period = "5s"
  }
}

resource "docker_container" "api" {
  name    = "${var.name_prefix}-api"
  image   = docker_image.clearance.image_id
  restart = "unless-stopped"
  command = ["node", "packages/clearance-api/dist/server.js"]

  env = [
    "NODE_ENV=production",
    "CLEARANCE_STRICT_SECRETS=1",
    "CLEARANCE_API_PORT=3200",
    "CLEARANCE_OPERATOR_TOKEN=${var.operator_token}",
    "CLEARANCE_SECRET=${var.clearance_secret}",
    "CLEARANCE_CREDENTIAL_KEY=${var.credential_key}",
    "CLEARANCE_CREDENTIAL_KEY_ID=${var.credential_key_id}",
    "CLEARANCE_BASE_URL=${local.sample_url}",
    "CLEARANCE_CONSOLE_URL=${local.console_url}",
    "CLEARANCE_API_HEALTH_URL=http://127.0.0.1:3200",
    "CLEARANCE_CONSOLE_HEALTH_URL=http://console:3100",
    "CLEARANCE_BACKUP_DIR=/backups",
    "CLEARANCE_CORS_ORIGINS=${local.console_url},${local.sample_url}",
    "DATABASE_URL=${local.database_url}",
  ]

  networks_advanced {
    name    = docker_network.clearance.name
    aliases = ["api"]
  }

  volumes {
    volume_name    = docker_volume.backups.name
    container_path = "/backups"
  }

  ports {
    ip       = "127.0.0.1"
    internal = 3200
    external = var.api_port
  }

  healthcheck {
    test         = ["CMD", "node", "-e", "fetch('http://127.0.0.1:3200/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
    interval     = "5s"
    timeout      = "5s"
    retries      = 20
    start_period = "15s"
  }

  depends_on = [docker_container.postgres]
}

resource "docker_container" "console" {
  name    = "${var.name_prefix}-console"
  image   = docker_image.clearance.image_id
  restart = "unless-stopped"
  command = ["node", "packages/clearance-console/src/server.js"]

  env = [
    "NODE_ENV=production",
    "CLEARANCE_STRICT_SECRETS=1",
    "CLEARANCE_CONSOLE_PORT=3100",
    "CLEARANCE_API_URL=http://api:3200",
    "CLEARANCE_OPERATOR_TOKEN=${var.operator_token}",
    "CLEARANCE_CONSOLE_ADMIN_USER=${var.console_admin_user}",
    "CLEARANCE_CONSOLE_ADMIN_PASSWORD=${var.console_admin_password}",
    "CLEARANCE_CONSOLE_SESSION_SECRET=${var.console_session_secret}",
  ]

  networks_advanced {
    name    = docker_network.clearance.name
    aliases = ["console"]
  }

  ports {
    ip       = "127.0.0.1"
    internal = 3100
    external = var.console_port
  }

  healthcheck {
    test         = ["CMD", "node", "-e", "fetch('http://127.0.0.1:3100/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
    interval     = "5s"
    timeout      = "5s"
    retries      = 20
    start_period = "15s"
  }

  depends_on = [docker_container.api]
}

resource "docker_container" "sample" {
  name    = "${var.name_prefix}-sample"
  image   = docker_image.clearance.image_id
  restart = "unless-stopped"
  command = ["node", "apps/sample-b2b/dist/server.js"]

  env = concat([
    "NODE_ENV=production",
    "CLEARANCE_STRICT_SECRETS=1",
    "SAMPLE_APP_PORT=3000",
    "CLEARANCE_SECRET=${var.clearance_secret}",
    "CLEARANCE_BASE_URL=${local.sample_url}",
    "DATABASE_URL=${local.database_url}",
  ], local.social_env)

  networks_advanced {
    name = docker_network.clearance.name
  }

  ports {
    ip       = "127.0.0.1"
    internal = 3000
    external = var.sample_port
  }

  healthcheck {
    test         = ["CMD", "node", "-e", "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
    interval     = "5s"
    timeout      = "5s"
    retries      = 20
    start_period = "15s"
  }

  depends_on = [docker_container.api]
}

output "api_url" {
  value = local.api_url
}

output "console_url" {
  value = local.console_url
}

output "sample_url" {
  value = local.sample_url
}

output "postgres_volume" {
  value = docker_volume.postgres.name
}

output "backup_volume" {
  value = docker_volume.backups.name
}
