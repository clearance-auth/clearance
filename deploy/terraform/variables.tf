variable "name_prefix" {
  type    = string
  default = "clearance-tf"
}

variable "network_name" {
  type    = string
  default = "clearance_tf_net"
}

variable "postgres_volume_name" {
  type    = string
  default = "clearance_tf_pg"
}

variable "backup_volume_name" {
  type    = string
  default = "clearance_tf_backups"
}

variable "clearance_image" {
  description = "Immutable Clearance release image in repository@sha256:<64 lowercase hex> form."
  type        = string
  validation {
    condition     = can(regex("^[^@[:space:]]+@sha256:[0-9a-f]{64}$", var.clearance_image))
    error_message = "clearance_image must be an immutable repository@sha256 digest from the signed release."
  }
}

variable "postgres_user" {
  type    = string
  default = "clearance"
}

variable "postgres_database" {
  type    = string
  default = "clearance"
}

variable "postgres_password" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.postgres_password) >= 16 && !contains(["clearance", "password", "change-me"], lower(var.postgres_password))
    error_message = "postgres_password must be at least 16 characters and cannot use a known default."
  }
}

variable "clearance_secret" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.clearance_secret) >= 16 && !strcontains(lower(var.clearance_secret), "change-me") && !strcontains(lower(var.clearance_secret), "dev-secret")
    error_message = "clearance_secret must be strong and cannot use a development default."
  }
}

variable "operator_token" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.operator_token) >= 16
    error_message = "operator_token must be at least 16 characters."
  }
}

variable "credential_key" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.credential_key) >= 32
    error_message = "credential_key must contain at least 32 characters."
  }
}

variable "credential_key_id" {
  type = string
  validation {
    condition     = length(trimspace(var.credential_key_id)) > 0
    error_message = "credential_key_id is required."
  }
}

variable "console_admin_user" {
  type    = string
  default = "admin"
}

variable "console_admin_password" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.console_admin_password) >= 16
    error_message = "console_admin_password must be at least 16 characters."
  }
}

variable "console_session_secret" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.console_session_secret) >= 16
    error_message = "console_session_secret must be at least 16 characters."
  }
}

variable "github_client_id" {
  type      = string
  default   = null
  nullable  = true
  sensitive = true
}

variable "github_client_secret" {
  type      = string
  default   = null
  nullable  = true
  sensitive = true
}

variable "google_client_id" {
  type      = string
  default   = null
  nullable  = true
  sensitive = true
}

variable "google_client_secret" {
  type      = string
  default   = null
  nullable  = true
  sensitive = true
}

variable "api_port" {
  type    = number
  default = 13200
  validation {
    condition     = var.api_port >= 1024 && var.api_port <= 65535
    error_message = "api_port must be between 1024 and 65535."
  }
}

variable "console_port" {
  type    = number
  default = 13100
  validation {
    condition     = var.console_port >= 1024 && var.console_port <= 65535
    error_message = "console_port must be between 1024 and 65535."
  }
}

variable "sample_port" {
  type    = number
  default = 13300
  validation {
    condition     = var.sample_port >= 1024 && var.sample_port <= 65535
    error_message = "sample_port must be between 1024 and 65535."
  }
}
