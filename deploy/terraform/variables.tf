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

variable "key_management_config_json" {
  description = "Purpose-separated encryption and access-token signing provider configuration."
  type        = string
  sensitive   = true
  validation {
    condition     = can(keys(jsondecode(var.key_management_config_json)))
    error_message = "key_management_config_json must be a JSON object."
  }
}

variable "deployment_id" {
  description = "Immutable identity for the deployed credential-authority generation."
  type        = string
  default     = "terraform-local"
  validation {
    condition     = length(trimspace(var.deployment_id)) > 0 && length(var.deployment_id) <= 200
    error_message = "deployment_id must be nonblank and at most 200 characters."
  }
}

variable "project_id" {
  description = "Project scope served by the local auth runtime and Vault."
  type        = string
  default     = "proj_default"
  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id is required."
  }
}

variable "environment_id" {
  description = "Environment scope served by the local auth runtime and Vault."
  type        = string
  default     = "env_default"
  validation {
    condition     = length(trimspace(var.environment_id)) > 0
    error_message = "environment_id is required."
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

variable "vault_port" {
  type    = number
  default = 13400
  validation {
    condition     = var.vault_port >= 1024 && var.vault_port <= 65535
    error_message = "vault_port must be between 1024 and 65535."
  }
}

variable "vault_product_name" {
  type    = string
  default = "Clearance"
  validation {
    condition     = length(trimspace(var.vault_product_name)) > 0 && length(var.vault_product_name) <= 80
    error_message = "vault_product_name must be nonblank and at most 80 characters."
  }
}

variable "vault_home_label" {
  type    = string
  default = "Clearance Vault"
  validation {
    condition     = length(trimspace(var.vault_home_label)) > 0 && length(var.vault_home_label) <= 120
    error_message = "vault_home_label must be nonblank and at most 120 characters."
  }
}

variable "vault_accent_color" {
  type    = string
  default = "#6558d3"
  validation {
    condition     = can(regex("^#[0-9A-Fa-f]{6}$", var.vault_accent_color))
    error_message = "vault_accent_color must be a six-digit hexadecimal color."
  }
}
