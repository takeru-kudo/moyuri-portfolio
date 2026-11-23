variable "account_id" {
  description = "Cloudflare account ID."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "account_id must be a 32-character lowercase hex string."
  }
}

variable "zone_id" {
  description = "Cloudflare zone ID of the site domain."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "zone_id must be a 32-character lowercase hex string."
  }
}

variable "notification_email" {
  description = "Email address that receives Cloudflare notifications."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.notification_email))
    error_message = "notification_email must be a non-empty email address."
  }
}

variable "developer_email" {
  description = "Developer email address allowed by the Beta Access policy."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.developer_email))
    error_message = "developer_email must be a non-empty email address."
  }

  validation {
    condition     = var.developer_email == lower(var.developer_email)
    error_message = "developer_email must be lowercase."
  }
}

variable "editor_email" {
  description = "Editor email address allowed by the Beta Access policy."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.editor_email))
    error_message = "editor_email must be a non-empty email address."
  }

  validation {
    condition     = var.editor_email == lower(var.editor_email)
    error_message = "editor_email must be lowercase."
  }
}

locals {
  zone_name = "moyuri-kudo.com"
}

variable "site_prod_worker_id" {
  description = "Immutable ID of the site-prod Worker whose preview URLs are protected by Access."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.site_prod_worker_id))
    error_message = "site_prod_worker_id must be a 32-character lowercase hex string."
  }
}

variable "hooks_waf_header_value" {
  description = "Expected x-hook-key header value on the hooks host (K11)."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[A-Za-z0-9+/]+={0,2}$", var.hooks_waf_header_value))
    error_message = "hooks_waf_header_value must be a non-empty base64 string."
  }

  validation {
    condition     = length(var.hooks_waf_header_value) >= 32 && length(var.hooks_waf_header_value) <= 128
    error_message = "hooks_waf_header_value must be 32 to 128 characters long."
  }
}
