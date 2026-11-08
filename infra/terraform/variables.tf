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

locals {
  zone_name = "moyuri-kudo.com"
}
