locals {
  beta_host = "beta.${local.zone_name}"
}

# One-time PIN login method for the account.
resource "cloudflare_zero_trust_access_identity_provider" "otp" {
  account_id = var.account_id
  name       = "One-time PIN"
  type       = "onetimepin"
  config     = {}
}

# Allows the developer and editor email addresses.
resource "cloudflare_zero_trust_access_policy" "beta_allow" {
  account_id = var.account_id
  name       = "Beta: developer and editor"
  decision   = "allow"
  include = [
    { email = { email = var.developer_email } },
    { email = { email = var.editor_email } },
  ]
}

# Protects the whole beta host; login with One-time PIN only.
resource "cloudflare_zero_trust_access_application" "beta" {
  account_id                = var.account_id
  name                      = "Beta site"
  type                      = "self_hosted"
  domain                    = local.beta_host
  destinations              = [{ type = "public", uri = local.beta_host }]
  session_duration          = "24h"
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.otp.id]
  auto_redirect_to_identity = true
  policies = [{
    id         = cloudflare_zero_trust_access_policy.beta_allow.id
    precedence = 1
  }]
}
