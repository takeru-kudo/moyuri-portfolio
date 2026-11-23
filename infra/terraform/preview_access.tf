# Service token for the E2E job (K5).
resource "cloudflare_zero_trust_access_service_token" "e2e" {
  account_id = var.account_id
  name       = "e2e (K5)"
  duration   = "8760h"
}

# Allows requests that present the E2E service token.
resource "cloudflare_zero_trust_access_policy" "preview_service_auth" {
  account_id = var.account_id
  name       = "site-prod previews: E2E service token"
  decision   = "non_identity"
  include = [
    { service_token = { token_id = cloudflare_zero_trust_access_service_token.e2e.id } },
  ]
}

# Allows the developer email address.
resource "cloudflare_zero_trust_access_policy" "preview_developer" {
  account_id = var.account_id
  name       = "site-prod previews: developer"
  decision   = "allow"
  include = [
    { email = { email = var.developer_email } },
  ]
}

# Protects the preview URLs of the site-prod Worker; login with One-time PIN only.
resource "cloudflare_zero_trust_access_application" "site_prod_previews" {
  account_id                = var.account_id
  name                      = "site-prod preview URLs"
  type                      = "self_hosted"
  destinations              = [{ type = "preview_worker", worker_id = var.site_prod_worker_id }]
  session_duration          = "24h"
  allowed_idps              = [cloudflare_zero_trust_access_identity_provider.otp.id]
  auto_redirect_to_identity = true
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.preview_service_auth.id
      precedence = 1
    },
    {
      id         = cloudflare_zero_trust_access_policy.preview_developer.id
      precedence = 2
    },
  ]
}
