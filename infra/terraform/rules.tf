locals {
  hooks_host = "hooks.${local.zone_name}"
}

# WAF custom rule: on the hooks host, blocks every request except GET /healthz
# and POST /microcms carrying the expected x-hook-key header value.
resource "cloudflare_ruleset" "waf_custom" {
  zone_id = var.zone_id
  name    = "WAF custom rules"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules = [{
    ref         = "hooks_allow_expected_only"
    description = "Block unexpected requests to the hooks host"
    expression = join(" and ", [
      "(http.host eq \"${local.hooks_host}\")",
      "not (http.request.method eq \"GET\" and http.request.uri.path eq \"/healthz\")",
      "not (http.request.method eq \"POST\" and http.request.uri.path eq \"/microcms\" and any(http.request.headers[\"x-hook-key\"][*] eq \"${var.hooks_waf_header_value}\"))",
    ])
    action = "block"
  }]
}

# Rate limiting rule: per IP and data center, blocks for 10 s after more than
# 30 requests in 10 s to the webhook and CSP report paths.
resource "cloudflare_ruleset" "rate_limit" {
  zone_id = var.zone_id
  name    = "Rate limiting rules"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules = [{
    ref         = "hooks_csp_per_ip"
    description = "Rate limit the webhook and CSP report paths per IP"
    expression  = "(http.request.uri.path in {\"/microcms\" \"/report\"})"
    action      = "block"
    ratelimit = {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = 10
      requests_per_period = 30
      mitigation_timeout  = 10
    }
  }]
}

# Configuration rule: turns off Browser Integrity Check on the hooks host.
resource "cloudflare_ruleset" "config" {
  zone_id = var.zone_id
  name    = "Configuration rules"
  kind    = "zone"
  phase   = "http_config_settings"

  rules = [{
    ref               = "hooks_bic_off"
    description       = "Disable Browser Integrity Check on the hooks host"
    expression        = "(http.host eq \"${local.hooks_host}\")"
    action            = "set_config"
    action_parameters = { bic = false }
  }]
}
