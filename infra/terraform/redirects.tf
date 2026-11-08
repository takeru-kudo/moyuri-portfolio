locals {
  www_host = "www.${local.zone_name}"
}

# Single Redirect: www host to the apex, keeping path and query string.
resource "cloudflare_ruleset" "redirects" {
  zone_id = var.zone_id
  name    = "Single Redirects"
  kind    = "zone"
  phase   = "http_request_dynamic_redirect"

  rules = [{
    ref         = "www_to_apex"
    description = "Redirect www to the apex host"
    expression  = "(http.host eq \"${local.www_host}\")"
    action      = "redirect"
    action_parameters = {
      from_value = {
        status_code           = 301
        preserve_query_string = true
        target_url = {
          expression = "concat(\"https://${local.zone_name}\", http.request.uri.path)"
        }
      }
    }
  }]
}
