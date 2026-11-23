# D1 database for the csp-report Worker.
resource "cloudflare_d1_database" "csp_reports" {
  account_id            = var.account_id
  name                  = "csp_reports"
  primary_location_hint = "apac"
}
