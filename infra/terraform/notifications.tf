resource "cloudflare_notification_policy" "http_ddos" {
  account_id = var.account_id
  name       = "HTTP DDoS attack"
  alert_type = "dos_attack_l7"
  enabled    = true
  mechanisms = {
    email = [{ id = var.notification_email }]
  }
}

resource "cloudflare_notification_policy" "universal_ssl" {
  account_id = var.account_id
  name       = "Universal SSL"
  alert_type = "universal_ssl_event_type"
  enabled    = true
  mechanisms = {
    email = [{ id = var.notification_email }]
  }
}
