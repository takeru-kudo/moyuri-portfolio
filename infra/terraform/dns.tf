# Null MX: the domain accepts no mail.
resource "cloudflare_dns_record" "mx_null" {
  zone_id  = var.zone_id
  name     = local.zone_name
  type     = "MX"
  content  = "."
  priority = 0
  ttl      = 1
}

# Proxied placeholder address for the www host; requests are answered by the redirect rule.
resource "cloudflare_dns_record" "www" {
  zone_id = var.zone_id
  name    = "www.${local.zone_name}"
  type    = "AAAA"
  content = "100::"
  proxied = true
  ttl     = 1
}

# TXT content is stored with surrounding double quotes.
resource "cloudflare_dns_record" "spf" {
  zone_id = var.zone_id
  name    = local.zone_name
  type    = "TXT"
  content = "\"v=spf1 -all\""
  ttl     = 1
}

resource "cloudflare_dns_record" "dmarc" {
  zone_id = var.zone_id
  name    = "_dmarc.${local.zone_name}"
  type    = "TXT"
  content = "\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""
  ttl     = 1
}

resource "cloudflare_dns_record" "dkim_empty" {
  zone_id = var.zone_id
  name    = "*._domainkey.${local.zone_name}"
  type    = "TXT"
  content = "\"v=DKIM1; p=\""
  ttl     = 1
}

locals {
  caa_issuers = {
    letsencrypt = "letsencrypt.org"
    google      = "pki.goog; cansignhttpexchanges=yes"
    sslcom      = "ssl.com"
  }

  caa_records = merge([
    for key, issuer in local.caa_issuers : {
      for tag in ["issue", "issuewild"] : "${key}_${tag}" => {
        tag   = tag
        value = issuer
      }
    }
  ]...)
}

resource "cloudflare_dns_record" "caa" {
  for_each = local.caa_records

  zone_id = var.zone_id
  name    = local.zone_name
  type    = "CAA"
  ttl     = 1
  data = {
    flags = 0
    tag   = each.value.tag
    value = each.value.value
  }
}
