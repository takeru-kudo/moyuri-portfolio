output "k5_client_id" {
  description = "Client ID of the E2E service token (K5)."
  value       = cloudflare_zero_trust_access_service_token.e2e.client_id
  sensitive   = true
}

output "k5_client_secret" {
  description = "Client secret of the E2E service token (K5)."
  value       = cloudflare_zero_trust_access_service_token.e2e.client_secret
  sensitive   = true
}
