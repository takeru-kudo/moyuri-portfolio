# The R2 endpoint is supplied at init time with -backend-config.
terraform {
  backend "s3" {
    bucket                      = "tfstate"
    key                         = "portfolio/terraform.tfstate"
    region                      = "auto"
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
