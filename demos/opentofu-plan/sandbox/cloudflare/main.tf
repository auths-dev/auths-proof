terraform {
  required_version = "= 1.12.5"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.22.0"
    }
  }

  backend "local" {
    path = "/data/auths-opentofu/cloudflare.tfstate"
  }
}

variable "AUTHS_ZONE_ID" {
  type      = string
  nullable  = false
  sensitive = true
}

variable "AUTHS_RECORD_NAME" {
  type     = string
  nullable = false
}

variable "AUTHS_RECORD_VALUE" {
  type     = string
  nullable = false
}

resource "cloudflare_dns_record" "authorized_demo" {
  zone_id = var.AUTHS_ZONE_ID
  name    = var.AUTHS_RECORD_NAME
  type    = "TXT"
  content = "\"${var.AUTHS_RECORD_VALUE}\""
  ttl     = 60
  proxied = false
  comment = "Synthetic Auths saved-plan demonstration"
}
