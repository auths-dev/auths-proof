terraform {
  required_version = "= 1.12.5"

  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "= 2.9.0"
    }
  }

  backend "local" {
    path          = "/data/auths-opentofu/local.tfstate"
    workspace_dir = "/data/auths-opentofu/workspaces"
  }
}

variable "AUTHS_OBJECT_ID" {
  type      = string
  nullable  = false
  sensitive = false

  validation {
    condition     = can(regex("^session-[0-9a-f]{32}$", var.AUTHS_OBJECT_ID))
    error_message = "AUTHS_OBJECT_ID must be the native service session identifier."
  }
}

variable "AUTHS_OBJECT_VALUE" {
  type      = string
  nullable  = false
  sensitive = true
}

resource "local_file" "authorized_object" {
  filename        = "/data/auths-opentofu/objects/${var.AUTHS_OBJECT_ID}.json"
  content         = jsonencode({ authorization = var.AUTHS_OBJECT_VALUE })
  file_permission = "0600"
}

output "provider_observation" {
  value = {
    object_path_commitment = sha256(local_file.authorized_object.filename)
    content_commitment     = local_file.authorized_object.content_sha256
  }
}
