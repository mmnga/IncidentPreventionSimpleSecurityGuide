terraform {
  required_version = ">= 1.5.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  # Supply an approved encrypted/locked backend outside the example checkout.
}
provider "aws" {
  region = var.region
  default_tags { tags = { Project = "atlas-synthetic", Environment = "example" } }
}
variable "region" { default = "ap-northeast-1" }
variable "provision_enabled" {
  type    = bool
  default = false
}
variable "account_id" {
  type    = string
  default = "000000000000"
}
resource "terraform_data" "fixture_guard" {
  input = "SYNTHETIC_REFERENCE_ONLY"
  lifecycle {
    precondition {
      condition     = var.provision_enabled && var.account_id != "000000000000"
      error_message = "Reference fixture: provisioning is disabled; no real account is supplied."
    }
  }
}
