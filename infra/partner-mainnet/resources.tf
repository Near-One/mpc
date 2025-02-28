terraform {
  backend "gcs" {
    bucket = "nearone-terraform"
    prefix = "state/infra/multichain/mainnet"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}
