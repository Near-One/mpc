terraform {
  backend "gcs" {
    bucket = "nearone-terraform"
    prefix = "state/infra/multichain/testnet"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}
