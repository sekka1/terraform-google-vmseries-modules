terraform {
  required_version = ">= 0.15.3, < 2.0"
  required_providers {
    google = { 
      # version = "~> 3.30" 
      version = ">= 4.50, < 5.0"
    }
  }
}
