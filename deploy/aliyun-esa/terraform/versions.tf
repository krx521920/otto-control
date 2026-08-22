terraform {
  required_version = ">= 1.6.0"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.279.0"
    }
  }
}

provider "alicloud" {
  region = var.region
}
