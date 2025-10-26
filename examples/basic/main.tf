terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.80.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "rg-storage-basic-example"
  location = "westeurope"
}

module "storage_account" {
  source = "../.."

  name                = "stbasicexample001"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  environment         = "test"

  account_tier             = "Standard"
  account_replication_type = "LRS"

  containers = {
    "data" = {
      container_access_type = "private"
    }
    "logs" = {
      container_access_type = "private"
    }
  }

  tags = {
    Example = "Basic"
  }
}

output "storage_account_name" {
  value = module.storage_account.name
}

output "primary_blob_endpoint" {
  value = module.storage_account.primary_blob_endpoint
}