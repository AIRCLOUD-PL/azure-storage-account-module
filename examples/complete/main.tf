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
  name     = "rg-storage-complete-example"
  location = "westeurope"
}

resource "azurerm_virtual_network" "example" {
  name                = "vnet-storage-example"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "storage" {
  name                 = "snet-storage"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "blob-dns-link"
  resource_group_name   = azurerm_resource_group.example.name
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.example.id
}

module "storage_account" {
  source = "../.."

  name                = "stcompleteexample001"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  environment         = "test"

  account_tier             = "Standard"
  account_replication_type = "GZRS"
  account_kind             = "StorageV2"
  access_tier              = "Hot"

  # Security
  enable_https_traffic_only         = true
  min_tls_version                   = "TLS1_2"
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  infrastructure_encryption_enabled = true

  # Identity
  identity_type = "SystemAssigned"

  # Blob Properties
  blob_properties = {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true

    delete_retention_policy = {
      days = 30
    }

    container_delete_retention_policy = {
      days = 7
    }

    cors_rules = [
      {
        allowed_headers    = ["*"]
        allowed_methods    = ["GET", "HEAD", "POST", "PUT", "DELETE"]
        allowed_origins    = ["https://example.com"]
        exposed_headers    = ["*"]
        max_age_in_seconds = 3600
      }
    ]
  }

  # Network Rules
  network_rules = {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = ["203.0.113.0/24"]
    virtual_network_subnet_ids = [
      azurerm_subnet.storage.id
    ]
  }

  # Containers
  containers = {
    "data" = {
      container_access_type = "private"
    }
    "backups" = {
      container_access_type = "private"
    }
    "logs" = {
      container_access_type = "private"
    }
  }

  # File Shares
  file_shares = {
    "files" = {
      quota            = 1024
      enabled_protocol = "SMB"
    }
    "shared" = {
      quota            = 512
      enabled_protocol = "SMB"
    }
  }

  # Queues
  queues = {
    "messages"      = {}
    "notifications" = {}
  }

  # Tables
  tables = {
    "users"    = {}
    "sessions" = {}
  }

  # Management Policy
  management_policy = {
    rules = [
      {
        name = "delete-old-blobs"
        filters = {
          prefix_match = ["logs/"]
          blob_types   = ["blockBlob"]
        }
        actions = {
          base_blob = {
            delete_after_days = 30
          }
        }
      },
      {
        name = "tier-blobs-to-cool"
        filters = {
          prefix_match = ["data/"]
          blob_types   = ["blockBlob"]
        }
        actions = {
          base_blob = {
            tier_to_cool_after_days    = 30
            tier_to_archive_after_days = 90
          }
        }
      }
    ]
  }

  # Advanced Threat Protection
  enable_advanced_threat_protection = true

  tags = {
    Example    = "Complete"
    Security   = "High"
    Compliance = "SOX"
  }
}

output "storage_account_id" {
  value = module.storage_account.id
}

output "storage_account_name" {
  value = module.storage_account.name
}

output "primary_blob_endpoint" {
  value = module.storage_account.primary_blob_endpoint
}

output "identity_principal_id" {
  value = module.storage_account.identity_principal_id
}

output "container_ids" {
  value = module.storage_account.container_ids
}

output "file_share_ids" {
  value = module.storage_account.file_share_ids
}