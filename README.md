# Azure Storage Account Terraform Module

Enterprise-grade Azure Storage Account module with comprehensive security and compliance features.

## Features

✅ **All Storage Types** - BlobStorage, FileStorage, BlockBlobStorage, StorageV2  
✅ **Advanced Security** - Customer-managed keys, private endpoints, network rules  
✅ **Data Protection** - Soft delete, versioning, immutability policies  
✅ **Lifecycle Management** - Automated tiering and deletion policies  
✅ **Threat Protection** - Advanced threat detection  
✅ **Multiple Services** - Blobs, Files, Queues, Tables  
✅ **Data Lake Gen2** - Hierarchical namespace support  
✅ **NFS v3** - Network File System support  

## Usage

### Basic Example

```hcl
module "storage_account" {
  source = "github.com/AIRCLOUD-PL/terraform-azurerm-storage-account?ref=v1.0.0"

  name                = "stprodwesteu001"
  location            = "westeurope"
  resource_group_name = "rg-production"
  environment         = "prod"
  
  account_tier             = "Standard"
  account_replication_type = "GRS"
  
  tags = {
    Environment = "Production"
  }
}
```

### With Encryption and Private Endpoints

```hcl
module "storage_account" {
  source = "github.com/AIRCLOUD-PL/terraform-azurerm-storage-account?ref=v1.0.0"

  name                = "stprodwesteu001"
  location            = "westeurope"
  resource_group_name = "rg-production"
  environment         = "prod"
  
  account_tier             = "Standard"
  account_replication_type = "GZRS"
  
  # Security
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  infrastructure_encryption_enabled = true
  
  # Customer-managed encryption
  customer_managed_key = {
    key_vault_key_id          = azurerm_key_vault_key.main.id
    user_assigned_identity_id = azurerm_user_assigned_identity.main.id
  }
  
  # Network security
  network_rules = {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    ip_rules                   = ["203.0.113.0/24"]
    virtual_network_subnet_ids = [azurerm_subnet.main.id]
  }
  
  # Blob properties
  blob_properties = {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true
    
    delete_retention_policy = {
      days = 30
    }
    
    container_delete_retention_policy = {
      days = 30
    }
  }
  
  # Threat protection
  enable_advanced_threat_protection = true
  
  tags = {
    Environment = "Production"
    Compliance  = "GDPR"
  }
}
```

## Version

Current version: **v1.0.0**

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.5.0 |
| azurerm | >= 3.80.0 |

## License

MIT

## Requirements

No requirements.

## Providers

No providers.

## Modules

No modules.

## Resources

No resources.

## Inputs

No inputs.

## Outputs

No outputs.

<!-- BEGIN_TF_DOCS -->
<!-- END_TF_DOCS -->
