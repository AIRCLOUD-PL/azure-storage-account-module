<p align="center">
  <a href="https://aircloud.com.pl"><img src=".github/assets/banner.png" alt="AIRCLOUD: DevOps, cloud and AI engineering" width="100%"></a>
</p>

# azure-storage-account-module

**Azure Storage Account Terraform module — parameterised, azurerm 4.x, CI-validated.**

[![CI](https://github.com/AIRCLOUD-PL/azure-storage-account-module/actions/workflows/ci.yml/badge.svg)](https://github.com/AIRCLOUD-PL/azure-storage-account-module/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/AIRCLOUD-PL/azure-storage-account-module?sort=semver)](https://github.com/AIRCLOUD-PL/azure-storage-account-module/releases)

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

Pin the module to a release tag:

```hcl
module "storage_account" {
  source = "git::https://github.com/AIRCLOUD-PL/azure-storage-account-module.git?ref=v1.0.0"

  # required inputs
  environment         = "..."
  location            = "..."
  resource_group_name = "..."
}
```

All inputs and outputs are listed in the generated reference below ([Inputs](#inputs), [Outputs](#outputs)). Worked examples live in [`examples/`](examples/).

### Basic Example

```hcl
module "storage_account" {
  source = "git::https://github.com/AIRCLOUD-PL/azure-storage-account-module.git?ref=v1.0.0"

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
  source = "git::https://github.com/AIRCLOUD-PL/azure-storage-account-module.git?ref=v1.0.0"

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

## License

MIT

## Reference

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | ~> 4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 4.81.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [azurerm_advanced_threat_protection.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/advanced_threat_protection) | resource |
| [azurerm_management_lock.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock) | resource |
| [azurerm_monitor_diagnostic_setting.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting) | resource |
| [azurerm_private_dns_zone.blob](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone) | resource |
| [azurerm_private_dns_zone.file](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone) | resource |
| [azurerm_private_dns_zone.queue](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone) | resource |
| [azurerm_private_dns_zone.table](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone) | resource |
| [azurerm_private_dns_zone_virtual_network_link.blob](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link) | resource |
| [azurerm_private_dns_zone_virtual_network_link.file](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link) | resource |
| [azurerm_private_dns_zone_virtual_network_link.queue](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link) | resource |
| [azurerm_private_dns_zone_virtual_network_link.table](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_dns_zone_virtual_network_link) | resource |
| [azurerm_private_endpoint.blob](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) | resource |
| [azurerm_private_endpoint.file](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) | resource |
| [azurerm_private_endpoint.queue](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) | resource |
| [azurerm_private_endpoint.table](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint) | resource |
| [azurerm_resource_group.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group) | resource |
| [azurerm_resource_group_policy_assignment.encryption_at_rest](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group_policy_assignment) | resource |
| [azurerm_resource_group_policy_assignment.https_only](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group_policy_assignment) | resource |
| [azurerm_resource_group_policy_assignment.public_access](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/resource_group_policy_assignment) | resource |
| [azurerm_storage_account.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account) | resource |
| [azurerm_storage_account_static_website.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_static_website) | resource |
| [azurerm_storage_container.containers](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_container) | resource |
| [azurerm_storage_management_policy.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_management_policy) | resource |
| [azurerm_storage_queue.queues](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_queue) | resource |
| [azurerm_storage_share.shares](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_share) | resource |
| [azurerm_storage_table.tables](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_table) | resource |
| [azurerm_resource_group.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/resource_group) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_access_tier"></a> [access\_tier](#input\_access\_tier) | Access tier: Hot or Cool | `string` | `"Hot"` | no |
| <a name="input_account_kind"></a> [account\_kind](#input\_account\_kind) | Account kind: BlobStorage, BlockBlobStorage, FileStorage, Storage, StorageV2 | `string` | `"StorageV2"` | no |
| <a name="input_account_replication_type"></a> [account\_replication\_type](#input\_account\_replication\_type) | Replication type: LRS, GRS, RAGRS, ZRS, GZRS, RAGZRS | `string` | `"GRS"` | no |
| <a name="input_account_tier"></a> [account\_tier](#input\_account\_tier) | Storage account tier: Standard or Premium | `string` | `"Standard"` | no |
| <a name="input_allow_nested_items_to_be_public"></a> [allow\_nested\_items\_to\_be\_public](#input\_allow\_nested\_items\_to\_be\_public) | Allow nested items (containers, blobs) to be public | `bool` | `false` | no |
| <a name="input_allow_shared_key_access"></a> [allow\_shared\_key\_access](#input\_allow\_shared\_key\_access) | Allow shared key access | `bool` | `true` | no |
| <a name="input_blob_properties"></a> [blob\_properties](#input\_blob\_properties) | Blob properties configuration | <pre>object({<br/>    versioning_enabled       = optional(bool, false)<br/>    change_feed_enabled      = optional(bool, false)<br/>    last_access_time_enabled = optional(bool, false)<br/>    cors_rules = optional(list(object({<br/>      allowed_headers    = list(string)<br/>      allowed_methods    = list(string)<br/>      allowed_origins    = list(string)<br/>      exposed_headers    = list(string)<br/>      max_age_in_seconds = number<br/>    })), [])<br/>    delete_retention_policy = optional(object({<br/>      days = number<br/>    }))<br/>    container_delete_retention_policy = optional(object({<br/>      days = number<br/>    }))<br/>  })</pre> | `null` | no |
| <a name="input_containers"></a> [containers](#input\_containers) | Map of blob containers to create | <pre>map(object({<br/>    container_access_type = optional(string, "private")<br/>  }))</pre> | `{}` | no |
| <a name="input_create_private_dns_zone"></a> [create\_private\_dns\_zone](#input\_create\_private\_dns\_zone) | Create private DNS zones for private endpoints | `bool` | `false` | no |
| <a name="input_create_resource_group"></a> [create\_resource\_group](#input\_create\_resource\_group) | Create resource group if it doesn't exist | `bool` | `false` | no |
| <a name="input_cross_tenant_replication_enabled"></a> [cross\_tenant\_replication\_enabled](#input\_cross\_tenant\_replication\_enabled) | Enable cross-tenant replication | `bool` | `false` | no |
| <a name="input_custom_domain"></a> [custom\_domain](#input\_custom\_domain) | Custom domain configuration | <pre>object({<br/>    name          = string<br/>    use_subdomain = optional(bool, false)<br/>  })</pre> | `null` | no |
| <a name="input_customer_managed_key"></a> [customer\_managed\_key](#input\_customer\_managed\_key) | Customer-managed key for encryption | <pre>object({<br/>    key_vault_key_id          = string<br/>    user_assigned_identity_id = string<br/>  })</pre> | `null` | no |
| <a name="input_diagnostic_settings"></a> [diagnostic\_settings](#input\_diagnostic\_settings) | Diagnostic settings configuration | <pre>object({<br/>    logs = list(object({<br/>      category = string<br/>    }))<br/>    metrics = list(object({<br/>      category = string<br/>      enabled  = bool<br/>    }))<br/>  })</pre> | <pre>{<br/>  "logs": [<br/>    {<br/>      "category": "StorageRead"<br/>    },<br/>    {<br/>      "category": "StorageWrite"<br/>    },<br/>    {<br/>      "category": "StorageDelete"<br/>    }<br/>  ],<br/>  "metrics": [<br/>    {<br/>      "category": "Transaction",<br/>      "enabled": true<br/>    },<br/>    {<br/>      "category": "Capacity",<br/>      "enabled": true<br/>    }<br/>  ]<br/>}</pre> | no |
| <a name="input_enable_advanced_threat_protection"></a> [enable\_advanced\_threat\_protection](#input\_enable\_advanced\_threat\_protection) | Enable advanced threat protection | `bool` | `true` | no |
| <a name="input_enable_diagnostic_settings"></a> [enable\_diagnostic\_settings](#input\_enable\_diagnostic\_settings) | Enable diagnostic settings for storage account | `bool` | `true` | no |
| <a name="input_enable_https_traffic_only"></a> [enable\_https\_traffic\_only](#input\_enable\_https\_traffic\_only) | Enable HTTPS traffic only | `bool` | `true` | no |
| <a name="input_enable_policy_assignments"></a> [enable\_policy\_assignments](#input\_enable\_policy\_assignments) | Enable Azure Policy assignments for this storage account | `bool` | `true` | no |
| <a name="input_enable_private_endpoint"></a> [enable\_private\_endpoint](#input\_enable\_private\_endpoint) | Enable private endpoints for storage account | `bool` | `false` | no |
| <a name="input_enable_resource_lock"></a> [enable\_resource\_lock](#input\_enable\_resource\_lock) | Enable resource lock for storage account | `bool` | `false` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment name (prod, dev, test) | `string` | n/a | yes |
| <a name="input_file_shares"></a> [file\_shares](#input\_file\_shares) | Map of file shares to create | <pre>map(object({<br/>    quota            = number<br/>    enabled_protocol = optional(string, "SMB")<br/>    acls = optional(list(object({<br/>      id = string<br/>      access_policies = optional(list(object({<br/>        permissions = string<br/>        start       = optional(string)<br/>        expiry      = optional(string)<br/>      })), [])<br/>    })), [])<br/>  }))</pre> | `{}` | no |
| <a name="input_identity_ids"></a> [identity\_ids](#input\_identity\_ids) | User assigned identity IDs | `list(string)` | `[]` | no |
| <a name="input_identity_type"></a> [identity\_type](#input\_identity\_type) | Managed identity type: SystemAssigned, UserAssigned, or both | `string` | `"SystemAssigned"` | no |
| <a name="input_infrastructure_encryption_enabled"></a> [infrastructure\_encryption\_enabled](#input\_infrastructure\_encryption\_enabled) | Enable infrastructure encryption (double encryption) | `bool` | `false` | no |
| <a name="input_is_hns_enabled"></a> [is\_hns\_enabled](#input\_is\_hns\_enabled) | Enable hierarchical namespace (Data Lake Storage Gen2) | `bool` | `false` | no |
| <a name="input_large_file_share_enabled"></a> [large\_file\_share\_enabled](#input\_large\_file\_share\_enabled) | Enable large file shares (100TiB) | `bool` | `false` | no |
| <a name="input_location"></a> [location](#input\_location) | Azure region | `string` | n/a | yes |
| <a name="input_lock_level"></a> [lock\_level](#input\_lock\_level) | Resource lock level: CanNotDelete or ReadOnly | `string` | `"CanNotDelete"` | no |
| <a name="input_log_analytics_workspace_id"></a> [log\_analytics\_workspace\_id](#input\_log\_analytics\_workspace\_id) | Log Analytics workspace ID for diagnostic settings | `string` | `null` | no |
| <a name="input_management_policy"></a> [management\_policy](#input\_management\_policy) | Lifecycle management policy | <pre>object({<br/>    rules = list(object({<br/>      name    = string<br/>      enabled = optional(bool, true)<br/>      filters = object({<br/>        prefix_match = optional(list(string), [])<br/>        blob_types   = optional(list(string), ["blockBlob"])<br/>      })<br/>      actions = object({<br/>        base_blob = optional(object({<br/>          tier_to_cool_after_days    = optional(number)<br/>          tier_to_archive_after_days = optional(number)<br/>          delete_after_days          = optional(number)<br/>        }))<br/>        snapshot = optional(object({<br/>          delete_after_days = number<br/>        }))<br/>      })<br/>    }))<br/>  })</pre> | `null` | no |
| <a name="input_min_tls_version"></a> [min\_tls\_version](#input\_min\_tls\_version) | Minimum TLS version: TLS1\_0, TLS1\_1, TLS1\_2 | `string` | `"TLS1_2"` | no |
| <a name="input_name"></a> [name](#input\_name) | Storage account name (3-24 chars, lowercase, numbers). If null, will be auto-generated. | `string` | `null` | no |
| <a name="input_naming_prefix"></a> [naming\_prefix](#input\_naming\_prefix) | Prefix for auto-generated storage account name | `string` | `"st"` | no |
| <a name="input_network_rules"></a> [network\_rules](#input\_network\_rules) | Network rules configuration | <pre>object({<br/>    default_action             = string<br/>    bypass                     = optional(list(string), ["AzureServices"])<br/>    ip_rules                   = optional(list(string), [])<br/>    virtual_network_subnet_ids = optional(list(string), [])<br/>    private_link_access = optional(list(object({<br/>      endpoint_resource_id = string<br/>      endpoint_tenant_id   = optional(string)<br/>    })), [])<br/>  })</pre> | `null` | no |
| <a name="input_nfsv3_enabled"></a> [nfsv3\_enabled](#input\_nfsv3\_enabled) | Enable NFS v3 protocol | `bool` | `false` | no |
| <a name="input_private_dns_zone_virtual_network_id"></a> [private\_dns\_zone\_virtual\_network\_id](#input\_private\_dns\_zone\_virtual\_network\_id) | Virtual network ID to link private DNS zones to | `string` | `null` | no |
| <a name="input_private_endpoint_subnet_id"></a> [private\_endpoint\_subnet\_id](#input\_private\_endpoint\_subnet\_id) | Subnet ID for private endpoints | `string` | `null` | no |
| <a name="input_private_endpoint_subresources"></a> [private\_endpoint\_subresources](#input\_private\_endpoint\_subresources) | List of subresources to create private endpoints for | `list(string)` | <pre>[<br/>  "blob"<br/>]</pre> | no |
| <a name="input_public_network_access_enabled"></a> [public\_network\_access\_enabled](#input\_public\_network\_access\_enabled) | Enable public network access | `bool` | `true` | no |
| <a name="input_queue_encryption_key_type"></a> [queue\_encryption\_key\_type](#input\_queue\_encryption\_key\_type) | Queue encryption key type: Service or Account | `string` | `"Service"` | no |
| <a name="input_queue_properties"></a> [queue\_properties](#input\_queue\_properties) | Queue properties configuration | <pre>object({<br/>    cors_rules = optional(list(object({<br/>      allowed_headers    = list(string)<br/>      allowed_methods    = list(string)<br/>      allowed_origins    = list(string)<br/>      exposed_headers    = list(string)<br/>      max_age_in_seconds = number<br/>    })), [])<br/>    logging = optional(object({<br/>      delete                = bool<br/>      read                  = bool<br/>      write                 = bool<br/>      version               = string<br/>      retention_policy_days = optional(number, 7)<br/>    }))<br/>  })</pre> | `null` | no |
| <a name="input_queues"></a> [queues](#input\_queues) | Map of queues to create | `map(object({}))` | `{}` | no |
| <a name="input_resource_group_location"></a> [resource\_group\_location](#input\_resource\_group\_location) | Location for resource group creation (if create\_resource\_group is true) | `string` | `null` | no |
| <a name="input_resource_group_name"></a> [resource\_group\_name](#input\_resource\_group\_name) | Resource group name | `string` | n/a | yes |
| <a name="input_sas_policy"></a> [sas\_policy](#input\_sas\_policy) | SAS policy configuration | <pre>object({<br/>    https_only     = optional(bool, true)<br/>    signed_version = optional(string, "2020-04-08")<br/>    permissions = object({<br/>      read    = optional(bool, false)<br/>      write   = optional(bool, false)<br/>      delete  = optional(bool, false)<br/>      list    = optional(bool, false)<br/>      add     = optional(bool, false)<br/>      create  = optional(bool, false)<br/>      update  = optional(bool, false)<br/>      process = optional(bool, false)<br/>      tag     = optional(bool, false)<br/>      filter  = optional(bool, false)<br/>    })<br/>    services = object({<br/>      blob  = optional(bool, false)<br/>      queue = optional(bool, false)<br/>      table = optional(bool, false)<br/>      file  = optional(bool, false)<br/>    })<br/>    resource_types = object({<br/>      service   = optional(bool, false)<br/>      container = optional(bool, false)<br/>      object    = optional(bool, false)<br/>    })<br/>    expiry = string<br/>    start  = optional(string)<br/>  })</pre> | `null` | no |
| <a name="input_sftp_enabled"></a> [sftp\_enabled](#input\_sftp\_enabled) | Enable SFTP | `bool` | `false` | no |
| <a name="input_shared_access_key_enabled"></a> [shared\_access\_key\_enabled](#input\_shared\_access\_key\_enabled) | Enable shared access key | `bool` | `true` | no |
| <a name="input_static_website"></a> [static\_website](#input\_static\_website) | Static website configuration | <pre>object({<br/>    index_document     = optional(string)<br/>    error_404_document = optional(string)<br/>  })</pre> | `null` | no |
| <a name="input_table_encryption_key_type"></a> [table\_encryption\_key\_type](#input\_table\_encryption\_key\_type) | Table encryption key type: Service or Account | `string` | `"Service"` | no |
| <a name="input_tables"></a> [tables](#input\_tables) | Map of tables to create | `map(object({}))` | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Resource tags | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_container_ids"></a> [container\_ids](#output\_container\_ids) | IDs of created containers |
| <a name="output_file_share_ids"></a> [file\_share\_ids](#output\_file\_share\_ids) | IDs of created file shares |
| <a name="output_id"></a> [id](#output\_id) | Storage account ID |
| <a name="output_identity"></a> [identity](#output\_identity) | Managed identity block |
| <a name="output_identity_principal_id"></a> [identity\_principal\_id](#output\_identity\_principal\_id) | Principal ID of managed identity |
| <a name="output_name"></a> [name](#output\_name) | Storage account name |
| <a name="output_primary_access_key"></a> [primary\_access\_key](#output\_primary\_access\_key) | Primary access key |
| <a name="output_primary_blob_endpoint"></a> [primary\_blob\_endpoint](#output\_primary\_blob\_endpoint) | Primary blob endpoint |
| <a name="output_primary_connection_string"></a> [primary\_connection\_string](#output\_primary\_connection\_string) | Primary connection string |
| <a name="output_primary_file_endpoint"></a> [primary\_file\_endpoint](#output\_primary\_file\_endpoint) | Primary file endpoint |
| <a name="output_primary_queue_endpoint"></a> [primary\_queue\_endpoint](#output\_primary\_queue\_endpoint) | Primary queue endpoint |
| <a name="output_primary_table_endpoint"></a> [primary\_table\_endpoint](#output\_primary\_table\_endpoint) | Primary table endpoint |
| <a name="output_secondary_access_key"></a> [secondary\_access\_key](#output\_secondary\_access\_key) | Secondary access key |
<!-- END_TF_DOCS -->

---

## Part of the AIRCLOUD Azure module catalog

Browse all modules with usage snippets in the [module catalog](https://aircloud-pl.github.io/) or on [github.com/AIRCLOUD-PL](https://github.com/AIRCLOUD-PL). Built and maintained by [AIRCLOUD](https://aircloud.com.pl): DevOps, cloud and AI engineering. Need a hand with Azure landing zones or platform engineering? See [aircloud.com.pl/consulting](https://aircloud.com.pl/consulting).
