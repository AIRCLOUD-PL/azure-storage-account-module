variable "name" {
  description = "Storage account name (3-24 chars, lowercase, numbers). If null, will be auto-generated."
  type        = string
  default     = null
}

variable "naming_prefix" {
  description = "Prefix for auto-generated storage account name"
  type        = string
  default     = "st"
}

variable "environment" {
  description = "Environment name (prod, dev, test)"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
}

variable "account_tier" {
  description = "Storage account tier: Standard or Premium"
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Standard", "Premium"], var.account_tier)
    error_message = "Account tier must be Standard or Premium."
  }
}

variable "account_replication_type" {
  description = "Replication type: LRS, GRS, RAGRS, ZRS, GZRS, RAGZRS"
  type        = string
  default     = "GRS"
  validation {
    condition     = contains(["LRS", "GRS", "RAGRS", "ZRS", "GZRS", "RAGZRS"], var.account_replication_type)
    error_message = "Must be valid replication type."
  }
}

variable "account_kind" {
  description = "Account kind: BlobStorage, BlockBlobStorage, FileStorage, Storage, StorageV2"
  type        = string
  default     = "StorageV2"
  validation {
    condition     = contains(["BlobStorage", "BlockBlobStorage", "FileStorage", "Storage", "StorageV2"], var.account_kind)
    error_message = "Must be valid account kind."
  }
}

variable "access_tier" {
  description = "Access tier: Hot or Cool"
  type        = string
  default     = "Hot"
  validation {
    condition     = contains(["Hot", "Cool"], var.access_tier)
    error_message = "Access tier must be Hot or Cool."
  }
}

variable "enable_https_traffic_only" {
  description = "Enable HTTPS traffic only"
  type        = bool
  default     = true
}

variable "min_tls_version" {
  description = "Minimum TLS version: TLS1_0, TLS1_1, TLS1_2"
  type        = string
  default     = "TLS1_2"
}

variable "allow_nested_items_to_be_public" {
  description = "Allow nested items (containers, blobs) to be public"
  type        = bool
  default     = false
}

variable "shared_access_key_enabled" {
  description = "Enable shared access key"
  type        = bool
  default     = true
}

variable "infrastructure_encryption_enabled" {
  description = "Enable infrastructure encryption (double encryption)"
  type        = bool
  default     = false
}

variable "large_file_share_enabled" {
  description = "Enable large file shares (100TiB)"
  type        = bool
  default     = false
}

variable "is_hns_enabled" {
  description = "Enable hierarchical namespace (Data Lake Storage Gen2)"
  type        = bool
  default     = false
}

variable "nfsv3_enabled" {
  description = "Enable NFS v3 protocol"
  type        = bool
  default     = false
}

variable "sftp_enabled" {
  description = "Enable SFTP"
  type        = bool
  default     = false
}

variable "cross_tenant_replication_enabled" {
  description = "Enable cross-tenant replication"
  type        = bool
  default     = false
}

variable "identity_type" {
  description = "Managed identity type: SystemAssigned, UserAssigned, or both"
  type        = string
  default     = "SystemAssigned"
}

variable "identity_ids" {
  description = "User assigned identity IDs"
  type        = list(string)
  default     = []
}

variable "blob_properties" {
  description = "Blob properties configuration"
  type = object({
    versioning_enabled       = optional(bool, false)
    change_feed_enabled      = optional(bool, false)
    last_access_time_enabled = optional(bool, false)
    cors_rules = optional(list(object({
      allowed_headers    = list(string)
      allowed_methods    = list(string)
      allowed_origins    = list(string)
      exposed_headers    = list(string)
      max_age_in_seconds = number
    })), [])
    delete_retention_policy = optional(object({
      days = number
    }))
    container_delete_retention_policy = optional(object({
      days = number
    }))
  })
  default = null
}

variable "queue_properties" {
  description = "Queue properties configuration"
  type = object({
    cors_rules = optional(list(object({
      allowed_headers    = list(string)
      allowed_methods    = list(string)
      allowed_origins    = list(string)
      exposed_headers    = list(string)
      max_age_in_seconds = number
    })), [])
    logging = optional(object({
      delete                = bool
      read                  = bool
      write                 = bool
      version               = string
      retention_policy_days = optional(number, 7)
    }))
  })
  default = null
}

variable "network_rules" {
  description = "Network rules configuration"
  type = object({
    default_action             = string
    bypass                     = optional(list(string), ["AzureServices"])
    ip_rules                   = optional(list(string), [])
    virtual_network_subnet_ids = optional(list(string), [])
    private_link_access = optional(list(object({
      endpoint_resource_id = string
      endpoint_tenant_id   = optional(string)
    })), [])
  })
  default = null
}

variable "customer_managed_key" {
  description = "Customer-managed key for encryption"
  type = object({
    key_vault_key_id          = string
    user_assigned_identity_id = string
  })
  default = null
}

variable "enable_advanced_threat_protection" {
  description = "Enable advanced threat protection"
  type        = bool
  default     = true
}

variable "containers" {
  description = "Map of blob containers to create"
  type = map(object({
    container_access_type = optional(string, "private")
  }))
  default = {}
}

variable "file_shares" {
  description = "Map of file shares to create"
  type = map(object({
    quota            = number
    enabled_protocol = optional(string, "SMB")
    acls = optional(list(object({
      id = string
      access_policies = optional(list(object({
        permissions = string
        start       = optional(string)
        expiry      = optional(string)
      })), [])
    })), [])
  }))
  default = {}
}

variable "queues" {
  description = "Map of queues to create"
  type        = map(object({}))
  default     = {}
}

variable "tables" {
  description = "Map of tables to create"
  type        = map(object({}))
  default     = {}
}

variable "management_policy" {
  description = "Lifecycle management policy"
  type = object({
    rules = list(object({
      name    = string
      enabled = optional(bool, true)
      filters = object({
        prefix_match = optional(list(string), [])
        blob_types   = optional(list(string), ["blockBlob"])
      })
      actions = object({
        base_blob = optional(object({
          tier_to_cool_after_days    = optional(number)
          tier_to_archive_after_days = optional(number)
          delete_after_days          = optional(number)
        }))
        snapshot = optional(object({
          delete_after_days = number
        }))
      })
    }))
  })
  default = null
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}

variable "enable_private_endpoint" {
  description = "Enable private endpoints for storage account"
  type        = bool
  default     = false
}

variable "private_endpoint_subresources" {
  description = "List of subresources to create private endpoints for"
  type        = list(string)
  default     = ["blob"]
  validation {
    condition = alltrue([
      for subresource in var.private_endpoint_subresources : contains(["blob", "file", "queue", "table"], subresource)
    ])
    error_message = "Private endpoint subresources must be one of: blob, file, queue, table."
  }
}

variable "private_endpoint_subnet_id" {
  description = "Subnet ID for private endpoints"
  type        = string
  default     = null
}

variable "create_private_dns_zone" {
  description = "Create private DNS zones for private endpoints"
  type        = bool
  default     = false
}

variable "private_dns_zone_virtual_network_id" {
  description = "Virtual network ID to link private DNS zones to"
  type        = string
  default     = null
}

variable "enable_diagnostic_settings" {
  description = "Enable diagnostic settings for storage account"
  type        = bool
  default     = true
}

variable "log_analytics_workspace_id" {
  description = "Log Analytics workspace ID for diagnostic settings"
  type        = string
  default     = null
}

variable "diagnostic_settings" {
  description = "Diagnostic settings configuration"
  type = object({
    logs = list(object({
      category = string
    }))
    metrics = list(object({
      category = string
      enabled  = bool
    }))
  })
  default = {
    logs = [
      { category = "StorageRead" },
      { category = "StorageWrite" },
      { category = "StorageDelete" }
    ]
    metrics = [
      { category = "Transaction", enabled = true },
      { category = "Capacity", enabled = true }
    ]
  }
}

variable "enable_resource_lock" {
  description = "Enable resource lock for storage account"
  type        = bool
  default     = false
}

variable "lock_level" {
  description = "Resource lock level: CanNotDelete or ReadOnly"
  type        = string
  default     = "CanNotDelete"
  validation {
    condition     = contains(["CanNotDelete", "ReadOnly"], var.lock_level)
    error_message = "Lock level must be CanNotDelete or ReadOnly."
  }
}

variable "static_website" {
  description = "Static website configuration"
  type = object({
    index_document     = optional(string)
    error_404_document = optional(string)
  })
  default = null
}

variable "custom_domain" {
  description = "Custom domain configuration"
  type = object({
    name          = string
    use_subdomain = optional(bool, false)
  })
  default = null
}

variable "sas_policy" {
  description = "SAS policy configuration"
  type = object({
    https_only     = optional(bool, true)
    signed_version = optional(string, "2020-04-08")
    permissions = object({
      read    = optional(bool, false)
      write   = optional(bool, false)
      delete  = optional(bool, false)
      list    = optional(bool, false)
      add     = optional(bool, false)
      create  = optional(bool, false)
      update  = optional(bool, false)
      process = optional(bool, false)
      tag     = optional(bool, false)
      filter  = optional(bool, false)
    })
    services = object({
      blob  = optional(bool, false)
      queue = optional(bool, false)
      table = optional(bool, false)
      file  = optional(bool, false)
    })
    resource_types = object({
      service   = optional(bool, false)
      container = optional(bool, false)
      object    = optional(bool, false)
    })
    expiry = string
    start  = optional(string)
  })
  default = null
}

variable "create_resource_group" {
  description = "Create resource group if it doesn't exist"
  type        = bool
  default     = false
}

variable "resource_group_location" {
  description = "Location for resource group creation (if create_resource_group is true)"
  type        = string
  default     = null
}

variable "public_network_access_enabled" {
  description = "Enable public network access"
  type        = bool
  default     = true
}

variable "allow_shared_key_access" {
  description = "Allow shared key access"
  type        = bool
  default     = true
}

variable "queue_encryption_key_type" {
  description = "Queue encryption key type: Service or Account"
  type        = string
  default     = "Service"
  validation {
    condition     = contains(["Service", "Account"], var.queue_encryption_key_type)
    error_message = "Queue encryption key type must be Service or Account."
  }
}

variable "table_encryption_key_type" {
  description = "Table encryption key type: Service or Account"
  type        = string
  default     = "Service"
  validation {
    condition     = contains(["Service", "Account"], var.table_encryption_key_type)
    error_message = "Table encryption key type must be Service or Account."
  }
}
