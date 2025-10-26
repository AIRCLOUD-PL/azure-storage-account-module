/**
 * # Azure Storage Account Module
 *
 * Enterprise-grade Azure Storage Account module with security and compliance features.
 *
 * ## Features
 * - All storage account types (StorageV2, BlobStorage, FileStorage, BlockBlobStorage)
 * - Encryption at rest with customer-managed keys
 * - Private endpoints for secure access
 * - Network rules and firewall
 * - Blob containers with access policies
 * - File shares with SMB/NFS
 * - Tables and queues
 * - Advanced threat protection
 * - Soft delete and versioning
 * - Lifecycle management policies
 */

locals {
  # Generate storage account name (must be 3-24 chars, lowercase, numbers only)
  storage_name_base = var.name != null ? var.name : "${var.naming_prefix}${var.environment}${replace(var.location, "-", "")}st"
  storage_name      = lower(substr(replace(local.storage_name_base, "/[^a-z0-9]/", ""), 0, 24))

  # Default tags
  default_tags = {
    ManagedBy   = "Terraform"
    Module      = "azure-storage-account"
    Environment = var.environment
  }

  tags = merge(local.default_tags, var.tags)
}

# Resource Group (if not provided externally)
resource "azurerm_resource_group" "main" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.resource_group_location != null ? var.resource_group_location : var.location
  tags     = local.tags
}

# Storage Account
resource "azurerm_storage_account" "main" {
  name                              = local.storage_name
  location                          = var.location
  resource_group_name               = var.resource_group_name
  account_kind                      = var.account_kind
  account_tier                      = var.account_tier
  account_replication_type          = var.account_replication_type
  access_tier                       = var.access_tier
  https_traffic_only_enabled        = var.enable_https_traffic_only
  min_tls_version                   = var.min_tls_version
  allow_nested_items_to_be_public   = var.allow_nested_items_to_be_public
  shared_access_key_enabled         = var.allow_shared_key_access
  public_network_access_enabled     = var.public_network_access_enabled
  is_hns_enabled                    = var.is_hns_enabled
  nfsv3_enabled                     = var.nfsv3_enabled
  large_file_share_enabled          = var.large_file_share_enabled
  queue_encryption_key_type         = var.queue_encryption_key_type
  table_encryption_key_type         = var.table_encryption_key_type
  infrastructure_encryption_enabled = var.infrastructure_encryption_enabled
  sftp_enabled                      = var.sftp_enabled
  cross_tenant_replication_enabled  = var.cross_tenant_replication_enabled

  # Identity
  dynamic "identity" {
    for_each = var.identity_type != null ? [1] : []
    content {
      type         = var.identity_type
      identity_ids = var.identity_type == "UserAssigned" || var.identity_type == "SystemAssigned, UserAssigned" ? var.identity_ids : null
    }
  }

  # Blob properties
  dynamic "blob_properties" {
    for_each = var.blob_properties != null ? [var.blob_properties] : []
    content {
      versioning_enabled       = try(blob_properties.value.versioning_enabled, false)
      change_feed_enabled      = try(blob_properties.value.change_feed_enabled, false)
      last_access_time_enabled = try(blob_properties.value.last_access_time_enabled, false)

      dynamic "cors_rule" {
        for_each = try(blob_properties.value.cors_rules, [])
        content {
          allowed_headers    = cors_rule.value.allowed_headers
          allowed_methods    = cors_rule.value.allowed_methods
          allowed_origins    = cors_rule.value.allowed_origins
          exposed_headers    = cors_rule.value.exposed_headers
          max_age_in_seconds = cors_rule.value.max_age_in_seconds
        }
      }

      dynamic "delete_retention_policy" {
        for_each = try(blob_properties.value.delete_retention_policy, null) != null ? [blob_properties.value.delete_retention_policy] : []
        content {
          days = delete_retention_policy.value.days
        }
      }

      dynamic "container_delete_retention_policy" {
        for_each = try(blob_properties.value.container_delete_retention_policy, null) != null ? [blob_properties.value.container_delete_retention_policy] : []
        content {
          days = container_delete_retention_policy.value.days
        }
      }
    }
  }

  # Queue properties
  dynamic "queue_properties" {
    for_each = var.queue_properties != null ? [var.queue_properties] : []
    content {
      dynamic "cors_rule" {
        for_each = try(queue_properties.value.cors_rules, [])
        content {
          allowed_headers    = cors_rule.value.allowed_headers
          allowed_methods    = cors_rule.value.allowed_methods
          allowed_origins    = cors_rule.value.allowed_origins
          exposed_headers    = cors_rule.value.exposed_headers
          max_age_in_seconds = cors_rule.value.max_age_in_seconds
        }
      }

      dynamic "logging" {
        for_each = try(queue_properties.value.logging, null) != null ? [queue_properties.value.logging] : []
        content {
          delete                = logging.value.delete
          read                  = logging.value.read
          write                 = logging.value.write
          version               = logging.value.version
          retention_policy_days = try(logging.value.retention_policy_days, 7)
        }
      }
    }
  }

  # Network rules
  dynamic "network_rules" {
    for_each = var.network_rules != null ? [var.network_rules] : []
    content {
      default_action             = network_rules.value.default_action
      bypass                     = try(network_rules.value.bypass, ["AzureServices"])
      ip_rules                   = try(network_rules.value.ip_rules, [])
      virtual_network_subnet_ids = try(network_rules.value.virtual_network_subnet_ids, [])

      dynamic "private_link_access" {
        for_each = try(network_rules.value.private_link_access, [])
        content {
          endpoint_resource_id = private_link_access.value.endpoint_resource_id
          endpoint_tenant_id   = try(private_link_access.value.endpoint_tenant_id, null)
        }
      }
    }
  }

  # Customer-managed key
  dynamic "customer_managed_key" {
    for_each = var.customer_managed_key != null ? [var.customer_managed_key] : []
    content {
      key_vault_key_id          = customer_managed_key.value.key_vault_key_id
      user_assigned_identity_id = customer_managed_key.value.user_assigned_identity_id
    }
  }

  tags = local.tags

  depends_on = [
    azurerm_resource_group.main
  ]
}

# Advanced Threat Protection
resource "azurerm_advanced_threat_protection" "main" {
  count = var.enable_advanced_threat_protection ? 1 : 0

  target_resource_id = azurerm_storage_account.main.id
  enabled            = true
}

# Blob Containers
resource "azurerm_storage_container" "containers" {
  for_each = var.containers

  name                  = each.key
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = try(each.value.container_access_type, "private")
}

# File Shares
resource "azurerm_storage_share" "shares" {
  for_each = var.file_shares

  name                 = each.key
  storage_account_name = azurerm_storage_account.main.name
  quota                = each.value.quota
  enabled_protocol     = try(each.value.enabled_protocol, "SMB")

  dynamic "acl" {
    for_each = try(each.value.acls, [])
    content {
      id = acl.value.id

      dynamic "access_policy" {
        for_each = try(acl.value.access_policies, [])
        content {
          permissions = access_policy.value.permissions
          start       = try(access_policy.value.start, null)
          expiry      = try(access_policy.value.expiry, null)
        }
      }
    }
  }
}

# Queues
resource "azurerm_storage_queue" "queues" {
  for_each = var.queues

  name                 = each.key
  storage_account_name = azurerm_storage_account.main.name
}

# Tables
resource "azurerm_storage_table" "tables" {
  for_each = var.tables

  name                 = each.key
  storage_account_name = azurerm_storage_account.main.name
}

# Management Policy
resource "azurerm_storage_management_policy" "main" {
  count = var.management_policy != null ? 1 : 0

  storage_account_id = azurerm_storage_account.main.id

  dynamic "rule" {
    for_each = var.management_policy.rules
    content {
      name    = rule.value.name
      enabled = try(rule.value.enabled, true)

      filters {
        prefix_match = try(rule.value.filters.prefix_match, [])
        blob_types   = try(rule.value.filters.blob_types, ["blockBlob"])
      }

      actions {
        dynamic "base_blob" {
          for_each = try(rule.value.actions.base_blob, null) != null ? [rule.value.actions.base_blob] : []
          content {
            tier_to_cool_after_days_since_modification_greater_than    = try(base_blob.value.tier_to_cool_after_days, null)
            tier_to_archive_after_days_since_modification_greater_than = try(base_blob.value.tier_to_archive_after_days, null)
            delete_after_days_since_modification_greater_than          = try(base_blob.value.delete_after_days, null)
          }
        }

        dynamic "snapshot" {
          for_each = try(rule.value.actions.snapshot, null) != null ? [rule.value.actions.snapshot] : []
          content {
            delete_after_days_since_creation_greater_than = snapshot.value.delete_after_days
          }
        }
      }
    }
  }
}

# Private Endpoints
resource "azurerm_private_endpoint" "blob" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "blob") ? 1 : 0

  name                = "${azurerm_storage_account.main.name}-blob-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${azurerm_storage_account.main.name}-blob-pe-conn"
    private_connection_resource_id = azurerm_storage_account.main.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  tags = local.tags
}

resource "azurerm_private_endpoint" "file" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "file") ? 1 : 0

  name                = "${azurerm_storage_account.main.name}-file-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${azurerm_storage_account.main.name}-file-pe-conn"
    private_connection_resource_id = azurerm_storage_account.main.id
    is_manual_connection           = false
    subresource_names              = ["file"]
  }

  tags = local.tags
}

resource "azurerm_private_endpoint" "queue" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "queue") ? 1 : 0

  name                = "${azurerm_storage_account.main.name}-queue-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${azurerm_storage_account.main.name}-queue-pe-conn"
    private_connection_resource_id = azurerm_storage_account.main.id
    is_manual_connection           = false
    subresource_names              = ["queue"]
  }

  tags = local.tags
}

resource "azurerm_private_endpoint" "table" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "table") ? 1 : 0

  name                = "${azurerm_storage_account.main.name}-table-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${azurerm_storage_account.main.name}-table-pe-conn"
    private_connection_resource_id = azurerm_storage_account.main.id
    is_manual_connection           = false
    subresource_names              = ["table"]
  }

  tags = local.tags
}

# Private DNS Zones
resource "azurerm_private_dns_zone" "blob" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "blob") && var.create_private_dns_zone ? 1 : 0

  name                = "privatelink.blob.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "file" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "file") && var.create_private_dns_zone ? 1 : 0

  name                = "privatelink.file.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "queue" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "queue") && var.create_private_dns_zone ? 1 : 0

  name                = "privatelink.queue.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone" "table" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "table") && var.create_private_dns_zone ? 1 : 0

  name                = "privatelink.table.core.windows.net"
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "blob") && var.create_private_dns_zone ? 1 : 0

  name                  = "${azurerm_storage_account.main.name}-blob-dns-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.blob[0].name
  virtual_network_id    = var.private_dns_zone_virtual_network_id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "file" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "file") && var.create_private_dns_zone ? 1 : 0

  name                  = "${azurerm_storage_account.main.name}-file-dns-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.file[0].name
  virtual_network_id    = var.private_dns_zone_virtual_network_id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "queue" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "queue") && var.create_private_dns_zone ? 1 : 0

  name                  = "${azurerm_storage_account.main.name}-queue-dns-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.queue[0].name
  virtual_network_id    = var.private_dns_zone_virtual_network_id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "table" {
  count = var.enable_private_endpoint && contains(var.private_endpoint_subresources, "table") && var.create_private_dns_zone ? 1 : 0

  name                  = "${azurerm_storage_account.main.name}-table-dns-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.table[0].name
  virtual_network_id    = var.private_dns_zone_virtual_network_id
  registration_enabled  = false
  tags                  = local.tags
}

# Diagnostic Settings
resource "azurerm_monitor_diagnostic_setting" "main" {
  count = var.enable_diagnostic_settings ? 1 : 0

  name                       = "${azurerm_storage_account.main.name}-diagnostics"
  target_resource_id         = azurerm_storage_account.main.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  dynamic "enabled_log" {
    for_each = var.diagnostic_settings.logs
    content {
      category = enabled_log.value.category
    }
  }

  dynamic "metric" {
    for_each = var.diagnostic_settings.metrics
    content {
      category = metric.value.category
      enabled  = metric.value.enabled
    }
  }
}

# Resource Lock
resource "azurerm_management_lock" "main" {
  count = var.enable_resource_lock ? 1 : 0

  name       = "${azurerm_storage_account.main.name}-lock"
  scope      = azurerm_storage_account.main.id
  lock_level = var.lock_level
  notes      = "Resource lock for Storage Account"
}

# Static Website
resource "azurerm_storage_account_static_website" "main" {
  count = var.static_website != null ? 1 : 0

  storage_account_id = azurerm_storage_account.main.id
  index_document     = try(var.static_website.index_document, null)
  error_404_document = try(var.static_website.error_404_document, null)
}

# Custom Domain

# SAS Policy
