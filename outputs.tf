output "id" {
  description = "Storage account ID"
  value       = azurerm_storage_account.main.id
}

output "name" {
  description = "Storage account name"
  value       = azurerm_storage_account.main.name
}

output "primary_blob_endpoint" {
  description = "Primary blob endpoint"
  value       = azurerm_storage_account.main.primary_blob_endpoint
}

output "primary_file_endpoint" {
  description = "Primary file endpoint"
  value       = azurerm_storage_account.main.primary_file_endpoint
}

output "primary_queue_endpoint" {
  description = "Primary queue endpoint"
  value       = azurerm_storage_account.main.primary_queue_endpoint
}

output "primary_table_endpoint" {
  description = "Primary table endpoint"
  value       = azurerm_storage_account.main.primary_table_endpoint
}

output "primary_access_key" {
  description = "Primary access key"
  value       = azurerm_storage_account.main.primary_access_key
  sensitive   = true
}

output "secondary_access_key" {
  description = "Secondary access key"
  value       = azurerm_storage_account.main.secondary_access_key
  sensitive   = true
}

output "primary_connection_string" {
  description = "Primary connection string"
  value       = azurerm_storage_account.main.primary_connection_string
  sensitive   = true
}

output "identity" {
  description = "Managed identity block"
  value       = try(azurerm_storage_account.main.identity[0], null)
}

output "identity_principal_id" {
  description = "Principal ID of managed identity"
  value       = try(azurerm_storage_account.main.identity[0].principal_id, null)
}

output "container_ids" {
  description = "IDs of created containers"
  value       = { for k, v in azurerm_storage_container.containers : k => v.id }
}

output "file_share_ids" {
  description = "IDs of created file shares"
  value       = { for k, v in azurerm_storage_share.shares : k => v.id }
}
