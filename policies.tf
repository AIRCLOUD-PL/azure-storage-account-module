/**
 * Security configurations and policies for Storage Account
 */

# Azure Policy - Require HTTPS traffic only
resource "azurerm_resource_group_policy_assignment" "https_only" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "${azurerm_storage_account.main.name}-https-only"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
  display_name         = "Secure transfer to storage accounts should be enabled"
  description          = "Ensures HTTPS traffic only for storage account"

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Azure Policy - Require encryption at rest
resource "azurerm_resource_group_policy_assignment" "encryption_at_rest" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "${azurerm_storage_account.main.name}-encryption"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25"
  display_name         = "Storage accounts should use customer-managed key for encryption"
  description          = "Ensures customer-managed encryption keys are used"

  parameters = jsonencode({
    effect = {
      value = "AuditIfNotExists"
    }
  })
}

# Azure Policy - Disable public access
resource "azurerm_resource_group_policy_assignment" "public_access" {
  count = var.enable_policy_assignments ? 1 : 0

  name                 = "${azurerm_storage_account.main.name}-public-access"
  resource_group_id    = data.azurerm_resource_group.main.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751"
  display_name         = "Storage account public access should be disallowed"
  description          = "Ensures public access is disabled for storage accounts"

  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}

# Data source for resource group
data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# Variables for policies
variable "enable_policy_assignments" {
  description = "Enable Azure Policy assignments for this storage account"
  type        = bool
  default     = true
}