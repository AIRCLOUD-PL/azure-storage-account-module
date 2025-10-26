package test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestStorageAccountModuleBasic(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/basic",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-basic",
			"location":           "westeurope",
			"environment":        "test",
			"account_tier":       "Standard",
			"account_replication_type": "LRS",
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)

	terraform.RequirePlannedValuesMapKeyExists(t, planStruct, "azurerm_storage_account.main")
}

func TestStorageAccountModuleWithEncryption(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-encryption",
			"location":           "westeurope",
			"environment":        "test",
			"enable_https_traffic_only": true,
			"min_tls_version": "TLS1_2",
			"public_network_access_enabled": false,
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)

	resourceChanges := terraform.GetResourceChanges(t, planStruct)
	
	for _, change := range resourceChanges {
		if change.Type == "azurerm_storage_account" && change.Change.After != nil {
			afterMap := change.Change.After.(map[string]interface{})
			
			if httpsOnly, ok := afterMap["enable_https_traffic_only"]; ok {
				assert.True(t, httpsOnly.(bool), "HTTPS traffic only should be enabled")
			}
			
			if tlsVersion, ok := afterMap["min_tls_version"]; ok {
				assert.Equal(t, "TLS1_2", tlsVersion, "TLS version should be 1.2")
			}
		}
	}
}

func TestStorageAccountModuleWithContainers(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-containers",
			"location":           "westeurope",
			"environment":        "test",
			"containers": map[string]interface{}{
				"data": map[string]interface{}{
					"container_access_type": "private",
				},
				"logs": map[string]interface{}{
					"container_access_type": "private",
				},
			},
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)

	terraform.RequirePlannedValuesMapKeyExists(t, planStruct, "azurerm_storage_container.containers")
}

func TestStorageAccountModuleWithPrivateEndpoint(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-pe",
			"location":           "westeurope",
			"environment":        "test",
			"private_endpoints": map[string]interface{}{
				"blob": map[string]interface{}{
					"subnet_id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet",
				},
			},
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)

	terraform.RequirePlannedValuesMapKeyExists(t, planStruct, "azurerm_private_endpoint.blob")
}

func TestStorageAccountModuleNamingConvention(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/basic",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-naming",
			"location":           "westeurope",
			"environment":        "prod",
			"naming_prefix":      "stprod",
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)
	
	resourceChanges := terraform.GetResourceChanges(t, planStruct)
	
	for _, change := range resourceChanges {
		if change.Type == "azurerm_storage_account" && change.Change.After != nil {
			afterMap := change.Change.After.(map[string]interface{})
			if name, ok := afterMap["name"]; ok {
				storageName := name.(string)
				assert.Contains(t, storageName, "prod", "Storage name should contain environment")
			}
		}
	}
}

func TestStorageAccountModuleSecurity(t *testing.T) {
	t.Parallel()

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "../examples/complete",
		
		Vars: map[string]interface{}{
			"resource_group_name": "rg-test-storage-security",
			"location":           "westeurope",
			"environment":        "test",
			"enable_advanced_threat_protection": true,
			"shared_access_key_enabled":         false,
			"allow_nested_items_to_be_public":   false,
		},
		
		PlanOnly: true,
	})

	defer terraform.Destroy(t, terraformOptions)

	planStruct := terraform.InitAndPlan(t, terraformOptions)

	terraform.RequirePlannedValuesMapKeyExists(t, planStruct, "azurerm_storage_account_security_alert_policy.main")
	
	resourceChanges := terraform.GetResourceChanges(t, planStruct)
	
	for _, change := range resourceChanges {
		if change.Type == "azurerm_storage_account" && change.Change.After != nil {
			afterMap := change.Change.After.(map[string]interface{})
			
			if publicAccess, ok := afterMap["allow_nested_items_to_be_public"]; ok {
				assert.False(t, publicAccess.(bool), "Public access should be disabled")
			}
			
			if sharedKey, ok := afterMap["shared_access_key_enabled"]; ok {
				assert.False(t, sharedKey.(bool), "Shared access key should be disabled")
			}
		}
	}
}