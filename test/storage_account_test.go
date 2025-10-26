package test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/azure"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
)

func TestAzureStorageAccountModule(t *testing.T) {
	t.Parallel()

	MultiTenantTestRunner(t, func(t *testing.T, config TestConfig) {
		SetupAzureAuth(t, config)
		CreateResourceGroup(t, config)
		
		uniqueID := config.UniqueID
		expectedStorageAccountName := fmt.Sprintf("teststorage%s", strings.ToLower(uniqueID))
		
		terraformDir := "../examples/basic"
		
		terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
			TerraformDir: terraformDir,
			Vars: map[string]interface{}{
				"storage_account_name":         expectedStorageAccountName,
				"location":                    config.Region,
				"resource_group_name":         fmt.Sprintf("%s-%s", config.ResourceGroup, uniqueID),
				"account_tier":                "Standard",
				"account_replication_type":    "LRS",
				"https_traffic_only_enabled":  true,
				"min_tls_version":             "TLS1_2",
				"enable_versioning":           true,
				"enable_change_feed":          true,
				"public_network_access_enabled": false,
				"containers": map[string]interface{}{
					"data": map[string]interface{}{
						"container_access_type": "private",
					},
					"logs": map[string]interface{}{
						"container_access_type": "private",
					},
				},
			},
			EnvVars: map[string]string{
				"ARM_SUBSCRIPTION_ID": config.SubscriptionID,
				"ARM_TENANT_ID":      config.TenantID,
			},
		})

		defer terraform.Destroy(t, terraformOptions)
		terraform.InitAndApply(t, terraformOptions)

		// Validate storage account
		storageAccountName := terraform.Output(t, terraformOptions, "storage_account_name")
		assert.Equal(t, expectedStorageAccountName, storageAccountName)

		// Validate HTTPS only
		storageAccount := azure.GetStorageAccount(t, fmt.Sprintf("%s-%s", config.ResourceGroup, uniqueID), storageAccountName, config.SubscriptionID)
		assert.True(t, *storageAccount.StorageAccountProperties.EnableHTTPSTrafficOnly)

		// Validate TLS version
		assert.Equal(t, "TLS1_2", string(storageAccount.StorageAccountProperties.MinimumTLSVersion))

		// Validate public access is disabled
		assert.False(t, *storageAccount.StorageAccountProperties.AllowBlobPublicAccess)

		// Security compliance validation
		ValidateSecurityCompliance(t, terraformOptions)
		
		// Validate encryption
		assert.NotNil(t, storageAccount.StorageAccountProperties.Encryption)
		assert.Equal(t, "Microsoft.Storage", string(storageAccount.StorageAccountProperties.Encryption.KeySource))
	})
}