// storageAccount.bicep
// create the storage account and container for the sysenv

targetScope = 'resourceGroup'

// this file is necessary since we can't change scope within a bicep file
// without loading another as a module

param location string
param sysenvName string
param storageAccountName string
param storageAccountType string
param tags object

// make the infrastructure state bucket for pulumi/terraform/etc
// storage accounts cannot have special characters, so we must strip them
// the storage account cannot have special characters
resource sysenvStorageAccount 'Microsoft.Storage/storageAccounts@2019-06-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: storageAccountType
  }
  kind: 'StorageV2'
  properties: {}
  tags: tags
}

resource sysenvStorageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2019-06-01' = {
  name: '${sysenvStorageAccount.name}/default/${sysenvName}'
}

output storageAccountName string = sysenvStorageAccount.name
output storageAccountContainer string = sysenvStorageContainer.name