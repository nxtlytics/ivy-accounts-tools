// create a sysenv in Azure!

// only allow deploy at subscription level
targetScope = 'subscription'

// This is the prefix for all tags - should match what you set in Thunder
// it's okay to leave this as the default.
@minLength(2)
@maxLength(5)
@description('SysEnv Tag Prefix')
param tagPrefix string = 'thunder'

@minLength(2)
@maxLength(5)
@description('SysEnv Name Prefix')
param prefix string

// get the location from the location of the deployment
param location string = deployment().location

@minLength(2)
@maxLength(10)
@description('SysEnv Purpose')
param purpose string

@allowed([
  'dev'
  'stage'
  'prod'
])
@description('SysEnv Phase')
param phase string

@allowed([
  'Standard_LRS'
  'Standard_GRS'
  'Standard_ZRS'
  'Premium_LRS'
])
@description('SysEnv Storage Account type')
param storageAccountType string = 'Standard_ZRS'

//@description('SysEnv Administrator AzureAD Groups')
//param administratorGroups array

// build the name of the sysenv
// (nameprefix)-az-(region)-(purpose)-(phase)
// nxt-az-eastus-app-prod
var sysenvName = '${prefix}-az-${location}-${purpose}-${phase}'

// build the name of the storage account
// TODO: bail if storageAccountName is longer than 24 characters??
var storageAccountName = '${prefix}${location}${purpose}${phase}'

// build the tags
var tags = {
	'${tagPrefix}:sysenv': sysenvName
	'${tagPrefix}:prefix': prefix
	'${tagPrefix}:purpose': purpose
	'${tagPrefix}:phase': phase
	'${tagPrefix}:group': 'main'
	'${tagPrefix}:team': 'Infrastructure'
	'${tagPrefix}:createdby': 'cloud-accounts-tools'
}

// make the resourcegroup
resource sysenvResourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: sysenvName
  location: location
  tags: tags
}

// include the storageAccount module
// we do this since bicep does not allow you to set scope on an individual resource
// without using a submodule
module storageAccount './storageAccount.bicep' = {
  name: 'infraStorageAccount'
  params: {
    location: location
  	sysenvName: sysenvName
	storageAccountName: storageAccountName
	storageAccountType: storageAccountType
	tags: tags
  }
  scope: sysenvResourceGroup
}

// add azureAD groups to the resource group
//resource adminRbac 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = [for group in administratorGroups: {
//  name: 'admin-${group}'
//  scope: sysenvResourceGroup.id
//  properties: {
//    roleDefinitionId: 'string'
//    principalId: 'string'
//    principalType: 'string'
//    description: 'string'
//    condition: 'string'
//    conditionVersion: 'string'
//    delegatedManagedIdentityResourceId: 'string'
//  }
//}]

// register some outputs
output sysenv string = sysenvName
output storageAccountName string = storageAccount.outputs.storageAccountName
output storageAccountContainer string = storageAccount.outputs.storageAccountContainer
output tags object = tags
