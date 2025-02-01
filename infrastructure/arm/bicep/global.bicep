// ------------------------------------------------------------
// Parameters - Core
// ------------------------------------------------------------

@description('The location targeted.')
param location string = resourceGroup().location

@minLength(3)
@description('The prefix name (for instance aio).')
param prefix string

@minLength(3)
@description('The unique identifier.')
param uid string

@minLength(3)
@description('The environment name (for instance dev or rel).')
param environment string

@minLength(3)
@description('The layer name.')
param layer string = 'corp'

// ------------------------------------------------------------
// Parameters - Networking
// ------------------------------------------------------------

@description('The virtual network settings.')
#disable-next-line no-unused-params
param vnetSettings object

@description('The networking self host agent settings.')
#disable-next-line no-unused-params
param agentSettings object

@description('The networking bastion settings.')
#disable-next-line no-unused-params
param bastionSettings object

@description('The networking cloud settings.')
#disable-next-line no-unused-params
param cloudSettings object

@description('The networking corp settings.')
param corpSettings object

@description('The networking sites settings.')
#disable-next-line no-unused-params
param sitesSettings array

// ------------------------------------------------------------
// Parameters - Virtual Machine (Cluster)
// ------------------------------------------------------------

@description('Specifies admin username.')
param vmAdminUserName string

@description('Specifies admin public key.')
param vmAdminPublicKey string

@description('Specifies image reference.')
param vmImageReference object

@description('Specifies the size.')
param vmSize string

@description('Specifies managed identity resource ID.')
param vmManagedIdentityId string

@allowed([
  'Enabled'
  'Disabled'
])
@description('Specifies the status of the auto shutdown.')
param vmAutoShutdownStatus string

@description('Specifies the time (24h HHmm format) of the auto shutdown.')
@minLength(4)
@maxLength(4)
param vmAutoShutdownTime string

@description('Specifies the time zone of the auto shutdown.')
param vmAutoShutdownTimeZoneId string

@description('Specifies the base64 encoded script to run on the Virtual Machine.')
param vmScript string

// ------------------------------------------------------------
// Parameters - Virtual Machine (Proxy)
// ------------------------------------------------------------

@description('Specifies admin username.')
param proxyAdminUserName string

@description('Specifies admin public key.')
param proxyAdminPublicKey string

@description('Specifies image reference.')
param proxyImageReference object

@description('Specifies the size.')
param proxySize string

@allowed([
  'Enabled'
  'Disabled'
])
@description('Specifies the status of the auto shutdown.')
param proxyAutoShutdownStatus string

@description('Specifies the time (24h HHmm format) of the auto shutdown.')
@minLength(4)
@maxLength(4)
param proxyAutoShutdownTime string

@description('Specifies the time zone of the auto shutdown.')
param proxyAutoShutdownTimeZoneId string

@description('Specifies the base64 encoded script to run on the Virtual Machine.')
param proxyScript string

@description('Specifies whether to install the proxy.')
param installProxy bool

@description('The name of the Azure Key Vault.')
param keyVaultName string

// ------------------------------------------------------------
// Variables
// ------------------------------------------------------------

var resourceSuffix = '${prefix}${uid}${environment}${layer}'
var resourceTags = {
  prefix: prefix
  uid: uid
  environment: environment
  layer: layer
}

var vnetName = 'vnet${prefix}${uid}${environment}cloud'
var cloudResourceGroupName = 'rg${prefix}${uid}${environment}cloud'

// ------------------------------------------------------------
// Resource - Virtual Machine (Proxy)
// ------------------------------------------------------------

var proxyName = 'proxy${resourceSuffix}'

// create proxy virtual machine
module proxyVirtualMachine './modules/proxyVirtualMachine.bicep'= {
  name: 'proxy-deployment'
  params: {
    location: location
    name: proxyName
    size: proxySize
    imageReference: proxyImageReference
    adminUserName: proxyAdminUserName
    adminPublicKey: proxyAdminPublicKey
    frontSubnetId: resourceId(cloudResourceGroupName, 'Microsoft.Network/virtualNetworks/subnets', vnetName, cloudSettings.subnet.name)
    backSubnetId: resourceId(cloudResourceGroupName, 'Microsoft.Network/virtualNetworks/subnets', vnetName, corpSettings.subnet.name)
    frontIpAddress: corpSettings.proxy.frontIpAddress
    backIpAddress: corpSettings.proxy.backIpAddress
    script: proxyScript
    resourceTags: resourceTags
  }
}
