// ------------------------------------------------------------
// Parameters - Core
// ------------------------------------------------------------

@description('The location targeted.')
param location string = resourceGroup().location

@minLength(10)
@description('The suffix name .')
param suffix string

@description('Client IP address.')
param ipAddress string
// ------------------------------------------------------------
// Parameters - Virtual Machine (Cluster)
// ------------------------------------------------------------

@description('Specifies admin username.')
param vmAdminUserName string

@description('Specifies admin public key.')
param vmAdminPublicKey string

@description('Specifies the size.')
param vmSize string

@description('Specifies the base64 encoded script to run on the Virtual Machine.')
param vmScript string

@description('Specifies the TCP port associated with the proxy.')
param vmProxyPort string
// ------------------------------------------------------------
// Variables 
// ------------------------------------------------------------

var vnetName = 'vnet${suffix}'
var resourceGroupName = 'rg${suffix}'

var resourceTags = {
  suffix: suffix
}

var vnetAddressPrefix = '10.0.0.0/8'
var snetProxyAddressPrefix = '10.0.0.0/24'
var snetProxyName = 'snet${suffix}proxy'
var nsgProxyName = 'nsg${suffix}proxy'
var nicProxyName = 'nic${suffix}proxy'
var pipProxyAddressName = 'pip${suffix}proxy'

resource nsgProxy 'Microsoft.Network/networkSecurityGroups@2020-05-01' = {
  name: nsgProxyName
  location: location
  properties: {
    securityRules: [
      {
        name: 'ssh_rule'
        properties: {
          description: 'Locks inbound down to ssh default port 22.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: ipAddress
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'proxy_rule'
        properties: {
          description: 'Locks inbound down to proxy port.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: vmProxyPort
          sourceAddressPrefix: ipAddress
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2021-08-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: snetProxyName
        properties: {
          addressPrefix: snetProxyAddressPrefix
          networkSecurityGroup: {
            id: nsgProxy.id
          }
        }
      }
    ]
  }
}

resource pipProxyAddress 'Microsoft.Network/publicIPAddresses@2020-05-01' = {
  name: pipProxyAddressName
  location: location
  properties: {
    dnsSettings: {
      domainNameLabel: pipProxyAddressName
    }
    publicIPAllocationMethod: 'Dynamic'
  }
  sku: {
    name: 'Basic'
  }
}

resource networkInterfaceProxy 'Microsoft.Network/networkInterfaces@2020-05-01' = {
  name: nicProxyName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfigProxy'
        properties: {
          publicIPAddress: {
            id: pipProxyAddress.id
          }
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, snetProxyName)
          }
        }
      }
    ]
  }
  dependsOn: [
    vnet
    nsgProxy
  ]
}

// ------------------------------------------------------------
// Resource - Virtual Machine (Proxy)
// ------------------------------------------------------------

var proxyName = 'proxy${suffix}'
var proxyImageReference = {
    publisher: 'Canonical'
    offer: '0001-com-ubuntu-server-jammy'
    sku: '22_04-lts-gen2'
    version: 'latest'
  }


// create proxy virtual machine
module proxyVirtualMachine './modules/proxyVirtualMachine.bicep'= {
  name: 'proxy-deployment'
  params: {
    location: location
    name: proxyName
    size: vmSize
    imageReference: proxyImageReference
    adminUserName: vmAdminUserName
    adminPublicKey: vmAdminPublicKey
    nicId: resourceId(resourceGroupName, 'Microsoft.Network/networkInterfaces', nicProxyName)
    script: vmScript
    resourceTags: resourceTags
  }
  dependsOn: [
    vnet
    nsgProxy
    networkInterfaceProxy
    pipProxyAddress
  ]  
}

// ------------------------------------------------------------
// Resources - Storage
// ------------------------------------------------------------
var storageName = 'sa${suffix}'
var storageContainerName = 'proxylogs'

// create storage account
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: resourceTags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    isHnsEnabled: true
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
    }
  }
  dependsOn: [
    vnet
  ]
}

// create storage container (schemas)
resource storageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: '${storageName}/default/${storageContainerName}'
  properties: {
    publicAccess: 'None'
    defaultEncryptionScope: '$account-encryption-key'
    denyEncryptionScopeOverride: false
  }
  dependsOn: [
    storageAccount
  ]
}

output AZURE_RESOURCE_PROXY_DNS_NAME string = pipProxyAddress.properties.dnsSettings.fqdn
output AZURE_RESOURCE_PROXY_PORT string = vmProxyPort
