// ------------------------------------------------------------
// Parameters - Core
// ------------------------------------------------------------

@description('The location targeted.')
param location string = resourceGroup().location

@description('The resource tags.')
param resourceTags object

// ------------------------------------------------------------
// Parameters - Virtual Machine
// ------------------------------------------------------------

@description('Specifies the name of the Virtual Machine.')
param name string

@description('Specifies the size of the Virtual Machine.')
param size string

@description('Specifies an image reference for the Virtual Machine.')
param imageReference object

@description('Specifies a username for the Virtual Machine.')
param adminUserName string

@description('Specifies the SSH public key.')
param adminPublicKey string

@allowed([
  'Enabled'
  'Disabled'
])


@description('Specifies the base64 encoded script to run on the Virtual Machine.')
param script string

// ------------------------------------------------------------
// Parameters - Networking
// ------------------------------------------------------------

@description('Specifies the id of the front subnet.')
param frontSubnetId string

@description('Specifies the id of the back subnet.')
param backSubnetId string

@description('Specifies the ip address of front nic.')
param frontIpAddress string

@description('Specifies the ip address of back nic.')
param backIpAddress string

// ------------------------------------------------------------
// Virtual Machine
// ------------------------------------------------------------

// create network interface
resource frontNetworkInterface 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${name}-front-nic'
  location: location
  tags: resourceTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfigfront'
        properties: {
          subnet: {
            id: frontSubnetId
          }
          privateIPAddress: frontIpAddress
          privateIPAllocationMethod: 'Static'
        }
      }
    ]
  }
}

resource backNetworkInterface 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${name}-back-nic'
  location: location
  tags: resourceTags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfigback'
        properties: {
          subnet: {
            id: backSubnetId
          }
          privateIPAddress: backIpAddress
          privateIPAllocationMethod: 'Static'
        }
      }
    ]
  }
}

// create virtual machine
resource proxyVirtualMachine 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: name
  location: location
  tags: resourceTags
  properties: {
    hardwareProfile: {
      vmSize: size
    }
    osProfile: {
      computerName: name
      adminUsername: adminUserName
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUserName}/.ssh/authorized_keys'
              keyData: adminPublicKey
            }
          ]
        }
        provisionVMAgent: true
        patchSettings: {
          assessmentMode: 'AutomaticByPlatform'
        }
      }
    }
    securityProfile: {
      encryptionAtHost: true
    }
    storageProfile: {
      imageReference: imageReference
      osDisk: {
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: frontNetworkInterface.id
          properties: {
            primary: true
          }            
        }
        {
          id: backNetworkInterface.id
          properties: {
            primary: false
          }            
        }        
      ]
    }
    //checkov:skip=CKV_AZURE_50:Virtual Machine extensions are installed
  }
}

// create custom script extension
// https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-linux#troubleshooting
resource customScriptExtension 'Microsoft.Compute/virtualMachines/extensions@2022-03-01' =  {
  parent: proxyVirtualMachine
  name: 'installCustomScript'
  location: location
  tags: resourceTags
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    settings: {
      skipDos2Unix: false
    }    
    protectedSettings: {
      script: script
    } 
  }
}

// ------------------------------------------------------------
// Outputs
// ------------------------------------------------------------

output id string = proxyVirtualMachine.id
