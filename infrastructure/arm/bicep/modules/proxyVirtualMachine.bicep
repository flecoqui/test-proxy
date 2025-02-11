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

@description('Specifies the base64 encoded script to run on the Virtual Machine.')
param script string

// ------------------------------------------------------------
// Parameters - Networking
// ------------------------------------------------------------

@description('Specifies the id of the nic card.')
param nicId string

// ------------------------------------------------------------
// Virtual Machine
// ------------------------------------------------------------

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
    storageProfile: {
      imageReference: imageReference
      osDisk: {
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nicId
          properties: {
            primary: true
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
output name string = proxyVirtualMachine.name
