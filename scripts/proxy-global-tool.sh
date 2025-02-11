#!/bin/sh
##########################################################################################################################################################################################
#- Purpose: Script used to install pre-requisites, deploy/undeploy service, start/stop service, test service
#- Parameters are:
#- [-a] ACTION - value: login, install, getsuffix, createconfig, deploy, test, undeploy,  
#- [-c] configuration file - which contains the configuration (configuration/default.env by default)
#- [-e] environment - "dev", "tst", "prd", "int", "val"
#
# if [ -z "$BASH_VERSION" ]
# then
#    echo Force bash
#    exec bash "$0" "$@"
# fi
# executable
###########################################################################################################################################################################################
# set -u
# echo  "$0" "$@"
BASH_SCRIPT=$(readlink -f "$0")
SCRIPTS_DIRECTORY=$(dirname "$BASH_SCRIPT")
#cd "$SCRIPTS_DIRECTORY"
    

##############################################################################
# colors for formatting the output
##############################################################################
# shellcheck disable=SC2034
{
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[0;31m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color
}
##############################################################################
#- function used to check whether an error occurred
##############################################################################
checkError() {
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        echo "${RED}"
        echo "An error occurred exiting from the current bash${NC}"
        exit 1
    fi
}


#--------------------------------------------------------------
# LOG FUNCTIONS
#--------------------------------------------------------------
LOG_DIR="/var/log/installproxy"
LOG_FILE="/var/log/installproxy/installproxy.log"

BACKUP_LOG_FILE="/var/log/installproxy/installproxy_"
MAXSIZE=1048576  # 1MB in bytes
logFile(){
  if [ ! -d "${LOG_DIR}" ]; then
    sudo mkdir -p "${LOG_DIR}" >/dev/null || true 
  fi
  CURRENT_DATE=$(date +"%y/%m/%d-%H:%M:%S")
  echo "${CURRENT_DATE}: $1" | sudo tee -a "${LOG_FILE}" > /dev/null
  # Check the size of the log file
  FILESIZE=$(sudo stat -c%s "$LOG_FILE")
  # Backup the log file if it exceeds the maximum size
  if [ "$FILESIZE" -ge "$MAXSIZE" ]; then
    TIMESTAMP=$(date +"%Y%m%d%H%M%S")
    sudo cp "$LOG_FILE" "${BACKUP_LOG_FILE}${TIMESTAMP}.log"
    sudo rm "$LOG_FILE"
    sudo touch "$LOG_FILE"  # Truncate the log file
  fi
}
###########################################################
#- function used to logInfo information in the virtual machine
###########################################################
logInfo()
{
    TS=$(date +"%Y/%m/%d-%H:%M:%S.%3N")
    MSG="${TS} $1"  
	echo "${MSG}"
    logFile "${MSG}"
}
###########################################################
#- function used to log information in stderr
###########################################################
logError() 
{ 
  printf "%s\n" "$*" >&2; 
  TS=$(date +"%Y/%m/%d-%H:%M:%S.%3N")
  MSG="${TS} ERROR: $*"  
  logFile "${MSG}"  
}
##############################################################################
#- function used to run command 
##############################################################################
runCommand() {
    cmd="${1}"
    stopOnError="false"
    if [ -z "${2}" ]; then
        stopOnError="false"
    else
        stopOnError="${2}"
    fi
    errorfile=$(mktemp)
    logInfo "${cmd}" 
    eval "${cmd}" 2> "${errorfile}"
    # shellcheck disable=SC2181
    errorcode=$?
    if [ "${errorcode}" -ne 0 ]; then
        echo "${RED}"
        logError "An error occurred while running command: \"${1}\" Error code: '${errorcode}' Message: \"$(tail -n 1 "${errorfile}")\""
        rm "${errorfile}"
        if [ "${stopOnError}" = "true" ]; then
            logError "Exiting from the current script"
            exit 1
        fi
    fi
    rm "${errorfile}"
}
##############################################################################
#- function cleanLock before installing Ubuntu packages
##############################################################################
cleanLock(){
    cmd="sudo killall apt apt-get dpkg"
    runCommand "${cmd}"
    cmd="sudo lsof /var/lib/dpkg/lock-frontend"
    runCommand "${cmd}"
    cmd="sudo rm /var/lib/dpkg/lock-frontend"
    runCommand "${cmd}"
    cmd="sudo lsof /var/lib/dpkg/lock"
    runCommand "${cmd}"
    cmd="sudo rm /var/lib/dpkg/lock"
    runCommand "${cmd}"    
}

##############################################################################
#- print functions
##############################################################################
printMessage(){
    echo "${GREEN}$1${NC}" 
}
printWarning(){
    echo "${YELLOW}$1${NC}" 
}
printError(){
    echo "${RED}$1${NC}" 
}
printProgress(){
    echo "${BLUE}$1${NC}" 
}

##############################################################################
#- azure Login 
##############################################################################
azLogin() {
    # Check if current process's user is logged on Azure
    # If no, then triggers az login
    if [ -z "$AZURE_SUBSCRIPTION_ID" ]; then
        printError "Variable AZURE_SUBSCRIPTION_ID not set"
        az login
        # get Azure Subscription and Tenant Id if already connected
        AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
        AZURE_TENANT_ID=$(az account show --query tenantId -o tsv 2> /dev/null) || true        
    fi
    if [ -z "$AZURE_TENANT_ID" ]; then
        printError "Variable AZURE_TENANT_ID not set"
        az login
        # get Azure Subscription and Tenant Id if already connected
        AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
        AZURE_TENANT_ID=$(az account show --query tenantId -o tsv 2> /dev/null) || true        
    fi
    azOk=true
    az account set -s "$AZURE_SUBSCRIPTION_ID" 2>/dev/null || azOk=false
    if [ ${azOk} = false ]; then
        printWarning "Need to az login"
        az login --tenant "$AZURE_TENANT_ID"
    fi

    azOk=true
    az account set -s "$AZURE_SUBSCRIPTION_ID"   || azOk=false
    if [ ${azOk} = false ]; then
        echo "unknown error"
        exit 1
    fi
}
##############################################################################
#- checkLoginAndSubscription 
##############################################################################
checkLoginAndSubscription() {
    az account show -o none
    # shellcheck disable=SC2181
    if [ $? -ne 0 ]; then
        printf "\nYou seems disconnected from Azure, running 'az login'."
        az login -o none
    fi
    CURRENT_SUBSCRIPTION_ID=$(az account show --query 'id' --output tsv)
    if [ -z "$AZURE_SUBSCRIPTION_ID" ] || [ "$AZURE_SUBSCRIPTION_ID" != "$CURRENT_SUBSCRIPTION_ID" ]; then
        # query subscriptions
        printf  "\nYou have access to the following subscriptions:"
        az account list --query '[].{name:name,"subscription Id":id}' --output table

        printf "\nYour current subscription is:"
        az account show --query '[name,id]'
        # shellcheck disable=SC2154
        if [ "${silentmode}"  =  false ] || [ -z "$CURRENT_SUBSCRIPTION_ID" ]; then        
            echo  "
            You will need to use a subscription with permissions for creating service principals (owner role provides this).
            If you want to change to a different subscription, enter the name or id.
            Or just press enter to continue with the current subscription."
            read -r  ">> " SUBSCRIPTION_ID

            if ! test -z "$SUBSCRIPTION_ID"
            then 
                az account set -s "$SUBSCRIPTION_ID"
                printf  "\nNow using:"
                az account show --query '[name,id]'
                CURRENT_SUBSCRIPTION_ID=$(az account show --query 'id' --output tsv)
            fi
        fi
    fi
}


##############################################################################
#- getResourceGroupName
##############################################################################
getResourceGroupName(){
    suffix=$1
    echo "rg${suffix}"
}
##############################################################################
#- getStorageAccountResourceName
##############################################################################
getStorageAccountResourceName(){
    suffix=$1
    echo "sa${suffix}"
}
##############################################################################
#- getProxyVMName
##############################################################################
getProxyVMName(){
    suffix=$1
    echo "proxy${suffix}"
}
##############################################################################
#- isStorageAccountNameAvailable
##############################################################################
isStorageAccountNameAvailable(){
    rg=$1
    name=$2
    # check if already exists in resource group
    # shellcheck disable=SC2046
    COUNT=$(az storage account list --resource-group "${rg}" --query "[?name=='${name}'] | length(@)"  2>/dev/null )
    if [ -z "${COUNT}" ] || [ "${COUNT}" = 0 ]
    then
        echo "true"
    else
        # check if already exists outside of resource group
        if [ "$(az storage account check-name --name "${name}" | jq -r '.nameAvailable'  2>/dev/null)" =  "false" ]
        then
            echo "false"
        else
            echo "true"
        fi
    fi    
}
##############################################################################
#- getNewSuffix
##############################################################################
getNewSuffix(){
    prefix=$1
    environment=$2
    subscription=$3
    checkname="false"
    while [ ${checkname}  =  "false" ]
    do
        suffix="${prefix}${environment}$(shuf -i 1000-9999 -n 1)"
        RESOURCE_GROUP=$(getResourceGroupName "${suffix}")
        AZURE_RESOURCE_STORAGE_ACCOUNT_NAME=$(getStorageAccountResourceName "${suffix}")
        checkname="false"
        if [ "$(isStorageAccountNameAvailable "${RESOURCE_GROUP}" "${AZURE_RESOURCE_STORAGE_ACCOUNT_NAME}" )"  =  "false" ]
        then
            continue
        fi
        echo "${suffix}"
        checkname="true"
    done
}
##############################################################################
#- deployAzureInfrastructure
##############################################################################
deployAzureInfrastructure(){
    subscription=$1
    region=$2
    suffix=$3
    resourcegroup=$4
    sku=$5
    ip=$6
    template=$7

    datadep=$(date +"%y%m%d-%H%M%S")
    
    cmd="az group create  --subscription $subscription --location $region --name $resourcegroup --output none "
    printProgress "$cmd"
    runCommand "$cmd" "true"

    cmd="az deployment group create \
        --name $datadep \
        --resource-group $resourcegroup \
        --subscription $subscription \
        --template-file $template \
        --output none \
        --parameters \
        suffix=$suffix  sku=$sku ipAddress=\"$ip\""

    printProgress "$cmd"
    runCommand "$cmd" "true"
    
    # Initialize the environment variables from the infrastructure deployment
    getDeploymentVariables "${resourcegroup}" "${datadep}"
}
##############################################################################
#- getDeploymentVariables
##############################################################################
getDeploymentVariables(){
    resourcegroup="$1"

    response=$(az group exists --resource-group "$resourcegroup")
    if [ "$response" = "true" ]; then
        if [ ! $# -ge 2 ]; then
            datadep=$(getDeploymentName "$AZURE_SUBSCRIPTION_ID" "$resourcegroup" 'storageAccountName')
        else
            if [ -z "$2" ]; then
                datadep=$(getDeploymentName "$AZURE_SUBSCRIPTION_ID" "$resourcegroup" 'storageAccountName')
            else
                datadep="$2"
            fi
        fi
        printProgress "Getting variables from deployment Name: ${datadep} from resource group ${resourcegroup}"
        for i in $(az deployment group show --resource-group "$resourcegroup" -n "$datadep" | jq  '.properties.outputs' | jq -r 'keys' | jq -r '.[]'); 
        do 
            start="azurE_RESOURCE_"
            case ${i} in
              ($start*) VARIABLE=$(echo "${i}" | tr '[:lower:]' '[:upper:]')
                cmd="az deployment group show --resource-group \"${resourcegroup}\" -n \"${datadep}\" | jq -r '.properties.outputs.\"${i}\".value'"
                VALUE=$(eval "${cmd}")
                # printProgress "${VARIABLE}=${VALUE}"
                export "${VARIABLE}"="${VALUE}" ;;
              (*)  ;;
            esac

            # if [[ "${i^^}" == AZURE_RESOURCE_* ]]; 
            # then 
            #     VARIABLE=$(echo "${i}" | tr a-z A-Z)
            #     cmd="az deployment group show --resource-group \"${resourcegroup}\" -n \"${datadep}\" | jq -r '.properties.outputs.\"${i}\".value'"
            #     VALUE=$(eval "${cmd}")
            #     printProgress "${VARIABLE}=${VALUE}"
            #     export ${VARIABLE}=${VALUE}
            # fi;
        done;
    fi
}


##############################################################################
#- undeployAzureInfrastructure
##############################################################################
undeployAzureInfrastructure(){
    subscription=$1
    resourcegroup=$2

    cmd="az group delete  --subscription $subscription  --name $resourcegroup -y --output none "
    printProgress "$cmd"
    runCommand "$cmd"
}
##############################################################################
#- getDeploymentName: get latest deployment Name for resource group
#  arg 1: Azure Subscription
#  arg 2: Resource Group
#  arg 3: Output variable to support
##############################################################################
getDeploymentName(){
    subscription="$1"
    resource_group="$2"
    output_variable="$3"
    cmd="az deployment group list -g  ${resource_group} --subscription ${subscription} --output json"
    #echo "$cmd"
    result=$(runCommand "$cmd")
    cmd="echo '$result' | jq -r 'length'"
    count=$(runCommand "$cmd")
    if [ -n "$count" ] ; then
        #echo "COUNT: $count"
        # shellcheck disable=SC2004
        for index in $(seq 0 $((${count} - 1)) )
        # for ((index=0;index<=(${count}-1);index++ ))
        do
            cmd="echo '$result' | jq -r '.[${index}].name'"
            name=$(runCommand "$cmd")
            #echo "name: $name"
            cmd="az deployment group show --resource-group ${resource_group} -n ${name} --subscription ${subscription} | jq -r '.properties.outputs.${output_variable}.value'"
            value=$(runCommand "$cmd")
            #echo "value: $value"
            if [ -n "$value" ]; then
                if [ "$value" != "null" ]; then
                    echo "${name}"
                    return
                fi
            fi
        done
    fi               
}

##############################################################################
#- removevarinfile
##############################################################################
removevarinfile() {
    FILE=$1
    VARIABLE=$2
    # Removing variable with single line "double quote" value"
    RESULT=$(grep "${VARIABLE}=\"[^\"]*\"" "${FILE}") 2>/dev/null || true
    if [ -n "${RESULT}" ]
    then
        #logInfo "${VARIABLE} Found in  ${FILE}, Removing now...";
        sudo sed -i  "/${VARIABLE}=/d" "${FILE}"
        return
    fi
    # Removing multi-lines variable between ""
    RESULT=$(grep "${VARIABLE}=\"" "${FILE}") 2>/dev/null || true
    if [ -n "${RESULT}" ]
    then
        #logInfo "${VARIABLE} Found in  ${FILE}, Removing now...";
        sudo sed -i "/^${VARIABLE}=\"/,/\"$/{
        /^${VARIABLE}=\"/d
        /\"$/d
        d
        }" "${FILE}"       
    fi
    # Removing single variable
    RESULT=$(grep "${VARIABLE}=" "${FILE}") 2>/dev/null || true
    if [ -n "${RESULT}" ]
    then
        #logInfo "${VARIABLE} Found in  ${FILE}, Removing now...";
        sudo sudo sed -i  "/${VARIABLE}=/d" "${FILE}"
    fi
}
ETC_ENVIRONMENT=/etc/environment
##############################################################################
#- removevar
##############################################################################
removevar() {
    VARIABLE=$1
    removevarinfile "${ETC_ENVIRONMENT}" "${VARIABLE}"
}
##############################################################################
#- addvarinfile
##############################################################################
addvarinfile() {
    FILE=$1
    VARIABLE=$2    
    VALUE=$3
    RESULT=$(grep "${VARIABLE}=" "${FILE}") 2>/dev/null || true
    if [ -z "${RESULT}" ]; then
        echo "${VARIABLE}=${VALUE}" | sudo tee -a "${FILE}" > /dev/null
        RESULT=$(grep "${VARIABLE}=" "${FILE}")
        if [ -z "${RESULT}" ]; then
            logError "Failed to Add ${VARIABLE}, Try again!";
        fi
    else
        logError "${VARIABLE} already exists : ${RESULT}"
    fi
}
##############################################################################
#- addvar
##############################################################################
addvar() {
    VARIABLE=$1
    VALUE=$2
    addvarinfile "${ETC_ENVIRONMENT}" "${VARIABLE}" "${VALUE}"
}
##############################################################################
#- updateConfigurationFile: Update configuration file
#  arg 1: Configuration file path
#  arg 2: Variable Name
#  arg 3: Value
##############################################################################
# updateConfigurationFile(){
#     configFile="$1"
#     variable="$2"
#     value="$3"

#     count=$(grep "${variable}=.*" -c < "$configFile") || true
#     if [ "${count}" != 0 ]; then
#         ESCAPED_REPLACE=$(printf '%s\n' "${value}" | sed -e 's/[\/&]/\\&/g')
#         sed -i "s/${variable}=.*/${variable}=${ESCAPED_REPLACE}/g" "${configFile}"  2>/dev/null       
#     elif [ "${count}" = 0 ]; then
#         # shellcheck disable=SC2046
#         if [ $(tail -c1 "${configFile}" | wc -l) -eq 0 ]; then
#             echo "" >> "${configFile}"
#         fi
#         echo "${variable}=${value}" >> "${configFile}"
#     fi
#     printProgress "${variable}=${value}"
# }
updateConfigurationFile(){
    configFile="$1"
    variable="$2"
    value="$3"
    
    removevarinfile "${configFile}" "${variable}"
    addvarinfile "${configFile}" "${variable}" "${value}"
    printProgress "${variable}=${value}"
}
##############################################################################
#- readConfigurationFile: Update configuration file
#  arg 1: Configuration file path
##############################################################################
readConfigurationFile(){
    file="$1"

    set -o allexport
    # shellcheck disable=SC1090
    . "$file"
    set +o allexport
}
##############################################################################
# Function to parse domain allow string 
##############################################################################
splitstring() {
    string=$1
    separator=";"
    array=$(echo "$string" | sed "s/${separator}/ /g")

    # Print each element on a new line
    for domain in ${array}; do
        echo "${domain}"
    done    
}
##############################################################################
# readlist
##############################################################################
readlist() {
    filename=$1
    list=""
    # Read each line in the file
    while IFS= read -r line
    do
    # Print the line
    if [ "$list" != "" ]; then
        list="${list},\"${line}\""
    else
        list="\"$line\""
    fi
    done < "$filename"
    echo "${list}"
}
##############################################################################
# uninstall squid
##############################################################################
uninstallsquidproxy() {
    logInfo "Updating package list (again - due to net-tools)..."
    cmd="sudo systemctl stop squid"
    runCommand "${cmd}" 2>/dev/null    
    cmd="sudo systemctl disable squid"
    runCommand "${cmd}" 2>/dev/null    
    cmd="sudo apt-get remove -y squid"
    runCommand "${cmd}"
    cmd="sudo rm -r /etc/squid/*"
    runCommand "${cmd}"
}

##############################################################################
# install squid
##############################################################################
installsquidproxy() {
    # Display general information
    # Suppress the "Daemons using outdated libraries" pop-up when using apt to install or update packages
    export NEEDRESTART_SUSPEND=1
    export NEEDRESTART_MODE=l

    CURRENT_SCRIPT=$(readlink -f "$0")
    SCRIPTS_DIRECTORY=$(dirname "$CURRENT_SCRIPT")

    # Clean pending process which could block net-tools installation
    logInfo "Cleaning pending process..."
    cleanLock

    # Updating the package list and upgrading installed packages
    logInfo "Updating package list and upgrade installed packages..."
    cmd="sudo apt-get update && sudo apt-get upgrade -y"
    runCommand "${cmd}"

    logInfo "Updating package list (again - due to net-tools)..."
    cmd="sudo apt-get update"
    runCommand "${cmd}"

    logInfo "Cleaning pending process..."
    cleanLock

    cmd="sudo apt-get install net-tools -y"
    runCommand "${cmd}" "true"

    logInfo "Cleaning pending process..."
    cleanLock

    cmd="sudo apt-get install apache2-utils -y"
    runCommand "${cmd}" "true"

    logInfo "Cleaning pending process..."
    cleanLock

    cmd="sudo apt-get install squid -y"
    runCommand "${cmd}" "true"

    cmd="sudo service squid stop"
    runCommand "${cmd}" 2>/dev/null

    PUBLIC_IP=$(curl -s ifconfig.me)
    PROXY_IP=$(ifconfig eth0 | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p') # DevSkim: ignore DS162092
    PROXY_BCST=$(ifconfig eth0 | sed -En 's/127.0.0.1//;s/.*broadcast (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p') # DevSkim: ignore DS162092
    PROXY_MASK=$(echo "${PROXY_BCST}" | sed  's/.255/.0/g')/24
    HOSTNAME=$(hostname)

    cat <<TEXT | sudo  tee "/etc/squid/sites.allowedlist.txt"
$(splitstring "$AZURE_RESOURCE_PROXY_DOMAIN_LIST")
TEXT

    sudo mv /etc/squid/squid.conf /etc/squid/squid.conf.defaut
    cat <<CONF | sudo  tee "/etc/squid/squid.conf"
visible_hostname ${HOSTNAME}

# http_port ${PROXY_IP}:${AZURE_RESOURCE_PROXY_PORT} 
http_port ${AZURE_RESOURCE_PROXY_PORT} 

cache_dir ufs /var/spool/squid 100 16 256
# Max size of buffer to download file
client_request_buffer_max_size 10000 KB

#################################### ACL ####################################

acl all src all # ACL to authorize all networks (Source = All)  ACL mandaotry
acl lan src ${AZURE_RESOURCE_SOURCE_IP_ADDRESS}
acl Safe_ports port 80 # Port HTTP = Port 'sure'
acl Safe_ports port 443 # Port HTTPS = Port 'sure'
############################################################################

# Disable all protocols and ports
http_access deny !Safe_ports

# deny  ; ! = except ; lan = acl name.
http_access deny !lan

# list of dns domains 
acl allowedlist dstdomain "/etc/squid/sites.allowedlist.txt"
http_access allow allowedlist
http_access deny all

# Authentication
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid proxy-caching web server
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
CONF

    sudo htpasswd -bc /etc/squid/passwd "${AZURE_RESOURCE_PROXY_USERNAME}" "${AZURE_RESOURCE_PROXY_PASSWORD}"

    cmd="sudo htpasswd -bc /etc/squid/passwd \"${AZURE_RESOURCE_PROXY_USERNAME}\" \"${AZURE_RESOURCE_PROXY_PASSWORD}\""
    logInfo "${cmd}"
    runCommand "${cmd}" "true"

    cmd="sudo service squid restart"
    logInfo "${cmd}"
    runCommand "${cmd}" "true"

    logInfo "Proxy Installed"
    logInfo "Client configuration:"
    logInfo "export HTTP_PROXY=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export HTTPS_PROXY=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export http_proxy=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export https_proxy=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export NO_PROXY=localhost,127.0.0.1,.svc,.svc.cluster.local,172.16.0.0/12,192.168.0.0/16,169.254.169.254,logcollector,${PROXY_MASK}/24,10.43.0.0/16" # DevSkim: ignore DS162092
    logInfo "export no_proxy=localhost,127.0.0.1,.svc,.svc.cluster.local,172.16.0.0/12,192.168.0.0/16,169.254.169.254,logcollector,${PROXY_MASK}/24,10.43.0.0/16" # DevSkim: ignore DS162092    
}

##############################################################################
# uninstall mitmproxy
##############################################################################
uninstallmitmproxy() {
    logInfo "Updating package list (again - due to net-tools)..."
    cmd="sudo systemctl stop mitmproxy.service"
    runCommand "${cmd}" 2>/dev/null    
    cmd="sudo systemctl disable mitmproxy.service"
    runCommand "${cmd}" 2>/dev/null    
    cmd="sudo rm -r /usr/local/bin/mitmproxy/*"
    runCommand "${cmd}"
    cmd="sudo rm /etc/systemd/system/mitmproxy.service"
    runCommand "${cmd}"
}

##############################################################################
# install squid
##############################################################################
installmitmproxy() {
    # Suppress the "Daemons using outdated libraries" pop-up when using apt to install or update packages
    export NEEDRESTART_SUSPEND=1
    export NEEDRESTART_MODE=l

    # Display general information
    CURRENT_SCRIPT=$(readlink -f "$0")
    SCRIPTS_DIRECTORY=$(dirname "$CURRENT_SCRIPT")

    logInfo "--------------------------------------------------"
    logInfo "GENERAL INFORMATION"
    logInfo "--------------------------------------------------"
    logInfo "Current scripts directory: ${SCRIPTS_DIRECTORY}"
    logInfo "Current user: $(whoami)"
    logInfo "Current host: $(hostname)"
    logInfo "Current date: $(date +"%y%m%d-%H%M%S")"
    logInfo "--------------------------------------------------"

    # Clean pending process which could block net-tools installation
    logInfo "Cleaning pending process..."
    cleanLock

    # Updating the package list and upgrading installed packages
    logInfo "Updating package list and upgrade installed packages..."
    cmd="sudo apt-get update && sudo apt-get upgrade -y"
    runCommand "${cmd}"

    cmd="sudo apt-get update -y"
    runCommand "${cmd}"

    logInfo "Cleaning pending process..."
    cleanLock
    cmd="sudo apt-get install net-tools -y"
    runCommand "${cmd}" "true"

    logInfo "Cleaning pending process..."
    cleanLock
    cmd="sudo apt-get install apache2-utils -y"
    runCommand "${cmd}" "true"

    logInfo "Cleaning pending process..."
    cleanLock
    cmd="sudo systemctl stop mitmproxy.service"
    runCommand "${cmd}" 2>/dev/null


    PUBLIC_IP=$(curl -s ifconfig.me)
    PROXY_IP=$(ifconfig eth0 | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p') # DevSkim: ignore DS162092
    PROXY_BCST=$(ifconfig eth0 | sed -En 's/127.0.0.1//;s/.*broadcast (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p') # DevSkim: ignore DS162092
    PROXY_MASK=$(echo "${PROXY_BCST}" | sed  's/.255/.0/g')/24
    HOSTNAME=$(hostname)

    # Installing the mitmproxy service 
    CURRENT_USER=$(whoami)
    logInfo "Installing MITMPROXY for user: ${CURRENT_USER}"
    if [ ! -d "/usr/local/bin/mitmproxy" ]; then
        sudo mkdir "/usr/local/bin/mitmproxy" || true
        sudo chown -R "${CURRENT_USER}" "/usr/local/bin/mitmproxy"
    fi
    if [ ! -d "/usr/local/bin/mitmproxy/cert" ]; then
        sudo mkdir "/usr/local/bin/mitmproxy/cert" || true
        sudo chown -R "${CURRENT_USER}" "/usr/local/bin/mitmproxy/cert"
    fi
    if [ ! -d "/var/log/mitmproxy" ]; then
        sudo mkdir "/var/log/mitmproxy" || true
        sudo chown -R "${CURRENT_USER}" "/var/log/mitmproxy"
    fi

    cmd="wget https://downloads.mitmproxy.org/11.0.2/mitmproxy-11.0.2-linux-x86_64.tar.gz -O /usr/local/bin/mitmproxy/mitmproxy-11.0.2-linux-x86_64.tar.gz"
    logInfo "${cmd}"
    runCommand "${cmd}" "true"

    cmd="tar -xf /usr/local/bin/mitmproxy/mitmproxy-11.0.2-linux-x86_64.tar.gz -C /usr/local/bin/mitmproxy"
    logInfo "${cmd}"
    runCommand "${cmd}" "true"

    cmd="sudo htpasswd -bc /usr/local/bin/mitmproxy/passwd \"${AZURE_RESOURCE_PROXY_USERNAME}\" \"${AZURE_RESOURCE_PROXY_PASSWORD}\""
    logInfo "${cmd}"
    runCommand "${cmd}" "true"

    cat <<TEXT | sudo  tee "/usr/local/bin/mitmproxy/sites.allowedlist.txt"
$(splitstring "$AZURE_RESOURCE_PROXY_DOMAIN_LIST")
TEXT

    DOMAIN_LIST=$(readlist "/usr/local/bin/mitmproxy/sites.allowedlist.txt")

    cat <<PYTHON | sudo tee /usr/local/bin/mitmproxy/domains_filter_parent.py
from mitmproxy import http, tcp
from datetime import datetime
import os
import shutil
from datetime import datetime

# List of domains to intercept
DOMAINLIST = [${DOMAIN_LIST}]

DUMP_FILE_PREFIX="/var/log/mitmproxy/dump"
ACCESS_FILE_PREFIX="/var/log/mitmproxy/access"
FILE_SUFFIX=".log"
MAXSIZE=1000000

def get_current_datetime_string() -> str:
    # Get the current date and time
    now = datetime.now()
    # Format the date and time as YYYYMMDD-HHMMSS
    formatted_datetime = now.strftime('%Y%m%d-%H%M%S')
    return formatted_datetime

def dump(flow: http.HTTPFlow, label: str) -> None:
    with open(f"{DUMP_FILE_PREFIX}{FILE_SUFFIX}", "a") as log:
        dumpproxy = os.getenv('DUMP_PROXY')
        if dumpproxy == "true":
            if label == "RESPONSE":
                if flow.response.content:
                    log.write(f"{datetime.now()} {label} {flow.request.timestamp_start} {flow.request.method} {flow.request.pretty_url} {flow.response.content.decode('utf-8', errors='replace')}\n")
                else:
                    log.write(f"{datetime.now()} {label} {flow.request.timestamp_start} {flow.request.method} {flow.request.pretty_url} \n")
            else:
                if flow.request.content:
                    log.write(f"{datetime.now()} {label} {flow.request.timestamp_start} {flow.request.method} {flow.request.pretty_url} {flow.request.content.decode('utf-8', errors='replace')}\n")
                else:
                    log.write(f"{datetime.now()} {label} {flow.request.timestamp_start} {flow.request.method} {flow.request.pretty_url} \n")
            log.seek(0,os.SEEK_END)
            size = log.tell()
            if size > MAXSIZE:
                datestring = get_current_datetime_string()
                shutil.copy(f"{DUMP_FILE_PREFIX}{FILE_SUFFIX}",f"{DUMP_FILE_PREFIX}_{datestring}{FILE_SUFFIX}")
                with open(f"{DUMP_FILE_PREFIX}{FILE_SUFFIX}", "w"):
                    pass

def logs(flow: http.HTTPFlow, label: str, protocol: str) -> None:
    with open(f"{ACCESS_FILE_PREFIX}{FILE_SUFFIX}", "a") as log:
        if protocol == "http":
            log.write(f"{datetime.now()} {label} {protocol} {flow.request.timestamp_start} {flow.client_conn.peername[0]} {flow.client_conn.peername[1]} {flow.request.method} {flow.request.host} {flow.request.port} {flow.request.url}\n")
        else:
            log.write(f"{datetime.now()} {label} tcp {flow.client_conn.timestamp_start} {flow.client_conn.peername[0]} {flow.client_conn.peername[1]}  {protocol.replace("tcp","")} {flow.server_conn.address[0]} {flow.server_conn.peername[1]}  \n")
        log.seek(0,os.SEEK_END)
        size = log.tell()
        if size > MAXSIZE:
            datestring = get_current_datetime_string()
            shutil.copy(f"{ACCESS_FILE_PREFIX}{FILE_SUFFIX}",f"{ACCESS_FILE_PREFIX}_{datestring}{FILE_SUFFIX}")
            with open(f"{ACCESS_FILE_PREFIX}{FILE_SUFFIX}", "w"):
                pass

# def tcp_message(flow: tcp.TCPFlow) -> None:
#     logs(flow,"IGNORED","tcpDATA")

def tcp_start(flow: tcp.TCPFlow) -> None:
    logs(flow,"IGNORED","tcpCONN")

def tcp_end(flow: tcp.TCPFlow) -> None:
    logs(flow,"IGNORED","tcpDISC")

def request(flow: http.HTTPFlow) -> None:
    # Check if the request host is in the whitelist
    dump(flow,"REQUEST ")
    if not any(domain in flow.request.host for domain in DOMAINLIST):
        flow.response = http.Response.make(
            403,  # HTTP status code
            b"Blocked by mitmproxy",  # Response body
            {"Content-Type": "text/plain"}  # Headers
        )
        logs(flow,"DENIED   ","http")
    else:        
        logs(flow,"ACCEPTED ","http")

def response(flow: http.HTTPFlow) -> None:
    # Check if the request host is in the whitelist
    dump(flow,"RESPONSE")
PYTHON

    CERT_FOLDER="$(mktemp -d)"
    logInfo "Creating mitmproxy-ca.pem under /usr/local/bin/mitmproxy/cert"
    echo "${AZURE_RESOURCE_PROXY_CA_KEY}" | sudo tee "${CERT_FOLDER}/proxy-ca.key"
    echo "${AZURE_RESOURCE_PROXY_CA}" | sudo tee "${CERT_FOLDER}/proxy-ca.crt"
    rm /usr/local/bin/mitmproxy/cert/* 2>/dev/null
    cat "${CERT_FOLDER}/proxy-ca.key" "${CERT_FOLDER}/proxy-ca.crt" > /usr/local/bin/mitmproxy/cert/mitmproxy-ca.pem

    IGNORE_HOST_LIST=" --ignore-hosts  raw.githubusercontent.com:443 "


    cat <<BASH | sudo tee /usr/local/bin/mitmproxy/mitmproxy.sh  # DevSkim: ignore DS440001
#!/bin/bash
/usr/local/bin/mitmproxy/mitmdump --mode regular  --set block_global=false --showhost -p ${AZURE_RESOURCE_PROXY_PORT} --set confdir=/usr/local/bin/mitmproxy/cert   --proxyauth  @/usr/local/bin/mitmproxy/passwd ${IGNORE_HOST_LIST} --set tls_version_client_min=TLS1_2 --show-ignored-hosts -s /usr/local/bin/mitmproxy/domains_filter_parent.py &>> /var/log/mitmproxy/mitmproxy.log # DevSkim: ignore DS440001
BASH
    checkError

    sudo chmod +x /usr/local/bin/mitmproxy/mitmproxy.sh
    checkError

    removevar SSLKEYLOGFILE
    addvar SSLKEYLOGFILE "/var/log/mitmproxy/sslkeylogfile.txt"

    removevar DUMP_PROXY
    addvar DUMP_PROXY "false"

    cat <<SERVICE | sudo tee /etc/systemd/system/mitmproxy.service
[Unit]
Description=mitmproxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mitmproxy/mitmproxy.sh
User=${CURRENT_USER}
Group=${CURRENT_USER}
Restart=on-abort
EnvironmentFile=/etc/environment

[Install]
WantedBy=multi-user.target
SERVICE
    checkError


    sudo touch /var/log/mitmproxy/sslkeylogfile.txt
    sudo chown "${CURRENT_USER}" /var/log/mitmproxy/sslkeylogfile.txt
    sudo touch /var/log/mitmproxy/dump.log
    sudo chown "${CURRENT_USER}" /var/log/mitmproxy/dump.log
    sudo touch /var/log/mitmproxy/access.log
    sudo chown "${CURRENT_USER}" /var/log/mitmproxy/access.log
    sudo touch /var/log/mitmproxy/mitmproxy.log
    sudo chown "${CURRENT_USER}" /var/log/mitmproxy/mitmproxy.log

    sudo systemctl daemon-reload
    checkError
    sudo systemctl enable mitmproxy.service
    checkError
    sudo systemctl start mitmproxy.service
    checkError


    logInfo "Proxy Installed"
    logInfo "Client configuration:"
    logInfo "export HTTP_PROXY=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export HTTPS_PROXY=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export http_proxy=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export https_proxy=http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${PUBLIC_IP}:${AZURE_RESOURCE_PROXY_PORT}" # DevSkim: ignore DS137138, DS162092
    logInfo "export NO_PROXY=localhost,127.0.0.1,.svc,.svc.cluster.local,172.16.0.0/12,192.168.0.0/16,169.254.169.254,logcollector,${PROXY_MASK}/24,10.43.0.0/16" # DevSkim: ignore DS162092
    logInfo "export no_proxy=localhost,127.0.0.1,.svc,.svc.cluster.local,172.16.0.0/12,192.168.0.0/16,169.254.169.254,logcollector,${PROXY_MASK}/24,10.43.0.0/16" # DevSkim: ignore DS162092
}

#######################################################
#- used to print out script usage
#######################################################
usage() {
    echo
    echo "Arguments:"
    printf " -a  Sets proxy-global-tool ACTION {login, install, getsuffix, createconfig, deploy, test, undeploy}\n"
    printf " -c  Sets the proxy-global-tool configuration file\n"
    printf " -e  Sets the environement - by default 'dev' ('dev', 'tst', 'prd', 'val')\n"
    printf " -r  Sets the Azure Region - by default 'eastus2' (For instance: 'westus2', 'westeurope', 'northeurope',...)\n"
    printf " -s  Sets subscription id \n"
    printf " -t  Sets tenant id\n"
    printf " -k  Sets proxy type: 'squidproxy' or 'mitmproxy'\n"
    printf " -p  Sets proxy port: '8008'\n"
    printf " -u  Sets proxy username: 'azureuser'\n"
    printf " -w  Sets proxy password: 'password'\n"
    printf " -d  Sets proxy domains list: '.bing.com;.microsoft.com'\n"


    echo
    echo "Example:"
    printf " bash ./scripts/proxy-global-tool.sh -a install \n"
    printf " bash ./scripts/proxy-global-tool.sh -a createconfig -c ./configuration/proxytool.env -e dev -r eastus2 \n" 
    printf " bash ./scripts/proxy-global-tool.sh -a deploy -k squidproxy -c ./configuration/proxytool.env \n"
    printf " bash ./scripts/proxy-global-tool.sh -a deploy -k mitmproxy -c ./configuration/proxytool.env \n"
    printf " bash ./scripts/proxy-global-tool.sh -a deploy -k squidproxy -c ./configuration/proxytool.env -p 8080 -u azureuser -w au -d 'ifconfig.me;.bing.com;.microsoft.com' \n"    
    printf " bash ./scripts/proxy-global-tool.sh -a test -c ./configuration/proxytool.env\n" 
    printf " bash ./scripts/proxy-global-tool.sh -a undeploy -c ./configuration/proxytool.env\n" 
}
NULL="null"
AZURE_ENVIRONMENT=dev
ACTION=
CONFIGURATION_FILE="$SCRIPTS_DIRECTORY/../configuration/.default.env"
AZURE_RESOURCE_PREFIX="prx"
AZURE_SUBSCRIPTION_ID=""
AZURE_TENANT_ID=""   
AZURE_REGION="eastus2"
SSH_PUBLIC_KEY=""
SSH_PRIVATE_KEY=""
AZURE_VM_ADMINUSERNAME="azureuser"
AZURE_RESOURCE_PROXY_KIND="squidproxy"
AZURE_RESOURCE_PROXY_PORT="8080"
AZURE_RESOURCE_PROXY_USERNAME="azureuser"
AZURE_RESOURCE_PROXY_PASSWORD="au"
AZURE_RESOURCE_PROXY_DOMAIN_LIST="ifconfig.me;www.bing.com;www.bing.dk"
AZURE_RESOURCE_PROXY_CA_KEY="${NULL}"
AZURE_RESOURCE_PROXY_CA="${NULL}"
AZURE_RESOURCE_SOURCE_IP_ADDRESS=$(curl -s http://ifconfig.me/ip) || true

# shellcheck disable=SC2034
while getopts "a:c:e:r:s:t:m:k:p:u:w:d:i:y:f:?h" opt; do
    case $opt in
    a) ACTION=$OPTARG ;;
    c) CONFIGURATION_FILE=$OPTARG ;;
    e) AZURE_ENVIRONMENT=$OPTARG ;;
    r) AZURE_REGION=$OPTARG ;;
    s) AZURE_SUBSCRIPTION_ID=$OPTARG ;;
    t) AZURE_TENANT_ID=$OPTARG ;;
    m) AZURE_VM_ADMINUSERNAME=$OPTARG ;;
    k) AZURE_RESOURCE_PROXY_KIND=$OPTARG ;;
    p) AZURE_RESOURCE_PROXY_PORT=$OPTARG ;;
    u) AZURE_RESOURCE_PROXY_USERNAME=$OPTARG ;;
    w) AZURE_RESOURCE_PROXY_PASSWORD=$OPTARG ;;
    d) AZURE_RESOURCE_PROXY_DOMAIN_LIST=$OPTARG ;;
    i) AZURE_RESOURCE_SOURCE_IP_ADDRESS=$OPTARG ;;
    y) AZURE_RESOURCE_PROXY_CA_KEY=$OPTARG ;;
    f) AZURE_RESOURCE_PROXY_CA=$OPTARG ;;    
    :)
        echo "Error: -${OPTARG} requires a value"
        exit 1
        ;;
    \?)
        usage
        exit 1
        ;;
    h)
        usage
        exit 1
        ;;
    *)
        usage
        exit 1
        ;;
    esac
done

# Validation
if [ $# -eq 0 ] || [ -z "${ACTION}" ] || [ -z "$CONFIGURATION_FILE" ]; then
    echo "Required parameters are missing"
    usage
    exit 1
fi
if [ "${ACTION}" != "login" ] && [ "${ACTION}" != "install" ] && [ "${ACTION}" != "vminstall" ]  && [ "${ACTION}" != "createconfig" ] && [ "${ACTION}" != "getsuffix" \
    ] && [ "${ACTION}" != "deploy" ] && [ "${ACTION}" != "undeploy" ] && [ "${ACTION}" != "test" ] && [ "${ACTION}" != "installproxy" ]; then
    echo "ACTION '${ACTION}' not supported, possible values: login, install, vminstall, getsuffix, createconfig, deploy, test, undeploy"
    usage
    exit 1
fi
# colors for formatting the output
# shellcheck disable=SC2034
YELLOW='\033[1;33m'
# shellcheck disable=SC2034
GREEN='\033[1;32m'
# shellcheck disable=SC2034
RED='\033[0;31m'
# shellcheck disable=SC2034
BLUE='\033[1;34m'
# shellcheck disable=SC2034
NC='\033[0m' # No Color


if [ "${ACTION}" = "install" ] ; then
    printMessage "Installing pre-requisites"
    printProgress "Installing azure cli"
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    az config set extension.use_dynamic_install=yes_without_prompt  2>/dev/null || true
    cmd="sudo apt-get -y update"
    runCommand "${cmd}" "true"    
    cmd="sudo apt-get -y install  jq"
    runCommand "${cmd}" "true"    
    cmd="sudo apt-get install net-tools -y"
    runCommand "${cmd}" "true"    
    cmd="sudo apt-get install dnsutils -y"
    runCommand "${cmd}" "true"    
    printMessage "Installing pre-requisites done"
    exit 0
fi

if [ "${ACTION}" = "login" ] ; then
    # if configuration file exists read subscription id and tenant id values in the file
    if [ "$CONFIGURATION_FILE" ]; then
        if [ -f "$CONFIGURATION_FILE" ]; then
            readConfigurationFile "$CONFIGURATION_FILE"
        fi
    fi
    printMessage "Login..."
    azLogin
    checkLoginAndSubscription
    printMessage "Login done"
    exit 0
fi

# check if configuration file is set 
if [ -z "$CONFIGURATION_FILE" ]; then
    CONFIGURATION_FILE="$SCRIPTS_DIRECTORY/../configuration/.default.env"
fi



if [ "${ACTION}" = "installproxy" ] ; then
  logInfo "--------------------------------------------------"
  logInfo "GENERAL INFORMATION"
  logInfo "--------------------------------------------------"
  logInfo "Current scripts directory: ${SCRIPTS_DIRECTORY}"
  logInfo "Current user: $(whoami)"
  logInfo "Current host: $(hostname)"
  logInfo "Current date: $(date +"%y%m%d-%H%M%S")"
  logInfo "--------------------------------------------------"
  if [ -f /etc/squid/squid.conf ]; then
    printMessage "Uninstalling squid proxy..."
    uninstallsquidproxy
    printMessage "Uninstalling squid proxy done"
  fi
  if [ -f /etc/systemd/system/mitmproxy.service ]; then
    printMessage "Uninstalling squid proxy..."
    uninstallmitmproxy
    printMessage "Uninstalling squid proxy..."
  fi
  if [ "${AZURE_RESOURCE_PROXY_KIND}" = "squidproxy" ]; then
    printMessage "Installing squid proxy..."
    installsquidproxy
    printMessage "Installing squid proxy done"
  elif [ "${AZURE_RESOURCE_PROXY_KIND}" = "mitmproxy" ]; then
    printMessage "Installing mitmproxy..."
    installmitmproxy
    printMessage "Installing mitmproxy done"
  fi
  exit 0
fi

# get Azure Subscription and Tenant Id if already connected
AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
AZURE_TENANT_ID=$(az account show --query tenantId -o tsv 2> /dev/null) || true

# check if configuration file is set 
if [ -z "${AZURE_SUBSCRIPTION_ID}" ] || [ -z "${AZURE_TENANT_ID}" ] && [ ! "${ACTION}" = "install" ] && [ ! "${ACTION}" = "login" ]; then
    printError "Connection to Azure required, launching 'az login'"
    printMessage "Login..."
    azLogin
    checkLoginAndSubscription
    printMessage "Login done"    
    AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
    AZURE_TENANT_ID=$(az account show --query tenantId -o tsv 2> /dev/null) || true
fi

if [ "${ACTION}" = "createconfig" ] ; then
    # Get a suffix available with no conflict with existing Azure resources
    printMessage  "Getting a suffix with no conflict with existing resources on Azure..."  
    AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
    if [ -n "${AZURE_SUBSCRIPTION_ID}" ]
    then
        AZURE_PROXY_SUFFIX=$(getNewSuffix  "${AZURE_RESOURCE_PREFIX}" "${AZURE_ENVIRONMENT}" "${AZURE_SUBSCRIPTION_ID}")
        printMessage "Suffix found AZURE_PROXY_SUFFIX: '${AZURE_PROXY_SUFFIX}'"
        cat > "$CONFIGURATION_FILE" << EOF
AZURE_REGION="${AZURE_REGION}"
AZURE_PROXY_SUFFIX=${AZURE_PROXY_SUFFIX}
AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
AZURE_TENANT_ID=${AZURE_TENANT_ID}
AZURE_ENVIRONMENT=${AZURE_ENVIRONMENT}
EOF
        printMessage "Creation of configuration file '${CONFIGURATION_FILE}' done"
        exit 0
    else
        printError "Connection to Azure required, run 'az login'"
    fi
fi

if [ "${ACTION}" = "getsuffix" ] ; then
    # Get a suffix available with no conflict with existing Azure resources
    AZURE_SUBSCRIPTION_ID=$(az account show --query id --output tsv 2> /dev/null) || true
    if [ -n "${AZURE_SUBSCRIPTION_ID}" ]
    then
        SUFFIX=$(getNewSuffix  "${AZURE_RESOURCE_PREFIX}" "${AZURE_ENVIRONMENT}" "${AZURE_SUBSCRIPTION_ID}")
        echo "${SUFFIX}"
    fi
    exit 0
fi

if [ "${ACTION}" = "deploy" ] ; then
  if [ "$CONFIGURATION_FILE" ]; then
      if [ ! -f "$CONFIGURATION_FILE" ]; then
         printError "$CONFIGURATION_FILE does not exist."
         exit 1
      fi
      printMessage "Updating configuration file: ${CONFIGURATION_FILE} with proxy parameters..."
      updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_KIND" "${AZURE_RESOURCE_PROXY_KIND}"
      updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_PORT" "${AZURE_RESOURCE_PROXY_PORT}"
      updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_USERNAME" "${AZURE_RESOURCE_PROXY_USERNAME}"
      updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_PASSWORD" "${AZURE_RESOURCE_PROXY_PASSWORD}"
      updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_DOMAIN_LIST" "\"${AZURE_RESOURCE_PROXY_DOMAIN_LIST}\""
      readConfigurationFile "$CONFIGURATION_FILE"
  else
      printWarning "No env. file specified. Using environment variables."
  fi
  printMessage "Deploying the infrastructure using configuration file: ${CONFIGURATION_FILE}..."
  # Check Azure connection
  printProgress "Check Azure connection for subscription: '$AZURE_SUBSCRIPTION_ID'"
  azLogin
  checkError    
  az config set extension.use_dynamic_install=yes_without_prompt  2>/dev/null || true 
  printMessage "Deploy infrastructure subscription: '$AZURE_SUBSCRIPTION_ID' region: '$AZURE_REGION' suffix: '$AZURE_PROXY_SUFFIX'"
  # Get resources names for the infrastructure deployment
  RESOURCE_GROUP=$(getResourceGroupName "${AZURE_PROXY_SUFFIX}")

  if [ ! -f ~/.ssh/"${AZURE_PROXY_SUFFIX}"key.pub ] || [ ! -f ~/.ssh/"${AZURE_PROXY_SUFFIX}"key ];
  then
    printProgress "Creating ssh keys for authentication with Virtual Machine  '${AZURE_PROXY_SUFFIX}key.pub'"
    TEMPDIR=$(mktemp -d)
    cmd="ssh-keygen -t rsa -b 2048 -f ${TEMPDIR}/${AZURE_PROXY_SUFFIX}key -q -P \"\""
    printProgress "$cmd"
    runCommand "$cmd" "true"

    SSH_PUBLIC_KEY="\"$(cat "${TEMPDIR}/${AZURE_PROXY_SUFFIX}key.pub")\""
    # printProgress "${SSH_PUBLIC_KEY}"
    SSH_PRIVATE_KEY="\"$(cat "${TEMPDIR}/${AZURE_PROXY_SUFFIX}key")\""
    # printProgress "${SSH_PRIVATE_KEY}"
    updateConfigurationFile "${CONFIGURATION_FILE}" "SSH_PUBLIC_KEY" "${SSH_PUBLIC_KEY}"
    updateConfigurationFile "${CONFIGURATION_FILE}" "SSH_PRIVATE_KEY" "${SSH_PRIVATE_KEY}"
    cp "${TEMPDIR}/${AZURE_PROXY_SUFFIX}key.pub" ~/.ssh/"${AZURE_PROXY_SUFFIX}key.pub"
    cp "${TEMPDIR}/${AZURE_PROXY_SUFFIX}key" ~/.ssh/"${AZURE_PROXY_SUFFIX}key"
    readConfigurationFile "${CONFIGURATION_FILE}"
  fi

  if [ "$(az group exists --name "${RESOURCE_GROUP}")" = "false" ]; then
      printProgress "Create resource group  '${RESOURCE_GROUP}'"
      cmd="az group create -l ${AZURE_REGION} -n ${RESOURCE_GROUP}"
      printProgress "$cmd"
      runCommand "$cmd" "true" 1>/dev/null
  fi

  if [ "${AZURE_RESOURCE_PROXY_KIND}" = "mitmproxy" ]; then
    PROXY_FOLDER="$(mktemp -d)"
    logProgress "Creating Proxy certificate authority under ${PROXY_FOLDER}..."
    DNS_NAME="pip${AZURE_PROXY_SUFFIX}proxy.${AZURE_REGION}.cloudapp.azure.com"
    DNS_PARENT_NAME="${AZURE_REGION}.cloudapp.azure.com"

    cat <<CFG > "${PROXY_FOLDER}/openssl.config"
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${PROXY_FOLDER}
certs             = \$dir/certs
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/cakey.pem
certificate       = \$dir/cacert.pem
default_md        = sha256
policy            = policy_any

[ policy_any ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits       = 2048
default_md         = sha256
default_keyfile    = privkey.pem
distinguished_name = req_distinguished_name
req_extensions     = v3_req
x509_extensions    = v3_req
	
[ req_distinguished_name ]
countryName                     = DK
countryName_default             = US
stateOrProvinceName             = DK
stateOrProvinceName_default     = California
localityName                    = San Francisco
localityName_default            = San Francisco
0.organizationName              = Contoso
0.organizationName_default      = My Company
organizationalUnitName          = IT
commonName                      = ${DNS_PARENT_NAME}
commonName_max                  = 64
emailAddress                    = admin@${DNS_PARENT_NAME}
emailAddress_max                = 64

[ v3_req ]
subjectAltName      = @alt_names
keyUsage            = critical, keyCertSign, nonRepudiation, digitalSignature, keyEncipherment
[ alt_names ]
DNS.1 = ${DNS_NAME}
CFG
    mkdir -p "${PROXY_FOLDER}/certs"
    mkdir -p "${PROXY_FOLDER}/newcerts"
    mkdir -p "${PROXY_FOLDER}/private"
    touch "${PROXY_FOLDER}/index.txt"
    echo 1000 > "${PROXY_FOLDER}/serial"

    logInfo "Creating Proxy certificate authority key..."
    openssl genpkey -algorithm RSA -out "${PROXY_FOLDER}/private/cakey.pem" -pkeyopt rsa_keygen_bits:2048
    logInfo "Creating Proxy certificate authority..."
    openssl req  -config "${PROXY_FOLDER}/openssl.config" -x509 -new -nodes -key "${PROXY_FOLDER}/private/cakey.pem" -days 3650  \
        -sha256 -out "${PROXY_FOLDER}/cacert.pem" -addext keyUsage=critical,keyCertSign \
        -subj "/C=DK/ST=DK/L=Copenhagen/O=Contoso/OU=IT/CN=contoso.com"
    logInfo "Checking Proxy certificate authority..."
    openssl x509 -noout -text -in "${PROXY_FOLDER}/cacert.pem"
    PROXY_CA_KEY=$(cat "${PROXY_FOLDER}/private/cakey.pem")
    PROXY_CA_CERTIFICATE=$(cat "${PROXY_FOLDER}/cacert.pem")  
    logProgress "Proxy certificate authority created"
  else
    PROXY_CA_KEY="${NULL}"
    PROXY_CA_CERTIFICATE="${NULL}"  
  fi
  updateConfigurationFile "${CONFIGURATION_FILE}" "PROXY_CERTIFICATE_AUTHORITY_KEY" "\"${PROXY_CA_KEY}\""
  updateConfigurationFile "${CONFIGURATION_FILE}" "PROXY_CERTIFICATE_AUTHORITY" "\"${PROXY_CA_CERTIFICATE}\""  


  printProgress "Get IP address"
  AGENT_IP_ADDRESS=$(curl -s https://ifconfig.me/ip) || true


  EOFMAIN="EOFMAIN$(shuf -i 1000-9999 -n 1)"
  EOFILE="EOFILE$(shuf -i 1000-9999 -n 1)"

  TEMPDIR=$(mktemp -d)
  cat << ${EOFMAIN} > "$TEMPDIR"/script.sh
#!/bin/sh
cat << '${EOFILE}' > ./proxy-global-tool.sh 
$(cat ./scripts/proxy-global-tool.sh)
${EOFILE}
chmod 0755 ./proxy-global-tool.sh
./proxy-global-tool.sh -a installproxy -k ${AZURE_RESOURCE_PROXY_KIND} -p ${AZURE_RESOURCE_PROXY_PORT} -u ${AZURE_RESOURCE_PROXY_USERNAME} -w ${AZURE_RESOURCE_PROXY_PASSWORD} -d "${AZURE_RESOURCE_PROXY_DOMAIN_LIST}" -i ${AZURE_RESOURCE_SOURCE_IP_ADDRESS} -y "${PROXY_CA_KEY}" -f "${PROXY_CA_CERTIFICATE}"
${EOFMAIN}
  
  # echo "$TEMPDIR/script.sh"
  # cat "$TEMPDIR/script.sh"
  # shellcheck disable=SC2002
  SCRIPT_COMMON_VALUE=$(cat "$TEMPDIR/script.sh" | gzip -9 | base64 -w 0)

  DEPLOY_NAME=$(date +"%y%m%d-%H%M%S")

  cmd="az deployment group create \
      --name $DEPLOY_NAME \
      --resource-group ${RESOURCE_GROUP} \
      --subscription ${AZURE_SUBSCRIPTION_ID} \
      --template-file ${SCRIPTS_DIRECTORY}/../infrastructure/arm/bicep/global.bicep \
      --output none \
      --parameters suffix=\"${AZURE_PROXY_SUFFIX}\" \
                   ipAddress=\"${AGENT_IP_ADDRESS}\" \
                   vmAdminUserName=\"${AZURE_VM_ADMINUSERNAME}\" \
                   vmAdminPublicKey=\"${SSH_PUBLIC_KEY}\" \
                   vmSize=\"Standard_B2ms\"  \
                   vmScript=\"${SCRIPT_COMMON_VALUE}\" \
                   vmProxyPort=\"${AZURE_RESOURCE_PROXY_PORT}\" "

  printProgress "${cmd%scriptValue=*}"
  runCommand "$cmd" "true"

  # Initialize the environment variables from the infrastructure deployment
  getDeploymentVariables "${RESOURCE_GROUP}" "${DEPLOY_NAME}"
  printProgress "Updating configuration in file '${CONFIGURATION_FILE}'" 
  
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_KIND" "${AZURE_RESOURCE_PROXY_KIND}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_PORT" "${AZURE_RESOURCE_PROXY_PORT}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_DNS_NAME" "${AZURE_RESOURCE_PROXY_DNS_NAME}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_USERNAME" "${AZURE_RESOURCE_PROXY_USERNAME}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_PASSWORD" "${AZURE_RESOURCE_PROXY_PASSWORD}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_PROXY_DOMAIN_LIST" "\"${AZURE_RESOURCE_PROXY_DOMAIN_LIST}\""
  AZURE_RESOURCE_HTTP_PROXY="http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${AZURE_RESOURCE_PROXY_DNS_NAME}:${AZURE_RESOURCE_PROXY_PORT}/"
  AZURE_RESOURCE_HTTPS_PROXY="http://${AZURE_RESOURCE_PROXY_USERNAME}:${AZURE_RESOURCE_PROXY_PASSWORD}@${AZURE_RESOURCE_PROXY_DNS_NAME}:${AZURE_RESOURCE_PROXY_PORT}/"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_HTTP_PROXY" "${AZURE_RESOURCE_HTTP_PROXY}"
  updateConfigurationFile "${CONFIGURATION_FILE}" "AZURE_RESOURCE_HTTPS_PROXY" "${AZURE_RESOURCE_HTTPS_PROXY}"

  printMessage "Deploying proxy infrastructure done"
  exit 0
fi


if [ "${ACTION}"  =  "undeploy" ] ; then
    if [ "$CONFIGURATION_FILE" ]; then
        if [ ! -f "$CONFIGURATION_FILE" ]; then
            printError "$CONFIGURATION_FILE does not exist."
            exit 1
        fi
        readConfigurationFile "$CONFIGURATION_FILE"
    else
        printWarning "No env. file specified. Using environment variables."
    fi

    printMessage "Undeploying the infrastructure..."
    # Check Azure connection
    printProgress "Check Azure connection for subscription: '$AZURE_SUBSCRIPTION_ID'"
    azLogin
    checkError
    RESOURCE_GROUP=$(getResourceGroupName "${AZURE_PROXY_SUFFIX}")
    if [ "$(az group exists --name "${RESOURCE_GROUP}")" = "true" ]; then
        printProgress "Delete resource group  '${RESOURCE_GROUP}'"
        cmd="az group delete  -n ${RESOURCE_GROUP} -y"
        printProgress "$cmd"
        runCommand "$cmd" "true"
    fi
    if [ -f ~/.ssh/"${AZURE_PROXY_SUFFIX}key.pub" ]; then
      printProgress "Removing ssh public keys for authentication with Virtual Machine  '${AZURE_PROXY_SUFFIX}key.pub'"    
      rm -f  ~/.ssh/"${AZURE_PROXY_SUFFIX}key.pub"
    fi
    if [ -f ~/.ssh/"${AZURE_PROXY_SUFFIX}key" ]; then
      printProgress "Removing ssh private keys for authentication with Virtual Machine  '${AZURE_PROXY_SUFFIX}key.pub'"    
      rm -f  ~/.ssh/"${AZURE_PROXY_SUFFIX}key"
    fi

    printMessage "Clearing configuration file for AZURE_PROXY_SUFFIX: '${AZURE_PROXY_SUFFIX}'"
    cat > "$CONFIGURATION_FILE" << EOF
AZURE_REGION="${AZURE_REGION}"
AZURE_PROXY_SUFFIX=${AZURE_PROXY_SUFFIX}
AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
AZURE_TENANT_ID=${AZURE_TENANT_ID}
AZURE_ENVIRONMENT=${AZURE_ENVIRONMENT}
EOF

    printMessage "Undeploying the infrastructure done"
    exit 0
fi
if [ "${ACTION}"  =  "test" ] ; then
    printMessage "Testing proxy..."
    azLogin
    checkError    
    printWarning "Please, ensure the proxy is configured to accept website 'ifconfig.me'"
    readConfigurationFile "${CONFIGURATION_FILE}"    
    LOCAL_IP=$(curl -s ifconfig.me)
    printMessage "Local IP Address: ${LOCAL_IP}"
    PROXY_FOLDER="$(mktemp -d)"
    if [ "${PROXY_CERTIFICATE_AUTHORITY}" = "${NULL}" ];then
        CERT_OPTION=""
    else
        echo "${PROXY_CERTIFICATE_AUTHORITY}" > "${PROXY_FOLDER}/ca.crt"
        CERT_OPTION="--cacert ${PROXY_FOLDER}/ca.crt"
    fi
    cmd="curl -s ${CERT_OPTION} --proxy ${AZURE_RESOURCE_HTTP_PROXY} http://ifconfig.me"
    PROXY_IP=$(eval "${cmd}")
    printMessage "Proxy IP Address from  http://ifconfig.me: ${PROXY_IP}"
    printMessage "With command: curl -s ${CERT_OPTION} --proxy ${AZURE_RESOURCE_HTTP_PROXY} http://ifconfig.me"    
    cmd="curl -s ${CERT_OPTION} --proxy ${AZURE_RESOURCE_HTTP_PROXY} https://ifconfig.me"
    PROXY_SSL_IP=$(eval "${cmd}")
    printMessage "Proxy IP Address from  https://ifconfig.me: ${PROXY_SSL_IP}"
    printMessage "With command: curl -s ${CERT_OPTION} --proxy ${AZURE_RESOURCE_HTTP_PROXY} https://ifconfig.me"
    PROXY_DNS_IP=$(dig +short  "${AZURE_RESOURCE_PROXY_DNS_NAME}")
    printMessage "Proxy IP Address associated with DNS name ${AZURE_RESOURCE_PROXY_DNS_NAME}: ${PROXY_DNS_IP}"
    if [ "${PROXY_DNS_IP}" = "${PROXY_IP}" ] && [ "${PROXY_DNS_IP}" = "${PROXY_SSL_IP}" ]; then
        printMessage "Test successful"
    else
        printError "Test failed: Proxy IP Address different from Proxy IP Address associated with DNS name "
    fi
    # rm -f -r "${PROXY_FOLDER}"
    printMessage "Testing proxy done"
    exit 0
fi

