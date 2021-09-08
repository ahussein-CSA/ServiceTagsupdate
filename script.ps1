#######################################################################################################
# Script: Add SQL CIDR block into Storage Account- Azure
# Author: Ahmed Hussein - Microsoft 
# Date: July 2020
# Version: 1.0
# References: 
# GitHub: 
#
# THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
# ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
# PARTICULAR PURPOSE.
#
# IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE
# LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS CODE OR INFORMATION.
#
#
########################################################################################################

Param
(
  [Parameter (Mandatory= $true)]
  [string] $subName,
  [Parameter (Mandatory= $true)]
  [string] $grpName,
  [Parameter (Mandatory= $true)]
  [string] $resName,
  [Parameter (Mandatory= $true)]
  [string]$locName,
  [Parameter (Mandatory= $true)]
  [string] $svcName 
)

$ServicePrincipalConnection = Get-AutomationConnection -Name 'AzureRunAsConnection'
try 
{ 
Connect-AzAccount -ServicePrincipal -Tenant $ServicePrincipalConnection.TenantID -ApplicationId $ServicePrincipalConnection.ApplicationID -CertificateThumbprint $ServicePrincipalConnection.CertificateThumbprint
} 
catch { 
    if (!$servicePrincipalConnection) 
    { 
        $ErrorMessage = "Connection $ServicePrincipalConnection not found." 
        throw $ErrorMessage 
    } else{ 
        Write-Error -Message $_.Exception 
        throw $_.Exception 
    } 
}

Select-AzSubscription -SubscriptionId $ServicePrincipalConnection.SubscriptionID
$variableName = "currentchangenumber"
$automationAccount = "testforoms"
$resourceGroup = "automation-rg"


$variable = Get-AzAutomationVariable -AutomationAccountName $automationAccount -Name $variableName -ResourceGroupName $resourceGroup
if (!$variable) 
{
    Write-Output "No variable is there"
    return
}

# Get the Service Tags Public IPs list (Note: Location only verifies version and does not filter on Region)
# https://docs.microsoft.com/en-us/powershell/module/az.network/get-aznetworkservicetag
$poshArray = Get-AzNetworkServiceTag -location $locName

# Filter the list to get the information for a specific Service type and/or Region
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object
$fltrArray = $poshArray.Values | Where-Object { $_.Name -eq $svcName }
$changenumber = $fltrArray.Properties.ChangeNumber
Write-Output $changenumber
if ($changenumber -eq $variable.value)
{ Write-Output "No changes required"}

else {
# Pattern-match only IPv4 Addresses as Firewall currently does not support IPv6
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators
$ipv4Array = @($fltrArray.Properties.AddressPrefixes) -like'*.*.*.*/*'

#delete all existing IP CIDRs 
(Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $grpName-AccountName $resName).IpRules | Remove-AzStorageAccountNetworkRule -ResourceGroupName $grpName -AccountName $resName
# Iterate through the array to add each address to the Firewall
# https://docs.microsoft.com/en-us/powershell/module/az.storage/add-azstorageaccountnetworkrule

Foreach ($ipv4 in $ipv4Array) {
    Add-AzStorageAccountNetworkRule -ResourceGroupName $grpName -AccountName $resName -IPAddressOrRange $ipv4;
}
Set-AzAutomationVariable -AutomationAccountName $automationAccount -Name $variableName -ResourceGroupName $resourceGroup -Value $changenumber -Encrypted $False
Write-Output "Changes are required"
}


  
