#Requires -Version 7
$ErrorActionPreference = "Stop"
Import-module .\ADLS_DataAssetGroupManagement1.ps1
# make sure you're in this directory when executing this script

$TenantId = "<TENANT-ID-GUID>"
$ApplicationId = "<SPN-APP-ID-GUID>" # DASG-Automation
$ObjectId = "<EA-SPN-OBJECT-ID-GUID>" # Application object ID, used for permissions, under enterprise applications
$clientSecret = "<SPN-SECRET>" # move to key vault, only for testing
$subscription = "<AZURE-SUBSCRIPTION-NAME>" # name of subscription

$groupOwner = @{'type' = 'servicePrincipals'; 'id' = $ObjectId}
$ServicePrincipalKey = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force # move to key vault
$Credential = New-Object -TypeName System.Management.Automation.PSCredential ($ApplicationId, $ServicePrincipalKey)
Write-Information "Login to Azure as SP: $ApplicationId"
$ctx = Connect-AzAccount -ServicePrincipal -Credential $Credential -TenantId $TenantId
$AzCtx = Select-AzSubscription -SubscriptionName $subscription

$ReqTokenBody = @{
    Grant_Type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_Id     = $ApplicationId
    Client_Secret = $clientSecret
}
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody -ErrorAction Stop
$GraphToken = ConvertTo-SecureString -String $TokenResponse.access_token -AsPlainText -Force
Remove-Variable TokenResponse

# example uses microsoft graph group schema extensions: https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http

$objs = @(
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/mynewpath/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $true; groupowner=$groupOwner; metadata=@{sensitivity="internal"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/nonexistantpath/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="internal"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/citydatacontainer/3ec624b9-bd8b-4caf-97b8-e2e5acc20173Safety/Release/city%3DChicago/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="classified"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/citydatacontainer/3ec624b9-bd8b-4caf-97b8-e2e5acc20173Safety/Release/city=SanFrancisco/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="classified"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/nyctlc/yellow/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="internal"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM2'; path='https://node2curated.blob.core.windows.net/enriched/nyctlc/green/'; recursive=$true; acl='r-x'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="internal"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
    @{node='HM1'; path='https://node1curated.blob.core.windows.net/enriched/diabetes/'; recursive=$true; acl='rwx'; browsableFromRoot = $true; createIfNotExists = $false; groupowner=$groupOwner; metadata=@{sensitivity="classified"; catalogue="https://web.purview.azure.com/datasetid=xyz"}}
)

[System.Collections.ArrayList] $outcome = @() # create list to store results of DASG calls
$objs | ForEach-Object -Process { Write-Host $(Get-Date -Format u)":"$_.path; $result = Set-DASG-ADLS -node $_.node -accessLevel $_.acl -path $_.path -groupOwner $_.groupOwner -recursive $_.recursive -createIfNotExists $_.createIfNotExists -browsableFromRoot $_.browsableFromRoot -metadata $_.metadata -AzCtx $AzCtx -GraphToken $GraphToken -Verbose; $outcome.Add($result)} -End {Write-Host "Completed at: "$(Get-Date -Format u)}

$outcome | ForEach {[PSCustomObject]$_} | Format-Table -AutoSize