#Requires -Version 7
$ErrorActionPreference = "Stop"
Import-module .\ADLS_DataAssetGroupManagement1.ps1
# make sure you're in this directory when executing this script

$TenantId = "<TENANT-ID-GUID>"
$ApplicationId = "<SPN-APP-ID-GUID>" # DASG-Automation
$ObjectId = "<EA-SPN-OBJECT-ID-GUID>" # Application object ID, used for permissions, under enterprise applications
$clientSecret = "<SPN-SECRET>" # move to key vault, only for testing
$subscription = "<AZURE-SUBSCRIPTION-NAME>" # name of subscription

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

$node = 'HM'
$recursive = $true
$createIfNotExists = $false
$accessLevel = 'r-x'
$groupOwner = @{'type' = 'servicePrincipals'; 'id' = $ObjectId}

[System.Collections.ArrayList] $outcome = @()
$paths = 'https://node2curated.blob.core.windows.net/enriched/mynewpath/','https://node2curated.blob.core.windows.net/enriched/citydatacontainer/3ec624b9-bd8b-4caf-97b8-e2e5acc20173Safety/Release/city%3DChicago/','https://node2curated.blob.core.windows.net/enriched/citydatacontainer/3ec624b9-bd8b-4caf-97b8-e2e5acc20173Safety/Release/city=SanFrancisco/','https://node2curated.blob.core.windows.net/enriched/nyctlc/yellow/','https://node2curated.blob.core.windows.net/enriched/nyctlc/green/','https://node1curated.blob.core.windows.net/enriched/diabetes/','https://node1curated.blob.core.windows.net/enriched'
$paths | ForEach-Object -Process { Write-Host $(Get-Date -Format u)":"$_; $result = Set-DASG-ADLS -node $node -accessLevel $accessLevel -path $_ -groupOwner $groupOwner -recursive $recursive -createIfNotExists $createIfNotExists -browsableFromRoot $true -AzCtx $AzCtx -GraphToken $GraphToken -Verbose; $outcome.Add($result)} -End {Write-Host "Completed at: "$(Get-Date -Format u)}

$outcome | ForEach {[PSCustomObject]$_} | Format-Table -AutoSize