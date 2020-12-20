Function Set-DASG-ADLS {
    <# 
    .SYNOPSIS Manages the creation of data asset groups in AAD as security groups and grants ADLS G2 ACLs to the DASG.
    .DESCRIPTION 
    This function leverages AzConnect and Microsoft Graph to automate group creation and ACL provisioning in ADLS.
    Function will act idempotently if groups, assets already exist, and update permissions to match desired config. 
    .PARAMETER Node - Prefix to add to created security group name
    .PARAMETER accessLevel - RWX, order is important
    .PARAMETER path - full ADLS resource URI abfss or https format. https://docs.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-introduction-abfs-uri
    .PARAMETER groupOwner - not used
    .PARAMETER recursive - update permissions of all child items 
    .PARAMETER createIfNotExists - if the path doesnt exist, create it
    .PARAMETER browsableFromRoot - makes the DASG a member of folder DASGs in above levels to allow browsing from root
    .PARAMETER simulate - don't modify/write to APIs
    .PARAMETER AzCtx - the context (tenant+subscription) used to connect to Azure
    .PARAMETER GraphToken - securestring OAuth Microsoft Graph token for the SPN
    #>        
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $node,
        [Parameter(Mandatory=$true)][ValidatePattern("[r-][w-][x-]")][ValidateLength(3,3)][string] $accessLevel,
        [Parameter(Mandatory=$true)][string] $path,
        [Parameter(Mandatory=$true)][hashtable] $groupOwner,
        [Parameter(Mandatory=$false)][AllowEmptyString()][string] $memberOf,
        [Parameter(Mandatory=$true)][ValidateSet($false,$true)][boolean] $recursive,
        [Parameter(Mandatory=$false)][ValidateSet($false,$true)][boolean] $createIfNotExists = $false,
        [Parameter(Mandatory=$false)][ValidateSet($false,$true)][boolean] $browsableFromRoot = $false,
        [Parameter(Mandatory=$false)][ValidateSet($false,$true)][boolean] $simulate=$false,
        [Parameter(Mandatory=$false)][hashtable] $metadata,
        [Parameter(Mandatory=$true)] $AzCtx,
        [Parameter(Mandatory=$true)][securestring] $GraphToken
    )
    Write-Verbose "`r`n#Start DASG - $path"
    if([string]::IsNullOrEmpty($groupOwner.id)){
        Write-Warning "Group owner missing id value"
        $message += "Group owner missing id value";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}   
    }
    if([string]::IsNullOrEmpty($groupOwner.type)){
        Write-Warning "Group owner missing type value"
        $message += "Group owner missing type value";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}   
    }
    $message = "" # output message, i.e. state, info, success outputted via return object
    $pathUrl = [System.Web.HTTPUtility]::UrlDecode($path)
    ####################
    # Extract parameters
    #Write-Verbose "#Extracting parameters - $path"
    $found = $pathUrl -match '(\w{2,5}):\/\/(\w+).[a-zA-Z]+.core.windows.net([\/].+)*'
    # (\w{2,}):\/\/(\w+).[a-zA-Z]+.core.windows.net([\/a-zA-Z0-9_-=]+)
    if ($found) {
        $protocol = $matches[1]
        $account = $matches[2]
        #$path = $matches[3] -split '/'
        
        $pathArray = $matches[3].Remove(0,1).split('/',[System.StringSplitOptions]::RemoveEmptyEntries)
        $fs = $pathArray[0] # filesystem
        $dir = ($pathArray[1..($pathArray.length)])
        $path = $dir -join "/"
    }
    else {
        $found = $pathUrl -match '(\w{2,}):\/\/(\w+)@(\w+).[a-zA-Z]+.core.windows.net([\/].+)*'
        If ($found) {
            $protocol = $matches[1]
            $account = $matches[3]
            
            $pathArray = $matches[4].Remove(0,1).split('/',[System.StringSplitOptions]::RemoveEmptyEntries)
            $fs = $matches[2] # filesystem
            
            $path = $pathArray -join "/"
            #$dirStr = $pathArray -join "-"
        } 
    }

    If(!$found) {
        Write-Warning "URI doesn't match format!"
        $message += "URI doesn't match format!";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}  
    }
    # if targetting the file-system path will be empty.
    #$isFSLevel = $false
    #If(!$path){
    #    $isFSLevel = $true # Note, filepath backslash, not URL forwardslash
    #}

    ####################
    # check storage location (account and path) exist
    # check account

    Write-Verbose "#Storage - getting ref $account"
    $storageResource = Get-AzResource -Name $account -ResourceType "Microsoft.Storage/storageAccounts" -ResourceGroupName * -DefaultProfile $AzCtx

    if($storageResource.length -gt 1) 
    {
        Write-Warning "More than one result, this shouldn't actually be possible...";
        $message += "More than one result, this shouldn't actually be possible...";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}        
    }

    if(($storageResource.length -eq 0) -Or (-Not $storageResource) ) 
    {
        Write-Warning "No storage account found with this name";
        $message += "No storage account found with this name";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    }

    if(!$storageResource[0].ResourceGroupName)
    {
        Write-Warning "No resource-group found for $account";
        $message += "No resource-group found for $account";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    } Else {$rg = $storageResource[0].ResourceGroupName}

    # check file/folder exists
    # https://docs.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-directory-file-acl-powershell
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $rg -AccountName $account
    if(!$storageAccount) 
    {
        Write-Warning "No storage account found with this name";
        $message += "No storage account found with this name";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    }
    $ctx = $storageAccount.Context
    #$ctx = New-AzStorageContext -StorageAccountName $account -UseConnectedAccount
    if(!$ctx) 
    {
        Write-Warning "No storage account found with this name"; 
        $message += "No storage account found with this name";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    }

    $parameters = @{'FileSystem' = $fs; 'Context' = $ctx}
    if(!([string]::IsNullOrEmpty($path))){ #omit path parameter if dealing with root/filesystem level
        $parameters['Path'] = $path
    }
    try {
        $item = Get-AzDataLakeGen2Item @parameters #-FileSystem $fs -Path $path -Context $ctx  
    }
    catch {
        # if the item doesnt exist
        $item = $null
    }


    if((!$item) -And $createIfNotExists)
    {
        $item = New-AzDataLakeGen2Item -FileSystem $fs -Path $path -Directory -Context $ctx;
        $message += "Path doesn't exist, creating; ";
        if(!$item)
        {
            Write-Warning "Couldn't write new file"; 
            $message += "Couldn't write new file";
            return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
        } 
    }
    elseif(!$item)
    {
        Write-Warning "Path does not exist"; 
        $message += "Path does not exist";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    }
    

    #####################
    # If browsable enabled, the DASG is made a member of parent folder non-recursive DASGs. 
    # I.e. you can navigate through from root using storage explorer, web page, however child contents (files and folders) of parent folders remain restricted
    # With this users can browse through from root

    Write-Verbose "#Browsable - $browsableFromRoot"
    $DASGReturnObj = $null
    if($browsableFromRoot){
        # count -1 as 
        for ($i = 0 ; $i -lt ($pathArray.count - 1) ; $i++) {
            # iterate through each layer target path
            $targetpath = "$($protocol)://$account.blob.core.windows.net/$($pathArray[0..$i] -join "/")"

            if($DASGReturnObj.GroupId){
                $parentGroupid = $DASGReturnObj.GroupId
            }
            else {
                $parentGroupid = $null
            }
            
            Write-Verbose "Checking DASG for $targetpath (level $i) parent group id [$parentGroupid]"
            $DASGReturnObj = Set-DASG-ADLS -node $node -accessLevel "r-x" -path $targetpath -groupOwner $groupOwner -memberOf $parentGroupid -recursive $false -createIfNotExists $false -AzCtx $AzCtx -GraphToken $GraphToken -Verbose
            if($null -eq $DASGReturnObj){
                Write-Warning "An error occured checking/creating parent DASG for $targetpath"
                $message += "An error occured checking/creating parent DASG for $targetpath";
                return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
            }
            else {
                $memberOf = $DASGReturnObj.GroupId
            }
        }
    }

    ####################
    # create data-asset group name
    # if access is given only to the specific folder, excluding files/objects beneath
    # create token at end of path to indicate DASG is non-recursive

    Write-Verbose "#Group - Creating name"
    if($recursive){
        $folderonly = ""
    }
    else {
        $folderonly = "."
    }

    #$folderonly = ($recursive) ? "" : "."
    # .Where({$_ -ne "" })
    $pathStr = ($fs,$path.replace('/','-'),$folderonly).Where({$_ -ne "" }) -join "-"
    $groupName = "$node-$($account)_$($pathStr)_"+$accessLevel.replace('-','')

    if($groupName.Length -gt 120)
    {
        $message += "Group name exceeds 120 char limit, creating shorter format; "
        Write-Host "Group name exceeds 120 char limit, creating shorter format" -ForegroundColor Yellow;
        $pathList = $path.split('/',[System.StringSplitOptions]::RemoveEmptyEntries)

        for ($i = 0 ; $i -le $pathList.count ; $i++) # Assess each level of filepath
        {
            $found = $pathList[$i] -match '(\w+)=(\w+)' # determine if its a partition key
            If ($found) {
                $pathList[$i] = $matches[1][0]+".="+$matches[2] # shorten key to single character
            }
            elseif($pathList[$i].Length -gt 15) # if level is longer truncate to 8 characters
            {
                $pathList[$i] = $pathList[$i].substring(0,8)+"."
            }
        }

        #$dirStr = $pathList -join "-"
        # create new shortened name
        #$groupName = "$node-$($account)_$fs-$($path.replace('/','-'))_"+$accessLevel.replace('-','')
        

        $pathStr = ($fs,$pathList -join "-",$folderonly) -join "-"
        $groupName = "$node-$($account)_$($pathStr)_"+$accessLevel.replace('-','')

        if($groupName.Length -gt 120)
        {
            Write-Warning "Shortened group name stil exceeds 120 char limit!"
            $message += "Shortened group name stil exceeds 120 char limit!";
            return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
        }
    }
    Write-Verbose "Name $groupName"
    # Need additional logic here to determine potential conflicts/overlaps

    ####################
    # AAD Group get or create if new
    # https://docs.microsoft.com/en-us/azure/active-directory/users-groups-roles/groups-settings-v2-cmdlets
    # https://msazure.club/connect-to-azure-ad-from-azure-function-with-powershell-script/

    Write-Verbose "#AAD - Retrieving AAD group $groupname"
    $AADGroups = Get-AADGroups $groupName $GraphToken #Get-AzureADGroup -Filter "DisplayName eq '$groupName'"
    if(!$AADGroups) 
    {
        Write-Verbose "Not found $groupname, creating."
        $message += "Created group; "
        # Doesn't exist, create
        if($metadata){
            $metadata['path'] = $pathUrl
            $metadata['service'] = $account
        }
        $AADGroup = New-AADGroup $groupName $groupOwner $GraphToken "This group grants access to ADLS data assets under $account $fs $path" $metadata  
        
        if(!$AADGroup)
        {
            Write-Warning "Couldn't create AAD group $groupName";
            $message += "Couldn't create AAD group $groupName";
            return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
        }
        #Add-AzureADGroupOwner -ObjectId $AADGroup.ObjectId -RefObjectId $AADGroupOwner.ObjectId
    }
    elseif($AADGroup.count -gt 1)
    {
        Write-Warning "Found multiple groups named $groupName!"
        $message += "Found multiple groups named $groupName!";
        return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
    }
    else {
        $AADGroup = $AADGroups[0] # Select the first
        $message += "Found existing group; "
        Write-Verbose "Found $groupName $($AADGroup.id)"
    }
    
    ## Set group membership to parent group ref
    if(!([string]::IsNullOrEmpty($memberOf)) ){
        # if not already member, add as member
        if(!(Get-AADGroupMember $memberOf $($AADGroup.id) $GraphToken))
        {   
            Write-Verbose "Adding $($AADGroup.id) to $memberOf"
            $message += "Adding $($AADGroup.id) to $memberOf; "
            $AddedGroupMember = Add-AADGroupMember $memberOf $AADGroup.id $GraphToken
            if(!$AddedGroupMember)
            {
                Write-Warning "Couldn't add $($AADGroup.id) to $memberOf";
                $message += "Couldn't add $($AADGroup.id) to $memberOf";
                return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Failed"; Message = $message}
            }
        }
        else {
            Write-Verbose "$($AADGroup.id) already member of $memberOf"
        }
    }
    else {
        Write-Verbose "No parent set, skipping group membership for $($AADGroup.id)"
    }

    ####################
    # Assign AAD group permissions to items
    #$item.ACL.EntityId -contains $AADGroup.ObjectId
    # Check if AAD group already is present
    Write-Verbose "Checking ACL membership $path $aaccessLevel for $($AADGroup.id)"
    $idx = $item.ACL.EntityId.IndexOf($AADGroup.Id)

    # -1 = AAD-Group wasn't found in existing ACLs, i.e. go and create it
    if ($idx -eq -1)
    {
        Write-Verbose "Assigning $groupName [$accessLevel] to $fs : $path (recursive: $recursive)"
        Update-Acls -GroupRef $AADGroup.Id -Permission $accessLevel -ctx $ctx -FileSystem $fs -Path $path -IsDirectory $item.IsDirectory -Recursive $recursive
    } else {
        Write-Verbose "Group ($groupName) already present [$($item.ACL[$idx].Permissions)]"
    
        ## If to-be and current permissions same, do nothing.
        $currentAccessLevel = $item.ACL[$idx].GetSymbolicRolePermissions()
        if( $currentAccessLevel -eq $accessLevel)
        {
            Write-Verbose "Group to-be permissions identical ($accessLevel)."
            $message += "ACLs identical to existing; "
        } else {
            Write-Verbose "Updating permissions ($currentAccessLevel --> $accessLevel)."
            $message += "Updating permissions ($currentAccessLevel --> $accessLevel); "
            Update-Acls -GroupRef $AADGroup.Id -Permission $accessLevel -ctx $ctx -FileSystem $fs -Path $path -IsDirectory $item.IsDirectory -Recursive $recursive
        }
    }
    Write-Verbose "Finished DASG $path"
    return @{ GroupId = $AADGroup.Id; GroupName = $AADGroup.displayName; Path = $path; Access = $accessLevel; Recursive = $recursive; Create = $createIfNotExists; Browse = $browsableFromRoot; State = "Success"; Message = $message}
} # End of function

function Update-Acls
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$GroupRef,
        [Parameter(Mandatory=$true)]
        [string]$Permission,
        [Parameter(Mandatory=$true)]
        [Microsoft.WindowsAzure.Commands.Common.Storage.LazyAzureStorageContext]$ctx,
        [Parameter(Mandatory=$true)]
        [string]$FileSystem,
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [bool]$IsDirectory,
        [Parameter(Mandatory=$true)]
        [bool]$Recursive
    )

    $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityId $GroupRef -Permission $accessLevel 
    if($IsDirectory -And $Recursive)
    {
        # set default mask if item is a directory and recursive behaviour enabled
        $acl = Set-AzDataLakeGen2ItemAclObject -AccessControlType group -EntityId $AADGroup.Id -Permission $accessLevel -DefaultScope -InputObject $acl
    }

    $parameter = @{'FileSystem' = $filesystem; 'Context' = $ctx; 'Acl' = $acl }

    if(!([string]::IsNullOrEmpty($Path)) ){ #omit path parameter if dealing with root/filesystem level
        $parameter['Path'] = $Path
    }

    if($Recursive){
        $aclResult = Update-AzDataLakeGen2AclRecursive @parameter #-Context $ctx -FileSystem $filesystem -Path $Path -Acl $acl
    }
    else {
        $aclResult = Update-AzDataLakeGen2Item @parameter
    }


    if(!$aclResult )
    { Write-Warning "Couldn't assign ACLs to group." }

    if($aclResult.FailedEntries )
    {
        Write-Warning $aclResult.FailedEntries
        #Set-AzDataLakeGen2AclRecursive -Context $ctx -FileSystem $fs -Path $path -Acl $acl -ContinuationToken $aclResult.ContinuationToken
    }
} # End of function

Function Get-AADGroups([string[]] $groupNames, [securestring] $token) {

    $filterString = "`$filter="
    foreach ($group in $groupNames) {
        $filterString += "DisplayName+eq+`'$group`'+or+"
    }
    # remove last +or+
    $filterString = $filterString -replace "(.*)\+or\+(.*)",'$1$2'
    
    $GetAADGroupParams = @{
        Method = 'GET'
        Uri    = "https://graph.microsoft.com/v1.0/groups?$filterString"
        Headers = @{
            'Content-Type' = 'application/json'
            'Authorization' = "Bearer $(ConvertFrom-SecureString -SecureString $token -AsPlainText)"
        }
    }
    $GetAADGroup = try { Invoke-RestMethod @GetAADGroupParams -ErrorAction Stop }
    catch { # if response not 200
        Write-Warning $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription $_.Exception.Message $_
        return
    }

    $groupIdList = $GetAADGroup.value | Select-Object id, displayName
    return $groupIdList
}

Function New-AADGroup([string] $groupName, [hashtable] $owner, [securestring] $token, [string] $description, [hashtable] $schemaext) {

    $CreateAADGroupParams = @{
        Method = 'POST'
        Uri    = "https://graph.microsoft.com/v1.0/groups"
        Headers = @{
            'Content-Type' = 'application/json'
            'Authorization' = "Bearer $(ConvertFrom-SecureString -SecureString $token -AsPlainText)"
        }
        Body = @{
            'displayName' = $groupName
            'description' = $description
            'mailEnabled' = $false
            'MailNickName' = 'NotSet'
            'securityEnabled' = $true
            'groupTypes' = @()
            'owners@odata.bind' = @("https://graph.microsoft.com/v1.0/$($owner.type)/$($owner.id)")
        } #| ConvertTo-Json
    } #$($owner.type)

    if($schemaext){ 
        # if group schema extension metadata defined
        # schema has to be created in advance
        # https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
        $CreateAADGroupParams['body']['datajacuzzi_dasg'] = $schemaext
    }
    $CreateAADGroupParams.Body = $CreateAADGroupParams.Body | ConvertTo-Json

    $CreateAADGroup = try { Invoke-RestMethod @CreateAADGroupParams -ErrorAction Stop }
    catch { # if response not 200
        Write-Warning $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription $_.Exception.Message $_
        return
    }

    return $CreateAADGroup | Select-Object id, displayName
}

Function Add-AADGroupMember([string] $parentGroupId, [string] $childGroupId, [securestring] $token) {
    Write-Verbose "Adding $childGroupId to $parentGroupId"
    $AddMemberParams = @{
        Method = 'POST'
        Uri    = "https://graph.microsoft.com/v1.0/groups/$parentGroupId/members/`$ref"
        Headers = @{
            'Content-Type' = 'application/json'
            'Authorization' = "Bearer $(ConvertFrom-SecureString -SecureString $token -AsPlainText)"
        }
        Body = @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$childGroupId"
        } | ConvertTo-Json
    }

    try { Invoke-RestMethod @AddMemberParams -ErrorAction Stop }
    catch { # if response not 200
        Write-Warning $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription $_.Exception.Message $_
        return 1
    }

    return 0
}

Function Get-AADGroupMember([string] $parentGroupId, [string] $childGroupId, [securestring] $token) {
    #https://docs.microsoft.com/en-us/graph/api/group-checkmemberobjects?view=graph-rest-1.0&tabs=http#examples
    Write-Verbose "Checking $childGroupId member of $parentGroupId"

    $CheckMemberParams = @{
        Method = 'POST'
        Uri    = "https://graph.microsoft.com/v1.0/groups/$childGroupId/checkMemberObjects"
        Headers = @{
            'Content-Type' = 'application/json'
            'Authorization' = "Bearer $(ConvertFrom-SecureString -SecureString $token -AsPlainText)"
        }
        Body = @{
            "ids" = @("$parentGroupId")
        } | ConvertTo-Json
    }

    $members = try { Invoke-RestMethod @CheckMemberParams -ErrorAction Stop }
    catch { # if response not 200
        Write-Warning $_.Exception.Response.StatusCode.value__ $_.Exception.Response.StatusDescription $_.Exception.Message $_
        return 1
    }

    if($members.value){
        # check the returned list contains the Id of the group
        return $members.value.Contains($parentGroupId)
    }
    else {
        return $false
    }
}