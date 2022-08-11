param (
    [string]$baseFolder = $( Read-Host "Input base folder path, please" ),
    [string]$jsonConfig = $( Read-Host "Input json config path, please" ),
    [string]$itAdminGroup = "MEDINCELL\Grp_IT_ADM"
 )

$accountITAdminGroup = New-Object System.Security.Principal.NTAccount("$itAdminGroup")

$sharePointJSON = Get-Content $jsonConfig -Raw

$sharePointDefinition = ConvertFrom-Json -InputObject $sharePointJSON

$manageACLLastReturnValue

Import-Module "PSCX"
Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeRestorePrivilege", $true) #Necessary to set Owner Permissions
Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeBackupPrivilege", $true) #Necessary to bypass Traverse Checking
Set-Privilege (new-object Pscx.Interop.TokenPrivilege "SeTakeOwnershipPrivilege", $true) #Necessary to override FilePermissions & take Ownership

function manageACL($folderPath, $withInerithence, $readOnlyGroups, $modifyGroups) {
    Write-Host "- Managing ACL for $folderPath"

    if ( -not (Test-Path $folderPath) ) {
        mkdir $folderPath > $null

        Write-Host "- Set ownership to $accountITAdminGroup"

        $aclObject = New-Object System.Security.AccessControl.DirectorySecurity

        $aclObject.SetOwner($accountITAdminGroup)

        Set-Acl $folderPath $aclObject
    }

    $aclObject = (Get-Item $folderPath).GetAccessControl("Access")

    $inheritanceFlag
    $propagationFlag 
    $accessType = [System.Security.AccessControl.AccessControlType]::Allow
    $readOnly = [System.Security.AccessControl.FileSystemRights]"ReadAndExecute" 
    $modify = [System.Security.AccessControl.FileSystemRights]"Modify" 
    $write = [System.Security.AccessControl.FileSystemRights]"Write" 
    $fullControl = [System.Security.AccessControl.FileSystemRights]"FullControl" 

    if ($withInerithence) {
        Write-Host "- Rights will be set for subfolder too"
        $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    } else {
        Write-Host "- Rights will be set for this folder only"
        $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::None
        $propagationFlag = [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
    }

    Write-Host "- Remove all existing rights"
    
    $aclObject.Access | %{$aclObject.RemoveAccessRule($_) > $null}

    $aclObject.SetAccessRuleProtection($true, $false)

    $aclObject.Access | %{Write-Host $_}
   
    Write-Host "- Start adding rights (duplicates will be simplified by the system)"
    if ( $readOnlyGroups -ne $null ) { 
        foreach($readOnlyGroup in $readOnlyGroups) {
            if ( $readOnlyGroup -ne $null ) {
                Write-Host "-- Add read only access to $readOnlyGroup"
                $accountForReadOnly = New-Object System.Security.Principal.NTAccount("$readOnlyGroup") 

                $aceObject = New-Object System.Security.AccessControl.FileSystemAccessRule($accountForReadOnly, $readOnly, $inheritanceFlag, $propagationFlag, $accessType)

                $aclObject.AddAccessRule($aceObject)
            }
        }
    }

    if ( $modifyGroups -ne $null ) { 
        foreach($modifyGroup in $modifyGroups) {
            if ( $modifyGroup -ne $null ) {
                Write-Host "-- Add read and write access to $modifyGroup"
                $accountForReadAndWrite = New-Object System.Security.Principal.NTAccount("$modifyGroup") 

                $aceObject = New-Object System.Security.AccessControl.FileSystemAccessRule($accountForReadAndWrite, $modify, $inheritanceFlag, [System.Security.AccessControl.PropagationFlags]::InheritOnly, $accessType)

                $aclObject.AddAccessRule($aceObject)

                $aceObject = New-Object System.Security.AccessControl.FileSystemAccessRule($accountForReadAndWrite, $readOnly, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit, $accessType)

                $aclObject.AddAccessRule($aceObject)

                $aceObject = New-Object System.Security.AccessControl.FileSystemAccessRule($accountForReadAndWrite, $write, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit, $accessType)

                $aclObject.AddAccessRule($aceObject)
            }
        }
    }

    foreach($fullControlGroup in "NT AUTHORITY\SYSTEM", $itAdminGroup) {
            Write-Host "-- Add full control to $fullControlGroup"
            $accountForFullControll = New-Object System.Security.Principal.NTAccount("$fullControlGroup") 
            
            $aceObject = New-Object System.Security.AccessControl.FileSystemAccessRule($accountForFullControll, $fullControl, $inheritanceFlag, $propagationFlag, $accessType)

            $aclObject.AddAccessRule($aceObject)
    }

    Set-Acl $folderPath $aclObject

    Write-Host "- End of ACL management"

}

function manageACLDefintion($folderPath, $contentInfo) {
    
    if ((Get-Member -InputObject $contentInfo -Name "ro" -MemberType NoteProperty) -or (Get-Member -InputObject $contentInfo -Name "rw" -MemberType NoteProperty)) {
        Write-Host "Working on leaf folder $folderPath"
        
        $listOfReadOnlyGroups = $contentInfo.ro
        $listOfReadAndWriteGroups = $contentInfo.rw

        manageACL $folderPath $true $listOfReadOnlyGroups $listOfReadAndWriteGroups

        return ($listOfReadOnlyGroups + $listOfReadAndWriteGroups)
    } else {
        Write-Host "Working on node folder $folderPath"

        $readOnlyAndNoInheritGroups = $null

        foreach($subFolder in ($contentInfo | Get-Member -MemberType NoteProperty).Name) {
            $subFolderPath = "$folderPath\$subFolder"
            $subContentInfo = $contentInfo."$subFolder"
            $subgroups = manageACLDefintion $subFolderPath $subContentInfo

            if ( $subgroups -ne $null ) {
                if ( $readOnlyAndNoInheritGroups -ne $null ) {
                    $readOnlyAndNoInheritGroups += $subgroups
                } else {
                    $readOnlyAndNoInheritGroups = $subgroups
                }
            }
        }

        if ( $readOnlyAndNoInheritGroups -ne $null ) {
            manageACL $folderPath $false $readOnlyAndNoInheritGroups $null
        }

        return $readOnlyAndNoInheritGroups
    }

}

manageACLDefintion $baseFolder $sharePointDefinition > $null