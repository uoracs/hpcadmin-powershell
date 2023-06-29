<#
 .Synopsis
  Get the details of a PIRG.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG AD groups from our PIRGS OU.

 .Parameter Name
  The name of the PIRG to get details for.

 .Parameter IncludeGroups
  Use this to return all the PIRG subgroups as well.

 .Example
   # Get the hpcrcf PIRG AD group details.
   Get-Pirg -Name hpcrcf

 .Example
   # Get all hpcrcf PIRG and PirgGroup AD group details.
   Get-Pirg -Name hpcrcf -IncludeGroups

 .Example
   # Get all PIRG AD groups.
   Get-Pirg
#>
function Get-Pirg {
    param(
        [string] $Name = "",
        [switch] $IncludeGroups = $false,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # if name is passed, limit to just that pirg
    if ($Name.length -gt 0) {
        $PirgNameRegex = Get-CleansedPirgName $Name
    } else {
        $PirgNameRegex = "[a-zA-Z0-9_]+"
    }
    # just the pirg group
    if (!($IncludeGroups)) {
        Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object { $_.Name -match "^is\.racs\.pirg\.$PirgNameRegex$"}
        return
    # return everything
    } else {
        Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object { $_.Name -match "^is\.racs\.pirg\.$PirgNameRegex(\.[a-zA-Z0-9_]+)?$"}
        return
    }
}

<#
 .Synopsis
  Get the details of a PIRG admin group.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG admin AD groups from our PIRGS OU.

 .Parameter Name
  The name of the PIRG to get admin details for.

 .Example
   # Get the hpcrcf admin PIRG AD group details.
   Get-PirgAdminGroup -Pirg hpcrcf
#>
function Get-PirgAdminGroup {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgFullName = "is.racs.pirg.$PirgName.admins"

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties "*" -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU @params
}

<#
 .Synopsis
  Get the details of a PIRG PI group.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG PI AD groups from our PIRGS OU.

 .Parameter Name
  The name of the PIRG to get PI details for.

 .Example
   # Get the racs PI PIRG AD group details.
   Get-PirgPIGroup -Pirg hpcrcf
#>
function Get-PirgPIGroup {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgFullName = "is.racs.pirg.$PirgName.pi"

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties "*" -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU @params
}

<#
 .Synopsis
  Get list of PIRG user groups.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG AD groups from our PIRGS OU.
#>
function Get-Pirgs {
    param(
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $filter = '^is\.racs\.pirg\.\w+$'

    Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object {$_.samaccountname -match $filter}
}


<#
 .Synopsis
  Create a new PIRG.

 .Description
  Create a new AD group in the PIRGs OU. The resulting group name will be "is.racs.pirg.NAME"

 .Parameter Name
  The name of the PIRG using only alphanumeric characters. This will be converted to lowercase during creation.

 .Example
   # Create the "test" PIRG
   New-Pirg -Name test
#>
function New-Pirg {
    param(
        [Parameter(Mandatory = $true)]
        [String] $Name,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    if (!($Name -cmatch "^[a-z][a-z0-9_]+[a-z0-9]$")) {
        Write-Error "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Name

    $ExistingGroup = Get-Pirg -Name $PirgName @params
    if ($ExistingGroup) {
        Write-Output "PIRG already exists"
        return
    }

    New-ADOrganizationalUnit -Name $PirgName -Path $PIRGSOU @params

    $PirgPath = Get-PirgPath -Name $PirgName

    New-ADGroup -Name "is.racs.pirg.$PirgName" -Path $PirgPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal @params
    New-ADGroup -Name "is.racs.pirg.$PirgName.pi" -Path $PirgPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal @params
    New-ADGroup -Name "is.racs.pirg.$PirgName.admins" -Path $PirgPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal @params
    Add-ADGroupMember -Identity is.racs.talapas.users -Members "is.racs.pirg.$PirgName"
}

<#
 .Synopsis
  Delete a PIRG.

 .Description
  Delete all groups and OU related to the PIRG.

 .Parameter Name
  The name of the PIRG.

 .Example
   # Remove the "test" PIRG
   Remove-Pirg -Name test
#>
function Remove-Pirg {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param(
        [Parameter(Mandatory = $true)]
        $Name,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Name

    $ExistingGroup = Get-Pirg -Name $PirgName @params
    if (!($ExistingGroup)) {
        Write-Output "PIRG not found: $PirgName"
        return
    }

    $PirgPath = Get-PirgPath $PirgName

    $PirgGroups = Get-ADgroup -Filter * -SearchBase $PirgPath
    foreach ($group in $PirgGroups) {
        # just extra safety
        if ($group.name.startswith("is.racs.pirg")) {
            Remove-ADGroup -Identity $group -Confirm:$false
        }
    }
    Get-ADOrganizationalUnit -Identity $PirgPath | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADOrganizationalUnit -Confirm:$false
}

<#
 .Synopsis
  Get users in a PIRG.

 .Description
  Return a list of all AD users in a PIRG.

 .Parameter Pirg
  The name of the PIRG.

 .Example
   # Get all users in the "hpcrcf" PIRG
   Get-PirgUsers -Pirg hpcrcf 
#>
function Get-PirgUsers {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg

    $GroupObject = Get-Pirg -Name $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember $GroupObject @params
}

<#
 .Synopsis
  Get admins of a PIRG.

 .Description
  Return a list of all AD users that are admins of a PIRG.

 .Parameter Pirg
  The name of the PIRG.

 .Example
   # Get all admins in the "hpcrcf" PIRG
   Get-PirgAdmins -Pirg hpcrcf 
#>
function Get-PirgAdmins {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg

    $GroupObject = Get-PirgAdminGroup -Name $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember $GroupObject @params
}

<#
 .Synopsis
  Get list of usernames in a PIRG.

 .Description
  Return a list of username strings in a PIRG.

 .Parameter Pirg
  The name of the PIRG.

 .Example
   # Get a list of username strings in the "racs" PIRG 
   Get-PirgUsernames -Pirg racs 
#>
function Get-PirgUsernames {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-PirgUsers -Pirg $PirgName @params | Select-Object -Property samaccountname
}

<#
 .Synopsis
  Add user to PIRG.

 .Description
  Add the given AD user object to the PIRG.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to add.

 .Example
   # Add Mark to the hpcrcf PIRG.
   Add-PirgUser -Pirg hpcrcf -User marka
#>
function Add-PirgUser {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        $User,
        
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        Write-Output "User not found"
        return
    }

    $GroupObject = Get-Pirg -Name $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
}


<#
 .Synopsis
  Remove user from PIRG.

 .Description
  Remove the given AD user object from the PIRG.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to remove.

 .Example
   # Remove Mark from the hpcrcf PIRG.
   Remove-PirgUser -Pirg hpcrcf -User marka
#>
function Remove-PirgUser {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        $User,
        
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        Write-Output "User not found"
        return
    }

    $GroupObject = Get-Pirg -Name $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Remove-PirgAdmin -Pirg $PirgName -User $UserName
    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
}

<#
 .Synopsis
  TEMP - Sync pirg membership with data from is-hpc-idm-txn

 .Description
  TEMP - Sync pirg membership with is-hpc-idm-txn

 .Parameter Pirg
  The name of the PIRG.

 .Example
   # Sync members for racs
   Sync-PirgMembers -Pirg racs 
#>
function Sync-PirgMembers {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $pirgJSON = Invoke-WebRequest -Uri "http://is-hpc-idm-txn.uoregon.edu/migrationdata/$PirgName"
    $pirgData = ConvertFrom-Json $pirgJSON.content

    foreach ($user in $pirgData.users) {
        Write-Output "Syncing $($user.username)"
        Add-PirgUser -Pirg $PirgName -User $user.username
    }
}

<#
 .Synopsis
  Set the user to the PI of the PIRG.

 .Description
  Sets the user as the only user in the PIRG PI group

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to set.

 .Example
   # Set Mark as the PI on the racs PIRG.
   Set-PirgPI -Pirg racs -User marka
#>
function Set-PirgPI {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        $User,
        
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        Write-Output "User not found"
        return
    }

    $GroupObject = Get-PirgPIGroup -Pirg $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $PirgObject = Get-Pirg -Pirg $PirgName @params

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # remove all the members of the PI group
    Get-ADGroupMember -Identity $GroupObject | ForEach-Object { Remove-ADGroupMember -Identity $GroupObject $_ @params -Confirm:$false }
    # add this user as the only user to that group
    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
    # the PI should also be an admin
    Add-PirgAdmin -Pirg $PirgObject -User $UserObject @params
    # and a user
    Add-PirgUser -Pirg $PirgObject -User $UserObject @params
}

<#
 .Synopsis
  Add user to PIRG admins.

 .Description
  Add the given AD user object to the PIRG admins group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to add.

 .Example
   # Add Mark as an admin to the hpcrcf PIRG.
   Add-PirgAdmin -Pirg hpcrcf -User marka
#>
function Add-PirgAdmin {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        $User,
        
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        Write-Output "User not found"
        return
    }

    $PirgAdminGroupName = $PirgName + ".admins"
    $GroupObject = Get-Pirg -Name $PirgAdminGroupName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
}

<#
 .Synopsis
  Remove user from PIRG admins.

 .Description
  Remove the given AD user object from the PIRG admins group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to remove.

 .Example
   # Remove Mark as an admin from the hpcrcf PIRG.
   Remove-PirgAdmin -Pirg hpcrcf -User marka
#>
function Remove-PirgAdmin {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        $User,
        
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        Write-Output "User not found"
        return
    }

    $PirgAdminGroupName = $PirgName + ".admins"
    $GroupObject = Get-Pirg -Name $PirgAdminGroupName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # This is safe if the user isn't a member of the group
    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
}