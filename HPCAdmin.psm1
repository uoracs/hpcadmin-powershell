New-Variable -Name PIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Global -Force

<#
 .Synopsis
  Show the help.

 .Description
  Shows a summary of useful functions in the module.
#>
function Show-HPCAdminHelp {
    Write-Host ""
    Write-Host "Pirg Management"
    Write-Host "      Getting PIRG Objects          |  Modifying PIRG Objects"
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "      Get-Pirg                      |  New-Pirg"
    Write-Host "      Get-Pirgs                     |  Remove-Pirg"
    Write-Host "      Get-PirgPIGroup"
    Write-Host "      Get-PirgAdminGroup"
    Write-Host ""
    Write-Host "Pirg User Management"
    Write-Host "      Getting PIRG Users            |  Modifying PIRG Users"
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "      Get-PirgUsers                 |  Add-PirgUser"
    Write-Host "      Get-PirgUsernames             |  Remove-PirgUser"
    Write-Host "      Get-PirgPIUser                |  Set-PirgPI"
    Write-Host "      Get-PirgAdmins                |  Add-PirgAdmin"
    Write-Host "                                    |  Remove-PirgAdmin"
    Write-Host ""
    Write-Host "Pirg SubGroup Management"
    Write-Host "      Getting PIRG Group Objects    |  Modifying PIRG Group Objects"
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "      Get-PirgGroup                 |  New-PirgGroup"
    Write-Host "      Get-PirgGroups                |  Remove-PirgGroup"
    Write-Host ""
    Write-Host "Pirg Group User Management"
    Write-Host "      Getting PIRG Group Users      |  Modifying PIRG Group Users"
    Write-Host "--------------------------------------------------------------------------------"
    Write-Host "      Get-PirgGroupUsers            |  Add-PirgGroupUser"
    Write-Host "      Get-PirgGroupUsernames        |  Remove-PirgGroupUser"
    Write-Host ""
    Write-Host "To see more available functions, use `Get-Command -Module HPCAdmin`. For more"
    Write-Host "information on a specific function, use `Get-Help FUNCTIONNAME`."
    Write-Host ""
}


###############################
#####   #PIRGManagement   #####
###############################

<#
 .Synopsis
  Get the details of a PIRG. This returns null if the PIRG is not found.

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
    }
    else {
        $PirgNameRegex = "[a-zA-Z0-9_]+"
    }
    # just the pirg group
    if (!($IncludeGroups)) {
        Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object { $_.Name -match "^is\.racs\.pirg\.$PirgNameRegex$" }
    }
    # return all groups starting with is.racs.pirg.
    else {
        Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object { $_.Name -match "^is\.racs\.pirg\.$PirgNameRegex" }
    }
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

    Get-ADGroup -Properties "*" -Filter "*" -SearchBase $PIRGSOU @params | Where-Object { $_.samaccountname -match $filter }
}

<#
 .Synopsis
  Get the details of a PIRG PI group. This returns null if the group is not found.

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

    $group = Get-ADGroup -Properties "*" -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU @params
    if (!($group)) {
        throw "PIRG admin group not found: $PirgFullName"
    }
    return $group
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
        throw "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $PirgName = Get-CleansedPirgName $Name

    $ExistingGroup = Get-Pirg -Name $PirgName @params
    if ($ExistingGroup) {
        throw "PIRG already exists: $PirgName"
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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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
        throw "PIRG not found: $PirgName"
    }

    $PirgPath = Get-PirgPath $PirgName

    $PirgGroups = Get-ADGroup -Filter * -SearchBase $PirgPath
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
  This will error if the PIRG is not found.

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
        throw "PIRG not found: $PirgName"
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
  Get the PI user of a PIRG.

 .Description
  Returns the user object of the PI of the PIRG.

 .Parameter Pirg
  The name of the PIRG to get PI user for.

 .Example
   # Get the bgmp PI user.
   Get-PirgPIUser -Pirg bgmp
#>
function Get-PirgPIUser {
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

    $PIGroup = Get-ADGroup -Properties "*" -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU @params
    if (!($PIGroup)) {
        throw "PIRG PI group not found"
    }
    Get-ADGroupMember -Identity $PIGroup @params
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

    $GroupObject = Get-PirgAdminGroup -Pirg $PirgName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember $GroupObject @params
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
        throw "User not found: $UserName"
    }

    $GroupObject = Get-Pirg -Name $PirgName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
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

    # TODO(lcrown): check if they're the PI, and warn/exit if so

    $PirgName = Get-CleansedPirgName $Pirg
    $UserName = Get-CleansedUserName $User

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        throw "User not found: $UserName"
    }

    $GroupObject = Get-Pirg -Name $PirgName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Remove-PirgAdmin -Pirg $PirgName -User $UserName
    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
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
        throw "User not found: $UserName"
    }

    $GroupObject = Get-PirgPIGroup -Pirg $PirgName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
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
        throw "User not found: $UserName"
    }

    $PirgAdminGroupName = $PirgName + ".admins"
    $GroupObject = Get-Pirg -Name $PirgAdminGroupName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # add user to admin group
    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
    # and add them to the pirg users
    Add-PirgUser -Pirg $PirgName -User $UserName @params
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
        throw "User not found: $UserName"
    }

    $PirgAdminGroupName = $PirgName + ".admins"
    $GroupObject = Get-Pirg -Name $PirgAdminGroupName @params
    if (!($GroupObject)) {
        throw "PIRG not found: $PirgName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # This is safe if the user isn't a member of the group
    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
}

####################################
#####   #PirgGroupManagement   #####
####################################

<#
 .Synopsis
  Get the details of a PIRG Group.

 .Description
  Simple wrapper for Get-ADGroup for getting a PIRG Group from our PIRG-specific OU.

 .Parameter Pirg
  The name of the PIRG this group belongs to.

 .Parameter Name
  The name of the PIRG Group to get details for.

 .Example
   # Get the "students" group details in the "hpcrcf" PIRG.
   Get-PirgGroup -Pirg hpcrcf -Group students
#>
function Get-PirgGroup {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Group,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $PirgGroupPath = Get-PirgGroupPath -Pirg $PirgName

    $PirgGroupFullName = "is.racs.pirg.$PirgName.$PirgGroupName"

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties * -Filter "name -like '$PirgGroupFullName'" -SearchBase $PirgGroupPath @params
}

<#
 .Synopsis
  Get all PIRG Groups associated with a PIRG.

 .Description
  Returns a list of AD Group objects of PirgGroups for a given PIRG.

 .Parameter Pirg
  The name of the PIRG to get groups for.

 .Example
   # Get all the Pirg Groups for the "hpcrcf" PIRG.
   Get-PirgGroups -Pirg hpcrcf
#>
function Get-PirgGroups {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupPath = Get-PirgGroupPath -Name $PirgName

    $PirgFullName = "is.racs.pirg.$PirgName"

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties * -Filter * -SearchBase $PirgGroupPath @params
}

<#
 .Synopsis
  Create a new PIRG Group.

 .Description
  Create a new AD group in the PIRG-specific OU. The resulting group name will be "is.racs.pirg.PIRG.NAME. These groups are used for Unix permissions on Talapas."

 .Parameter Pirg
  The name of the PIRG to add the group to.

 .Parameter Group
  The name of the Group, limited to alphanumeric characters. This name will be converted to all lowercase for creation.

 .Example
   # Create the "students" Group in the "hpcrcf" PIRG.
   New-PirgGroup -Pirg hpcrcf -Group students
#>
function New-PirgGroup {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Group,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    if (!($Group -cmatch "^[a-z][a-z0-9_]+[a-z0-9]$")) {
        throw "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
    }

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $PirgGroupPath = Get-PirgGroupPath -Name $PirgName

    $ExistingGroup = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName
    if ($ExistingGroup) {
        throw "PIRG Group already exists: $PirgGroupName"
    }

    $PirgExists = Get-Pirg -Name $PirgName
    if (!($PirgExists)) {
        throw "PIRG not found: $PirgName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    # create the Groups OU if it doesn't exist
    $maybe_ou = Get-ADOrganizationalUnit -Identity $PirgGroupPath @params
    if (!($maybe_ou)) {
        New-ADOrganizationalUnit -Name "Groups" -Path $PirgGroupPath @params
    }

    New-ADGroup -Name "is.racs.pirg.$PirgName.$PirgGroupName" -Path $PirgGroupPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal
}

# TODO(lcrown): Remove-PirgGroup


<#
 .Synopsis
  Get users in a PIRG Group.

 .Description
  Return a list of all AD users in a PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Group
  The name of the PIRG Group.

 .Example
   # Get all users in the "hpcrcf.students" PIRG Group
   Get-PirgUsers -Pirg hpcrcf -Group students
#>
function Get-PirgGroupUsers {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Name,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName
    if (!($GroupObject)) {
        throw "PIRG Group not found: $PirgName.$PirgGroupName"
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember $GroupObject @params
}

<#
 .Synopsis
  Get list of usernames in a PIRG Group.

 .Description
  Return a list of username strings in a PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Group
  The name of the PIRG Group.

 .Example
   # Get all users in the "hpcrcf.students" PIRG Group
   Get-PirgUsernames -Pirg hpcrcf -Group students
#>
function Get-PirgGroupUsernames {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Group,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-PirgGroupUsers -Pirg $Pirg -Group $Group $params | Select-Object -Property samaccountname
}


<#
 .Synopsis
  Add user to PIRG Group.

 .Description
  Add the given AD user object to the PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Group
  The name of the PIRG Group.

 .Parameter User
  Username of the user to add.

 .Example
   # Add Mark to the staff group in the hpcrcf PIRG.
   Add-PirgUser -Pirg hpcrcf -Group staff -User marka
#>
function Add-PirgGroupUser {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Group,

        [Parameter(Mandatory = $true)]
        [String] $User,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $UserName = $User.ToLower()

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        throw "User not found: $UserName"
    }

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName @params
    if (!($GroupObject)) {
        throw "PIRG Group not found: $PirgName.$PirgGroupName"
    }


    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
}

<#
 .Synopsis
  Remove user from PIRG Group.

 .Description
  Remove the given AD user object from the PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Group
  The name of the PIRG Group.

 .Parameter User
  Username of the user to remove.

 .Example
   # Remove Mark from the staff group in the hpcrcf PIRG.
   Remove-PirgUser -Pirg hpcrcf -Group staff -User marka
#>
function Remove-PirgGroupUser {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg,

        [Parameter(Mandatory = $true)]
        [String] $Group,

        [Parameter(Mandatory = $true)]
        [String] $User,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $UserName = $User.ToLower()

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $UserObject = Get-ADUser $UserName @params
    if (!($UserObject)) {
        throw "User not found: $UserName"
    }

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName @params
    if (!($GroupObject)) {
        throw "PIRG Group not found : $PirgName.$PirgGroupName"
    }


    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject -Confirm:$false @params
}


###############################
###  Manifest Import        ###
###############################

<#
 .Synopsis
  Get manifest data from an HPCAdmin server.

 .Description
  Manifest contains all pirg membership data from HPCAdmin. This manifest is then imported with Import-HPCAdminManifest.

 .Parameter URL
  The URL of the HPCAdmin server manifest export endpoint.

 .Example
   # Get a manifest
   Get-HPCAdminManifest -URL "https://hpcadmin.example.org/export/memberships"
#>
function Get-HPCAdminManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$URL,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        return Invoke-WebRequest $URL | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to fetch manifest from ${URL}"
        Write-Error $_
        throw
    }
}

<#
 .Synopsis
  Get current manifest hash if it exists.

 .Description
  Returns the current manifest data hash from disk.
  Manifest data contains a hash that serves as a version number.
  If our saved hash doesn't match the server hash, we know to import the manifest data.
  If they match, we can exit without doing any work.

 .Parameter Location
  The filesystem location to the hash file.
  By default, it's %appdata%/HPCAdmin/manifest-hash

 .Example
   # Get the current manifest hash
   Get-HPCAdminManifestHash
#>
function Get-HPCAdminManifestHash {
    param(
        $Location = "%appdata%\HPCADMIN\manifest-hash",

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    try {
        $hash = Get-Content $Location
        return $hash.Trim()
    }
    catch {
        return ""
    }
}
<#
 .Synopsis
  Save HPCAdmin manifest hash.

 .Description
  Saves the specified hash data to disk.

 .Parameter Hash
  The hash as a string.

 .Parameter Location
  The filesystem location to the hash file.
  By default, it's %appdata%/HPCAdmin/manifest-hash

 .Example
   # Save a manifest hash
   Save-HPCAdminManifestHash -Hash 2a097269
#>
function Save-HPCAdminManifestHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash,

        $Location = "%appdata%\HPCADMIN\manifest-hash",

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    try {
        New-Item -Path $Location -ItemType File -Force
        Add-Content -Path $Location -Value $Hash
    }
    catch {
        Write-Error "Failed to write to path ${Location}"
        Write-Error $_
        throw
    }
}

<#
 .Synopsis
  Import HPCAdmin manifest data

 .Description
  Synchronizes AD with manifest data from an HPCAdmin server.

 .Parameter URL
  The URL of the HPCAdmin server manifest export endpoint.

 .Example
   # Synchronize with AD
   Import-HPCAdminManifest -URL "https://hpcadmin.example.org/export/memberships"

 .Example
   # Synchronize with AD, custom local hash location
   Import-HPCAdminManifest -URL "https://hpcadmin.example.org/export/memberships" -Location "C:\Users\foo\hash"
#>
function Import-HPCAdminManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$URL,

        [string]$Location = "%appdata%\HPCADMIN\manifest-hash",

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $manifest_data = Get-HPCAdminManifest -URL $URL
    $manifest_current_hash = Get-HPCAdminManifestHash -Location $Location

    # return early if the hashes match. no work to be done.
    if ($manifest_data.Hash -eq $manifest_current_hash) {
        return
    }

    # example payload
    # {
    #   "generated_date": "2020-11-24 15:00:00",
    #   "hash": "c8c6d6e7f3a2b6e5a",
    #   "version": "1.0.0",
    #   "data": {
    #     "pirgs": [
    #       {
    #         "name": "dufeklab",
    #         "owner": "jdufek",
    #         "admins": ["lcrown", "marka", "jill"],
    #         "users": ["john", "jack", "mary", "steve", "jill"],
    #         "groups": [
    #           {
    #             "name": "students",
    #             "users": ["john", "jack", "mary"]
    #           },
    #           {
    #             "name": "instructors",
    #             "users": ["steve", "jill"]
    #           }
    #         ]
    #       }
    #     ]
    #   }
    # }
    foreach ($pirg in $manifest_data.data.pirgs) {
        # create the pirg if it doesn't exist
        try {
            $pirg_obj = Get-Pirg -Name $pirg.name
        }
        catch {
            $pirg_obj = New-Pirg -Name $pirg.name -Owner $pirg.owner
        }
        # set the owner if it doesn't match
        $owner = Get-PirgPIUser -Pirg $pirg_obj
        try {
            $new_owner = Get-ADUser -Identity $pirg.owner
        }
        catch {
            Write-Error "Failed to find user ${pirg.owner}"
            Write-Error $_
            continue
        }
        if ($owner.DistinguishedName -ne $new_owner.DistinguishedName) {
            Set-PirgPI -Pirg $pirg_obj -User $new_owner
        }
        # get the list of existing admins
        $admins = Get-PirgAdmins -Pirg $pirg_obj
        # compare to the list of admins in the payload
        $new_admins = @()
        foreach ($admin in $pirg.admins) {
            try {
                $new_admin = Get-ADUser -Identity $admin
            }
            catch {
                Write-Error "Failed to find user ${admin}"
                Write-Error $_
                continue
            }
            $new_admins += $new_admin
        }
        # go through new admins and add them if they don't exist in ad
        foreach ($new_admin in $new_admins) {
            if ($admins -notcontains $new_admin) {
                Add-PirgAdmin -Pirg $pirg_obj -User $new_admin
            }
        }
        # go through old admins and remove them if they don't exist in the manifest
        foreach ($admin in $admins) {
            if ($new_admins -notcontains $admin) {
                Remove-PirgAdmin -Pirg $pirg_obj -User $admin
            }
        }

        # get the list of existing users
        $users = Get-PirgUsers -Pirg $pirg_obj
        # compare to the list of users in the payload
        $new_users = @()
        foreach ($user in $pirg.users) {
            try {
                $new_user = Get-ADUser -Identity $user
            }
            catch {
                Write-Error "Failed to find user ${user}"
                Write-Error $_
                continue
            }
            $new_users += $new_user
        }
        # go through new users and add them if they don't exist in ad
        foreach ($new_user in $new_users) {
            if ($users -notcontains $new_user) {
                Add-PirgUser -Pirg $pirg_obj -User $new_user
            }
        }
        # go through old users and remove them if they don't exist in the manifest
        foreach ($user in $users) {
            if ($new_users -notcontains $user) {
                Remove-PirgUser -Pirg $pirg_obj -User $user
            }
        }

        # create the pirg groups if they don't exist
        $pirg_groups = Get-PirgGroups -Pirg $pirg_obj
        foreach ($new_pg in $pirg.groups) {
            foreach ($pg in $pirg_groups) {
                $short_name = Get-PirgGroupShortName -Group $pg
                if ($short_name -eq $new_pg.name) {
                    continue 2
                }
            }
            New-PirgGroup -Pirg $pirg_obj -Name $new_pg.name
        }

        # delete the pirg groups if they don't exist in the manifest
        foreach ($pg in $pirg_groups) {
            $short_name = Get-PirgGroupShortName -Group $pg
            foreach ($new_pg in $pirg.groups) {
                if ($short_name -eq $new_pg.name) {
                    continue 2
                }
            }
            Remove-PirgGroup -Pirg $pirg_obj -Group $pg
        }

        #TODO(lcrown): add/remove users from pirg groups


    }




    # if success, we save the hash
    Save-HPCAdminManifestHash -Hash $manifest_data.Hash -Location $Location
}

#####################
#####   #Util   #####
#####################

<#
 .Synopsis
  Get the next available HPC gidNumber.

 .Description
  Returns the next available gidNumber in the RACS gid range (300,000 - 400,000).
#>
function Get-NextPirgGid {
    param(
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )
    return (Get-ADGroup -Properties gidNumber -SearchBase $PIRGSOU -Filter "*" @params | Select-Object gidNumber | Sort-Object -Property gidNumber | Select-Object -Last 1).gidNumber + 1
}

<#
 .Synopsis
  Get the OU path for the Pirg.

 .Description
  Returns the full path to the Pirg's OU

 .Parameter Name
  The name of the PIRG to get OU path for.
#>
function Get-PirgPath {
    param(
        [Parameter(Mandatory = $true)]
        [String] $Name
    )
    return "ou=" + $Name + "," + $PIRGSOU
}

<#
 .Synopsis
  Get the OU path for the Pirg Groups.

 .Description
  Returns the full path to the Pirg's Groups OU

 .Parameter Name
  The name of the PIRG to get OU path for.
#>
function Get-PirgGroupPath {
    param(
        [Parameter(Mandatory = $true)]
        [String] $Pirg
    )
    return "ou=Groups,ou=${Pirg},${PIRGSOU}"
}


<#
 .Synopsis
  Cleanses Pirg name

 .Description
  Returns short name of pirg no matter the type of input object

 .Parameter Pirg
  Pirg to get name for. Can be string or ADGroup object
#>
function Get-CleansedPirgName {
    param(
        [Parameter(Mandatory = $true)]
        $Pirg
    )

    if ($Pirg.GetType().Name -eq "ADGroup") {
        return $Pirg.Name.split(".")[-1].ToLower()
    }

    if ($Pirg.GetType().Name -eq "String") {
        if ($Pirg.contains(".")) {
            return $Pirg.split(".")[-1].ToLower()
        }
        return $Pirg.ToLower()
    }

    throw "Invalid Pirg object used. Must be either string or ADGroup"
}

<#
 .Synopsis
  Cleanses User name

 .Description
  Returns username of user no matter the type of input object

 .Parameter User
  User to get username for. Can be string or ADUser object
#>
function Get-CleansedUserName {
    param(
        [Parameter(Mandatory = $true)]
        $User
    )

    if ($User.GetType().Name -eq "ADUser") {
        return [string]$User.samaccountname
    }

    if ($User.GetType().Name -eq "String") {
        return $User.ToLower()
    }

    throw "Invalid User object used. Must be either string or ADUser"
}

<#
 .Synopsis
  Get the existing gidNumber for the Pirg.

 .Description
  Returns the gidNumber of the Pirg AD group

 .Parameter Name
  The name of the PIRG to get OU path for.
#>
function Get-PirgGidNumber {
    param(
        [Parameter(Mandatory = $true)]
        [String] $Name
    )
    $PirgName = Get-CleansedPirgName $Name
    Get-Pirg -Name $PirgName | Select-Object gidNumber
}

<#
 .Synopsis
  Get the short name for a given Pirg Group.

 .Description
  Returns the last element of the Pirg Group's name separated by periods.

 .Parameter Group
  The PIRG Group object.
#>
function Get-PirgGroupShortName {
    param(
        [Parameter(Mandatory = $true)]
        [psobject] $Group
    )
    return $Group.Name.split(".")[-1]
}



###############################
###  Misc Tools             ###
###############################

<#
 .Synopsis
  Get email list for Talapas users.

 .Description
  Returns a list of email addresses of all users of Talapas.
#>
function Get-TalapasUserEmailList {
    param(
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $emailList = [System.Collections.ArrayList]::new()
    foreach ($pirg in (Get-Pirgs @params)) {
        foreach ($user in (Get-PirgUsers -Pirg $pirg @params)) {
            $user = Get-ADUser $user -Properties mail @params
            if (!($emailList.Contains($user.mail))) {
                [void]$emailList.Add($user.mail)
            }
        }
    }

    $emailString = $emailList -join ";"
    Write-Output $emailString
}

<#
 .Synopsis
  Get email list for Talapas admins.

 .Description
  Returns a list of email addresses of all admins of PIRGs on Talapas.
#>
function Get-TalapasAdminEmailList {
    param(
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    $emailList = [System.Collections.ArrayList]::new()
    foreach ($pirg in (Get-Pirgs @params)) {
        foreach ($user in (Get-PirgAdmins -Pirg $pirg @params)) {
            $user = Get-ADUser $user -Properties mail @params
            if (!($emailList.Contains($user.mail))) {
                [void]$emailList.Add($user.mail)
            }
        }
    }

    $emailString = $emailList -join ";"
    Write-Output $emailString
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
