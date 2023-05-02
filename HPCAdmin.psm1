New-Variable -Name PIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Script -Force

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
  Get the next OU path for the Pirg.

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

    Write-Error "Invalid Pirg object used"
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

    Write-Error "Invalid User object used"
}

###############################
###  Pirg Management        ###
###############################

<#
 .Synopsis
  Get the details of a PIRG.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG AD groups from our PIRGS OU.

 .Parameter Name
  The name of the PIRG to get details for.

 .Example
   # Get the hpcrcf PIRG AD group details.
   Get-Pirg -Name hpcrcf
#>
function Get-Pirg {
    param(
        [Parameter(Mandatory = $true)]
        $Name,

        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]
        [PSCredential] $Credential
    )

    $PirgName = Get-CleansedPirgName $Name
    $PirgFullName = "is.racs.pirg.$PirgName"

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

    Get-ADGroup -Properties "*" -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU @params
}

<#
 .Synopsis
  Get the details of a PIRG owner group.

 .Description
  Simple wrapper for Get-ADGroup for getting PIRG owner AD groups from our PIRGS OU.

 .Parameter Name
  The name of the PIRG to get owner details for.

 .Example
   # Get the hpcrcf owner PIRG AD group details.
   Get-PirgOwnerGroup -Pirg hpcrcf
#>
function Get-PirgOwnerGroup {
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

    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
}

<#
 .Synopsis
  Set the user to the owner of the PIRG.

 .Description
  Sets the user as the only user in the PIRG PI group

 .Parameter Pirg
  The name of the PIRG.

 .Parameter User
  Username of the user to set.

 .Example
   # Set Mark as the owner on the hpcrcf PIRG.
   Set-PirgOwner -Pirg hpcrcf -User marka
#>
function Set-PirgOwner {
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

    Write-Output "getting pirg owner group for: $PirgName"
    $GroupObject = Get-PirgOwnerGroup -Pirg $PirgName @params
    if (!($GroupObject)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember -Identity $GroupObject | ForEach-Object { Remove-ADGroupMember -Identity $GroupObject $_ @params -Confirm:$false }
    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
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

    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject @params -Confirm:$false
}


###############################
###  Pirg Group Management  ###
###############################

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
    $PirgPath = Get-PirgPath -Name $PirgName

    $PirgGroupFullName = "is.racs.pirg.$PirgName.$PirgGroupName"

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties * -Filter "name -like '$PirgGroupFullName'" -SearchBase $PirgPath @params
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
        Write-Error "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
        return
    }

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $PirgPath = Get-PirgPath -Name $PirgName

    $ExistingGroup = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName
    if ($ExistingGroup) {
        Write-Output "PIRG Group already exists"
        return
    }

    $PirgExists = Get-Pirg -Name $PirgName
    if (!($PirgExists)) {
        Write-Output "PIRG not found"
        return
    }

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    New-ADGroup -Name "is.racs.pirg.$PirgName.$PirgGroupName" -Path $PirgPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal
}


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
        Write-Output "PIRG Group not found"
        return
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
        Write-Output "User not found"
        return
    }

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName @params
    if (!($GroupObject)) {
        Write-Output "PIRG Group not found"
        return
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
        Write-Output "User not found"
        return
    }

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Group $PirgGroupName @params
    if (!($GroupObject)) {
        Write-Output "PIRG Group not found"
        return
    }
    

    Remove-ADGroupMember -Identity $GroupObject -Members $UserObject -Confirm:$false @params
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