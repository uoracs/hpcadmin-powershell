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
    # TODO(lcrown): ensure user exists in pirg group first
    # TODO(lcrown): remove from admin group
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

    # TODO(lcrown): check admins group and remove user from that group too

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
    # TODO(lcrown): ensure user exists in pirg group first
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

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroupMember -Identity $GroupObject | ForEach-Object { Remove-ADGroupMember -Identity $GroupObject $_ @params -Confirm:$false }
    Add-ADGroupMember -Identity $GroupObject -Members $UserObject @params
    Add-PirgAdmin $UserObject
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
    # TODO(lcrown): ensure user exists in pirg group first
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
    $PirgPath = Get-PirgPath -Name $PirgName

    $PirgFullName = "is.racs.pirg.$PirgName"
    $ExcludeGroups = ($PirgFullName, "$PirgFullname.admins", "$PirgFullname.pi")

    $params = @{}
    if ($Credential) { $params['Credential'] = $Credential }

    Get-ADGroup -Properties * -Filter * -SearchBase $PirgPath @params | Where-Object { $_.Name -notin $ExcludeGroups }
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

    # TODO(lcrown): create a "Groups" OU inside the pirg OU if groups are used. keeps it clean and away from the primary 3 groups.
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

    }




    # if success, we save the hash
    Save-HPCAdminManifestHash -Hash $manifest_data.Hash -Location $Location
}