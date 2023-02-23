New-Variable -Name PIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Script -Force

<#
 .Synopsis
  Get the next available HPC gidNumber.

 .Description
  Returns the next available gidNumber in the RACS gid range (300,000 - 400,000).
#>
function Get-NextPirgGid {
    return (Get-ADGroup -Properties gidNumber -SearchBase $PIRGSOU -Filter * | Select-Object gidNumber | Sort-Object -Property gidNumber | Select-Object -Last 1).gidNumber + 1
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
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    $PirgName = $Name.ToLower()

    $PirgFullName = "is.racs.pirg.$PirgName"
    Get-ADGroup -Properties * -Filter "name -like '$PirgFullName'" -SearchBase $PIRGSOU
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
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    if (!($Name -cmatch "^[a-z][a-z0-9_][a-z0-9]+$")) {
        Write-Error "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
        return
    }

    $PirgName = $Name.ToLower()

    $ExistingGroup = Get-Pirg -Name $PirgName
    if ($ExistingGroup) {
        Write-Output "PIRG already exists, exiting."
        return
    }

    New-ADGroup -Name "is.racs.pirg.$PirgName" -Path $PIRGSOU -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
}

<#
 .Synopsis
  Get users in a PIRG.

 .Description
  Return a list of all AD users in a PIRG.

 .Parameter Name
  The name of the PIRG.

 .Example
   # Get all users in the "hpcrcf" PIRG
   Get-PirgUsers -Name hpcrcf 
#>
function Get-PirgUsers {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    $PirgName = $Name.ToLower()

    $GroupObject = Get-Pirg -Name $PirgName
    if (!($GroupObject)) {
        Write-Output "PIRG not found, exiting."
        return
    }

    Get-ADGroupMember $GroupObject
}

<#
 .Synopsis
  Get list of usernames in a PIRG.

 .Description
  Return a list of username strings in a PIRG.

 .Parameter Name
  The name of the PIRG.

 .Example
   # Get a list of username strings in the "hpcrcf.students" PIRG Group
   Get-PirgUsernames -Pirg hpcrcf -Name students
#>
function Get-PirgUsernames {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    Get-PirgUsers -Pirg $Pirg -Name $Name | Select-Object -Property samaccountname
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
        [Parameter(Mandatory=$true)]
        [String] $Pirg,

        [Parameter(Mandatory=$true)]
        [String] $User
    )

    $PirgName = $Pirg.ToLower()
    $UserName = $User.ToLower()

    $UserObject = Get-ADUser $UserName
    if (!($UserObject)) {
        Write-Output "User not found, exiting."
        return
    }

    $GroupObject = Get-Pirg -Name $PirgName
    if (!($GroupObject)) {
        Write-Output "PIRG not found, exiting."
        return
    }

    Add-ADGroupMember -Identity $GroupObject -Members $UserObject
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
   Get-PirgGroup -Pirg hpcrcf -Name students
#>
function Get-PirgGroup {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Pirg,

        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    $PirgName = $Pirg.ToLower()
    $PirgGroupName = $Name.ToLower()

    $PirgGroupFullName = "is.racs.pirg.$PirgName.$PirgGroupName"
    Get-ADGroup -Properties * -Filter "name -like '$PirgGroupFullName'" -SearchBase $PIRGSOU
}

<#
 .Synopsis
  Create a new PIRG Group.

 .Description
  Create a new AD group in the PIRG-specific OU. The resulting group name will be "is.racs.pirg.PIRG.NAME. These groups are used for Unix permissions on Talapas."

 .Parameter Pirg
  The name of the PIRG to add the group to.

 .Parameter Name
  The name of the Group, limited to alphanumeric characters. This name will be converted to all lowercase for creation.

 .Example
   # Create the "students" Group in the "hpcrcf" PIRG.
   New-PirgGroup -Pirg hpcrcf -Name students
#>
function New-PirgGroup {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Pirg,

        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    if (!($Name -cmatch "^[a-z][a-z0-9_][a-z0-9]+$")) {
        Write-Error "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
        return
    }

    $PirgName = $Pirg.ToLower()
    $PirgGroupName = $Name.ToLower()

    $ExistingGroup = Get-PirgGroup -Pirg $PirgName -Name $PirgGroupName
    if ($ExistingGroup) {
        Write-Output "PIRG Group already exists, exiting."
        return
    }

    $PirgExists = Get-Pirg -Name $PirgName
    if (!($PirgExists)) {
        Write-Output "PIRG not found, exiting."
        return
    }

    New-ADGroup -Name "is.racs.pirg.$PirgName.$PirgGroupName" -Path $PIRGSOU -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
}


<#
 .Synopsis
  Get users in a PIRG Group.

 .Description
  Return a list of all AD users in a PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Name
  The name of the PIRG Group.

 .Example
   # Get all users in the "hpcrcf.students" PIRG Group
   Get-PirgUsers -Pirg hpcrcf -Name students
#>
function Get-PirgGroupUsers {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Pirg,
        
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    $PirgName = $Pirg.ToLower()
    $PirgGroupName = $Name.ToLower()

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Name $PirgGroupName
    if (!($GroupObject)) {
        Write-Output "PIRG Group not found, exiting."
        return
    }
    Get-ADGroupMember $GroupObject
}

<#
 .Synopsis
  Get list of usernames in a PIRG Group.

 .Description
  Return a list of username strings in a PIRG Group.

 .Parameter Pirg
  The name of the PIRG.

 .Parameter Name
  The name of the PIRG Group.

 .Example
   # Get all users in the "hpcrcf.students" PIRG Group
   Get-PirgUsernames -Pirg hpcrcf -Name students
#>
function Get-PirgGroupUsernames {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Pirg,
        
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    Get-PirgGroupUsers -Pirg $Pirg -Name $Name | Select-Object -Property samaccountname
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
        [Parameter(Mandatory=$true)]
        [String] $Pirg,

        [Parameter(Mandatory=$true)]
        [String] $Group,

        [Parameter(Mandatory=$true)]
        [String] $User
    )

    $PirgName = $Pirg.ToLower()
    $PirgGroupName = $Group.ToLower()
    $UserName = $User.ToLower()

    $UserObject = Get-ADUser $UserName
    if (!($UserObject)) {
        Write-Output "User not found, exiting."
        return
    }

    $GroupObject = Get-PirgGroup -Pirg $PirgName -Name $PirgGroupName
    if (!($GroupObject)) {
        Write-Output "PIRG Group not found, exiting."
        return
    }

    Add-ADGroupMember -Identity $GroupObject -Members $UserObject
}