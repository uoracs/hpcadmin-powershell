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
        Write-Error "Name must be lowercase alphanumeric, start with a letter, and may contain underscores"
        return
    }

    $PirgName = Get-CleansedPirgName $Pirg
    $PirgGroupName = $Group.ToLower()
    $PirgGroupPath = Get-PirgGroupPath -Name $PirgName

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

    # create the Groups OU if it doesn't exist
    $maybe_ou = Get-ADOrganizationalUnit -Identity $PirgGroupPath @params
    if (!($maybe_ou)) {
        New-ADOrganizationalUnit -Name "Groups" -Path $PirgGroupPath @params
    }

    New-ADGroup -Name "is.racs.pirg.$PirgName.$PirgGroupName" -Path $PirgGroupPath -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid) } -GroupCategory Security -GroupScope Universal
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