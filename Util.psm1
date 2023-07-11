New-Variable -Name PIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Global -Force

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

Export-ModuleMember -Variable PIRGSOU -Function *
