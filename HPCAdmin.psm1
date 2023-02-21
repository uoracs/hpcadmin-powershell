New-Variable -Name ALLPIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Script -Force

<#
 .Synopsis
  Get the next available HPC gidNumber.

 .Description
  Returns the next available gidNumber in the RACS gid range (300,000 - 400,000).
#>
function Get-NextPirgGid {
    # Returns the next available gidNumber in the RACS gid range (300,000 - 400,000)
    return (Get-ADGroup -Properties gidNumber -SearchBase $ALLPIRGSOU -Filter * | Select-Object gidNumber | Sort-Object -Property gidNumber | Select-Object -Last 1).gidNumber + 1
}

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

    $PirgName = $Pirg.ToLower()

    $PirgFullName = "is.racs.pirg.$PirgName"
    Get-ADGroup -Properties * -Filter "name -like '$PirgFullName'" -SearchBase $ALLPIRGSOU
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
        [ValidatePattern("^[a-z0-9]+$")]
        [String] $Name
    )

    $PirgName = $Pirg.ToLower()

    $ExistingGroup = Get-Pirg -Name $PirgName
    if ($ExistingGroup) {
        Write-Output "PIRG already exists, exiting."
        return
    }


    New-ADOrganizationalUnit -Name $PirgName -Path $ALLPIRGSOU
    New-ADGroup -Name "is.racs.pirg.$PirgName" -Path "ou=$PirgName,$ALLPIRGSOU" -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
}

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
    Get-ADGroup -Properties * -Filter "name -like '$PirgGroupFullName'" -SearchBase $ALLPIRGSOU
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
        [ValidatePattern("^[a-z0-9]+$")]
        [String] $Name
    )

    $PirgName = $Pirg.ToLower()
    $PirgGroupName = $Name.ToLower()

    $ExistingGroup = Get-PirgGroup -Pirg $PirgName -Name $PirgGroupName
    if ($ExistingGroup) {
        Write-Output "PIRG Group already exists, exiting."
        return
    }

    $PirgExists = Get-Pirg -Name $PirgName
    if (!($PirgExists)) {
        Write-Output "PIRG does not exist, exiting."
        return
    }

    New-ADGroup -Name "is.racs.pirg.$PirgName.$PirgGroupName" -Path "ou=$PirgName,$ALLPIRGSOU" -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
}

