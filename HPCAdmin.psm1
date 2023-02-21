New-Variable -Name ALLPIRGSOU -Value "ou=PIRGS,ou=RACS,ou=Groups,ou=IS,ou=units,dc=ad,dc=uoregon,dc=edu" -Scope Script -Force

<#
 .Synopsis
  Get the next available HPC gidNumber.

 .Description
  Returns the next available gidNumber in the RACS gid range (300,000 - 400,000).
#>
function Get-NextPirgGid {
    # Returns the next available gidNumber in the RACS gid range (300,000 - 400,000)
    return (Get-ADGroup -Properties gidNumber -SearchBase $ALLPIRGSOU -Filter * | Select-Object gidNumber | Sort-Object | Select-Object -Last 1).gidNumber + 1
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
    $GroupName = "is.racs.pirg.$Name"
    Get-ADGroup -Properties * -Filter "name -like '$GroupName'" -SearchBase $ALLPIRGSOU
}


<#
 .Synopsis
  Create a new PIRG.

 .Description
  Create a new AD group in the PIRGs OU. The resulting group name will be "is.racs.pirg.NAME"

 .Parameter Name
  The name of the PIRG using only [a-zA-Z].

 .Example
   # Create the "test" PIRG
   New-Pirg -Name test
#>
function New-Pirg {
    param(
        [Parameter(Mandatory=$true)]
        [ValidatePattern('[a-zA-Z]')]
        [String] $Name
    )
    $ExistingGroup = Get-Pirg -Name $Name
    if ($ExistingGroup) {
        Write-Output "PIRG already exists, exiting."
        return
    }

    New-ADOrganizationalUnit -Name $Name -Path $ALLPIRGSOU
    New-ADGroup -Name "is.racs.pirg.$Name" -Path "ou=$Name,$ALLPIRGSOU" -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
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

    $PirgGroupName = "is.racs.pirg.$Pirg.$Name"
    Get-ADGroup -Properties * -Filter "name -like '$PirgGroupName'" -SearchBase $ALLPIRGSOU
}

<#
 .Synopsis
  Create a new PIRG Group.

 .Description
  Create a new AD group in the PIRG-specific OU. The resulting group name will be "is.racs.pirg.PIRG.NAME. These groups are used for Unix permissions on Talapas."

 .Parameter Pirg
  The name of the PIRG to add the group to.

 .Parameter Name
  The name of the Group using only [a-zA-Z].

 .Example
   # Create the "students" Group in the "hpcrcf" PIRG.
   New-PirgGroup -Pirg hpcrcf -Name students
#>
function New-PirgGroup {
    param(
        [Parameter(Mandatory=$true)]
        [String] $Pirg,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('[a-zA-Z]')]
        [String] $Name
    )

    $ExistingGroup = Get-PirgGroup -Pirg $Pirg -Name $Name
    if ($ExistingGroup) {
        Write-Output "PIRG Group already exists, exiting."
        return
    }

    $PirgExists = Get-Pirg -Name $Pirg
    if (!($PirgExists)) {
        Write-Output "PIRG does not exist, exiting."
    }

    New-ADGroup -Name "is.racs.pirg.$Pirg.$name" -Path "ou=$Pirg,$ALLPIRGSOU" -OtherAttributes @{"gidNumber" = $(Get-NextPirgGid)} -GroupCategory Security -GroupScope Universal
}

