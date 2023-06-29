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