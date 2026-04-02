[CmdletBinding()]
param()


Trace-VstsEnteringInvocation $MyInvocation
try {
    $goodStatuses = @("Completed")
    $badStatuses = @("Errored", "Cancelled", "Failed")
    $validStatuses = @()
    $validStatuses+=$goodStatuses
    $validStatuses+=$badStatuses

    function Get-StatusCodeFromException {
        param($Exception)

        $resolvedException = $Exception
        if ($Exception -is [System.Management.Automation.ErrorRecord]) {
            $resolvedException = $Exception.Exception
        }

        if ($null -eq $resolvedException) {
            return $null
        }

        if ($resolvedException.PSObject.Properties['Response'] -and $null -ne $resolvedException.Response -and $resolvedException.Response.PSObject.Properties['StatusCode']) {
            return [int]$resolvedException.Response.StatusCode
        }

        if ($resolvedException.PSObject.Properties['Exception'] -and $null -ne $resolvedException.Exception -and $resolvedException.Exception.PSObject.Properties['Response'] -and $null -ne $resolvedException.Exception.Response -and $resolvedException.Exception.Response.PSObject.Properties['StatusCode']) {
            return [int]$resolvedException.Exception.Response.StatusCode
        }

        return $null
    }

    function Get-DorcAccessToken {
        param(
            [string]$TokenUrl,
            [hashtable]$Headers,
            [hashtable]$FormData
        )

        $tokenResult = Invoke-WebRequest -Uri $TokenUrl -Method POST -Headers $Headers -Body $FormData -UseBasicParsing
        return $tokenResult.Content | ConvertFrom-Json
    }

    function Refresh-DorcAccessToken {
        param(
            [string]$TokenUrl,
            [hashtable]$Headers,
            [hashtable]$FormData,
            [int]$RefreshWindowSeconds = 120
        )

        $tokenResponse = Get-DorcAccessToken -TokenUrl $TokenUrl -Headers $Headers -FormData $FormData
        $expiresIn = 3600
        if ($tokenResponse.PSObject.Properties['expires_in'] -and $tokenResponse.expires_in) {
            $expiresIn = [int]$tokenResponse.expires_in
        }

        $safeExpiryIn = [Math]::Max(($expiresIn - $RefreshWindowSeconds), 30)
        $expiresAt = (Get-Date).AddSeconds($safeExpiryIn)
        Write-Host "DOrc access token refreshed. Valid for approx $safeExpiryIn seconds."

        return @{
            AccessToken = $tokenResponse.access_token
            ExpiresAt = $expiresAt
        }
    }

    function Ensure-DorcAccessToken {
        param(
            [hashtable]$TokenState,
            [string]$TokenUrl,
            [hashtable]$Headers,
            [hashtable]$FormData
        )

        if (-not $TokenState.ContainsKey('AccessToken') -or -not $TokenState.ContainsKey('ExpiresAt') -or -not $TokenState.AccessToken -or (Get-Date) -ge $TokenState.ExpiresAt) {
            $newToken = Refresh-DorcAccessToken -TokenUrl $TokenUrl -Headers $Headers -FormData $FormData
            $TokenState.AccessToken = $newToken.AccessToken
            $TokenState.ExpiresAt = $newToken.ExpiresAt
        }
    }

    Import-VstsLocStrings "$PSScriptRoot\Task.json"

    # Get task variables.
    #[bool]$debug = Get-VstsTaskVariable -Name System.Debug -AsBool

    # Get the inputs.
    [string]$baseurl = Get-VstsInput -Name baseurl -Require
    [string]$DorcIDSsecret = Get-VstsInput -Name DorcIDSsecret -Require    
    [string]$project = Get-VstsInput -Name project -Require
    [string]$targetenv = Get-VstsInput -Name targetenv -Require
    [string]$buildtext = Get-VstsInput -Name buildtext -Default $null
    [string]$buildnum = Get-VstsInput -Name buildnum  -Default $null
    [string]$components = Get-VstsInput -Name components -Require
    [bool]$pinned = Get-VstsInput -Name pinned -AsBool -Default $false
    [string]$builduri = Get-VstsInput -Name builduri -Default $null
    [string]$vstfsUrl = Get-VstsInput -Name vstfsUrl -Default $null

    #receiving the token from IDS for DORC
    $baseurl = $baseurl.TrimEnd('/')
    Write-Host "DorcApiUrl is:" $baseurl
    $IDSHeaders = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    $IDSFormData = @{
        "grant_type" = "client_credentials"
        "client_id" = "dorc-cli"
        "client_secret" = "$DorcIDSsecret"
        "scope" = "dorc-api.manage"
    }
    $IDSBaseURL = Invoke-WebRequest -Uri "$baseurl/ApiConfig" -UseBasicParsing | ConvertFrom-Json
    $IDSBaseURL = $IDSBaseURL.OAuthAuthority +"/connect/token"
    Write-Host "IDSBaseURL is:" $IDSBaseURL
    $tokenState = @{}
    Ensure-DorcAccessToken -TokenState $tokenState -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData

    $DorcAPIHeaders = @{}
    $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

    # Code 
    $requestUrl = $baseurl+"/Request"
    
    $request = [ordered]@{
        Project= "$project"
        Environment = "$targetenv"
        BuildUrl = "$builduri"
        BuildText = "$buildtext"
        BuildNum = "$buildnum"
        Pinned = $pinned
        VstsUrl = "$vstfsUrl"
        Components = @($components.Split(";"))
    }
    $jsonRequest = ConvertTo-Json $request
    Write-Host $jsonRequest
    try {
        $result = Invoke-RestMethod -Method POST -Uri $requestUrl -Body $jsonRequest -ContentType "application/json" -Headers $DorcAPIHeaders
    }
    catch {
        $statusCode = Get-StatusCodeFromException -Exception $_
        if ($statusCode -eq 401) {
            Write-Host "Received 401 from DOrc API while creating request. Refreshing token and retrying once."
            $newToken = Refresh-DorcAccessToken -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
            $tokenState.AccessToken = $newToken.AccessToken
            $tokenState.ExpiresAt = $newToken.ExpiresAt
            $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

            try {
                $result = Invoke-RestMethod -Method POST -Uri $requestUrl -Body $jsonRequest -ContentType "application/json" -Headers $DorcAPIHeaders
            }
            catch {
                throw
            }
        }
        else {
            throw
        }
    }
    
    if ($result.Id -gt 0){
        Write-Host "Request " $result.Id " was created"
        $itemUrl=$requestUrl+"?id="+$result.Id
        $oldStatus = ""
        while (-not $validStatuses.Contains($oldStatus)){
            Start-Sleep -Seconds 5

            Ensure-DorcAccessToken -TokenState $tokenState -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
            $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

            try {
                $r=Invoke-RestMethod -Method GET -Uri $itemUrl -Headers $DorcAPIHeaders
            }
            catch {
                $statusCode = Get-StatusCodeFromException -Exception $_
                if ($statusCode -eq 401) {
                    Write-Host "Received 401 from DOrc API. Refreshing token and retrying once."
                    $newToken = Refresh-DorcAccessToken -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
                    $tokenState.AccessToken = $newToken.AccessToken
                    $tokenState.ExpiresAt = $newToken.ExpiresAt
                    $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"
                    $r=Invoke-RestMethod -Method GET -Uri $itemUrl -Headers $DorcAPIHeaders
                }
                else {
                    throw
                }
            }

            if ($oldStatus -ne $r.Status) {
                Write-Host "Request " $result.Id " is changed status to " $r.Status
                $oldStatus=$r.Status
            }            
        }
        Write-Host "Collecting deploy results"
        if (-not $goodStatuses.Contains($oldStatus)){
            $message= "Execution finished with status: "+$oldStatus
            $id=$result.Id
            $uri=$baseurl + "/ResultStatuses?requestId=$id"
            $r = Invoke-WebRequest -Uri $uri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
            $cmps = ConvertFrom-Json -InputObject $r.Content
            foreach ($cmp in $cmps) {
                Write-Host "<|=======================================================================|>"
                Write-Host "<|               "$cmp.ComponentName $cmp.Status
                Write-Host "<|=======================================================================|>"
                Write-Host $cmp.Log
            }
            Write-VstsSetResult -Result "Failed" -Message $message
        }else {
            $message= "Execution finished with status: "+$oldStatus
            $id=$result.Id
            $uri=$baseurl + "/ResultStatuses?requestId=$id"
            $r = Invoke-WebRequest -Uri $uri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
            $cmps = ConvertFrom-Json -InputObject $r.Content
            foreach ($cmp in $cmps) {
                Write-Host "<|=======================================================================|>"
                Write-Host "<|               "$cmp.ComponentName $cmp.Status
                Write-Host "<|=======================================================================|>"
                Write-Host $cmp.Log
            }
            Write-VstsSetResult -Result "Succeeded" -Message $message
        }
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}