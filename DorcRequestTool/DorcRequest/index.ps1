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

function Get-ApiErrorMessage {
        param($Exception)

        # Try ErrorDetails first (PowerShell 6+)
        if ($Exception.ErrorDetails) {
            if ($Exception.ErrorDetails.Message) {
                try {
                    $parsed = ConvertFrom-Json -InputObject $Exception.ErrorDetails.Message -ErrorAction SilentlyContinue
                    if ($parsed.Message) {
                        return $parsed.Message
                    }
                    if ($parsed.message) {
                        return $parsed.message
                    }
                    if ($parsed.error_description) {
                        return $parsed.error_description
                    }
                    if ($parsed -is [string]) {
                        return $parsed
                    }
                    return ($parsed | ConvertTo-Json)
                }
                catch {
                    return $Exception.ErrorDetails.Message
                }
            }
        }

        # Try to access response body from WebException (PowerShell < 6)
        if ($Exception.Exception -is [System.Net.WebException]) {
            try {
                $webEx = $Exception.Exception
                if ($webEx.Response -and $webEx.Response.GetType().Name -eq "HttpWebResponse") {
                    $stream = $webEx.Response.GetResponseStream()
                    if ($stream) {
                        $reader = [System.IO.StreamReader]::new($stream)
                        $responseBody = $reader.ReadToEnd()
                        $reader.Dispose()
                        if ($responseBody) {
                            try {
                                $parsed = ConvertFrom-Json -InputObject $responseBody -ErrorAction SilentlyContinue
                                if ($parsed.Message) {
                                    return $parsed.Message
                                }
                                if ($parsed.message) {
                                    return $parsed.message
                                }
                                if ($parsed.error_description) {
                                    return $parsed.error_description
                                }
                                return ($parsed | ConvertTo-Json)
                            }
                            catch {
                                return $responseBody
                            }
                        }
                    }
                }
            }
            catch {
                # Silently continue if response extraction fails
            }
        }

        # Fallback to exception message
        if ($Exception.Exception.Message) {
            return $Exception.Exception.Message
        }

        if ($Exception.Message) {
            return $Exception.Message
        }

        return $null
    }

    function Normalize-ApiErrorMessage {
        param([string]$Message)

        if (-not $Message) {
            return $Message
        }

        # Convert escaped apostrophe unicode to a visible quote style expected in pipeline logs.
        $normalized = $Message -replace '\\u0027', '"'

        # Preserve multiline output by converting escaped line breaks to actual line breaks.
        $normalized = $normalized -replace '\\r\\n', "`r`n"
        $normalized = $normalized -replace '\\n', "`n"
        $normalized = $normalized -replace '\\r', "`r"

        return $normalized
    }

    function Convert-DorcLogForDisplay {
        param([string]$LogText)

        if (-not $LogText) {
            return $LogText
        }

        $displayText = $LogText

        # If API returned a JSON string (quoted with escaped newlines), deserialize first.
        try {
            $parsed = ConvertFrom-Json -InputObject $displayText -ErrorAction Stop
            if ($parsed -is [string]) {
                $displayText = $parsed
            }
        }
        catch {
            # Keep original text if it is not JSON.
        }

        # Fallback: unescape common escaped sequences so logs keep line breaks in output.
        if ($displayText -match '\\r\\n|\\n|\\t') {
            try {
                $displayText = [System.Text.RegularExpressions.Regex]::Unescape($displayText)
            }
            catch {
                # Keep as-is if unescape fails.
            }
        }

        return $displayText
    }

    function Get-DorcAccessToken {
        param(
            [string]$TokenUrl,
            [hashtable]$Headers,
            [hashtable]$FormData
        )

        $tokenResult = Invoke-WebRequest -Uri $TokenUrl -Method POST -Headers $Headers -Body $FormData -UseBasicParsing
        $parsed = $tokenResult.Content | ConvertFrom-Json
        if (-not $parsed.access_token) {
            throw "Token response did not contain an access_token. Response: $($tokenResult.Content)"
        }
        return $parsed
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

    # Fetch a single component's log, transparently refreshing the token on a 401.
    # Returns the log content as a string, or throws for non-401 failures (e.g. 404 when no log exists yet).
    function Get-DorcComponentLog {
        param(
            [string]$LogUri,
            [hashtable]$TokenState,
            [string]$TokenUrl,
            [hashtable]$IDSHeaders,
            [hashtable]$IDSFormData,
            [hashtable]$DorcAPIHeaders
        )

        try {
            Ensure-DorcAccessToken -TokenState $TokenState -TokenUrl $TokenUrl -Headers $IDSHeaders -FormData $IDSFormData
            $DorcAPIHeaders["Authorization"] = "Bearer $($TokenState.AccessToken)"
            return (Invoke-WebRequest -Uri $LogUri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing).Content
        }
        catch {
            if ((Get-StatusCodeFromException -Exception $_) -eq 401) {
                $newToken = Refresh-DorcAccessToken -TokenUrl $TokenUrl -Headers $IDSHeaders -FormData $IDSFormData
                $TokenState.AccessToken = $newToken.AccessToken
                $TokenState.ExpiresAt = $newToken.ExpiresAt
                $DorcAPIHeaders["Authorization"] = "Bearer $($TokenState.AccessToken)"
                return (Invoke-WebRequest -Uri $LogUri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing).Content
            }
            throw
        }
    }

    # Print only the portion of a component's log that hasn't been printed yet, tailing it live.
    # $LengthState tracks chars already emitted per component; $HeaderState tracks whether the banner was shown.
    function Write-ComponentLogDelta {
        param(
            [string]$Name,
            [string]$LogContent,
            [hashtable]$LengthState,
            [hashtable]$HeaderState
        )

        if ($null -eq $LogContent) { return }

        $printed = 0
        if ($LengthState.ContainsKey($Name)) { $printed = $LengthState[$Name] }

        # If the log was rewritten shorter than what we've seen, reprint from the start.
        if ($LogContent.Length -lt $printed) { $printed = 0 }
        if ($LogContent.Length -le $printed) { return }

        if (-not $HeaderState.ContainsKey($Name)) {
            Write-Host "<|=======================================================================|>"
            Write-Host ("<|  {0}  |>" -f $Name)
            Write-Host "<|=======================================================================|>"
            $HeaderState[$Name] = $true
        }
        # Offsets are tracked against the raw log; convert only the new chunk for display.
        Write-Host (Convert-DorcLogForDisplay -LogText $LogContent.Substring($printed))
        $LengthState[$Name] = $LogContent.Length
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
    [int]$pollIntervalSeconds = Get-VstsInput -Name pollIntervalSeconds -AsInt -Default 2
    if ($pollIntervalSeconds -lt 1) { $pollIntervalSeconds = 1 }

    #receiving the token from IDS for DORC
    $baseurl = $baseurl.TrimEnd('/')
    Write-Host "DorcApiUrl is:" $baseurl
    $IDSHeaders = @{
        "Content-Type" = "application/x-www-form-urlencoded"
    }
    $IDSFormData = @{
        "grant_type" = "client_credentials"
        "client_id" = "dorc-cli"
        "client_secret" = $DorcIDSsecret
        "scope" = "dorc-api.manage"
    }
    try {
        $apiConfigResponse = Invoke-WebRequest -Uri "$baseurl/ApiConfig" -UseBasicParsing
        $apiConfig = ConvertFrom-Json -InputObject $apiConfigResponse.Content
    }
    catch {
        Write-VstsSetResult -Result "Failed" -Message "Failed to fetch or parse DOrc API config from '$baseurl/ApiConfig': $($_.Exception.Message)"
        return
    }
    if (-not $apiConfig.OAuthAuthority) {
        Write-VstsSetResult -Result "Failed" -Message "DOrc API config did not return an OAuthAuthority value."
        return
    }
    $IDSBaseURL = $apiConfig.OAuthAuthority.TrimEnd('/') + "/connect/token"
    Write-Host "IDSBaseURL is:" $IDSBaseURL
    $tokenState = @{}
    Ensure-DorcAccessToken -TokenState $tokenState -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData

    $DorcAPIHeaders = @{}
    $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

    # Code 
    $requestUrl = $baseurl+"/Request"
    
    $request = [ordered]@{
        Project = $project
        Environment = $targetenv
        Pinned = $pinned
        Components = @($components.Split(";") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    }
    if ($builduri) { $request["BuildUrl"] = $builduri }
    if ($buildtext) { $request["BuildText"] = $buildtext }
    if ($buildnum) { $request["BuildNum"] = $buildnum }
    if ($vstfsUrl) { $request["VstsUrl"] = $vstfsUrl }
    $jsonRequest = ConvertTo-Json $request -Depth 5
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
                $apiError = Get-ApiErrorMessage -Exception $_

                # If still generic, attempt to read full response body from exception.
                if (-not $apiError -or $apiError -like "*Bad Request*") {
                    try {
                        if ($_.ErrorDetails.Message) {
                            $apiError = $_.ErrorDetails.Message
                        }
                        elseif ($_.Exception.Response) {
                            $stream = $_.Exception.Response.GetResponseStream()
                            $reader = [System.IO.StreamReader]::new($stream)
                            $responseBody = $reader.ReadToEnd()
                            $reader.Dispose()
                            if ($responseBody) {
                                $apiError = $responseBody
                            }
                        }
                    }
                    catch {
                        # Keep original extracted error.
                    }
                }

                if ($apiError) {
                    $apiError = Normalize-ApiErrorMessage -Message $apiError
                    throw "API Error: $apiError"
                }
                throw
            }
        }
        else {
            $apiError = Get-ApiErrorMessage -Exception $_

            # If still generic, attempt to read full response body from exception.
            if (-not $apiError -or $apiError -like "*Bad Request*") {
                try {
                    if ($_.ErrorDetails.Message) {
                        $apiError = $_.ErrorDetails.Message
                    }
                    elseif ($_.Exception.Response) {
                        $stream = $_.Exception.Response.GetResponseStream()
                        $reader = [System.IO.StreamReader]::new($stream)
                        $responseBody = $reader.ReadToEnd()
                        $reader.Dispose()
                        if ($responseBody) {
                            $apiError = $responseBody
                        }
                    }
                }
                catch {
                    # Keep original extracted error.
                }
            }

            if ($apiError) {
                $apiError = Normalize-ApiErrorMessage -Message $apiError
                throw "API Error: $apiError"
            }
            throw
        }
    }
    
    if ($null -ne $result -and $null -ne $result.Id -and $result.Id -ne 0){
        Write-Host "Request $($result.Id) was created"
        $itemUrl=$requestUrl+"?id="+$result.Id
        $oldStatus = ""
        $r = $null
        $componentStatuses = @{}
        $componentLogLengths = @{}   # chars of each component's log already printed
        $componentHeaderPrinted = @{} # whether the log banner was emitted for a component
        $componentFinalized = @{}     # components whose final log has been fully streamed
        $pendingStatuses = @("Pending", "NotStarted", "Not Started", "Queued", "")
        $pollStartTime = Get-Date
        $pollDeadline = $pollStartTime.AddMinutes(240)
        while ((-not ($validStatuses -contains $oldStatus)) -and ((Get-Date) -lt $pollDeadline)){
            Start-Sleep -Seconds $pollIntervalSeconds

            Ensure-DorcAccessToken -TokenState $tokenState -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
            $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

            try {
                $r = Invoke-RestMethod -Method GET -Uri $itemUrl -Headers $DorcAPIHeaders
            }
            catch {
                $statusCode = Get-StatusCodeFromException -Exception $_
                if ($statusCode -eq 401) {
                    try {
                        Write-Host "Received 401 from DOrc API. Refreshing token and retrying once."
                        $newToken = Refresh-DorcAccessToken -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
                        $tokenState.AccessToken = $newToken.AccessToken
                        $tokenState.ExpiresAt = $newToken.ExpiresAt
                        $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"
                        $r = Invoke-RestMethod -Method GET -Uri $itemUrl -Headers $DorcAPIHeaders
                    }
                    catch {
                        Write-Host "Warning: Failed to fetch request status after token refresh: $($_.Exception.Message)"
                        continue
                    }
                }
                else {
                    Write-Host "Warning: Failed to fetch request status: $($_.Exception.Message)"
                    continue
                }
            }

            if ($null -ne $r -and $oldStatus -ne $r.Status) {
                Write-Host "Request $($result.Id) status: $($r.Status)"
                $oldStatus = $r.Status
            }

            # Live component progress
            $componentStatusUri = $baseurl + "/ResultStatuses?requestId=$($result.Id)"
            try {
                $componentResponse = Invoke-WebRequest -Uri $componentStatusUri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
                $currentComponents = @(ConvertFrom-Json -InputObject $componentResponse.Content)
            }
            catch {
                $statusCode = Get-StatusCodeFromException -Exception $_
                if ($statusCode -eq 401) {
                    try {
                        $newToken = Refresh-DorcAccessToken -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
                        $tokenState.AccessToken = $newToken.AccessToken
                        $tokenState.ExpiresAt = $newToken.ExpiresAt
                        $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"
                        $componentResponse = Invoke-WebRequest -Uri $componentStatusUri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
                        $currentComponents = @(ConvertFrom-Json -InputObject $componentResponse.Content)
                    }
                    catch {
                        Write-Host "Warning: Failed to fetch component statuses after token refresh: $($_.Exception.Message)"
                        $currentComponents = @()
                    }
                }
                else {
                    Write-Host "Warning: Failed to fetch component statuses: $($_.Exception.Message)"
                    $currentComponents = @()
                }
            }
            # Flatten in case the response is wrapped in a nested array, so each
            # $cmp is a single component object rather than the whole collection.
            $flatComponents = @()
            foreach ($entry in $currentComponents) {
                $flatComponents += $entry
            }

            foreach ($cmp in $flatComponents) {
                if (-not $cmp -or -not $cmp.ComponentName) { continue }
                $name = [string]$cmp.ComponentName
                $status = [string]$cmp.Status

                # Announce status transitions.
                $prevStatus = $null
                if ($componentStatuses.ContainsKey($name)) {
                    $prevStatus = $componentStatuses[$name]
                }
                if ($prevStatus -ne $status) {
                    Write-Host ("  [{0}] {1}" -f $status, $name)
                    $componentStatuses[$name] = $status
                }

                # Stream the log live while the component is running, and capture the tail once it finishes.
                if ($null -ne $cmp.Id -and -not $componentFinalized.ContainsKey($name)) {
                    $isPending = $pendingStatuses -contains $status
                    if (-not $isPending) {
                        $isFinished = $status -ne "Running"
                        $logUri = $baseurl + "/ResultStatuses/Log?requestId=$($result.Id)&resultId=$($cmp.Id)"
                        try {
                            $logContent = Get-DorcComponentLog -LogUri $logUri -TokenState $tokenState -TokenUrl $IDSBaseURL -IDSHeaders $IDSHeaders -IDSFormData $IDSFormData -DorcAPIHeaders $DorcAPIHeaders
                            Write-ComponentLogDelta -Name $name -LogContent $logContent -LengthState $componentLogLengths -HeaderState $componentHeaderPrinted
                        }
                        catch {
                            # 404 simply means no log is available yet; ignore and retry next poll.
                            if ((Get-StatusCodeFromException -Exception $_) -ne 404) {
                                Write-Host "Warning: Failed to fetch log for '$name': $($_.Exception.Message)"
                            }
                        }
                        if ($isFinished) { $componentFinalized[$name] = $true }
                    }
                }
            }
        }
        if (-not ($validStatuses -contains $oldStatus)) {
            $lastStatus = if ($oldStatus) { $oldStatus } else { "(no status received)" }
            Write-VstsSetResult -Result "Failed" -Message "Polling timed out. Last status: $lastStatus"
            return
        }

        Write-Host "Collecting deploy results"
        $id = $result.Id
        $uri = $baseurl + "/ResultStatuses?requestId=$id"

        Ensure-DorcAccessToken -TokenState $tokenState -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
        $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"

        try {
            $r = Invoke-WebRequest -Uri $uri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
        }
        catch {
            $statusCode = Get-StatusCodeFromException -Exception $_
            if ($statusCode -eq 401) {
                try {
                    $newToken = Refresh-DorcAccessToken -TokenUrl $IDSBaseURL -Headers $IDSHeaders -FormData $IDSFormData
                    $tokenState.AccessToken = $newToken.AccessToken
                    $tokenState.ExpiresAt = $newToken.ExpiresAt
                    $DorcAPIHeaders["Authorization"] = "Bearer $($tokenState.AccessToken)"
                    $r = Invoke-WebRequest -Uri $uri -Method GET -Headers $DorcAPIHeaders -UseBasicParsing
                }
                catch {
                    Write-VstsSetResult -Result "Failed" -Message "Failed to fetch deployment results after token refresh: $($_.Exception.Message)"
                    return
                }
            }
            else {
                Write-VstsSetResult -Result "Failed" -Message "Failed to fetch deployment results: $($_.Exception.Message)"
                return
            }
        }

        try {
            $cmps = @(ConvertFrom-Json -InputObject $r.Content)
        }
        catch {
            Write-Host "Warning: Failed to parse deployment results: $($_.Exception.Message)"
            $cmps = @()
        }

        # Safety net: emit logs for any component that finished too quickly to be tailed live.
        # Components already streamed are skipped; for the rest only the un-printed tail is shown.
        foreach ($cmp in $cmps) {
            if (-not $cmp -or -not $cmp.ComponentName) { continue }
            $name = [string]$cmp.ComponentName
            if ($componentFinalized.ContainsKey($name)) { continue }

            if ($null -ne $cmp.Id) {
                $logUri = $baseurl + "/ResultStatuses/Log?requestId=$id&resultId=$($cmp.Id)"
                try {
                    $logContent = Get-DorcComponentLog -LogUri $logUri -TokenState $tokenState -TokenUrl $IDSBaseURL -IDSHeaders $IDSHeaders -IDSFormData $IDSFormData -DorcAPIHeaders $DorcAPIHeaders
                    Write-ComponentLogDelta -Name $name -LogContent $logContent -LengthState $componentLogLengths -HeaderState $componentHeaderPrinted
                }
                catch {
                    if ((Get-StatusCodeFromException -Exception $_) -eq 404) {
                        Write-ComponentLogDelta -Name $name -LogContent $cmp.Log -LengthState $componentLogLengths -HeaderState $componentHeaderPrinted
                    }
                    else {
                        Write-Host "Warning: Failed to fetch full log for component '$name': $($_.Exception.Message)"
                        Write-ComponentLogDelta -Name $name -LogContent $cmp.Log -LengthState $componentLogLengths -HeaderState $componentHeaderPrinted
                    }
                }
            }
            else {
                Write-ComponentLogDelta -Name $name -LogContent $cmp.Log -LengthState $componentLogLengths -HeaderState $componentHeaderPrinted
            }
        }

        $message = "Execution finished with status: " + $oldStatus
        if ($goodStatuses -contains $oldStatus) {
            Write-VstsSetResult -Result "Succeeded" -Message $message
        }
        else {
            Write-VstsSetResult -Result "Failed" -Message $message
        }
    }
    else {
        Write-VstsSetResult -Result "Failed" -Message "DOrc did not return a valid request ID."
    }
} finally {
    Trace-VstsLeavingInvocation $MyInvocation
}
