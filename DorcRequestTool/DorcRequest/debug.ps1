Import-Module -name .\ps_modules\VstsTaskSdk\vstsTaskSdk 
$env:INPUT_BASEURL="http://localhost:32194/api"
$env:INPUT_DORCIDSSECRET= ""
$env:INPUT_PROJECT="SDCT"
$env:INPUT_TARGETENV="Comms DV 01"
$env:INPUT_BUILDTEXT="CommsTool.master_19.06.29.1"
$env:INPUT_BUILDNUM="CommsTool.master_19.06.29.1"
$env:INPUT_COMPONENTS="00 - Deloy WEB Site"
$env:INPUT_PINNED="false"
$env:INPUT_VSTFSURL="vstfs:///Build/Build/378024"
#$env:INPUT_BUILDURI="NA"
Invoke-VstsTaskScript -ScriptBlock ([scriptblock]::Create('. .\index.ps1'))
Remove-Module -name vstsTaskSdk 
