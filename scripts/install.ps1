$ErrorActionPreference = 'Stop'
$Repository = 'x0c/agent-dbctl'
$Version = $env:AGENT_DBCTL_VERSION
if (!$Version -or $Version -eq 'latest') {
    $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repository/releases/latest").tag_name
}
if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$') { throw "Invalid release version: $Version" }

$Arch = if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { 'arm64' } else { 'amd64' }
$Asset = "agent-dbctl_${Version}_windows_${Arch}.zip"
$Temp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory $Temp | Out-Null
try {
    $Base = "https://github.com/$Repository/releases/download/$Version"
    Invoke-WebRequest "$Base/$Asset" -OutFile (Join-Path $Temp $Asset)
    Invoke-WebRequest "$Base/SHA256SUMS" -OutFile (Join-Path $Temp 'SHA256SUMS')
    $Line = Get-Content (Join-Path $Temp 'SHA256SUMS') | Where-Object { $_.EndsWith("  $Asset") }
    if (!$Line -or $Line.Count -gt 1) { throw "Missing or duplicate checksum for $Asset" }
    $Expected = ($Line -split ' ')[0]
    $Actual = (Get-FileHash (Join-Path $Temp $Asset) -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) { throw 'Release checksum mismatch' }

    Expand-Archive (Join-Path $Temp $Asset) -DestinationPath $Temp
    $Binary = Join-Path $Temp 'agent-dbctl.exe'
    $env:AGENT_DBCTL_NO_SKILL_SYNC = '1'
    $VerJson = (& $Binary version --json | ConvertFrom-Json)
    if ($VerJson.data.version -ne $Version) { throw "Release version mismatch: $($VerJson.data.version)" }

    $Destination = if ($env:AGENT_DBCTL_INSTALL_DIR) { $env:AGENT_DBCTL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'agent-dbctl\bin' }
    New-Item -ItemType Directory -Force $Destination | Out-Null
    Copy-Item $Binary (Join-Path $Destination 'agent-dbctl.exe') -Force
    Write-Host "Installed agent-dbctl $Version to $Destination. Add this directory to PATH if needed."
} finally {
    Remove-Item $Temp -Recurse -Force
}
