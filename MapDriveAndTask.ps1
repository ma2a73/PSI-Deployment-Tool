param(
    [string]$Location
)

$targetScriptPath = "C:\ProgramData\MapDriveAndTask.ps1"

if ($MyInvocation.MyCommand.Path -ne $targetScriptPath) {
    try {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $targetScriptPath -Force
    } catch {
        Write-Host "Failed to copy script: $_"
        exit 1
    }
}

$runKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$scriptName = "MapSharedDrive"

try {
    $existingValue = Get-ItemProperty -Path $runKey -Name $scriptName -ErrorAction SilentlyContinue
    if (-not $existingValue) {
        $registryCommand = "PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetScriptPath`" -Location `"$Location`""
        Set-ItemProperty -Path $runKey -Name $scriptName -Value $registryCommand
    }
} catch {
    Write-Host "Failed to add Run key: $_"
}

function Map-SharedDrive {
    try {
        $remotePath = switch ($Location.ToUpper()) {
            "GEORGIA"  { "\\GA-DC02\Shared2" }
            "ARKANSAS" { "\\ID-DC\IDShared" }
            "IDAHO"    { "\\ID-DC\IDShared" }
            Default    { Write-Host "Invalid location input: $Location"; return }
        }

        if ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
            if (-not (Get-SmbMapping -LocalPath "S:" -ErrorAction SilentlyContinue)) {
                New-SmbMapping -LocalPath "S:" -RemotePath $remotePath -Persistent $true
            }
        }
    } catch {
        Write-Host "Error mapping shared drive: $_"
    }
}

Map-SharedDrive
Start-Sleep -Seconds 1
