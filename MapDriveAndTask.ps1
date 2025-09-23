param(
    [string]$Location
)

$targetScriptPath = "$env:ProgramData\MapDriveAndTask.ps1"

if ($MyInvocation.MyCommand.Path -ne $targetScriptPath) {
    try {
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $targetScriptPath -Force
        Write-Host "Copied script to $targetScriptPath"
    } catch {
        Write-Host "Failed to copy script: $_"
        exit 1
    }
}

$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$scriptName = "MapSharedDrive"

try {
    $existingValue = Get-ItemProperty -Path $runKey -Name $scriptName -ErrorAction SilentlyContinue

    if (-not $existingValue) {
        Set-ItemProperty -Path $runKey -Name $scriptName `
            -Value "PowerShell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetScriptPath`" -Location `"$Location`""
        Write-Host "Registry Run key added for $scriptName in HKCU"
    } else {
        Write-Host "Registry Run key already exists in HKCU. Skipping."
    }
} catch {
    Write-Host "Failed to add or check Run key in HKCU: $_"
}

function Map-SharedDrive {
    try {
        $remotePath = switch ($Location.ToUpper()) {
            "GEORGIA"  { "\\GA-DC02\Shared2" }
            "ARKANSAS" { "\\ID-DC\IDShared" }
            "IDAHO"    { "\\ID-DC\IDShared" }
            Default    { Write-Host "Invalid location input: $Location"; exit 1 }
        }

        if ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
            if (-not (Get-SmbMapping -LocalPath "S:" -ErrorAction SilentlyContinue)) {
                New-SmbMapping -LocalPath "S:" -RemotePath $remotePath -Persistent $true
                Write-Host "S: drive mapped for $env:USERNAME"
            } else {
                Write-Host "S: drive already mapped for $env:USERNAME"
            }
        } else {
            Write-Host "$env:USERNAME is not a domain user. Skipping drive mapping."
        }
    } catch {
        Write-Host "Error mapping shared drive: $_"
    }
}

Map-SharedDrive
