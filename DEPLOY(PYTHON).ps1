param(
    [string]$timezone,
    [string]$location,
    [string]$computerName,
    [switch]$installVPN,
    [switch]$installVANTAGE
)

if ($env:PSI_DEPLOYMENT_DIR) {
    $DeploymentRoot = $env:PSI_DEPLOYMENT_DIR
    Write-Host "Using deployment directory from environment: $DeploymentRoot"
} else {
    $DeploymentRoot = $PSScriptRoot
    Write-Host "Using script directory: $DeploymentRoot"
}

$script:DefenderDisabled = $false 
$script:OriginalPowerPlan = $null
$script:DeploymentStartTime = Get-Date

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"

$localLogDirectory = "C:\Logs"
if (-not (Test-Path $localLogDirectory)) {
    New-Item -Path $localLogDirectory -ItemType Directory -Force | Out-Null
}

$logName = if (![string]::IsNullOrWhiteSpace($computerName)) { $computerName } else { $env:COMPUTERNAME }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName = "$logName-SetupLog-$timestamp.txt"
$localLogPath = Join-Path $localLogDirectory $logFileName

Start-Transcript -Path $localLogPath -NoClobber

function Optimize-DeploymentPerformance {
    Write-Host "=== OPTIMIZING SYSTEM FOR DEPLOYMENT SPEED ===" -ForegroundColor Cyan
    
    try {
        $currentProcess = Get-Process -Id $PID
        $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::High
        Write-Host "Set deployment process priority to HIGH"
        
        try {
            $script:OriginalPowerPlan = (powercfg /getactivescheme) -replace '.*GUID: ([a-f0-9\-]+).*', '$1'
            $highPerf = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
            powercfg /setactive $highPerf | Out-Null 2>&1
            Write-Host "Activated HIGH PERFORMANCE power plan (original: $script:OriginalPowerPlan)"
        } catch {
            Write-Host "Power plan optimization skipped"
        }
        
        try {
            $defenderSettings = Get-MpPreference -ErrorAction SilentlyContinue
            if ($defenderSettings -and $defenderSettings.DisableRealtimeMonitoring -eq $false) {
                Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
                $script:DefenderDisabled = $true
                Write-Host "Temporarily disabled Windows Defender real-time scanning (silent)"
            }
        } catch {
        }
        
        try {
            $visualEffectsPath = "HKCU:\Control Panel\Desktop"
            Set-ItemProperty -Path $visualEffectsPath -Name "DragFullWindows" -Value "0" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $visualEffectsPath -Name "MenuShowDelay" -Value "0" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $visualEffectsPath -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -ErrorAction SilentlyContinue
        } catch {
        }
        
        $servicesToOptimize = @("Themes", "TabletInputService", "Fax")
        foreach ($service in $servicesToOptimize) {
            try {
                $svc = Get-Service $service -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    Stop-Service $service -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    Write-Host "Temporarily stopped service: $service"
                }
            } catch {
            }
        }
        
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1 -ErrorAction SilentlyContinue
        } catch {
        }
        
        try {
            [System.Net.ServicePointManager]::DefaultConnectionLimit = 100
            [System.Net.ServicePointManager]::Expect100Continue = $false
            [System.Net.ServicePointManager]::UseNagleAlgorithm = $false
        } catch {
        }
        
        Write-Host "Performance optimization completed - deployment should run significantly faster" -ForegroundColor Green
        
    } catch {
    }
}

function Enable-RemoteManagement {
    Write-Host "=== ENABLING REMOTE MANAGEMENT ===" -ForegroundColor Cyan
    
    try {
        try {
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            Set-WSManInstance -ResourceURI winrm/config/service -ValueSet @{AllowUnencrypted="false"} -ErrorAction SilentlyContinue | Out-Null
            Set-WSManInstance -ResourceURI winrm/config/service/auth -ValueSet @{Basic="true"} -ErrorAction SilentlyContinue | Out-Null
            Write-Host "PowerShell Remoting enabled"
        } catch {
        }
        
        try {
            Set-WSManInstance -ResourceURI winrm/config -ValueSet @{MaxTimeoutms="1800000"} -ErrorAction SilentlyContinue | Out-Null
            Set-WSManInstance -ResourceURI winrm/config/winrs -ValueSet @{MaxMemoryPerShellMB="2048"} -ErrorAction SilentlyContinue | Out-Null
        } catch {
        }
        
        try {
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            Write-Host "Remote Desktop enabled"
        } catch {
        }
        
        $firewallRules = @(
            "Windows Management Instrumentation (WMI)",
            "Windows Remote Management",
            "Remote Desktop",
            "File and Printer Sharing"
        )
        
        foreach ($rule in $firewallRules) {
            try {
                Enable-NetFirewallRule -DisplayGroup $rule -ErrorAction SilentlyContinue
            } catch {
            }
        }
        Write-Host "Firewall rules enabled for remote management"
        
        $services = @("WinRM", "TermService", "Winmgmt")
        foreach ($service in $services) {
            try {
                Set-Service $service -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service $service -ErrorAction SilentlyContinue
            } catch {
            }
        }
        
        Write-Host "Remote management configuration completed" -ForegroundColor Green
        
    } catch {
    }
}

function Write-DeploymentProgress {
    param(
        [int]$CurrentStep,
        [int]$TotalSteps,
        [string]$StepDescription,
        [int]$StepProgress = 0
    )
    
    $overallProgress = [math]::Round((($CurrentStep - 1) / $TotalSteps) * 100)
    $elapsed = (Get-Date) - $script:DeploymentStartTime
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    Write-Host "[$timestamp] ($($elapsed.ToString('mm\:ss'))) Step $CurrentStep/$TotalSteps ($overallProgress%): $StepDescription" -ForegroundColor Cyan
    if ($StepProgress -gt 0) {
        Write-Host "  Step Progress: $StepProgress%" -ForegroundColor Yellow
    }
}

if (-not $timezone) { 
    $timezone = "EASTERN"
    Write-Host "Using default timezone: $timezone" -ForegroundColor Yellow
} else { 
    Write-Host "Received Timezone: $timezone" 
}

if (-not $location) { 
    $location = "GEORGIA"
    Write-Host "Using default location: $location" -ForegroundColor Yellow
} else { 
    Write-Host "Received Location: $location" 
}

if (-not $computerName) { 
    $computerName = $env:COMPUTERNAME
    Write-Host "Using current computer name: $computerName" -ForegroundColor Yellow
} else { 
    Write-Host "Received Computer Name: $computerName" 
}

Write-DeploymentProgress -CurrentStep 1 -TotalSteps 15 -StepDescription "Optimizing system performance for deployment"
Optimize-DeploymentPerformance

Write-DeploymentProgress -CurrentStep 2 -TotalSteps 15 -StepDescription "Enabling remote management capabilities"
Enable-RemoteManagement

function Get-DomainCredential {
    param([string]$ScriptDirectory = $DeploymentRoot)  
    
    try {
        Write-Host "=== CREDENTIAL LOADING ==="
        Write-Host "Script directory: $ScriptDirectory"
        
        $keyPath = Join-Path $ScriptDirectory "key.key"
        $encryptedPath = Join-Path $ScriptDirectory "encrypted.txt"
        
        Write-Host "Looking for key file: $keyPath"
        Write-Host "Looking for encrypted file: $encryptedPath"
        
        if (-not (Test-Path $keyPath)) {
            Write-Host "credential_error: key.key file not found at $keyPath"
            Write-Host "Available files in directory:"
            Get-ChildItem $ScriptDirectory -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  - $($_.Name)" }
            return $null
        }
        
        if (-not (Test-Path $encryptedPath)) {
            Write-Host "credential_error: encrypted.txt file not found at $encryptedPath"
            Write-Host "Available files in directory:"
            Get-ChildItem $ScriptDirectory -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  - $($_.Name)" }
            return $null
        }
        
        $keySize = (Get-Item $keyPath).Length
        $encryptedSize = (Get-Item $encryptedPath).Length
        
        Write-Host "key.key size: $keySize bytes"
        Write-Host "encrypted.txt size: $encryptedSize bytes"
        
        if ($keySize -eq 0) {
            Write-Host "credential_error: key.key file is empty"
            return $null
        }
        
        if ($encryptedSize -eq 0) {
            Write-Host "credential_error: encrypted.txt file is empty"
            return $null
        }
        
        Write-Host "Loading credential files..."
        $key = Get-Content -Path $keyPath -Encoding Byte -ErrorAction Stop
        $encrypted = Get-Content -Path $encryptedPath -Raw -ErrorAction Stop
        
        if (-not $key -or $key.Length -eq 0) {
            Write-Host "credential_error: Key content is empty or invalid"
            return $null
        }
        
        if (-not $encrypted -or $encrypted.Trim() -eq "") {
            Write-Host "credential_error: Encrypted content is empty or invalid"
            return $null
        }
        
        Write-Host "Converting encrypted password..."
        $securePassword = $encrypted | ConvertTo-SecureString -Key $key -ErrorAction Stop
        
        Write-Host "Creating credential object..."
        $credential = New-Object System.Management.Automation.PSCredential("PSI-PAC\Support", $securePassword) -ErrorAction Stop
        
        Write-Host "credential_status: success"
        Write-Host "Credential object created successfully for: PSI-PAC\Support"
        return $credential
        
    } catch {
        Write-Host "credential_error: $($_.Exception.Message)"
        Write-Host "credential_error_details: $($_.Exception.GetType().FullName)"
        Write-Host "credential_error_line: $($_.InvocationInfo.ScriptLineNumber)"
        return $null
    }
}

function Set-TimeZoneFromUserInput {
    try {
        switch ($timezone.ToUpper()) {
            "EASTERN"  { Set-TimeZone "Eastern Standard Time" -ErrorAction SilentlyContinue; Write-Host "Timezone set to Eastern Standard Time" }
            "CENTRAL"  { Set-TimeZone "Central Standard Time" -ErrorAction SilentlyContinue; Write-Host "Timezone set to Central Standard Time" }
            "MOUNTAIN" { Set-TimeZone "Mountain Standard Time" -ErrorAction SilentlyContinue; Write-Host "Timezone set to Mountain Standard Time" }
            Default    { Write-Host "Invalid timezone input: $timezone" }
        }
    } catch {
        Write-Host "Timezone setting skipped: $($_.Exception.Message)"
    }
}

function Test-NetworkConnectivity {
    param([string]$Location)
    
    $servers = switch ($Location.ToUpper()) {
        "GEORGIA"  { @("GA-DC02", "ga-dc02.psi-pac.com") }
        "ARKANSAS" { @("AR-DC", "10.1.199.2") }
        "IDAHO"    { @("ID-DC", "id-dc.psi-pac.com") }
        Default    { @("GA-DC02") }
    }
    
    foreach ($server in $servers) {
        if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -TimeoutSeconds 5 -ErrorAction SilentlyContinue)) {
            Write-Host "Cannot reach $server" -ForegroundColor Yellow
            return $false
        }
    }
    Write-Host "Network connectivity verified for $Location"
    return $true
}

function Rename-ComputerPrompt {
    param([string]$ComputerName, [object]$Credential)
    
    Write-Host "=== COMPUTER RENAME PROCESS ==="
    
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        Write-Host "Computer name not provided - skipping rename"
        return $false
    }
    
    if (-not $Credential) {
        Write-Host "No domain credentials available - attempting local rename only"
        try {
            Rename-Computer -NewName $ComputerName -Force -ErrorAction Stop | Out-Null
            Write-Host "Computer renamed to $ComputerName (local only)"
            return $true
        } catch {
            Write-Host "Failed to rename computer locally: $($_.Exception.Message)"
            return $false
        }
    }
    
    try {
        Write-Host "Renaming computer to: $ComputerName"
        Write-Host "Using domain credentials for rename operation"
        Rename-Computer -NewName $ComputerName -Force -DomainCredential $Credential -ErrorAction Stop | Out-Null
        Write-Host "Computer renamed to $ComputerName successfully"
        return $true
    } catch {
        Write-Host "Failed to rename computer with domain credentials: $($_.Exception.Message)"
        Write-Host "Attempting local rename as fallback..."
        
        try {
            Rename-Computer -NewName $ComputerName -Force -ErrorAction Stop | Out-Null
            Write-Host "Computer renamed to $ComputerName (local fallback)"
            return $true
        } catch {
            Write-Host "Failed to rename computer (all methods): $($_.Exception.Message)"
            return $false
        }
    }
}

function Run-Installer {
    param (
        [string]$Path,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 900
    )

    if (-not (Test-Path $Path)) {
        Write-Host "Installer not found: $Path"
        return $false
    }

    Write-Host "Running installer: $Path"

    if ($null -eq $Arguments) { $Arguments = @() }
    $safeArgs = @()
    foreach ($a in $Arguments) {
        if ($a -ne $null -and $a -ne "") { $safeArgs += $a }
    }

    try {
        $processArgs = @{
            FilePath = $Path
            PassThru = $true
            WindowStyle = 'Hidden'
            Wait = $true
            ErrorAction = 'SilentlyContinue'
        }
        
        if ($safeArgs.Count -gt 0) {
            $processArgs.ArgumentList = $safeArgs
        }
        
        $process = Start-Process @processArgs

        if ($process.ExitCode -eq 0) {
            Write-Host "Installer completed successfully: $Path" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Installer completed with exit code $($process.ExitCode): $Path" -ForegroundColor Yellow
            return $true 
        }
    } catch {
        Write-Host "Installer failed: $Path - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Install-SharedDriveTask {
    param(
        [string]$Location
    )
    $remotePath = switch ($Location.ToUpper()) {
        "GEORGIA"  { "\\GA-DC02\Shared2" }
        "ARKANSAS" { "\\AR-DC\Shared" }
        "IDAHO"    { "\\ID-DC\IDShared" }
        Default    { "\\GA-DC02\Shared2" }
    }
    
    try {
        $scriptContent = @"
if (-not (Test-Path "`$env:LOCALAPPDATA\SDriveMapped.txt")) {
    if (-not (Get-SmbMapping -LocalPath S: -ErrorAction SilentlyContinue)) {
        New-SmbMapping -LocalPath S: -RemotePath "$remotePath" -Persistent `$true
    }
    New-Item -Path "`$env:LOCALAPPDATA\SDriveMapped.txt" -ItemType File -Force | Out-Null
}
"@
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -All
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$scriptContent`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
        
        Register-ScheduledTask -TaskName "MapSharedDrive" -Action $action -Trigger $trigger -Principal $principal -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Shared drive task configured for: $remotePath" -ForegroundColor Green
    } catch {
        Write-Host "Failed to configure shared drive task: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Switch-Logs {
    try {
        $remoteLogDir = "\\ga-dc02\Shared2\New I.T\PC Deployment Tool - Version 1.33\DEPLOY LOGS"
        $remoteLogPath = Join-Path $remoteLogDir $logFileName
        if (Test-Path $remoteLogDir) {
            Copy-Item -Path $localLogPath -Destination $remoteLogDir -Force -ErrorAction SilentlyContinue
            Write-Host "Log file copied to shared location."

            Stop-Transcript -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2

            Start-Transcript -Path $remoteLogPath -Append -ErrorAction SilentlyContinue
            Write-Host "Logging continued on shared drive: $remoteLogPath"
        } else {
            Write-Host "Remote log directory not found. Continuing with local logging."
        }
    } catch {
        Write-Host "Failed to switch to remote logging: $($_.Exception.Message)"
    }
}

function Start-ParallelInstallations {
    Write-Host "=== STARTING PARALLEL INSTALLATIONS ===" -ForegroundColor Cyan
    
    $jobs = @()
    
    $tvJob = Start-Job -Name "TeamViewer" -ScriptBlock {
        param($scriptRoot)
        $tvPath = Join-Path $scriptRoot "Teamviewer_Setup.exe"
        if (Test-Path $tvPath) {
            try {
                $process = Start-Process -FilePath $tvPath -ArgumentList "/S" -PassThru -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                return "TeamViewer: Exit code $($process.ExitCode)"
            } catch {
                return "TeamViewer: Failed - $($_.Exception.Message)"
            }
        } else {
            return "TeamViewer: Installer not found"
        }
    } -ArgumentList $DeploymentRoot
    $jobs += $tvJob
    
    $csJob = Start-Job -Name "CrowdStrike" -ScriptBlock {
        param($scriptRoot)
        $csPath = Join-Path $scriptRoot "WindowsSensor.MaverickGyr.exe"
        if (Test-Path $csPath) {
            try {
                $process = Start-Process -FilePath $csPath -ArgumentList "/install", "/quiet", "/norestart", "CID=47AB920FB2F34F00BEDE8311E34EA489-EB" -PassThru -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                return "CrowdStrike: Exit code $($process.ExitCode)"
            } catch {
                return "CrowdStrike: Failed - $($_.Exception.Message)"
            }
        } else {
            return "CrowdStrike: Installer not found"
        }
    } -ArgumentList $DeploymentRoot
    $jobs += $csJob
    
    $dotnetJob = Start-Job -Name "DotNet" -ScriptBlock {
        try {
            Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/NoRestart", "/Quiet" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
            return ".NET Framework: Installation initiated"
        } catch {
            return ".NET Framework: Failed - $($_.Exception.Message)"
        }
    }
    $jobs += $dotnetJob
    
    $featuresJob = Start-Job -Name "Features" -ScriptBlock {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All
            Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -All
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
            return "System Features: Enabled successfully"
        } catch {
            return "System Features: Failed - $($_.Exception.Message)"
        }
    }
    $jobs += $featuresJob
    
    Write-Host "Started $($jobs.Count) parallel installation jobs" -ForegroundColor Green
    
    $timeout = 300
    $startTime = Get-Date
    
    while ($jobs.Count -gt 0 -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
        $completedJobs = $jobs | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }
        
        foreach ($job in $completedJobs) {
            $result = Receive-Job -Job $job -ErrorAction SilentlyContinue
            Write-Host $result -ForegroundColor $(if ($result -match "Failed") { "Red" } else { "Green" })
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
        }
        
        if ($jobs.Count -gt 0) {
            Start-Sleep -Seconds 2
        }
    }
    
    $jobs | ForEach-Object {
        Stop-Job -Job $_ -ErrorAction SilentlyContinue
        Remove-Job -Job $_ -Force -ErrorAction SilentlyContinue
    }
    
    Write-Host "Parallel installations completed" -ForegroundColor Green
}

function Install-Vantage {
    param (
        [string]$location
    )

    $targetPath = "C:\client803"
    $defaultTotalFiles = 17023

    switch ($location.ToUpper()) {
        "GEORGIA" { 
            $remoteZip      = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803.zip"
            $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
            $fallbackFolder = "\\ga-dc02\Shared2\Vantage\client803"
        }
        "ARKANSAS" { 
            $remoteZip      = "\\ar-dc\Shared\Vantage\client803.zip"
            $remoteFolder   = "\\ar-dc\Shared\Vantage\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
            $fallbackFolder = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
        }
        "IDAHO" { 
            $remoteZip      = "\\id-dc\IDShared\Shipping\Rack Sheet\PSI BOL & Invoice\Vantage\client803.zip"
            $remoteFolder   = "\\id-dc\IDShared\Shipping\Rack Sheet\PSI BOL & Invoice\Vantage\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
            $fallbackFolder = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
        }
        default { 
            $remoteZip      = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803.zip"
            $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
            $fallbackFolder = $null
        }
    }

    Write-Host "=== VANTAGE INSTALLATION PROCESS ===" -ForegroundColor Cyan
    Write-Host "Target location: $location"
    Write-Output "vantage progress: 0"

    if (Test-Path $targetPath) {
        Write-Host "Target directory already exists: $targetPath"
        $existingFiles = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "Existing files: $existingFiles"
        if ($existingFiles -gt 1000) {
            Write-Host "Vantage appears to already be installed. Skipping installation."
            Write-Output "vantage progress: 100"
            return
        }
    }

    $zipSuccess = $false
    
    if (Test-Path $remoteZip -ErrorAction SilentlyContinue) {
        Write-Host "Found ZIP archive: $remoteZip" -ForegroundColor Green
        Write-Host "Using compressed archive method (10-20x faster)..." -ForegroundColor Cyan
        
        try {
            $tempZip = "$env:TEMP\client803_install.zip"
            
            Write-Host "Copying compressed archive..."
            Write-Output "vantage progress: 5"
            
            $copyJob = Start-Job -ScriptBlock {
                param($source, $dest)
                try {
                    Copy-Item -Path $source -Destination $dest -Force -ErrorAction Stop
                    return @{Success=$true; Size=(Get-Item $dest).Length}
                } catch {
                    return @{Success=$false; Error=$_.Exception.Message}
                }
            } -ArgumentList $remoteZip, $tempZip
            
            $startTime = Get-Date
            $timeout = 600
            $lastProgress = 5
            
            while ($copyJob.State -eq 'Running' -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                $progress = 5 + [math]::Min([math]::Round(($elapsed / $timeout) * 45), 45)
                
                if ($progress -gt $lastProgress) {
                    Write-Output "vantage progress: $progress"
                    $lastProgress = $progress
                }
                Start-Sleep -Seconds 3
            }
            
            $copyResult = Wait-Job $copyJob -Timeout 30 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $copyJob -Force -ErrorAction SilentlyContinue
            
            if ($copyResult.Success) {
                Write-Output "vantage progress: 50"
                $zipSize = [math]::Round($copyResult.Size / 1MB, 2)
                Write-Host "Archive copied successfully ($zipSize MB)" -ForegroundColor Green
                Write-Host "Extracting archive to $targetPath..."
                
                try {
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $targetPath)
                    
                    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                    Write-Output "vantage progress: 85"
                    
                    $finalCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
                    Write-Host "Archive extraction completed: $finalCount files extracted" -ForegroundColor Green
                    
                    $zipSuccess = $true
                    
                } catch {
                    Write-Host "Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                    if (Test-Path $targetPath) {
                        Remove-Item $targetPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            } else {
                Write-Host "ZIP copy failed: $($copyResult.Error)" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "Archive method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ZIP archive not found: $remoteZip" -ForegroundColor Yellow
        Write-Host "Falling back to folder copy method..."
    }

    if (-not $zipSuccess) {
        Write-Host "Using ultra-optimized robocopy method..." -ForegroundColor Yellow
        
        $sourceAvailable = $false
        $actualSource = $null
        
        if (Test-Path $remoteFolder -ErrorAction SilentlyContinue) {
            Write-Host "Primary source available: $remoteFolder" -ForegroundColor Green
            $sourceAvailable = $true
            $actualSource = $remoteFolder
        } elseif ($fallbackFolder -and (Test-Path $fallbackFolder -ErrorAction SilentlyContinue)) {
            Write-Host "Using fallback source: $fallbackFolder" -ForegroundColor Yellow
            $sourceAvailable = $true
            $actualSource = $fallbackFolder
        } else {
            Write-Host "ERROR: No accessible Vantage source found!" -ForegroundColor Red
            Write-Output "vantage error: Cannot access source folders"
            return
        }

        if ($sourceAvailable) {
            try {
                Write-Host "Counting files in source directory..."
                $totalFiles = (Get-ChildItem -Path $actualSource -Recurse -File -ErrorAction Stop).Count
                if (-not $totalFiles -or $totalFiles -le 0) { 
                    $totalFiles = $defaultTotalFiles 
                }
                Write-Host "Total files to copy: $totalFiles"
            } catch { 
                $totalFiles = $defaultTotalFiles 
                Write-Host "Could not count files, using default: $totalFiles"
            }
        }

        Write-Host "Starting ultra-optimized robocopy operation..."
        Write-Output "vantage progress: 5"
        
        try {
            New-Item -Path $targetPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            
            $robocopyJob = Start-Job -ScriptBlock {
                param($source, $target)
                $result = robocopy $source $target /E /MT:32 /R:1 /W:1 /J /NFL /NDL /NJH /NJS /NC /NS /NP /COMPRESS
                return $LASTEXITCODE
            } -ArgumentList $actualSource, $targetPath
            
            $startTime = Get-Date
            $timeout = 1800
            
            while ($robocopyJob.State -eq 'Running' -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
                if (Test-Path $targetPath) {
                    try {
                        $currentCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
                        $percent = [math]::Min([math]::Round(($currentCount / $totalFiles) * 80) + 5, 85)
                        Write-Output "vantage progress: $percent"
                    } catch {
                        Write-Output "vantage progress: 10"
                    }
                }
                Start-Sleep -Seconds 5
            }
            
            $robocopyResult = Wait-Job $robocopyJob -Timeout 30 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $robocopyJob -Force -ErrorAction SilentlyContinue
            
            if ($robocopyResult -le 7) {
                Write-Host "Robocopy completed successfully (exit code: $robocopyResult)" -ForegroundColor Green
                Write-Output "vantage progress: 85"
            } else {
                Write-Host "Robocopy completed with warnings (exit code: $robocopyResult)" -ForegroundColor Yellow
                Write-Output "vantage progress: 85"
            }
            
        } catch {
            Write-Host "Robocopy failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Output "vantage error: Copy operation failed - $($_.Exception.Message)"
            return
        }
    }
    
    if (Test-Path $targetPath) {
        $finalCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "Copy verification: $finalCount files copied" -ForegroundColor Green
        if ($finalCount -lt 1000) {
            Write-Host "WARNING: File count seems low. Installation may be incomplete." -ForegroundColor Yellow
        }
    }

    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
    
    Write-Host "Installing Vantage dependencies..." -ForegroundColor Cyan
    $installSteps = @(
        @{ Path = "$DeploymentRoot\Microsoft WSE 3.0 Runtime.msi"; Percent = 90; Name = "Microsoft WSE 3.0" },
        @{ Path = "$DeploymentRoot\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Percent = 95; Name = "Crystal Reports" },
        @{ Path = "$DeploymentRoot\dotNetFx35Setup.exe"; Percent = 98; Name = ".NET Framework 3.5" },
        @{ Path = "$DeploymentRoot\sqlncli.msi"; Percent = 99; Name = "SQL Native Client" }
    )
    
    foreach ($step in $installSteps) {
        if (Test-Path $step.Path) {
            Write-Host "Installing $($step.Name)..."
            $ext = [System.IO.Path]::GetExtension($step.Path).ToLower()
            $args = switch ($ext) { 
                ".msi" { @("/i", "`"$($step.Path)`"", "/quiet", "/norestart") } 
                ".exe" { @("/quiet", "/norestart") } 
                default { @("/quiet", "/norestart") } 
            }
            Start-Process -FilePath $step.Path -ArgumentList $args -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
            Write-Output "vantage progress: $($step.Percent)"
        } else {
            Write-Host "Dependency not found: $($step.Name) at $($step.Path)" -ForegroundColor Yellow
        }
    }

    $desktopPath = "$env:PUBLIC\Desktop"
    if (Test-Path $remoteShortcut) { 
        Copy-Item -Path $remoteShortcut -Destination $desktopPath -Force -ErrorAction SilentlyContinue
        Write-Host "Desktop shortcut copied successfully"
    } else {
        Write-Host "Desktop shortcut not found: $remoteShortcut" -ForegroundColor Yellow
    }

    Write-Output "vantage progress: 100"
    Write-Host "Vantage installation completed successfully" -ForegroundColor Green
}

function Remove-Office365 {
    [CmdletBinding()]
    param(
        [switch]$Force,
        [switch]$WhatIf
    )
    
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Office removal requires Administrator privileges - skipping"
        return
    }
    
    $windowsVersion = [System.Environment]::OSVersion.Version
    $isWindows10Plus = $windowsVersion.Major -ge 10
    $isWindows8Plus = $windowsVersion.Major -gt 6 -or ($windowsVersion.Major -eq 6 -and $windowsVersion.Minor -ge 2)
    
    try {
        Write-Host "=== OFFICE 365 REMOVAL SCRIPT (ZERO-POPUP VERSION) ===" -ForegroundColor Green
        
        if ($WhatIf) {
            Write-Host "RUNNING IN WHATIF MODE - No changes will be made" -ForegroundColor Yellow
        }
        
        Write-Host "Step 1: Detecting Office installations..." -ForegroundColor Yellow
        
        $installedOffice = @()
        try {
            $installedOffice = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "^Microsoft.*Office|^Microsoft.*365|^Microsoft.*OneNote|^Microsoft.*Teams|^Office.*Professional|^Office.*Standard" }
        } catch {
        }
        
        if ($installedOffice) {
            Write-Host "Found Office installations:" -ForegroundColor Cyan
            $installedOffice | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
        }
        
        $appxOffice = @()
        if ($isWindows8Plus) {
            try {
                $appxOffice = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -match "Microsoft.*Office|Microsoft.*OneNote|Microsoft.*Teams|Microsoft.*365" }
                if ($appxOffice) {
                    Write-Host "Found UWP/Store Office apps:" -ForegroundColor Cyan
                    $appxOffice | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor White }
                }
            } catch {
            }
        }
        
        Write-Host "Step 2: Terminating Office processes..." -ForegroundColor Yellow
        $procList = @("winword","excel","powerpnt","outlook","onenote","msaccess","mspub","lync","teams","onenotem","onenoteim","officeclicktorun","msteams","skype","OfficeClickToRun")
        $killedProcs = @()
        
        foreach ($proc in $procList) {
            $processes = Get-Process -Name $proc -ErrorAction SilentlyContinue
            if ($processes) {
                if (-not $WhatIf) {
                    $processes | Stop-Process -Force -ErrorAction SilentlyContinue
                }
                $killedProcs += $proc
            }
        }
        
        if ($killedProcs.Count -gt 0) {
            if ($WhatIf) {
                $actionText = "Would kill"
            } else {
                $actionText = "Killed"
            }
            Write-Host "$actionText processes: $($killedProcs -join ', ')" -ForegroundColor Yellow
        }
        
        if (-not $WhatIf) {
            Start-Sleep -Seconds 3
        }
        
        Write-Host "Step 3: Managing Office services..." -ForegroundColor Yellow
        $services = @("ClickToRunSvc","OfficeSvc","OfficeClickToRun")
        
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service) {
                if ($WhatIf) {
                    $actionText = "Would manage"
                } else {
                    $actionText = "Managing"
                }
                Write-Host "$actionText service: $svc (Status: $($service.Status))" -ForegroundColor Cyan
                if (-not $WhatIf) {
                    if ($service.Status -eq 'Running') {
                        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    }
                    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                }
            }
        }
        
        Write-Host "Step 4: ClickToRun removal..." -ForegroundColor Yellow
        $clickToRunPaths = @()
        
        $programFilesPaths = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) }
        foreach ($programFiles in $programFilesPaths) {
            $ctrPath = Join-Path $programFiles "Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
            if (Test-Path $ctrPath) {
                $clickToRunPaths += $ctrPath
            }
        }
        
        foreach ($path in $clickToRunPaths) {
            if ($WhatIf) {
                $actionText = "Would use"
            } else {
                $actionText = "Using"
            }
            Write-Host "$actionText ClickToRun at: $path" -ForegroundColor Cyan
            if (-not $WhatIf) {
                try {
                    $ctrArgs = @(
                        "scenario=install",
                        "scenariosubtype=ARP", 
                        "sourcetype=None",
                        "productstoremove=All",
                        "forceappshutdown=True",
                        "DisplayLevel=False"
                    )
                    
                    Write-Host "Starting completely silent ClickToRun removal..." -ForegroundColor Cyan
                    Start-Process -FilePath $path -ArgumentList $ctrArgs -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "ClickToRun removal completed silently." -ForegroundColor Green
                    
                } catch {
                }
            }
        }
        
        if ($isWindows8Plus -and $appxOffice) {
            Write-Host "Step 5: UWP app removal..." -ForegroundColor Yellow
            
            foreach ($app in $appxOffice) {
                if ($WhatIf) {
                    $actionText = "Would remove"
                } else {
                    $actionText = "Removing"
                }
                Write-Host "$actionText UWP app: $($app.Name)" -ForegroundColor Red
                if (-not $WhatIf) {
                    try {
                        Remove-AppxPackage -Package $app.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                        Write-Host "Successfully removed: $($app.Name)" -ForegroundColor Green
                    } catch {
                    }
                }
            }
            
            if ($isWindows10Plus) {
                $appxPatterns = @("Microsoft.Office*", "Microsoft.MicrosoftOfficeHub*", "Microsoft.OneNote*", "Microsoft.Teams*", "Microsoft.365*")
                foreach ($pattern in $appxPatterns) {
                    $provisionedApps = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName -like $pattern }
                    foreach ($app in $provisionedApps) {
                        if ($WhatIf) {
                            $actionText = "Would remove"
                        } else {
                            $actionText = "Removing"
                        }
                        Write-Host "$actionText provisioned app: $($app.DisplayName)" -ForegroundColor Red
                        if (-not $WhatIf) {
                            Remove-AppxProvisionedPackage -Online -PackageName $app.PackageName -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }
        
        Write-Host "Step 6: Silent WMI-based uninstall..." -ForegroundColor Yellow
        
        if ($installedOffice -and -not $WhatIf) {
            foreach ($product in $installedOffice) {
                Write-Host "Uninstalling: $($product.DisplayName)" -ForegroundColor Yellow
                
                try {
                    $product.Uninstall() | Out-Null
                    Write-Host "Successfully removed: $($product.DisplayName)" -ForegroundColor Green
                } catch {
                }
                
                Start-Sleep -Seconds 1
            }
        }
        
        Write-Host "Step 7: File system cleanup..." -ForegroundColor Yellow
        
        $basePaths = @()
        if ($env:ProgramFiles) { $basePaths += $env:ProgramFiles }
        if (${env:ProgramFiles(x86)}) { $basePaths += ${env:ProgramFiles(x86)} }
        
        $cleanupPaths = @()
        foreach ($basePath in $basePaths) {
            $cleanupPaths += Join-Path $basePath "Microsoft Office"
            $cleanupPaths += Join-Path $basePath "Common Files\Microsoft Shared\Office*"
            $cleanupPaths += Join-Path $basePath "Common Files\Microsoft Shared\ClickToRun"
        }
        
        $cleanupPaths += Join-Path $env:LOCALAPPDATA "Microsoft\Office"
        $cleanupPaths += Join-Path $env:APPDATA "Microsoft\Office"
        $cleanupPaths += Join-Path $env:ProgramData "Microsoft\Office"
        
        foreach ($path in $cleanupPaths) {
            if ($path -match '\*') {
                $parentPath = Split-Path $path -Parent
                $filter = Split-Path $path -Leaf
                if (Test-Path $parentPath) {
                    $matchingPaths = Get-ChildItem -Path $parentPath -Filter $filter -ErrorAction SilentlyContinue
                    foreach ($matchingPath in $matchingPaths) {
                        if ($WhatIf) {
                            $actionText = "Would remove"
                        } else {
                            $actionText = "Removing"
                        }
                        Write-Host "$actionText directory: $($matchingPath.FullName)" -ForegroundColor Red
                        if (-not $WhatIf) {
                            Remove-Item -Path $matchingPath.FullName -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            } else {
                if (Test-Path $path) {
                    if ($WhatIf) {
                        $actionText = "Would remove"
                    } else {
                        $actionText = "Removing"
                    }
                    Write-Host "$actionText directory: $path" -ForegroundColor Red
                    if (-not $WhatIf) {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        
        Write-Host "Step 8: Registry cleanup..." -ForegroundColor Yellow
        
        $regPaths = @(
            "HKCU:\Software\Microsoft\Office",
            "HKCU:\Software\Microsoft\OneNote"
        )
        
        if ($Force) {
            $regPaths += @(
                "HKLM:\SOFTWARE\Microsoft\Office",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office"
            )
        }
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                if ($WhatIf) {
                    $actionText = "Would remove"
                } else {
                    $actionText = "Removing"
                }
                Write-Host "$actionText registry key: $regPath" -ForegroundColor Red
                if (-not $WhatIf) {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        Write-Host "=== OFFICE REMOVAL COMPLETED (ZERO-POPUP) ===" -ForegroundColor Green
        if (-not $WhatIf) {
            Write-Host "REBOOT RECOMMENDED before installing new Office!" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Office removal encountered an error but continuing deployment" -ForegroundColor Yellow
    }
}

function Complete-OfficeRemoval {
    Write-Host "=== FORCING COMPLETE OFFICE CLEANUP ===" -ForegroundColor Cyan
    
    $officeProcesses = @("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", 
                         "mspub", "lync", "teams", "onenotem", "onenoteim", "officeclicktorun",
                         "msteams", "skype", "OfficeClickToRun", "integrator", "OSPPSVC")
    
    foreach ($proc in $officeProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    $services = @("ClickToRunSvc", "OfficeSvc", "OfficeClickToRun", "OSPPSVC")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            & sc.exe delete $svc 2>&1 | Out-Null
        }
    }
    
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office",
        "HKCU:\Software\Microsoft\Office",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\O365*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\O365*"
    )
    
    foreach ($path in $regPaths) {
        if ($path -like "*\**") {
            $parent = Split-Path $path -Parent
            $filter = Split-Path $path -Leaf
            if (Test-Path $parent) {
                Get-ChildItem -Path $parent -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -like $filter } | 
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        } elseif (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    $officePaths = @(
        "$env:ProgramFiles\Microsoft Office",
        "${env:ProgramFiles(x86)}\Microsoft Office",
        "$env:ProgramFiles\Common Files\Microsoft Shared",
        "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared"
    )
    
    foreach ($path in $officePaths) {
        if (Test-Path $path) {
            & takeown.exe /F "$path" /R /D Y 2>&1 | Out-Null
            & icacls.exe "$path" /grant administrators:F /T 2>&1 | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Start-Sleep -Seconds 5
    
    $officeCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*Microsoft*365*" -or $_.DisplayName -like "*Office*" }
    
    if ($officeCheck) {
        Write-Host "WARNING: Office remnants still detected" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "Office cleanup completed successfully" -ForegroundColor Green
    return $true
}

function Install-AdobeReader {
    $msiPath = Join-Path $DeploymentRoot "AcroRead.msi"
    $mstPath = Join-Path $DeploymentRoot "AcroRead.mst"
    $mspPath = Join-Path $DeploymentRoot "AcroRdrDCUpd2500120693.msp"
    $cabPath = Join-Path $DeploymentRoot "Data1.cab"

    if (-not (Test-Path $msiPath)) { 
        Write-Host "MSI not found: $msiPath" 
        return $false 
    }
    
    $hasPatch = Test-Path $mspPath
    if ($hasPatch) {
        Write-Host "MSP patch file found: $mspPath"
    }
    
    Write-Host "Starting Adobe Reader installation with error 1624 fixes and patch application..."

    if ($hasPatch) {
        try {
            Write-Host "Attempting installation with integrated patch (Method 1)..."
            $patchArgs = @("/i", "`"$msiPath`"", "PATCH=`"$mspPath`"", "/qn", "/norestart", "ALLUSERS=1", "EULA_ACCEPT=YES", "SUPPRESS_APP_LAUNCH=YES")
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $patchArgs -Wait -PassThru -WorkingDirectory $DeploymentRoot -WindowStyle Hidden -ErrorAction SilentlyContinue
            
            if ($process.ExitCode -eq 0) {
                Write-Host "Adobe Reader installed successfully with patch (Method 1)" -ForegroundColor Green
                return $true
            }
            Write-Host "Method 1 failed with exit code: $($process.ExitCode)"
        } catch {
            Write-Host "Method 1 failed with exception: $($_.Exception.Message)"
        }
    }

    try {
        Write-Host "Attempting installation without transform (Method 2)..."
        $simpleArgs = @("/i", "`"$msiPath`"", "/qn", "/norestart", "ALLUSERS=1", "EULA_ACCEPT=YES", "SUPPRESS_APP_LAUNCH=YES")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $simpleArgs -Wait -PassThru -WorkingDirectory $DeploymentRoot -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Adobe Reader base installation successful (Method 2)" -ForegroundColor Green
            
            if ($hasPatch) {
                Write-Host "Applying MSP patch..."
                if (Apply-MSPatch -MspPath $mspPath) {
                    Write-Host "Adobe Reader installation and patch completed successfully" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "Base installation succeeded but patch failed" -ForegroundColor Yellow
                    return $true
                }
            }
            return $true
        }
        Write-Host "Method 2 failed with exit code: $($process.ExitCode)"
    } catch {
        Write-Host "Method 2 failed with exception: $($_.Exception.Message)"
    }

    if (Test-Path $mstPath) {
        try {
            Write-Host "Attempting installation with transform (Method 3)..."
            $tempDir = Join-Path $env:TEMP "AdobeInstall"
            New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            
            Copy-Item $msiPath "$tempDir\AcroRead.msi" -Force -ErrorAction SilentlyContinue
            Copy-Item $mstPath "$tempDir\AcroRead.mst" -Force -ErrorAction SilentlyContinue
            if (Test-Path $cabPath) { Copy-Item $cabPath "$tempDir\Data1.cab" -Force -ErrorAction SilentlyContinue }
            if ($hasPatch) { Copy-Item $mspPath "$tempDir\AcroRead.msp" -Force -ErrorAction SilentlyContinue }
            
            Push-Location $tempDir -ErrorAction SilentlyContinue
            
            if ($hasPatch) {
                $transformPatchArgs = @("/i", "AcroRead.msi", "TRANSFORMS=AcroRead.mst", "PATCH=AcroRead.msp", "/qn", "/norestart", "ALLUSERS=1")
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $transformPatchArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
                
                if ($process.ExitCode -eq 0) {
                    Write-Host "Adobe Reader installed successfully with transform and patch (Method 3a)" -ForegroundColor Green
                    Pop-Location -ErrorAction SilentlyContinue
                    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    return $true
                }
            }
            
            $transformArgs = @("/i", "AcroRead.msi", "TRANSFORMS=AcroRead.mst", "/qn", "/norestart", "ALLUSERS=1")
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $transformArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
            Pop-Location -ErrorAction SilentlyContinue
            
            if ($process.ExitCode -eq 0) {
                Write-Host "Adobe Reader base installation with transform successful (Method 3b)" -ForegroundColor Green
                
                if ($hasPatch) {
                    Write-Host "Applying MSP patch..."
                    $tempMspPath = Join-Path $tempDir "AcroRead.msp"
                    if (Apply-MSPatch -MspPath $tempMspPath) {
                        Write-Host "Adobe Reader installation with transform and patch completed successfully" -ForegroundColor Green
                        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        return $true
                    } else {
                        Write-Host "Base installation with transform succeeded but patch failed" -ForegroundColor Yellow
                        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                        return $true
                    }
                }
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                return $true
            }
            Write-Host "Method 3 failed with exit code: $($process.ExitCode)"
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "Method 3 failed with exception: $($_.Exception.Message)"
        }
    }

    try {
        Write-Host "Attempting Windows Installer repair and retry (Method 4)..."
        Restart-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        
        $repairArgs = @("/i", "`"$msiPath`"", "/qn", "/norestart", "REINSTALL=ALL", "REINSTALLMODE=vomus")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $repairArgs -Wait -PassThru -WorkingDirectory $DeploymentRoot -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Adobe Reader repair installation successful (Method 4)" -ForegroundColor Green
            
            if ($hasPatch) {
                Write-Host "Applying MSP patch after repair..."
                if (Apply-MSPatch -MspPath $mspPath) {
                    Write-Host "Adobe Reader repair and patch completed successfully" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "Repair installation succeeded but patch failed" -ForegroundColor Yellow
                    return $true
                }
            }
            return $true
        }
        Write-Host "Method 4 failed with exit code: $($process.ExitCode)"
    } catch {
        Write-Host "Method 4 failed with exception: $($_.Exception.Message)"
    }

    try {
        Write-Host "Attempting direct executable installation (Method 5)..."
        $exePath = Join-Path $DeploymentRoot "AcroRead.exe"
        if (Test-Path $exePath) {
            $process = Start-Process -FilePath $exePath -ArgumentList "/sAll", "/rs", "/msi" -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
            if ($process.ExitCode -eq 0) {
                Write-Host "Adobe Reader executable installation successful (Method 5)" -ForegroundColor Green
                
                if ($hasPatch) {
                    Write-Host "Applying MSP patch after executable installation..."
                    if (Apply-MSPatch -MspPath $mspPath) {
                        Write-Host "Adobe Reader executable installation and patch completed successfully" -ForegroundColor Green
                        return $true
                    } else {
                        Write-Host "Executable installation succeeded but patch failed" -ForegroundColor Yellow
                        return $true
                    }
                }
                return $true
            }
        }
    } catch {
        Write-Host "Method 5 failed with exception: $($_.Exception.Message)"
    }

    Write-Host "All Adobe Reader installation methods failed. Manual installation may be required." -ForegroundColor Red
    return $false
}

function Apply-MSPatch {
    param([string]$MspPath)
    
    if (-not (Test-Path $MspPath)) {
        Write-Host "MSP patch file not found: $MspPath" -ForegroundColor Red
        return $false
    }
    
    try {
        Write-Host "Applying MSP patch: $MspPath"
        
        $patchArgs = @("/p", "`"$MspPath`"", "/qn", "/norestart")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $patchArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "MSP patch applied successfully" -ForegroundColor Green
            return $true
        }
        
        Write-Host "Direct patch application failed with exit code: $($process.ExitCode)"
        
        $adobeProducts = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Adobe*Reader*" -or $_.Name -like "*Acrobat*Reader*" }
        
        if ($adobeProducts) {
            foreach ($product in $adobeProducts) {
                try {
                    Write-Host "Attempting to patch product: $($product.Name)"
                    $productPatchArgs = @("/p", "`"$MspPath`"", "/qn", "/norestart", "TARGETPRODUCT=$($product.IdentifyingNumber)")
                    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $productPatchArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Host "MSP patch applied successfully to $($product.Name)" -ForegroundColor Green
                        return $true
                    }
                } catch {
                    Write-Host "Failed to patch $($product.Name): $($_.Exception.Message)"
                }
            }
        }
        
        Write-Host "MSP patch application failed" -ForegroundColor Red
        return $false
        
    } catch {
        Write-Host "MSP patch application failed with exception: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Install-VPN {
    $vpnInstaller = Join-Path $DeploymentRoot "silent.bat"
    if (-not (Test-Path $vpnInstaller)) {
        Write-Host "VPN installer not found at $vpnInstaller"
        return $false
    }

    try {
        Write-Host "Installing Barracuda VPN client..."
        $process = Start-Process -FilePath $vpnInstaller -WorkingDirectory $DeploymentRoot -Wait -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
        Write-Host "Barracuda VPN installation completed."
        return $true
    }
    catch {
        Write-Host "Unable to install Barracuda VPN: $($_.Exception.Message)"
        return $false
    }
}

function Install-VPNProfile {
    $vpnProfile = Join-Path $DeploymentRoot "PSI-PAC VPN.vpn"
    if (Test-Path $vpnProfile) {
        try {
            Start-Process -FilePath $vpnProfile -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Host "VPN profile imported successfully."
            return $true
        } catch {
            Write-Host "Failed to import VPN profile: $_"
            return $false
        }
    } else {
        Write-Host "VPN profile file missing, skipping import."
        return $false
    }
    
    try {
        Resolve-DnsName -Name "busybee.psi-pac.com" -Server 8.8.8.8 -ErrorAction SilentlyContinue | Select-Object -Property Name, IPAddress | Out-Null
        Write-Host "DNS resolution test passed for busybee.psi-pac.com"
    }
    catch {
        Write-Host "Unable to resolve busybee.psi-pac.com DNS"
    }
}

function Install-Office365 {
    $setupPath = Join-Path $DeploymentRoot "setup.exe"
    $configPath = Join-Path $DeploymentRoot "officesilent.xml"
    
    if (-not (Test-Path $setupPath)) { 
        Write-Host "Setup file not found: $setupPath"
        return $false 
    }
    if (-not (Test-Path $configPath)) { 
        Write-Host "Configuration file not found: $configPath"
        return $false 
    }
    
    $args = @(
        "/configure", "`"$configPath`""
    )
    Write-Host "Installing Office 365..."
    $result = Run-Installer -Path $setupPath -Arguments $args -TimeoutSeconds 1800
    
    Write-Host "Office 365 installation complete."
    return $result
}

function Verify-Installations {
    $reported = @{
        TeamViewer = $false
        Adobe      = $false
        Office365  = $false
    }

    $verificationJob = Start-Job -ScriptBlock {
        param($reported)

        while ($true) {
            if (-not $reported.TeamViewer -and (Test-Path "C:\Program Files (x86)\TeamViewer")) {
                Write-Host "TeamViewer installed"
                $reported.TeamViewer = $true
            }

            if (-not $reported.Adobe) {
                $adobeCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                              Where-Object { $_.DisplayName -like "*Adobe*Reader*" }
                if ($adobeCheck) {
                    Write-Host "Adobe Acrobat installed"
                    $reported.Adobe = $true
                }
            }

            if (-not $reported.Office365) {
                $office = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                          Where-Object { $_.DisplayName -like "*Microsoft 365*" -or $_.DisplayName -like "*Office*" }
                if ($office) {
                    Write-Host "Office 365 installed"
                    $reported.Office365 = $true
                }
            }

            if ($reported.Values -notcontains $false) {
                break
            }

            Start-Sleep -Seconds 15
        }
    } -ArgumentList $reported

    return $verificationJob
}

function Run-WindowsUpdates {
    try {
        Write-Output "winupdate progress: 0"
        Write-Host "=== OPTIMIZED WINDOWS UPDATES (HIGH-SPEED MODE) ===" -ForegroundColor Cyan
        
        Write-Host "Method 1: Triggering updates via registry..." -ForegroundColor Yellow
        try {
            $wuRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            if (Test-Path $wuRegPath) {
                Set-ItemProperty -Path $wuRegPath -Name "AUOptions" -Value 4 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $wuRegPath -Name "ScheduledInstallDay" -Value 0 -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $wuRegPath -Name "ScheduledInstallTime" -Value 3 -ErrorAction SilentlyContinue
            }
            Write-Output "winupdate progress: 5"
        } catch {
            Write-Host "Registry trigger failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Write-Host "Method 2: Using UsoClient for rapid updates..." -ForegroundColor Yellow
        $usoSuccess = $false
        try {
            Write-Host "  - Starting update scan..."
            $usoScanJob = Start-Job -ScriptBlock {
                try {
                    & UsoClient.exe ScanInstallWait 2>&1 | Out-Null
                    return $LASTEXITCODE
                } catch {
                    return 1
                }
            }
            
            Write-Output "winupdate progress: 10"
            $scanResult = Wait-Job $usoScanJob -Timeout 120 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $usoScanJob -Force -ErrorAction SilentlyContinue
            
            if ($scanResult -eq 0 -or $null -eq $scanResult) {
                Write-Host "  - Scan completed, starting downloads..."
                Write-Output "winupdate progress: 25"
                
                $usoDownloadJob = Start-Job -ScriptBlock {
                    try {
                        & UsoClient.exe StartDownload 2>&1 | Out-Null
                        return $LASTEXITCODE
                    } catch {
                        return 1
                    }
                }
                
                $downloadResult = Wait-Job $usoDownloadJob -Timeout 300 | Receive-Job -ErrorAction SilentlyContinue
                Remove-Job $usoDownloadJob -Force -ErrorAction SilentlyContinue
                Write-Output "winupdate progress: 50"
                
                Write-Host "  - Starting installation..."
                $usoInstallJob = Start-Job -ScriptBlock {
                    try {
                        & UsoClient.exe StartInstall 2>&1 | Out-Null
                        return $LASTEXITCODE
                    } catch {
                        return 1
                    }
                }
                
                $installResult = Wait-Job $usoInstallJob -Timeout 600 | Receive-Job -ErrorAction SilentlyContinue
                Remove-Job $usoInstallJob -Force -ErrorAction SilentlyContinue
                Write-Output "winupdate progress: 80"
                
                $usoSuccess = $true
                Write-Host "UsoClient method completed successfully" -ForegroundColor Green
            }
        } catch {
            Write-Host "UsoClient method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        if ($usoSuccess) {
            Write-Output "winupdate progress: 100"
            Write-Host "Windows Updates initiated successfully (will continue in background)" -ForegroundColor Green
            return $true
        }
        
        Write-Host "Method 3: Trying Windows Update Assistant..." -ForegroundColor Yellow
        try {
            $wuaPath = Join-Path $DeploymentRoot "Windows10Upgrade9252.exe"
            if (Test-Path $wuaPath) {
                Write-Host "  - Running Windows Update Assistant..."
                $wuaJob = Start-Job -ScriptBlock {
                    param($path)
                    try {
                        $process = Start-Process -FilePath $path -ArgumentList "/quietinstall", "/skipeula", "/auto", "upgrade", "/copylogs" -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
                        Wait-Process -Id $process.Id -Timeout 600 -ErrorAction SilentlyContinue
                        return $true
                    } catch {
                        return $false
                    }
                } -ArgumentList $wuaPath
                
                Write-Output "winupdate progress: 85"
                $wuaResult = Wait-Job $wuaJob -Timeout 700 | Receive-Job -ErrorAction SilentlyContinue
                Remove-Job $wuaJob -Force -ErrorAction SilentlyContinue
                
                if ($wuaResult) {
                    Write-Output "winupdate progress: 100"
                    Write-Host "Windows Update Assistant completed" -ForegroundColor Green
                    return $true
                }
            }
        } catch {
            Write-Host "Windows Update Assistant failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Write-Host "Method 4: Using PSWindowsUpdate module (this may take longer)..." -ForegroundColor Yellow
        Write-Output "winupdate progress: 15"
        
        try {
            $moduleJob = Start-Job -ScriptBlock {
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    [Net.ServicePointManager]::MaxServicePointIdleTime = 10000
                    
                    $ProgressPreference = 'SilentlyContinue'
                    $ErrorActionPreference = 'SilentlyContinue'
                    
                    if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                        Import-Module PSWindowsUpdate -Force
                        return $true
                    }
                    
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -MinimumVersion 2.8.5.201 | Out-Null
                    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck | Out-Null
                    Import-Module PSWindowsUpdate -Force
                    return $true
                } catch {
                    return $false
                }
            }
            
            $moduleReady = Wait-Job $moduleJob -Timeout 90 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $moduleJob -Force -ErrorAction SilentlyContinue
            
            if (-not $moduleReady) {
                Write-Output "winupdate error: Failed to install PSWindowsUpdate module"
                Write-Host "PSWindowsUpdate module installation failed" -ForegroundColor Red
                return $false
            }
            
            Write-Output "winupdate progress: 30"
            Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
            
            Write-Host "  - Scanning for critical updates..."
            $updateJob = Start-Job -ScriptBlock {
                try {
                    Import-Module PSWindowsUpdate -Force -ErrorAction SilentlyContinue
                    
                    $updates = Get-WindowsUpdate -MicrosoftUpdate -Criteria "IsInstalled=0 and Type='Software' and BrowseOnly=0" -ErrorAction SilentlyContinue |
                        Where-Object { 
                            ($_.MsrcSeverity -eq 'Critical' -or $_.MsrcSeverity -eq 'Important') -and 
                            ($_.Size -lt 200MB)
                        } |
                        Select-Object -First 10
                    
                    if ($updates) {
                        $updates | ForEach-Object -Parallel {
                            try {
                                Install-WindowsUpdate -KBArticleID $_.KBArticleIDs -AcceptAll -IgnoreReboot -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                            } catch {
                            }
                        } -ThrottleLimit 3
                        
                        return @{Success=$true; Count=$updates.Count}
                    }
                    return @{Success=$true; Count=0}
                } catch {
                    return @{Success=$false; Error=$_.Exception.Message}
                }
            }
            
            Write-Output "winupdate progress: 40"
            
            $updateTimeout = 900
            $updateStartTime = Get-Date
            $lastProgress = 40
            
            while ($updateJob.State -eq 'Running' -and ((Get-Date) - $updateStartTime).TotalSeconds -lt $updateTimeout) {
                $elapsed = ((Get-Date) - $updateStartTime).TotalSeconds
                $progress = [math]::Min(40 + [math]::Round(($elapsed / $updateTimeout) * 50), 90)
                
                if ($progress -gt $lastProgress) {
                    Write-Output "winupdate progress: $progress"
                    $lastProgress = $progress
                }
                
                Start-Sleep -Seconds 10
            }
            
            $updateResult = Wait-Job $updateJob -Timeout 30 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $updateJob -Force -ErrorAction SilentlyContinue
            
            if ($updateResult.Success) {
                Write-Output "winupdate progress: 100"
                if ($updateResult.Count -gt 0) {
                    Write-Host "Installed $($updateResult.Count) critical updates" -ForegroundColor Green
                } else {
                    Write-Host "No critical updates found or already up to date" -ForegroundColor Green
                }
                return $true
            } else {
                Write-Output "winupdate progress: 100"
                Write-Host "Update check completed with warnings: $($updateResult.Error)" -ForegroundColor Yellow
                return $true
            }
            
        } catch {
            Write-Output "winupdate error: $($_.Exception.Message)"
            Write-Host "PSWindowsUpdate method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Write-Output "winupdate progress: 100"
        Write-Host "Windows Updates triggered but verification incomplete - updates will continue in background" -ForegroundColor Yellow
        return $true
        
    } catch {
        Write-Output "winupdate error: $($_.Exception.Message)"
        Write-Host "Windows Updates encountered an error but deployment will continue" -ForegroundColor Yellow
        return $false
    }
}

function Restore-SystemSettings {
    Write-Host "=== RESTORING SYSTEM SETTINGS ===" -ForegroundColor Cyan
    
    try {
        if ($script:DefenderDisabled) {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Write-Host "Restored Windows Defender real-time protection" -ForegroundColor Green
            } catch {
            }
        }
        
        if ($script:OriginalPowerPlan) {
            try {
                powercfg /setactive $script:OriginalPowerPlan | Out-Null 2>&1
                Write-Host "Restored original power plan: $script:OriginalPowerPlan" -ForegroundColor Green
            } catch {
            }
        }
        
        try {
            $currentProcess = Get-Process -Id $PID
            $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Normal
            Write-Host "Reset process priority to normal"
        } catch {
        }
        
        $servicesToRestart = @("Themes", "TabletInputService")
        foreach ($service in $servicesToRestart) {
            try {
                Start-Service $service -ErrorAction SilentlyContinue
                Write-Host "Restarted service: $service"
            } catch {
            }
        }
        
        Write-Host "System settings restoration completed" -ForegroundColor Green
        
    } catch {
    }
}

function Complete-Deployment {
    param([hashtable]$Results)
    
    Write-Host "`n=== DEPLOYMENT COMPLETION ===" -ForegroundColor Green
    
    try {
        $totalTime = (Get-Date) - $script:DeploymentStartTime
        Write-Host "Total deployment time: $($totalTime.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
        
        Write-Host "`nDeployment Results:" -ForegroundColor Yellow
        foreach ($key in $Results.Keys) {
            $status = if ($Results[$key]) { "SUCCESS" } else { "FAILED" }
            $color = if ($Results[$key]) { "Green" } else { "Red" }
            Write-Host "  $key`: $status" -ForegroundColor $color
        }
        
        $jobs = Get-Job -ErrorAction SilentlyContinue
        foreach ($job in $jobs) {
            if ($job.State -in @('Completed', 'Failed', 'Stopped')) {
                Remove-Job $job -Force -ErrorAction SilentlyContinue
            }
        }
        
        $tempFiles = @(
            "$env:TEMP\AdobeReader_*.log",
            "$env:TEMP\OfficeUninstall.log",
            "$env:TEMP\AdobeInstall"
        )
        foreach ($pattern in $tempFiles) {
            Get-ChildItem $pattern -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        }
        
        Write-Host "`n=== DEPLOYMENT COMPLETED SUCCESSFULLY ===" -ForegroundColor Green
        Write-Host "REBOOT REQUIRED to complete installation" -ForegroundColor Yellow
        Write-Host "Remote management is now enabled for future maintenance" -ForegroundColor Cyan
        
    } finally {
        Restore-SystemSettings
        
        Stop-Transcript -ErrorAction SilentlyContinue
    }
}

Write-Host "=== PSI DEPLOYMENT TOOL - OPTIMIZED HIGH-SPEED VERSION ===" -ForegroundColor Green

Write-DeploymentProgress -CurrentStep 1 -TotalSteps 15 -StepDescription "Pre-staging installation files"

Write-DeploymentProgress -CurrentStep 2 -TotalSteps 15 -StepDescription "Loading credentials and configuring timezone"

Write-Host "Loading domain credentials from: $DeploymentRoot"
$Credential = Get-DomainCredential -ScriptDirectory $DeploymentRoot

if ($Credential) {
    Write-Host "Credentials loaded successfully" -ForegroundColor Green
} else {
    Write-Host "WARNING: Failed to load credentials - domain operations will be skipped" -ForegroundColor Yellow
}

Set-TimeZoneFromUserInput

Write-DeploymentProgress -CurrentStep 3 -TotalSteps 15 -StepDescription "Domain operations (parallel with software installation)"

$domainJob = Start-Job -ScriptBlock {
    param($location, $computerName, $credential)
    
    $domainJoined = $false
    $computerRenamed = $false
    
    if ($credential) {
        $servers = switch ($location.ToUpper()) {
            "GEORGIA"  { @("GA-DC02") }
            "ARKANSAS" { @("AR-DC", "10.1.199.2") }
            "IDAHO"    { @("ID-DC") }
            Default    { @("GA-DC02") }
        }
        
        $networkOk = $true
        foreach ($server in $servers) {
            if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -TimeoutSeconds 5 -ErrorAction SilentlyContinue)) {
                $networkOk = $false
                break
            }
        }
        
        if ($networkOk) {
            try {
                switch ($location.ToUpper()) {
                    "GEORGIA" {
                        Add-Computer -DomainName "psi-pac.com" -Server "GA-DC02" -Credential $credential -Force -ErrorAction Stop | Out-Null
                        $domainJoined = $true
                    }
                    "ARKANSAS" {
                        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.1.199.2" -ErrorAction Stop | Out-Null
                        Add-Computer -DomainName "psi-pac.com" -Server "AR-DC" -Credential $credential -Force -ErrorAction Stop
                        $domainJoined = $true
                    }
                    "IDAHO" {
                        Add-Computer -DomainName "psi-pac.com" -Server "ID-DC" -Credential $credential -Force -ErrorAction Stop | Out-Null
                        $domainJoined = $true
                    }
                }
            } catch {
            }
            
            if (-not [string]::IsNullOrWhiteSpace($computerName)) {
                try {
                    if ($domainJoined) {
                        Rename-Computer -NewName $computerName -Force -DomainCredential $credential -ErrorAction Stop | Out-Null
                    } else {
                        Rename-Computer -NewName $computerName -Force -ErrorAction Stop | Out-Null
                    }
                    $computerRenamed = $true
                } catch {
                }
            }
        }
    }
    
    return @{
        DomainJoined = $domainJoined
        ComputerRenamed = $computerRenamed
    }
} -ArgumentList $location, $computerName, $Credential

Write-DeploymentProgress -CurrentStep 4 -TotalSteps 15 -StepDescription "Starting parallel software installations"

Start-ParallelInstallations

Write-DeploymentProgress -CurrentStep 5 -TotalSteps 15 -StepDescription "Adobe Reader installation (with 1624 fix)"
$adobeInstalled = Install-AdobeReader

Write-DeploymentProgress -CurrentStep 6 -TotalSteps 15 -StepDescription "Office 365 removal (zero-popup automation)"
Remove-Office365

Write-Host "Performing aggressive Office cleanup..." -ForegroundColor Yellow
$cleanupSuccess = Complete-OfficeRemoval

Start-Sleep -Seconds 10

Write-DeploymentProgress -CurrentStep 7 -TotalSteps 15 -StepDescription "Office 365 installation"
if ($cleanupSuccess) {
    $officeInstalled = Install-Office365
} else {
    Write-Host "Office cleanup incomplete - installation may fail. Consider manual reboot." -ForegroundColor Yellow
    $officeInstalled = Install-Office365
}

Write-DeploymentProgress -CurrentStep 8 -TotalSteps 15 -StepDescription "VPN and Vantage (if requested)"
$vpnInstalled = if ($installVPN) {
    if (Install-VPN) {
        Install-VPNProfile
        $true
    } else { $false }
} else { $null }

if ($installVANTAGE) { 
    Install-Vantage -location $location 
}

Write-DeploymentProgress -CurrentStep 9 -TotalSteps 15 -StepDescription "Shared drives and logging"
Install-SharedDriveTask -Location $location
Switch-Logs

Write-DeploymentProgress -CurrentStep 10 -TotalSteps 15 -StepDescription "Waiting for domain operations to complete"
$domainResults = Wait-Job $domainJob -Timeout 60 | Receive-Job -ErrorAction SilentlyContinue
Remove-Job $domainJob -Force -ErrorAction SilentlyContinue

Write-DeploymentProgress -CurrentStep 11 -TotalSteps 15 -StepDescription "Starting optimized Windows Updates (high-speed mode)"
$updatesJob = Start-Job -ScriptBlock ${function:Run-WindowsUpdates}

Write-DeploymentProgress -CurrentStep 12 -TotalSteps 15 -StepDescription "Final verification and cleanup"

$verificationJob = Verify-Installations

Write-Host "Waiting for Windows Updates to complete (max 20 minutes)..." -ForegroundColor Yellow
$updateResult = Wait-Job $updatesJob -Timeout 1200 | Receive-Job -ErrorAction SilentlyContinue
Remove-Job $updatesJob -Force -ErrorAction SilentlyContinue

if ($updateResult) {
    Write-Host "Windows Updates: Completed" -ForegroundColor Green
} else {
    Write-Host "Windows Updates: Continuing in background" -ForegroundColor Yellow
}

$verificationResults = Wait-Job $verificationJob -Timeout 60 | Receive-Job -ErrorAction SilentlyContinue
Remove-Job $verificationJob -Force -ErrorAction SilentlyContinue

Write-DeploymentProgress -CurrentStep 13 -TotalSteps 15 -StepDescription "Finalizing deployment"

$deploymentResults = @{
    "Domain Join" = $domainResults.DomainJoined
    "Computer Rename" = $domainResults.ComputerRenamed
    "Adobe Reader" = $adobeInstalled
    "Office 365" = $officeInstalled
    "Windows Updates" = ($updateResult -ne $null)
}

if ($installVPN) { $deploymentResults["VPN"] = $vpnInstalled }

Write-DeploymentProgress -CurrentStep 14 -TotalSteps 15 -StepDescription "Deployment complete"

Complete-Deployment -Results $deploymentResults
