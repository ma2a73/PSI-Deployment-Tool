param(
    [string]$timezone,
    [string]$location,
    [string]$computerName,
    [switch]$installVPN,
    [switch]$installVANTAGE
)

$localLogDirectory = "C:\Logs"
if (-not (Test-Path $localLogDirectory)) {
    New-Item -Path $localLogDirectory -ItemType Directory -Force | Out-Null
}

$logName = if (![string]::IsNullOrWhiteSpace($computerName)) { $computerName } else { $env:COMPUTERNAME }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName = "$logName-SetupLog-$timestamp.txt"
$localLogPath = Join-Path $localLogDirectory $logFileName

Start-Transcript -Path $localLogPath -NoClobber

if (-not $timezone) { throw "Timezone parameter is null or empty." } else { Write-Host "Received Timezone: $timezone" }
if (-not $location) { throw "Location parameter is null or empty." } else { Write-Host "Received Location: $location" }
if (-not $computerName) { throw "Computer name is null or empty." } else { Write-Host "Received Computer Name: $computerName" }

$folderPath = $PSScriptRoot
$keyPath = Join-Path $folderPath "key.key"
$encryptedPath = Join-Path $folderPath "encrypted.txt"
$key = Get-Content -Path $keyPath -Encoding Byte
$encrypted = Get-Content -Path $encryptedPath -Raw
$securePassword = $encrypted | ConvertTo-SecureString -Key $key
$Credential = New-Object System.Management.Automation.PSCredential("PSI-PAC\Support", $securePassword)

$jobQueue = @()

function Set-TimeZoneFromUserInput {
    switch ($timezone.ToUpper()) {
        "EASTERN"  { Set-TimeZone "Eastern Standard Time"; Write-Host "Timezone set to Eastern Standard Time" }
        "CENTRAL"  { Set-TimeZone "Central Standard Time"; Write-Host "Timezone set to Central Standard Time" }
        "MOUNTAIN" { Set-TimeZone "Mountain Standard Time"; Write-Host "Timezone set to Mountain Standard Time" }
        Default    { Write-Host "Invalid timezone input: $timezone" }
    }
}

function Join-DomainBasedOnLocation {
    $joined = $false
    switch ($location.ToUpper()) {
        "GEORGIA" {
            try {
                Add-Computer -DomainName "psi-pac.com" -Server "GA-DC02" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
            } catch {
                Write-Host "Failed to join GEORGIA domain: $_"
            }
        }
        "ARKANSAS" {
            try {
                Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.1.199.2" -ErrorAction Stop | Out-Null
                Add-Computer -DomainName "psi-pac.com" -Server "AR-DC" -Credential $Credential -Force -ErrorAction Stop
                $joined = $true
            } catch {
                Write-Host "Failed to join ARKANSAS domain: $_"
            }
        }
        "IDAHO" {
            try {
                Add-Computer -DomainName "psi-pac.com" -Server "ID-DC" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
            } catch {
                Write-Host "Failed to join IDAHO domain: $_"
            }
        }
        Default {
            Write-Host "Invalid location provided: $location"
        }
    }
    if ($joined) {
        Write-Host "Successfully joined domain for $location"
    }
}

function Start-FastInstaller {
    param (
        [string]$Path,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 600,
        [string]$FriendlyName = $(Split-Path $Path -Leaf),
        [switch]$Background
    )

    if (-not (Test-Path $Path)) {
        Write-Host "$FriendlyName installer not found: $Path"
        return $null
    }

    $safeArgs = @()
    if ($Arguments) {
        foreach ($a in $Arguments) {
            if ($a -and $a.Trim()) { $safeArgs += $a.Trim() }
        }
    }

    if ($Background) {
        $job = Start-Job -Name "Install_$FriendlyName" -ScriptBlock {
            param($FilePath, $Args, $Timeout, $Name)
            try {
                if ($Args -and $Args.Count -gt 0) {
                    $proc = Start-Process -FilePath $FilePath -ArgumentList $Args -PassThru -WindowStyle Hidden
                } else {
                    $proc = Start-Process -FilePath $FilePath -PassThru -WindowStyle Hidden
                }
                
                if (-not $proc.WaitForExit($Timeout * 1000)) {
                    $proc.Kill()
                    return @{ Success = $false; ExitCode = -1; Message = "$Name timed out" }
                }
                
                return @{ Success = ($proc.ExitCode -eq 0); ExitCode = $proc.ExitCode; Message = "$Name completed" }
            } catch {
                return @{ Success = $false; ExitCode = -2; Message = "$Name failed: $_" }
            }
        } -ArgumentList $Path, $safeArgs, $TimeoutSeconds, $FriendlyName
        
        Write-Host "Started $FriendlyName in background..."
        return $job
    } else {
        Write-Host "Installing $FriendlyName..."
        try {
            if ($safeArgs.Count -gt 0) {
                $proc = Start-Process -FilePath $Path -ArgumentList $safeArgs -PassThru -WindowStyle Hidden
            } else {
                $proc = Start-Process -FilePath $Path -PassThru -WindowStyle Hidden
            }
            
            if ($proc.WaitForExit($TimeoutSeconds * 1000)) {
                Write-Host "$FriendlyName completed with exit code: $($proc.ExitCode)"
                return $proc.ExitCode -eq 0
            } else {
                Write-Host "$FriendlyName timed out and was terminated"
                $proc.Kill()
                return $false
            }
        } catch {
            Write-Host "$FriendlyName failed: $_"
            return $false
        }
    }
}

function Rename-ComputerPrompt {
    if ([string]::IsNullOrWhiteSpace($computerName)) {
        Write-Host "Computer name not provided."
        return
    }
    try {
        Rename-Computer -NewName $computerName -Force -DomainCredential $Credential | Out-Null
        Write-Host "Computer renamed to $computerName"
    } catch {
        Write-Host "Failed to rename computer: $_"
    }
}

function Install-SharedDriveTask {
    param([string]$Location)
    
    $remotePath = switch ($Location.ToUpper()) {
        "GEORGIA"  { "\\GA-DC02\Shared2" }
        "ARKANSAS" { "\\AR-DC\Shared" }
        "IDAHO"    { "\\ID-DC\IDShared" }
        Default    { "\\GA-DC02\Shared2" }
    }
    
    $scriptContent = @"
if (-not (Test-Path "`$env:LOCALAPPDATA\SDriveMapped.txt")) {
    if (-not (Get-SmbMapping -LocalPath S: -ErrorAction SilentlyContinue)) {
        New-SmbMapping -LocalPath S: -RemotePath "$remotePath" -Persistent `$true
    }
    New-Item -Path "`$env:LOCALAPPDATA\SDriveMapped.txt" -ItemType File -Force | Out-Null
}
"@
    
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart | Out-Null
    } catch {
        Write-Host "SMB1 feature enable failed: $_"
    }
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$scriptContent`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
    
    Register-ScheduledTask -TaskName "MapSharedDrive" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Switch-Logs {
    $remoteLogDir = "\\ga-dc02\Shared2\New I.T\PC Deployment Tool - Version 1.33\DEPLOY LOGS"
    $remoteLogPath = Join-Path $remoteLogDir $logFileName
    if (Test-Path $remoteLogDir) {
        try {
            Copy-Item -Path $localLogPath -Destination $remoteLogDir -Force
            Write-Host "Log file copied to shared location."
            Stop-Transcript
            Start-Sleep -Seconds 1
            Start-Transcript -Path $remoteLogPath -Append
            Write-Host "Logging continued on shared drive: $remoteLogPath"
        } catch {
            Write-Host "Log switching failed: $_"
        }
    } else {
        Write-Host "Remote log directory not found. Skipping log copy."
    }
}

function Enable-SystemFeatures {
    Write-Host "Configuring system features..."
    
    $registryOps = @(
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Terminal Server"; Name = "fDenyTSConnections"; Value = 0 }
    )
    
    foreach ($op in $registryOps) {
        try {
            Set-ItemProperty -Path $op.Path -Name $op.Name -Value $op.Value -Force
        } catch {
            Write-Host "Registry operation failed for $($op.Path)\$($op.Name): $_"
        }
    }
    
    try {
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" | Out-Null
        Write-Host "Remote Desktop enabled."
    } catch {
        Write-Host "RDP firewall rule failed: $_"
    }
}

function Enable-DotNetFramework {
    Write-Host "Enabling .NET Framework 3.5..."
    
    $job = Start-Job -ScriptBlock {
        try {
            $sxsSource = "X:\sources\sxs"
            if (Test-Path $sxsSource) {
                Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -LimitAccess -Source $sxsSource -ErrorAction SilentlyContinue | Out-Null
            }
            DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /Quiet | Out-Null
            return "SUCCESS"
        } catch {
            return "FAILED: $_"
        }
    }
    
    if (Wait-Job -Job $job -Timeout 120) {
        $result = Receive-Job -Job $job
        Write-Host ".NET Framework operation: $result"
    } else {
        Write-Host ".NET Framework operation timed out"
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

function Install-TeamViewer {
    Write-Host "Installing TeamViewer"
    $tvPath = Join-Path $folderPath "Teamviewer_Setup.exe"
    if (Test-Path $tvPath) {
        Start-FastInstaller -Path $tvPath -Arguments @("/S") -FriendlyName "TeamViewer" -TimeoutSeconds 300
    } else {
        Write-Host "TeamViewer installer not found"
    }
}

function Install-CrowdStrike {
    param(
        [string]$InstallerPath = "$PSScriptRoot\WindowsSensor.MaverickGyr.exe",
        [string]$CID = "47AB920FB2F34F00BEDE8311E34EA489-EB"
    )

    Write-Host "Checking if CrowdStrike is already installed..."

    if ((Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue) -or 
        (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\CSFalconService")) {
        Write-Host "CrowdStrike is already installed"
        return $true
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-Host "CrowdStrike installer not found: $InstallerPath"
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($CID)) {
        Write-Host "CID not provided. Silent install requires CID."
        return $false
    }

    Write-Host "Launching CrowdStrike installer..."
    $args = @("/install", "/quiet", "/norestart", "CID=$CID")
    return Start-FastInstaller -Path $InstallerPath -Arguments $args -FriendlyName "CrowdStrike" -TimeoutSeconds 300
}

function Install-Vantage {
    param([string]$location)

    $batPath = Join-Path $folderPath "client803.bat"
    $targetPath = "C:\client803"
    $sourceClientFolder = Join-Path $folderPath "client803_source" 
    $defaultTotalFiles = 17023

    switch ($location.ToUpper()) {
        "GEORGIA" { 
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        "ARKANSAS" { 
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        "IDAHO" { 
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        default { 
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
    }

    if (Test-Path $sourceClientFolder) {
        try {
            $totalFiles = (Get-ChildItem -Path $sourceClientFolder -Recurse -File -ErrorAction Stop).Count
            if (-not $totalFiles -or $totalFiles -le 0) { $totalFiles = $defaultTotalFiles }
        } catch { $totalFiles = $defaultTotalFiles }
    } else {
        $totalFiles = $defaultTotalFiles
    }

    if (-not (Test-Path $batPath)) {
        Write-Output "vantage progress: 0"
        Write-Output "vantage error: client803.bat not found at $batPath"
        return
    }

    $startProcessParams = @{
        FilePath = $batPath
        PassThru = $true
        WindowStyle = 'Hidden'
    }
    
    if (-not [string]::IsNullOrWhiteSpace($location)) {
        $startProcessParams.ArgumentList = $location
    }
    
    $process = Start-Process @startProcessParams
    $lastReportedPercent = -1
    $checkInterval = 2
    $stabilityRequired = 6

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalMinutes -lt 30) {
        if ($process -and $process.HasExited) { $process = $null }
        
        if (Test-Path $targetPath) {
            try { 
                $currentCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count 
            } catch { 
                $currentCount = 0 
            }
            
            $percent = if ($totalFiles -gt 0) { 
                [math]::Min(100, [math]::Max(0, [math]::Round(($currentCount / $totalFiles) * 100)))
            } else { 0 }
            
            if ($percent -ne $lastReportedPercent) {
                Write-Output "vantage progress: $percent"
                $lastReportedPercent = $percent
                $stableCount = 0
            } else {
                $stableCount++
                if ($stableCount -ge $stabilityRequired -and $percent -eq 100) {
                    break
                }
            }
        } else {
            if ($lastReportedPercent -ne 0) {
                Write-Output "vantage progress: 0"
                $lastReportedPercent = 0
            }
        }
        Start-Sleep -Seconds $checkInterval
    }

    if ($lastReportedPercent -lt 100) { 
        Write-Output "vantage progress: 100" 
    }

    if (Test-Path $remoteShortcut) { 
        try {
            Copy-Item -Path $remoteShortcut -Destination "$env:PUBLIC\Desktop" -Force 
        } catch {
            Write-Host "Failed to copy Vantage shortcut: $_"
        }
    }

    $installSteps = @(
        @{ Path = "$folderPath\Microsoft WSE 3.0 Runtime.msi"; Percent = 90; Args = @("/qn", "/norestart") },
        @{ Path = "$folderPath\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Percent = 95; Args = @("/qn", "/norestart") },
        @{ Path = "$folderPath\dotNetFx35Setup.exe"; Percent = 98; Args = @("/qn", "/norestart") },
        @{ Path = "$folderPath\sqlncli.msi"; Percent = 99; Args = @("/qn", "/norestart") }
    )

    foreach ($step in $installSteps) {
        if (Test-Path $step.Path) {
            Start-FastInstaller -Path $step.Path -Arguments $step.Args -FriendlyName (Split-Path $step.Path -Leaf) -TimeoutSeconds 180
            Write-Output "vantage progress: $($step.Percent)"
        }
    }

    Write-Output "vantage progress: 100"
}

function Remove-Office365 {
    Write-Host "Checking for existing Office 365..."
    try {
        $officeApps = Get-AppxPackage -Name "*Office*" -ErrorAction SilentlyContinue
        if ($officeApps) {
            Write-Host "Removing Office UWP apps..."
            $officeApps | Remove-AppxPackage -ErrorAction SilentlyContinue
        }
        
        $officeMSI = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { 
            $_.Vendor -eq "Microsoft Corporation" -and $_.Name -like "*Office*" 
        }
        if ($officeMSI) {
            Write-Host "Found MSI Office installation, removing..."
            $officeMSI | ForEach-Object { $_.Uninstall() | Out-Null }
        }
    } catch {
        Write-Host "Office removal completed with warnings: $_"
    }
}

function Install-AdobeReader {
    $msiPath = Join-Path $folderPath "AcroRead.msi"
    $mstPath = Join-Path $folderPath "AcroRead.mst"
    $mspPath = Join-Path $folderPath "AcroRdrDCUpd2500120693.msp"
    $cabPath = Join-Path $folderPath "Data1.cab"
    
    $requiredFiles = @($msiPath, $mstPath, $mspPath, $cabPath)
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) { 
            Write-Host "Adobe file not found: $(Split-Path $file -Leaf)"
            return $false 
        }
    }
    
    Write-Host "All Adobe Reader files found. Starting installation..."
    
    Push-Location $folderPath
    try {
        $baseArgs = @("/i", "`"AcroRead.msi`"", "TRANSFORMS=`"AcroRead.mst`"", "/qn", "/norestart")
        
        Write-Host "Installing Adobe Reader base with transform..."
        $baseProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $baseArgs -PassThru -WindowStyle Hidden
        
        if (-not $baseProcess.WaitForExit(300000)) {
            $baseProcess.Kill()
            Write-Host "Adobe base installation timed out"
            return $false
        }
        
        if ($baseProcess.ExitCode -ne 0) {
            Write-Host "Base installation failed with exit code: $($baseProcess.ExitCode)"
            return $false
        }
        
        Write-Host "Base installation successful. Applying patch..."
        Start-Sleep -Seconds 3
        
        $patchArgs = @("/p", "`"AcroRdrDCUpd2500120693.msp`"", "/qn", "/norestart")
        $patchProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $patchArgs -PassThru -WindowStyle Hidden
        
        if ($patchProcess.WaitForExit(180000)) {
            Write-Host "Adobe Reader installation and patch complete (patch exit code: $($patchProcess.ExitCode))"
        } else {
            Write-Host "Patch installation timed out but base install succeeded"
        }
        
        return $true
        
    } finally {
        Pop-Location
    }
}

function Install-VPN {
    $vpnInstaller = Join-Path $PSScriptRoot "silent.bat"

    if (-not (Test-Path $vpnInstaller)) {
        Write-Host "VPN installer not found at $vpnInstaller"
        return $false
    }

    Write-Host "Installing Barracuda VPN client..."
    return Start-FastInstaller -Path $vpnInstaller -FriendlyName "Barracuda VPN" -TimeoutSeconds 300
}

function Install-VPNProfile {
    $vpnProfile = Join-Path $PSScriptRoot "PSI-PAC VPN.vpn"
    if (Test-Path $vpnProfile) {
        try {
            Start-Process -FilePath $vpnProfile -WindowStyle Hidden
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
}

function Install-Office365 {
    $setupPath = Join-Path $folderPath "setup.exe"
    $configPath = Join-Path $folderPath "officesilent.xml"
    
    if (-not (Test-Path $setupPath)) { Write-Host "Setup file not found: $setupPath"; return $false }
    if (-not (Test-Path $configPath)) { Write-Host "Configuration file not found: $configPath"; return $false }
    
    Write-Host "Installing Office 365..."
    $args = @("/configure", "`"$configPath`"")
    return Start-FastInstaller -Path $setupPath -Arguments $args -FriendlyName "Office 365" -TimeoutSeconds 1800
}

function Start-VerificationJobs {
    $verifyJob = Start-Job -ScriptBlock {
        $checks = @{
            TeamViewer = { Test-Path "C:\Program Files (x86)\TeamViewer" }
            Adobe = { Test-Path "HKLM:\SOFTWARE\Adobe" }
            Office365 = { 
                $office = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
                          Where-Object { $_.DisplayName -like "*Microsoft 365*" -or $_.DisplayName -like "*Office*" }
                return $office -ne $null
            }
        }
        
        $reported = @{}
        $timeout = 300
        $elapsed = 0
        
        while ($elapsed -lt $timeout) {
            foreach ($name in $checks.Keys) {
                if (-not $reported[$name] -and (& $checks[$name])) {
                    Write-Output "$name installed"
                    $reported[$name] = $true
                }
            }
            
            if ($reported.Count -eq $checks.Count) { break }
            Start-Sleep -Seconds 10
            $elapsed += 10
        }
        
        return $reported
    }
    
    return $verifyJob
}

function Run-WindowsUpdates {
    Write-Host "Starting optimized Windows Updates..."
    Write-Output "winupdate progress: 0"
    
    try {
        $job = Start-Job -ScriptBlock {
            try {
                Write-Output "winupdate progress: 5"
                
                if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -Confirm:$false | Out-Null
                    Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -Confirm:$false -AllowClobber | Out-Null
                    Write-Output "winupdate progress: 15"
                }
                
                Import-Module PSWindowsUpdate -Force
                Write-Output "winupdate progress: 20"
                
                $updates = Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -AcceptAll
                $totalUpdates = $updates.Count
                
                if ($totalUpdates -eq 0) {
                    Write-Output "winupdate progress: 100"
                    Write-Output "winupdate complete"
                    return
                }
                
                Write-Output "winupdate progress: 30"
                
                $installParams = @{
                    MicrosoftUpdate = $true
                    AcceptAll = $true
                    IgnoreReboot = $true
                    Confirm = $false
                    ForceDownload = $true
                    ForceInstall = $true
                }
                
                $progressStep = 70 / $totalUpdates
                $currentProgress = 30
                
                Install-WindowsUpdate @installParams -Verbose | ForEach-Object {
                    $currentProgress += $progressStep
                    $roundedProgress = [math]::Min(100, [math]::Round($currentProgress))
                    Write-Output "winupdate progress: $roundedProgress"
                }
                
                Write-Output "winupdate progress: 100"
                Write-Output "winupdate complete"
                
            } catch {
                Write-Output "winupdate error: $_"
            }
        }
        
        $timeout = 1800
        if (Wait-Job -Job $job -Timeout $timeout) {
            Receive-Job -Job $job | ForEach-Object { Write-Output $_ }
        } else {
            Write-Output "winupdate error: Updates timed out after $timeout seconds"
            Stop-Job -Job $job
        }
        
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Output "winupdate error: $_"
    }
}

Write-Host "=== OPTIMIZED PSI DEPLOYMENT STARTING ==="

Set-TimeZoneFromUserInput
Join-DomainBasedOnLocation
Rename-ComputerPrompt
Install-SharedDriveTask -Location $location
Switch-Logs

Write-Host "=== PARALLEL SYSTEM CONFIGURATION ==="
$systemJobs = @()

$systemJobs += Start-Job -Name "EnableFeatures" -ScriptBlock {
    Enable-SystemFeatures
}

$systemJobs += Start-Job -Name "DotNet" -ScriptBlock {
    Enable-DotNetFramework
}

foreach ($job in $systemJobs) {
    if (Wait-Job -Job $job -Timeout 60) {
        Receive-Job -Job $job | ForEach-Object { Write-Host "[SYSTEM] $_" }
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
}

Write-Host "=== CORE SOFTWARE INSTALLATION ==="
Install-TeamViewer
Install-AdobeReader

if (Install-CrowdStrike) { 
    Write-Host "CrowdStrike finished, continuing..." 
} else { 
    Write-Host "CrowdStrike failed, continuing anyway..." 
}

Write-Host "=== OPTIONAL SOFTWARE INSTALLATION ==="
if ($installVPN) {
    if (Install-VPN) {
        Start-Sleep -Seconds 3
        Install-VPNProfile
    } else {
        Write-Host "Skipping VPN profile import since installation failed."
    }
} else {
    Write-Host "Barracuda VPN install bypassed" -ForegroundColor Cyan
}

if ($installVANTAGE) { 
    Install-Vantage -location $location
} else { 
    Write-Host "Vantage installation bypassed" -ForegroundColor Cyan 
}

Write-Host "=== OFFICE 365 DEPLOYMENT ==="
Remove-Office365
Install-Office365

Write-Host "=== STARTING VERIFICATION AND UPDATES ==="
$verifyJob = Start-VerificationJobs

Write-Host "=== RUNNING WINDOWS UPDATES ==="
Run-WindowsUpdates

Write-Host "=== COLLECTING VERIFICATION RESULTS ==="
if (Wait-Job -Job $verifyJob -Timeout 60) {
    Receive-Job -Job $verifyJob | ForEach-Object { Write-Host "[VERIFY] $_" }
}
Remove-Job -Job $verifyJob -Force -ErrorAction SilentlyContinue

Write-Host "=== CLEANING UP BACKGROUND JOBS ==="
try {
    $allJobs = Get-Job
    foreach ($job in $allJobs) {
        if ($job.State -in @('Completed', 'Failed', 'Stopped')) {
            Write-Host "Collecting output for job: $($job.Name) (State: $($job.State))"
            Receive-Job -Job $job -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "[JOB] $_" }
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "Job $($job.Name) still running (State: $($job.State))"
        }
    }
} catch {
    Write-Host "Error during job cleanup: $_"
}

Write-Host "=== DEPLOYMENT COMPLETE ==="
Stop-Transcript
