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

function Run-Installer {
    param (
        [string]$Path,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 900
    )

    if (-not (Test-Path $Path)) {
        Write-Host "Installer not found: $Path"
        return
    }

    Write-Host "Running installer: $Path"

    if ($null -eq $Arguments) { $Arguments = @() }
    $safeArgs = @()
    foreach ($a in $Arguments) {
        if ($a -ne $null -and $a -ne "") { $safeArgs += $a }
    }

    if ($safeArgs.Count -gt 0) {
        $process = Start-Process -FilePath $Path -ArgumentList $safeArgs -PassThru -WindowStyle Hidden
    } else {
        $process = Start-Process -FilePath $Path -PassThru -WindowStyle Hidden
    }

    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($process -and -not $process.HasExited -and $sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 2
    }

    if ($process -and -not $process.HasExited) {
        Write-Host "Installer exceeded timeout. Killing process: $Path"
        try { $process.Kill() } catch {}
    } else {
        Write-Host "Installer completed: $Path"
    }

    $processName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill() }
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
    param(
        [string]$Location
    )
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
    
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$scriptContent`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Limited
    
    Register-ScheduledTask -TaskName "MapSharedDrive" -Action $action -Trigger $trigger -Principal $principal -Force
}


function Switch-Logs {
    $remoteLogDir = "\\ga-dc02\Shared2\New I.T\PC Deployment Tool - Version 1.33\DEPLOY LOGS"
    $remoteLogPath = Join-Path $remoteLogDir $logFileName
    if (Test-Path $remoteLogDir) {
        Copy-Item -Path $localLogPath -Destination $remoteLogDir -Force
        Write-Host "Log file copied to shared location."

        Stop-Transcript
        Start-Sleep -Seconds 2

        Start-Transcript -Path $remoteLogPath -Append
        Write-Host "Logging continued on shared drive: $remoteLogPath"
    } else {
        Write-Host "Remote log directory not found. Skipping log copy."
    }
}

function Enable-RDP {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Write-Host "Remote Desktop enabled."
}

function Enable-DotNetFramework {
    try {
        Write-Host "Enabling .NET Framework 3.5 (includes 2.0 and 3.0)..."
        
        $sxsSource = "X:\sources\sxs"
        if (Test-Path $sxsSource) {
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -LimitAccess -Source $sxsSource -ErrorAction SilentlyContinue
        }

        DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /Quiet | Out-Null
        Write-Host ".NET Framework installation initiated silently."
    } catch {
        Write-Host "Failed to enable .NET Framework: $_"
    }
}

function Install-TeamViewer {
    Write-Host "Installing TeamViewer"
    & "$folderPath\Teamviewer_Setup.exe" /i /qn /S
}

function Start-BackgroundInstaller {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [string[]]$Arguments = @(),
        [int]$WaitSeconds = 30,
        [string]$FriendlyName = $(Split-Path $Path -Leaf)
    )

    if (-not (Test-Path $Path)) {
        Write-Host "$FriendlyName installer not found: $Path"
        return $null
    }

    Write-Host "Starting $FriendlyName in background (will wait up to $WaitSeconds seconds for completion)..."

    if ($null -eq $Arguments) { $Arguments = @() }
    $safeArgs = @()
    foreach ($a in $Arguments) {
        if ($a -ne $null -and $a -ne "") { $safeArgs += $a }
    }

    $job = Start-Job -Name ("InstallJob_" + [System.Guid]::NewGuid().ToString()) -ScriptBlock {
        param($p, $a, $friendly)
        try {
            if ($null -eq $a) { $a = @() }
            $innerArgs = @()
            foreach ($x in $a) { if ($x -ne $null -and $x -ne "") { $innerArgs += $x } }

            if ($innerArgs.Count -gt 0) {
                $proc = Start-Process -FilePath $p -ArgumentList $innerArgs -PassThru -WindowStyle Hidden
            } else {
                $proc = Start-Process -FilePath $p -PassThru -WindowStyle Hidden
            }

            if ($proc) {
                $proc | Wait-Process
                Write-Output "${friendly}: process finished"
            } else {
                Write-Output "${friendly}: Start-Process returned no process object"
            }
        } catch {
            Write-Output "${friendly}: installer job error: $_"
        }
    } -ArgumentList $Path, $safeArgs, $FriendlyName

    $completed = $false
    if ($WaitSeconds -gt 0) {
        $completed = Wait-Job -Job $job -Timeout $WaitSeconds
    } else {
        $completed = $false
    }

    if ($completed) {
        $output = Receive-Job -Job $job -Keep
        Write-Host "$FriendlyName background job completed within timeout."
        if ($output) { $output | ForEach-Object { Write-Host $_ } }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "$FriendlyName still running in background (did not finish within $WaitSeconds seconds). Continuing with the rest of the script."
    }

    return $job
}

function Install-CrowdStrike {
    param(
        [string]$InstallerPath = "$PSScriptRoot\WindowsSensor.MaverickGyr.exe",
        [string]$CID = "47AB920FB2F34F00BEDE8311E34EA489-EB"
    )

    Write-Host "Checking if CrowdStrike is already installed..."

    $service = Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "CrowdStrike is already installed (Service: $($service.Status))"
        Write-Output $true
        return
    }

    $csRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CSFalconService"
    if (Test-Path $csRegPath) {
        $imagePath = (Get-ItemProperty -Path $csRegPath -ErrorAction SilentlyContinue).ImagePath
        Write-Host "CrowdStrike is already installed (Registry entry found: $imagePath)"
        Write-Output $true
        return
    }

    if (-not (Test-Path $InstallerPath)) {
        Write-Host "CrowdStrike installer not found: $InstallerPath"
        Write-Output $false
        return
    }

    if ([string]::IsNullOrWhiteSpace($CID)) {
        Write-Host "CID not provided. Silent install requires CID."
        Write-Output $false
        return
    }

    $args = "/install","/quiet","/norestart","CID=$CID"
    try {
        Write-Host "Launching CrowdStrike installer..."
        $proc = Start-Process -FilePath $InstallerPath -ArgumentList $args -PassThru -WindowStyle Hidden -Wait
        if ($proc -and ($proc.ExitCode -eq 0)) {
            Write-Host "CrowdStrike installed successfully (ExitCode $($proc.ExitCode))"
            Write-Output $true
        } else {
            $exit = if ($proc) { $proc.ExitCode } else { "unknown" }
            Write-Host "CrowdStrike installer finished with exit code $exit"
            Write-Output $false
        }
    } catch {
        Write-Host "CrowdStrike installation failed: $_"
        Write-Output $false
    }
}

function Install-Vantage {
    param (
        [string]$location
    )

    $batPath       = Join-Path $folderPath "client803.bat"
    $targetPath    = "C:\client803"
    $sourceClientFolder = Join-Path $folderPath "client803_source" 
    $defaultTotalFiles  = 17023

    switch ($location.ToUpper()) {
        "GEORGIA" { 
            $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        "ARKANSAS" { 
            $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        "IDAHO" { 
            $remoteFolder   = "\\id-dc\IDShared\Shipping\Rack Sheet\PSI BOL & Invoice\Vantage\client803\client803"
            $remoteShortcut = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
        }
        default { 
            $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
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
    $noChangeCounter = 0
    $lastCount = -1
    $stabilitySecondsRequired = 8
    $sleepInterval = 1

    while ($true) {
        if ($process -and $process.HasExited) { $process = $null }
        if (Test-Path $targetPath) {
            try { $currentCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count } catch { $currentCount = 0 }
            $percent = 0
            if ($totalFiles -gt 0) {
                $percent = [math]::Round(( [double]$currentCount / [double]$totalFiles) * 100)
                if ($percent -lt 0) { $percent = 0 }
                if ($percent -gt 100) { $percent = 100 }
            }
            if ($percent -ne $lastReportedPercent) {
                Write-Output "vantage progress: $percent"
                $lastReportedPercent = $percent
                $noChangeCounter = 0
            } else {
                if ($lastCount -eq $currentCount) { $noChangeCounter += $sleepInterval } else { $noChangeCounter = 0 }
            }
            $lastCount = $currentCount
            if ($noChangeCounter -ge $stabilitySecondsRequired) {
                if ($lastReportedPercent -lt 100) { Write-Output "vantage progress: 100" }
                break
            }
        } else {
            if ($lastReportedPercent -ne 0) {
                Write-Output "vantage progress: 0"
                $lastReportedPercent = 0
            }
        }
        Start-Sleep -Seconds $sleepInterval
    }

    if (Test-Path $targetPath) {
        $finalCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($finalCount -gt 0) { Write-Output "vantage progress: 100" }
    } else { Write-Output "vantage progress: 100" }

    $desktopPath = "$env:PUBLIC\Desktop"
    if (Test-Path $remoteShortcut) { Copy-Item -Path $remoteShortcut -Destination $desktopPath -Force }

    $installSteps = @(
        @{ Path = "$folderPath\Microsoft WSE 3.0 Runtime.msi"; Percent = 90 },
        @{ Path = "$folderPath\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Percent = 95 },
        @{ Path = "$folderPath\dotNetFx35Setup.exe"; Percent = 98 },
        @{ Path = "$folderPath\sqlncli.msi"; Percent = 99 }
    )

    foreach ($step in $installSteps) {
        if (Test-Path $step.Path) {
            $ext = [System.IO.Path]::GetExtension($step.Path).ToLower()
            $args = switch ($ext) { 
                ".msi" { "/quiet /norestart" } 
                ".exe" { "/quiet /norestart" } 
                default { "/quiet /norestart" } 
            }
            Start-Process -FilePath $step.Path -ArgumentList $args -Wait -WindowStyle Hidden
            Write-Output "vantage progress: $($step.Percent)"
        }
    }

    Write-Output "vantage progress: 100"
}

function Remove-Office365 {
    try {
        Write-Host "Removing existing Office 365 applications"
        $office = Get-WmiObject -Class Win32_Product | Where-Object { $_.Vendor -eq "Microsoft Corporation" } | Out-Null
        $office.Uninstall()
        Get-AppxPackage -Name "Microsoft.Office.Desktop" | Remove-AppPackage | Out-Null
    }
    catch {
        Write-Host "Unable to locate existing Office 365 applications"
    }
}

function Install-AdobeReader {
    $installer = "$folderPath\Adobe Acrobat.exe"
    
    if (-not (Test-Path $installer)) {
        Write-Host "Adobe installer not found: $installer"
        return $null
    }
    
    Write-Host "Starting Adobe Reader installation as background job..."
    
    $job = Start-Job -Name "AdobeInstallJob" -ScriptBlock {
        param($installerPath)
        
        $silentArgs = @(
            "/S",
            "/v/qn", 
            "/norestart",
            "EULA_ACCEPT=YES",
            "SUPPRESS_APP_LAUNCH=YES",
            "DISABLE_BROWSER_INTEGRATION=YES"
        )
        
        try {
            Write-Output "Starting Adobe installation..."
            $process = Start-Process -FilePath $installerPath -ArgumentList $silentArgs -WindowStyle Hidden -PassThru
            
            $completed = $process.WaitForExit(600000)
            
            if (-not $completed) {
                Write-Output "Adobe installer timed out after 10 minutes - terminating"
                try { $process.Kill() } catch { }
                return "Adobe installation timed out"
            } else {
                Write-Output "Adobe installation completed successfully"
                return "Adobe installation finished"
            }
        } catch {
            Write-Output "Adobe installer error: $_"
            return "Adobe installation failed: $_"
        }
    } -ArgumentList $installer
    
    Write-Host "Adobe Reader installation started in background (Job ID: $($job.Id))"
    Write-Host "Script will continue while Adobe installs..."
    
    return $job
}

function Install-VPN {
    $vpnInstaller = Join-Path $PSScriptRoot "silent.bat"

    if (-not (Test-Path $vpnInstaller)) {
        Write-Host "VPN installer not found at $vpnInstaller"
        return $false
    }

    try {
        Write-Host "Installing Barracuda VPN client..."
        Start-Process -FilePath $vpnInstaller -WorkingDirectory $PSScriptRoot -Wait -WindowStyle Hidden
        Write-Host "Barracuda VPN installation completed."
        return $true
    }
    catch {
        Write-Host "Unable to install Barracuda VPN"
        return $false
    }
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
    try {
    Resolve-DnsName -Name "busybee.psi-pac.com" -Server 8.8.8.8 | Select-Object -Property Name, IPAddress
    }
    catch {
    Write-Host "Unable to resolve busybee.psi-pac.com DNS"
    }
}


function Install-Office365 {
    $installer = "$folderPath\OfficeSetup.exe"
    Run-Installer -Path $installer
}

function Verify-Installations {
    $reported = @{
        TeamViewer = $false
        Adobe      = $false
        Office365  = $false
    }

    Start-Job -ScriptBlock {
        param($reported)

        while ($true) {
            if (-not $reported.TeamViewer -and (Test-Path "C:\Program Files (x86)\TeamViewer")) {
                Write-Host "TeamViewer installed"
                $reported.TeamViewer = $true
            }

            if (-not $reported.Adobe -and (Test-Path "HKLM:\SOFTWARE\Adobe")) {
                Write-Host "Adobe Acrobat installed"
                $reported.Adobe = $true
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
    } -ArgumentList $reported | Out-Null
}

function Run-WindowsUpdates {
    try {
        Write-Output "winupdate progress: 0"

        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
        Install-Module -Name PSWindowsUpdate -SkipPublisherCheck -Force -Scope CurrentUser | Out-Null
        Import-Module PSWindowsUpdate -Force

        $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -Confirm:$false
        $total = $updates.Count
        $count = 0

        foreach ($update in $updates) {
            $count++
            $percent = [math]::Round(($count / $total) * 100)
            Write-Output "winupdate progress: $percent"
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -Confirm:$false -Verbose | Out-Null
        }
        Write-Output "winupdate complete"
    } catch {
        Write-Output "winupdate error: $_"
    }
}

Set-TimeZoneFromUserInput
Join-DomainBasedOnLocation
Rename-ComputerPrompt
Install-SharedDriveTask
Switch-Logs
Enable-RDP
Install-TeamViewer
$adobeJob = Install-AdobeReader
Enable-DotNetFramework
if (Install-CrowdStrike) { Write-Host "CrowdStrike finished, continuing..." } else { Write-Host "CrowdStrike failed, continuing anyway..." }
if ($installVANTAGE) { Install-Vantage } else { Write-Host "Vantage installation bypassed" -ForegroundColor Cyan }
Remove-Office365
if ($installVPN) {
    if (Install-VPN) {
        Start-Sleep -Seconds 5
        Install-VPNProfile
    } else {
        Write-Host "Skipping VPN profile import since installation failed."
    }
} else {
    Write-Host "Barracuda VPN install bypassed" -ForegroundColor Cyan
}
Install-Office365
Verify-Installations
Run-WindowsUpdates
try {
    $bgJobs = Get-Job | Where-Object { $_.Name -like 'InstallJob_*' -or $_.Name -like 'AdobeInstallJob' }
    foreach ($j in $bgJobs) {
        if ($j.State -in 'Completed','Failed','Stopped') {
            Write-Host "Collecting output for background job Id=$($j.Id) Name=$($j.Name) State=$($j.State)"
            Receive-Job -Job $j -Wait -AutoRemoveJob | ForEach-Object { Write-Host "[BG JOB $($j.Id)] $_" }
        } else {
            Write-Host "Background job Id=$($j.Id) Name=$($j.Name) is still running (State=$($j.State)). Leaving it to finish in background."
        }
    }
} catch {
    Write-Host "Error while collecting background job outputs: $_"
}
Stop-Transcript

