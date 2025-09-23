# PYTHON MODIFIED VERSION - FOR USE WITH PYINSTALLER-BUNDLED PYTHON EXE 9/3/2025 2:28PM EST
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

# ------------------- FUNCTIONS -------------------

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

    # Ensure $Arguments is an array and remove null/empty entries
    if ($null -eq $Arguments) { $Arguments = @() }
    $safeArgs = @()
    foreach ($a in $Arguments) {
        if ($a -ne $null -and $a -ne "") { $safeArgs += $a }
    }

    # Start process with or without ArgumentList depending on whether we have args
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

function Map-SharedDriveCall {
    $mapScript = Join-Path $PSScriptRoot "MapDriveAndTask.ps1"
    if (Test-Path $mapScript) {

        $targetScriptPath = "$env:LOCALAPPDATA\MapDriveAndTask.ps1"

        if ($MyInvocation.MyCommand.Path -ne $targetScriptPath) {
            try {
                Copy-Item -Path $mapScript -Destination $targetScriptPath -Force
                Write-Host "Copied MapDrive script to $targetScriptPath"
            } catch {
                Write-Host "Failed to copy MapDrive script: $_"
            }
        }

        $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $scriptName = "MapSharedDrive"

        try {
            $existingValue = Get-ItemProperty -Path $runKey -Name $scriptName -ErrorAction SilentlyContinue

            if (-not $existingValue) {
                Set-ItemProperty -Path $runKey -Name $scriptName `
                    -Value "PowerShell.exe -NoProfile -WindowStyle Hidden -File `"$targetScriptPath`" -Location `"$location`""
                Write-Host "Registry Run key added for $scriptName"
            } else {
                Write-Host "Registry Run key already exists. Skipping."
            }
        } catch {
            Write-Host "Failed to add or check Run key: $_"
        }

        & powershell.exe -ExecutionPolicy Bypass -File $targetScriptPath -Location $location
    }
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
        [int]$BackgroundWaitSeconds = 30
    )

    Write-Host "Installing CrowdStrike (launched as background job)..."
    Start-Sleep -Seconds 2

    $installer = Join-Path $folderPath "WindowsSensor.MaverickGyr.exe"

    if (-not (Test-Path $installer)) {
        Write-Host "CrowdStrike installer not found: $installer"
        return
    }

    $args = @()  # add silent args here if required

    $job = Start-BackgroundInstaller -Path $installer -Arguments $args -WaitSeconds $BackgroundWaitSeconds -FriendlyName "CrowdStrike"

    if ($job) {
        try {
            $jobInfoFile = Join-Path $localLogDirectory "CrowdStrikeInstallJob_$($job.Id).txt"
            $job | Out-String | Out-File -FilePath $jobInfoFile -Encoding utf8 -Force
            Write-Host "CrowdStrike background job started (JobId=$($job.Id)). Info saved to $jobInfoFile"
        } catch {
            Write-Host "Unable to write job info file: $_"
        }
    }
}

function Install-Vantage {
    $batPath = Join-Path $folderPath "client803.bat"
    $targetPath = "C:\Client803"
    $sourceClientFolder = Join-Path $folderPath "client803_source" 
    $defaultTotalFiles = 17023

    if (Test-Path $sourceClientFolder) {
        try {
            $totalFiles = (Get-ChildItem -Path $sourceClientFolder -Recurse -File -ErrorAction Stop).Count
            if (-not $totalFiles -or $totalFiles -le 0) { $totalFiles = $defaultTotalFiles }
        } catch {
            $totalFiles = $defaultTotalFiles
        }
    } else {
        $totalFiles = $defaultTotalFiles
    }

    if (-not (Test-Path $batPath)) {
        Write-Output "vantage progress: 0"
        Write-Output "vantage error: client803.bat not found at $batPath"
        return
    }

    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$batPath`"" -PassThru -WindowStyle Hidden
    $lastReportedPercent = -1
    $noChangeCounter = 0
    $lastCount = -1
    $stabilitySecondsRequired = 8
    $sleepInterval = 1

    while ($true) {
        if ($process -and $process.HasExited) { $process = $null }

        if (Test-Path $targetPath) {
            try {
                $currentCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
            } catch {
                $currentCount = 0
            }

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
                if ($lastCount -eq $currentCount) {
                    $noChangeCounter += $sleepInterval
                } else {
                    $noChangeCounter = 0
                }
            }

            $lastCount = $currentCount

            if ($noChangeCounter -ge $stabilitySecondsRequired) {
                if ($lastReportedPercent -lt 100) {
                    Write-Output "vantage progress: 100"
                }
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
        if ($finalCount -gt 0) {
            Write-Output "vantage progress: 100"
        }
    } else {
        Write-Output "vantage progress: 100"
    }

    $Password = ConvertTo-SecureString "Password!" -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential("Vantage_User", $Password)

    Copy-Item -Path "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk" -Destination "C:\Users\Public\Desktop" -Force

    $installSteps = @(
        @{ Path = "$folderPath\Microsoft WSE 3.0 Runtime.msi"; Percent = 90 },
        @{ Path = "$folderPath\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Percent = 95 },
        @{ Path = "$folderPath\dotNetFx35Setup.exe"; Percent = 98 }
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

    $shortcutPath = "S:\New I.T\New PCs\2) VantageInstall\Vantage 8.03.lnk"
    $desktopPath = "$env:PUBLIC\Desktop"
    if (Test-Path $shortcutPath) {
        Copy-Item -Path $shortcutPath -Destination $desktopPath -Force
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

function Run-AdobeInstaller {
    param (
        [string]$Path,
        [string[]]$Arguments = @("/sAll","/rs","/rps","/msi","/norestart","/quiet","EULA_ACCEPT=YES"),
        [int]$TimeoutSeconds = 600
    )

    if (-not (Test-Path $Path)) {
        Write-Host "Adobe installer not found: $Path"
        return
    }

    Write-Host "Running Adobe installer: $Path"

    $proc = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -WindowStyle Hidden

    $sw = [Diagnostics.Stopwatch]::StartNew()

    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $adobeRunning = Get-Process -Name "AcroPro*" -ErrorAction SilentlyContinue
        if (-not $proc.HasExited -or $adobeRunning) {
            Start-Sleep -Seconds 5
        } else {
            break
        }
    }

    $adobeRunning = Get-Process -Name "AcroPro*" -ErrorAction SilentlyContinue
    if ($adobeRunning) {
        Write-Host "Adobe install exceeded timeout. Killing Acrobat processes..."
        $adobeRunning | ForEach-Object { try { $_.Kill() } catch {} }
    }

    if ($proc.HasExited) {
        Write-Host "Adobe installer completed successfully."
    } else {
        Write-Host "Adobe installer forced to close after timeout."
    }
}

function Install-AdobeReader {
    $installer = "$folderPath\Adobe Acrobat.exe"
    $desktopPath = "C:\Users\$env:USERNAME\Desktop"
    Copy-Item -Path $installer -Destination $desktopPath -Force

    Run-AdobeInstaller -Path "$desktopPath\Adobe Acrobat.exe"
}


function Install-VPN {
    Start-Process -FilePath "$folderPath\silent.bat" -WorkingDirectory $folderPath -Wait -WindowStyle Hidden
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

# ------------------- MAIN EXECUTION -------------------

Set-TimeZoneFromUserInput
Join-DomainBasedOnLocation
Rename-ComputerPrompt
Map-SharedDriveCall
Switch-Logs
Enable-RDP
Install-TeamViewer
Install-AdobeReader
# Launch CrowdStrike in background and continue
Install-CrowdStrike -BackgroundWaitSeconds 30
Enable-DotNetFramework
if ($installVANTAGE) {
    Install-Vantage
} else {
    Write-Host "Vantage installation bypassed" -ForegroundColor Cyan
}

Remove-Office365

if ($installVPN) {
    Install-VPN
} else {
    Write-Host "Barracuda VPN install bypassed" -ForegroundColor Cyan
}

Install-Office365
Verify-Installations
Run-WindowsUpdates


try {
    $bgJobs = Get-Job | Where-Object { $_.Name -like 'InstallJob_*' }
    foreach ($j in $bgJobs) {
        if ($j.State -eq 'Completed' -or $j.State -eq 'Failed' -or $j.State -eq 'Stopped') {
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
