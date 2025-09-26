param(
    [string]$timezone,
    [string]$location,
    [string]$computerName,
    [switch]$installVPN,
    [switch]$installVANTAGE
)

# Create local log directory
$localLogDirectory = "C:\Logs"
if (-not (Test-Path $localLogDirectory)) {
    New-Item -Path $localLogDirectory -ItemType Directory -Force | Out-Null
}

$logName = if (![string]::IsNullOrWhiteSpace($computerName)) { $computerName } else { $env:COMPUTERNAME }
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFileName = "$logName-SetupLog-$timestamp.txt"
$localLogPath = Join-Path $localLogDirectory $logFileName

Start-Transcript -Path $localLogPath -NoClobber

# Validate parameters
if (-not $timezone) { throw "Timezone parameter is null or empty." } else { Write-Host "Received Timezone: $timezone" }
if (-not $location) { throw "Location parameter is null or empty." } else { Write-Host "Received Location: $location" }
if (-not $computerName) { throw "Computer name is null or empty." } else { Write-Host "Received Computer Name: $computerName" }

# Enhanced credential loading function
function Get-DomainCredential {
    param([string]$ScriptDirectory = $PSScriptRoot)
    
    try {
        Write-Host "=== CREDENTIAL LOADING ==="
        Write-Host "Script directory: $ScriptDirectory"
        
        # Look for credential files in current script directory (where Python copied them)
        $keyPath = Join-Path $ScriptDirectory "key.key"
        $encryptedPath = Join-Path $ScriptDirectory "encrypted.txt"
        
        Write-Host "Looking for key file: $keyPath"
        Write-Host "Looking for encrypted file: $encryptedPath"
        
        # Validate key file
        if (-not (Test-Path $keyPath)) {
            Write-Host "credential_error: key.key file not found at $keyPath"
            Write-Host "Available files in directory:"
            Get-ChildItem $ScriptDirectory | ForEach-Object { Write-Host "  - $($_.Name)" }
            return $null
        }
        
        # Validate encrypted file
        if (-not (Test-Path $encryptedPath)) {
            Write-Host "credential_error: encrypted.txt file not found at $encryptedPath"
            Write-Host "Available files in directory:"
            Get-ChildItem $ScriptDirectory | ForEach-Object { Write-Host "  - $($_.Name)" }
            return $null
        }
        
        # Check file sizes
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
        
        # Load the files
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
    switch ($timezone.ToUpper()) {
        "EASTERN"  { Set-TimeZone "Eastern Standard Time"; Write-Host "Timezone set to Eastern Standard Time" }
        "CENTRAL"  { Set-TimeZone "Central Standard Time"; Write-Host "Timezone set to Central Standard Time" }
        "MOUNTAIN" { Set-TimeZone "Mountain Standard Time"; Write-Host "Timezone set to Mountain Standard Time" }
        Default    { Write-Host "Invalid timezone input: $timezone" }
    }
}

function Join-DomainBasedOnLocation {
    param([string]$Location, [object]$Credential)
    
    Write-Host "=== DOMAIN JOIN PROCESS ==="
    
    if (-not $Credential) {
        Write-Host "Domain join skipped: No valid credentials available"
        Write-Host "Manual domain join required after deployment"
        return $false
    }
    
    Write-Host "Domain join credentials validated successfully"
    Write-Host "Attempting to join domain for location: $Location"
    
    $joined = $false
    switch ($Location.ToUpper()) {
        "GEORGIA" {
            try {
                Write-Host "Joining GEORGIA domain (psi-pac.com via GA-DC02)..."
                Add-Computer -DomainName "psi-pac.com" -Server "GA-DC02" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
                Write-Host "Successfully joined GEORGIA domain"
            } catch {
                Write-Host "Failed to join GEORGIA domain: $($_.Exception.Message)"
                Write-Host "Error details: $($_.Exception.GetType().FullName)"
            }
        }
        "ARKANSAS" {
            try {
                Write-Host "Configuring DNS for ARKANSAS domain..."
                Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.1.199.2" -ErrorAction Stop | Out-Null
                Write-Host "Joining ARKANSAS domain (psi-pac.com via AR-DC)..."
                Add-Computer -DomainName "psi-pac.com" -Server "AR-DC" -Credential $Credential -Force -ErrorAction Stop
                $joined = $true
                Write-Host "Successfully joined ARKANSAS domain"
            } catch {
                Write-Host "Failed to join ARKANSAS domain: $($_.Exception.Message)"
                Write-Host "Error details: $($_.Exception.GetType().FullName)"
            }
        }
        "IDAHO" {
            try {
                Write-Host "Joining IDAHO domain (psi-pac.com via ID-DC)..."
                Add-Computer -DomainName "psi-pac.com" -Server "ID-DC" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
                Write-Host "Successfully joined IDAHO domain"
            } catch {
                Write-Host "Failed to join IDAHO domain: $($_.Exception.Message)"
                Write-Host "Error details: $($_.Exception.GetType().FullName)"
            }
        }
        Default {
            Write-Host "Invalid location provided: $Location"
            Write-Host "Valid locations: GEORGIA, ARKANSAS, IDAHO"
        }
    }
    
    if ($joined) {
        Write-Host "Domain join completed successfully for $Location"
    } else {
        Write-Host "Domain join failed for $Location - manual intervention required"
    }
    
    return $joined
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
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart
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

function Enable-SystemFeatures {
    try {
        Write-Host "Enabling Windows features..."
        
        # Enable SMB1 Protocol for network shares
        Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
        
        # Enable Remote Desktop
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -ErrorAction SilentlyContinue
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        
        Write-Host "System features enabled successfully"
        return $true
        
    } catch {
        Write-Host "Failed to enable system features: $($_.Exception.Message)"
        return $false
    }
}

function Enable-DotNetFramework {
    try {
        Write-Host "Enabling .NET Framework 3.5 (includes 2.0 and 3.0)..."
        
        $sxsSource = "X:\sources\sxs"
        if (Test-Path $sxsSource) {
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -LimitAccess -Source $sxsSource -ErrorAction SilentlyContinue | Out-Null
        }

        DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /NoRestart /Quiet | Out-Null
        Write-Host ".NET Framework installation initiated silently."
        return $true
    } catch {
        Write-Host "Failed to enable .NET Framework: $_"
        return $false
    }
}

function Install-TeamViewer {
    Write-Host "Installing TeamViewer"
    $tvPath = Join-Path $PSScriptRoot "Teamviewer_Setup.exe"
    if (Test-Path $tvPath) {
        & $tvPath /i /qn /S
    } else {
        Write-Host "TeamViewer installer not found: $tvPath"
    }
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
        return $true
    }

    $csRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CSFalconService"
    if (Test-Path $csRegPath) {
        $imagePath = (Get-ItemProperty -Path $csRegPath -ErrorAction SilentlyContinue).ImagePath
        Write-Host "CrowdStrike is already installed (Registry entry found: $imagePath)"
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

    $args = "/install","/quiet","/norestart","CID=$CID"
    try {
        Write-Host "Launching CrowdStrike installer..."
        $proc = Start-Process -FilePath $InstallerPath -ArgumentList $args -PassThru -WindowStyle Hidden -Wait
        if ($proc -and ($proc.ExitCode -eq 0)) {
            Write-Host "CrowdStrike installed successfully (ExitCode $($proc.ExitCode))"
            return $true
        } else {
            $exit = if ($proc) { $proc.ExitCode } else { "unknown" }
            Write-Host "CrowdStrike installer finished with exit code $exit"
            return $false
        }
    } catch {
        Write-Host "CrowdStrike installation failed: $_"
        return $false
    }
}

function Install-Vantage {
    param (
        [string]$location
    )

    $batPath       = Join-Path $PSScriptRoot "client803.bat"
    $targetPath    = "C:\client803"
    $sourceClientFolder = Join-Path $PSScriptRoot "client803_source" 
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
        @{ Path = "$PSScriptRoot\Microsoft WSE 3.0 Runtime.msi"; Percent = 90 },
        @{ Path = "$PSScriptRoot\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Percent = 95 },
        @{ Path = "$PSScriptRoot\dotNetFx35Setup.exe"; Percent = 98 },
        @{ Path = "$PSScriptRoot\sqlncli.msi"; Percent = 99 }
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
    $msiPath = Join-Path $PSScriptRoot "AcroRead.msi"
    $mstPath = Join-Path $PSScriptRoot "AcroRead.mst"
    $mspPath = Join-Path $PSScriptRoot "AcroRdrDCUpd2500120693.msp"
    $cabPath = Join-Path $PSScriptRoot "Data1.cab"
    
    if (-not (Test-Path $msiPath)) { Write-Host "MSI not found: $msiPath"; return $false }
    if (-not (Test-Path $mstPath)) { Write-Host "MST not found: $mstPath"; return $false }
    if (-not (Test-Path $mspPath)) { Write-Host "MSP not found: $mspPath"; return $false }
    if (-not (Test-Path $cabPath)) { Write-Host "CAB not found: $cabPath"; return $false }
    
    Write-Host "All Adobe Reader files found. Starting installation..."
    
    Push-Location $PSScriptRoot
    
    try {
        $baseArgs = @(
            "/i", "`"AcroRead.msi`"",
            "TRANSFORMS=`"AcroRead.mst`"",
            "/qn", "/norestart"
        )
        
        Write-Host "Installing Adobe Reader base with transform..."
        $baseProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $baseArgs -Wait -PassThru
        
        if ($baseProcess.ExitCode -ne 0) {
            Write-Host "Base installation failed with exit code: $($baseProcess.ExitCode)"
            return $false
        }
        
        Write-Host "Base installation successful. Applying patch..."
        Start-Sleep -Seconds 5
        
        $patchArgs = @(
            "/p", "`"AcroRdrDCUpd2500120693.msp`"",
            "/qn", "/norestart"
        )
        
        $patchProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $patchArgs -Wait -PassThru
        
        if ($baseProcess.ExitCode -eq 0) {
            Write-Host "Adobe Reader installation and patch complete"
            return $true
        } else {
            Write-Host "Installation completed but patch may have failed"
            return $true
        }
        
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
    $setupPath = Join-Path $PSScriptRoot "setup.exe"
    $configPath = Join-Path $PSScriptRoot "officesilent.xml"
    
    if (-not (Test-Path $setupPath)) { Write-Host "Setup file not found: $setupPath"; return $false }
    if (-not (Test-Path $configPath)) { Write-Host "Configuration file not found: $configPath"; return $false }
    
    $args = @(
        "/configure", "`"$configPath`""
    )
    Write-Host "Installing Office 365..."
    Run-Installer -Path $setupPath -Arguments $args -TimeoutSeconds 1800
    
    Write-Host "Office 365 installation complete."
    return $true
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

# === MAIN EXECUTION ===
Write-Host "=== PSI DEPLOYMENT TOOL STARTING ==="
Write-Host "Loading domain credentials..."

$folderPath = $PSScriptRoot
$Credential = Get-DomainCredential -ScriptDirectory $folderPath

if ($Credential) {
    Write-Host "Domain credentials loaded successfully"
} else {
    Write-Host "WARNING: Domain credentials not available - limited functionality"
    Write-Host "Domain join and computer rename will be skipped"
}

# Execute deployment steps
Set-TimeZoneFromUserInput

# Join domain with enhanced error handling
$domainJoined = Join-DomainBasedOnLocation -Location $location -Credential $Credential

# Rename computer with enhanced error handling
$computerRenamed = Rename-ComputerPrompt -ComputerName $computerName -Credential $Credential

# Continue with system configuration
Install-SharedDriveTask -Location $location
Switch-Logs
Enable-RDP

# System configuration (sequential instead of parallel)
Write-Host "=== SYSTEM CONFIGURATION ==="
Enable-SystemFeatures
Enable-DotNetFramework

# Install applications
Install-TeamViewer
Install-AdobeReader

if (Install-CrowdStrike) { 
    Write-Host "CrowdStrike finished, continuing..." 
} else { 
    Write-Host "CrowdStrike failed, continuing anyway..." 
}

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

if ($installVANTAGE) { 
    Install-Vantage -location $location 
} else { 
    Write-Host "Vantage installation bypassed" -ForegroundColor Cyan 
}

Remove-Office365
Install-Office365
Verify-Installations
Run-WindowsUpdates

# Clean up background jobs
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
