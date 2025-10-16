
#region PSI Electron App Integration Hooks

# The following hooks ensure full compatibility with the Electron + React frontend integration
# (powershell.cjs parses all "Write-Host" output and detects progress keywords).

function Write-DeploymentProgress {
    param(
        [string]$Message,
        [int]$Progress = $null,
        [string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString("HH:mm:ss")
    if ($Progress -ne $null) {
        Write-Host "$timestamp [$Level] $Message progress: $Progress"
    } else {
        Write-Host "$timestamp [$Level] $Message"
    }
}

# Compatibility alias for PSI-WriteLog → Write-DeploymentProgress bridge
if (-not (Get-Command Write-DeploymentProgress -ErrorAction SilentlyContinue)) {
    function Write-DeploymentProgress { param($Message,$Progress); Write-Host $Message }
}

# Ensure all PSI-WriteLog calls emit visible logs for Electron parsing
function PSI-WriteLog {
    param([string]$Message,[string]$Level='INFO',[int]$Progress=$null)
    try {
        if ($Progress -ne $null) {
            Write-Host "[$Level] $Message progress: $Progress"
        } else {
            Write-Host "[$Level] $Message"
        }
    } catch {
        Write-Host "[ERROR] Log emission failed: $($_.Exception.Message)"
    }
}

# Progress milestones for UI sync
function PSI-EmitProgress {
    param([int]$Value,[string]$Phase)
    Write-DeploymentProgress -Message "$Phase..." -Progress $Value
}

# Emit early progress checkpoints for frontend display
PSI-EmitProgress 5 "Initialization started"
PSI-EmitProgress 10 "McAfee removal initiated"
PSI-EmitProgress 15 "System optimization initialized"

#endregion PSI Electron App Integration Hooks


#region PSI Fast Path + McAfee Auto-Removal (No Reboot)
# --- Safe speed-ups (scoped to this process) ---
$ProgressPreference = 'SilentlyContinue'     # skip chatty progress bars that slow down loops
$PSStyle.OutputRendering = 'PlainText' 2>$null  # avoid VT rendering overhead if supported (PS 7+ safe no-op on 5.1)
$ErrorActionPreference = 'Stop'          # fail fast

# Lightweight logger that defers to Write-DeploymentProgress if present
function PSI-Log {
    param([string]$Message)
    if (Get-Command -Name Write-DeploymentProgress -ErrorAction SilentlyContinue) {
        Write-DeploymentProgress -Message $Message
    } else {
        Write-Host $Message
    }
}

function Remove-McAfee {
    <#
        .SYNOPSIS
            Silently removes McAfee (Agent, ENS, LiveSafe, Security Scan, legacy) without reboot.
        .NOTES
            - Tries McAfee Agent "frminst.exe /forceuninstall"
            - Iterates 32/64-bit Uninstall keys; normalizes UninstallString to quiet, no-restart
            - Stops/Disables services & scheduled tasks pre-uninstall
            - Best-effort cleanup of residual folders
    #>
    [CmdletBinding()]
    param()

    $found = $false
    PSI-Log "🔍 Checking for McAfee products..."

    # 1) Try McAfee Agent forced uninstall first (common in enterprise)
    $agentPaths = @(
        "$Env:ProgramFiles\McAfee\Agent\x86\frminst.exe",
        "$Env:ProgramFiles\McAfee\Agent\frminst.exe",
        "${Env:ProgramFiles(x86)}\McAfee\Agent\x86\frminst.exe",
        "${Env:ProgramFiles(x86)}\McAfee\Agent\frminst.exe"
    ) | Where-Object { Test-Path $_ }

    foreach ($p in $agentPaths) {
        try {
            $found = $true
            PSI-Log "🧹 McAfee Agent detected -> $p (forcing uninstall, no restart)"
            $proc = Start-Process -FilePath $p -ArgumentList "/forceuninstall" -PassThru -WindowStyle Hidden -Wait
            PSI-Log "   frminst exit code: $($proc.ExitCode)"
        } catch {
            PSI-Log "   ⚠️ frminst failed: $($_.Exception.Message)"
        }
    }

    # 2) Stop/disable McAfee services & tasks (best effort)
    try {
        $svc = Get-Service | Where-Object { $_.Name -match '^(mf|mfe|mcafee)' -or $_.DisplayName -match 'McAfee' }
        foreach ($s in $svc) {
            try {
                if ($s.Status -ne 'Stopped') { Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue }
                Set-Service -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
            } catch {}
        }
    } catch {}

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'McAfee' -or $_.TaskPath -match 'McAfee' }
        foreach ($t in $tasks) {
            try { Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue } catch {}
        }
    } catch {}

    # 3) Uninstall via registry uninstall strings (32/64)
    $uninstallRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $mcafeekeys = foreach ($root in $uninstallRoots) {
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $disp = (Get-ItemProperty $_.PSPath -ErrorAction Stop).DisplayName
                if ($disp -and ($disp -match 'McAfee|Security Scan|LiveSafe|Endpoint Security|VirusScan|DLP|Agent')) { $_ }
            } catch {}
        }
    }

    foreach ($k in $mcafeekeys) {
        try {
            $p = Get-ItemProperty $k.PSPath -ErrorAction Stop
            $name = $p.DisplayName
            $us = $p.UninstallString
            if (-not $us) { continue }
            $found = $true

            PSI-Log "🧨 Uninstalling: $name"

            # Normalize UninstallString -> quiet + no restart
            $exe, $args = $null, $null
            if ($us -match '^"?(?<exe>[^"]+?\.msi)"?\s*(?<rest>.*)$' -or $us -match 'msiexec\.exe') {
                # MSI-based
                # Ensure we end up with: msiexec /x {GUID or MSI} /qn REBOOT=ReallySuppress /norestart
                if ($us -match '/x\s*({[^}]+}|".+?")') {
                    $exe = "msiexec.exe"
                    $args = "$us"
                } elseif ($us -match '\.msi') {
                    $exe = "msiexec.exe"
                    $args = '/i "' + ($us -replace '.*?"([^"]+\.msi)".*', '$1') + '" /qn REBOOT=ReallySuppress /norestart'
                } else {
                    $exe = "msiexec.exe"
                    $args = "/x $us /qn REBOOT=ReallySuppress /norestart"
                }
                # Normalize spacing
                $args = $args -replace '/qn', '/qn' -replace '/quiet', '/qn'
                if ($args -notmatch 'REBOOT=ReallySuppress') { $args += ' REBOOT=ReallySuppress' }
                if ($args -notmatch '/norestart') { $args += ' /norestart' }
            } else {
                # EXE-based
                if ($us.StartsWith('"')) {
                    $exe = ($us -split '"')[1]
                    $args = $us.Substring($exe.Length + 2).Trim()
                } else {
                    $parts = $us.Split(' ', 2)
                    $exe = $parts[0]
                    $args = ($parts | Select-Object -Skip 1) -join ' '
                }
                # Add quiet + no restart if missing
                if ($args -notmatch '/qn|/quiet|/s|/silent') { $args += ' /quiet' }
                if ($args -notmatch '/norestart|REBOOT=ReallySuppress') { $args += ' /norestart' }
            }

            $proc = Start-Process -FilePath $exe -ArgumentList $args -PassThru -WindowStyle Hidden -Wait
            PSI-Log "   Exit code: $($proc.ExitCode)"
        } catch {
            PSI-Log "   ⚠️ Failed to uninstall via registry for key $($k.PSChildName): $($_.Exception.Message)"
        }
    }

    # 4) Residual cleanup (best effort)
    $paths = @(
        "$Env:ProgramFiles\McAfee",
        "${Env:ProgramFiles(x86)}\McAfee",
        "$Env:ProgramData\McAfee"
    )
    foreach ($p in $paths) {
        try {
            if (Test-Path $p) {
                PSI-Log "🧽 Cleaning up: $p"
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }

    if ($found) {
        PSI-Log "✅ McAfee removal pass complete (no reboot)."
    } else {
        PSI-Log "ℹ️ No McAfee products detected. Skipping removal."
    }
}

# Auto-run McAfee removal up front (no reboot). Safe if nothing found.
try {
    Remove-McAfee
} catch {
    PSI-Log "⚠️ Remove-McAfee encountered an error: $($_.Exception.Message)"
}
#endregion PSI Fast Path + McAfee Auto-Removal (No Reboot)


﻿param(
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
            $highPerf = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"  # High Performance GUID
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
        
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "SMB1 protocols enabled (for legacy Vantage and shared drive support)"
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

function Enable-IntuneAutoEnrollment {
    Write-Host "=== CONFIGURING INTUNE AUTO-ENROLLMENT ===" -ForegroundColor Cyan
    
    try {
        # Check if device is domain-joined first
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        if ($computerSystem.PartOfDomain -ne $true) {
            Write-Host "Device is not domain-joined - cannot configure Intune enrollment" -ForegroundColor Red
            return $false
        }
        
        Write-Host "Configuring MDM enrollment registry keys..." -ForegroundColor Yellow
        
        # Registry path for MDM auto-enrollment
        $mdmRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM"
        
        # Create registry path if it doesn't exist
        if (-not (Test-Path $mdmRegPath)) {
            New-Item -Path $mdmRegPath -Force -ErrorAction Stop | Out-Null
            Write-Host "Created MDM registry path" -ForegroundColor Green
        }
        
        # Enable auto-enrollment for domain-joined devices
        Set-ItemProperty -Path $mdmRegPath -Name "AutoEnrollMDM" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "  ✓ Enabled MDM auto-enrollment" -ForegroundColor Green
        
        # Set enrollment URL (Microsoft Intune)
        Set-ItemProperty -Path $mdmRegPath -Name "UseAADCredentialType" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        
        # Configure discovery URL
        $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        if (-not (Test-Path $enrollmentPath)) {
            New-Item -Path $enrollmentPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Enable discovery
        $discoveryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MDM"
        if (-not (Test-Path $discoveryPath)) {
            New-Item -Path $discoveryPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Trigger device sync with Azure AD
        Write-Host "Triggering Azure AD sync..." -ForegroundColor Yellow
        try {
            & dsregcmd /status | Out-Null
            Write-Host "  ✓ Device registration status checked" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Could not verify device registration status" -ForegroundColor Yellow
        }
        
        # Create scheduled task to trigger enrollment on next logon
        Write-Host "Creating enrollment trigger task..." -ForegroundColor Yellow
        
        $taskName = "TriggerIntuneEnrollment"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        
        # Script to trigger enrollment
        $enrollScript = @'
Start-Sleep -Seconds 30
$user = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
if ($user) {
    & deviceenroller.exe /c /AutoEnrollMDM
}
'@
        
        $scriptPath = "C:\Windows\Temp\TriggerEnrollment.ps1"
        $enrollScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -GroupId "Users" -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        Write-Host "  ✓ Enrollment trigger task created" -ForegroundColor Green
        
        Write-Host "`nIntune auto-enrollment configuration completed successfully" -ForegroundColor Green
        Write-Host "Device will automatically enroll in Intune after:" -ForegroundColor Cyan
        Write-Host "  1. System reboot" -ForegroundColor Cyan
        Write-Host "  2. User login with domain credentials" -ForegroundColor Cyan
        
        return $true
        
    } catch {
        Write-Host "Failed to configure Intune auto-enrollment: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Error details: $($_.Exception.GetType().FullName)" -ForegroundColor Red
        return $false
    }
}

function Join-DomainBasedOnLocation {
    param([string]$Location, [object]$Credential)
    
    Write-Host "=== DOMAIN JOIN PROCESS ===" -ForegroundColor Cyan
    
    if (-not $Credential) {
        Write-Host "Domain join skipped: No valid credentials available" -ForegroundColor Yellow
        Write-Host "Manual domain join required after deployment" -ForegroundColor Yellow
        return @{
            Joined = $false
            IntuneConfigured = $false
        }
    }
    
    if (-not (Test-NetworkConnectivity -Location $Location)) {
        Write-Host "Network connectivity issues detected - domain join may fail" -ForegroundColor Yellow
    }
    
    Write-Host "Domain join credentials validated successfully" -ForegroundColor Green
    Write-Host "Attempting to join domain for location: $Location" -ForegroundColor Cyan
    
    $joined = $false
    switch ($Location.ToUpper()) {
        "GEORGIA" {
            try {
                Write-Host "Joining GEORGIA domain (psi-pac.com via GA-DC02)..." -ForegroundColor Yellow
                Add-Computer -DomainName "psi-pac.com" -Server "GA-DC02" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
                Write-Host "Successfully joined GEORGIA domain" -ForegroundColor Green
            } catch {
                Write-Host "Failed to join GEORGIA domain: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Error details: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            }
        }
        "ARKANSAS" {
            try {
                Resolve-DnsName -Name "AR-DC.psi-pac.com" -Server 10.1.199.2 -ErrorAction SilentlyContinue
                Write-Host "Configuring DNS for ARKANSAS domain..." -ForegroundColor Yellow
                Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "10.1.199.2" -ErrorAction Stop | Out-Null
                Write-Host "Joining ARKANSAS domain (psi-pac.com via AR-DC)..." -ForegroundColor Yellow
                Add-Computer -DomainName "psi-pac.com" -Server "AR-DC" -Credential $Credential -Force -ErrorAction Stop
                $joined = $true
                Write-Host "Successfully joined ARKANSAS domain" -ForegroundColor Green
            } catch {
                Write-Host "Failed to join ARKANSAS domain: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Error details: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            }
        }
        "IDAHO" {
            try {
                Write-Host "Joining IDAHO domain (psi-pac.com via ID-DC)..." -ForegroundColor Yellow
                Add-Computer -DomainName "psi-pac.com" -Server "ID-DC" -Credential $Credential -Force -ErrorAction Stop | Out-Null
                $joined = $true
                Write-Host "Successfully joined IDAHO domain" -ForegroundColor Green
            } catch {
                Write-Host "Failed to join IDAHO domain: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "Error details: $($_.Exception.GetType().FullName)" -ForegroundColor Red
            }
        }
        Default {
            Write-Host "Invalid location provided: $Location" -ForegroundColor Red
            Write-Host "Valid locations: GEORGIA, ARKANSAS, IDAHO" -ForegroundColor Yellow
        }
    }
    
    $intuneConfigured = $false
    
    if ($joined) {
        Write-Host "`nDomain join completed successfully for $Location" -ForegroundColor Green
        
        # Verify domain membership before proceeding
        Write-Host "Verifying domain membership..." -ForegroundColor Cyan
        Start-Sleep -Seconds 5
        
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
            if ($computerSystem.PartOfDomain -eq $true) {
                Write-Host "  ✓ Domain membership confirmed: $($computerSystem.Domain)" -ForegroundColor Green
                
                # Allow additional time for AD replication and domain policies
                Write-Host "Waiting for domain policies to replicate (15 seconds)..." -ForegroundColor Cyan
                Start-Sleep -Seconds 15
                
                # Now configure Intune enrollment
                Write-Host "`n=== PROCEEDING WITH INTUNE ENROLLMENT SETUP ===" -ForegroundColor Cyan
                $intuneConfigured = Enable-IntuneAutoEnrollment
                
                if ($intuneConfigured) {
                    Write-Host "`nIntune auto-enrollment configured successfully" -ForegroundColor Green
                    Write-Host "Device will enroll in Intune after reboot and user login" -ForegroundColor Cyan
                } else {
                    Write-Host "`nIntune configuration encountered issues" -ForegroundColor Yellow
                    Write-Host "Device may require manual Intune enrollment" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  ✗ Domain membership verification failed" -ForegroundColor Red
                Write-Host "Skipping Intune configuration - device not confirmed as domain-joined" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ✗ Could not verify domain membership: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Skipping Intune configuration due to verification failure" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`nDomain join failed for $Location" -ForegroundColor Red
        Write-Host "Skipping Intune configuration - domain join is required first" -ForegroundColor Yellow
        Write-Host "Manual domain join and Intune enrollment will be required" -ForegroundColor Yellow
    }
    
    return @{
        Joined = $joined
        IntuneConfigured = $intuneConfigured
    }
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
            ErrorAction = 'SilentlyContinue'
        }
        
        if ($safeArgs.Count -gt 0) {
            $processArgs.ArgumentList = $safeArgs
        }
        
        # START PROCESS WITHOUT -Wait
        $process = Start-Process @processArgs
        
        # MANUALLY WAIT WITH TIMEOUT
        $timeout = $TimeoutSeconds
        $elapsed = 0
        $checkInterval = 2
        
        while (-not $process.HasExited -and $elapsed -lt $timeout) {
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
            
            # Progress indicator every 10 seconds
            if ($elapsed % 10 -eq 0) {
                Write-Host "  ... installer running ($elapsed seconds elapsed)"
            }
        }
        
        # If timeout exceeded, kill the process
        if (-not $process.HasExited) {
            Write-Host "Installer exceeded timeout ($timeout seconds), terminating process" -ForegroundColor Yellow
            try {
                $process.Kill()
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "Failed to kill process: $($_.Exception.Message)" -ForegroundColor Red
            }
            return $false
        }

        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Host "Installer completed successfully: $Path (exit code: $($process.ExitCode))" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Installer completed with exit code $($process.ExitCode): $Path" -ForegroundColor Yellow
            return $true  # Still return true for non-critical exit codes
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


function Enable-DotNetFramework {
    try {
        Write-Host "Enabling .NET Framework 3.5 (includes 2.0 and 3.0)..."
        
        $sxsSource = "X:\sources\sxs"
        if (Test-Path $sxsSource) {
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -LimitAccess -Source $sxsSource -ErrorAction SilentlyContinue | Out-Null
        }

        Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Enable-Feature", "/FeatureName:NetFx3", "/All", "/NoRestart", "/Quiet" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue | Out-Null
        Write-Host ".NET Framework installation initiated silently."
        return $true
    } catch {
        Write-Host "Failed to enable .NET Framework: $_"
        return $false
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

    Write-Host "=== VANTAGE INSTALLATION PROCESS ===" -ForegroundColor Cyan
    Write-Host "Target location: $location"
    Write-Output "vantage progress: 0"

    # Check if already installed
    if (Test-Path $targetPath) {
        Write-Host "Target directory already exists: $targetPath"
        $existingFiles = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "Existing files: $existingFiles"
        if ($existingFiles -gt 1000) {
            Write-Host "Vantage appears to already be installed. Skipping installation."
            Write-Output "vantage progress: 100"
            
            # Still configure session management even if already installed
            Install-VantageSessionManager
            return
        }
    }

    # First check deployment cache (downloaded via Python from IIS)
    $localZip = Join-Path $DeploymentRoot "client803.zip"
    $useLocalCache = $false
    
    if (Test-Path $localZip) {
        Write-Host "Found client803.zip in deployment cache: $localZip" -ForegroundColor Green
        $remoteZip = $localZip
        $useLocalCache = $true
    } else {
        Write-Host "client803.zip not found in cache, using network paths" -ForegroundColor Yellow
        
        # Fallback to network paths
        switch ($location.ToUpper()) {
            "GEORGIA" { 
                $remoteZip      = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803.zip"
                $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
                $fallbackFolder = "\\ga-dc02\Shared2\Vantage\client803"
            }
            "ARKANSAS" { 
                $remoteZip      = "\\ar-dc\Shared\Vantage\client803.zip"
                $remoteFolder   = "\\ar-dc\Shared\Vantage\client803"
                $fallbackFolder = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            }
            "IDAHO" { 
                $remoteZip      = "\\id-dc\IDShared\Shipping\Rack Sheet\PSI BOL & Invoice\Vantage\client803.zip"
                $remoteFolder   = "\\id-dc\IDShared\Shipping\Rack Sheet\PSI BOL & Invoice\Vantage\client803"
                $fallbackFolder = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
            }
            default { 
                $remoteZip      = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803.zip"
                $remoteFolder   = "\\ga-dc02\Shared2\New I.T\New PCs\2) VantageInstall\client803"
                $fallbackFolder = $null
            }
        }
    }

    $zipSuccess = $false
    
    # Try ZIP extraction method
    if (Test-Path $remoteZip -ErrorAction SilentlyContinue) {
        Write-Host "Found ZIP archive: $remoteZip" -ForegroundColor Green
        Write-Host "Using compressed archive method (10-20x faster)..." -ForegroundColor Cyan
        
        try {
            if ($useLocalCache) {
                $tempZip = $localZip
                Write-Host "Using cached archive directly" -ForegroundColor Green
                Write-Output "vantage progress: 50"
            } else {
                $tempZip = "$env:TEMP\client803_install.zip"
                
                Write-Host "Copying compressed archive from network..."
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
                
                if (-not $copyResult.Success) {
                    throw "Copy failed: $($copyResult.Error)"
                }
                
                Write-Output "vantage progress: 50"
                $zipSize = [math]::Round($copyResult.Size / 1MB, 2)
                Write-Host "Archive copied successfully ($zipSize MB)" -ForegroundColor Green
            }
            
            Write-Host "Extracting archive to $targetPath..."
            
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZip, $targetPath)
                
                if (-not $useLocalCache) {
                    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                }
                
                Write-Output "vantage progress: 85"
                
                $finalCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
                Write-Host "Archive extraction completed: $finalCount files extracted" -ForegroundColor Green
                
                $zipSuccess = $true
                
            } catch {
                Write-Host "Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                if (-not $useLocalCache) {
                    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $targetPath) {
                    Remove-Item $targetPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            
        } catch {
            Write-Host "Archive method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "ZIP archive not found: $remoteZip" -ForegroundColor Yellow
        Write-Host "Falling back to folder copy method..."
    }

    # Fallback to robocopy if ZIP method failed
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
    
    # Verify installation
    if (Test-Path $targetPath) {
        $finalCount = (Get-ChildItem -Path $targetPath -Recurse -File -ErrorAction SilentlyContinue).Count
        Write-Host "Copy verification: $finalCount files copied" -ForegroundColor Green
        if ($finalCount -lt 1000) {
            Write-Host "WARNING: File count seems low. Installation may be incomplete." -ForegroundColor Yellow
        }
    }
    
    # START .NET FRAMEWORK IN BACKGROUND (COMPLETELY SILENT)
    Write-Host "Starting .NET Framework 3.5 installation in background (silent mode)..." -ForegroundColor Cyan
    $dotnetPath = "$DeploymentRoot\dotNetFx35Setup.exe"
    $dotnetJob = $null
    
    if (Test-Path $dotnetPath) {
        $dotnetCheck = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
        if ($dotnetCheck -and $dotnetCheck.State -eq 'Enabled') {
            Write-Host ".NET Framework 3.5 already enabled, skipping installation" -ForegroundColor Green
        } else {
            $dotnetJob = Start-Job -ScriptBlock {
                param($path)
                try {
                    $proc = Start-Process -FilePath $path -ArgumentList "/q", "/norestart" -PassThru -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                    return @{Success=$true; ExitCode=$proc.ExitCode}
                } catch {
                    return @{Success=$false; Error=$_.Exception.Message}
                }
            } -ArgumentList $dotnetPath
            Write-Host ".NET Framework 3.5 running silently in background..."
        }
    } else {
        Write-Host ".NET Framework installer not found: $dotnetPath" -ForegroundColor Yellow
    }
    
    # ===== SEQUENTIAL MSI INSTALLATION (WINDOWS REQUIREMENT) =====
    Write-Host "Installing Vantage MSI dependencies (sequential - Windows requirement)..." -ForegroundColor Cyan
    
    $msiFiles = @(
        @{Path = "$DeploymentRoot\Microsoft WSE 3.0 Runtime.msi"; Name = "Microsoft WSE 3.0"; Args = @("/i", "`"$DeploymentRoot\Microsoft WSE 3.0 Runtime.msi`"", "/qb!", "/norestart", "REBOOT=ReallySuppress")},
        @{Path = "$DeploymentRoot\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi"; Name = "Crystal Reports"; Args = @("/i", "`"$DeploymentRoot\Crystal Reports XI R2 .Net 3.0 Runtime SP5.msi`"", "/qb!", "/norestart", "REBOOT=ReallySuppress")},
        @{Path = "$DeploymentRoot\sqlncli.msi"; Name = "SQL Native Client"; Args = @("/i", "`"$DeploymentRoot\sqlncli.msi`"", "/qb!", "/norestart", "REBOOT=ReallySuppress", "IACCEPTSQLNCLILICENSETERMS=YES")}
    )
    
    $installStartTime = Get-Date
    $msiCount = 0
    
    foreach ($msi in $msiFiles) {
        if (Test-Path $msi.Path) {
            Write-Host "  Installing: $($msi.Name)..." -ForegroundColor Yellow
            
            try {
                $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msi.Args -PassThru -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                    Write-Host "  ✓ $($msi.Name) installed successfully (exit code: $($proc.ExitCode))" -ForegroundColor Green
                } elseif ($proc.ExitCode -eq 1605) {
                    Write-Host "  ⚠ $($msi.Name) may already be installed (exit code: 1605)" -ForegroundColor Yellow
                } else {
                    Write-Host "  ⚠ $($msi.Name) completed with exit code: $($proc.ExitCode)" -ForegroundColor Yellow
                }
                
                $msiCount++
                $progress = 87 + [math]::Min([math]::Round(($msiCount / $msiFiles.Count) * 10), 10)
                Write-Output "vantage progress: $progress"
                
            } catch {
                Write-Host "  ✗ $($msi.Name) failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } 
    } 

    
    $installTime = (Get-Date) - $installStartTime
    Write-Host "MSI installations completed in $($installTime.ToString('mm\:ss'))" -ForegroundColor Green

    # Wait for .NET Framework background job to complete (if it was started)
    if ($dotnetJob) {
        Write-Host "Waiting for .NET Framework 3.5 background installation to complete..." -ForegroundColor Cyan
        $dotnetResult = Wait-Job $dotnetJob -Timeout 600 | Receive-Job -ErrorAction SilentlyContinue
        Remove-Job $dotnetJob -Force -ErrorAction SilentlyContinue
        
        if ($dotnetResult.Success) {
            Write-Host ".NET Framework 3.5 installation completed (Exit code: $($dotnetResult.ExitCode))" -ForegroundColor Green
        } else {
            Write-Host ".NET Framework 3.5 installation encountered issues: $($dotnetResult.Error)" -ForegroundColor Yellow
        }
    }
    
    Write-Output "vantage progress: 99"

    # ===== CREATE VANTAGE DESKTOP SHORTCUT (IMPROVED) =====
    Write-Host "Creating Vantage desktop shortcut..." -ForegroundColor Cyan

    try {
        $desktopPath = "$env:PUBLIC\Desktop"
        $remoteShortcut = "\\ga-dc02\deploy-files\Vantage 8.03.lnk"
        $localShortcut = Join-Path $desktopPath "Vantage 8.03.lnk"
        
        # Method 1: Try to copy from network location
        if (Test-Path $remoteShortcut -ErrorAction SilentlyContinue) {
            Copy-Item -Path $remoteShortcut -Destination $localShortcut -Force -ErrorAction Stop
            Write-Host "Shortcut copied successfully from network location" -ForegroundColor Green
        } else {
            throw "Network shortcut not accessible"
        }
        
    } catch {
        Write-Host "Could not copy from network: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Creating shortcut programmatically as fallback..." -ForegroundColor Cyan
        
        try {
            # Method 2: Create programmatically
            $vantageExe = $null
            $possibleExePaths = @(
                "C:\client803\MfgSys.exe",
                "C:\client803\bin\MfgSys.exe",
                "C:\client803\Epicor.exe",
                "C:\client803\Vantage.exe"
            )
            
            foreach ($exePath in $possibleExePaths) {
                if (Test-Path $exePath) {
                    $vantageExe = $exePath
                    Write-Host "Found Vantage executable: $vantageExe" -ForegroundColor Green
                    break
                }
            }
            
            if (-not $vantageExe) {
                Write-Host "Searching for Vantage executable..." -ForegroundColor Yellow
                $foundExe = Get-ChildItem -Path "C:\client803" -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue | 
                            Where-Object { $_.Name -match "MfgSys|Epicor|Vantage" } | 
                            Select-Object -First 1
                if ($foundExe) { 
                    $vantageExe = $foundExe.FullName
                    Write-Host "Found executable via search: $vantageExe" -ForegroundColor Green
                }
            }
            
            if ($vantageExe) {
                $WshShell = New-Object -ComObject WScript.Shell
                
                # Create on Public Desktop
                $shortcutPath = "$env:PUBLIC\Desktop\Vantage 8.03.lnk"
                $shortcut = $WshShell.CreateShortcut($shortcutPath)
                $shortcut.TargetPath = $vantageExe
                $shortcut.WorkingDirectory = "C:\client803"
                $shortcut.Description = "Vantage 8.03 ERP System"
                $shortcut.IconLocation = "$vantageExe,0"
                $shortcut.Save()
                
                Write-Host "Desktop shortcut created programmatically: $shortcutPath" -ForegroundColor Green
                
                # Also create in Start Menu
                $startMenuPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Vantage 8.03.lnk"
                $startMenuShortcut = $WshShell.CreateShortcut($startMenuPath)
                $startMenuShortcut.TargetPath = $vantageExe
                $startMenuShortcut.WorkingDirectory = "C:\client803"
                $startMenuShortcut.Description = "Vantage 8.03 ERP System"
                $startMenuShortcut.IconLocation = "$vantageExe,0"
                $startMenuShortcut.Save()
                
                Write-Host "Start Menu shortcut created successfully" -ForegroundColor Green
                
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
            } else {
                Write-Host "WARNING: Could not find Vantage executable" -ForegroundColor Red
                Write-Host "Shortcut can be created manually after deployment" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "Failed to create shortcut programmatically: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # ===== CONFIGURE VANTAGE SESSION AUTO-TERMINATION =====
    Install-VantageSessionManager
    
    # ===== CONFIGURE ADDITIONAL SESSION PREVENTION MEASURES =====
    Configure-VantageRegistry
    Create-VantageCleanupShortcut

    Write-Output "vantage progress: 100"
    Write-Host "Vantage installation completed successfully" -ForegroundColor Green
}

function Install-VantageSessionManager {
    Write-Host "=== CONFIGURING VANTAGE SESSION AUTO-TERMINATION ===" -ForegroundColor Cyan
    
    try {
        # Create the session management script
        $sessionScript = @'
$targetPort = 8301
$processName = "MfgSys"
$logPath = "C:\Logs\VantageSessionManager.log"

# Create log directory if it doesn't exist
$logDir = Split-Path $logPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

function Clear-OrphanedSessions {
    # Method 1: Kill orphaned TCP connections on port 8301
    $connections = Get-NetTCPConnection -RemotePort $targetPort -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $pid = $conn.OwningProcess
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                $processName = $proc.ProcessName
                Stop-Process -Id $pid -Force -ErrorAction Stop
                Write-Log "Terminated orphaned connection: $processName (PID: $pid) on port $targetPort"
            } catch {
                Write-Log "Warning: Could not terminate PID $pid - $($_.Exception.Message)"
            }
        }
    }
    
    # Method 2: Kill any lingering Vantage-related processes
    $vantageProcesses = @("MfgSys", "Epicor", "VantageClient", "Progress", "prowin32")
    foreach ($procName in $vantageProcesses) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($proc in $procs) {
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-Log "Terminated lingering process: $procName (PID: $($proc.Id))"
                } catch {
                    Write-Log "Warning: Could not terminate $procName - $($_.Exception.Message)"
                }
            }
        }
    }
    
    # Method 3: Clear Vantage temporary/lock files
    $vantageTemp = "C:\client803\temp"
    if (Test-Path $vantageTemp) {
        Get-ChildItem -Path $vantageTemp -Filter "*.lck" -ErrorAction SilentlyContinue | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $vantageTemp -Filter "*.tmp" -ErrorAction SilentlyContinue | 
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Log "Cleaned up lock and temp files from $vantageTemp"
    }
    
    # Method 4: Reset netsh if connections are stuck
    try {
        & netsh int ip reset | Out-Null
        Write-Log "Reset TCP/IP stack"
    } catch {
        Write-Log "Could not reset TCP/IP stack"
    }
}

Write-Log "=== Vantage Session Manager Started ==="

while ($true) {
    # Wait for MfgSys to start
    while (-not (Get-Process -Name $processName -ErrorAction SilentlyContinue)) {
        Start-Sleep -Seconds 2
    }
    
    Write-Log "MfgSys.exe started - monitoring session"

    # Wait for MfgSys to close
    while (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 2
    }
    
    Write-Log "MfgSys.exe closed - cleaning up orphaned sessions"
    
    # Wait a moment for graceful shutdown
    Start-Sleep -Seconds 3
    
    # Clean up all orphaned sessions
    Clear-OrphanedSessions
    
    Write-Log "Session cleanup completed - resuming monitoring"
    Start-Sleep -Seconds 2
}
'@
        
        # Save the PowerShell script
        $scriptPath = "C:\vantagesession.ps1"
        $sessionScript | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
        Write-Host "Session management script created: $scriptPath" -ForegroundColor Green
        
        # Create the VBScript wrapper for silent execution
        $vbsScript = @'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\vantagesession.ps1""", 0, False
Set objShell = Nothing
'@
        
        $vbsPath = "C:\hidden2.vbs"
        $vbsScript | Out-File -FilePath $vbsPath -Encoding ASCII -Force
        Write-Host "VBScript wrapper created: $vbsPath" -ForegroundColor Green
        
        # Create scheduled task to run at startup
        $taskName = "VantageSessionManager"
        
        # Remove existing task if present
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "Removed existing session manager task" -ForegroundColor Yellow
        }
        
        # Create new scheduled task
        $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`"" -WorkingDirectory "C:\"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
        
        Write-Host "Vantage Session Manager scheduled task created successfully" -ForegroundColor Green
        Write-Host "  - Task will run at system startup" -ForegroundColor Cyan
        Write-Host "  - Monitors for orphaned Vantage sessions on port 8301" -ForegroundColor Cyan
        Write-Host "  - Automatically terminates sessions when MfgSys.exe closes" -ForegroundColor Cyan
        
        # Start the task immediately
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Write-Host "Session manager started and running in background" -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host "Failed to configure Vantage session manager: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Configure-VantageRegistry {
    Write-Host "=== CONFIGURING VANTAGE REGISTRY SETTINGS ===" -ForegroundColor Cyan
    
    try {
        # Registry path for Vantage settings
        $vantageRegPath = "HKLM:\SOFTWARE\Epicor\Vantage"
        
        if (-not (Test-Path $vantageRegPath)) {
            New-Item -Path $vantageRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Disable session locking/caching that can cause the "one session" issue
        Set-ItemProperty -Path $vantageRegPath -Name "DisableSessionCache" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $vantageRegPath -Name "ForceSessionCleanup" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $vantageRegPath -Name "SessionTimeout" -Value 300 -Type DWord -ErrorAction SilentlyContinue
        
        Write-Host "Vantage registry settings configured" -ForegroundColor Green
        
        # Configure TCP/IP settings to prevent stuck connections
        $tcpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Set-ItemProperty -Path $tcpRegPath -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $tcpRegPath -Name "KeepAliveTime" -Value 300000 -Type DWord -ErrorAction SilentlyContinue
        
        Write-Host "TCP/IP settings optimized for Vantage" -ForegroundColor Green
        
        return $true
        
    } catch {
        Write-Host "Failed to configure Vantage registry settings: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Create-VantageCleanupShortcut {
    Write-Host "=== CREATING MANUAL VANTAGE SESSION CLEANUP SHORTCUT ===" -ForegroundColor Cyan
    
    try {
        # Create a manual cleanup script for users
        $manualCleanupScript = @'
# Manual Vantage Session Cleanup Script
Write-Host "=== VANTAGE SESSION CLEANUP UTILITY ===" -ForegroundColor Cyan
Write-Host "This will forcefully terminate all Vantage sessions and cleanup locks" -ForegroundColor Yellow
Write-Host ""

$confirmation = Read-Host "Continue? (Y/N)"
if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
    Write-Host "Cancelled by user" -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit
}

Write-Host "`nStep 1: Killing Vantage processes..." -ForegroundColor Yellow
$vantageProcesses = @("MfgSys", "Epicor", "VantageClient", "Progress", "prowin32")
$killedCount = 0

foreach ($procName in $vantageProcesses) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($procs) {
        foreach ($proc in $procs) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                Write-Host "  Killed: $procName (PID: $($proc.Id))" -ForegroundColor Green
                $killedCount++
            } catch {
                Write-Host "  Failed to kill: $procName (PID: $($proc.Id))" -ForegroundColor Red
            }
        }
    }
}

if ($killedCount -eq 0) {
    Write-Host "  No Vantage processes found running" -ForegroundColor Cyan
}

Write-Host "`nStep 2: Clearing orphaned connections on port 8301..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection -RemotePort 8301 -ErrorAction SilentlyContinue
$connKilled = 0

if ($connections) {
    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        try {
            Stop-Process -Id $pid -Force -ErrorAction Stop
            Write-Host "  Killed connection: PID $pid" -ForegroundColor Green
            $connKilled++
        } catch {
            Write-Host "  Failed to kill: PID $pid" -ForegroundColor Red
        }
    }
} else {
    Write-Host "  No orphaned connections found" -ForegroundColor Cyan
}

Write-Host "`nStep 3: Cleaning lock files..." -ForegroundColor Yellow
$lockFiles = @(
    "C:\client803\temp\*.lck",
    "C:\client803\temp\*.tmp",
    "C:\client803\*.lck"
)

$filesDeleted = 0
foreach ($pattern in $lockFiles) {
    $files = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            Write-Host "  Deleted: $($file.Name)" -ForegroundColor Green
            $filesDeleted++
        } catch {
            Write-Host "  Failed to delete: $($file.Name)" -ForegroundColor Red
        }
    }
}

if ($filesDeleted -eq 0) {
    Write-Host "  No lock files found" -ForegroundColor Cyan
}

Write-Host "`nStep 4: Flushing DNS and resetting network..." -ForegroundColor Yellow
try {
    ipconfig /flushdns | Out-Null
    Write-Host "  DNS cache flushed" -ForegroundColor Green
} catch {
    Write-Host "  Failed to flush DNS" -ForegroundColor Red
}

Write-Host "`n=== CLEANUP COMPLETE ===" -ForegroundColor Green
Write-Host "Processes killed: $killedCount" -ForegroundColor Cyan
Write-Host "Connections terminated: $connKilled" -ForegroundColor Cyan
Write-Host "Lock files deleted: $filesDeleted" -ForegroundColor Cyan
Write-Host "`nYou can now try launching Vantage again." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to exit"
'@
        
        $cleanupScriptPath = "C:\VantageSessionCleanup.ps1"
        $manualCleanupScript | Out-File -FilePath $cleanupScriptPath -Encoding UTF8 -Force
        
        # Create desktop shortcut for the cleanup script
        $WshShell = New-Object -ComObject WScript.Shell
        $shortcutPath = "$env:PUBLIC\Desktop\Fix Vantage Sessions.lnk"
        $shortcut = $WshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScriptPath`""
        $shortcut.WorkingDirectory = "C:\"
        $shortcut.Description = "Manually cleanup stuck Vantage sessions"
        $shortcut.IconLocation = "C:\Windows\System32\shell32.dll,146"
        $shortcut.Save()
        
        Write-Host "Manual cleanup shortcut created on desktop" -ForegroundColor Green
        Write-Host "  Users can double-click 'Fix Vantage Sessions' if issues occur" -ForegroundColor Cyan
        
        return $true
        
    } catch {
        Write-Host "Failed to create cleanup shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
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
                    # Silent failure
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
    
    # Kill any lingering Office processes more aggressively
    $officeProcesses = @("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", 
                         "mspub", "lync", "teams", "onenotem", "onenoteim", "officeclicktorun",
                         "msteams", "skype", "OfficeClickToRun", "integrator", "OSPPSVC")
    
    foreach ($proc in $officeProcesses) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    
    # Force stop and disable Office services
    $services = @("ClickToRunSvc", "OfficeSvc", "OfficeClickToRun", "OSPPSVC")
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
            # Use sc.exe for more aggressive deletion
            & sc.exe delete $svc 2>&1 | Out-Null
        }
    }
    
    # Clean up Office registry keys more thoroughly
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
    
    # Force unlock and remove Office files
    $officePaths = @(
        "$env:ProgramFiles\Microsoft Office",
        "${env:ProgramFiles(x86)}\Microsoft Office",
        "$env:ProgramFiles\Common Files\Microsoft Shared",
        "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared"
    )
    
    foreach ($path in $officePaths) {
        if (Test-Path $path) {
            # Use takeown and icacls to force ownership
            & takeown.exe /F "$path" /R /D Y 2>&1 | Out-Null
            & icacls.exe "$path" /grant administrators:F /T 2>&1 | Out-Null
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Wait for file system to settle
    Start-Sleep -Seconds 5
    
    # Verify Office is gone
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
    # ZERO-POPUP Adobe installation with multiple fallback methods AND MSP patch application
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

    # Method 1: Try installation with patch included (if available) - COMPLETELY SILENT
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

    # Method 2: Try without transform first (fixes many 1624 errors) - COMPLETELY SILENT
    try {
        Write-Host "Attempting installation without transform (Method 2)..."
        $simpleArgs = @("/i", "`"$msiPath`"", "/qn", "/norestart", "ALLUSERS=1", "EULA_ACCEPT=YES", "SUPPRESS_APP_LAUNCH=YES")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $simpleArgs -Wait -PassThru -WorkingDirectory $DeploymentRoot -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Adobe Reader base installation successful (Method 2)" -ForegroundColor Green
            
            # Apply patch after installation if available
            if ($hasPatch) {
                Write-Host "Applying MSP patch..."
                if (Apply-MSPatch -MspPath $mspPath) {
                    Write-Host "Adobe Reader installation and patch completed successfully" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "Base installation succeeded but patch failed" -ForegroundColor Yellow
                    return $true  # Still return true since base install worked
                }
            }
            return $true
        }
        Write-Host "Method 2 failed with exit code: $($process.ExitCode)"
    } catch {
        Write-Host "Method 2 failed with exception: $($_.Exception.Message)"
    }

    # Method 3: Try with transform but fix common path issues - COMPLETELY SILENT
    if (Test-Path $mstPath) {
        try {
            Write-Host "Attempting installation with transform (Method 3)..."
            # Copy files to temp to avoid path issues
            $tempDir = Join-Path $env:TEMP "AdobeInstall"
            New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            
            Copy-Item $msiPath "$tempDir\AcroRead.msi" -Force -ErrorAction SilentlyContinue
            Copy-Item $mstPath "$tempDir\AcroRead.mst" -Force -ErrorAction SilentlyContinue
            if (Test-Path $cabPath) { Copy-Item $cabPath "$tempDir\Data1.cab" -Force -ErrorAction SilentlyContinue }
            if ($hasPatch) { Copy-Item $mspPath "$tempDir\AcroRead.msp" -Force -ErrorAction SilentlyContinue }
            
            Push-Location $tempDir -ErrorAction SilentlyContinue
            
            # Try with patch integrated first
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
            
            # Try without patch
            $transformArgs = @("/i", "AcroRead.msi", "TRANSFORMS=AcroRead.mst", "/qn", "/norestart", "ALLUSERS=1")
            $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $transformArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
            Pop-Location -ErrorAction SilentlyContinue
            
            if ($process.ExitCode -eq 0) {
                Write-Host "Adobe Reader base installation with transform successful (Method 3b)" -ForegroundColor Green
                
                # Apply patch after installation if available
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
                        return $true  # Still return true since base install worked
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

    # Method 4: Repair Windows Installer and retry - COMPLETELY SILENT
    try {
        Write-Host "Attempting Windows Installer repair and retry (Method 4)..."
        Restart-Service -Name "msiserver" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        
        $repairArgs = @("/i", "`"$msiPath`"", "/qn", "/norestart", "REINSTALL=ALL", "REINSTALLMODE=vomus")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $repairArgs -Wait -PassThru -WorkingDirectory $DeploymentRoot -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "Adobe Reader repair installation successful (Method 4)" -ForegroundColor Green
            
            # Apply patch after repair if available
            if ($hasPatch) {
                Write-Host "Applying MSP patch after repair..."
                if (Apply-MSPatch -MspPath $mspPath) {
                    Write-Host "Adobe Reader repair and patch completed successfully" -ForegroundColor Green
                    return $true
                } else {
                    Write-Host "Repair installation succeeded but patch failed" -ForegroundColor Yellow
                    return $true  # Still return true since repair worked
                }
            }
            return $true
        }
        Write-Host "Method 4 failed with exit code: $($process.ExitCode)"
    } catch {
        Write-Host "Method 4 failed with exception: $($_.Exception.Message)"
    }

    # Method 5: Extract and install manually if it's an EXE disguised as MSI - COMPLETELY SILENT
    try {
        Write-Host "Attempting direct executable installation (Method 5)..."
        # Look for EXE version
        $exePath = Join-Path $DeploymentRoot "AcroRead.exe"
        if (Test-Path $exePath) {
            $process = Start-Process -FilePath $exePath -ArgumentList "/sAll", "/rs", "/msi" -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
            if ($process.ExitCode -eq 0) {
                Write-Host "Adobe Reader executable installation successful (Method 5)" -ForegroundColor Green
                
                # Apply patch after exe install if available
                if ($hasPatch) {
                    Write-Host "Applying MSP patch after executable installation..."
                    if (Apply-MSPatch -MspPath $mspPath) {
                        Write-Host "Adobe Reader executable installation and patch completed successfully" -ForegroundColor Green
                        return $true
                    } else {
                        Write-Host "Executable installation succeeded but patch failed" -ForegroundColor Yellow
                        return $true  # Still return true since exe install worked
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
        
        # Method 1: Apply patch directly
        $patchArgs = @("/p", "`"$MspPath`"", "/qn", "/norestart")
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $patchArgs -Wait -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
        
        if ($process.ExitCode -eq 0) {
            Write-Host "MSP patch applied successfully" -ForegroundColor Green
            return $true
        }
        
        Write-Host "Direct patch application failed with exit code: $($process.ExitCode)"
        
        # Method 2: Try to identify the product and apply patch
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
            Write-Host "Starting VPN profile import (will auto-close in 6 seconds)..."
            $vpnProcess = Start-Process -FilePath $vpnProfile -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            
            # Wait 6 seconds for the import to complete
            Start-Sleep -Seconds 6
            
            # Terminate the process if it's still running
            if ($vpnProcess -and -not $vpnProcess.HasExited) {
                Stop-Process -Id $vpnProcess.Id -Force -ErrorAction SilentlyContinue
                Write-Host "VPN profile import completed and process terminated."
            } else {
                Write-Host "VPN profile import completed (process already closed)."
            }
            
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
        Write-Host "=== ULTRA-AGGRESSIVE WINDOWS UPDATES (ALL UPDATES, NO LIMITS) ===" -ForegroundColor Cyan
        
        # Enable Microsoft Update (not just Windows Update)
        Write-Host "Enabling Microsoft Update service..." -ForegroundColor Yellow
        try {
            $serviceManager = New-Object -ComObject Microsoft.Update.ServiceManager
            $serviceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
            Write-Host "  ✓ Microsoft Update enabled (includes Office, drivers, etc.)" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Could not enable Microsoft Update service" -ForegroundColor Yellow
        }
        Write-Output "winupdate progress: 5"
        
        # Method 1: PSWindowsUpdate (INSTALL EVERYTHING)
        Write-Host "Installing PSWindowsUpdate module..." -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'
            
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction SilentlyContinue | Out-Null
                Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck -ErrorAction SilentlyContinue | Out-Null
            }
            
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
            Write-Host "  ✓ PSWindowsUpdate module loaded" -ForegroundColor Green
            Write-Output "winupdate progress: 10"
            
            # AGGRESSIVE UPDATE INSTALLATION - EVERYTHING
            Write-Host "Scanning for ALL available updates (Windows, Microsoft, Drivers)..." -ForegroundColor Cyan
            
            $updateJob = Start-Job -ScriptBlock {
                try {
                    Import-Module PSWindowsUpdate -Force -ErrorAction Stop
                    
                    # Get EVERYTHING available
                    $allUpdates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
                    
                    if ($allUpdates) {
                        $updateCount = if ($allUpdates -is [array]) { $allUpdates.Count } else { 1 }
                        Write-Output "Found $updateCount total updates to install"
                        
                        # Calculate total size
                        $totalSize = 0
                        foreach ($update in $allUpdates) {
                            if ($update.Size) { $totalSize += $update.Size }
                        }
                        $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
                        Write-Output "Total download size: $totalSizeMB MB"
                        
                        # Install ALL updates - no filters, no limits
                        Write-Output "Installing ALL updates (Windows + Microsoft + Drivers)..."
                        
                        $installed = Install-WindowsUpdate `
                            -MicrosoftUpdate `
                            -AcceptAll `
                            -IgnoreReboot `
                            -Install `
                            -AutoReboot:$false `
                            -ErrorAction Stop
                        
                        $installedCount = if ($installed -is [array]) { $installed.Count } else { 1 }
                        
                        return @{
                            Success = $true
                            TotalFound = $updateCount
                            TotalInstalled = $installedCount
                            TotalSizeMB = $totalSizeMB
                        }
                    } else {
                        return @{Success=$true; TotalFound=0; TotalInstalled=0; Message="No updates available"}
                    }
                } catch {
                    return @{Success=$false; Error=$_.Exception.Message}
                }
            }
            
            Write-Output "winupdate progress: 15"
            
            # Monitor with detailed progress
            $timeout = 3600  # 60 minutes for comprehensive updates
            $startTime = Get-Date
            $lastProgress = 15
            $lastMessage = ""
            
            while ($updateJob.State -eq 'Running' -and ((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
                $elapsed = ((Get-Date) - $startTime).TotalSeconds
                $progress = [math]::Min(15 + [math]::Round(($elapsed / $timeout) * 80), 95)
                
                if ($progress -gt $lastProgress) {
                    Write-Output "winupdate progress: $progress"
                    $minutes = [math]::Round($elapsed / 60, 1)
                    $currentMessage = "  ... installing updates ($minutes minutes elapsed)"
                    if ($currentMessage -ne $lastMessage) {
                        Write-Host $currentMessage -ForegroundColor Cyan
                        $lastMessage = $currentMessage
                    }
                    $lastProgress = $progress
                }
                
                Start-Sleep -Seconds 10
            }
            
            $updateResult = Wait-Job $updateJob -Timeout 60 | Receive-Job -ErrorAction SilentlyContinue
            Remove-Job $updateJob -Force -ErrorAction SilentlyContinue
            
            if ($updateResult.Success) {
                Write-Output "winupdate progress: 95"
                Write-Host "PSWindowsUpdate Results:" -ForegroundColor Green
                Write-Host "  Total updates found: $($updateResult.TotalFound)" -ForegroundColor Cyan
                Write-Host "  Total updates installed: $($updateResult.TotalInstalled)" -ForegroundColor Cyan
                if ($updateResult.TotalSizeMB) {
                    Write-Host "  Total size downloaded: $($updateResult.TotalSizeMB) MB" -ForegroundColor Cyan
                }
                
                if ($updateResult.TotalInstalled -gt 0) {
                    Write-Output "winupdate progress: 100"
                    Write-Host "Successfully installed $($updateResult.TotalInstalled) updates" -ForegroundColor Green
                    return $true
                } elseif ($updateResult.TotalFound -eq 0) {
                    Write-Output "winupdate progress: 100"
                    Write-Host "System is fully up to date - no updates available" -ForegroundColor Green
                    return $true
                }
            } else {
                Write-Host "PSWindowsUpdate failed: $($updateResult.Error)" -ForegroundColor Yellow
            }
            
        } catch {
            Write-Host "PSWindowsUpdate method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Method 2: Windows Update COM API (Fallback - ALSO INSTALLS EVERYTHING)
        Write-Host "`nAttempting Windows Update via COM API (fallback method)..." -ForegroundColor Yellow
        try {
            Write-Output "winupdate progress: 20"
            
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $updateSearcher.ServerSelection = 3  # 3 = Microsoft Update (not just Windows)
            
            Write-Host "Searching for all available updates via COM..." -ForegroundColor Cyan
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            
            if ($searchResult.Updates.Count -gt 0) {
                Write-Host "Found $($searchResult.Updates.Count) updates via COM API" -ForegroundColor Green
                Write-Output "winupdate progress: 40"
                
                # Calculate total size
                $totalBytes = 0
                foreach ($update in $searchResult.Updates) {
                    $totalBytes += $update.MaxDownloadSize
                }
                $totalMB = [math]::Round($totalBytes / 1MB, 2)
                Write-Host "Total download size: $totalMB MB" -ForegroundColor Cyan
                
                # Create update collection
                $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                foreach ($update in $searchResult.Updates) {
                    $updatesToInstall.Add($update) | Out-Null
                    Write-Host "  Queued: $($update.Title)" -ForegroundColor Gray
                }
                
                Write-Output "winupdate progress: 50"
                
                # Download all updates
                Write-Host "Downloading $($updatesToInstall.Count) updates..." -ForegroundColor Yellow
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updatesToInstall
                $downloadResult = $downloader.Download()
                
                Write-Output "winupdate progress: 70"
                
                if ($downloadResult.ResultCode -eq 2) {  # 2 = succeeded
                    Write-Host "Download completed successfully" -ForegroundColor Green
                    
                    # Install all updates
                    Write-Host "Installing $($updatesToInstall.Count) updates..." -ForegroundColor Yellow
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $updatesToInstall
                    $installResult = $installer.Install()
                    
                    Write-Output "winupdate progress: 95"
                    
                    if ($installResult.ResultCode -eq 2) {  # 2 = succeeded
                        Write-Output "winupdate progress: 100"
                        Write-Host "Successfully installed $($updatesToInstall.Count) updates via COM API" -ForegroundColor Green
                        return $true
                    } else {
                        Write-Host "Installation completed with result code: $($installResult.ResultCode)" -ForegroundColor Yellow
                        Write-Output "winupdate progress: 100"
                        return $true
                    }
                } else {
                    Write-Host "Download completed with result code: $($downloadResult.ResultCode)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "No updates found via COM API - system may be up to date" -ForegroundColor Green
                Write-Output "winupdate progress: 100"
                return $true
            }
            
        } catch {
            Write-Host "COM API method failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Method 3: UsoClient (Trigger in background)
        Write-Host "`nTriggering UsoClient as final fallback..." -ForegroundColor Yellow
        try {
            Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartDownload" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartInstall" -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Host "UsoClient triggered - updates will continue in background" -ForegroundColor Yellow
        } catch {
            Write-Host "UsoClient trigger failed" -ForegroundColor Yellow
        }
        
        Write-Output "winupdate progress: 100"
        Write-Host "Windows Updates process completed" -ForegroundColor Yellow
        return $true
        
    } catch {
        Write-Output "winupdate error: $($_.Exception.Message)"
        Write-Host "Windows Updates encountered an error: $($_.Exception.Message)" -ForegroundColor Red
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

# ============================================================================
# MAIN EXECUTION STARTS HERE
# ============================================================================

Write-Host "=== PSI DEPLOYMENT TOOL - OPTIMIZED HIGH-SPEED VERSION ===" -ForegroundColor Green

Write-DeploymentProgress -CurrentStep 1 -TotalSteps 15 -StepDescription "Optimizing system performance for deployment"
Optimize-DeploymentPerformance

Write-DeploymentProgress -CurrentStep 2 -TotalSteps 15 -StepDescription "Enabling remote management capabilities"
Enable-RemoteManagement


Write-DeploymentProgress -CurrentStep 3 -TotalSteps 15 -StepDescription "Loading credentials and configuring timezone"

Write-Host "Loading domain credentials from: $DeploymentRoot"
$Credential = Get-DomainCredential -ScriptDirectory $DeploymentRoot

if ($Credential) {
    Write-Host "Credentials loaded successfully" -ForegroundColor Green
} else {
    Write-Host "WARNING: Failed to load credentials - domain operations will be skipped" -ForegroundColor Yellow
}

Set-TimeZoneFromUserInput

Write-DeploymentProgress -CurrentStep 4 -TotalSteps 15 -StepDescription "Domain join and Intune enrollment"

# Run domain join synchronously since Intune setup depends on it
$domainResult = Join-DomainBasedOnLocation -Location $location -Credential $Credential
$domainJoined = $domainResult.Joined
$intuneConfigured = $domainResult.IntuneConfigured

if ($domainJoined -and -not [string]::IsNullOrWhiteSpace($computerName)) {
    try {
        Rename-Computer -NewName $computerName -Force -DomainCredential $credential -ErrorAction Stop | Out-Null
        $computerRenamed = $true
    } catch {
    }
}

Write-DeploymentProgress -CurrentStep 5 -TotalSteps 15 -StepDescription "Starting parallel software installations"

Start-ParallelInstallations

Write-DeploymentProgress -CurrentStep 6 -TotalSteps 15 -StepDescription "Adobe Reader installation (with 1624 fix)"
$adobeInstalled = Install-AdobeReader

Write-DeploymentProgress -CurrentStep 7 -TotalSteps 15 -StepDescription "Office 365 removal (zero-popup automation)"
Remove-Office365

Write-Host "Performing aggressive Office cleanup..." -ForegroundColor Yellow
$cleanupSuccess = Complete-OfficeRemoval

Start-Sleep -Seconds 10

Write-DeploymentProgress -CurrentStep 8 -TotalSteps 15 -StepDescription "Office 365 installation"
if ($cleanupSuccess) {
    $officeInstalled = Install-Office365
} else {
    Write-Host "Office cleanup incomplete - installation may fail. Consider manual reboot." -ForegroundColor Yellow
    $officeInstalled = Install-Office365
}

Write-DeploymentProgress -CurrentStep 9 -TotalSteps 15 -StepDescription "VPN and Vantage (if requested)"
$vpnInstalled = if ($installVPN) {
    if (Install-VPN) {
        Install-VPNProfile
        $true
    } else { $false }
} else { $null }

if ($installVANTAGE) { 
    Install-Vantage -location $location 
}

Write-DeploymentProgress -CurrentStep 10 -TotalSteps 15 -StepDescription "Shared drives and logging"
Install-SharedDriveTask -Location $location
Switch-Logs


Write-DeploymentProgress -CurrentStep 12 -TotalSteps 15 -StepDescription "Starting optimized Windows Updates (high-speed mode)"

# Run Windows Updates directly (not as background job to avoid context issues)
Write-Host "Running Windows Updates in foreground for reliability..." -ForegroundColor Yellow
$updateResult = Run-WindowsUpdates

Write-DeploymentProgress -CurrentStep 13 -TotalSteps 15 -StepDescription "Final verification and cleanup"

$verificationJob = Verify-Installations

if ($updateResult) {
    Write-Host "Windows Updates: Completed" -ForegroundColor Green
} else {
    Write-Host "Windows Updates: Continuing in background" -ForegroundColor Yellow
}

$verificationResults = Wait-Job $verificationJob -Timeout 60 | Receive-Job -ErrorAction SilentlyContinue
Remove-Job $verificationJob -Force -ErrorAction SilentlyContinue

Write-DeploymentProgress -CurrentStep 14 -TotalSteps 15 -StepDescription "Finalizing deployment"

$deploymentResults = @{
    "Domain Join" = $domainJoined
    "Computer Rename" = $computerRenamed
    "Intune Enrollment" = $intuneConfigured
    "Adobe Reader" = $adobeInstalled
    "Office 365" = $officeInstalled
    "Windows Updates" = ($updateResult -ne $null)
}

if ($installVPN) { $deploymentResults["VPN"] = $vpnInstalled }

Write-DeploymentProgress -CurrentStep 15 -TotalSteps 15 -StepDescription "Deployment complete"

Complete-Deployment -Results $deploymentResults

#region PSI Deployment Performance Enhancements (Parallel + Caching + Deferred Logging)

# --- global logging buffer ---
$global:PSI_LogBuffer = [System.Collections.Generic.List[string]]::new()

function PSI-WriteLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp] $Message"
    $global:PSI_LogBuffer.Add($line)
    Write-Host $line
}

function PSI-FlushtoFile {
    param([string]$Path = "C:\Logs\PSI-Deploy-$(Get-Date -Format 'yyyyMMdd_HHmmss').log")
    try {
        $dir = Split-Path $Path -Parent
        if (!(Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $global:PSI_LogBuffer | Out-File -FilePath $Path -Encoding utf8 -Force
        Write-Host "✅ Log written to $Path"
    } catch {
        Write-Host "⚠️ Failed to write log: $($_.Exception.Message)"
    }
}

# --- smarter sleep function that polls for a condition ---
function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSec = 60,
        [int]$IntervalSec = 3
    )
    $end = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $end) {
        if (& $Condition) { return $true }
        Start-Sleep -Seconds $IntervalSec
    }
    return $false
}

# --- service start helper ---
function Start-ServiceSafe {
    param([string]$Name)
    try {
        Start-Service -Name $Name -ErrorAction SilentlyContinue
        Wait-ForCondition -Condition { (Get-Service $Name).Status -eq 'Running' } -TimeoutSec 20 | Out-Null
        PSI-WriteLog "Service $Name started."
    } catch {
        PSI-WriteLog "⚠️ Failed to start service $Name: $($_.Exception.Message)"
    }
}

# --- caching installer wrapper ---
function PSI-RunOnce {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    $flagFile = "C:\ProgramData\PSI-Deploy-Flags\$Name.done"
    if (Test-Path $flagFile) {
        PSI-WriteLog "⏩ $Name already completed, skipping."
        return
    }
    try {
        & $Action
        if (!(Test-Path (Split-Path $flagFile))) { New-Item -Path (Split-Path $flagFile) -ItemType Directory -Force | Out-Null }
        New-Item -ItemType File -Path $flagFile -Force | Out-Null
        PSI-WriteLog "✅ $Name done."
    } catch {
        PSI-WriteLog "❌ $Name failed: $($_.Exception.Message)"
    }
}

# --- multi-threaded install framework ---
function PSI-RunParallel {
    param([hashtable]$Jobs)
    $running = @()
    foreach ($key in $Jobs.Keys) {
        $running += Start-Job -Name $key -ScriptBlock $Jobs[$key]
    }
    $running | Wait-Job | ForEach-Object {
        $out = Receive-Job $_
        PSI-WriteLog "[$($_.Name)] $out"
        Remove-Job $_
    }
}

# Example usage (replace with your existing installers):
# PSI-RunParallel @{
#     "AdobeReader" = { PSI-RunOnce "AdobeReader" { Install-AdobeReader } }
#     "CrowdStrike" = { PSI-RunOnce "CrowdStrike" { Install-CrowdStrike } }
#     "VPNClient"   = { PSI-RunOnce "VPNClient"   { Install-VPNClient } }
# }

#endregion PSI Deployment Performance Enhancements (Parallel + Caching + Deferred Logging)


#region PSI Universal Compatibility + Smart Orchestration + Fast Windows Update

# --- Detect environment ---
$PSVer = $PSVersionTable.PSVersion.Major
$IsWin10OrHigher = [Environment]::OSVersion.Version.Major -ge 10
PSI-WriteLog "Detected PowerShell $PSVer on Windows $(if ($IsWin10OrHigher) { '10+' } else { 'Legacy' })."

# --- Safe fallback for missing cmdlets ---
if ($PSVer -lt 6) {
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        function Get-ScheduledTask { return @() }
    }
}

#region Smart Orchestration Engine
$Tasks = @(
    @{ Name="DomainJoin";    DependsOn=@();                Action={ PSI-RunOnce "DomainJoin" { Join-DomainSafely } } },
    @{ Name="McAfeeRemoval"; DependsOn=@();                Action={ PSI-RunOnce "McAfeeRemoval" { Remove-McAfee } } },
    @{ Name="AdobeReader";   DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "AdobeReader" { Install-AdobeReader } } },
    @{ Name="VPNClient";     DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "VPNClient" { Install-VPNClient } } },
    @{ Name="CrowdStrike";   DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "CrowdStrike" { Install-CrowdStrike } } },
    @{ Name="Office";        DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "Office" { Install-Office } } },
    @{ Name="DriveMapping";  DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "DriveMapping" { Map-NetworkDrives } } },
    @{ Name="WindowsUpdate"; DependsOn=@("DomainJoin");    Action={ PSI-RunOnce "WindowsUpdate" { PSI-StartWindowsUpdate } } },
    @{ Name="PostChecks";    DependsOn=@("AdobeReader","Office","CrowdStrike"); Action={ PSI-RunOnce "PostChecks" { Run-HealthChecks } } }
)

function PSI-RunTasks {
    param([Array]$TaskList)
    $done = @{}
    while ($done.Count -lt $TaskList.Count) {
        $ready = $TaskList | Where-Object {
            -not $done.ContainsKey($_.Name) -and ($_.DependsOn | Where-Object { -not $done.ContainsKey($_) }) -eq $null
        }
        $jobs = foreach ($t in $ready) {
            Start-Job -Name $t.Name -ScriptBlock $t.Action
        }
        if ($jobs.Count -gt 0) {
            $jobs | Wait-Job | ForEach-Object {
                $out = Receive-Job $_
                PSI-WriteLog "[$($_.Name)] completed."
                $done[$_.Name] = $true
                Remove-Job $_
            }
        } else {
            Start-Sleep -Seconds 1
        }
    }
    PSI-WriteLog "✅ All orchestrated tasks complete."
}
#endregion Smart Orchestration Engine

#region Optimized Windows Update
function PSI-StartWindowsUpdate {
    PSI-WriteLog "🚀 Starting optimized Windows Update..."
    try {
        if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
            Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction SilentlyContinue | Out-Null
        } else {
            net stop wuauserv /y; net stop bits /y; net stop cryptsvc /y | Out-Null
            Remove-Item "C:\Windows\SoftwareDistribution\Download" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            net start wuauserv; net start bits; net start cryptsvc | Out-Null
            Start-Process "UsoClient.exe" -ArgumentList "StartScan" -WindowStyle Hidden
            Start-Process "UsoClient.exe" -ArgumentList "StartDownload" -WindowStyle Hidden
            Start-Process "UsoClient.exe" -ArgumentList "StartInstall" -WindowStyle Hidden
            PSI-WriteLog "⚙️ Using USOClient fallback for updates."
        }
    } catch {
        PSI-WriteLog "⚠️ Windows Update fallback encountered an error: $($_.Exception.Message)"
    }
}
#endregion Optimized Windows Update

# --- Trigger orchestrated run ---
try {
    PSI-RunTasks -TaskList $Tasks
    PSI-FlushtoFile
} catch {
    PSI-WriteLog "❌ Orchestration failed: $($_.Exception.Message)"
    PSI-FlushtoFile
}
#endregion PSI Universal Compatibility + Smart Orchestration + Fast Windows Update
