#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
  Windows 11 Privacy
  Covers:
    1) Telemetry (DiagTrack, tasks, minimal firewall blocks)
    2) Ads/Recommendations (Spotlight, suggestions, consumer features)
    3) Microsoft Account nudges/addition (post-OOBE)
    4) Defender cloud features (MAPS, sample submission)
    5) Activity History & Location

  How to run with sufficient permissions:
    1) Press Start, type "PowerShell".
    2) Right-click "Windows PowerShell" or "Windows Terminal" â†’ "Run as administrator".
    3) Optional per-session policy:  Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
    4) Execute:  .\windows_11_privacy.ps1

  Notes:
    - Defender Tamper Protection must be OFF for Defender policy changes.
    - Some toggles are per-user (HKCU). Run for each user if desired.
    - Firewall FQDN rules do not block direct IPs.
#>

# ===========================
# Utility / scaffolding
# ===========================
$ErrorActionPreference = 'Stop'
$FirewallRulePrefix = 'PrivacyBlock-'
$SupportsFqdn = ($null -ne (Get-Command New-NetFirewallRule).Parameters['RemoteFqdn'])
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsMarker = '# PRIVACY-FQDN-BLOCK'

function Write-Info($msg){ Write-Host "[*] $msg" }
function Write-OK($msg){ Write-Host "[OK] $msg" }
function Write-FAIL($msg){ Write-Host "[X]  $msg" -ForegroundColor Red }
function Write-STEP($msg){ Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# ---- Validate user has Admin privs ----
function Test-Admin {
  # Token check + HKLM write test for certainty
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { return $false }
  try{
    $testPath = 'HKLM:\SOFTWARE\_Windows_11_Privacy_AdminTest'
    if (-not (Test-Path $testPath)) { New-Item $testPath -Force | Out-Null }
    New-ItemProperty -Path $testPath -Name 'CanWrite' -PropertyType DWord -Value 1 -Force | Out-Null
    Remove-Item -Path $testPath -Recurse -Force -ErrorAction SilentlyContinue
    return $true
  } catch { return $false }
}

if (-not (Test-Admin)) {
  Write-FAIL "Insufficient permissions. This script requires an elevated PowerShell."
  Write-Host "`nRun as Administrator:"
  Write-Host "  1) Start â†’ type 'PowerShell' â†’ right-click â†’ 'Run as administrator'."
  Write-Host "  2) Optional: Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process"
  Write-Host "  3) Re-run: .\\windows_11_privacy.ps1"
  exit 1
}

# ---- Validate that this is Windows 11 ----
function Is-Win11 {
    try {
        $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $pn    = [string]$os.ProductName
        $build = [int]$os.CurrentBuild      # or [int]$os.CurrentBuildNumber
        $isClient = ($pn -notmatch 'Server')
        return ($isClient -and $build -ge 22000)  # 22000+ == Windows 11
    } catch { return $false }
}

if (-not (Is-Win11)) {
  $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  Write-FAIL "This script is intended only for Windows 11. Detected: $($os.ProductName)"
  exit 1
}

# ---- Pre-change safety utilities ----
function New-PrivacySnapshot {
  $global:SnapshotDir = Join-Path $PSScriptRoot ("Snapshot_{0:yyyyMMdd_HHmmss}" -f (Get-Date))
  New-Item -ItemType Directory -Path $global:SnapshotDir -Force | Out-Null
  Write-Info ("Snapshot directory: {0}" -f $global:SnapshotDir)

  $SvcNames = @('DiagTrack','dmwappushservice','lfsvc')
  $SvcState = foreach($n in $SvcNames){
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if($s){
      $wmi = Get-WmiObject -Class Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
      [pscustomobject]@{ Name=$n; Status=$s.Status; StartType=($wmi.StartMode) }
    }
  }
  $SvcState | ConvertTo-Json | Set-Content (Join-Path $global:SnapshotDir 'services.json')

  $TaskPaths = @(
    '\Microsoft\Windows\Application Experience\',
    '\Microsoft\Windows\Autochk\',
    '\Microsoft\Windows\Customer Experience Improvement Program\',
    '\Microsoft\Windows\DiskDiagnostic\',
    '\Microsoft\Windows\Feedback\Siuf\',
    '\Microsoft\Windows\Windows Error Reporting\'
  )
  $Tasks = foreach($p in $TaskPaths){
    Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue |
      Select-Object TaskPath,TaskName,State
  }
  $Tasks | ConvertTo-Json | Set-Content (Join-Path $global:SnapshotDir 'tasks.json')

  Get-NetFirewallRule -DisplayName 'PrivacyBlock-*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName,Direction,Action,Profile |
    ConvertTo-Json | Set-Content (Join-Path $global:SnapshotDir 'firewall.json')

  try { Get-MpPreference | ConvertTo-Json | Set-Content (Join-Path $global:SnapshotDir 'defender.json') } catch {}

  & reg.exe export "HKLM\SOFTWARE\Policies\Microsoft\Windows" (Join-Path $global:SnapshotDir 'HKLM_Policies_Windows.reg') /y | Out-Null
  & reg.exe export "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" (Join-Path $global:SnapshotDir 'HKCU_ContentDeliveryManager.reg') /y | Out-Null
  & reg.exe export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" (Join-Path $global:SnapshotDir 'HKCU_Explorer_Advanced.reg') /y | Out-Null

  Write-OK "Snapshot captured"
}

function Test-SystemProtection { try { Get-ComputerRestorePoint | Out-Null; return $true } catch { return $false } }
function New-PrivacyRestorePoint {
  try { Checkpoint-Computer -Description "Windows_11_Privacy_PreChange" -RestorePointType "MODIFY_SETTINGS" | Out-Null; Write-OK "System restore point created" }
  catch { Write-FAIL ("Restore point failed: {0}" -f $_.Exception.Message) }
}

function Invoke-Safely {
  param(
    [Parameter(Mandatory=$true)][ScriptBlock]$Action,
    [Parameter(Mandatory=$true)][string]$Description
  )
  try { & $Action; Write-OK $Description; return $true }
  catch { Write-FAIL "$Description :: $($_.Exception.Message)"; return $false }
}

function Set-Reg {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet('String','DWord','QWord')][string]$Type,
    [Parameter(Mandatory=$true)]$Value
  )
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
  New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Remove-RegValue {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if (Test-Path $Path) {
    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $Path -Name $Name -Force
    }
  }
}

function Disable-Svc($Name){
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
    Set-Service -Name $Name -StartupType Disabled
  }
}
function Enable-Svc {
  param([string]$Name,[ValidateSet('Automatic','Manual','Disabled')]$StartupType='Automatic')
  if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
    Set-Service -Name $Name -StartupType $StartupType
    try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}
  }
}

function Disable-TaskPath($TaskPath){
  $tasks = Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
  if ($tasks) { $tasks | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Out-Null } }
}
function Enable-TaskPath($TaskPath){
  $tasks = Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue
  if ($tasks) { $tasks | ForEach-Object { Enable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Out-Null } }
}

function Add-BlockDomain {
  param([Parameter(Mandatory=$true)][string]$Domain)

  if ($SupportsFqdn) {
    $rule = "$FirewallRulePrefix$Domain"
    if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $rule -Direction Outbound -Action Block -Profile Any -RemoteFqdn $Domain | Out-Null
      Write-OK "Firewall FQDN block: $Domain"
    }
  } else {
    if (-not (Test-Path $HostsPath)) { throw "Hosts file not found: $HostsPath" }
    $line4 = "0.0.0.0 $Domain $HostsMarker"
    $line6 = ":: $Domain $HostsMarker"
    $hosts = Get-Content $HostsPath -ErrorAction Stop
    if ($hosts -notcontains $line4) { Add-Content -Path $HostsPath -Value $line4 }
    if ($hosts -notcontains $line6) { Add-Content -Path $HostsPath -Value $line6 }
    Write-OK "Hosts-block: $Domain"
  }
}

function Remove-BlockDomain {
  param([Parameter(Mandatory=$true)][string]$Domain)

  if ($SupportsFqdn) {
    $rule = "$FirewallRulePrefix$Domain"
    $r = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    if ($r) { $r | Remove-NetFirewallRule | Out-Null; Write-OK "Firewall unblocked: $Domain" }
  } else {
    if (Test-Path $HostsPath) {
      $escaped = [regex]::Escape($Domain)
      (Get-Content $HostsPath) |
        Where-Object { $_ -notmatch "^\s*(0\.0\.0\.0|::)\s+$escaped\s+$([regex]::Escape($HostsMarker))\s*$" } |
        Set-Content $HostsPath
      Write-OK "Hosts-unblock: $Domain"
    }
  }
}

function Prompt-YesNo($message, $defaultYes=$true){
  $suffix = if ($defaultYes) { "[Y/n]" } else { "[y/N]" }
  while ($true){
    $resp = Read-Host "$message $suffix"
    if ([string]::IsNullOrWhiteSpace($resp)) { return $defaultYes }
    switch ($resp.Trim().ToLower()){
      'y' { return $true }
      'yes' { return $true }
      'n' { return $false }
      'no' { return $false }
      default { Write-Host "Enter y or n." }
    }
  }
}

function Prompt-BackupChoice {
  Write-STEP "Backup options before applying DISABLE changes"
  Write-Host "  1) Proceed without additional backups"
  Write-Host "  2) Enable snapshot backup"
  Write-Host "  3) Enable system restore point (System Protection MUST be enabled)"
  Write-Host "  4) Enable both snapshot and system restore point"
  while ($true) {
    $choice = Read-Host "Select 1-4"
    if ($choice -in @('1','2','3','4')) { return $choice }
  }
}


# ===========================
# Optional transcript
# ===========================
if (Prompt-YesNo "Start transcript logging to .\\Windows_11_Privacy.log?" $false) {
  try { Start-Transcript -Path "$PSScriptRoot\Windows_11_Privacy.log" -Append | Out-Null } catch { Write-FAIL "Transcript failed: $($_.Exception.Message)" }
}


# ===========================
# Defender detection / tamper status
# ===========================
$DefenderAvailable = $false
$DefenderTamperOn = $false
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  $DefenderAvailable = $true
  if ($mp.IsTamperProtected) { $DefenderTamperOn = $true }
} catch {}
if ($DefenderAvailable -and $DefenderTamperOn) {
  Write-FAIL "Defender Tamper Protection is ON. Disable it: Windows Security â†’ Virus & threat protection â†’ Manage settings."
}


# ===========================
# Mode selection
# ===========================
Write-STEP "Mode selection"

function Select-Mode {
    while ($true) {
        $resp = Read-Host "Apply DISABLE-hardening settings? Choose No to ENABLE/undo them. Or Q to Quit [Y/n/q]"
        if ([string]::IsNullOrWhiteSpace($resp)) {
            Write-Info "Mode: DISABLE (harden/strip)."
            return $true
        }
        switch ($resp.Trim().ToLower()) {
            'y' { Write-Info "Mode: DISABLE (harden/strip)."; return $true }
            'yes' { Write-Info "Mode: DISABLE (harden/strip)."; return $true }
            'n' { Write-Info "Mode: ENABLE (restore/default)."; return $false }
            'no' { Write-Info "Mode: ENABLE (restore/default)."; return $false }
            'q' { Write-FAIL "User chose to quit."; exit 0 }
            'quit' { Write-FAIL "User chose to quit."; exit 0 }
            default { Write-Host "Enter y, n, or q." }
        }
    }
}

$modeDisable = Select-Mode


# ===========================
# Telemetry
# ===========================
$TelemetryHosts = @(
  'v10.events.data.microsoft.com',
  'settings-win.data.microsoft.com',
  'vortex-win.data.microsoft.com'
)

function Telemetry-Disable {
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'DWord' 0 } "Policy: AllowTelemetry=0"
  Invoke-Safely { Disable-Svc 'DiagTrack' } "Service: DiagTrack disabled"
  Invoke-Safely { Disable-Svc 'dmwappushservice' } "Service: dmwappushservice disabled (if present)"
  # Task paths (silently ignore if missing)
  foreach($p in '\Microsoft\Windows\Application Experience\',
                 '\Microsoft\Windows\Autochk\',
                 '\Microsoft\Windows\Customer Experience Improvement Program\',
                 '\Microsoft\Windows\DiskDiagnostic\',
                 '\Microsoft\Windows\Feedback\Siuf\',
                 '\Microsoft\Windows\Windows Error Reporting\'){
    Invoke-Safely { Disable-TaskPath $p } "Tasks disabled: $p"
  }
  # Explicit CEIP Consolidator
  Invoke-Safely { Disable-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Customer Experience Improvement Program\\' -TaskName 'Consolidator' -ErrorAction SilentlyContinue | Out-Null } "Task disabled: CEIP Consolidator"
  foreach($h in $TelemetryHosts){ Invoke-Safely { Add-BlockDomain $h } "Firewall block: $h" }
  # Optional: WER policy off
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' 'Disabled' 'DWord' 1 } "Policy: Windows Error Reporting disabled"
}

function Telemetry-Enable {
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' 'DWord' 1 } "Policy: AllowTelemetry=1"
  Invoke-Safely { Enable-Svc 'DiagTrack' 'Automatic' } "Service: DiagTrack enabled"
  Invoke-Safely { Enable-Svc 'dmwappushservice' 'Manual' } "Service: dmwappushservice enabled (if present)"
  foreach($p in '\Microsoft\Windows\Application Experience\',
                 '\Microsoft\Windows\Autochk\',
                 '\Microsoft\Windows\Customer Experience Improvement Program\',
                 '\Microsoft\Windows\DiskDiagnostic\',
                 '\Microsoft\Windows\Feedback\Siuf\',
                 '\Microsoft\Windows\Windows Error Reporting\'){
    Invoke-Safely { Enable-TaskPath $p } "Tasks enabled: $p"
  }
  Invoke-Safely { Enable-ScheduledTask -TaskPath '\\Microsoft\\Windows\\Customer Experience Improvement Program\\' -TaskName 'Consolidator' -ErrorAction SilentlyContinue | Out-Null } "Task enabled: CEIP Consolidator"
  foreach($h in $TelemetryHosts){ Invoke-Safely { Remove-BlockDomain $h } "Firewall unblocked: $h" }
  # Clear WER policy
  Invoke-Safely { Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Recurse -Force -ErrorAction SilentlyContinue } "Policy cleared: Windows Error Reporting"
}


# ===========================
# Ads / Recommendations
# ===========================
function Ads-Disable {
  # System-wide Spotlight and consumer features
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightFeatures' 'DWord' 1 } "Spotlight features disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsSpotlightOnSettings' 'DWord' 1 } "Spotlight in Settings disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableConsumerFeatures' 'DWord' 1 } "Consumer features disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableSoftLanding' 'DWord' 1 } "SoftLanding upsell disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableAccountNotifications' 'DWord' 1 } "Account notifications disabled"
  # Per-user Start/Lock suggestions
  $cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
  Invoke-Safely { Set-Reg $cdm 'SubscribedContent-310093Enabled' 'DWord' 0 } "Start suggestions off"
  Invoke-Safely { Set-Reg $cdm 'SubscribedContent-338388Enabled' 'DWord' 0 } "Settings suggestions off"
  Invoke-Safely { Set-Reg $cdm 'SubscribedContent-353694Enabled' 'DWord' 0 } "Lock screen suggestions off"
  Invoke-Safely { Set-Reg $cdm 'SubscribedContent-314559Enabled' 'DWord' 0 } "Spotlight feeds off"
  Invoke-Safely { Set-Reg $cdm 'SilentInstalledAppsEnabled' 'DWord' 0 } "Silent app installs off"
  Invoke-Safely { Set-Reg $cdm 'SystemPaneSuggestionsEnabled' 'DWord' 0 } "System pane suggestions off"
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_IrisRecommendations' 'DWord' 0 } "Start 'Recommended' off"
  Invoke-Safely { Set-Reg $cdm 'ContentDeliveryAllowed' 'DWord' 0 } "ContentDelivery off"
  Invoke-Safely { Set-Reg $cdm 'RotatingLockScreenEnabled' 'DWord' 0 } "Lock Spotlight off"
  Invoke-Safely { Set-Reg $cdm 'RotatingLockScreenOverlayEnabled' 'DWord' 0 } "Lock Spotlight overlays off"
}

function Ads-Enable {
  foreach($name in 'DisableWindowsSpotlightFeatures','DisableWindowsSpotlightOnSettings','DisableConsumerFeatures','DisableSoftLanding','DisableAccountNotifications'){
    Invoke-Safely { Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' $name } "Policy cleared: $name"
  }
  $cdm = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
  Invoke-Safely { Set-Reg $cdm 'ContentDeliveryAllowed' 'DWord' 1 } "ContentDelivery on"
  foreach($name in 'SubscribedContent-310093Enabled','SubscribedContent-338388Enabled','SubscribedContent-353694Enabled','SubscribedContent-314559Enabled','SilentInstalledAppsEnabled','SystemPaneSuggestionsEnabled','RotatingLockScreenEnabled','RotatingLockScreenOverlayEnabled'){
    Invoke-Safely { Set-Reg $cdm $name 'DWord' 1 } "Enable: $name"
  }
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Start_IrisRecommendations' 'DWord' 1 } "Start 'Recommended' on"
}

function Maybe-RestartExplorer {
  if (Prompt-YesNo "Restart Explorer to apply Start/Lock changes now?" $false) {
    try { Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force } catch {}
    Start-Process explorer.exe
    Write-OK "Explorer restarted"
  }
}


# ===========================
# Microsoft Account (MSA) requirement prompts/nudges
# ===========================
function MSA-Disable {
  $strict = 1
  if (Prompt-YesNo "Use STRICT block for Microsoft Accounts (value=3)? Standard block is 1." $false) { $strict = 3 }
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'NoConnectedUser' 'DWord' $strict } "Block adding MSA (NoConnectedUser=$strict)"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount' 'DisableUserAuth' 'DWord' 1 } "Disable MSA auth (policy)"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount' 'DisableMSA' 'DWord' 1 } "Disable MSA (legacy policy)"
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' 'DWord' 0 } "SCOOBE upsell off"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableAccountNotifications' 'DWord' 1 } "Account notifications off"
}
function MSA-Enable {
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'NoConnectedUser' 'DWord' 0 } "Allow adding MSA"
  foreach($kv in @('DisableUserAuth','DisableMSA')){
    Invoke-Safely { Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount' $kv } "Policy cleared: $kv"
  }
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement' 'ScoobeSystemSettingEnabled' 'DWord' 1 } "SCOOBE upsell on"
  Invoke-Safely { Remove-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableAccountNotifications' } "Account notifications policy cleared"
}


# ===========================
# Defender cloud features
# ===========================
function Defender-Disable {
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SpynetReporting' 'DWord' 0 } "Policy: MAPS off"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent' 'DWord' 2 } "Policy: Sample submission never"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' 'MpCloudBlockLevel' 'DWord' 0 } "Policy: Cloud block minimal"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection' 'DWord' 1 } "Policy: PUA protection ON"
  if ($DefenderAvailable -and -not $DefenderTamperOn -and ($mp.AMServiceEnabled)) {
    Invoke-Safely { Set-MpPreference -MAPSReporting 0 -SubmitSamplesConsent 2 -CloudBlockLevel 0 } "Defender prefs set (MAPS off, no samples)"
  } else {
    Write-Info "Defender not active or tamper on; skipping Set-MpPreference."
  }
}
function Defender-Enable {
  foreach($p in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet','HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine')){
    Invoke-Safely { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue } "Policies cleared: $p"
  }
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection' 'DWord' 1 } "Policy: PUA protection ON"
  if ($DefenderAvailable -and -not $DefenderTamperOn -and ($mp.AMServiceEnabled)) {
    Invoke-Safely { Set-MpPreference -MAPSReporting 2 -SubmitSamplesConsent 1 -CloudBlockLevel 2 } "Defender prefs set (MAPS Advanced, send safe samples)"
  } else {
    Write-Info "Defender not active or tamper on; skipping Set-MpPreference."
  }
}


# ===========================
# Activity History & Location
# ===========================
function ActivityLocation-Disable {
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableActivityFeed' 'DWord' 0 } "Activity Feed disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'PublishUserActivities' 'DWord' 0 } "Publish activities disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'UploadUserActivities' 'DWord' 0 } "Upload activities disabled"
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation' 'DWord' 1 } "Location disabled (policy)"
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'String' 'Deny' } "Per-user location consent: Deny"
  Invoke-Safely { Disable-Svc 'lfsvc' } "Geolocation service disabled"
}
function ActivityLocation-Enable {
  foreach($kv in @('EnableActivityFeed','PublishUserActivities','UploadUserActivities')){
    Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' $kv 'DWord' 1 } "Activity policy enabled: $kv"
  }
  Invoke-Safely { Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' 'DisableLocation' 'DWord' 0 } "Location policy enabled"
  Invoke-Safely { Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' 'Value' 'String' 'Allow' } "Per-user location consent: Allow"
  Invoke-Safely { Enable-Svc 'lfsvc' 'Manual' } "Geolocation service enabled (Manual)"
}


# ---- If disabling features, offer additional backup options ----
if ($modeDisable) {
  Write-Info "Although ENABLE can revert most changes, additional safety options are available: snapshot and system restore."
  $bk = Prompt-BackupChoice
  switch ($bk) {
    '1' { Write-Info "Proceeding without additional backups." }
    '2' { New-PrivacySnapshot }
    '3' {
      if (Test-SystemProtection) {
        New-PrivacyRestorePoint
      } else {
        Write-FAIL "System Protection appears disabled."
        if (Prompt-YesNo "Proceed without a restore point?" $true) { Write-Info "Continuing without restore point." } else { Write-FAIL "Aborting per user choice."; exit 1 }
      }
    }
    '4' {
      New-PrivacySnapshot
      if (Test-SystemProtection) {
        New-PrivacyRestorePoint
      } else {
        Write-FAIL "System Protection appears disabled."
        if (Prompt-YesNo "Proceed without a restore point?" $true) { Write-Info "Continuing without restore point." } else { Write-FAIL "Aborting per user choice."; exit 1 }
      }
    }
  }
}


# ===========================
# Step runner
# ===========================
function Run-Step {
  param(
    [string]$Title,
    [ScriptBlock]$DisableAction,
    [ScriptBlock]$EnableAction,
    [bool]$DefaultApply = $true,
    [switch]$AfterAdsRestart
  )
  Write-STEP $Title
  $apply = Prompt-YesNo "Apply this step now?" $DefaultApply
  if (-not $apply) { Write-Info "Skipped: $Title"; return }
  if ($modeDisable) {
    & $DisableAction
  } else {
    & $EnableAction
  }
  if ($AfterAdsRestart) { Maybe-RestartExplorer }
}


# ===========================
# Execute
# ===========================
Run-Step -Title "1) Telemetry: DiagTrack, tasks, minimal firewall blocks" -DisableAction { Telemetry-Disable } -EnableAction { Telemetry-Enable }
Run-Step -Title "2) Ads / Recommendations: Start menu, lock screen, Settings banners" -DisableAction { Ads-Disable } -EnableAction { Ads-Enable } -AfterAdsRestart
Run-Step -Title "3) Microsoft Account prompts/addition: OOBE and post-setup nudges" -DisableAction { MSA-Disable } -EnableAction { MSA-Enable }
Run-Step -Title "4) Defender cloud features: MAPS, sample submission" -DisableAction { Defender-Disable } -EnableAction { Defender-Enable }
Run-Step -Title "5) Activity History & Location: Timeline, global location service" -DisableAction { ActivityLocation-Disable } -EnableAction { ActivityLocation-Enable }

Write-STEP "Completed successfully."
Write-Info ("Mode: {0}" -f ($(if($modeDisable){'DISABLE'} else {'ENABLE'})))
Write-Info "Some changes require sign-out or reboot to take effect."
try { Stop-Transcript | Out-Null } catch {}
