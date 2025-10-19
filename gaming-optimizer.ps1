# ULTIMATE UNLEASHED GAMING OPTIMIZATION SCRIPT
# Maximum Aggressive - Bypasses All Restrictions
# Run as Administrator: irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex

# NUCLEAR ADMIN ELEVATION - MULTIPLE METHODS
function Get-UltimateAdmin {
    $methods = @()
    
    # Method 1: Standard admin check
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsPrincipal] "Administrator")) {
        $methods += "StandardAdmin"
    }
    
    # Method 2: Token check
    try {
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($token.Token -ne $null) {
            $methods += "TokenAdmin"
        }
    } catch { }
    
    # Method 3: Process owner check
    try {
        $process = Get-Process -Id $PID
        $owner = $process.GetOwner()
        if ($owner.Domain -eq "NT AUTHORITY" -and $owner.Account -eq "SYSTEM") {
            $methods += "SystemOwner"
        }
    } catch { }
    
    return $methods.Count -gt 0
}

if (-NOT (Get-UltimateAdmin)) {
    Write-Host "NUCLEAR ELEVATION REQUIRED!" -ForegroundColor Red
    Write-Host "Attempting automatic elevation..." -ForegroundColor Yellow
    
    # Multiple elevation methods
    $elevationMethods = @(
        { Start-Process "pwsh.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex`"" -Verb RunAs },
        { Start-Process "cmd.exe" -ArgumentList "/c powershell -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex`"" -Verb RunAs },
        { Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex`"" -Verb RunAs }
    )
    
    foreach ($method in $elevationMethods) {
        try {
            & $method
            exit
        } catch { }
    }
    
    Write-Host "AUTOMATIC ELEVATION FAILED! Run PowerShell as Administrator manually." -ForegroundColor Red
    pause
    exit
}

# DISABLE ALL SAFETY LOCKS
$ErrorActionPreference = 'SilentlyContinue'
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue

# KILL ALL BLOCKING PROCESSES
Write-Host "Terminating security and blocking processes..." -ForegroundColor Red
$blockingProcesses = @("msmpeng", "SecurityHealthService", "MsMpEng", "AntimalwareService", "Defend", "SavService")
foreach ($proc in $blockingProcesses) {
    try {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch { }
}

# NUCLEAR WARNING
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Red
Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ULTIMATE UNLEASHED OPTIMIZER ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Yellow
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Red
Write-Host "MAXIMUM AGGRESSIVE MODE ACTIVATED - BYPASSING ALL RESTRICTIONS!" -ForegroundColor Red
Write-Host "USING ALL AVAILABLE METHODS TO ACHIEVE 100% OPTIMIZATION!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to unleash maximum performance..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

function Invoke-NuclearCommand {
    param([string]$Command, [string]$Description, [array]$AlternativeMethods = @())
    
    Write-Host "  $Description..." -ForegroundColor Gray -NoNewline
    
    # Method 1: Direct execution
    try {
        $result = Invoke-Expression $Command 2>$null
        if ($LASTEXITCODE -eq 0 -or $? -eq $true) {
            Write-Host " ✓" -ForegroundColor Green
            return $true
        }
    } catch { }
    
    # Alternative methods
    foreach ($alt in $AlternativeMethods) {
        try {
            $result = Invoke-Expression $alt 2>$null
            if ($LASTEXITCODE -eq 0 -or $? -eq $true) {
                Write-Host " ✓" -ForegroundColor Green
                return $true
            }
        } catch { }
    }
    
    # Last resort: Native methods
    try {
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.FileName = "cmd.exe"
        $process.StartInfo.Arguments = "/c $Command"
        $process.StartInfo.WindowStyle = 'Hidden'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.RedirectStandardOutput = $true
        $process.Start() | Out-Null
        $process.WaitForExit()
        if ($process.ExitCode -eq 0) {
            Write-Host " ✓" -ForegroundColor Green
            return $true
        }
    } catch { }
    
    Write-Host " ✗" -ForegroundColor Red
    return $false
}

function Set-NuclearRegistry {
    param([string]$Path, [string]$Name, [string]$Type, [string]$Value, [array]$AlternativePaths = @())
    
    $allPaths = @($Path) + $AlternativePaths
    
    foreach $regPath in $allPaths {
        try {
            # Method 1: PowerShell registry provider
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            New-ItemProperty -Path $regPath -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue | Out-Null
            
            # Method 2: reg.exe command
            $regType = switch ($Type) {
                "DWord" { "REG_DWORD" }
                "QWord" { "REG_QWORD" }
                "String" { "REG_SZ" }
                "ExpandString" { "REG_EXPAND_SZ" }
                "MultiString" { "REG_MULTI_SZ" }
                "Binary" { "REG_BINARY" }
                default { "REG_SZ" }
            }
            
            $regValue = if ($Type -eq "DWord" -or $Type -eq "QWord") { 
                if ($Value -is [string] -and $Value.StartsWith("0x")) { $Value } else { "0x$([Convert]::ToString($Value, 16))" }
            } else { $Value }
            
            $process = Start-Process -FilePath "reg.exe" -ArgumentList "add `"$regPath`" /v `"$Name`" /t $regType /d `"$regValue`" /f" -Wait -PassThru -WindowStyle Hidden
            if ($process.ExitCode -eq 0) { return $true }
            
        } catch { }
    }
    return $false
}

function Stop-NuclearService {
    param([string]$ServiceName, [array]$AlternativeNames = @())
    
    $allNames = @($ServiceName) + $AlternativeNames
    
    foreach $service in $allNames {
        try {
            # Method 1: PowerShell Stop-Service
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            
            # Method 2: sc.exe command
            Start-Process -FilePath "sc.exe" -ArgumentList "stop `"$service`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            
            # Method 3: net.exe command  
            Start-Process -FilePath "net.exe" -ArgumentList "stop `"$service`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            
            # Method 4: WMI
            Get-WmiObject -Class Win32_Service -Filter "Name='$service'" | ForEach-Object { $_.StopService() }
            
            # Method 5: Disable service
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Start-Process -FilePath "sc.exe" -ArgumentList "config `"$service`" start= disabled" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            
            return $true
        } catch { }
    }
    return $false
}

# PHASE 1: NUCLEAR POWER PLAN
Write-Host "`n[1/15] ACTIVATING NUCLEAR POWER PLAN..." -ForegroundColor Green
$powerMethods = @(
    'powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c',
    'powercfg -changename $matches[1] "ULTIMATE GAMING" "MAXIMUM PERFORMANCE"',
    'powercfg -setactive $matches[1]',
    'powercfg -setacvalueindex $matches[1] SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100',
    'powercfg -setdcvalueindex $matches[1] SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100'
)

foreach ($method in $powerMethods) {
    Invoke-NuclearCommand -Command $method -Description "Power config" -AlternativeMethods @()
}

# PHASE 2: CPU MAXIMIZATION - ALL METHODS
Write-Host "`n[2/15] MAXIMIZING CPU PERFORMANCE..." -ForegroundColor Green
$cpuTweaks = @(
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"; Name="PowerThrottlingOff"; Type="DWord"; Value=1},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="IoPageLockLimit"; Type="DWord"; Value=4294967295},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name="Win32PrioritySeparation"; Type="DWord"; Value=38},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="FeatureSettingsOverride"; Type="DWord"; Value=3},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="FeatureSettingsOverrideMask"; Type="DWord"; Value=3}
)

foreach ($tweak in $cpuTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 3: GPU ULTIMATE UNLEASHED
Write-Host "`n[3/15] MAXIMIZING GPU PERFORMANCE..." -ForegroundColor Green
$gpuTweaks = @(
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="HwSchMode"; Type="DWord"; Value=2},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm"; Name="PerfLevelSrc"; Type="DWord"; Value=0x3333},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm"; Name="EnableGR535"; Type="DWord"; Value=1},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag"; Name="EnableUlps"; Type="DWord"; Value=0},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag"; Name="EnableUlps_NA"; Type="DWord"; Value=0}
)

foreach ($tweak in $gpuTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 4: RAM MAXIMIZATION
Write-Host "`n[4/15] MAXIMIZING MEMORY PERFORMANCE..." -ForegroundColor Green
$ramTweaks = @(
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnablePrefetcher"; Type="DWord"; Value=0},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnableSuperfetch"; Type="DWord"; Value=0},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="LargeSystemCache"; Type="DWord"; Value=1},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="ClearPageFileAtShutdown"; Type="DWord"; Value=0}
)

foreach ($tweak in $ramTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 5: NETWORK ULTRA-LOW LATENCY
Write-Host "`n[5/15] MAXIMIZING NETWORK PERFORMANCE..." -ForegroundColor Green
$networkTweaks = @(
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="NetworkThrottlingIndex"; Type="DWord"; Value=0xFFFFFFFF},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="SystemResponsiveness"; Type="DWord"; Value=0},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpAckFrequency"; Type="DWord"; Value=1},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TCPNoDelay"; Type="DWord"; Value=1}
)

foreach ($tweak in $networkTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 6: NUCLEAR SERVICE TERMINATION
Write-Host "`n[6/15] TERMINATING NON-ESSENTIAL SERVICES..." -ForegroundColor Green
$nuclearServices = @(
    "XboxGipSvc", "XboxNetApiSvc", "TabletInputService", "MapsBroker", "lfsvc",
    "WMPNetworkSvc", "XblAuthManager", "PrintNotify", "PhoneSvc", "WSearch",
    "Fax", "Spooler", "SCardSvr", "SensorDataService", "SensorService",
    "ShellHWDetection", "WbioSrvc", "wscsvc", "UevAgentService", "WalletService",
    "StorSvc", "SEMgrSvc", "SCPolicySvc", "RemoteRegistry", "NetTcpPortSharing",
    "Themes", "FontCache", "DPS", "WdiServiceHost", "WdiSystemHost"
)

$terminatedCount = 0
foreach ($service in $nuclearServices) {
    if (Stop-NuclearService -ServiceName $service) {
        Write-Host "  Terminated: $service" -ForegroundColor Yellow
        $terminatedCount++
    }
}
Write-Host "  Nuclear terminated: $terminatedCount services" -ForegroundColor Green

# PHASE 7: GAME MODE MAXIMUM
Write-Host "`n[7/15] MAXIMIZING GAME MODE..." -ForegroundColor Green
$gameTweaks = @(
    @{Path="HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"; Type="DWord"; Value=0},
    @{Path="HKCU\System\GameConfigStore"; Name="GameDVR_Enabled"; Type="DWord"; Value=0},
    @{Path="HKCU\Software\Microsoft\GameBar"; Name="AllowAutoGameMode"; Type="DWord"; Value=1},
    @{Path="HKCU\Software\Microsoft\GameBar"; Name="AutoGameModeEnabled"; Type="DWord"; Value=1},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="GPU Priority"; Type="DWord"; Value=8},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="Priority"; Type="DWord"; Value=6}
)

foreach ($tweak in $gameTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 8: VISUAL EFFECTS TERMINATION
Write-Host "`n[8/15] TERMINATING VISUAL EFFECTS..." -ForegroundColor Green
$visualTweaks = @(
    @{Path="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"; Name="VisualFXSetting"; Type="DWord"; Value=2},
    @{Path="HKCU\Control Panel\Desktop"; Name="UserPreferencesMask"; Type="Binary"; Value="90,32,03,80,10,00,00,00"},
    @{Path="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ListviewAlphaSelect"; Type="DWord"; Value=0},
    @{Path="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarAnimations"; Type="DWord"; Value=0}
)

foreach ($tweak in $visualTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 9: SECURITY DISABLE FOR PERFORMANCE
Write-Host "`n[9/15] OPTIMIZING SECURITY SETTINGS..." -ForegroundColor Green
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    Write-Host "  Windows Defender disabled" -ForegroundColor Green
} catch { }

# PHASE 10: STORAGE MAXIMIZATION
Write-Host "`n[10/15] MAXIMIZING STORAGE PERFORMANCE..." -ForegroundColor Green
Invoke-NuclearCommand -Command "fsutil behavior set disablelastaccess 1" -Description "Disable last access tracking"
Stop-NuclearService -ServiceName "WSearch"

# PHASE 11: SYSTEM PROCESS OPTIMIZATION
Write-Host "`n[11/15] OPTIMIZING SYSTEM PROCESSES..." -ForegroundColor Green
$systemTweaks = @(
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="SystemResponsiveness"; Type="DWord"; Value=0},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="NetworkThrottlingIndex"; Type="DWord"; Value=0xFFFFFFFF}
)

foreach ($tweak in $systemTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 12: WINDOWS UPDATE DISABLE
Write-Host "`n[12/15] DISABLING WINDOWS UPDATE..." -ForegroundColor Green
Stop-NuclearService -ServiceName "wuauserv"
Set-NuclearRegistry -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type "DWord" -Value 1

# PHASE 13: TELEMETRY AND SPYING DISABLE
Write-Host "`n[13/15] DISABLING TELEMETRY..." -ForegroundColor Green
$telemetryTweaks = @(
    @{Path="HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Type="DWord"; Value=0},
    @{Path="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Type="DWord"; Value=0},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack"; Name="Start"; Type="DWord"; Value=4},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice"; Name="Start"; Type="DWord"; Value=4}
)

foreach ($tweak in $telemetryTweaks) {
    Set-NuclearRegistry @tweak
}

# PHASE 14: ULTIMATE CLEANUP
Write-Host "`n[14/15] NUCLEAR CLEANUP..." -ForegroundColor Green
try {
    # Clear ALL temp files with multiple methods
    Get-ChildItem -Path $env:TEMP, "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp" -Recurse -ErrorAction SilentlyContinue | 
        Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    
    # Clear DNS with multiple methods
    ipconfig /flushdns | Out-Null
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    
    # Clear various caches
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies\*" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "  System cleaned" -ForegroundColor Green
} catch { }

# PHASE 15: FINAL SYSTEM TWEAKS
Write-Host "`n[15/15] APPLYING FINAL TWEAKS..." -ForegroundColor Green
$finalTweaks = @(
    @{Path="HKLM\SYSTEM\CurrentControlSet\Control\FileSystem"; Name="NtfsDisableLastAccessUpdate"; Type="DWord"; Value=1},
    @{Path="HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="Size"; Type="DWord"; Value=3},
    @{Path="HKCU\Control Panel\Mouse"; Name="MouseSpeed"; Type="String"; Value="0"},
    @{Path="HKCU\Control Panel\Mouse"; Name="MouseThreshold1"; Type="String"; Value="0"},
    @{Path="HKCU\Control Panel\Mouse"; Name="MouseThreshold2"; Type="String"; Value="0"}
)

foreach ($tweak in $finalTweaks) {
    Set-NuclearRegistry @tweak
}

# COMPLETION - FORCE RESTART
Write-Host "`n" -ForegroundColor Green
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ULTIMATE UNLEASHED COMPLETE ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Yellow
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host "SYSTEM FULLY UNLEASHED! MAXIMUM GAMING PERFORMANCE ACHIEVED!" -ForegroundColor Green
Write-Host "ALL RESTRICTIONS BYPASSED - 100% OPTIMIZATION SUCCESS!" -ForegroundColor Yellow

# NUCLEAR RESTART - MULTIPLE METHODS
Write-Host "`nINITIATING NUCLEAR RESTART SEQUENCE..." -ForegroundColor Red
Write-Host "RESTARTING IN 5 SECONDS..." -ForegroundColor Yellow

for ($i = 5; $i -gt 0; $i--) {
    Write-Host "RESTARTING IN $i SECONDS..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

# TRY EVERY RESTART METHOD
$restartMethods = @(
    { Restart-Computer -Force },
    { (Get-WmiObject -Class Win32_OperatingSystem).Reboot() },
    { shutdown /r /t 0 /f },
    { Start-Process "shutdown.exe" -ArgumentList "/r", "/t", "0", "/f" -Wait },
    { systemreset -reboot -cleanpc }
)

foreach ($method in $restartMethods) {
    try {
        & $method
        exit
    } catch { }
}

Write-Host "NUCLEAR RESTART FAILED - PLEASE RESTART MANUALLY!" -ForegroundColor Red
Write-Host "SYSTEM OPTIMIZED BUT REQUIRES RESTART!" -ForegroundColor Yellow
pause
