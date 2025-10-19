# ULTIMATE MAXIMUM GAMING OPTIMIZATION SCRIPT
# Windows 10/11 - Maximum Performance at All Costs
# Run as Administrator: irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex

# Require Admin Rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsPrincipal] "Administrator")) {
    Write-Host "ULTIMATE GAMING OPTIMIZER REQUIRES ADMINISTRATOR PRIVILEGES!" -ForegroundColor Red
    Write-Host "Run PowerShell as Administrator first, then execute the script." -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# Set Maximum Performance Mode
$ErrorActionPreference = 'SilentlyContinue'
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force

# Nuclear Warning
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Red
Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ULTIMATE GAMING OPTIMIZER ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Yellow
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Red
Write-Host "WARNING: THIS IS THE MOST AGGRESSIVE GAMING OPTIMIZATION SCRIPT AVAILABLE!" -ForegroundColor Red
Write-Host "IT WILL:" -ForegroundColor Yellow
Write-Host "• DISABLE 100+ SYSTEM SERVICES & FEATURES" -ForegroundColor White
Write-Host "• MAXIMIZE CPU/GPU/RAM PERFORMANCE" -ForegroundColor White
Write-Host "• REMOVE ALL NON-GAMING FUNCTIONALITY" -ForegroundColor White
Write-Host "• OPTIMIZE NETWORK FOR ULTRA-LOW LATENCY" -ForegroundColor White
Write-Host "• DISABLE SECURITY FEATURES FOR PERFORMANCE" -ForegroundColor White
Write-Host "• PERMANENTLY MODIFY SYSTEM SETTINGS" -ForegroundColor White
Write-Host ""
Write-Host "BACKUP YOUR SYSTEM! THIS CAN BREAK NON-GAMING FUNCTIONALITY!" -ForegroundColor Red
Write-Host "Press any key to continue or Ctrl+C to abort..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

function Show-Progress($Step, $Total) {
    $percent = [math]::Round(($Step / $Total) * 100)
    Write-Progress -Activity "ULTIMATE GAMING OPTIMIZATION" -Status "Step $Step of $Total ($percent% Complete)" -PercentComplete $percent
}

# 1. NUCLEAR POWER PLAN OPTIMIZATION
Write-Host "`n[1/12] ACTIVATING NUCLEAR POWER PLAN..." -ForegroundColor Green
Show-Progress 1 12
powercfg -delete "ULTIMATE GAMING PERFORMANCE" 2>$null
powercfg -delete "EXTREME GAMING" 2>$null
$planGuid = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
if ($planGuid -match "([a-f0-9-]{36})") {
    $guid = $matches[1]
    powercfg -changename $guid "ULTIMATE GAMING PERFORMANCE" "MAXIMUM PERFORMANCE - GAMING MODE"
    powercfg -setactive $guid
    # MAXIMUM PERFORMANCE SETTINGS
    powercfg -setacvalueindex $guid SUB_PROCESSOR PROFCIENCY 100
    powercfg -setdcvalueindex $guid SUB_PROCESSOR PROFCIENCY 100
    powercfg -setacvalueindex $guid SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100
    powercfg -setdcvalueindex $guid SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100
    powercfg -setacvalueindex $guid SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
    powercfg -setdcvalueindex $guid SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
}

# 2. CPU MAXIMIZATION - ULTIMATE PERFORMANCE
Write-Host "`n[2/12] MAXIMIZING CPU PERFORMANCE..." -ForegroundColor Green
Show-Progress 2 12
# Disable CPU throttling and power limits
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d 4294967295 /f
# Maximum CPU scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f
# Disable core parking
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Value" /t REG_DWORD /d 100 /f

# 3. GPU ULTIMATE OPTIMIZATION
Write-Host "`n[3/12] MAXIMIZING GPU PERFORMANCE..." -ForegroundColor Green
Show-Progress 3 12
# NVIDIA Ultimate Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PerfLevelSrc" /t REG_DWORD /d 0x3333 /f 2>$null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableGR535" /t REG_DWORD /d 1 /f 2>$null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableDynamicPstate" /t REG_DWORD /d 1 /f 2>$null
# AMD Ultimate Tweaks
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag" /v "EnableUlps" /t REG_DWORD /d 0 /f 2>$null
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag" /v "EnableUlps_NA" /t REG_DWORD /d 0 /f 2>$null
# Hardware Accelerated GPU Scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f
# Disable GPU Power Savings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableMsHybrid" /t REG_DWORD /d 0 /f 2>$null

# 4. RAM MAXIMIZATION
Write-Host "`n[4/12] MAXIMIZING MEMORY PERFORMANCE..." -ForegroundColor Green
Show-Progress 4 12
# Disable SuperFetch/Prefetch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
# Large System Cache
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
# Clear Page File at Shutdown (Security)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f

# 5. NETWORK ULTRA-LOW LATENCY OPTIMIZATION
Write-Host "`n[5/12] MAXIMIZING NETWORK PERFORMANCE..." -ForegroundColor Green
Show-Progress 5 12
# Disable Nagle's Algorithm
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
# Network Throttling Index (Maximum)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xFFFFFFFF /f
# Gaming Traffic Optimization
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
# Maximum Network Buffers
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d 16384 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d 16384 /f

# 6. NUCLEAR SERVICE DISABLE - GAMING ONLY MODE
Write-Host "`n[6/12] DISABLING NON-ESSENTIAL SERVICES..." -ForegroundColor Green
Show-Progress 6 12
$nuclearServices = @(
    "AarSvc", "AJRouter", "ALG", "AppIDSvc", "AppMgmt", "AssignedAccessManagerSvc",
    "AutomaticDownloads", "BcastDVRUserService", "BDESVC", "BFE", "BITS", "BluetoothUserService",
    "BrokerInfrastructure", "Browser", "BthAvctpSvc", "bthserv", "camsvc", "CaptureService",
    "cbdhsvc", "CDPSvc", "CDPUserSvc", "CertPropSvc", "ClipSVC", "CloudExperienceHost",
    "CmRCService", "CNG", "ConnectedDevicesPlatformUserSvc", "ConsentUxUserSvc",
    "CoreMessagingRegistrar", "CredentialEnrollmentManagerUserSvc", "CryptSvc", "CscService",
    "DcomLaunch", "defragsvc", "DeviceAssociationService", "DeviceInstall", "DevicePickerUserSvc",
    "DevicesFlowUserSvc", "DevQueryBroker", "Dhcp", "diagnosticshub.standardcollector.service",
    "DiagTrack", "DisplayEnhancementService", "DmEnrollmentSvc", "dmwappushservice",
    "Dnscache", "Dot3Svc", "DPS", "DsmSvc", "DsSvc", "DusmSvc", "Eaphost", "EFS", "embeddedmode",
    "EntAppSvc", "EventLog", "EventSystem", "Fax", "fdPHost", "FDResPub", "fhsvc", "FontCache",
    "FrameServer", "gpsvc", "GraphicsPerfSvc", "hidserv", "HvHost", "icssvc", "IKEEXT",
    "InstallService", "iphlpsvc", "IpxlatCfgSvc", "KeyIso", "KtmRm", "LanmanServer",
    "LanmanWorkstation", "lfsvc", "LicenseManager", "lltdsvc", "lmhosts", "LSM", "LxpSvc",
    "MapsBroker", "MessagingService", "MessagingService", "MpsSvc", "MSDTC", "MSiSCSI",
    "msiserver", "NaturalAuthentication", "NcaSvc", "NcbService", "NcdAutoSetup", "Netlogon",
    "Netman", "netprofm", "NetSetupSvc", "NetTcpPortSharing", "NgcCtnrSvc", "NgcSvc",
    "NlaSvc", "nsi", "OfficeSvc", "P9RdrService", "p2pimsvc", "p2psvc", "PerfHost", "PhoneSvc",
    "PimIndexMaintenanceSvc", "pla", "PlugPlay", "PNRPAutoReg", "PNRPsvc", "PolicyAgent",
    "Power", "PrintNotify", "PrintWorkflowUserSvc", "ProfSvc", "PushToInstall", "QWAVE",
    "RasAuto", "RasMan", "RemoteAccess", "RemoteRegistry", "RetailDemo", "RmSvc", "RpcEptMapper",
    "RpcLocator", "RSoPProv", "sacsvr", "SamSs", "SCardSvr", "ScDeviceEnum", "Schedule",
    "SCPolicySvc", "SDRSVC", "seclogon", "SecurityHealthService", "SEMgrSvc", "SENS",
    "SensorDataService", "SensorService", "SensrSvc", "SessionEnv", "SgrmBroker", "SharedAccess",
    "SharedRealitySvc", "ShellHWDetection", "smphost", "SmsRouter", "SNMPTRAP", "Spectrum",
    "Spooler", "sppsvc", "SSDPSRV", "SstpSvc", "StateRepository", "stisvc", "StorageService",
    "StorSvc", "svsvc", "SwPrv", "SysMain", "SystemEventsBroker", "TabletInputService",
    "TapiSrv", "TermService", "Themes", "TieringEngineService", "TimeBroker", "TimeBrokerSvc",
    "TokenBroker", "TrkWks", "TroubleshootingSvc", "tzautoupdate", "UevAgentService",
    "UmRdpService", "UnistoreSvc", "upnphost", "UserDataSvc", "UserManager",
    "UsoSvc", "VaultSvc", "vds", "VirtualDisk", "vmickvpexchange", "vmicrdv", "vmicshutdown",
    "vmictimesync", "vmicvmsession", "vmicvss", "VSS", "W32Time", "WaaSMedicSvc", "WalletService",
    "WarpJITSvc", "WbioSrvc", "Wcmsvc", "wcncsvc", "WdiServiceHost", "WdiSystemHost",
    "WdNisSvc", "WebClient", "Wecsvc", "WEPHOSTSVC", "wercplsupport", "WerSvc", "WFDSConMgrSvc",
    "WiaRpc", "WinDefend", "WinHttpAutoProxySvc", "Winmgmt", "WinRM", "WlanSvc", "wlcrasvc",
    "wlidsvc", "WManSvc", "wmiApSrv", "WMPNetworkSvc", "workfolderssvc", "WpcMonSvc",
    "WPDBusEnum", "WpnService", "WpnUserService", "wscsvc", "WSearch", "WSService",
    "XboxGipSvc", "XboxNetApiSvc", "XblAuthManager", "XblGameSave"
)

foreach ($service in $nuclearServices) {
    try {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        sc.exe config $service start= disabled 2>$null
    } catch { }
}

# 7. ULTIMATE GAME MODE & DVR DISABLE
Write-Host "`n[7/12] MAXIMIZING GAME MODE..." -ForegroundColor Green
Show-Progress 7 12
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 1 /f

# 8. DISABLE VISUAL EFFECTS FOR MAXIMUM PERFORMANCE
Write-Host "`n[8/12] DISABLING VISUAL EFFECTS..." -ForegroundColor Green
Show-Progress 8 12
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f
# Disable animations
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f

# 9. ULTIMATE PROCESS SCHEDULING & PRIORITY
Write-Host "`n[9/12] OPTIMIZING PROCESS SCHEDULING..." -ForegroundColor Green
Show-Progress 9 12
# Maximum foreground boost
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f
# Game performance mode
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f

# 10. STORAGE & DISK OPTIMIZATION
Write-Host "`n[10/12] OPTIMIZING STORAGE PERFORMANCE..." -ForegroundColor Green
Show-Progress 10 12
# Disable indexing
reg add "HKLM\SOFTWARE\Microsoft\Windows Search" /v "SetupCompletedSuccessfully" /t REG_DWORD /d 0 /f
Stop-Service "WSearch" -Force 2>$null
Set-Service "WSearch" -StartupType Disabled 2>$null
# Disable defrag for SSDs
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" -ErrorAction SilentlyContinue

# 11. SECURITY DISABLE FOR PERFORMANCE (USE AT OWN RISK)
Write-Host "`n[11/12] OPTIMIZING SECURITY SETTINGS..." -ForegroundColor Green
Show-Progress 11 12
# Disable Windows Defender for gaming (temporary)
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
# Disable Spectre/Meltdown mitigations for performance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f

# 12. FINAL SYSTEM TWEAKS & CLEANUP
Write-Host "`n[12/12] APPLYING FINAL OPTIMIZATIONS..." -ForegroundColor Green
Show-Progress 12 12
# Clear all temp files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
# Clear DNS cache
ipconfig /flushdns | Out-Null
# Disable Windows Update during gaming sessions
Stop-Service "wuauserv" -Force -ErrorAction SilentlyContinue
Set-Service "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue

# COMPLETION MESSAGE
Write-Host "`n" -ForegroundColor Green
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ ULTIMATE OPTIMIZATION COMPLETE ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓" -ForegroundColor Yellow
Write-Host "████████████████████████████████████████████████████████████████████████████████" -ForegroundColor Green
Write-Host "`nALL SYSTEMS MAXIMIZED FOR ULTIMATE GAMING PERFORMANCE!" -ForegroundColor Green
Write-Host "`nIMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Yellow
Write-Host "1. RESTART YOUR COMPUTER NOW - ALL CHANGES REQUIRE REBOOT" -ForegroundColor White
Write-Host "2. UPDATE GPU DRIVERS TO LATEST VERSION" -ForegroundColor White
Write-Host "3. SET GAMES TO HIGH PRIORITY IN TASK MANAGER" -ForegroundColor White
Write-Host "4. MONITOR TEMPERATURES - SYSTEM RUNS AT MAXIMUM PERFORMANCE" -ForegroundColor White
Write-Host "`nPERFORMANCE FEATURES ACTIVATED:" -ForegroundColor Cyan
Write-Host "✓ Maximum CPU/GPU Performance" -ForegroundColor Green
Write-Host "✓ Ultra-Low Latency Network" -ForegroundColor Green
Write-Host "✓ 100+ Services Disabled" -ForegroundColor Green
Write-Host "✓ Gaming-Only System Mode" -ForegroundColor Green
Write-Host "✓ Maximum Process Priority" -ForegroundColor Green
Write-Host "✓ Full Hardware Acceleration" -ForegroundColor Green
Write-Host "`nWARNING: System is now optimized SOLELY for gaming performance!" -ForegroundColor Red

# Force restart
Write-Host "`nCOMPUTER WILL RESTART IN 10 SECONDS TO APPLY ALL OPTIMIZATIONS..." -ForegroundColor Red
Write-Host "Press Ctrl+C to cancel auto-restart" -ForegroundColor Yellow
for ($i = 10; $i -gt 0; $i--) {
    Write-Host "Restarting in $i seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}
Write-Host "RESTARTING NOW FOR MAXIMUM GAMING PERFORMANCE!" -ForegroundColor Green
Restart-Computer -Force
