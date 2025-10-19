# Gaming Optimization Master Script for Windows 10/11
# Requires Administrator privileges
# Run with: irm bit.ly/win-game-opt | iex
# (Replace with your actual repo URL)

param(
    [switch]$Force = $false,
    [switch]$SkipWarning = $false
)

# Elevate to Admin if not already
function Elevate-Admin {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Elevating to Administrator privileges..." -ForegroundColor Yellow
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        if ($Force) { $arguments += " -Force" }
        if ($SkipWarning) { $arguments += " -SkipWarning" }
        
        Start-Process "pwsh.exe" -Verb RunAs -ArgumentList $arguments
        exit
    }
}

# Display warning
function Show-Warning {
    if (-not $SkipWarning) {
        Write-Host "==================================================" -ForegroundColor Red
        Write-Host "           GAMING OPTIMIZATION SCRIPT" -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Red
        Write-Host "WARNING: This script will make significant system changes!" -ForegroundColor Red
        Write-Host ""
        Write-Host "Changes include:" -ForegroundColor Yellow
        Write-Host "• Registry modifications" -ForegroundColor White
        Write-Host "• Service disabling" -ForegroundColor White
        Write-Host "• System configuration changes" -ForegroundColor White
        Write-Host "• Network optimizations" -ForegroundColor White
        Write-Host "• Power plan adjustments" -ForegroundColor White
        Write-Host ""
        Write-Host "Backup your system before proceeding!" -ForegroundColor Red
        Write-Host "Press any key to continue or Ctrl+C to abort..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# System Information
function Get-SystemInfo {
    Write-Host "`nCollecting system information..." -ForegroundColor Green
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $processor = Get-CimInstance -ClassName Win32_Processor
    $gpu = Get-CimInstance -ClassName Win32_VideoController
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    
    Write-Host "System: $($computerSystem.Model)" -ForegroundColor Cyan
    Write-Host "Processor: $($processor.Name)" -ForegroundColor Cyan
    Write-Host "GPU: $($gpu.Name)" -ForegroundColor Cyan
    Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor Cyan
    Write-Host "Memory: $([math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor Cyan
}

# Create Ultimate Power Plan
function Optimize-PowerPlan {
    Write-Host "`nCreating Ultimate Gaming Power Plan..." -ForegroundColor Green
    
    # Remove existing plan if exists
    powercfg -delete "Ultimate Gaming Performance" 2>$null
    
    # Create new power plan from High Performance
    $powerPlanGuid = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    if ($powerPlanGuid -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
        $planGuid = $matches[1]
        powercfg -changename $planGuid "Ultimate Gaming Performance" "Maximum performance for gaming"
        
        # Set as active
        powercfg -setactive $planGuid
        
        # Power plan settings
        $settings = @(
            "SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 893dee8e-2bef-41e0-89c6-b55d0929964c 100", # Processor performance boost mode - Aggressive
            "SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100", # Maximum processor state - 100%
            "SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100", # Minimum processor state - 100%
            "SUB_PROCESSOR 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 0",   # Processor performance core parking min cores - 100%
            "SUB_GRAPHICS 5fb92a4e-2e66-4e6f-9509-44f162e38b6f 5d76a2ca-e8c0-402f-a133-2158492d58ad 1",    # GPU preference - High Performance
            "SUB_GRAPHICS 5fb92a4e-2e66-4e6f-9509-44f162e38b6f e48a2c5c-8299-4c70-97a3-1b543c83ea0c 1"     # Hardware accelerated GPU scheduling - Enabled
        )
        
        foreach ($setting in $settings) {
            powercfg -setacvalueindex $planGuid $setting.Split(' ')[0] $setting.Split(' ')[1] $setting.Split(' ')[2] $setting.Split(' ')[3]
            powercfg -setdcvalueindex $planGuid $setting.Split(' ')[0] $setting.Split(' ')[1] $setting.Split(' ')[2] $setting.Split(' ')[3]
        }
        
        powercfg -S $planGuid
        Write-Host "Ultimate Gaming Power Plan activated!" -ForegroundColor Green
    }
}

# Optimize GPU Settings
function Optimize-GPU {
    Write-Host "`nOptimizing GPU settings..." -ForegroundColor Green
    
    # NVIDIA Optimizations (if NVIDIA GPU present)
    $nvidiaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm"
    if (Test-Path $nvidiaPath) {
        Write-Host "Applying NVIDIA optimizations..." -ForegroundColor Yellow
        
        $nvidiaSettings = @(
            @{Path = $nvidiaPath; Name = "UsePlatformClock"; Type = "DWord"; Value = 0},
            @{Path = $nvidiaPath; Name = "EnableGR535"; Type = "DWord"; Value = 1},
            @{Path = $nvidiaPath; Name = "DisableDynamicPstate"; Type = "DWord"; Value = 1}
        )
        
        foreach ($setting in $nvidiaSettings) {
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force -ErrorAction SilentlyContinue
        }
    }
    
    # General GPU optimizations
    $gpuSettings = @(
        @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D9"; Type = "DWord"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D10"; Type = "DWord"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D11"; Type = "DWord"; Value = 1}
    )
    
    foreach ($setting in $gpuSettings) {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force
    }
}

# Optimize Network for Gaming
function Optimize-Network {
    Write-Host "`nOptimizing network settings for gaming..." -ForegroundColor Green
    
    # Disable Nagle's algorithm
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" -Name "TcpAckFrequency" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" -Name "TCPNoDelay" -Value 1 -ErrorAction SilentlyContinue
    
    # Network throttling index
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Force
    
    # Gaming DCOM priority
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "DefaultLaunchPermission" -Type "Binary" -Value ([byte[]](0x01,0x00,0x04,0x80)) -Force
}

# Disable Non-Essential Services
function Disable-NonEssentialServices {
    Write-Host "`nDisabling non-essential services..." -ForegroundColor Green
    
    $servicesToDisable = @(
        "XboxGipSvc", "XboxNetApiSvc", "WSearch", "TabletInputService",
        "Fax", "MapsBroker", "lfsvc", "SharedAccess", "lltdsvc",
        "NetTcpPortSharing", "RemoteRegistry", "SCardSvr", "SensorDataService",
        "SensorService", "ShellHWDetection", "WbioSrvc", "WMPNetworkSvc",
        "wscsvc", "XblAuthManager", "XboxNetApiSvc", "Spooler",
        "PrintNotify", "PhoneSvc", "WpcMonSvc", "UevAgentService",
        "WalletService", "StorSvc", "SEMgrSvc", "SCPolicySvc"
    )
    
    foreach ($service in $servicesToDisable) {
        try {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            Write-Host "Disabled: $service" -ForegroundColor Yellow
        } catch {
            Write-Host "Could not disable: $service" -ForegroundColor Red
        }
    }
}

# Optimize Windows Game Mode and GPU Scheduling
function Optimize-GameSettings {
    Write-Host "`nOptimizing Windows gaming features..." -ForegroundColor Green
    
    $gameSettings = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVR"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\GraphicsDrivers"; Name = "HwSchMode"; Type = "DWord"; Value = 2},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"; Name = "AppCaptureEnabled"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\GameBar"; Name = "AllowAutoGameMode"; Type = "DWord"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\GameBar"; Name = "AutoGameModeEnabled"; Type = "DWord"; Value = 1}
    )
    
    foreach ($setting in $gameSettings) {
        if (-not (Test-Path $setting.Path)) {
            New-Item -Path $setting.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force
    }
}

# Optimize System Performance
function Optimize-SystemPerformance {
    Write-Host "`nOptimizing system performance..." -ForegroundColor Green
    
    # Disable visual effects
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type "DWord" -Value 2
    
    # Performance registry tweaks
    $performanceTweaks = @(
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "PreFetchParameters"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name = "Win32PrioritySeparation"; Type = "DWord"; Value = 38},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name = "SystemResponsiveness"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "GPU Priority"; Type = "DWord"; Value = 8},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name = "Priority"; Type = "DWord"; Value = 6}
    )
    
    foreach ($tweak in $performanceTweaks) {
        if (-not (Test-Path $tweak.Path)) {
            New-Item -Path $tweak.Path -Force | Out-Null
        }
        Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Force
    }
}

# Clean Temporary Files
function Clean-TempFiles {
    Write-Host "`nCleaning temporary files..." -ForegroundColor Green
    
    $cleanPaths = @(
        "$env:TEMP\*",
        "$env:WINDIR\Temp\*",
        "$env:LOCALAPPDATA\Temp\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*",
        "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies\*"
    )
    
    foreach ($path in $cleanPaths) {
        try {
            Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Continue on error
        }
    }
    
    # Clear DNS cache
    ipconfig /flushdns | Out-Null
}

# Final Optimizations
function Apply-FinalOptimizations {
    Write-Host "`nApplying final optimizations..." -ForegroundColor Green
    
    # Disable Windows features that impact gaming
    $features = @(
        "Printing-PrintToPDFServices-Features",
        "Printing-XPSServices-Features",
        "WorkFolders-Client"
    )
    
    foreach ($feature in $features) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue
        } catch {
            # Continue on error
        }
    }
    
    # Set process priority
    $scriptBlock = {
        $processes = Get-Process | Where-Object { $_.ProcessName -like "*game*" -or $_.ProcessName -like "*steam*" -or $_.ProcessName -like "*epic*" }
        foreach ($process in $processes) {
            try {
                $process.PriorityClass = "High"
            } catch {
                # Continue on error
            }
        }
    }
    
    # Register script to run at logon for ongoing optimization
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\GameOptimizer.ps1"
    $scriptBlock.ToString() | Out-File -FilePath $startupPath -Encoding UTF8
}

# Main Execution
function Main {
    Elevate-Admin
    Show-Warning
    Get-SystemInfo
    
    Write-Host "`nStarting gaming optimization process..." -ForegroundColor Green
    
    # Execute optimizations
    Optimize-PowerPlan
    Optimize-GPU
    Optimize-Network
    Disable-NonEssentialServices
    Optimize-GameSettings
    Optimize-SystemPerformance
    Clean-TempFiles
    Apply-FinalOptimizations
    
    # Final steps
    Write-Host "`n" + "="*50 -ForegroundColor Green
    Write-Host "GAMING OPTIMIZATION COMPLETE!" -ForegroundColor Green
    Write-Host "="*50 -ForegroundColor Green
    Write-Host "`nRecommended next steps:" -ForegroundColor Yellow
    Write-Host "1. Restart your computer" -ForegroundColor White
    Write-Host "2. Update your GPU drivers" -ForegroundColor White
    Write-Host "3. Set game executables to high priority in Task Manager" -ForegroundColor White
    Write-Host "4. Monitor temperatures during gaming sessions" -ForegroundColor White
    Write-Host "`nSome changes require a restart to take effect." -ForegroundColor Cyan
    
    # Prompt for restart
    $restart = Read-Host "`nRestart now? (y/n)"
    if ($restart -eq 'y' -or $restart -eq 'Y') {
        Restart-Computer -Force
    }
}

# Execution
try {
    Main
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Please run the script again or check system compatibility." -ForegroundColor Yellow
}
