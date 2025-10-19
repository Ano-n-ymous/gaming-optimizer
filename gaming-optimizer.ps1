# Gaming Optimization Master Script for Windows 10/11
# Requires Administrator privileges
# Run with: irm [your-repo-url] | iex

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
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $gpu = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        Write-Host "System: $($computerSystem.Model)" -ForegroundColor Cyan
        Write-Host "Processor: $($processor.Name)" -ForegroundColor Cyan
        Write-Host "GPU: $($gpu.Name)" -ForegroundColor Cyan
        Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor Cyan
        Write-Host "Memory: $([math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor Cyan
    } catch {
        Write-Host "Could not retrieve complete system information" -ForegroundColor Red
    }
}

# Create Ultimate Power Plan
function Optimize-PowerPlan {
    Write-Host "`nCreating Ultimate Gaming Power Plan..." -ForegroundColor Green
    
    try {
        # Remove existing plan if exists
        powercfg -delete "Ultimate Gaming Performance" 2>$null
        
        # Create new power plan from High Performance
        $powerPlanGuid = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        if ($powerPlanGuid -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
            $planGuid = $matches[1]
            powercfg -changename $planGuid "Ultimate Gaming Performance" "Maximum performance for gaming"
            
            # Set as active
            powercfg -setactive $planGuid
            
            Write-Host "Ultimate Gaming Power Plan activated!" -ForegroundColor Green
        }
    } catch {
        Write-Host "Power plan optimization failed: $_" -ForegroundColor Red
    }
}

# Optimize GPU Settings
function Optimize-GPU {
    Write-Host "`nOptimizing GPU settings..." -ForegroundColor Green
    
    try {
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
                try {
                    Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "Failed to set NVIDIA setting $($setting.Name)" -ForegroundColor Red
                }
            }
        }
        
        # General GPU optimizations
        $gpuSettings = @(
            @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D9"; Type = "DWord"; Value = 1},
            @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D10"; Type = "DWord"; Value = 1},
            @{Path = "HKLM:\SOFTWARE\Microsoft\DirectX"; Name = "UseD3D11"; Type = "DWord"; Value = 1}
        )
        
        foreach ($setting in $gpuSettings) {
            try {
                if (-not (Test-Path $setting.Path)) {
                    New-Item -Path $setting.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force -ErrorAction Stop
            } catch {
                Write-Host "Failed to set GPU setting $($setting.Name)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "GPU optimization failed: $_" -ForegroundColor Red
    }
}

# Optimize Network for Gaming
function Optimize-Network {
    Write-Host "`nOptimizing network settings for gaming..." -ForegroundColor Green
    
    try {
        # Network throttling index
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Force -ErrorAction SilentlyContinue
        
        # Gaming DCOM priority
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "DefaultLaunchPermission" -Type "Binary" -Value ([byte[]](0x01,0x00,0x04,0x80)) -Force -ErrorAction SilentlyContinue
        
        Write-Host "Network optimizations applied!" -ForegroundColor Green
    } catch {
        Write-Host "Network optimization failed: $_" -ForegroundColor Red
    }
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
            $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceObj) {
                Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                Write-Host "Disabled: $service" -ForegroundColor Yellow
            }
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
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force -ErrorAction Stop
        } catch {
            Write-Host "Failed to set game setting: $($setting.Name)" -ForegroundColor Red
        }
    }
}

# Optimize System Performance
function Optimize-SystemPerformance {
    Write-Host "`nOptimizing system performance..." -ForegroundColor Green
    
    try {
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
            try {
                if (-not (Test-Path $tweak.Path)) {
                    New-Item -Path $tweak.Path -Force | Out-Null
                }
                Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Force -ErrorAction Stop
            } catch {
                Write-Host "Failed to set performance tweak: $($tweak.Name)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "System performance optimization failed: $_" -ForegroundColor Red
    }
}

# Clean Temporary Files
function Clean-TempFiles {
    Write-Host "`nCleaning temporary files..." -ForegroundColor Green
    
    $cleanPaths = @(
        "$env:TEMP\*",
        "$env:WINDIR\Temp\*",
        "$env:LOCALAPPDATA\Temp\*"
    )
    
    foreach ($path in $cleanPaths) {
        try {
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        } catch {
            # Continue on error
        }
    }
    
    # Clear DNS cache
    ipconfig /flushdns | Out-Null
    Write-Host "Temporary files cleaned!" -ForegroundColor Green
}

# Final Optimizations
function Apply-FinalOptimizations {
    Write-Host "`nApplying final optimizations..." -ForegroundColor Green
    
    try {
        # Set process priority script for startup
        $scriptBlock = @"
            `$processes = Get-Process | Where-Object { `$_.ProcessName -like "*game*" -or `$_.ProcessName -like "*steam*" -or `$_.ProcessName -like "*epic*" }
            foreach (`$process in `$processes) {
                try {
                    `$process.PriorityClass = "High"
                } catch {
                    # Continue on error
                }
            }
"@
        
        # Register script to run at logon for ongoing optimization
        $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\GameOptimizer.ps1"
        $scriptBlock | Out-File -FilePath $startupPath -Encoding UTF8 -Force
        Write-Host "Startup optimizer created!" -ForegroundColor Green
    } catch {
        Write-Host "Final optimizations failed: $_" -ForegroundColor Red
    }
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
    try {
        $restart = Read-Host "`nRestart now? (y/n)"
        if ($restart -eq 'y' -or $restart -eq 'Y') {
            Restart-Computer -Force
        }
    } catch {
        Write-Host "Could not restart automatically. Please restart manually." -ForegroundColor Yellow
    }
}

# Execution
try {
    # Set execution policy first
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Main
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Please run the script again or check system compatibility." -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
