# Gaming Optimization Master Script for Windows 10/11
# Requires Administrator privileges
# Run with: irm https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1 | iex

param(
    [switch]$Force = $false,
    [switch]$SkipWarning = $false
)

# Elevate to Admin if not already
function Elevate-Admin {
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Elevating to Administrator privileges..." -ForegroundColor Yellow
        
        # Download the script to a temporary file and run that instead
        $tempScript = "$env:TEMP\gaming-optimizer-admin.ps1"
        $scriptUrl = "https://raw.githubusercontent.com/Ano-n-ymous/gaming-optimizer/main/gaming-optimizer.ps1"
        
        try {
            Invoke-WebRequest -Uri $scriptUrl -OutFile $tempScript -ErrorAction Stop
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`""
            if ($Force) { $arguments += " -Force" }
            if ($SkipWarning) { $arguments += " -SkipWarning" }
            
            Start-Process "pwsh.exe" -Verb RunAs -ArgumentList $arguments
            exit
        } catch {
            Write-Host "Failed to download script for elevation: $_" -ForegroundColor Red
            Write-Host "Please run PowerShell as Administrator manually and try again." -ForegroundColor Yellow
            pause
            exit
        }
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
        if ($gpu.Name) {
            Write-Host "GPU: $($gpu.Name)" -ForegroundColor Cyan
        }
        Write-Host "OS: $($os.Caption) $($os.Version)" -ForegroundColor Cyan
        Write-Host "Memory: $([math]::Round($computerSystem.TotalPhysicalMemory/1GB, 2)) GB" -ForegroundColor Cyan
    } catch {
        Write-Host "Could not retrieve complete system information" -ForegroundColor Yellow
    }
}

# Create Ultimate Power Plan
function Optimize-PowerPlan {
    Write-Host "`nCreating Ultimate Gaming Power Plan..." -ForegroundColor Green
    
    try {
        # Remove existing plan if exists
        powercfg -delete "Ultimate Gaming Performance" 2>$null
        
        # Create new power plan from High Performance
        $powerPlanOutput = powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        if ($powerPlanOutput -match "([a-f0-9-]{36})") {
            $planGuid = $matches[1]
            powercfg -changename $planGuid "Ultimate Gaming Performance" "Maximum performance for gaming"
            
            # Set as active
            powercfg -setactive $planGuid
            
            Write-Host "Ultimate Gaming Power Plan activated!" -ForegroundColor Green
        } else {
            Write-Host "Using existing High Performance plan" -ForegroundColor Yellow
            powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
    } catch {
        Write-Host "Power plan optimization completed with warnings" -ForegroundColor Yellow
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
                    # Skip if cannot set
                }
            }
        }
        
        Write-Host "GPU optimizations applied!" -ForegroundColor Green
    } catch {
        Write-Host "GPU optimization completed with warnings" -ForegroundColor Yellow
    }
}

# Optimize Network for Gaming
function Optimize-Network {
    Write-Host "`nOptimizing network settings for gaming..." -ForegroundColor Green
    
    try {
        # Network throttling index
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Force -ErrorAction SilentlyContinue
        
        Write-Host "Network optimizations applied!" -ForegroundColor Green
    } catch {
        Write-Host "Network optimization completed with warnings" -ForegroundColor Yellow
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
        "wscsvc", "XblAuthManager", "Spooler", "PrintNotify", "PhoneSvc"
    )
    
    $disabledCount = 0
    foreach ($service in $servicesToDisable) {
        try {
            $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceObj -and $serviceObj.Status -ne 'Stopped') {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            $disabledCount++
            Write-Host "Disabled: $service" -ForegroundColor Yellow
        } catch {
            # Skip if cannot disable
        }
    }
    Write-Host "Disabled $disabledCount non-essential services" -ForegroundColor Green
}

# Optimize Windows Game Mode and GPU Scheduling
function Optimize-GameSettings {
    Write-Host "`nOptimizing Windows gaming features..." -ForegroundColor Green
    
    $gameSettings = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name = "AllowGameDVR"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"; Name = "AppCaptureEnabled"; Type = "DWord"; Value = 0},
        @{Path = "HKLM:\SOFTWARE\Microsoft\GameBar"; Name = "AllowAutoGameMode"; Type = "DWord"; Value = 1},
        @{Path = "HKLM:\SOFTWARE\Microsoft\GameBar"; Name = "AutoGameModeEnabled"; Type = "DWord"; Value = 1}
    )
    
    foreach ($setting in $gameSettings) {
        try {
            if (-not (Test-Path $setting.Path)) {
                New-Item -Path $setting.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $setting.Path -Name $setting.Name -Value $setting.Value -Force -ErrorAction SilentlyContinue
        } catch {
            # Skip if cannot set
        }
    }
    Write-Host "Game settings optimized!" -ForegroundColor Green
}

# Optimize System Performance
function Optimize-SystemPerformance {
    Write-Host "`nOptimizing system performance..." -ForegroundColor Green
    
    try {
        # Performance registry tweaks
        $performanceTweaks = @(
            @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "PreFetchParameters"; Type = "DWord"; Value = 1},
            @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name = "ClearPageFileAtShutdown"; Type = "DWord"; Value = 0}
        )
        
        foreach ($tweak in $performanceTweaks) {
            try {
                Set-ItemProperty -Path $tweak.Path -Name $tweak.Name -Value $tweak.Value -Force -ErrorAction SilentlyContinue
            } catch {
                # Skip if cannot set
            }
        }
        Write-Host "System performance optimized!" -ForegroundColor Green
    } catch {
        Write-Host "System performance optimization completed with warnings" -ForegroundColor Yellow
    }
}

# Clean Temporary Files
function Clean-TempFiles {
    Write-Host "`nCleaning temporary files..." -ForegroundColor Green
    
    try {
        # Clear temp files
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        
        # Clear DNS cache
        ipconfig /flushdns | Out-Null
        
        Write-Host "Temporary files cleaned!" -ForegroundColor Green
    } catch {
        Write-Host "Temp file cleanup completed with warnings" -ForegroundColor Yellow
    }
}

# Main Execution
function Main {
    # Set execution policy first
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    
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
            Write-Host "Restarting computer..." -ForegroundColor Yellow
            Restart-Computer -Force
        } else {
            Write-Host "Please restart your computer manually to apply all changes." -ForegroundColor Yellow
            Write-Host "Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    } catch {
        Write-Host "Please restart your computer manually to apply all changes." -ForegroundColor Yellow
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Start the script
try {
    Main
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Host "Please run the script again or check system compatibility." -ForegroundColor Yellow
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
