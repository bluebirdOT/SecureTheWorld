<#
.SYNOPSIS
    CyberPatriot Windows Hardening Script - Prompt-Driven Safe Mode
.DESCRIPTION
    Hardens Windows systems by enforcing user/account policies, audit policies, firewall rules,
    service & app hardening, password policies, AV, update, and other best practices.
    Prompts before making any changes, designed for scoring and safety.
    Reads authorized users/admins from "Users.txt" in the script directory.
#>

# ====== Initialization ======
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$UserListPath = Join-Path $ScriptDir "Users.txt"

# ====== Prompt Function ======
function Confirm-Action {
    param([string]$Message)
    Write-Host "$Message (Y/N)" -ForegroundColor Yellow
    $choice = Read-Host
    return ($choice -match '^(y|yes)$')
}

# ====== Audit Policy Enforcement ======
function Enable-AllAudits {
    if (Confirm-Action "Apply audit policy changes (all success/failure events)?") {
        try {
            auditpol /set /category:* /success:enable /failure:enable | Out-Null
            Write-Host "All audit categories set to Success and Failure" -ForegroundColor Green
        } catch {
            Write-Host "Failed to configure audit policies: ${_}" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped audit policy changes." -ForegroundColor Yellow
    }
}

# ====== User Management ======
function Manage-Users {
    if (-not (Test-Path $UserListPath)) {
        Write-Host "User list file not found: $UserListPath" -ForegroundColor Red
        return
    }

    $authorizedUsers = @{}
    Get-Content $UserListPath | ForEach-Object {
        if ($_ -match '^\s*#') { return }
        if ($_ -match '^\s*(?<name>[^\s;]+)\s*;?\s*(?<role>admin)?\s*$') {
            $authorizedUsers[$Matches['name']] = ($Matches['role'] -eq 'admin')
        }
    }

    $localUsers = Get-LocalUser | ForEach-Object { $_.Name }

    # Add missing authorized users
    foreach ($user in $authorizedUsers.Keys) {
        if ($localUsers -notcontains $user) {
            if (Confirm-Action "User '$user' not found. Add?") {
                try {
                    $password = Read-Host "Enter temporary password for $user" -AsSecureString
                    New-LocalUser -Name $user -Password $password -UserMayNotChangePassword $false -PasswordNeverExpires $false
                    Write-Host "Added missing user: $user" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to add user ${user}: ${_}" -ForegroundColor Red
                }
            }
        }
    }

    # Remove unauthorized users
    foreach ($user in $localUsers) {
       if ($user -in @("Administrator","Guest","defaultaccount","WDAGUtilityAccount")) {
           if (Confirm-Action "User '$user' is built-in. Disable instead of removing?") {
           Disable-LocalUser -Name $user
           Write-Host "Disabled built-in user: ${user}" -ForegroundColor Green
           }
       } elseif (-not $authorizedUsers.ContainsKey($user)) {
           if (Confirm-Action "User '$user' is not in authorized list. Remove?") {
               try {
                   Remove-LocalUser -Name $user
                   Write-Host "Removed unauthorized user: ${user}" -ForegroundColor Green
               } catch {
                   Write-Host "Failed to remove user ${user}: $($_.Exception.Message)" -ForegroundColor Red
               }
           }
       }
    }

    # Manage admin rights
    $admins = Get-LocalGroupMember -Group "Administrators" | ForEach-Object { $_.Name.Split('\')[-1] }
    foreach ($user in $authorizedUsers.Keys) {
        $shouldBeAdmin = $authorizedUsers[$user]
        $isAdmin = $admins -contains $user

        if ($shouldBeAdmin -and -not $isAdmin) {
            if (Confirm-Action "User '$user' should be admin. Add to Administrators?") {
                try {
                    Add-LocalGroupMember -Group "Administrators" -Member $user
                    Write-Host "Granted admin rights to $user" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to add admin rights to ${user}: ${_}" -ForegroundColor Red
                }
            }
        } elseif (-not $shouldBeAdmin -and $isAdmin) {
            if (Confirm-Action "User '$user' should NOT be admin. Remove from Administrators?") {
                try {
                    Remove-LocalGroupMember -Group "Administrators" -Member $user
                    Write-Host "Removed admin rights from $user" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to remove admin rights from ${user}: $_" -ForegroundColor Red
                }
            }
        }
    }
}

# ====== Service Hardening ======
function Harden-Services {
    $BadServices = @(
        "Telnet","FTPSVC","RemoteRegistry","SNMP","SSDPDiscovery",
        "BluetoothSupportService","LanmanServer"
    )

    foreach ($service in $BadServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "Service detected: $service (Status: $($svc.Status))" -ForegroundColor Yellow
            if (Confirm-Action "Disable and stop service $service?") {
                try {
                    Stop-Service -Name $service -Force
                    Set-Service -Name $service -StartupType Disabled
                    Write-Host "Disabled service: $service" -ForegroundColor Green
                } catch {
                    Write-Host "Failed to disable service ${service}: ${_}" -ForegroundColor Red
                }
            }
        }
    }
}

# ====== App Removal ======
function Remove-BadTools {
    $BadToolNames = @(
        "wireshark","nmap","metasploit","john","hydra","aircrack","kali",
        "netcat","nc.exe","putty","telnet","ftp","steam","epicgameslauncher",
        "discord","vlc","obs","spotify","ccleaner","bleachbit","minecraft"
    )

    # Appx/UWP removal
    try {
        $appxPkgs = Get-AppxPackage -ErrorAction SilentlyContinue
        foreach ($tool in $BadToolNames) {
            $matches = $appxPkgs | Where-Object { $_.Name -match $tool }
            foreach ($pkg in $matches) {
                $display = "$($pkg.Name) ($($pkg.PackageFullName))"
                Write-Host "Found Appx package: $display" -ForegroundColor Yellow
                if (Confirm-Action "Remove Appx package $display?") {
                    Remove-AppxPackage -Package $pkg.PackageFullName
                    Write-Host "Removed Appx package: $display" -ForegroundColor Green
                }
            }
        }
    } catch {
        Write-Host "Appx package scan failed: $_" -ForegroundColor Red
    }

    # Win32 app removal
    try {
        $packages = Get-Package -ErrorAction SilentlyContinue
        foreach ($tool in $BadToolNames) {
            $candidates = $packages | Where-Object { $_.Name -match $tool -or ($_.DisplayName -match $tool) }
            foreach ($pkg in $candidates) {
                $name = $pkg.Name
                Write-Host "Found installed Win32 app: $name" -ForegroundColor Yellow
                if (Confirm-Action "Uninstall '$name' now?") {
                    Uninstall-Package -Name $name -Force
                    Write-Host "Uninstalled package: $name" -ForegroundColor Green
                }
            }
        }
    } catch {
        Write-Host "Win32 package scan failed: $_" -ForegroundColor Red
    }
}

# ====== Password & Account Lockout Policy ======
function Configure-PasswordPolicy {
    if (Confirm-Action "Apply password complexity and lockout policies?") {
        try {
            secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
            (Get-Content "$env:TEMP\secpol.cfg") |
                ForEach-Object {
                    $_ -replace "PasswordComplexity = 0", "PasswordComplexity = 1" `
                       -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 12" `
                       -replace "LockoutBadCount = \d+", "LockoutBadCount = 5" `
                       -replace "ResetLockoutCount = \d+", "ResetLockoutCount = 30" `
                       -replace "LockoutDuration = \d+", "LockoutDuration = 30"
                } | Set-Content "$env:TEMP\secpol.cfg"
            secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
            Remove-Item "$env:TEMP\secpol.cfg" -Force
            Write-Host "Password complexity and lockout policies applied" -ForegroundColor Green
        } catch {
            Write-Host "Failed to configure password policy: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped password and lockout policy." -ForegroundColor Yellow
    }
}

# ====== Firewall Hardening ======
function Harden-Firewall {
    if (Confirm-Action "Enable Windows Firewall for all profiles?") {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            Write-Host "Firewall enabled for Domain, Private, and Public profiles" -ForegroundColor Green
        } catch {
            Write-Host "Failed to enable firewall: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped enabling firewall." -ForegroundColor Yellow
    }

    if (Confirm-Action "Block all inbound connections by default?") {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
            Write-Host "Default inbound action set to Block for all profiles" -ForegroundColor Green
        } catch {
            Write-Host "Failed to set inbound blocking: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped setting inbound block." -ForegroundColor Yellow
    }

    if (Confirm-Action "Log dropped packets and successful connections?") {
        try {
            Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            Write-Host "Firewall logging enabled" -ForegroundColor Green
        } catch {
            Write-Host "Failed to enable firewall logging: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped enabling firewall logging." -ForegroundColor Yellow
    }
}

# ====== Best Practices ======
function Apply-BestPractices {
    if (Confirm-Action "Disable Guest account?") {
        try {
            Disable-LocalUser -Name "Guest"
            Write-Host "Guest account disabled" -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable Guest account: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped disabling Guest account." -ForegroundColor Yellow
    }

    if (Confirm-Action "Disable built-in Administrator account (RID 500)?") {
        try {
            Disable-LocalUser -Name "Administrator"
            Write-Host "Built-in Administrator account disabled" -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable built-in Administrator: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped disabling built-in Administrator." -ForegroundColor Yellow
    }

    if (Confirm-Action "Disable PowerShell remoting?") {
        try {
            Disable-PSRemoting -Force
            Write-Host "PowerShell remoting disabled" -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable PS remoting: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped disabling PowerShell remoting." -ForegroundColor Yellow
    }

    if (Confirm-Action "Disable AutoPlay/AutoRun?") {
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
            Write-Host "AutoPlay/AutoRun disabled" -ForegroundColor Green
        } catch {
            Write-Host "Failed to disable AutoPlay/AutoRun: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Skipped disabling AutoPlay/AutoRun." -ForegroundColor Yellow
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Write-Host "Secure Boot status: $secureBoot" -ForegroundColor Cyan
    } catch {
        Write-Host "Secure Boot check not supported on this system" -ForegroundColor Yellow
    }
}

# ====== Remove Unused Windows Features ======
function Remove-UnusedWindowsFeatures {
    $UnusedFeatures = @(
        "XPS Viewer","Internet-Explorer-Optional-amd64","SMB1Protocol","Removable Storage Management"
    )
    foreach ($feature in $UnusedFeatures) {
        $state = Get-WindowsOptionalFeature -FeatureName $feature -Online -ErrorAction SilentlyContinue
        if ($state.State -eq "Enabled") {
            Write-Host "Windows Feature enabled: $feature" -ForegroundColor Yellow
            if (Confirm-Action "Disable/Remove Windows Feature '$feature'?") {
                Disable-WindowsOptionalFeature -FeatureName $feature -Online
                Write-Host "Disabled Windows Feature: $feature" -ForegroundColor Green
            }
        }
    }
}

# ====== Disable Unused Network Adapters ======
function Disable-UnusedNetworkAdapters {
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notmatch "Ethernet|Wi-Fi" }
    foreach ($adapter in $adapters) {
        Write-Host "Unused network adapter detected: $($adapter.Name)" -ForegroundColor Yellow
        if (Confirm-Action "Disable network adapter '$($adapter.Name)'?") {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false
            Write-Host "Disabled network adapter: $($adapter.Name)" -ForegroundColor Green
        }
    }
}

# ====== Block All Outbound Firewall Traffic ======
function Harden-FirewallOutbound {
    if (Confirm-Action "Block all outbound firewall connections by default (except needed traffic)?") {
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
        Write-Host "Default outbound action set to Block for all profiles" -ForegroundColor Green
    } else {
        Write-Host "Skipped outbound firewall blocking." -ForegroundColor Yellow
    }
}

# ====== Remove Custom Firewall Rules ======
function Remove-CustomFirewallRules {
    $customRules = Get-NetFirewallRule | Where-Object { $_.Group -ne "Windows Firewall" }
    foreach ($rule in $customRules) {
        Write-Host "Custom firewall rule detected: $($rule.Name)" -ForegroundColor Yellow
        if (Confirm-Action "Delete custom firewall rule '$($rule.Name)'?") {
            Remove-NetFirewallRule -Name $rule.Name
            Write-Host "Removed firewall rule: $($rule.Name)" -ForegroundColor Green
        }
    }
}

# ====== Enable Automatic Updates ======
function Enable-AutomaticUpdates {
    if (Confirm-Action "Enable automatic updates for Windows?") {
        Set-Service -Name wuauserv -StartupType Automatic
        Write-Host "Automatic updates enabled." -ForegroundColor Green
    } else {
        Write-Host "Skipped enabling automatic updates." -ForegroundColor Yellow
    }
}

# ====== Check Defender Status and Run Quick Scan ======
function Check-AVAndScan {
    $defender = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($defender -and $defender.Status -eq "Running") {
        Write-Host "Windows Defender is running." -ForegroundColor Green
        if (Confirm-Action "Run a quick antivirus scan with Windows Defender?") {
            Start-MpScan -ScanType QuickScan
            Write-Host "Quick Defender scan started." -ForegroundColor Green
        }
    } else {
        Write-Host "Windows Defender is NOT running!" -ForegroundColor Red
    }
}

# ====== Remove Scheduled Tasks ======
function Remove-BadScheduledTasks {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -match 'Update|Game|Remote|Utility|Chat|Cleaner' }
    foreach ($task in $tasks) {
        Write-Host "Suspicious scheduled task: $($_.TaskName)" -ForegroundColor Yellow
        if (Confirm-Action "Delete scheduled task '$($_.TaskName)'?") {
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
            Write-Host "Removed scheduled task: $($_.TaskName)" -ForegroundColor Green
        }
    }
}

# ====== Set UAC to Highest Security ======
function Harden-UAC {
    if (Confirm-Action "Set User Account Control (UAC) to highest security?") {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "ConsentPromptBehaviorAdmin" -Value 2
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "EnableLUA" -Value 1
        Write-Host "UAC set to highest security level." -ForegroundColor Green
    } else {
        Write-Host "Skipped changing UAC settings." -ForegroundColor Yellow
    }
}

# ====== Print Final Scoring/Safety Checklist ======
function Print-ActionSummary {
    Write-Host "`n=== End of Hardening Script ===" -ForegroundColor Cyan
    Write-Host "Checklist for points and safety review:" -ForegroundColor Magenta
    Write-Host "- Extra admin/hidden/guest/local accounts"
    Write-Host "- Unused software in Program Files folders"
    Write-Host "- Remaining scheduled tasks and service list"
    Write-Host "- Local Group Policy Editor for sanctioned policies"
    Write-Host "- Confirm Defender reports zero threats"
    Write-Host "`nKeep this window open for scoring documentation!"
}

# ====== Run All Steps ======
Write-Host "=== Starting Windows Hardening Script ===" -ForegroundColor Cyan
Enable-AllAudits
Manage-Users
Harden-Services
Remove-BadTools
Configure-PasswordPolicy
Harden-Firewall
Apply-BestPractices
Remove-UnusedWindowsFeatures
Disable-UnusedNetworkAdapters
Harden-FirewallOutbound
Remove-CustomFirewallRules
Enable-AutomaticUpdates
Check-AVAndScan
Remove-BadScheduledTasks
Harden-UAC
Print-ActionSummary
Write-Host "=== Finished Windows Hardening Script ===" -ForegroundColor Cyan
