<#
.SYNOPSIS
    CyberPatriot Windows Hardening Script - Prompt-Driven Safe Mode
.DESCRIPTION
    Hardens Windows systems by enforcing user/account policies, audit policies, firewall rules,
    service & app hardening, password policies, and other best practices.
    Always prompts before making changes.
    Reads authorized users and admins from "Users.txt" in the script directory.
#>

# ====== Initialization ======
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$UserListPath = Join-Path $ScriptDir "Users.txt"
$LogPath = Join-Path $ScriptDir "secure_windows.log"
$Summary = @()

# Initialize log file
if (Test-Path $LogPath) { Remove-Item $LogPath -Force }
Write-Output "=== Script started ===" | Out-File $LogPath

# ====== Logging Function ======
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $entry = "[$Level] $Message"
    $global:Summary += @{ Level = $Level; Message = $Message }
    Write-Output $entry | Tee-Object -FilePath $LogPath -Append
}

# ====== Prompt Function ======
function Confirm-Action {
    param([string]$Message)
    Write-Host "$Message (Y/N)" -ForegroundColor Yellow
    $choice = Read-Host
    return ($choice -match '^(y|yes)$')
}

# ====== Audit Policy Enforcement ======
function Enable-AllAudits {
    Write-Log "Preparing to enable all Success/Failure audit policies" "ACTION"
    if (Confirm-Action "Apply audit policy changes (all success/failure events)?") {
        try {
            auditpol /set /category:* /success:enable /failure:enable | Out-Null
            Write-Log "All audit categories set to Success and Failure" "INFO"
        } catch {
            Write-Log "Failed to configure audit policies - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped applying audit policy changes" "INFO"
    }
}

# ====== User Management ======
function Manage-Users {
    if (-not (Test-Path $UserListPath)) {
        Write-Log "User list file not found: $UserListPath" "ERROR"
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
                    Write-Log "Added missing user: $user" "ACTION"
                } catch {
                    Write-Log "Failed to add user $user - $_" "ERROR"
                }
            } else {
                Write-Log "Skipped adding user: $user" "INFO"
            }
        }
    }

    # Remove unauthorized users
    foreach ($user in $localUsers) {
        if (-not $authorizedUsers.ContainsKey($user)) {
            if (Confirm-Action "User '$user' is not authorized. Remove?") {
                try {
                    Remove-LocalUser -Name $user
                    Write-Log "Removed unauthorized user: $user" "ACTION"
                } catch {
                    Write-Log "Failed to remove user $user - $_" "ERROR"
                }
            } else {
                Write-Log "Skipped removing unauthorized user: $user" "INFO"
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
                    Write-Log "Granted admin rights to $user" "ACTION"
                } catch {
                    Write-Log "Failed to add admin rights to $user - $_" "ERROR"
                }
            } else {
                Write-Log "Skipped granting admin rights to $user" "INFO"
            }
        } elseif (-not $shouldBeAdmin -and $isAdmin) {
            if (Confirm-Action "User '$user' should NOT be admin. Remove from Administrators?") {
                try {
                    Remove-LocalGroupMember -Group "Administrators" -Member $user
                    Write-Log "Removed admin rights from $user" "ACTION"
                } catch {
                    Write-Log "Failed to remove admin rights from $user - $_" "ERROR"
                }
            } else {
                Write-Log "Skipped removing admin rights from $user" "INFO"
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
            Write-Log "Service detected: $service (Status: $($svc.Status))" "WARN"
            if (Confirm-Action "Disable and stop service $service?") {
                try {
                    Stop-Service -Name $service -Force
                    Set-Service -Name $service -StartupType Disabled
                    Write-Log "Disabled service: $service" "ACTION"
                } catch {
                    Write-Log "Failed to disable service $service - $_" "ERROR"
                }
            } else {
                Write-Log "Skipped disabling service: $service" "INFO"
            }
        }
    }
}

function Remove-BadTools {
    # Names/patterns to look for (case-insensitive regex)
  $BadToolNames = @(
    # Hacking / pen-testing tools
    "wireshark","nmap","metasploit","john","hydra","aircrack","kali","netcat","nc.exe","putty","telnet","ftp","curl","wget","python","php","ruby","perl",
    # System cleaners / potentially unwanted tools
    "ccleaner","bleachbit",
    # Media / games / chat apps
    "steam","epicgameslauncher","minecraft","discord","vlc","obs","spotify"
)

    Write-Log "Scanning for suspicious Appx and classic applications..." "ACTION"

    # ----- Appx packages -----
    try {
        $appxPkgs = Get-AppxPackage -ErrorAction SilentlyContinue
        foreach ($tool in $BadToolNames) {
            $matches = $appxPkgs | Where-Object { $_.Name -match $tool }
            foreach ($pkg in $matches) {
                $display = "$($pkg.Name) ($($pkg.PackageFullName))"
                Write-Log "Found Appx package: $display" "WARN"
                if (Confirm-Action "Remove Appx package $display?") {
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                        Write-Log "Removed Appx package: $display" "ACTION"
                    } catch {
                        Write-Log "Failed to remove Appx package $display - $_" "ERROR"
                    }
                } else {
                    Write-Log "Skipped Appx package: $display" "INFO"
                }
            }
        }
    } catch {
        Write-Log "Appx package scan failed - $_" "ERROR"
    }

    # ----- Classic (Win32) applications via registry uninstall keys -----
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $classicApps = @()
    foreach ($path in $uninstallPaths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Select-Object DisplayName, UninstallString, QuietUninstallString, InstallLocation
            $classicApps += $items
        } catch {
            # Continue even if one hive is not accessible
        }
    }

    foreach ($tool in $BadToolNames) {
        $candidates = $classicApps | Where-Object { $_.DisplayName -and ($_.DisplayName -match $tool) } | Sort-Object DisplayName -Unique
        foreach ($app in $candidates) {
            $name = $app.DisplayName
            $uninstall = $app.UninstallString
            $quiet = $app.QuietUninstallString
            $installLoc = $app.InstallLocation

            Write-Log "Found classic app: $name" "WARN"
            if (-not $uninstall -and -not $quiet) {
                Write-Log "No uninstall command found for $name; skipping automatic uninstall" "ERROR"
                if (Confirm-Action "No automatic uninstaller found for '$name'. Open Control Panel > Programs and Features to uninstall manually?") {
                    Start-Process "appwiz.cpl"
                    Write-Log "Opened Programs and Features for manual uninstall of $name" "INFO"
                } else {
                    Write-Log "User skipped manual uninstall prompt for $name" "INFO"
                }
                continue
            }

            if (Confirm-Action "Uninstall '$name' now?") {
                # Prefer quiet uninstall string if present
                $toRun = if ($quiet) { $quiet } else { $uninstall }

                # If the string references msiexec with a GUID, extract GUID
                if ($toRun -match "Msi[Ee]xec.*\{(?<guid>[0-9A-Fa-f\-]+)\}") {
                    $guid = $Matches['guid']
                    $msiArgs = "/x {$guid} /qn /norestart"
                    try {
                        Write-Log "Attempting silent MSI uninstall for $name (GUID: {$guid})" "ACTION"
                        Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
                        Write-Log "msiexec returned for $name (GUID: {$guid})" "INFO"
                    } catch {
                        Write-Log "msiexec uninstall failed for $name - $_" "ERROR"
                    }
                } else {
                    # Try to parse an executable path and args
                    $exe = $null; $args = $null
                    if ($toRun -match '^"(?<exe>[^"]+)"\s*(?<args>.*)$') {
                        $exe = $Matches['exe']
                        $args = $Matches['args']
                    } elseif ($toRun -match '^(?<exe>\S+)\s*(?<args>.*)$') {
                        $exe = $Matches['exe']
                        $args = $Matches['args']
                    }

                    if ($exe) {
                        # If path is relative or contains msiexec, normalize
                        try {
                            # If file exists, try to stop any running processes that point to that file
                            if (Test-Path $exe) {
                                $running = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                                    ($_.Path -and ($_.Path -eq $exe)) -or ($_.ProcessName -and $exe -match $_.ProcessName)
                                }
                                foreach ($p in $running) {
                                    try {
                                        Write-Log "Stopping running process $($p.ProcessName) (Id $($p.Id)) before uninstall" "ACTION"
                                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                                    } catch {
                                        Write-Log "Failed to stop process $($p.ProcessName) - $_" "WARN"
                                    }
                                }
                            }
                        } catch {
                            # ignore process stopping errors
                        }

                        # Try to add common silent args if none supplied (best-effort)
                        if (-not $args -or $args.Trim() -eq "") {
                            # Many uninstallers support /S, /quiet, or /silent; try /S then /quiet
                            $trialArgs = @("/S","/quiet","/silent")
                        } else {
                            $trialArgs = @($args)
                        }

                        $uninstalled = $false
                        foreach ($tryArgs in $trialArgs) {
                            try {
                                Write-Log "Running uninstaller: $exe $tryArgs" "ACTION"
                                Start-Process -FilePath $exe -ArgumentList $tryArgs -Wait -NoNewWindow -ErrorAction Stop
                                Start-Sleep -Seconds 1
                                Write-Log "Uninstaller finished for $name with args: $tryArgs" "INFO"
                                $uninstalled = $true
                                break
                            } catch {
                                Write-Log "Uninstaller attempt failed for $name with args '$tryArgs' - $_" "WARN"
                            }
                        }

                        if (-not $uninstalled) {
                            # Final attempt: run the original uninstall string as-is (may include its own args)
                            try {
                                Write-Log "Attempting uninstall with original command string for $name" "ACTION"
                                # Use cmd /c to allow complex uninstall strings
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $toRun -Wait -NoNewWindow -ErrorAction Stop
                                Write-Log "Original uninstall command executed for $name" "INFO"
                            } catch {
                                Write-Log "Failed to execute original uninstall command for $name - $_" "ERROR"
                            }
                        }
                    } else {
                        Write-Log "Could not parse uninstall command for $name: $toRun" "ERROR"
                    }
                }

                # After attempting uninstall, provide a moment and optionally check if the DisplayName still exists
                Start-Sleep -Seconds 2
                $stillInstalled = $false
                try {
                    $stillInstalled = (Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $name }) -ne $null
                } catch {
                    $stillInstalled = $true
                }

                if (-not $stillInstalled) {
                    Write-Log "Confirmed: $name appears removed (or no longer present in registry uninstall entries)" "ACTION"
                } else {
                    Write-Log "Warning: $name still appears present after uninstall attempt. Manual removal may be required." "WARN"
                }
            } else {
                Write-Log "Skipped uninstall for $name" "INFO"
            }
        }
    }

    Write-Log "Finished scanning/uninstall attempts for suspicious applications." "INFO"
}

# ====== Password & Account Lockout Policy ======
function Configure-PasswordPolicy {
    Write-Log "Preparing to configure password complexity and account lockout policies" "ACTION"
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
            Write-Log "Password complexity and lockout policies applied" "INFO"
        } catch {
            Write-Log "Failed to configure password policy - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped applying password and lockout policy" "INFO"
    }
}

# ====== Firewall Hardening ======
function Harden-Firewall {
    Write-Log "Preparing to configure Windows Firewall" "ACTION"

    if (Confirm-Action "Enable Windows Firewall for all profiles?") {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            Write-Log "Firewall enabled for Domain, Private, and Public profiles" "INFO"
        } catch {
            Write-Log "Failed to enable firewall - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped enabling firewall" "INFO"
    }

    if (Confirm-Action "Block all inbound connections by default?") {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
            Write-Log "Default inbound action set to Block for all profiles" "INFO"
        } catch {
            Write-Log "Failed to set inbound blocking - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped setting inbound block" "INFO"
    }

    if (Confirm-Action "Log dropped packets and successful connections?") {
        try {
            Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
            Write-Log "Firewall logging enabled" "INFO"
        } catch {
            Write-Log "Failed to enable firewall logging - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped enabling firewall logging" "INFO"
    }
}

# ====== Best Practices ======
function Apply-BestPractices {
    Write-Log "Preparing to apply Windows security best practices" "ACTION"

    if (Confirm-Action "Disable Guest account?") {
        try {
            Disable-LocalUser -Name "Guest"
            Write-Log "Guest account disabled" "INFO"
        } catch {
            Write-Log "Failed to disable Guest account - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped disabling Guest account" "INFO"
    }

    if (Confirm-Action "Disable built-in Administrator account (RID 500)?") {
        try {
            Disable-LocalUser -Name "Administrator"
            Write-Log "Built-in Administrator account disabled" "INFO"
        } catch {
            Write-Log "Failed to disable built-in Administrator - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped disabling built-in Administrator" "INFO"
    }

    if (Confirm-Action "Disable PowerShell remoting?") {
        try {
            Disable-PSRemoting -Force
            Write-Log "PowerShell remoting disabled" "INFO"
        } catch {
            Write-Log "Failed to disable PS remoting - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped disabling PowerShell remoting" "INFO"
    }

    if (Confirm-Action "Disable AutoPlay/AutoRun?") {
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
            Write-Log "AutoPlay/AutoRun disabled" "INFO"
        } catch {
            Write-Log "Failed to disable AutoPlay/AutoRun - $_" "ERROR"
        }
    } else {
        Write-Log "Skipped disabling AutoPlay/AutoRun" "INFO"
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        Write-Log "Secure Boot status: $secureBoot" "INFO"
    } catch {
        Write-Log "Secure Boot check not supported on this system" "WARN"
    }
}

# ====== Summary Report ======
function Print-Summary {
    $actions = $Summary | Where-Object { $_.Level -eq "ACTION" }
    $skips = $Summary | Where-Object { $_.Level -eq "INFO" -and $_.Message -match 'Skipped' }
    $errors = $Summary | Where-Object { $_.Level -eq "ERROR" }

    Write-Host "`n=== Summary Report ===" -ForegroundColor Cyan
    Write-Host "Actions taken: $($actions.Count)"
    Write-Host "Actions skipped: $($skips.Count)"
    Write-Host "Errors: $($errors.Count)`n"

    if ($actions.Count -gt 0) {
        Write-Host "Actions:" -ForegroundColor Green
        $actions | ForEach-Object { Write-Host "- $($_.Message)" }
    }

    if ($errors.Count -gt 0) {
        Write-Host "`nErrors:" -ForegroundColor Red
        $errors | ForEach-Object { Write-Host "- $($_.Message)" }
    }
}

# ====== Run All Steps ======
Write-Log "=== Starting Windows Hardening Script ==="
Enable-AllAudits
Manage-Users
Harden-Services
Remove-BadTools
Configure-PasswordPolicy
Harden-Firewall
Apply-BestPractices
Write-Log "=== Finished Windows Hardening Script ==="
Print-Summary
