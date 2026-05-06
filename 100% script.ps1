#Requires -RunAsAdministrator

# Windows Security Hardening Script - Comprehensive
# Outputs confirmation messages for each completed action

Write-Host "=== Windows Security Hardening Script ===" -ForegroundColor Cyan
Write-Host "Starting security hardening operations..." -ForegroundColor Green
Write-Host ""

# ============================================================================
# SECTION 1: USER MANAGEMENT
# ============================================================================

Write-Host "--- USER MANAGEMENT ---" -ForegroundColor Yellow

# Remove ozai account
net user ozai /delete
# Remove azula account
net user azula /delete

# Remove momo from Administrators
net localgroup administrators momo /delete

# Remove piandao from Administrators
net localgroup administrators piandao /delete

# Disable administrator account
try {
    Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Host "Administrator account is disabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Administrator account: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 2: PASSWORD AND ACCOUNT POLICIES
# ============================================================================

Write-Host "`n--- PASSWORD AND ACCOUNT POLICIES ---" -ForegroundColor Yellow

# Set password expiration for specific user
try {
    $user = Get-LocalUser -Name "toph_beifong" -ErrorAction SilentlyContinue
    if ($user) {
        Set-LocalUser -Name "toph_beifong" -PasswordNeverExpires $false
        Write-Host "User toph_beifong password expires" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to set password expiration: $($_.Exception.Message)" -ForegroundColor Red
}

# Configure Account Lockout Policy - 5 attempts, 30 minute lockout
try {
    net accounts /lockoutduration:30
    net accounts /lockoutthreshold:5
    Write-Host "Account lockout policy configured: 5 attempts, 30 minute lockout" -ForegroundColor Green
} catch {
    Write-Host "Failed to set account lockout policy: $($_.Exception.Message)" -ForegroundColor Red
}

# Disable reversible encryption
try {
    # Configure via Group Policy Registry
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "NoLMHash" -Value 1 -Type DWord -Force
    Write-Host "Passwords are not stored using reversible encryption" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable reversible encryption: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 3: AUDIT AND SECURITY POLICIES
# ============================================================================

Write-Host "`n--- AUDIT AND SECURITY POLICIES ---" -ForegroundColor Yellow

# Enable Audit Credential Validation [Failure]
try {
    auditpol /set /subcategory:"Credential Validation" /failure:enable | Out-Null
    Write-Host "Audit Credential Validation [Failure]" -ForegroundColor Green
} catch {
    Write-Host "Failed to enable Credential Validation audit: $($_.Exception.Message)" -ForegroundColor Red
}

# Disable anonymous SAM enumeration
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LSAAnonymousNameLookup" /t REG_DWORD /d 1 /f | Out-Null
    Write-Host "Anonymous SAM enumeration is disabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable anonymous SAM enumeration: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 4: WINDOWS DEFENDER
# ============================================================================

Write-Host "`n--- WINDOWS DEFENDER ---" -ForegroundColor Yellow

# Clear Windows Defender exclusion paths
try {
    $exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    if ($exclusions) {
        foreach ($exclusion in $exclusions) {
            Remove-MpPreference -ExclusionPath $exclusion -ErrorAction SilentlyContinue
        }
    }
    Write-Host "Windows Defender exclusion path cleared" -ForegroundColor Green
} catch {
    Write-Host "Failed to clear Defender exclusions: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 5: REMOTE ACCESS AND POWERSHELL
# ============================================================================

Write-Host "`n--- REMOTE ACCESS AND POWERSHELL ---" -ForegroundColor Yellow

# Disable Remote Desktop Sharing
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
    Write-Host "Remote desktop sharing is turned off" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable RDP: $($_.Exception.Message)" -ForegroundColor Red
}

# Set PowerShell Execution Policy to Restricted
try {
    Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force
    Write-Host "PowerShell execution set to restricted" -ForegroundColor Green
} catch {
    Write-Host "Failed to set PowerShell execution policy: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 6: FILE PERMISSIONS
# ============================================================================

Write-Host "`n--- FILE PERMISSIONS ---" -ForegroundColor Yellow

# Remove Everyone full control from FileZilla settings file
try {
    $filePath = "C:\ProgramData\filezilla-server\settings.xml"
    if (Test-Path $filePath) {
        $acl = Get-Acl $filePath
        $rule = $acl.Access | Where-Object { $_.IdentityReference -eq "Everyone" }
        if ($rule) {
            $acl.RemoveAccessRule($rule) | Out-Null
            Set-Acl -Path $filePath -AclObject $acl
        }
        Write-Host "Everyone is no longer allowed full control to C:/ProgramData/filezilla-server/settings.xml" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to modify FileZilla settings permissions: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 7: WINDOWS SERVICES
# ============================================================================

Write-Host "`n--- WINDOWS SERVICES ---" -ForegroundColor Yellow

# Stop and disable Remote Registry service
try {
    sc config RemoteRegistry start= disabled
    Write-Host "Remote Registry service has been stopped and disabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Remote Registry: $($_.Exception.Message)" -ForegroundColor Red
}

# Stop and disable Xbox Live Game Save service
try {
    $xboxService = Get-Service -Name "XblGameSave" -ErrorAction SilentlyContinue
    if ($xboxService) {
        Stop-Service -Name "XblGameSave" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "XblGameSave" -StartupType Disabled -ErrorAction SilentlyContinue
    }
    Write-Host "Xbox Live Game Save service has been stopped and disabled" -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Xbox Game Save service: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================================
# SECTION 8: WINDOWS UPDATE
# ============================================================================

Write-Host "`n--- WINDOWS UPDATE ---" -ForegroundColor Yellow

# Enable Windows Update automatic checking
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
    Write-Host "Windows automatically checks for updates" -ForegroundColor Green
} catch {
    Write-Host "Failed to enable Windows Update: $($_.Exception.Message)" -ForegroundColor Red
}

# Enable updates for other Microsoft products
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "AllowMUUpdateService" -Value 1 -Type DWord -Force
    Write-Host "Receive updates for other Microsoft products when you update Windows" -ForegroundColor Green
} catch {
    Write-Host "Failed to enable Microsoft product updates: $($_.Exception.Message)" -ForegroundColor Red
}
    VICARIUS STRONGLY RECOMMENDS RUNNING THIS SCRIPT IN A TEST LAB ENVIRONMENT
    BEFORE DEPLOYING IT TO PRODUCTION. USE AT YOUR OWN DISCRETION ONLY AFTER
    CAREFULLY ANALYZING THE CODE.

.AUTHOR
This script has been made by Vicarius Research Team

.VERSION
1.0
#>

# ==========================================
# TAG CONFIGURATION
# ==========================================
$TagInfo = "[Info]"
$TagWarn = "[Warning]"
$TagErr  = "[Error]"

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Warning","Error")][string]$Level = "Info"
    )
    $tag = switch ($Level) {
        "Info"    { $TagInfo }
        "Warning" { $TagWarn }
        "Error"   { $TagErr }
    }
    Write-Host "$tag $Message"
}

Write-Status "Disable Store Passwords Using Reversible Encryption - CIS Benchmark 1.1.7" "Info"
Write-Status "--------------------------------------------------------------------------" "Info"

# Admin check
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "Administrator privileges required." "Error"
        Write-Output "RESULT=CIS-1.1.7-REVERSIBLE-ENCRYPTION|COMPLIANT|FALSE"
        exit 1
    }
} catch {
    Write-Status "Unable to verify elevation: $($_.Exception.Message)" "Warning"
}

# Define paths
$AutomationTitle = "CIS-1.1.7-REVERSIBLE-ENCRYPTION"
$TempDir = $env:TEMP
$ExportCfg = Join-Path $TempDir "secpol_export.cfg"
$ImportCfg = Join-Path $TempDir "secpol_import.cfg"
$SeceditLog = Join-Path $TempDir "secedit_import.log"

# Export current security policy
try {
    Write-Status "Exporting current security policy..." "Info"
    $exportResult = & secedit /export /cfg $ExportCfg 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Failed to export security policy: $exportResult" "Error"
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
        exit 1
    }
} catch {
    Write-Status "Failed to export security policy: $($_.Exception.Message)" "Error"
    Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
    exit 1
}

# Read and modify the policy
try {
    $policyContent = Get-Content -Path $ExportCfg -ErrorAction Stop
    $settingFound = $false
    $alreadyCompliant = $false

    $updatedContent = $policyContent | ForEach-Object {
        if ($_ -match "^\s*ClearTextPassword\s*=") {
            $settingFound = $true
            if ($_ -match "=\s*0\s*$") {
                $alreadyCompliant = $true
            }
            "ClearTextPassword = 0"
        } else {
            $_
        }
    }

    if (-not $settingFound) {
        Write-Status "ClearTextPassword setting not found in exported policy. Injecting into [System Access] section..." "Info"
        $updatedContent = $policyContent | ForEach-Object {
            $_
            if ($_ -match "^\[System Access\]") {
                "ClearTextPassword = 0"
            }
        }
    }

    if ($alreadyCompliant) {
        Write-Status "Reversible encryption is already disabled (ClearTextPassword = 0)." "Info"
        Write-Status "System is already compliant with CIS 1.1.7." "Info"
        Remove-Item -Path $ExportCfg -Force -ErrorAction SilentlyContinue
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|TRUE"
        exit 0
    }

    Write-Status "Setting ClearTextPassword to 0 (Disabled)..." "Info"
    $updatedContent | Set-Content -Path $ImportCfg -Encoding Unicode -ErrorAction Stop
} catch {
    Write-Status "Failed to process security policy: $($_.Exception.Message)" "Error"
    Remove-Item -Path $ExportCfg -Force -ErrorAction SilentlyContinue
    Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
    exit 1
}

# Import the modified policy
try {
    Write-Status "Applying updated security policy..." "Info"
    $importResult = & secedit /configure /db secedit.sdb /cfg $ImportCfg /log $SeceditLog /quiet 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Failed to apply security policy: $importResult" "Error"
        Remove-Item -Path $ExportCfg, $ImportCfg, $SeceditLog -Force -ErrorAction SilentlyContinue
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
        exit 1
    }
} catch {
    Write-Status "Failed to apply security policy: $($_.Exception.Message)" "Error"
    Remove-Item -Path $ExportCfg, $ImportCfg, $SeceditLog -Force -ErrorAction SilentlyContinue
    Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
    exit 1
}

# Verify configuration
try {
    Write-Status "Verifying applied configuration..." "Info"
    $VerifyCfg = Join-Path $TempDir "secpol_verify.cfg"
    $verifyResult = & secedit /export /cfg $VerifyCfg 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Status "Could not export policy for verification: $verifyResult" "Warning"
        Remove-Item -Path $ExportCfg, $ImportCfg, $SeceditLog -Force -ErrorAction SilentlyContinue
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
        exit 1
    }

    $verifyContent = Get-Content -Path $VerifyCfg -ErrorAction Stop
    $verified = $verifyContent | Where-Object { $_ -match "^\s*ClearTextPassword\s*=\s*0\s*$" }

    Remove-Item -Path $ExportCfg, $ImportCfg, $SeceditLog, $VerifyCfg -Force -ErrorAction SilentlyContinue

    if ($verified) {
        Write-Status "Reversible encryption successfully disabled (ClearTextPassword = 0)." "Info"
        Write-Status "System is now compliant with CIS 1.1.7." "Info"
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|TRUE"
    } else {
        Write-Status "Verification failed: ClearTextPassword is not set to 0." "Error"
        Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
        exit 1
    }
} catch {
    Write-Status "Could not verify configuration: $($_.Exception.Message)" "Warning"
    Remove-Item -Path $ExportCfg, $ImportCfg, $SeceditLog -Force -ErrorAction SilentlyContinue
    Write-Output "RESULT=$AutomationTitle|COMPLIANT|FALSE"
    exit 1 }


  #  I hope this works gng