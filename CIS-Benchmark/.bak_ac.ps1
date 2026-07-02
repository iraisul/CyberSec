#Requires -Version 5.1
<#
================================================================================
 Invoke-CISWin11GapAssessment.ps1
--------------------------------------------------------------------------------
 CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0 - Level 1 (L1)
 Automated Configuration Gap Assessment & Risk Report Generator

 PURPOSE
   Read-only assessment of a Windows 11 host against a curated, high-impact
   set of CIS Level 1 controls. Produces a professional HTML report and a
   management-ready PDF containing:
     - Executive summary and compliance posture
     - Per-control PASS/FAIL/MANUAL results (current value vs. CIS expected)
     - Risk, impact, likelihood, risk score, and severity for each gap
     - Exploit / Proof-of-Concept availability and MITRE ATT&CK mapping
     - 5x5 Likelihood x Impact risk matrix (heat map)
     - Prioritised remediation guidance (GPO path + registry command)

 AUTHOR   : Offensive Security Team
 SCOPE    : Single Windows 11 Pro host (stand-alone / lab)
 PROFILE  : CIS Benchmark v5.0.0, Level 1
 MODE     : READ-ONLY. This script does NOT change any configuration.

 REQUIREMENTS
   - Run in an ELEVATED PowerShell session (Run as Administrator).
     secedit / auditpol and several registry hives require admin rights.
   - Windows PowerShell 5.1 or PowerShell 7+.
   - Microsoft Edge (present by default on Windows 11) for PDF export.

 USAGE
   powershell -ExecutionPolicy Bypass -File .\Invoke-CISWin11GapAssessment.ps1
   .\Invoke-CISWin11GapAssessment.ps1 -OutputFolder 'C:\CIS_Report' -OpenReport
   .\Invoke-CISWin11GapAssessment.ps1 -SkipPdf          # HTML only

 DISCLAIMER
   Curated subset of the benchmark for prioritised, offensive-security-relevant
   coverage. It is not a substitute for a full CIS-CAT certified scan. Validate
   findings before remediating production systems.
================================================================================
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path $env:USERPROFILE 'Desktop\CIS_Win11_GapAssessment'),
    [switch]$SkipPdf,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# ------------------------------------------------------------------ #
# 0.  Environment / privilege checks
# ------------------------------------------------------------------ #
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "This script is NOT running elevated. secedit / auditpol checks will be reported as ERROR."
    Write-Warning "Re-launch PowerShell 'As Administrator' for complete and accurate results."
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$HtmlPath   = Join-Path $OutputFolder ("CIS_Win11_GapAssessment_{0}.html" -f $stamp)
$PdfPath    = Join-Path $OutputFolder ("CIS_Win11_GapAssessment_{0}.pdf"  -f $stamp)
$CsvPath    = Join-Path $OutputFolder ("CIS_Win11_GapAssessment_{0}.csv"  -f $stamp)

Write-Host "`n=== CIS Windows 11 v5.0.0 (L1) Gap Assessment ===" -ForegroundColor Cyan
Write-Host "Output folder : $OutputFolder"

# ------------------------------------------------------------------ #
# 1.  Data collection helpers (secedit / auditpol snapshots)
# ------------------------------------------------------------------ #
$script:SecPol   = @{}   # [System Access] and [Privilege Rights]
$script:AuditPol = @{}   # subcategory -> setting

function Initialize-SecPol {
    try {
        $inf = Join-Path $env:TEMP ("secpol_{0}.inf" -f (Get-Random))
        secedit /export /cfg $inf /quiet | Out-Null
        $section = ''
        foreach ($line in Get-Content $inf) {
            $t = $line.Trim()
            if ($t -match '^\[(.+)\]$')       { $section = $matches[1]; continue }
            if ($t -match '^(.+?)\s*=\s*(.*)$') {
                $k = $matches[1].Trim(); $v = $matches[2].Trim()
                $script:SecPol["$section::$k"] = $v
            }
        }
        Remove-Item $inf -Force -ErrorAction SilentlyContinue
        $script:SecPolLoaded = $true
    } catch { $script:SecPolLoaded = $false }
}

function Initialize-AuditPol {
    try {
        $csv = auditpol /get /category:* /r 2>$null | ConvertFrom-Csv
        foreach ($row in $csv) {
            if ($row.Subcategory) {
                $script:AuditPol[$row.Subcategory.Trim()] = $row.'Inclusion Setting'.Trim()
            }
        }
        $script:AuditPolLoaded = $true
    } catch { $script:AuditPolLoaded = $false }
}

function Get-RegValue {
    param([string]$Path,[string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }   # $null = value / key absent
}

function Get-ServiceStart {
    param([string]$Name)
    Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'Start'
}

# ------------------------------------------------------------------ #
# 2.  Comparison engine
# ------------------------------------------------------------------ #
function Compare-Value {
    param($Actual,[string]$Op,$Expected)
    $numA = 0.0; $numE = 0.0
    $okA = [double]::TryParse("$Actual",[ref]$numA)
    $okE = [double]::TryParse("$Expected",[ref]$numE)
    switch ($Op) {
        'eq'        { return ("$Actual" -eq "$Expected") -or ($okA -and $okE -and $numA -eq $numE) }
        'ne'        { return "$Actual" -ne "$Expected" }
        'ge'        { return $okA -and $numA -ge $numE }
        'le'        { return $okA -and $numA -le $numE }
        'gt'        { return $okA -and $numA -gt $numE }
        'lt'        { return $okA -and $numA -lt $numE }
        'in'        { return $Expected -contains "$Actual" -or $Expected -contains $Actual }
        'match'     { return "$Actual" -match $Expected }
        'exists'    { return $null -ne $Actual }
        'notexists' { return $null -eq $Actual }
        # nonzero and <= max : "X or fewer but not 0"
        'nzle'      { return $okA -and ($numA -ne 0) -and ($numA -le $numE) }
        # value must be 0 OR >= min
        'zeroOrGe'  { return $okA -and ($numA -eq 0 -or $numA -ge $numE) }
        default     { return $false }
    }
}

# ------------------------------------------------------------------ #
# 3.  Control catalogue
# ------------------------------------------------------------------ #
# Each control carries both the technical check and the risk metadata that the
# management report requires:
#   Type      : Reg | SecPol | AuditPol | Service
#   Impact    : 1-5   business/technical impact if exploited
#   Likelihood: 1-5   probability of exploitation given exposure
#   Poc       : real-world exploit / tooling availability
#   Mitre     : MITRE ATT&CK technique id(s)
# RiskScore = Impact x Likelihood (computed only for FAILED controls).
$script:Controls = New-Object System.Collections.Generic.List[object]

function AC {
    param(
        [string]$Id,[string]$Title,[string]$Section,[string]$Type,
        [string]$Path,[string]$Name,[string]$Op,$Expected,
        [int]$Impact,[int]$Likelihood,[string]$Risk,[string]$Poc,
        [string]$Mitre,[string]$Remediation
    )
    $script:Controls.Add([pscustomobject]@{
        Id=$Id; Title=$Title; Section=$Section; Type=$Type;
        Path=$Path; Name=$Name; Op=$Op; Expected=$Expected;
        Impact=$Impact; Likelihood=$Likelihood; Risk=$Risk; Poc=$Poc;
        Mitre=$Mitre; Remediation=$Remediation
    })
}

$SA  = 'System Access'
$PR  = 'Privilege Rights'
$LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$SYSPOL = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

# ---- 1. Account Policies (secedit / System Access) ----
AC '1.1.1' "Enforce password history >= 24" '1 Account Policies' SecPol "$SA::PasswordHistorySize" '' 'ge' 24 3 3 `
   'Password reuse enables attackers to re-authenticate with previously compromised credentials and undermines forced rotation.' `
   'N/A - policy weakness leveraged after credential capture' 'T1110, T1078' `
   'Computer Config > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > "Enforce password history" = 24.'
AC '1.1.2' "Maximum password age <= 365 and not 0" '1 Account Policies' SecPol "$SA::MaximumPasswordAge" '' 'nzle' 365 3 3 `
   'Passwords that never expire prolong the useful life of any captured credential.' `
   'N/A - extends value of stolen credentials' 'T1078, T1110' `
   'Password Policy > "Maximum password age" = 365 or fewer, not 0.'
AC '1.1.3' "Minimum password age >= 1" '1 Account Policies' SecPol "$SA::MinimumPasswordAge" '' 'ge' 1 2 2 `
   'A zero minimum age lets users cycle through the history to reuse a favourite password immediately.' `
   'N/A' 'T1110' 'Password Policy > "Minimum password age" = 1 or more.'
AC '1.1.4' "Minimum password length >= 14" '1 Account Policies' SecPol "$SA::MinimumPasswordLength" '' 'ge' 14 4 4 `
   'Short passwords fall quickly to offline brute-force / mask attacks against captured NTLM or Kerberos hashes.' `
   'Public - hashcat / John the Ripper offline cracking' 'T1110.002' `
   'Password Policy > "Minimum password length" = 14 or more.'
AC '1.1.5' "Password must meet complexity = Enabled" '1 Account Policies' SecPol "$SA::PasswordComplexity" '' 'eq' 1 4 4 `
   'Without complexity, dictionary and rule-based cracking of captured hashes succeeds far faster.' `
   'Public - hashcat rule attacks' 'T1110.002' 'Password Policy > "Password must meet complexity requirements" = Enabled.'
AC '1.1.7' "Store passwords w/ reversible encryption = Disabled" '1 Account Policies' SecPol "$SA::ClearTextPassword" '' 'eq' 0 5 3 `
   'Reversible encryption is effectively plaintext storage; a SAM/domain compromise yields cleartext passwords.' `
   'Public - trivially decrypted once obtained' 'T1003' 'Password Policy > "Store passwords using reversible encryption" = Disabled.'
AC '1.2.1' "Account lockout duration >= 15 min" '1 Account Policies' SecPol "$SA::LockoutDuration" '' 'ge' 15 2 3 `
   'Short or zero lockout duration reduces the cost of sustained online password guessing.' `
   'Public - password spraying tools' 'T1110.003' 'Account Lockout Policy > "Account lockout duration" = 15 or more.'
AC '1.2.2' "Account lockout threshold 1-5 (not 0)" '1 Account Policies' SecPol "$SA::LockoutBadCount" '' 'nzle' 5 4 4 `
   'A threshold of 0 disables lockout entirely, permitting unlimited online password guessing / spraying.' `
   'Public - CrackMapExec / Kerbrute spraying' 'T1110.001, T1110.003' 'Account Lockout Policy > "Account lockout threshold" = 5 or fewer, not 0.'
AC '1.2.4' "Reset lockout counter >= 15 min" '1 Account Policies' SecPol "$SA::ResetLockoutCount" '' 'ge' 15 2 3 `
   'A short reset window lets an attacker slowly guess passwords while staying under the lockout threshold.' `
   'Public - low-and-slow spraying' 'T1110.003' 'Account Lockout Policy > "Reset account lockout counter after" = 15 or more.'

# ---- 2.2 User Rights Assignment (secedit / Privilege Rights) ----
AC '2.2.x1' "Debug programs (SeDebugPrivilege) = Administrators only" '2 Local Policies' SecPol "$PR::SeDebugPrivilege" '' 'eq' 'S-1-5-32-544' 5 4 `
   'SeDebugPrivilege allows reading any process memory (LSASS) and injecting code - the classic path to credential theft and token manipulation.' `
   'Public - Mimikatz sekurlsa::logonpasswords, ProcDump + pypykatz' 'T1003.001, T1055' `
   'User Rights Assignment > "Debug programs" = Administrators only (remove all other principals).'
AC '2.2.x2' "Access this computer from network restricted" '2 Local Policies' SecPol "$PR::SeNetworkLogonRight" '' 'match' 'S-1-5-32-544' 3 3 `
   'Overly broad network logon rights widen the attack surface for SMB / lateral-movement authentication.' `
   'Public - CrackMapExec / PsExec lateral movement' 'T1021.002' `
   'User Rights Assignment > "Access this computer from the network" = Administrators, Remote Desktop Users only.'

# ---- 2.3 Security Options ----
AC '2.3.1.1' "Block Microsoft accounts" '2 Local Policies' Reg "$SYSPOL" 'NoConnectedUser' 'eq' 3 2 2 `
   'Unmanaged Microsoft accounts bypass local credential governance and complicate incident response.' 'N/A' 'T1078' `
   'Security Options > "Accounts: Block Microsoft accounts" = "Users cant add or log on with Microsoft accounts".'
AC '2.3.1.2' "Guest account status = Disabled" '2 Local Policies' SecPol "$SA::EnableGuestAccount" '' 'eq' 0 4 3 `
   'An enabled Guest account provides an unauthenticated foothold and anonymous resource access.' `
   'Public - anonymous SMB/share enumeration' 'T1078.001' 'Security Options > "Accounts: Guest account status" = Disabled.'
AC '2.3.1.4' "Limit local blank-password use to console = Enabled" '2 Local Policies' Reg "$LSA" 'LimitBlankPasswordUse' 'eq' 1 4 3 `
   'Disabling this lets blank-password local accounts authenticate over the network (RDP/SMB).' `
   'Public - network logon with blank password' 'T1078.003' 'Security Options > "Accounts: Limit local account use of blank passwords to console logon only" = Enabled.'
AC '2.3.2.1' "Audit: force subcategory settings = Enabled" '2 Local Policies' Reg "$LSA" 'SCENoApplyLegacyAuditPolicy' 'eq' 1 3 2 `
   'Legacy audit policy overrides granular subcategories, causing loss of critical security telemetry.' 'N/A - detection gap' 'T1562.002' `
   'Security Options > "Audit: Force audit policy subcategory settings to override" = Enabled.'
AC '2.3.6.1' "Domain member: encrypt/sign secure channel (always) = Enabled" '2 Local Policies' Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" 'RequireSignOrSeal' 'eq' 1 3 3 `
   'Unsigned/unencrypted secure-channel traffic can be intercepted or tampered with.' 'Public - MITM on netlogon' 'T1557' `
   'Security Options > "Domain member: Digitally encrypt or sign secure channel data (always)" = Enabled.'
AC '2.3.7.3' "Interactive logon: lock on smart-card removal" '2 Local Policies' Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption' 'in' @('1','2') 2 2 `
   'An unattended, unlocked session invites walk-up compromise and session hijacking.' 'Physical access' 'T1078' `
   'Security Options > "Interactive logon: Smart card removal behavior" = Lock Workstation.'
AC '2.3.7.4' "Machine inactivity limit <= 900s (not 0)" '2 Local Policies' Reg "$SYSPOL" 'InactivityTimeoutSecs' 'nzle' 900 2 2 `
   'Sessions left unlocked indefinitely enable walk-up access to an authenticated desktop.' 'Physical access' 'T1078' `
   'Security Options > "Interactive logon: Machine inactivity limit" = 900 seconds or fewer, not 0.'
AC '2.3.8.1' "Network client: always digitally sign SMB = Enabled" '2 Local Policies' Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 'eq' 1 4 4 `
   'Without required SMB signing, sessions are exposed to SMB relay and man-in-the-middle attacks.' `
   'Public - ntlmrelayx (impacket), Responder' 'T1557.001, T1187' 'Security Options > "Microsoft network client: Digitally sign communications (always)" = Enabled.'
AC '2.3.9.1' "Network server: always digitally sign SMB = Enabled" '2 Local Policies' Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 'eq' 1 4 4 `
   'Disabled server-side SMB signing allows relay of authentication to this host.' `
   'Public - ntlmrelayx relay target' 'T1557.001' 'Security Options > "Microsoft network server: Digitally sign communications (always)" = Enabled.'
AC '2.3.10.2' "Network access: no anonymous SAM enumeration" '2 Local Policies' Reg "$LSA" 'RestrictAnonymousSAM' 'eq' 1 3 3 `
   'Anonymous SAM enumeration leaks local account names for targeted spraying.' `
   'Public - enum4linux / rpcclient' 'T1087.001' 'Security Options > "Network access: Do not allow anonymous enumeration of SAM accounts" = Enabled.'
AC '2.3.10.3' "Network access: no anonymous SAM+share enumeration" '2 Local Policies' Reg "$LSA" 'RestrictAnonymous' 'eq' 1 3 3 `
   'Null-session enumeration reveals accounts and shares to unauthenticated attackers.' `
   'Public - enum4linux, smbclient null session' 'T1087, T1135' 'Security Options > "...anonymous enumeration of SAM accounts and shares" = Enabled.'
AC '2.3.10.9' "Everyone permissions do NOT apply to anonymous" '2 Local Policies' Reg "$LSA" 'EveryoneIncludesAnonymous' 'eq' 0 3 3 `
   'Granting Everyone rights to anonymous users exposes resources to unauthenticated access.' `
   'Public - anonymous share access' 'T1135' 'Security Options > "...Let Everyone permissions apply to anonymous users" = Disabled.'
AC '2.3.11.1' "No storage of LAN Manager hash (NoLMHash)" '2 Local Policies' Reg "$LSA" 'NoLmHash' 'eq' 1 5 4 `
   'LM hashes are cryptographically weak and crack in seconds, yielding plaintext passwords.' `
   'Public - hashcat -m 3000 (LM) trivially cracked' 'T1003, T1110.002' `
   'Security Options > "Network security: Do not store LAN Manager hash value on next password change" = Enabled.'
AC '2.3.11.7' "LAN Manager auth level = NTLMv2 only, refuse LM+NTLM" '2 Local Policies' Reg "$LSA" 'LmCompatibilityLevel' 'eq' 5 5 4 `
   'Allowing LM/NTLMv1 exposes weak challenge-response hashes to capture, relay and offline cracking.' `
   'Public - Responder + hashcat -m 5500 (NetNTLMv1)' 'T1557.001, T1110' `
   'Security Options > "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM".'
AC '2.3.11.9' "Min NTLM SSP session security (clients)" '2 Local Policies' Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'NTLMMinClientSec' 'eq' 537395200 3 3 `
   'Weak NTLM session security permits downgrade and tampering of authenticated sessions.' 'Public - NTLM downgrade' 'T1557' `
   'Security Options > "Network security: Minimum session security for NTLM SSP based clients" = Require NTLMv2 & 128-bit encryption.'
AC '2.3.17.1' "UAC: Admin Approval Mode for built-in Admin = Enabled" '2 Local Policies' Reg "$SYSPOL" 'FilterAdministratorToken' 'eq' 1 3 3 `
   'Without this, the built-in Administrator runs with a full token and no consent prompt, easing privilege abuse.' `
   'Public - UAC bypass chains' 'T1548.002' 'Security Options > "User Account Control: Admin Approval Mode for the Built-in Administrator account" = Enabled.'
AC '2.3.17.2' "UAC: elevation prompt for admins = Prompt for consent (secure desktop)" '2 Local Policies' Reg "$SYSPOL" 'ConsentPromptBehaviorAdmin' 'in' @('1','2') 3 3 `
   'Auto-elevation (value 0) removes the human checkpoint before high-integrity execution.' `
   'Public - UACMe auto-elevation abuse' 'T1548.002' 'Security Options > "...Behavior of the elevation prompt for administrators..." = Prompt for consent on the secure desktop.'
AC '2.3.17.5' "UAC: Run all admins in Admin Approval Mode = Enabled" '2 Local Policies' Reg "$SYSPOL" 'EnableLUA' 'eq' 1 5 4 `
   'Disabling EnableLUA turns UAC off entirely; every process runs elevated and token-based defences collapse.' `
   'Public - full UAC disablement, unrestricted elevation' 'T1548.002' 'Security Options > "User Account Control: Run all administrators in Admin Approval Mode" = Enabled.'
AC '2.3.17.6' "UAC: elevate prompts on the secure desktop = Enabled" '2 Local Policies' Reg "$SYSPOL" 'PromptOnSecureDesktop' 'eq' 1 3 3 `
   'Prompts off the secure desktop can be spoofed or automated by malware.' 'Public - prompt spoofing' 'T1548.002' `
   'Security Options > "User Account Control: Switch to the secure desktop when prompting for elevation" = Enabled.'
AC '2.3.17.7' "UAC: detect application installations = Enabled" '2 Local Policies' Reg "$SYSPOL" 'EnableInstallerDetection' 'eq' 1 2 2 `
   'Installer detection ensures setup programs are elevated with consent rather than silently.' 'N/A' 'T1548.002' `
   'Security Options > "User Account Control: Detect application installations and prompt for elevation" = Enabled.'

# ---- 5. System Services (Disabled = Start value 4) ----
$svc = @(
  @('5.3','Computer Browser (Browser)','Browser','Legacy SMB browsing protocol widens the lateral-movement / discovery surface.','Public - network enumeration','T1046'),
  @('5.7','IIS Admin Service (IISADMIN)','IISADMIN','A web server on a workstation is an unnecessary, high-value attack surface.','Public - web exploitation','T1190'),
  @('5.10','Microsoft FTP Service (FTPSVC)','FTPSVC','FTP transmits credentials in cleartext and is a common initial-access vector.','Public - cleartext credential capture','T1190, T1071'),
  @('5.12','OpenSSH SSH Server (sshd)','sshd','An exposed SSH server offers remote access and a brute-force target.','Public - Hydra / brute force','T1021.004'),
  @('5.23','RPC Locator (RpcLocator)','RpcLocator','Unneeded RPC surface increases exposure to remote code execution flaws.','Public - RPC exploits','T1210'),
  @('5.25','Routing and Remote Access (RemoteAccess)','RemoteAccess','Unneeded routing/VPN service enlarges the remote attack surface.','Public','T1133'),
  @('5.27','Simple TCP/IP Services (simptcp)','simptcp','Legacy echo/chargen services are amplification and info-leak vectors.','Public - DoS amplification','T1498'),
  @('5.30','SSDP Discovery (SSDPSRV)','SSDPSRV','SSDP is used for network discovery and UPnP abuse.','Public - SSDP/UPnP abuse','T1046'),
  @('5.31','UPnP Device Host (upnphost)','upnphost','UPnP can auto-expose services and is frequently abused.','Public - UPnP abuse','T1046'),
  @('5.40','World Wide Web Publishing Service (W3SVC)','W3SVC','An unnecessary web server is a direct exploitation surface.','Public - web exploitation','T1190'),
  @('5.44','LxssManager (WSL)','LxssManager','WSL provides an alternate execution environment that can evade EDR if unmanaged.','Public - defence evasion via WSL','T1202')
)
foreach ($s in $svc) {
  AC $s[0] ("{0} = Disabled" -f $s[1]) '5 System Services' Service "" $s[2] 'in' @('4') 3 2 $s[3] $s[4] $s[5] `
    ("System Services > `"{0}`" = Disabled (or uninstall the role/feature). Registry: HKLM\SYSTEM\CurrentControlSet\Services\{1}\Start = 4." -f $s[1],$s[2])
}

# ---- 9. Windows Defender Firewall ----
foreach ($p in @('Domain','Private','Public')) {
  $fw = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${p}Profile"
  AC "9.$p.1" "Firewall state ($p profile) = On" '9 Windows Firewall' Reg $fw 'EnableFirewall' 'eq' 1 4 3 `
     "A disabled firewall on the $p profile removes host-based network filtering, exposing all listening services." `
     'Public - direct service exploitation / lateral movement' 'T1562.004, T1021' `
     "Firewall with Advanced Security > $p Profile > Firewall state = On."
  AC "9.$p.2" "Inbound connections ($p) = Block (default)" '9 Windows Firewall' Reg $fw 'DefaultInboundAction' 'eq' 1 4 3 `
     "A permissive default inbound action lets unsolicited traffic reach local services." `
     'Public - remote service exploitation' 'T1021, T1190' `
     "$p Profile > Inbound connections = Block (default)."
}

# ---- 17. Advanced Audit Policy (auditpol) ----
$aud = @(
  @('17.1.1','Credential Validation','Success and Failure','Missing credential-validation auditing blinds detection of brute-force / spraying.','T1110'),
  @('17.2.1','Application Group Management','Success and Failure','Group changes are a common persistence / privilege-escalation signal.','T1098'),
  @('17.3.1','Process Creation','Success','Without process-creation auditing, execution of attacker tooling goes unlogged.','T1059'),
  @('17.5.1','Account Lockout','Failure','Lockout events are a primary indicator of password-guessing attacks.','T1110'),
  @('17.5.4','Special Logon','Success','Special-privilege logons (admin) are key to spotting privilege abuse.','T1078'),
  @('17.6.1','Detailed File Share','Failure','Failed share access auditing surfaces reconnaissance and lateral movement.','T1135'),
  @('17.7.1','Audit Policy Change','Success and Failure','Attackers disable auditing to hide - policy-change logging detects this.','T1562.002'),
  @('17.7.2','Authentication Policy Change','Success','Changes to auth policy can indicate privilege escalation or persistence.','T1484'),
  @('17.8.1','Sensitive Privilege Use','Success and Failure','Use of sensitive privileges (SeDebug, SeBackup) flags credential/token abuse.','T1134'),
  @('17.9.1','IPsec Driver','Success and Failure','Loss of network security telemetry.','T1562'),
  @('17.9.3','Security State Change','Success','Startup/shutdown and security subsystem changes are tamper indicators.','T1562'),
  @('17.9.5','System Integrity','Success and Failure','Integrity subsystem failures reveal driver/rootkit tampering.','T1014')
)
foreach ($a in $aud) {
  AC $a[0] ("Audit: {0} = {1}" -f $a[1],$a[2]) '17 Advanced Audit Policy' AuditPol "" $a[1] 'auditmatch' $a[2] 2 3 `
    $a[3] 'N/A - detection / visibility gap' $a[4] `
    ("Advanced Audit Policy Configuration > locate `"{0}`" and set = {1}." -f $a[1],$a[2])
}

# ---- 18. Administrative Templates (Computer) ----
AC '18.4.1' "Disable SMBv1 client driver (mrxsmb10 Start=4)" '18 Admin Templates' Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 'eq' 4 5 4 `
   'SMBv1 is obsolete and the vector for EternalBlue / WannaCry-class remote code execution and relay.' `
   'Public - MS17-010 (EternalBlue), Metasploit module' 'T1210, T1021.002' `
   'Admin Templates > MS Security Guide > "Configure SMB v1 client driver" = Enabled: Disable driver.'
AC '18.4.2' "Disable SMBv1 server = Enabled" '18 Admin Templates' Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 'eq' 0 5 4 `
   'A listening SMBv1 server is directly exploitable by EternalBlue and enables NTLM relay.' `
   'Public - MS17-010 (EternalBlue)' 'T1210' 'Admin Templates > MS Security Guide > "Configure SMB v1 server" = Disabled.'
AC '18.4.3' "Enable SEHOP = Enabled (DisableExceptionChainValidation=0)" '18 Admin Templates' Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 'eq' 0 3 2 `
   'SEHOP mitigates a class of memory-corruption exploitation techniques.' 'Public - SEH overwrite exploits' 'T1203' `
   'Admin Templates > MS Security Guide > "Enable Structured Exception Handling Overwrite Protection (SEHOP)" = Enabled.'
AC '18.4.5' "WDigest: do not cache plaintext creds (UseLogonCredential=0)" '18 Admin Templates' Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 'in' @('0') 5 5 `
   'When enabled, WDigest caches cleartext passwords in LSASS memory - a one-command harvest for attackers.' `
   'Public - Mimikatz sekurlsa::wdigest' 'T1003.001' 'Admin Templates > MS Security Guide > "WDigest Authentication" = Disabled.'
AC '18.5.4.1' "Turn off multicast name resolution (LLMNR) = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'eq' 0 4 5 `
   'LLMNR/mDNS lets an attacker on the LAN poison name resolution and capture NetNTLM hashes.' `
   'Public - Responder (very common, high success)' 'T1557.001' `
   'Admin Templates > Network > DNS Client > "Turn off multicast name resolution" = Enabled.'
AC '18.6.x' "Disable NetBIOS/NBT-NS broadcast (NodeType = P-node 2)" '18 Admin Templates' Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NodeType' 'eq' 2 4 5 `
   'NBT-NS broadcast resolution is poisonable to capture and relay NetNTLM authentication.' `
   'Public - Responder + ntlmrelayx' 'T1557.001' 'Set NetBIOS node type to P-node (disable NBT-NS broadcast) via DHCP option 46 or registry NodeType=2.'
AC '18.8.x1' "Disallow autoplay for all drives (NoDriveTypeAutoRun=255)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 'eq' 255 3 3 `
   'Autoplay enables automatic execution of malicious payloads from removable / network media.' `
   'Public - USB/HID payload delivery (Rubber Ducky, BadUSB)' 'T1091, T1200' `
   'Admin Templates > Windows Components > AutoPlay Policies > "Turn off AutoPlay" = Enabled: All drives.'
AC '18.8.x2' "Disable Autorun commands (NoAutorun=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun' 'eq' 1 3 3 `
   'Honouring autorun.inf allows removable media to launch code automatically.' `
   'Public - removable media payloads' 'T1091' 'AutoPlay Policies > "Set the default behavior for AutoRun" = Enabled: Do not execute any autorun commands.'
AC '18.9.WI1' "Windows Installer: AlwaysInstallElevated (HKLM) = Disabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 'in' @('0') 5 4 `
   'AlwaysInstallElevated lets any user install MSI packages as SYSTEM - a well-known local privilege escalation.' `
   'Public - msfvenom MSI + local priv-esc (very common)' 'T1548.002' `
   'Admin Templates > Windows Components > Windows Installer > "Always install with elevated privileges" = Disabled.'
AC '18.9.RDP1' "Remote Desktop: always prompt for password (fPromptForPassword=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword' 'eq' 1 3 3 `
   'Saved RDP credentials permit passwordless reconnection and credential reuse.' 'Public - RDP session hijack' 'T1021.001' `
   'Admin Templates > ... Remote Desktop Session Host > Security > "Always prompt for password upon connection" = Enabled.'
AC '18.9.RDP2' "Remote Desktop: high encryption level (MinEncryptionLevel=3)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'MinEncryptionLevel' 'eq' 3 3 3 `
   'Weak RDP encryption exposes sessions to interception and downgrade.' 'Public - RDP MITM' 'T1557' `
   'Remote Desktop Session Host > Security > "Set client connection encryption level" = High Level.'
AC '18.9.RDP3' "Remote Desktop: do not allow password saving (DisablePasswordSaving=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'DisablePasswordSaving' 'eq' 1 2 3 `
   'Cached RDP passwords can be reused for lateral movement.' 'Public - credential reuse' 'T1021.001' `
   'Remote Desktop Connection Client > "Do not allow passwords to be saved" = Enabled.'
AC '18.9.LSA1' "LSA protection (RunAsPPL) = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'RunAsPPL' 'in' @('1','2') 5 4 `
   'Without LSA protection, LSASS memory can be read directly to extract credentials and Kerberos tickets.' `
   'Public - Mimikatz / pypykatz LSASS dump' 'T1003.001' `
   'Admin Templates > MS Security Guide > "Configure LSASS to run as a protected process" = Enabled with UEFI lock. (CIS v5: HKLM\SOFTWARE\Policies\Microsoft\Windows\System:RunAsPPL=1)'
AC '18.9.CG1' "Virtualization Based Security = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'EnableVirtualizationBasedSecurity' 'eq' 1 4 3 `
   'VBS underpins Credential Guard and HVCI; without it, isolated credential/kernel protections are absent.' `
   'Public - unmitigated LSASS credential theft' 'T1003' `
   'Admin Templates > System > Device Guard > "Turn On Virtualization Based Security" = Enabled.'
AC '18.9.CG2' "Credential Guard = Enabled (LsaCfgFlags)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags' 'in' @('1','2') 5 3 `
   'Credential Guard isolates NTLM/Kerberos secrets from LSASS; disabled, they can be harvested and relayed / pass-the-hash.' `
   'Public - pass-the-hash, Mimikatz' 'T1003.001, T1550.002' `
   'Admin Templates > System > Device Guard > "Turn On Virtualization Based Security" > Credential Guard = Enabled with UEFI lock.'

# ---- 18.10 Windows Components (Defender / SmartScreen / PowerShell / WinRM) ----
AC '18.10.D1' "Microsoft Defender Antivirus enabled (DisableAntiSpyware!=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 'in' @('0') 5 4 `
   'Disabling Defender removes the primary endpoint malware defence.' `
   'Public - defence evasion prerequisite for most malware' 'T1562.001' `
   'Admin Templates > Windows Components > Microsoft Defender Antivirus > "Turn off Microsoft Defender Antivirus" = Disabled (i.e. AV enabled).'
AC '18.10.D2' "Defender real-time protection ON (DisableRealtimeMonitoring!=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 'in' @('0') 5 4 `
   'Real-time protection blocks payloads on write/execute; disabled, malware runs freely.' `
   'Public - malware execution' 'T1562.001' `
   'Microsoft Defender Antivirus > Real-Time Protection > "Turn off real-time protection" = Disabled.'
AC '18.10.D3' "Defender PUA protection = Enabled (PUAProtection=1)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' 'PUAProtection' 'eq' 1 3 3 `
   'PUA protection blocks bundleware and dual-use tools frequently abused by attackers.' 'Public - LOLbin/dual-use tooling' 'T1105' `
   'Microsoft Defender Antivirus > "Configure detection for potentially unwanted applications" = Enabled: Block.'
AC '18.10.SS1' "SmartScreen for Explorer = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 'eq' 1 3 4 `
   'SmartScreen blocks known-malicious downloads and phishing; disabling raises initial-access success.' `
   'Public - phishing / drive-by download' 'T1204, T1566' `
   'Admin Templates > Windows Components > File Explorer / SmartScreen > "Configure Windows Defender SmartScreen" = Enabled: Warn and prevent bypass.'
AC '18.10.PS1' "PowerShell Script Block Logging = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'eq' 1 3 4 `
   'Without script-block logging, obfuscated / fileless PowerShell attacks are effectively invisible.' `
   'N/A - detection gap for PowerShell tradecraft (Empire, PowerSploit)' 'T1059.001, T1562' `
   'Admin Templates > Windows Components > Windows PowerShell > "Turn on PowerShell Script Block Logging" = Enabled.'
AC '18.10.PS2' "PowerShell Module Logging = Enabled" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 'eq' 1 2 3 `
   'Module logging records pipeline execution details useful for detecting malicious tooling.' 'N/A - detection gap' 'T1059.001' `
   'Windows PowerShell > "Turn on Module Logging" = Enabled (Module names = *).'
AC '18.10.WRM1' "WinRM client: disallow Basic auth (AllowBasic=0)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 'eq' 0 3 3 `
   'Basic auth transmits reusable credentials and is trivially captured/relayed.' 'Public - credential capture' 'T1021.006, T1557' `
   'Admin Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Client > "Allow Basic authentication" = Disabled.'
AC '18.10.WRM2' "WinRM service: disallow Basic auth (AllowBasic=0)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 'eq' 0 3 3 `
   'Basic auth on the WinRM listener exposes credentials and enables lateral movement.' 'Public - Evil-WinRM' 'T1021.006' `
   'WinRM Service > "Allow Basic authentication" = Disabled.'
AC '18.10.WRM3' "WinRM service: disallow unencrypted traffic (AllowUnencryptedTraffic=0)" '18 Admin Templates' Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' 'eq' 0 3 3 `
   'Unencrypted WS-Management traffic can be intercepted, exposing commands and credentials.' 'Public - MITM capture' 'T1557' `
   'WinRM Service > "Allow unencrypted traffic" = Disabled.'

# ------------------------------------------------------------------ #
# 4.  Run the assessment
# ------------------------------------------------------------------ #
Initialize-SecPol
Initialize-AuditPol

$results = New-Object System.Collections.Generic.List[object]
$total   = $script:Controls.Count
$idx = 0

foreach ($c in $script:Controls) {
    $idx++
    Write-Progress -Activity "Assessing CIS L1 controls" -Status "$($c.Id) $($c.Title)" -PercentComplete (($idx/$total)*100)

    $status = 'FAIL'; $note = ''; $actualDisplay = ''

    try {
        switch ($c.Type) {
            'Reg' {
                $actual = Get-RegValue -Path $c.Path -Name $c.Name
                $actualDisplay = if ($null -eq $actual) { '<not set>' } else { "$actual" }
                $pass = Compare-Value -Actual $actual -Op $c.Op -Expected $c.Expected
            }
            'SecPol' {
                if (-not $script:SecPolLoaded) { throw "secedit export unavailable (requires elevation)" }
                $actual = $script:SecPol[$c.Path]
                $actualDisplay = if ($null -eq $actual -or $actual -eq '') { '<not defined>' } else { "$actual" }
                $pass = Compare-Value -Actual $actual -Op $c.Op -Expected $c.Expected
            }
            'AuditPol' {
                if (-not $script:AuditPolLoaded) { throw "auditpol query unavailable (requires elevation)" }
                $actual = $script:AuditPol[$c.Name]
                $actualDisplay = if ($null -eq $actual) { '<not found>' } else { "$actual" }
                if ($c.Op -eq 'auditmatch') {
                    $exp = "$($c.Expected)"
                    if ($exp -eq 'Success and Failure') {
                        $pass = ($actual -eq 'Success and Failure')
                    } else {
                        $pass = ($actual -eq $exp -or $actual -eq 'Success and Failure')
                    }
                } else {
                    $pass = Compare-Value -Actual $actual -Op $c.Op -Expected $c.Expected
                }
            }
            'Service' {
                $actual = Get-ServiceStart -Name $c.Name
                $actualDisplay = if ($null -eq $actual) { '<not installed>' } else { "Start=$actual" }
                # Not installed = compliant (service absent). Start=4 = Disabled = compliant.
                $pass = ($null -eq $actual) -or (Compare-Value -Actual $actual -Op 'eq' -Expected 4)
            }
            default { throw "unknown control type $($c.Type)" }
        }
        $status = if ($pass) { 'PASS' } else { 'FAIL' }
    }
    catch {
        $status = 'ERROR'; $note = $_.Exception.Message; $actualDisplay = 'ERROR'
    }

    $riskScore = if ($status -eq 'FAIL') { $c.Impact * $c.Likelihood } else { 0 }
    $sev = 'None'
    if ($status -eq 'FAIL') {
        $sev = if     ($riskScore -ge 20) { 'Critical' }
               elseif ($riskScore -ge 12) { 'High' }
               elseif ($riskScore -ge 6)  { 'Medium' }
               else                       { 'Low' }
    }

    $expDisp = if ($c.Expected -is [array]) { $c.Expected -join ' | ' } else { "$($c.Expected)" }

    $results.Add([pscustomobject]@{
        Id=$c.Id; Title=$c.Title; Section=$c.Section; Status=$status;
        Expected=$expDisp; Actual=$actualDisplay; Impact=$c.Impact; Likelihood=$c.Likelihood;
        RiskScore=$riskScore; Severity=$sev; Risk=$c.Risk; Poc=$c.Poc;
        Mitre=$c.Mitre; Remediation=$c.Remediation; Note=$note
    })
}
Write-Progress -Activity "Assessing CIS L1 controls" -Completed

# ------------------------------------------------------------------ #
# 5.  Aggregate statistics
# ------------------------------------------------------------------ #
$pass   = ($results | Where-Object Status -eq 'PASS').Count
$fail   = ($results | Where-Object Status -eq 'FAIL').Count
$err    = ($results | Where-Object Status -eq 'ERROR').Count
$assessed = $pass + $fail
$compliance = if ($assessed -gt 0) { [math]::Round(($pass/$assessed)*100,1) } else { 0 }

$crit = ($results | Where-Object Severity -eq 'Critical').Count
$high = ($results | Where-Object Severity -eq 'High').Count
$med  = ($results | Where-Object Severity -eq 'Medium').Count
$low  = ($results | Where-Object Severity -eq 'Low').Count

# 5x5 matrix counts (FAIL only): key = "Likelihood,Impact"
$matrix = @{}
foreach ($L in 1..5) { foreach ($Imp in 1..5) { $matrix["$L,$Imp"] = 0 } }
foreach ($r in ($results | Where-Object Status -eq 'FAIL')) {
    $matrix["$($r.Likelihood),$($r.Impact)"]++
}

$results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# ------------------------------------------------------------------ #
# 6.  HTML report
# ------------------------------------------------------------------ #
function HtmlEnc([string]$s){ if($null -eq $s){return ''}; $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }

$os     = Get-CimInstance Win32_OperatingSystem
$hostNm = $env:COMPUTERNAME
$osName = $os.Caption
$osVer  = "$($os.Version) (Build $($os.BuildNumber))"
$dateStr = (Get-Date).ToString('yyyy-MM-dd HH:mm')

$sevColor = @{ Critical='#7d0a0a'; High='#c0392b'; Medium='#e67e22'; Low='#f1c40f'; None='#27ae60' }

function MatrixColor([int]$score){
    if     ($score -ge 20) { '#7d0a0a' }
    elseif ($score -ge 12) { '#c0392b' }
    elseif ($score -ge 6)  { '#e67e22' }
    else                   { '#f1c40f' }
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append(@"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>CIS Windows 11 v5.0.0 L1 Gap Assessment</title>
<style>
 @page { size: A4; margin: 14mm; }
 * { box-sizing: border-box; }
 body { font-family: 'Segoe UI', Arial, sans-serif; color:#1c2733; margin:0; font-size:12px; line-height:1.5; }
 h1 { font-size:24px; margin:0 0 4px; }
 h2 { font-size:17px; border-bottom:2px solid #0b5394; padding-bottom:4px; color:#0b5394; margin-top:28px; page-break-after:avoid; }
 h3 { font-size:14px; color:#0b5394; margin:18px 0 6px; page-break-after:avoid; }
 h4 { margin:0 0 4px; font-size:13px; }
 .cover { background:linear-gradient(135deg,#0b3d66,#0b5394); color:#fff; padding:46px 40px; border-radius:8px; }
 .cover .sub { font-size:14px; opacity:.92; margin-top:2px; }
 .badge { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-weight:600; font-size:11px; }
 table { border-collapse:collapse; width:100%; margin:10px 0; }
 th,td { border:1px solid #cdd6df; padding:6px 8px; text-align:left; vertical-align:top; }
 th { background:#0b5394; color:#fff; font-weight:600; }
 tr:nth-child(even) td { background:#f4f7fa; }
 .kpi-wrap { display:flex; gap:14px; flex-wrap:wrap; margin:16px 0; }
 .kpi { flex:1; min-width:110px; border:1px solid #cdd6df; border-radius:8px; padding:14px; text-align:center; }
 .kpi .n { font-size:28px; font-weight:700; }
 .kpi .l { font-size:11px; color:#5a6b7b; text-transform:uppercase; letter-spacing:.5px; }
 .matrix td { text-align:center; font-weight:700; color:#fff; width:16%; height:44px; }
 .matrix th { text-align:center; background:#33475b; color:#fff; }
 .axis { background:#33475b; color:#fff; font-weight:600; text-align:center; }
 .muted { color:#5a6b7b; }
 .finding { border:1px solid #cdd6df; border-left:5px solid #c0392b; border-radius:6px; padding:10px 12px; margin:10px 0; page-break-inside:avoid; }
 .finding.Critical{ border-left-color:#7d0a0a;} .finding.High{border-left-color:#c0392b;}
 .finding.Medium{ border-left-color:#e67e22;} .finding.Low{border-left-color:#f1c40f;}
 .finding p { margin:4px 0; }
 .meta { font-size:11px; color:#334; }
 .meta b { color:#0b5394; }
 code { background:#eef2f6; padding:1px 4px; border-radius:3px; font-family:Consolas,monospace; font-size:11px; }
 .foot { margin-top:30px; font-size:10px; color:#889; border-top:1px solid #cdd6df; padding-top:8px; }
 .pass{color:#27ae60;font-weight:700;} .fail{color:#c0392b;font-weight:700;} .errs{color:#8e44ad;font-weight:700;}
</style></head><body>
"@)

# Cover
[void]$sb.Append(@"
<div class='cover'>
 <div style='font-size:12px;letter-spacing:2px;opacity:.85'>CONFIDENTIAL &bull; INTERNAL USE ONLY</div>
 <h1>CIS Windows 11 Benchmark &ndash; Configuration Gap Assessment</h1>
 <div class='sub'>Benchmark: CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0 &bull; Profile: Level 1 (L1)</div>
 <div class='sub'>Prepared by: Offensive Security Team</div>
 <div class='sub'>Host: $(HtmlEnc $hostNm) &nbsp;|&nbsp; $(HtmlEnc $osName) &nbsp;|&nbsp; $(HtmlEnc $osVer)</div>
 <div class='sub'>Assessment date: $dateStr</div>
</div>
"@)

# Executive summary
$topRisks = $results | Where-Object Status -eq 'FAIL' | Sort-Object RiskScore -Descending | Select-Object -First 5
[void]$sb.Append("<h2>1. Executive Summary</h2>")
[void]$sb.Append("<p>This report presents an automated configuration gap assessment of host <b>$(HtmlEnc $hostNm)</b> against the <b>CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0, Level 1</b> profile. A curated set of <b>$total</b> high-impact, offensive-security-relevant controls was evaluated. The assessment is read-only and made no changes to the system.</p>")
[void]$sb.Append("<p>The host achieved a Level 1 compliance rate of <b>$compliance%</b> across evaluable controls. The assessment identified <b>$fail</b> configuration gaps: <span style='color:#7d0a0a;font-weight:700'>$crit Critical</span>, <span style='color:#c0392b;font-weight:700'>$high High</span>, <span style='color:#e67e22;font-weight:700'>$med Medium</span>, and <span style='color:#b7950b;font-weight:700'>$low Low</span>. Severity is derived from a risk score (Impact &times; Likelihood, range 1-25).</p>")

[void]$sb.Append(@"
<div class='kpi-wrap'>
 <div class='kpi'><div class='n'>$compliance%</div><div class='l'>L1 Compliance</div></div>
 <div class='kpi'><div class='n' style='color:#27ae60'>$pass</div><div class='l'>Passed</div></div>
 <div class='kpi'><div class='n' style='color:#c0392b'>$fail</div><div class='l'>Failed</div></div>
 <div class='kpi'><div class='n' style='color:#7d0a0a'>$crit</div><div class='l'>Critical</div></div>
 <div class='kpi'><div class='n' style='color:#c0392b'>$high</div><div class='l'>High</div></div>
 <div class='kpi'><div class='n' style='color:#8e44ad'>$err</div><div class='l'>Not Assessed</div></div>
</div>
"@)

if ($err -gt 0) {
    [void]$sb.Append("<p class='muted'>Note: $err control(s) could not be evaluated (typically because the script was not run elevated). Re-run in an elevated PowerShell session for full coverage.</p>")
}

# Top risks
[void]$sb.Append("<h3>Top Priority Findings</h3><table><tr><th>#</th><th>ID</th><th>Finding</th><th>Severity</th><th>Risk Score</th><th>PoC / Tooling</th></tr>")
$rank=0
foreach ($t in $topRisks) {
    $rank++
    [void]$sb.Append("<tr><td>$rank</td><td>$(HtmlEnc $t.Id)</td><td>$(HtmlEnc $t.Title)</td><td><span class='badge' style='background:$($sevColor[$t.Severity])'>$($t.Severity)</span></td><td style='text-align:center'><b>$($t.RiskScore)</b></td><td>$(HtmlEnc $t.Poc)</td></tr>")
}
if ($rank -eq 0) { [void]$sb.Append("<tr><td colspan='6' class='pass'>No failed controls.</td></tr>") }
[void]$sb.Append("</table>")

# Methodology
[void]$sb.Append(@"
<h2>2. Methodology &amp; Risk Model</h2>
<p>Controls were evaluated by directly reading the effective system configuration: the Windows registry, the local security policy (via <code>secedit /export</code>), the advanced audit policy (via <code>auditpol</code>), and service startup states. Each observed value was compared against the CIS v5.0.0 Level 1 recommended value.</p>
<p>Every failed control is scored on two axes, each 1 (very low) to 5 (very high):</p>
<ul>
 <li><b>Impact</b> &ndash; the technical / business consequence if the weakness is exploited (e.g. full credential compromise = 5).</li>
 <li><b>Likelihood</b> &ndash; the probability of exploitation given the exposure and the maturity / availability of public tooling.</li>
</ul>
<p><b>Risk Score = Impact &times; Likelihood</b> (range 1-25), banded as:
 <span class='badge' style='background:#7d0a0a'>Critical 20-25</span>
 <span class='badge' style='background:#c0392b'>High 12-19</span>
 <span class='badge' style='background:#e67e22'>Medium 6-11</span>
 <span class='badge' style='background:#f1c40f;color:#333'>Low 1-5</span>.
Each finding also records public Proof-of-Concept / exploit tooling availability and the relevant <b>MITRE ATT&amp;CK</b> technique.</p>
"@)

# Risk matrix
[void]$sb.Append("<h2>3. Risk Matrix (Likelihood &times; Impact)</h2>")
[void]$sb.Append("<p>Each cell shows the number of failed controls at that Likelihood / Impact combination. Cell colour reflects the resulting risk band.</p>")
[void]$sb.Append("<table class='matrix'><tr><th colspan='2' rowspan='2' style='background:#1c2733'>Failed controls</th><th colspan='5'>Impact &rarr;</th></tr><tr>")
foreach ($imp in 1..5){ [void]$sb.Append("<th>$imp</th>") }
[void]$sb.Append("</tr>")
$firstRow=$true
foreach ($L in 5..1) {
    [void]$sb.Append("<tr>")
    if ($firstRow){ [void]$sb.Append("<td class='axis' rowspan='5' style='writing-mode:vertical-rl;transform:rotate(180deg)'>Likelihood &uarr;</td>"); $firstRow=$false }
    [void]$sb.Append("<td class='axis'>$L</td>")
    foreach ($imp in 1..5) {
        $n = $matrix["$L,$imp"]
        $col = MatrixColor ($L*$imp)
        $txt = if ($n -gt 0) { $n } else { '&middot;' }
        [void]$sb.Append("<td style='background:$col'>$txt</td>")
    }
    [void]$sb.Append("</tr>")
}
[void]$sb.Append("</table>")

# Compliance by section
[void]$sb.Append("<h2>4. Compliance by Benchmark Section</h2><table><tr><th>Section</th><th>Assessed</th><th>Passed</th><th>Failed</th><th>Compliance</th></tr>")
foreach ($grp in ($results | Group-Object Section | Sort-Object Name)) {
    $gp = ($grp.Group | Where-Object Status -eq 'PASS').Count
    $gf = ($grp.Group | Where-Object Status -eq 'FAIL').Count
    $ga = $gp+$gf
    $gc = if ($ga -gt 0){ [math]::Round(($gp/$ga)*100,0) } else {0}
    [void]$sb.Append("<tr><td>$(HtmlEnc $grp.Name)</td><td style='text-align:center'>$ga</td><td style='text-align:center' class='pass'>$gp</td><td style='text-align:center' class='fail'>$gf</td><td style='text-align:center'><b>$gc%</b></td></tr>")
}
[void]$sb.Append("</table>")

# Full results table
[void]$sb.Append("<h2>5. Full Control Results</h2><table><tr><th>ID</th><th>Control</th><th>Status</th><th>Expected</th><th>Observed</th><th>Sev</th><th>Score</th></tr>")
$ordered = $results | Sort-Object @{e={switch($_.Status){'FAIL'{0}'ERROR'{1}'PASS'{2}default{3}}}}, @{e='RiskScore';Descending=$true}, Id
foreach ($r in $ordered) {
    $stCls = switch($r.Status){'PASS'{'pass'}'FAIL'{'fail'}default{'errs'}}
    $sevBadge = if($r.Status -eq 'FAIL'){"<span class='badge' style='background:$($sevColor[$r.Severity])'>$($r.Severity)</span>"}else{'-'}
    $scoreTxt = if($r.Status -eq 'FAIL'){$r.RiskScore}else{'-'}
    [void]$sb.Append("<tr><td>$(HtmlEnc $r.Id)</td><td>$(HtmlEnc $r.Title)</td><td class='$stCls'>$($r.Status)</td><td>$(HtmlEnc $r.Expected)</td><td>$(HtmlEnc $r.Actual)</td><td style='text-align:center'>$sevBadge</td><td style='text-align:center'>$scoreTxt</td></tr>")
}
[void]$sb.Append("</table>")

# Detailed findings + remediation (FAIL only, by severity)
[void]$sb.Append("<h2>6. Detailed Findings &amp; Remediation</h2>")
$sevOrder = @{Critical=0;High=1;Medium=2;Low=3}
$fails = $results | Where-Object Status -eq 'FAIL' | Sort-Object @{e={$sevOrder[$_.Severity]}}, @{e='RiskScore';Descending=$true}, Id
if ($fails.Count -eq 0) {
    [void]$sb.Append("<p class='pass'>No Level 1 configuration gaps were identified in the assessed control set.</p>")
} else {
    foreach ($r in $fails) {
        [void]$sb.Append(@"
<div class='finding $($r.Severity)'>
 <h4>[$(HtmlEnc $r.Id)] $(HtmlEnc $r.Title) &nbsp; <span class='badge' style='background:$($sevColor[$r.Severity])'>$($r.Severity) &bull; Score $($r.RiskScore)</span></h4>
 <div class='meta'><b>Section:</b> $(HtmlEnc $r.Section) &nbsp;|&nbsp; <b>Expected:</b> <code>$(HtmlEnc $r.Expected)</code> &nbsp;|&nbsp; <b>Observed:</b> <code>$(HtmlEnc $r.Actual)</code></div>
 <div class='meta'><b>Impact:</b> $($r.Impact)/5 &nbsp;|&nbsp; <b>Likelihood:</b> $($r.Likelihood)/5 &nbsp;|&nbsp; <b>MITRE ATT&amp;CK:</b> $(HtmlEnc $r.Mitre)</div>
 <p><b>Risk:</b> $(HtmlEnc $r.Risk)</p>
 <p><b>Exploit / PoC availability:</b> $(HtmlEnc $r.Poc)</p>
 <p><b>Remediation:</b> $(HtmlEnc $r.Remediation)</p>
</div>
"@)
    }
}

# Footer
[void]$sb.Append(@"
<div class='foot'>
 Generated $dateStr by Invoke-CISWin11GapAssessment.ps1 &bull; Benchmark: CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0 (Level 1).
 This is a curated, prioritised subset of the full benchmark intended for offensive-security triage and management reporting; it is not a CIS-CAT certified full scan. Validate all findings before remediating.
</div>
</body></html>
"@)

Set-Content -Path $HtmlPath -Value $sb.ToString() -Encoding UTF8
Write-Host "HTML report written: $HtmlPath" -ForegroundColor Green
Write-Host "CSV data written    : $CsvPath" -ForegroundColor Green

# ------------------------------------------------------------------ #
# 7.  PDF export via Microsoft Edge (headless) - no external modules
# ------------------------------------------------------------------ #
function Find-Edge {
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

if (-not $SkipPdf) {
    $edge = Find-Edge
    if ($edge) {
        try {
            $fileUri = ([System.Uri]$HtmlPath).AbsoluteUri
            $edgeArgs = @(
                '--headless=new','--disable-gpu','--no-first-run',
                "--print-to-pdf=`"$PdfPath`"", '--no-pdf-header-footer', "`"$fileUri`""
            )
            Start-Process -FilePath $edge -ArgumentList $edgeArgs -WindowStyle Hidden -Wait
            Start-Sleep -Milliseconds 800
            if (Test-Path $PdfPath) {
                Write-Host "PDF report written  : $PdfPath" -ForegroundColor Green
            } else {
                Write-Warning "Edge ran but PDF not found. Open the HTML report and print to PDF manually: $HtmlPath"
            }
        } catch {
            Write-Warning "PDF export failed ($($_.Exception.Message)). Open the HTML and print to PDF: $HtmlPath"
        }
    } else {
        Write-Warning "Microsoft Edge not found - skipping PDF. Open the HTML report and use Print > Save as PDF: $HtmlPath"
    }
}

# ------------------------------------------------------------------ #
# 8.  Console summary
# ------------------------------------------------------------------ #
$dur = [math]::Round(((Get-Date)-$script:StartTime).TotalSeconds,1)
Write-Host ""
Write-Host "================ ASSESSMENT SUMMARY ================" -ForegroundColor Cyan
Write-Host ("Host            : {0}  ({1})" -f $hostNm,$osName)
Write-Host ("Controls        : {0} assessed  |  {1} PASS  |  {2} FAIL  |  {3} not assessed" -f $total,$pass,$fail,$err)
Write-Host ("L1 Compliance   : {0}%" -f $compliance)
Write-Host ("Severity (fails): Critical {0} | High {1} | Medium {2} | Low {3}" -f $crit,$high,$med,$low) -ForegroundColor Yellow
Write-Host ("Duration        : {0}s" -f $dur)
Write-Host "====================================================" -ForegroundColor Cyan

if ($OpenReport) {
    if (Test-Path $PdfPath) { Start-Process $PdfPath } else { Start-Process $HtmlPath }
}

# Return structured results to the pipeline for further automation
$results
