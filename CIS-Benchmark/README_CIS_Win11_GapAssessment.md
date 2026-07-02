# CIS Windows 11 v5.0.0 (Level 1) — Gap Assessment Toolkit

`Invoke-CISWin11GapAssessment.ps1` performs a **read-only** configuration gap
assessment of a Windows 11 host against a curated, high‑impact subset of the
**CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0, Level 1** profile, then
produces a management‑ready **PDF** (plus HTML and CSV) report.

## What it produces

A single professional report containing:

- Executive summary + compliance KPIs (compliance %, pass/fail, severity counts)
- Methodology & risk model
- **5×5 Likelihood × Impact risk matrix** (heat map)
- Compliance by benchmark section
- Full control results table (expected vs. observed value)
- Detailed findings with, for every gap: **risk, impact, likelihood, risk score,
  severity, exploit/PoC availability, and MITRE ATT&CK mapping**, plus
  step‑by‑step **remediation** (Group Policy path + registry key/value)

Output files (timestamped) are written to the output folder:
`CIS_Win11_GapAssessment_<stamp>.pdf` / `.html` / `.csv`

## Requirements

- Windows 11, **PowerShell 5.1 or 7+**
- **Run as Administrator** (secedit / auditpol and several registry hives need it).
  Without elevation those checks are marked `ERROR` / *Not Assessed*.
- Microsoft Edge (default on Windows 11) — used to render the PDF with no
  external modules or installs. If Edge is missing, the HTML is still produced
  and you can Print → Save as PDF.

## How to run

```powershell
# From an ELEVATED PowerShell prompt, in the folder containing the script:
powershell -ExecutionPolicy Bypass -File .\Invoke-CISWin11GapAssessment.ps1

# Choose an output folder and open the report when done:
.\Invoke-CISWin11GapAssessment.ps1 -OutputFolder 'C:\CIS_Report' -OpenReport

# HTML only (skip PDF):
.\Invoke-CISWin11GapAssessment.ps1 -SkipPdf
```

Default output folder: `%USERPROFILE%\Desktop\CIS_Win11_GapAssessment`.

## Risk model

Each failed control is scored on two 1–5 axes:

- **Impact** — technical/business consequence if exploited (full credential
  compromise = 5).
- **Likelihood** — probability of exploitation given exposure and public tooling
  maturity.

**Risk Score = Impact × Likelihood** (1–25):

| Band | Score |
|------|-------|
| Critical | 20–25 |
| High | 12–19 |
| Medium | 6–11 |
| Low | 1–5 |

## Coverage

~55 curated Level 1 controls across: Account & Lockout Policy, User Rights,
Security Options (LSA/NTLM/SMB signing/UAC/anonymous access), System Services,
Windows Firewall, Advanced Audit Policy, and Administrative Templates
(SMBv1, WDigest, LLMNR/NBT‑NS, LSA Protection/Credential Guard, Defender,
SmartScreen, PowerShell logging, WinRM, RDP, AutoRun, AlwaysInstallElevated).

These were selected for offensive‑security relevance — they map directly to
common attack paths (Responder/ntlmrelayx, Mimikatz LSASS dumps, EternalBlue,
password spraying, UAC bypass, MSI privilege escalation).

## Extending to the full benchmark

Controls are defined declaratively via the `AC` helper. To add a control, append
another `AC` line with its registry/secpol/auditpol/service check and risk
metadata — the engine, scoring, matrix, and report pick it up automatically.

## Important caveats

- **Read‑only.** The script changes nothing; it only reports.
- This is a **prioritised subset**, not a CIS‑CAT certified full scan (500+
  recommendations). Validate all findings before remediating.
- Some Level 1 items (e.g. rename Administrator/Guest, BitLocker, certain user
  rights) require organisation‑specific values and are best confirmed manually.
- Test remediations in the lab before applying to production; hardening (e.g.
  disabling services, SMB signing, Credential Guard) can affect functionality.
