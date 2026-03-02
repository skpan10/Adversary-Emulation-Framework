"""
Technique: T1003.001 — OS Credential Dumping: LSASS Memory
Tactic:    Credential Access
Reference: https://attack.mitre.org/techniques/T1003/001/

ATTACKER CHAIN:
  Post-access → dump LSASS memory → extract NTLM hashes / Kerberos tickets
  → pass-the-hash / pass-the-ticket for lateral movement

DETECTION LOGIC:
  - Process accessing lsass.exe memory (OpenProcess with PROCESS_VM_READ)
  - Known dump tools: mimikatz, procdump, comsvcs.dll MiniDump
  - Unsigned process reading lsass memory
  - Suspicious command line: "lsass" + "minidump" or "comsvcs"

FALSE POSITIVE SOURCES:
  - AV/EDR products reading LSASS (exclude by process signature)
  - Windows Error Reporting (WerFault.exe)
  - Crash dump collection tools (exclude known vendor paths)
"""

TECHNIQUE_ID   = "T1003.001"
TECHNIQUE_NAME = "OS Credential Dumping: LSASS Memory"
TACTIC         = "credential_access"
PLATFORM       = ["Windows"]
SEVERITY       = "Critical"
FALSE_POSITIVE_RISK = "LOW"

KNOWN_DUMP_TOOLS = [
    "mimikatz.exe", "procdump.exe", "procdump64.exe",
    "nanodump.exe", "dumpert.exe", "safetydump.exe"
]

SUSPICIOUS_CMDLINE_PATTERNS = [
    "lsass", "minidump", "comsvcs.dll",
    "sekurlsa", "logonpasswords", "privilege::debug"
]

FP_EXCLUSIONS = {
    "processes": ["MsMpEng.exe", "WerFault.exe", "csrss.exe"],
    "signed_vendors": ["Microsoft", "CrowdStrike", "SentinelOne"],
    "paths": ["C:\\Windows\\System32\\", "C:\\Program Files\\Windows Defender\\"]
}


def execute(safe_mode: bool = True) -> dict:
    """
    Simulate LSASS credential dumping technique.
    ALWAYS runs in safe mode — never actually dumps credentials.
    Generates detection artifacts only.
    """
    import os

    # This technique ALWAYS simulates — we never dump actual credentials
    artifact_path = "reports/artifacts/T1003.001_simulated.txt"
    os.makedirs("reports/artifacts", exist_ok=True)

    with open(artifact_path, "w") as f:
        f.write("[SIMULATED] T1003.001 - LSASS Credential Dump\n")
        f.write("Simulated tool: procdump64.exe -ma lsass.exe lsass.dmp\n")
        f.write("Simulated parent: cmd.exe (spawned by attacker shell)\n")
        f.write(f"Known dump tools: {KNOWN_DUMP_TOOLS}\n")
        f.write(f"Suspicious patterns: {SUSPICIOUS_CMDLINE_PATTERNS}\n")
        f.write("NOTE: Actual credential dumping disabled in all modes\n")

    return {
        "artifacts": [artifact_path],
        "indicators": ["procdump", "lsass", "minidump", "comsvcs"],
        "notes": "Credential dump ALWAYS simulated — artifacts written for rule validation only",
        "simulated": True,
        "technique_metadata": {
            "known_tools": KNOWN_DUMP_TOOLS,
            "suspicious_patterns": SUSPICIOUS_CMDLINE_PATTERNS,
            "fp_exclusions": FP_EXCLUSIONS
        }
    }


def get_kql_rule() -> str:
    return """
// T1003.001 - LSASS Memory Access / Credential Dumping
// CRITICAL severity — very low FP rate with proper exclusions
// FALSE POSITIVE REDUCTION:
//   - Excludes AV/EDR products by process name
//   - Excludes WerFault (crash dumps)
//   - Excludes System32 signed binaries
//   - Scores by tool name match + command line + parent

let KnownDumpTools = dynamic(["mimikatz","procdump","nanodump","dumpert","safetydump"]);
let FPExcluded = dynamic(["MsMpEng.exe","WerFault.exe","csrss.exe"]);
let FPPaths = dynamic(["C:\\\\Windows\\\\System32\\\\","C:\\\\Program Files\\\\Windows Defender\\\\"]);

DeviceProcessEvents
| where FileName has_any (KnownDumpTools)
    or ProcessCommandLine has_any ("lsass","minidump","comsvcs.dll","sekurlsa","logonpasswords")
| where InitiatingProcessFileName !in~ (FPExcluded)
| where not(FolderPath has_any (FPPaths))
| extend
    IsKnownTool = FileName has_any (KnownDumpTools),
    HasLsassRef = ProcessCommandLine has "lsass",
    HasMiniDump = ProcessCommandLine has_any ("minidump","MiniDump","comsvcs"),
    IsSigned = isnotempty(ProcessVersionInfoCompanyName)
| extend RiskScore =
    toint(IsKnownTool) * 5 +
    toint(HasLsassRef) * 3 +
    toint(HasMiniDump) * 3 +
    toint(not(IsSigned)) * 2
| where RiskScore >= 5
| project TimeGenerated, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName,
    RiskScore, IsKnownTool, HasLsassRef, SHA256
| order by RiskScore desc
"""
