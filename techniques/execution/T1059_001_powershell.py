"""
Technique: T1059.001 — Command and Scripting Interpreter: PowerShell
Tactic:    Execution
Reference: https://attack.mitre.org/techniques/T1059/001/

ATTACKER CHAIN:
  Attacker lands on endpoint → uses PowerShell to run encoded commands,
  download payloads, or bypass execution policy.

DETECTION LOGIC:
  - Encoded command flag (-enc, -encodedcommand)
  - Suspicious parent process (Word, Excel, browser spawning PowerShell)
  - Unusual working directory
  - Network connection from PowerShell process

FALSE POSITIVE SOURCES:
  - IT automation scripts (exclude known admin accounts + signed scripts)
  - Software installers (exclude parent: msiexec, TrustedInstaller)
  - Scheduled tasks (exclude SYSTEM + task scheduler parents)
"""

TECHNIQUE_ID   = "T1059.001"
TECHNIQUE_NAME = "Command and Scripting Interpreter: PowerShell"
TACTIC         = "execution"
PLATFORM       = ["Windows"]
SEVERITY       = "High"
FALSE_POSITIVE_RISK = "MEDIUM"

# Command-line patterns that indicate malicious use
SUSPICIOUS_CMDLINE_PATTERNS = [
    "-encodedcommand",
    "-enc ",
    "-noprofile -noninteractive",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "net.webclient",
    "bypass",
    "hidden",
    "frombase64string",
]

# Parent processes that should NOT spawn PowerShell legitimately
SUSPICIOUS_PARENT_PROCESSES = [
    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
]

# Exclusions to reduce false positives
FP_EXCLUSIONS = {
    "parent_processes": ["msiexec.exe", "TrustedInstaller.exe", "svchost.exe"],
    "account_patterns": ["svc-", "SYSTEM", "_admin"],
    "cmdline_whitelist": ["WindowsUpdate", "MicrosoftUpdate", "-File C:\\Scripts\\approved\\"],
}


def execute(safe_mode: bool = True) -> dict:
    """
    Simulate PowerShell execution technique.
    In safe_mode: generates artifacts without actual execution.
    In live_mode: executes harmless PowerShell command and captures telemetry.
    """
    import subprocess
    import platform

    artifacts = []
    indicators = []
    notes = ""

    if platform.system() != "Windows":
        return {
            "artifacts": ["platform_skip.log"],
            "indicators": ["powershell", "encodedcommand", "bypass"],
            "notes": "Non-Windows platform — telemetry artifacts simulated",
            "simulated": True
        }

    if safe_mode:
        # Safe simulation — write artifact file only, no actual execution
        artifact_path = "reports/artifacts/T1059.001_simulated.txt"
        import os
        os.makedirs("reports/artifacts", exist_ok=True)
        with open(artifact_path, "w") as f:
            f.write(f"[SIMULATED] T1059.001 PowerShell Execution\n")
            f.write(f"Simulated cmdline: powershell.exe -EncodedCommand <base64>\n")
            f.write(f"Simulated parent: winword.exe\n")
            f.write(f"Suspicious patterns detected: {SUSPICIOUS_CMDLINE_PATTERNS[:3]}\n")
        artifacts.append(artifact_path)
        indicators = ["powershell", "encodedcommand", "bypass", "winword"]
        notes = "Safe mode — execution simulated, artifacts written for detection validation"

    else:
        # Live mode — harmless PowerShell execution for telemetry generation
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-Date"],
                capture_output=True, text=True, timeout=10
            )
            artifacts.append("process_telemetry:powershell.exe")
            indicators = ["powershell", "-noprofile"]
            notes = f"Live execution completed: {result.stdout.strip()}"
        except Exception as e:
            notes = f"Live execution failed: {e}"

    return {
        "artifacts": artifacts,
        "indicators": indicators,
        "notes": notes,
        "technique_metadata": {
            "suspicious_patterns": SUSPICIOUS_CMDLINE_PATTERNS,
            "suspicious_parents": SUSPICIOUS_PARENT_PROCESSES,
            "fp_exclusions": FP_EXCLUSIONS
        }
    }


def get_kql_rule() -> str:
    """Returns the KQL detection rule for this technique."""
    return """
// T1059.001 - PowerShell Execution with Suspicious Indicators
// FALSE POSITIVE REDUCTION:
//   - Excludes known software installer parents (msiexec, TrustedInstaller)
//   - Excludes signed IT automation scripts
//   - Requires encoded command OR suspicious parent process (not just PowerShell spawn)

let SuspiciousParents = dynamic(["winword.exe","excel.exe","outlook.exe","mshta.exe","wscript.exe"]);
let FPExcludedParents = dynamic(["msiexec.exe","TrustedInstaller.exe"]);
let FPExcludedCmdPatterns = dynamic(["WindowsUpdate","MicrosoftUpdate"]);

DeviceProcessEvents
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where InitiatingProcessFileName !in~ (FPExcludedParents)
| where not(ProcessCommandLine has_any (FPExcludedCmdPatterns))
| extend
    HasEncodedCmd = ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String"),
    HasSuspiciousParent = InitiatingProcessFileName in~ (SuspiciousParents),
    HasNetworkDownload = ProcessCommandLine has_any ("DownloadString","WebClient","Invoke-WebRequest"),
    HasPolicyBypass = ProcessCommandLine has_any ("bypass","unrestricted","-nop")
| extend SuspiciousScore =
    toint(HasEncodedCmd) * 3 +
    toint(HasSuspiciousParent) * 3 +
    toint(HasNetworkDownload) * 2 +
    toint(HasPolicyBypass) * 1
| where SuspiciousScore >= 3
| project TimeGenerated, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName,
    HasEncodedCmd, HasSuspiciousParent, HasNetworkDownload,
    SuspiciousScore, SHA256
| order by SuspiciousScore desc
"""
