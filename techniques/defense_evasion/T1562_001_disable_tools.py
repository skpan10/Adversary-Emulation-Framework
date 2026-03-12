"""
Technique: T1562.001 — Impair Defenses: Disable or Modify Tools
Tactic:    Defense Evasion
Reference: https://attack.mitre.org/techniques/T1562/001/

ATTACKER CHAIN:
  Attacker gains elevated access → disables AV/EDR/logging →
  operates without detection → achieves objectives unimpeded

DETECTION LOGIC:
  - sc.exe stop/delete on security services
  - Set-MpPreference -DisableRealtimeMonitoring
  - Registry writes disabling Windows Defender
  - Audit policy modification (auditpol /set)
  - Event log clearing (wevtutil cl)

FALSE POSITIVE SOURCES:
  - Legitimate AV uninstall during product migration
  - IT admin disabling Defender before installing enterprise AV
  - Exclusion: require change outside of known maintenance windows
"""

TECHNIQUE_ID   = "T1562.001"
TECHNIQUE_NAME = "Impair Defenses: Disable or Modify Security Tools"
TACTIC         = "defense_evasion"
PLATFORM       = ["Windows"]
SEVERITY       = "Critical"
FALSE_POSITIVE_RISK = "LOW"

DEFENSE_IMPAIR_COMMANDS = [
    "Set-MpPreference -DisableRealtimeMonitoring",
    "sc stop WinDefend",
    "sc delete WinDefend",
    "auditpol /set /category:* /success:disable",
    "wevtutil cl System",
    "wevtutil cl Security",
    "net stop \"Windows Defender\"",
]

SECURITY_SERVICES = [
    "WinDefend", "MsMpSvc", "Sense",
    "SecurityHealthService", "wscsvc"
]


def execute(safe_mode: bool = True) -> dict:
    import os

    artifact_path = "reports/artifacts/T1562.001_simulated.txt"
    os.makedirs("reports/artifacts", exist_ok=True)

    with open(artifact_path, "w") as f:
        f.write("[SIMULATED] T1562.001 - Defense Impairment\n")
        f.write("Simulated: Set-MpPreference -DisableRealtimeMonitoring $true\n")
        f.write("Simulated: sc stop WinDefend\n")
        f.write("Simulated: wevtutil cl Security\n")
        f.write(f"Impair commands: {DEFENSE_IMPAIR_COMMANDS[:3]}\n")

    return {
        "artifacts": [artifact_path],
        "indicators": [
            "Set-MpPreference", "DisableRealtimeMonitoring",
            "wevtutil", "sc stop", "WinDefend"
        ],
        "notes": "Safe simulation — no actual security tools modified",
        "simulated": True
    }


def get_kql_rule() -> str:
    return """
// T1562.001 - Defense Impairment Detection
// Critical severity — very low FP rate
// FALSE POSITIVE REDUCTION:
//   - Nearly zero legitimate use cases for disabling real-time protection
//   - Flag any account except SYSTEM performing these actions
//   - Alert immediately, no scoring threshold needed

let DefenseImpairCmds = dynamic([
    "DisableRealtimeMonitoring","DisableBehaviorMonitoring",
    "DisableIOAVProtection","DisableScriptScanning",
    "wevtutil cl","auditpol /set"
]);
let SecurityServices = dynamic(["WinDefend","MsMpSvc","Sense","SecurityHealthService"]);

// Signal 1: PowerShell disabling Defender
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (DefenseImpairCmds)
| extend AlertType = "PowerShell_Defense_Disable"
| union (
    // Signal 2: sc.exe stopping security services
    DeviceProcessEvents
    | where FileName =~ "sc.exe"
    | where ProcessCommandLine has_any ("stop","delete","disabled")
    | where ProcessCommandLine has_any (SecurityServices)
    | extend AlertType = "SC_Security_Service_Stop"
) | union (
    // Signal 3: Event log clearing
    DeviceProcessEvents
    | where FileName =~ "wevtutil.exe"
    | where ProcessCommandLine has_any ("cl ","clear-log")
    | where ProcessCommandLine has_any ("Security","System","Application")
    | extend AlertType = "EventLog_Cleared"
)
| where AccountName != "SYSTEM"  // Filter pure system operations
| project TimeGenerated, DeviceName, AccountName,
    AlertType, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by TimeGenerated desc
"""
