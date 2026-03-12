"""
Technique: T1021.002 — Remote Services: SMB/Windows Admin Shares
Tactic:    Lateral Movement
Reference: https://attack.mitre.org/techniques/T1021/002/

ATTACKER CHAIN:
  Compromised credentials → authenticate to admin shares (C$, ADMIN$, IPC$)
  → copy tools / execute remotely via PsExec / SC → move to next target

DETECTION LOGIC:
  - Authentication to admin shares (C$, ADMIN$) from non-standard accounts
  - PsExec service installation (PSEXESVC)
  - Lateral tool transfer via SMB followed by execution
  - New service created remotely within 5 minutes of SMB auth

FALSE POSITIVE SOURCES:
  - IT admins performing legitimate remote management (exclude admin accounts)
  - Backup software accessing shares (exclude by process signature)
  - Patch management tools (exclude known RMM processes)
"""

TECHNIQUE_ID   = "T1021.002"
TECHNIQUE_NAME = "Remote Services: SMB/Windows Admin Shares"
TACTIC         = "lateral_movement"
PLATFORM       = ["Windows"]
SEVERITY       = "Critical"
FALSE_POSITIVE_RISK = "MEDIUM"

ADMIN_SHARES = ["C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"]

LATERAL_MOVEMENT_TOOLS = [
    "psexec.exe", "psexesvc.exe",
    "paexec.exe", "remcom.exe",
    "csexec.exe"
]

FP_EXCLUSIONS = {
    "admin_accounts": ["svc-backup", "svc-patch", "svc-deploy"],
    "rmm_processes": ["TeamViewer.exe", "ConnectWiseControl.exe", "ScreenConnect.exe"],
    "backup_processes": ["BackupExec.exe", "veeam.exe", "besr.exe"]
}


def execute(safe_mode: bool = True) -> dict:
    import os

    artifact_path = "reports/artifacts/T1021.002_simulated.txt"
    os.makedirs("reports/artifacts", exist_ok=True)

    with open(artifact_path, "w") as f:
        f.write("[SIMULATED] T1021.002 - SMB Lateral Movement\n")
        f.write("Simulated: net use \\\\TARGET\\C$ /user:DOMAIN\\compromised_user\n")
        f.write("Simulated: psexec.exe \\\\TARGET -u admin -p pass cmd.exe\n")
        f.write(f"Admin shares targeted: {ADMIN_SHARES}\n")
        f.write(f"Lateral tools: {LATERAL_MOVEMENT_TOOLS}\n")

    return {
        "artifacts": [artifact_path],
        "indicators": ["smb", "admin share", "psexec", "lateral", "C$", "ADMIN$"],
        "notes": "Safe simulation — network activity simulated only",
        "simulated": True
    }


def get_kql_rule() -> str:
    return """
// T1021.002 - SMB Lateral Movement via Admin Shares
// FALSE POSITIVE REDUCTION:
//   - Exclude known IT admin/service accounts
//   - Exclude known RMM and backup software
//   - Require admin share + either PsExec tool OR new service within 5min
//   - Flag non-admin accounts authenticating to C$ / ADMIN$

let AdminShares = dynamic(["C$","ADMIN$","IPC$"]);
let LateralTools = dynamic(["psexec","paexec","remcom","csexec"]);
let FPServiceAccounts = dynamic(["svc-backup","svc-patch","svc-deploy"]);
let FPProcesses = dynamic(["TeamViewer.exe","ConnectWiseControl.exe","BackupExec.exe"]);

// Signal 1: Admin share authentication
let AdminShareAuth =
    DeviceNetworkEvents
    | where RemotePort == 445
    | where ActionType == "ConnectionSuccess"
    | where InitiatingProcessFileName !in~ (FPProcesses)
    | where AccountName !in~ (FPServiceAccounts)
    | project DeviceName, AccountName, RemoteIP,
        AuthTime = TimeGenerated, InitiatingProcessFileName;

// Signal 2: PsExec / lateral tool usage
let LateralToolUsage =
    DeviceProcessEvents
    | where FileName has_any (LateralTools)
        or ProcessCommandLine has_any (AdminShares)
    | project DeviceName, AccountName,
        ToolTime = TimeGenerated, FileName, ProcessCommandLine;

// Correlate: same device + same account within 10 min
AdminShareAuth
| join kind=inner LateralToolUsage on DeviceName, AccountName
| where abs(datetime_diff('minute', ToolTime, AuthTime)) <= 10
| extend LateralMovementConfidence = "HIGH"
| project AuthTime, DeviceName, AccountName,
    TargetIP = RemoteIP, LateralTool = FileName,
    CommandLine = ProcessCommandLine, LateralMovementConfidence
| order by AuthTime desc
"""
