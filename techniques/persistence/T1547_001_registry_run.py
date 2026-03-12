"""
Technique: T1547.001 — Boot/Logon Autostart Execution: Registry Run Keys
Tactic:    Persistence
Reference: https://attack.mitre.org/techniques/T1547/001/

ATTACKER CHAIN:
  Post-execution → write to Run/RunOnce registry key →
  payload executes on every logon → maintains persistence across reboots

DETECTION LOGIC:
  - Registry write to HKCU/HKLM Run keys by non-standard processes
  - Value pointing to temp/user-writable paths
  - Encoded or obfuscated command line in registry value
  - New Run key created outside business hours

FALSE POSITIVE SOURCES:
  - Legitimate software installers (exclude signed + known paths)
  - Windows Update components
  - Common tools: Dropbox, OneDrive, Teams (build exclusion list)
"""

TECHNIQUE_ID   = "T1547.001"
TECHNIQUE_NAME = "Boot/Logon Autostart: Registry Run Keys"
TACTIC         = "persistence"
PLATFORM       = ["Windows"]
SEVERITY       = "High"
FALSE_POSITIVE_RISK = "HIGH"  # Many legit apps use Run keys

PERSISTENCE_REGISTRY_KEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]

SUSPICIOUS_VALUE_PATTERNS = [
    "\\AppData\\Roaming\\",
    "\\Temp\\",
    "\\Downloads\\",
    "powershell", "cmd /c", "wscript",
    "base64", "-enc",
]

FP_EXCLUSIONS = {
    "known_vendors": ["Microsoft", "Google", "Dropbox", "OneDrive", "Zoom", "Teams"],
    "known_paths": [
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\",
        "C:\\Windows\\"
    ],
    "known_values": ["OneDrive", "Teams", "Discord", "Slack"]
}


def execute(safe_mode: bool = True) -> dict:
    """
    Simulate registry persistence technique.
    Safe mode: writes a clearly-labeled test key that is immediately cleaned up.
    """
    import os
    import platform

    artifact_path = "reports/artifacts/T1547.001_simulated.txt"
    os.makedirs("reports/artifacts", exist_ok=True)

    if platform.system() == "Windows" and not safe_mode:
        import winreg
        test_key_name = "AEF_TestPersistence_DELETEME"
        test_key_value = "C:\\Temp\\harmless_test.bat"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, test_key_name, 0, winreg.REG_SZ, test_key_value)
            winreg.CloseKey(key)

            # Immediately clean up
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.DeleteValue(key, test_key_name)
            winreg.CloseKey(key)

            with open(artifact_path, "w") as f:
                f.write(f"[LIVE] Registry key written and cleaned: {test_key_name}\n")
            return {
                "artifacts": [artifact_path],
                "indicators": ["registry", "run key", "persistence", "HKCU"],
                "notes": "Live mode — test key written and immediately deleted"
            }
        except Exception as e:
            pass

    # Safe simulation
    with open(artifact_path, "w") as f:
        f.write("[SIMULATED] T1547.001 - Registry Run Key Persistence\n")
        f.write(f"Simulated key: HKCU\\...\\Run\n")
        f.write(f"Simulated value: C:\\Users\\victim\\AppData\\Roaming\\malware.exe\n")
        f.write(f"Persistence keys targeted: {PERSISTENCE_REGISTRY_KEYS[:2]}\n")
        f.write(f"Suspicious patterns: {SUSPICIOUS_VALUE_PATTERNS}\n")

    return {
        "artifacts": [artifact_path],
        "indicators": ["registry", "run", "persistence", "AppData", "Roaming"],
        "notes": "Safe simulation — no actual registry modification",
        "simulated": True
    }


def get_kql_rule() -> str:
    return """
// T1547.001 - Registry Run Key Persistence
// HIGH false positive risk — many legitimate apps use Run keys
// FALSE POSITIVE REDUCTION:
//   - Only flag values pointing to user-writable/temp paths
//   - Exclude known software vendor registry values
//   - Require suspicious path OR encoded command in value data
//   - Exclude writes from signed installer processes

let RunKeys = dynamic([
    "\\\\CurrentVersion\\\\Run",
    "\\\\CurrentVersion\\\\RunOnce"
]);
let SuspiciousPaths = dynamic(["\\\\AppData\\\\Roaming\\\\","\\\\Temp\\\\","\\\\Downloads\\\\"]);
let FPExcludedValues = dynamic(["OneDrive","Teams","Discord","Slack","Dropbox","GoogleDrive"]);
let FPExcludedParents = dynamic(["msiexec.exe","TrustedInstaller.exe","setup.exe"]);

DeviceRegistryEvents
| where RegistryKey has_any (RunKeys)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryValueData has_any (SuspiciousPaths)
    or RegistryValueData has_any ("powershell","cmd /c","wscript","base64","-enc")
| where RegistryValueName !in~ (FPExcludedValues)
| where InitiatingProcessFileName !in~ (FPExcludedParents)
| extend
    PointsToTempPath = RegistryValueData has_any (SuspiciousPaths),
    HasEncodedPayload = RegistryValueData has_any ("base64","-enc","FromBase64"),
    UsesScriptHost = RegistryValueData has_any ("wscript","cscript","mshta")
| extend PersistenceRiskScore =
    toint(PointsToTempPath) * 3 +
    toint(HasEncodedPayload) * 4 +
    toint(UsesScriptHost) * 3
| where PersistenceRiskScore >= 3
| project TimeGenerated, DeviceName, AccountName,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, PersistenceRiskScore
| order by PersistenceRiskScore desc
"""
