"""
MITRE ATT&CK Coverage Matrix
Generates a Navigator-compatible layer file and terminal coverage table.
"""

import json
from pathlib import Path

# Full framework coverage mapping
MITRE_COVERAGE_MAP = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "has_rule": True,
        "has_emulation": True,
        "fp_handling": True,
        "parent_process_logic": True,
        "cmdline_parsing": True,
        "coverage_score": 95
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "tactic": "Credential Access",
        "has_rule": True,
        "has_emulation": True,
        "fp_handling": True,
        "parent_process_logic": True,
        "cmdline_parsing": True,
        "coverage_score": 90
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "tactic": "Persistence",
        "has_rule": True,
        "has_emulation": True,
        "fp_handling": True,
        "parent_process_logic": True,
        "cmdline_parsing": False,
        "coverage_score": 80
    },
    "T1021.002": {
        "name": "SMB/Admin Shares",
        "tactic": "Lateral Movement",
        "has_rule": True,
        "has_emulation": True,
        "fp_handling": True,
        "parent_process_logic": False,
        "cmdline_parsing": True,
        "coverage_score": 85
    },
    "T1562.001": {
        "name": "Disable Security Tools",
        "tactic": "Defense Evasion",
        "has_rule": True,
        "has_emulation": True,
        "fp_handling": True,
        "parent_process_logic": False,
        "cmdline_parsing": True,
        "coverage_score": 92
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "has_rule": True,
        "has_emulation": False,
        "fp_handling": True,
        "parent_process_logic": False,
        "cmdline_parsing": False,
        "coverage_score": 75
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "has_rule": True,
        "has_emulation": False,
        "fp_handling": True,
        "parent_process_logic": False,
        "cmdline_parsing": False,
        "coverage_score": 70
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "has_rule": True,
        "has_emulation": False,
        "fp_handling": True,
        "parent_process_logic": True,
        "cmdline_parsing": True,
        "coverage_score": 88
    },
}


def print_coverage_table():
    """Print a formatted MITRE coverage table to terminal."""
    print("\n" + "="*90)
    print("  MITRE ATT&CK COVERAGE MATRIX")
    print("="*90)
    print(f"{'Technique':<15} {'Name':<35} {'Tactic':<20} {'Rule':<6} {'Emul':<6} {'FP':<6} {'Score'}")
    print("-"*90)

    total_score = 0
    for tid, data in sorted(MITRE_COVERAGE_MAP.items()):
        rule  = "✅" if data["has_rule"] else "❌"
        emul  = "✅" if data["has_emulation"] else "⬜"
        fp    = "✅" if data["fp_handling"] else "❌"
        score = data["coverage_score"]
        total_score += score
        score_bar = "█" * (score // 10) + "░" * (10 - score // 10)
        print(f"{tid:<15} {data['name']:<35} {data['tactic']:<20} {rule:<6} {emul:<6} {fp:<6} [{score_bar}] {score}%")

    avg = total_score / len(MITRE_COVERAGE_MAP)
    bar = "█" * int(avg // 10) + "░" * (10 - int(avg // 10))
    print("-"*90)
    print(f"{'OVERALL AVERAGE':<76} [{bar}] {avg:.1f}%")
    print("="*90)

    # Quality breakdown
    full_coverage = sum(1 for d in MITRE_COVERAGE_MAP.values()
                       if d["has_rule"] and d["has_emulation"] and d["fp_handling"])
    print(f"\n  Techniques with full coverage (rule + emulation + FP handling): {full_coverage}/{len(MITRE_COVERAGE_MAP)}")
    print(f"  Techniques needing emulation module : {sum(1 for d in MITRE_COVERAGE_MAP.values() if not d['has_emulation'])}")
    print(f"  Techniques needing FP improvement   : {sum(1 for d in MITRE_COVERAGE_MAP.values() if not d['fp_handling'])}\n")


def export_navigator_layer() -> str:
    """Export ATT&CK Navigator compatible layer JSON."""
    techniques = []
    for tid, data in MITRE_COVERAGE_MAP.items():
        score = data["coverage_score"]
        color = (
            "#22c55e" if score >= 85 else
            "#f59e0b" if score >= 65 else
            "#ef4444"
        )
        tactic = data["tactic"].lower().replace(" ", "-")
        techniques.append({
            "techniqueID": tid.split(".")[0],
            "subtechniqueId": tid if "." in tid else None,
            "tactic": tactic,
            "score": score,
            "color": color,
            "comment": f"{data['name']} | FP Handled: {data['fp_handling']} | Coverage: {score}%",
            "enabled": True
        })

    layer = {
        "name": "Adversary Emulation Framework — Coverage",
        "versions": {"attack": "14", "navigator": "4.9"},
        "domain": "enterprise-attack",
        "description": "Detection coverage from Adversary Emulation Framework runs",
        "techniques": [t for t in techniques if t["subtechniqueId"] is None or t["subtechniqueId"]],
        "gradient": {
            "colors": ["#ef4444", "#f59e0b", "#22c55e"],
            "minValue": 0,
            "maxValue": 100
        }
    }

    output = "reports/navigator_layer.json"
    Path("reports").mkdir(exist_ok=True)
    with open(output, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"ATT&CK Navigator layer exported: {output}")
    return output


if __name__ == "__main__":
    print_coverage_table()
    export_navigator_layer()
