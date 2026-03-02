# ⚔️ Adversary Emulation Framework

![CI](https://github.com/skpan10/adversary-emulation-framework/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)
![Coverage](https://img.shields.io/badge/Detection%20Coverage-84%25-green)
![License](https://img.shields.io/badge/License-MIT-gray)

> **Validate your detection rules by simulating the attacker. Not the other way around.**

Most detection engineers write KQL rules and assume they work. This framework **proves it** — by executing MITRE ATT&CK techniques against a controlled lab, checking whether your Sentinel/Defender rules actually fire, and generating a gap report with Before vs After coverage metrics.

This is what Microsoft DART and CrowdStrike's detection teams do internally. Now it's open source.

---

## 🧠 The Core Problem This Solves

```
Traditional approach:
  Write rule → Deploy to SIEM → Wait for real attack → Hope it works

This framework:
  Simulate attack → Check if rule fires → Measure coverage % → Fix gaps → Repeat
```

---

## 🏗️ Architecture

```
adversary-emulation-framework/
│
├── engine.py                        # Core orchestrator — loads, executes, validates
│
├── techniques/                      # MITRE ATT&CK technique modules
│   ├── execution/
│   │   └── T1059_001_powershell.py  # Command-line parsing, parent process logic
│   ├── credential_access/
│   │   └── T1003_001_lsass_dump.py  # Tool detection, FP exclusion by vendor
│   ├── persistence/
│   │   └── T1547_001_registry_run.py# Registry monitoring, known-good exclusions
│   ├── lateral_movement/
│   │   └── T1021_002_smb_shares.py  # Multi-signal correlation (SMB + tool)
│   └── defense_evasion/
│       └── T1562_001_disable_tools.py # Defense impairment patterns
│
├── detection/
│   ├── rules/                       # KQL rules matched to each technique
│   │   └── T1059.001.kql            # With FP handling, scoring, parent logic
│   ├── gap_analyzer.py              # Before/After comparison engine
│   └── mitre_coverage.py            # Coverage matrix + Navigator export
│
├── reports/
│   ├── report_generator.py          # HTML report with coverage visualizations
│   └── run_<id>.json                # Machine-readable run artifacts
│
├── lab/
│   └── config.json                  # Safe mode, exclusions, thresholds
│
└── .github/workflows/ci.yml         # Auto-runs emulation + validates coverage
```

---

## 🎯 MITRE ATT&CK Coverage Matrix

| Technique | Name | Tactic | Rule | Emulation | FP Handling | Coverage |
|-----------|------|--------|------|-----------|-------------|----------|
| T1059.001 | PowerShell Execution | Execution | ✅ | ✅ | ✅ | 95% |
| T1003.001 | LSASS Memory Dump | Credential Access | ✅ | ✅ | ✅ | 90% |
| T1547.001 | Registry Run Keys | Persistence | ✅ | ✅ | ✅ | 80% |
| T1021.002 | SMB/Admin Shares | Lateral Movement | ✅ | ✅ | ✅ | 85% |
| T1562.001 | Disable Security Tools | Defense Evasion | ✅ | ✅ | ✅ | 92% |
| T1110 | Brute Force | Credential Access | ✅ | ⬜ | ✅ | 75% |
| T1078 | Valid Accounts | Initial Access | ✅ | ⬜ | ✅ | 70% |
| T1218 | LOLBIN Execution | Defense Evasion | ✅ | ⬜ | ✅ | 88% |

**Overall Detection Coverage: 84.4%** (target: ≥80%)

---

## 🔬 Detection Rule Quality Standards

Every rule in this framework implements all 5 quality dimensions:

### 1. False Positive Handling
```kql
-- Every rule has explicit FP exclusions, not just detection logic
let FPExcludedParents = dynamic(["msiexec.exe","TrustedInstaller.exe"]);
let FPExcludedAccounts = dynamic(["svc-backup","svc-patch"]);
| where InitiatingProcessFileName !in~ (FPExcludedParents)
```

### 2. Parent Process Logic
```kql
-- Rules validate the full process chain, not just the leaf process
let SuspiciousParents = dynamic(["winword.exe","excel.exe","mshta.exe"]);
| extend HasSuspiciousParent = InitiatingProcessFileName in~ (SuspiciousParents)
```

### 3. Command-Line Parsing
```kql
-- Deep command-line inspection with pattern scoring
| extend
    HasEncodedCmd = ProcessCommandLine has_any ("-enc","-encodedcommand"),
    HasNetworkDownload = ProcessCommandLine has_any ("DownloadString","WebClient"),
    HasPolicyBypass = ProcessCommandLine has_any ("bypass","unrestricted")
```

### 4. Suspicious Pattern Extraction
```kql
-- Multi-signal scoring prevents single-indicator false positives
| extend SuspiciousScore =
    toint(HasEncodedCmd) * 3 +
    toint(HasSuspiciousParent) * 3 +
    toint(HasNetworkDownload) * 2
| where SuspiciousScore >= 3   -- Requires multiple signals to fire
```

### 5. Coverage Validation
```python
# Engine automatically validates: did the rule fire for this technique?
detection_status, rule_fired = engine._validate_detection(technique_id, artifacts)
# Output: DETECTED | MISSED | PARTIAL
```

---

## 📊 Before vs After Rule Tuning

The gap analyzer tracks coverage improvement across runs:

```
════════════════════════════════════════════════════
  BEFORE vs AFTER RULE TUNING
════════════════════════════════════════════════════
  Before : 61.5% (8/13 techniques)
  After  : 84.6% (11/13 techniques)
  Delta  : +23.1% | Trend: IMPROVING
  3 new techniques detected. 2 gaps remain.
════════════════════════════════════════════════════
```

**What changed between runs:**
- Added parent process exclusions to T1059.001 → reduced FP rate by 40%
- Added multi-signal scoring to T1547.001 → eliminated common software FPs
- Created new rule for T1021.002 → lateral movement now fully covered

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Windows lab environment (or safe simulation mode on any OS)
- Microsoft Defender for Endpoint / Azure Sentinel (for live validation)

### Run emulation (safe simulation mode)
```bash
git clone https://github.com/skpan10/adversary-emulation-framework
cd adversary-emulation-framework
pip install -r requirements.txt

# Run all techniques (safe mode — no actual execution)
python engine.py

# Run specific tactics only
python engine.py --tactics execution credential_access

# Generate coverage matrix
python detection/mitre_coverage.py
```

### Analyze gaps (with before/after comparison)
```bash
# Single run analysis
python detection/gap_analyzer.py --run reports/run_<id>.json

# Before vs After comparison
python detection/gap_analyzer.py \
  --run reports/run_<current>.json \
  --baseline reports/run_<previous>.json
```

### Generate HTML report
```bash
python reports/report_generator.py --run reports/run_<id>.json --gap reports/gap_analysis.json
```

---

## ⚙️ Safe Mode vs Live Mode

| Mode | What happens | Use when |
|------|-------------|---------|
| `safe_mode: true` (default) | Generates artifacts + telemetry only, zero execution | CI/CD, code review, demos |
| `safe_mode: false` | Executes techniques against local lab environment | Dedicated isolated lab VM only |

> ⚠️ **Never run live mode outside of an isolated lab environment you own and control.**

---

## 📋 Sample Run Output

```
╔══════════════════════════════════════════════════════════╗
║          ADVERSARY EMULATION — RUN SUMMARY               ║
╠══════════════════════════════════════════════════════════╣
║  Run ID   : a3f9c12b8e41                                 ║
║  Platform : Windows                                      ║
╠══════════════════════════════════════════════════════════╣
║  Total Techniques : 5                                    ║
║  ✅ Detected      : 4                                    ║
║  ❌ Missed        : 1                                    ║
║  ⚠️  Partial       : 0                                    ║
╠══════════════════════════════════════════════════════════╣
║  Coverage : [████████████████████████░░░░░░] 80.0%      ║
╠══════════════════════════════════════════════════════════╣
║  Detection Gaps   : 1                                    ║
║  Recommendations  : 2                                    ║
╚══════════════════════════════════════════════════════════╝
```

---

## 🔗 Integration with Detection-as-Code Framework

This framework is designed to pair with the [Detection-as-Code Framework](https://github.com/skpan10/Detection-Rules-):

```
Detection-as-Code Repo          Adversary Emulation Framework
─────────────────────           ──────────────────────────────
KQL rules written here    →     Rules validated here
MITRE ATT&CK mapped       →     Coverage % measured here
FP logic documented       →     FP risk scored here
CI validates syntax       →     CI validates detection works
```

**Together, they form a complete detection engineering loop:**
1. Write rule in Detection-as-Code repo
2. Run emulation framework to validate it fires
3. Check coverage % — did the gap close?
4. Compare Before vs After — quantify the improvement
5. Commit improvements to both repos

---

## 🤝 Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for technique module standards.

**Adding a new technique:**
1. Create `techniques/<tactic>/T<id>_<name>.py`
2. Implement `execute(safe_mode)` returning `{artifacts, indicators, notes}`
3. Create matching `detection/rules/T<id>.kql` with FP handling
4. Run `python detection/mitre_coverage.py` to update the matrix

---

## 📄 License
MIT — Built for the detection engineering community.
