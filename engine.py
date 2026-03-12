"""
Adversary Emulation Engine
Core orchestrator for executing MITRE ATT&CK techniques and validating detection coverage.
"""

import json
import time
import hashlib
import platform
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("reports/emulation.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TechniqueResult:
    technique_id: str
    technique_name: str
    tactic: str
    status: str                        # EXECUTED | SKIPPED | FAILED
    detection_status: str              # DETECTED | MISSED | PARTIAL | UNKNOWN
    execution_time_ms: float
    artifacts_generated: list[str] = field(default_factory=list)
    detection_rule_fired: Optional[str] = None
    false_positive_risk: str = "LOW"   # LOW | MEDIUM | HIGH
    notes: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class EmulationReport:
    run_id: str
    operator: str
    target_platform: str
    start_time: str
    end_time: str
    total_techniques: int
    detected: int
    missed: int
    partial: int
    skipped: int
    coverage_pct: float
    results: list[TechniqueResult]
    gap_analysis: list[dict]
    recommendations: list[str]


class EmulationEngine:
    """
    Core engine that loads technique modules, executes them safely,
    and validates detection coverage against configured KQL rules.
    """

    def __init__(self, config_path: str = "lab/config.json"):
        self.config = self._load_config(config_path)
        self.results: list[TechniqueResult] = []
        self.run_id = hashlib.sha256(
            datetime.utcnow().isoformat().encode()
        ).hexdigest()[:12]
        self.platform = platform.system()
        logger.info(f"Engine initialized | Run ID: {self.run_id} | Platform: {self.platform}")

    def _load_config(self, path: str) -> dict:
        try:
            with open(path) as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config not found at {path}, using defaults")
            return {
                "operator": "unknown",
                "safe_mode": True,
                "detection_validation": True,
                "report_format": ["json", "html"],
                "excluded_techniques": []
            }

    def load_techniques(self, tactic_filter: Optional[list] = None) -> list:
        """Dynamically load all technique modules from the techniques/ directory."""
        import importlib.util
        techniques = []
        base = Path("techniques")

        for tactic_dir in sorted(base.iterdir()):
            if not tactic_dir.is_dir():
                continue
            if tactic_filter and tactic_dir.name not in tactic_filter:
                continue
            for py_file in sorted(tactic_dir.glob("T*.py")):
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)
                    techniques.append(mod)
                    logger.info(f"Loaded technique: {py_file.stem}")
                except Exception as e:
                    logger.error(f"Failed to load {py_file.stem}: {e}")
        return techniques

    def execute_technique(self, module) -> TechniqueResult:
        """Execute a single technique module and record the result."""
        tid = getattr(module, "TECHNIQUE_ID", "UNKNOWN")
        name = getattr(module, "TECHNIQUE_NAME", "Unknown")
        tactic = getattr(module, "TACTIC", "Unknown")
        fp_risk = getattr(module, "FALSE_POSITIVE_RISK", "LOW")

        if tid in self.config.get("excluded_techniques", []):
            logger.info(f"SKIPPED (excluded): {tid}")
            return TechniqueResult(
                technique_id=tid, technique_name=name, tactic=tactic,
                status="SKIPPED", detection_status="UNKNOWN",
                execution_time_ms=0, false_positive_risk=fp_risk,
                notes="Excluded by config"
            )

        logger.info(f"Executing: {tid} - {name}")
        start = time.time()

        try:
            artifacts = module.execute(safe_mode=self.config.get("safe_mode", True))
            elapsed = (time.time() - start) * 1000

            detection_status = "UNKNOWN"
            rule_fired = None

            if self.config.get("detection_validation", True):
                detection_status, rule_fired = self._validate_detection(tid, artifacts)

            result = TechniqueResult(
                technique_id=tid, technique_name=name, tactic=tactic,
                status="EXECUTED", detection_status=detection_status,
                execution_time_ms=round(elapsed, 2),
                artifacts_generated=artifacts.get("artifacts", []),
                detection_rule_fired=rule_fired,
                false_positive_risk=fp_risk,
                notes=artifacts.get("notes", "")
            )
            logger.info(f"  → Status: {detection_status} | Rule: {rule_fired or 'none'}")
            return result

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            logger.error(f"  → FAILED: {e}")
            return TechniqueResult(
                technique_id=tid, technique_name=name, tactic=tactic,
                status="FAILED", detection_status="UNKNOWN",
                execution_time_ms=round(elapsed, 2),
                false_positive_risk=fp_risk, notes=str(e)
            )

    def _validate_detection(self, technique_id: str, artifacts: dict) -> tuple[str, Optional[str]]:
        """
        Check if a detection rule exists and would fire for this technique.
        In a live environment this queries Sentinel/Defender APIs.
        In lab mode it checks the local rules/ directory for matching logic.
        """
        rules_path = Path("detection/rules")
        rule_file = rules_path / f"{technique_id}.kql"

        if not rule_file.exists():
            return "MISSED", None

        with open(rule_file) as f:
            rule_content = f.read()

        # Check if artifacts match what the rule looks for
        indicators = artifacts.get("indicators", [])
        for indicator in indicators:
            if any(kw.lower() in rule_content.lower() for kw in indicator.split()):
                return "DETECTED", rule_file.name

        return "PARTIAL", rule_file.name

    def run(self, tactic_filter: Optional[list] = None) -> EmulationReport:
        """Full emulation run: load → execute → validate → report."""
        start_time = datetime.utcnow().isoformat()
        logger.info("=" * 60)
        logger.info(f"ADVERSARY EMULATION RUN STARTED | ID: {self.run_id}")
        logger.info("=" * 60)

        techniques = self.load_techniques(tactic_filter)
        if not techniques:
            logger.warning("No techniques loaded. Check techniques/ directory.")

        for module in techniques:
            result = self.execute_technique(module)
            self.results.append(result)

        end_time = datetime.utcnow().isoformat()

        # Tally results
        detected = sum(1 for r in self.results if r.detection_status == "DETECTED")
        missed = sum(1 for r in self.results if r.detection_status == "MISSED")
        partial = sum(1 for r in self.results if r.detection_status == "PARTIAL")
        skipped = sum(1 for r in self.results if r.status == "SKIPPED")
        executed = sum(1 for r in self.results if r.status == "EXECUTED")
        coverage = round((detected / executed * 100) if executed > 0 else 0, 1)

        gap_analysis = self._build_gap_analysis()
        recommendations = self._build_recommendations()

        report = EmulationReport(
            run_id=self.run_id,
            operator=self.config.get("operator", "unknown"),
            target_platform=self.platform,
            start_time=start_time,
            end_time=end_time,
            total_techniques=len(self.results),
            detected=detected,
            missed=missed,
            partial=partial,
            skipped=skipped,
            coverage_pct=coverage,
            results=self.results,
            gap_analysis=gap_analysis,
            recommendations=recommendations
        )

        self._save_report(report)
        self._print_summary(report)
        return report

    def _build_gap_analysis(self) -> list[dict]:
        gaps = []
        for r in self.results:
            if r.detection_status in ("MISSED", "PARTIAL"):
                gaps.append({
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "tactic": r.tactic,
                    "gap_type": r.detection_status,
                    "false_positive_risk": r.false_positive_risk,
                    "priority": "HIGH" if r.tactic in (
                        "credential_access", "lateral_movement"
                    ) else "MEDIUM",
                    "recommended_rule": f"detection/rules/{r.technique_id}.kql"
                })
        return sorted(gaps, key=lambda x: x["priority"])

    def _build_recommendations(self) -> list[str]:
        recs = []
        missed = [r for r in self.results if r.detection_status == "MISSED"]
        high_fp = [r for r in self.results if r.false_positive_risk == "HIGH"]

        if missed:
            tactics = list(set(r.tactic for r in missed))
            recs.append(
                f"Create detection rules for {len(missed)} undetected techniques "
                f"across tactics: {', '.join(tactics)}"
            )
        if high_fp:
            recs.append(
                f"Review and tune {len(high_fp)} rules with HIGH false positive risk "
                f"— add parent process and command-line exclusion logic"
            )
        coverage = round(
            sum(1 for r in self.results if r.detection_status == "DETECTED") /
            max(sum(1 for r in self.results if r.status == "EXECUTED"), 1) * 100, 1
        )
        if coverage < 70:
            recs.append(
                f"Current coverage {coverage}% is below 70% baseline — "
                f"prioritize credential_access and lateral_movement gaps"
            )
        return recs

    def _save_report(self, report: EmulationReport):
        Path("reports").mkdir(exist_ok=True)
        json_path = f"reports/run_{report.run_id}.json"
        with open(json_path, "w") as f:
            json.dump(asdict(report), f, indent=2)
        logger.info(f"Report saved: {json_path}")

    def _print_summary(self, report: EmulationReport):
        bar_len = 30
        filled = int(bar_len * report.coverage_pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"""
╔══════════════════════════════════════════════════════════╗
║          ADVERSARY EMULATION — RUN SUMMARY               ║
╠══════════════════════════════════════════════════════════╣
║  Run ID   : {report.run_id:<44} ║
║  Platform : {report.target_platform:<44} ║
╠══════════════════════════════════════════════════════════╣
║  Total Techniques : {report.total_techniques:<37} ║
║  ✅ Detected      : {report.detected:<37} ║
║  ❌ Missed        : {report.missed:<37} ║
║  ⚠️  Partial       : {report.partial:<37} ║
║  ⏭  Skipped       : {report.skipped:<37} ║
╠══════════════════════════════════════════════════════════╣
║  Coverage : [{bar}] {report.coverage_pct:>5}%  ║
╠══════════════════════════════════════════════════════════╣
║  Detection Gaps   : {len(report.gap_analysis):<37} ║
║  Recommendations  : {len(report.recommendations):<37} ║
╚══════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Adversary Emulation Engine")
    parser.add_argument("--tactics", nargs="+", help="Filter by tactic(s)")
    parser.add_argument("--config", default="lab/config.json")
    args = parser.parse_args()

    engine = EmulationEngine(config_path=args.config)
    engine.run(tactic_filter=args.tactics)
