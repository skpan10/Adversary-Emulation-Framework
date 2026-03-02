"""
Detection Gap Analyzer
Compares emulation run results to produce:
  - Coverage % metric
  - Before vs After rule tuning comparison
  - Prioritized gap report
  - Rule quality scoring
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Optional


class GapAnalyzer:
    """
    Analyzes detection coverage gaps across emulation runs.
    Supports before/after comparison to quantify rule tuning improvements.
    """

    TACTIC_PRIORITY = {
        "credential_access": 1,
        "lateral_movement": 1,
        "defense_evasion": 2,
        "execution": 2,
        "persistence": 3,
        "discovery": 4,
        "collection": 4,
    }

    def __init__(self, baseline_run: Optional[str] = None):
        """
        baseline_run: path to a previous run JSON for before/after comparison.
        """
        self.baseline = self._load_run(baseline_run) if baseline_run else None

    def _load_run(self, path: str) -> dict:
        with open(path) as f:
            return json.load(f)

    def analyze(self, current_run_path: str) -> dict:
        current = self._load_run(current_run_path)
        analysis = {
            "run_id": current["run_id"],
            "analyzed_at": datetime.utcnow().isoformat(),
            "coverage_summary": self._coverage_summary(current),
            "gap_report": self._gap_report(current),
            "rule_quality_scores": self._rule_quality_scores(current),
            "tactic_coverage": self._tactic_coverage(current),
        }

        if self.baseline:
            analysis["before_after_comparison"] = self._before_after(
                self.baseline, current
            )

        return analysis

    def _coverage_summary(self, run: dict) -> dict:
        results = run["results"]
        executed = [r for r in results if r["status"] == "EXECUTED"]
        detected = [r for r in executed if r["detection_status"] == "DETECTED"]
        missed = [r for r in executed if r["detection_status"] == "MISSED"]
        partial = [r for r in executed if r["detection_status"] == "PARTIAL"]

        coverage_pct = round(len(detected) / len(executed) * 100, 1) if executed else 0

        # Coverage rating
        if coverage_pct >= 80:
            rating = "STRONG"
            rating_color = "green"
        elif coverage_pct >= 60:
            rating = "MODERATE"
            rating_color = "yellow"
        else:
            rating = "WEAK"
            rating_color = "red"

        return {
            "total_executed": len(executed),
            "detected": len(detected),
            "missed": len(missed),
            "partial": len(partial),
            "coverage_pct": coverage_pct,
            "rating": rating,
            "rating_color": rating_color,
            "coverage_bar": self._coverage_bar(coverage_pct)
        }

    def _coverage_bar(self, pct: float, width: int = 40) -> str:
        filled = int(width * pct / 100)
        return "█" * filled + "░" * (width - filled) + f" {pct}%"

    def _gap_report(self, run: dict) -> list[dict]:
        gaps = []
        for r in run["results"]:
            if r["detection_status"] not in ("MISSED", "PARTIAL"):
                continue

            priority = self.TACTIC_PRIORITY.get(r["tactic"], 5)
            gaps.append({
                "technique_id": r["technique_id"],
                "technique_name": r["technique_name"],
                "tactic": r["tactic"],
                "gap_type": r["detection_status"],
                "false_positive_risk": r["false_positive_risk"],
                "priority_score": priority,
                "priority_label": "CRITICAL" if priority == 1 else
                                  "HIGH" if priority == 2 else "MEDIUM",
                "recommended_action": self._recommend_action(r),
                "rule_path": f"detection/rules/{r['technique_id']}.kql"
            })

        return sorted(gaps, key=lambda x: x["priority_score"])

    def _recommend_action(self, result: dict) -> str:
        if result["detection_status"] == "MISSED":
            return (
                f"Create new KQL rule at detection/rules/{result['technique_id']}.kql. "
                f"Focus on: command-line patterns, parent process validation, "
                f"suspicious path references."
            )
        elif result["detection_status"] == "PARTIAL":
            return (
                f"Tune existing rule {result['technique_id']}.kql — "
                f"expand indicator coverage or lower detection threshold. "
                f"Review false positive exclusions."
            )
        return "No action required."

    def _rule_quality_scores(self, run: dict) -> list[dict]:
        """
        Score each executed technique's detection rule on quality dimensions.
        """
        scores = []
        rules_dir = Path("detection/rules")

        for r in run["results"]:
            if r["status"] != "EXECUTED":
                continue

            rule_file = rules_dir / f"{r['technique_id']}.kql"
            score = {
                "technique_id": r["technique_id"],
                "has_rule": rule_file.exists(),
                "detected": r["detection_status"] == "DETECTED",
                "fp_risk": r["false_positive_risk"],
                "quality_dimensions": {}
            }

            if rule_file.exists():
                content = rule_file.read_text()
                dims = {
                    "has_fp_exclusions":   "FP" in content or "false positive" in content.lower(),
                    "has_parent_process":  "InitiatingProcess" in content or "parent" in content.lower(),
                    "has_cmdline_parsing": "ProcessCommandLine" in content or "CommandLine" in content,
                    "has_scoring":         "Score" in content or "score" in content,
                    "has_time_window":     "ago(" in content,
                    "has_order_by":        "order by" in content.lower(),
                    "has_project":         "| project" in content.lower(),
                    "has_mitre_comment":   "T1" in content,
                }
                score["quality_dimensions"] = dims
                quality_score = sum(1 for v in dims.values() if v)
                score["quality_score"] = quality_score
                score["quality_pct"] = round(quality_score / len(dims) * 100)
                score["quality_grade"] = (
                    "A" if quality_score >= 7 else
                    "B" if quality_score >= 5 else
                    "C" if quality_score >= 3 else "D"
                )
            else:
                score["quality_score"] = 0
                score["quality_pct"] = 0
                score["quality_grade"] = "F"

            scores.append(score)

        return sorted(scores, key=lambda x: x["quality_score"], reverse=True)

    def _tactic_coverage(self, run: dict) -> dict:
        """Coverage breakdown by MITRE tactic."""
        tactic_map: dict[str, dict] = {}

        for r in run["results"]:
            if r["status"] != "EXECUTED":
                continue
            t = r["tactic"]
            if t not in tactic_map:
                tactic_map[t] = {"detected": 0, "total": 0, "missed": [], "partial": []}
            tactic_map[t]["total"] += 1
            if r["detection_status"] == "DETECTED":
                tactic_map[t]["detected"] += 1
            elif r["detection_status"] == "MISSED":
                tactic_map[t]["missed"].append(r["technique_id"])
            elif r["detection_status"] == "PARTIAL":
                tactic_map[t]["partial"].append(r["technique_id"])

        for t, data in tactic_map.items():
            data["coverage_pct"] = round(
                data["detected"] / data["total"] * 100, 1
            ) if data["total"] > 0 else 0

        return dict(sorted(
            tactic_map.items(),
            key=lambda x: x[1]["coverage_pct"]
        ))

    def _before_after(self, baseline: dict, current: dict) -> dict:
        """
        Before vs After comparison — quantifies improvement from rule tuning.
        """
        def get_stats(run: dict) -> dict:
            results = run["results"]
            executed = [r for r in results if r["status"] == "EXECUTED"]
            detected = sum(1 for r in executed if r["detection_status"] == "DETECTED")
            missed = sum(1 for r in executed if r["detection_status"] == "MISSED")
            return {
                "run_id": run["run_id"],
                "coverage_pct": round(detected / len(executed) * 100, 1) if executed else 0,
                "detected": detected,
                "missed": missed,
                "total": len(executed)
            }

        before = get_stats(baseline)
        after = get_stats(current)

        delta_coverage = round(after["coverage_pct"] - before["coverage_pct"], 1)
        newly_detected = after["detected"] - before["detected"]
        still_missed = after["missed"]

        return {
            "before": before,
            "after": after,
            "delta_coverage_pct": delta_coverage,
            "newly_detected_techniques": newly_detected,
            "remaining_gaps": still_missed,
            "improvement_summary": (
                f"Coverage improved by {delta_coverage}% "
                f"({newly_detected} new techniques detected). "
                f"{still_missed} gaps remain."
            ),
            "trend": "IMPROVING" if delta_coverage > 0 else
                     "STABLE" if delta_coverage == 0 else "DEGRADING"
        }

    def print_report(self, analysis: dict):
        """Pretty-print the gap analysis to terminal."""
        s = analysis["coverage_summary"]
        print(f"""
╔══════════════════════════════════════════════════════════╗
║           DETECTION GAP ANALYSIS REPORT                  ║
╠══════════════════════════════════════════════════════════╣
║  Coverage: [{s['coverage_bar']}]
║  Rating  : {s['rating']:<50} ║
╠══════════════════════════════════════════════════════════╣
║  TACTIC COVERAGE BREAKDOWN                               ║""")

        for tactic, data in analysis["tactic_coverage"].items():
            bar = self._coverage_bar(data["coverage_pct"], 20)
            print(f"║  {tactic:<22} [{bar}]")

        if analysis.get("before_after_comparison"):
            ba = analysis["before_after_comparison"]
            print(f"""╠══════════════════════════════════════════════════════════╣
║  BEFORE vs AFTER RULE TUNING                             ║
║  Before : {ba['before']['coverage_pct']}% ({ba['before']['detected']}/{ba['before']['total']} techniques)
║  After  : {ba['after']['coverage_pct']}% ({ba['after']['detected']}/{ba['after']['total']} techniques)
║  Delta  : {ba['delta_coverage_pct']:+.1f}% | Trend: {ba['trend']}
║  {ba['improvement_summary']}""")

        print(f"""╠══════════════════════════════════════════════════════════╣
║  TOP GAPS (by priority)                                  ║""")
        for gap in analysis["gap_report"][:5]:
            print(f"║  [{gap['priority_label']:<8}] {gap['technique_id']:<12} {gap['technique_name'][:28]}")

        print("╚══════════════════════════════════════════════════════════╝")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Detection Gap Analyzer")
    parser.add_argument("--run", required=True, help="Current run JSON path")
    parser.add_argument("--baseline", help="Baseline run JSON for before/after comparison")
    parser.add_argument("--output", default="reports/gap_analysis.json")
    args = parser.parse_args()

    analyzer = GapAnalyzer(baseline_run=args.baseline)
    analysis = analyzer.analyze(args.run)
    analyzer.print_report(analysis)

    with open(args.output, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"\nFull report saved: {args.output}")
