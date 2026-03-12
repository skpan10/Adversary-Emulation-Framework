"""
HTML Report Generator
Produces a professional, self-contained HTML report from emulation results.
"""

import json
from datetime import datetime
from pathlib import Path


def generate_html_report(run_path: str, gap_path: str = None) -> str:
    with open(run_path) as f:
        run = json.load(f)

    gap = {}
    if gap_path and Path(gap_path).exists():
        with open(gap_path) as f:
            gap = json.load(f)

    coverage = run.get("coverage_pct", 0)
    color = "#22c55e" if coverage >= 80 else "#f59e0b" if coverage >= 60 else "#ef4444"
    results = run.get("results", [])

    rows = ""
    for r in results:
        det = r["detection_status"]
        status_badge = {
            "DETECTED": '<span style="background:#22c55e;color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">DETECTED</span>',
            "MISSED":   '<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">MISSED</span>',
            "PARTIAL":  '<span style="background:#f59e0b;color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">PARTIAL</span>',
            "UNKNOWN":  '<span style="background:#6b7280;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">UNKNOWN</span>',
        }.get(det, det)

        fp_badge = {
            "LOW":    '<span style="color:#22c55e;font-weight:600">LOW</span>',
            "MEDIUM": '<span style="color:#f59e0b;font-weight:600">MEDIUM</span>',
            "HIGH":   '<span style="color:#ef4444;font-weight:600">HIGH</span>',
        }.get(r.get("false_positive_risk",""), r.get("false_positive_risk",""))

        rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:700;color:#60a5fa">{r['technique_id']}</td>
          <td>{r['technique_name']}</td>
          <td style="text-transform:capitalize">{r['tactic'].replace('_',' ')}</td>
          <td>{status_badge}</td>
          <td>{fp_badge}</td>
          <td style="color:#9ca3af">{r.get('notes','')[:60]}</td>
        </tr>"""

    gap_rows = ""
    for g in gap.get("gap_report", []):
        pri_color = "#ef4444" if g["priority_label"]=="CRITICAL" else "#f59e0b" if g["priority_label"]=="HIGH" else "#60a5fa"
        gap_rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:700;color:#60a5fa">{g['technique_id']}</td>
          <td>{g['technique_name']}</td>
          <td style="text-transform:capitalize">{g['tactic'].replace('_',' ')}</td>
          <td><span style="color:{pri_color};font-weight:700">{g['priority_label']}</span></td>
          <td style="font-size:12px;color:#9ca3af">{g['recommended_action'][:80]}...</td>
        </tr>"""

    ba_section = ""
    if gap.get("before_after_comparison"):
        ba = gap["before_after_comparison"]
        delta_color = "#22c55e" if ba["delta_coverage_pct"] > 0 else "#ef4444"
        ba_section = f"""
        <div class="card">
          <h2>Before vs After Rule Tuning</h2>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-top:16px">
            <div class="metric-box">
              <div class="metric-label">Before</div>
              <div class="metric-value">{ba['before']['coverage_pct']}%</div>
              <div class="metric-sub">{ba['before']['detected']}/{ba['before']['total']} techniques</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">After</div>
              <div class="metric-value">{ba['after']['coverage_pct']}%</div>
              <div class="metric-sub">{ba['after']['detected']}/{ba['after']['total']} techniques</div>
            </div>
            <div class="metric-box">
              <div class="metric-label">Improvement</div>
              <div class="metric-value" style="color:{delta_color}">{ba['delta_coverage_pct']:+.1f}%</div>
              <div class="metric-sub">{ba['trend']}</div>
            </div>
          </div>
          <p style="margin-top:16px;color:#9ca3af">{ba['improvement_summary']}</p>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Adversary Emulation Report — {run['run_id']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', system-ui, sans-serif; padding: 40px; }}
  h1 {{ font-size: 28px; font-weight: 800; color: #f8fafc; margin-bottom: 4px; }}
  h2 {{ font-size: 18px; font-weight: 700; color: #cbd5e1; margin-bottom: 16px; }}
  .subtitle {{ color: #64748b; font-size: 14px; margin-bottom: 32px; }}
  .grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }}
  .metric-box {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; text-align: center; }}
  .metric-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
  .metric-value {{ font-size: 32px; font-weight: 800; }}
  .metric-sub {{ font-size: 12px; color: #64748b; margin-top: 4px; }}
  .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
  .coverage-bar-wrap {{ background: #0f172a; border-radius: 8px; height: 24px; margin: 16px 0; overflow: hidden; }}
  .coverage-bar-fill {{ height: 100%; border-radius: 8px; transition: width 1s ease; display: flex; align-items: center; padding-left: 12px; font-size: 13px; font-weight: 700; color: #000; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #0f172a; color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 10px 16px; text-align: left; border-bottom: 1px solid #334155; }}
  td {{ padding: 12px 16px; border-bottom: 1px solid #1e293b; vertical-align: middle; }}
  tr:hover td {{ background: #1e293b55; }}
  .badge-run {{ background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 4px 10px; font-size: 12px; font-family: monospace; color: #60a5fa; }}
</style>
</head>
<body>
<h1>🛡️ Adversary Emulation Framework</h1>
<p class="subtitle">
  Run ID: <span class="badge-run">{run['run_id']}</span> &nbsp;|&nbsp;
  Platform: {run['target_platform']} &nbsp;|&nbsp;
  {run['start_time'][:19].replace('T',' ')} UTC
</p>

<div class="grid">
  <div class="metric-box">
    <div class="metric-label">Coverage</div>
    <div class="metric-value" style="color:{color}">{coverage}%</div>
    <div class="metric-sub">Detection Rate</div>
  </div>
  <div class="metric-box">
    <div class="metric-label">Techniques</div>
    <div class="metric-value" style="color:#f8fafc">{run['total_techniques']}</div>
    <div class="metric-sub">Total Executed</div>
  </div>
  <div class="metric-box">
    <div class="metric-label">Detected</div>
    <div class="metric-value" style="color:#22c55e">{run['detected']}</div>
    <div class="metric-sub">Rules Fired</div>
  </div>
  <div class="metric-box">
    <div class="metric-label">Missed</div>
    <div class="metric-value" style="color:#ef4444">{run['missed']}</div>
    <div class="metric-sub">Coverage Gaps</div>
  </div>
  <div class="metric-box">
    <div class="metric-label">Partial</div>
    <div class="metric-value" style="color:#f59e0b">{run['partial']}</div>
    <div class="metric-sub">Needs Tuning</div>
  </div>
</div>

<div class="card">
  <h2>Overall Detection Coverage</h2>
  <div class="coverage-bar-wrap">
    <div class="coverage-bar-fill" style="width:{coverage}%;background:{color}">
      {coverage}% Covered
    </div>
  </div>
</div>

{ba_section}

<div class="card">
  <h2>Technique Results — MITRE ATT&CK Mapping</h2>
  <table>
    <thead>
      <tr>
        <th>Technique ID</th><th>Name</th><th>Tactic</th>
        <th>Detection</th><th>FP Risk</th><th>Notes</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>

<div class="card">
  <h2>Detection Gap Analysis — Prioritized Remediation</h2>
  <table>
    <thead>
      <tr>
        <th>Technique</th><th>Name</th><th>Tactic</th>
        <th>Priority</th><th>Recommended Action</th>
      </tr>
    </thead>
    <tbody>{gap_rows if gap_rows else '<tr><td colspan="5" style="text-align:center;color:#22c55e;padding:24px">✅ No critical gaps detected</td></tr>'}</tbody>
  </table>
</div>

<p style="text-align:center;color:#334155;margin-top:32px;font-size:12px">
  Adversary Emulation Framework — Detection Coverage Report — Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
</p>
</body>
</html>"""

    output_path = f"reports/run_{run['run_id']}_report.html"
    with open(output_path, "w") as f:
        f.write(html)
    print(f"HTML report generated: {output_path}")
    return output_path


if __name__ == "__main__":
    import argparse, glob
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", help="Run JSON path (defaults to latest)")
    parser.add_argument("--gap", help="Gap analysis JSON path")
    args = parser.parse_args()

    run_path = args.run
    if not run_path:
        runs = sorted(glob.glob("reports/run_*.json"))
        run_path = runs[-1] if runs else None

    if run_path:
        generate_html_report(run_path, args.gap)
    else:
        print("No run reports found. Run engine.py first.")
