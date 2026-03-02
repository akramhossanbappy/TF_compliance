"""
Report Generator — Produces JSON and HTML reports from validation findings.
"""

import json
import os
from datetime import datetime, timezone
from typing import List
from .cis_rules import Finding


class ReportGenerator:
    """Generates CIS benchmark validation reports in JSON and HTML formats."""

    def __init__(self, findings: List[Finding], summary: dict, output_dir: str = "reports"):
        self.findings = findings
        self.summary = summary
        self.output_dir = output_dir
        self.timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    def _findings_to_dicts(self) -> List[dict]:
        return [
            {
                "rule_id": f.rule_id,
                "rule_title": f.rule_title,
                "status": f.status.value,
                "severity": f.severity.value,
                "resource_id": f.resource_id,
                "resource_name": f.resource_name,
                "description": f.description,
                "remediation": f.remediation,
                "details": f.details,
            }
            for f in self.findings
        ]

    def generate_json(self) -> str:
        """Generate JSON report and return the file path."""
        filepath = os.path.join(self.output_dir, f"cis_report_{self.timestamp}.json")
        report = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "benchmark": "CIS AWS Foundations Benchmark v3.0",
                "scope": "Security Groups",
            },
            "summary": self.summary,
            "findings": self._findings_to_dicts(),
        }

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        print(f"📄 JSON report saved: {filepath}")
        return filepath

    def generate_html(self) -> str:
        """Generate HTML report and return the file path."""
        filepath = os.path.join(self.output_dir, f"cis_report_{self.timestamp}.html")
        findings_dicts = self._findings_to_dicts()

        # Group findings by resource
        by_resource = {}
        for f in findings_dicts:
            rid = f["resource_id"]
            if rid not in by_resource:
                by_resource[rid] = {"name": f["resource_name"], "findings": []}
            by_resource[rid]["findings"].append(f)

        # Build HTML
        findings_html = ""
        for sg_id, data in by_resource.items():
            rows = ""
            for f in data["findings"]:
                status_class = {
                    "PASS": "status-pass",
                    "FAIL": "status-fail",
                    "WARN": "status-warn"
                }.get(f["status"], "")

                severity_class = {
                    "CRITICAL": "sev-critical",
                    "HIGH": "sev-high",
                    "MEDIUM": "sev-medium",
                    "LOW": "sev-low"
                }.get(f["severity"], "")

                rows += f"""
                <tr>
                    <td><span class="badge {status_class}">{f['status']}</span></td>
                    <td><span class="badge {severity_class}">{f['severity']}</span></td>
                    <td><strong>{f['rule_id']}</strong></td>
                    <td>{f['description']}</td>
                    <td>{f['remediation']}</td>
                </tr>"""

            findings_html += f"""
            <div class="sg-section">
                <h3>🔒 {data['name']} <span class="sg-id">({sg_id})</span></h3>
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Severity</th>
                            <th>Rule</th>
                            <th>Description</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>{rows}
                    </tbody>
                </table>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIS Benchmark Report — Security Groups</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #1a1a2e; margin-bottom: 0.5rem; }}
        h2 {{ color: #16213e; margin: 1.5rem 0 1rem; }}
        h3 {{ color: #0f3460; margin-bottom: 0.5rem; }}
        .meta {{ color: #666; margin-bottom: 2rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .summary-card {{ background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card .number {{ font-size: 2rem; font-weight: 700; }}
        .summary-card .label {{ color: #666; font-size: 0.875rem; margin-top: 0.25rem; }}
        .num-pass {{ color: #27ae60; }}
        .num-fail {{ color: #e74c3c; }}
        .num-warn {{ color: #f39c12; }}
        .num-total {{ color: #2c3e50; }}
        .sg-section {{ background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .sg-id {{ color: #888; font-weight: 400; font-size: 0.875rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ background: #f8f9fa; padding: 0.75rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; color: #666; border-bottom: 2px solid #dee2e6; }}
        td {{ padding: 0.75rem; border-bottom: 1px solid #eee; font-size: 0.875rem; }}
        .badge {{ padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
        .status-pass {{ background: #d4edda; color: #155724; }}
        .status-fail {{ background: #f8d7da; color: #721c24; }}
        .status-warn {{ background: #fff3cd; color: #856404; }}
        .sev-critical {{ background: #721c24; color: #fff; }}
        .sev-high {{ background: #e74c3c; color: #fff; }}
        .sev-medium {{ background: #f39c12; color: #fff; }}
        .sev-low {{ background: #3498db; color: #fff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CIS AWS Benchmark — Security Group Validation Report</h1>
        <p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Benchmark: CIS AWS Foundations v3.0</p>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="number num-total">{self.summary['total_checks']}</div>
                <div class="label">Total Checks</div>
            </div>
            <div class="summary-card">
                <div class="number num-pass">{self.summary['passed']}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card">
                <div class="number num-fail">{self.summary['failed']}</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-card">
                <div class="number num-warn">{self.summary['warnings']}</div>
                <div class="label">Warnings</div>
            </div>
            <div class="summary-card">
                <div class="number num-pass">{self.summary['pass_rate']}</div>
                <div class="label">Pass Rate</div>
            </div>
        </div>

        <h2>Findings by Security Group</h2>
        {findings_html}
    </div>
</body>
</html>"""

        with open(filepath, "w") as f:
            f.write(html)

        print(f"📊 HTML report saved: {filepath}")
        return filepath

    def generate(self, fmt: str = "both") -> List[str]:
        """Generate reports in the specified format(s)."""
        files = []
        if fmt in ("json", "both"):
            files.append(self.generate_json())
        if fmt in ("html", "both"):
            files.append(self.generate_html())
        return files
