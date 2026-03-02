#!/usr/bin/env python3
"""
merge_results.py
Normalises tfsec + checkov JSON output into a unified findings format.
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime


# ── Severity mapping ──────────────────────────────────────────────────────────
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def normalise_severity(raw: str) -> str:
    raw = (raw or "").upper()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "ERROR":    "HIGH",
        "MEDIUM":   "MEDIUM",
        "WARNING":  "MEDIUM",
        "LOW":      "LOW",
        "NOTE":     "LOW",
        "INFO":     "INFO",
        "NOTICE":   "INFO",
    }
    return mapping.get(raw, "LOW")


# ── tfsec parser ──────────────────────────────────────────────────────────────
def parse_tfsec(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        sev = normalise_severity(r.get("severity", "LOW"))
        loc = r.get("location", {})
        findings.append({
            "id":          r.get("rule_id", ""),
            "title":       r.get("rule_description", r.get("description", "")),
            "description": r.get("long_description", r.get("rule_description", "")),
            "severity":    sev,
            "severity_rank": SEV_RANK.get(sev, 0),
            "resource":    r.get("resource", ""),
            "file":        loc.get("filename", ""),
            "line_start":  loc.get("start_line", 0),
            "line_end":    loc.get("end_line", 0),
            "impact":      r.get("impact", ""),
            "resolution":  r.get("resolution", ""),
            "links":       r.get("links", []),
            "source":      "tfsec",
            "status":      "FAILED",
        })
    return findings


# ── checkov parser ────────────────────────────────────────────────────────────
def _checkov_severity(check: dict) -> str:
    """
    Extract severity from a checkov failed_check entry.
    checkov's JSON schema has changed across versions:
      - v2 stores severity in check["severity"]
      - some builds put it in check["check_result"]["evaluated_keys"]["severity"]
      - check_result can be a dict OR a list — handle both safely
    """
    # 1. Top-level severity field (most reliable, present in checkov v2+)
    raw = check.get("severity") or ""
    if raw:
        return normalise_severity(str(raw))

    # 2. check_result may be a dict or a list; never call .get() on a list
    check_result = check.get("check_result", {})
    if isinstance(check_result, dict):
        evaluated = check_result.get("evaluated_keys", {})
        if isinstance(evaluated, dict):
            raw = evaluated.get("severity", "")
            if raw:
                return normalise_severity(str(raw))

    # 3. Fallback
    return "LOW"


def _checkov_check_meta(check: dict) -> tuple[str, str, str]:
    """Return (name, guideline_url, check_id) from a check entry."""
    # check["check"] is sometimes a dict, sometimes absent
    meta = check.get("check")
    if isinstance(meta, dict):
        name      = meta.get("name", "") or ""
        guideline = meta.get("guideline", "") or ""
    else:
        name      = ""
        guideline = ""

    check_id = check.get("check_id", "") or ""
    title    = name or check_id
    return title, guideline, check_id


def parse_checkov(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []

    # checkov output can be:
    #   - a single dict  { "results": { "failed_checks": [...] } }
    #   - a list of such dicts (one per check type / runner)
    if isinstance(data, list):
        blocks = data
    elif isinstance(data, dict):
        blocks = [data]
    else:
        return []

    findings = []
    for block in blocks:
        if not isinstance(block, dict):
            continue

        # Results may be nested under "results" or at the top level
        results = block.get("results", block)
        if not isinstance(results, dict):
            continue

        for check in results.get("failed_checks", []):
            if not isinstance(check, dict):
                continue

            sev              = _checkov_severity(check)
            title, guideline, check_id = _checkov_check_meta(check)
            loc              = check.get("file_line_range") or [0, 0]
            if not isinstance(loc, (list, tuple)):
                loc = [0, 0]

            findings.append({
                "id":            check_id,
                "title":         title,
                "description":   title,
                "severity":      sev,
                "severity_rank": SEV_RANK.get(sev, 0),
                "resource":      check.get("resource", "") or "",
                "file":          check.get("file_path", "") or "",
                "line_start":    loc[0] if len(loc) > 0 else 0,
                "line_end":      loc[1] if len(loc) > 1 else 0,
                "impact":        "",
                "resolution":    guideline,
                "links":         [guideline] if guideline else [],
                "source":        "checkov",
                "status":        "FAILED",
            })
    return findings


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Merge tfsec + checkov results")
    parser.add_argument("--tfsec",   required=True, type=Path)
    parser.add_argument("--checkov", required=True, type=Path)
    parser.add_argument("--output",  required=True, type=Path)
    args = parser.parse_args()

    tfsec_findings   = parse_tfsec(args.tfsec)
    checkov_findings = parse_checkov(args.checkov)
    all_findings     = tfsec_findings + checkov_findings

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO
    all_findings.sort(key=lambda x: x["severity_rank"], reverse=True)

    # Build summary
    def count(sev): return sum(1 for f in all_findings if f["severity"] == sev)

    summary = {
        "total":    len(all_findings),
        "critical": count("CRITICAL"),
        "high":     count("HIGH"),
        "medium":   count("MEDIUM"),
        "low":      count("LOW"),
        "info":     count("INFO"),
        "tfsec_count":   len(tfsec_findings),
        "checkov_count": len(checkov_findings),
    }

    output = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "summary":   summary,
        "findings":  all_findings,
    }

    args.output.write_text(json.dumps(output, indent=2))
    print(f"[merge] {len(all_findings)} total findings written to {args.output}")


if __name__ == "__main__":
    main()
