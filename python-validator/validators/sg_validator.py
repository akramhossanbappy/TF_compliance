"""
Security Group Validator — Fetches SGs from AWS and runs all CIS checks.
"""

import boto3
from typing import List, Optional
from .cis_rules import ALL_RULES, Finding


class SGValidator:
    """Validates AWS security groups against CIS benchmark rules."""

    def __init__(self, region: str, profile: Optional[str] = None, config: dict = None):
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self.ec2 = self.session.client("ec2")
        self.config = config or {}
        self.findings: List[Finding] = []

    def fetch_security_groups(self, sg_ids: Optional[List[str]] = None) -> List[dict]:
        """Fetch security groups from AWS. Optionally filter by SG IDs."""
        params = {}
        if sg_ids:
            params["GroupIds"] = sg_ids

        security_groups = []
        paginator = self.ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate(**params):
            security_groups.extend(page["SecurityGroups"])

        return security_groups

    def fetch_network_interfaces(self) -> dict:
        """Fetch network interfaces to identify unused security groups."""
        sg_usage = {}
        paginator = self.ec2.get_paginator("describe_network_interfaces")

        for page in paginator.paginate():
            for eni in page["NetworkInterfaces"]:
                for group in eni.get("Groups", []):
                    sg_id = group["GroupId"]
                    sg_usage[sg_id] = sg_usage.get(sg_id, 0) + 1

        return sg_usage

    def validate(self, sg_ids: Optional[List[str]] = None) -> List[Finding]:
        """Run all CIS checks against fetched security groups."""
        print("🔍 Fetching security groups from AWS...")
        security_groups = self.fetch_security_groups(sg_ids)
        print(f"   Found {len(security_groups)} security group(s)")

        print("🔍 Checking network interface associations...")
        sg_usage = self.fetch_network_interfaces()

        self.findings = []

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            print(f"\n📋 Validating: {sg_name} ({sg_id})")

            for rule in ALL_RULES:
                if rule.check_fn:
                    try:
                        rule_findings = rule.check_fn(sg, config=self.config)
                        self.findings.extend(rule_findings)

                        for f in rule_findings:
                            icon = "✅" if f.status.value == "PASS" else "❌" if f.status.value == "FAIL" else "⚠️"
                            print(f"   {icon} [{f.rule_id}] {f.status.value}: {f.description}")
                    except Exception as e:
                        print(f"   ❗ Error running {rule.rule_id}: {e}")
                        self.findings.append(Finding(
                            rule_id=rule.rule_id,
                            rule_title=rule.title,
                            status=Finding.__class__,
                            severity=rule.severity,
                            resource_id=sg_id,
                            resource_name=sg_name,
                            description=f"Error during check: {str(e)}",
                            remediation="Investigate the error"
                        ))

            # Check for unused security groups
            if sg_id not in sg_usage and sg.get("GroupName") != "default":
                self.findings.append(Finding(
                    rule_id="CUSTOM-UNUSED",
                    rule_title="No unused security groups",
                    status=Finding.__module__ and __import__("validators.cis_rules", fromlist=["Status"]).Status.WARN,
                    severity=__import__("validators.cis_rules", fromlist=["Severity"]).Severity.LOW,
                    resource_id=sg_id,
                    resource_name=sg_name,
                    description="Security group is not attached to any network interface",
                    remediation="Review and delete unused security groups to reduce attack surface"
                ))

        return self.findings

    def get_summary(self) -> dict:
        """Return a summary of all findings."""
        total = len(self.findings)
        passed = sum(1 for f in self.findings if f.status.value == "PASS")
        failed = sum(1 for f in self.findings if f.status.value == "FAIL")
        warnings = sum(1 for f in self.findings if f.status.value == "WARN")

        by_severity = {}
        for f in self.findings:
            sev = f.severity.value
            if sev not in by_severity:
                by_severity[sev] = {"PASS": 0, "FAIL": 0, "WARN": 0}
            by_severity[sev][f.status.value] = by_severity[sev].get(f.status.value, 0) + 1

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "pass_rate": f"{(passed / total * 100):.1f}%" if total > 0 else "N/A",
            "by_severity": by_severity
        }
