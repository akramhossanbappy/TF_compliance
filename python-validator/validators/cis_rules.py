"""
CIS AWS Foundations Benchmark — Security Group Rule Definitions.

Each rule is a dataclass with an ID, description, severity, and a check function.
The check function receives a security group dict (from boto3) and returns
a list of Finding objects.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional
import ipaddress


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    status: Status
    severity: Severity
    resource_id: str
    resource_name: str
    description: str
    remediation: str
    details: Optional[str] = None


@dataclass
class CISRule:
    rule_id: str
    title: str
    description: str
    severity: Severity
    cis_section: str
    check_fn: Optional[Callable] = None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _get_sg_name(sg: dict) -> str:
    """Extract Name tag from security group."""
    for tag in sg.get("Tags", []):
        if tag["Key"] == "Name":
            return tag["Value"]
    return sg.get("GroupName", "unnamed")


def _is_open_cidr(cidr: str) -> bool:
    """Check if a CIDR is 0.0.0.0/0 or ::/0."""
    return cidr in ("0.0.0.0/0", "::/0")


def _is_overly_broad_cidr(cidr: str, max_prefix: int = 8) -> bool:
    """Check if CIDR prefix length is dangerously broad."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.prefixlen <= max_prefix
    except ValueError:
        return False


def _port_in_range(target_port: int, from_port: int, to_port: int) -> bool:
    """Check if a target port falls within a rule's port range."""
    if from_port == -1 and to_port == -1:
        return True  # All traffic
    return from_port <= target_port <= to_port


def _is_all_traffic(rule: dict) -> bool:
    """Check if rule allows all protocols/ports."""
    return rule.get("IpProtocol") == "-1"


# ---------------------------------------------------------------------------
# CIS 5.1: No unrestricted SSH (port 22) from 0.0.0.0/0
# ---------------------------------------------------------------------------

def check_cis_5_1(sg: dict, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    for rule in sg.get("IpPermissions", []):
        if _is_all_traffic(rule) or _port_in_range(22, rule.get("FromPort", 0), rule.get("ToPort", 0)):
            for ip_range in rule.get("IpRanges", []):
                if _is_open_cidr(ip_range.get("CidrIp", "")):
                    findings.append(Finding(
                        rule_id="CIS-5.1",
                        rule_title="No unrestricted SSH access",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows SSH (port 22) from 0.0.0.0/0",
                        remediation="Restrict SSH access to specific CIDR blocks (e.g., corporate VPN IP range)",
                        details=f"Rule: {rule}"
                    ))
            for ip_range in rule.get("Ipv6Ranges", []):
                if _is_open_cidr(ip_range.get("CidrIpv6", "")):
                    findings.append(Finding(
                        rule_id="CIS-5.1",
                        rule_title="No unrestricted SSH access",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows SSH (port 22) from ::/0",
                        remediation="Restrict SSH access to specific IPv6 CIDR blocks",
                        details=f"Rule: {rule}"
                    ))

    if not findings:
        findings.append(Finding(
            rule_id="CIS-5.1",
            rule_title="No unrestricted SSH access",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="SSH access is properly restricted",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CIS 5.2: No unrestricted RDP (port 3389) from 0.0.0.0/0
# ---------------------------------------------------------------------------

def check_cis_5_2(sg: dict, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    for rule in sg.get("IpPermissions", []):
        if _is_all_traffic(rule) or _port_in_range(3389, rule.get("FromPort", 0), rule.get("ToPort", 0)):
            for ip_range in rule.get("IpRanges", []):
                if _is_open_cidr(ip_range.get("CidrIp", "")):
                    findings.append(Finding(
                        rule_id="CIS-5.2",
                        rule_title="No unrestricted RDP access",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows RDP (port 3389) from 0.0.0.0/0",
                        remediation="Restrict RDP access to specific CIDR blocks",
                        details=f"Rule: {rule}"
                    ))
            for ip_range in rule.get("Ipv6Ranges", []):
                if _is_open_cidr(ip_range.get("CidrIpv6", "")):
                    findings.append(Finding(
                        rule_id="CIS-5.2",
                        rule_title="No unrestricted RDP access",
                        status=Status.FAIL,
                        severity=Severity.HIGH,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows RDP (port 3389) from ::/0",
                        remediation="Restrict RDP access to specific IPv6 CIDR blocks",
                        details=f"Rule: {rule}"
                    ))

    if not findings:
        findings.append(Finding(
            rule_id="CIS-5.2",
            rule_title="No unrestricted RDP access",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="RDP access is properly restricted",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CIS 5.3: No unrestricted ingress (all ports from 0.0.0.0/0)
# ---------------------------------------------------------------------------

def check_cis_5_3(sg: dict, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    for rule in sg.get("IpPermissions", []):
        if _is_all_traffic(rule):
            for ip_range in rule.get("IpRanges", []):
                if _is_open_cidr(ip_range.get("CidrIp", "")):
                    findings.append(Finding(
                        rule_id="CIS-5.3",
                        rule_title="No unrestricted ingress",
                        status=Status.FAIL,
                        severity=Severity.CRITICAL,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows ALL traffic from 0.0.0.0/0",
                        remediation="Remove the rule allowing all traffic from 0.0.0.0/0. Use specific port and CIDR rules.",
                        details=f"Rule: {rule}"
                    ))

    if not findings:
        findings.append(Finding(
            rule_id="CIS-5.3",
            rule_title="No unrestricted ingress",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            resource_id=sg_id,
            resource_name=sg_name,
            description="No unrestricted ingress rules found",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CIS 5.4: Default security group restricts all traffic
# ---------------------------------------------------------------------------

def check_cis_5_4(sg: dict, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    if sg.get("GroupName") != "default":
        return [Finding(
            rule_id="CIS-5.4",
            rule_title="Default SG restricts all traffic",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="Not a default security group — skipped",
            remediation="N/A"
        )]

    has_ingress = len(sg.get("IpPermissions", [])) > 0
    has_egress = len(sg.get("IpPermissionsEgress", [])) > 0

    if has_ingress or has_egress:
        findings.append(Finding(
            rule_id="CIS-5.4",
            rule_title="Default SG restricts all traffic",
            status=Status.FAIL,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="Default security group has active ingress/egress rules",
            remediation="Remove all inbound and outbound rules from the default security group",
            details=f"Ingress rules: {len(sg.get('IpPermissions', []))}, Egress rules: {len(sg.get('IpPermissionsEgress', []))}"
        ))
    else:
        findings.append(Finding(
            rule_id="CIS-5.4",
            rule_title="Default SG restricts all traffic",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="Default security group properly restricts all traffic",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CUSTOM: Overly broad CIDR ranges
# ---------------------------------------------------------------------------

def check_broad_cidrs(sg: dict, config: dict = None, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)
    max_prefix = config.get("max_open_cidr_prefix", 8) if config else 8
    found_issue = False

    for rule in sg.get("IpPermissions", []):
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if _is_overly_broad_cidr(cidr, max_prefix) and not _is_open_cidr(cidr):
                found_issue = True
                findings.append(Finding(
                    rule_id="CUSTOM-BROAD-CIDR",
                    rule_title="No overly broad CIDR ranges",
                    status=Status.WARN,
                    severity=Severity.MEDIUM,
                    resource_id=sg_id,
                    resource_name=sg_name,
                    description=f"Ingress rule uses overly broad CIDR: {cidr} (prefix <= /{max_prefix})",
                    remediation=f"Narrow the CIDR range to be more specific than /{max_prefix}",
                    details=f"Rule: port {rule.get('FromPort')}-{rule.get('ToPort')}, CIDR: {cidr}"
                ))

    if not found_issue:
        findings.append(Finding(
            rule_id="CUSTOM-BROAD-CIDR",
            rule_title="No overly broad CIDR ranges",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            resource_id=sg_id,
            resource_name=sg_name,
            description="No overly broad CIDR ranges found",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CUSTOM: Security group must have a description
# ---------------------------------------------------------------------------

def check_description(sg: dict, **kwargs) -> List[Finding]:
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)
    desc = sg.get("Description", "")

    if not desc or desc.strip() == "" or desc == "default VPC security group":
        return [Finding(
            rule_id="CUSTOM-DESCRIPTION",
            rule_title="SG has meaningful description",
            status=Status.FAIL,
            severity=Severity.LOW,
            resource_id=sg_id,
            resource_name=sg_name,
            description="Security group is missing a meaningful description",
            remediation="Add a descriptive description to the security group"
        )]

    return [Finding(
        rule_id="CUSTOM-DESCRIPTION",
        rule_title="SG has meaningful description",
        status=Status.PASS,
        severity=Severity.LOW,
        resource_id=sg_id,
        resource_name=sg_name,
        description="Security group has a description",
        remediation="N/A"
    )]


# ---------------------------------------------------------------------------
# CUSTOM: Unrestricted egress
# ---------------------------------------------------------------------------

def check_unrestricted_egress(sg: dict, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    for rule in sg.get("IpPermissionsEgress", []):
        if _is_all_traffic(rule):
            for ip_range in rule.get("IpRanges", []):
                if _is_open_cidr(ip_range.get("CidrIp", "")):
                    findings.append(Finding(
                        rule_id="CUSTOM-EGRESS",
                        rule_title="Egress is restricted",
                        status=Status.WARN,
                        severity=Severity.MEDIUM,
                        resource_id=sg_id,
                        resource_name=sg_name,
                        description="Security group allows ALL outbound traffic to 0.0.0.0/0",
                        remediation="Restrict egress to specific ports and destinations",
                        details=f"Rule: {rule}"
                    ))

    if not findings:
        findings.append(Finding(
            rule_id="CUSTOM-EGRESS",
            rule_title="Egress is restricted",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            resource_id=sg_id,
            resource_name=sg_name,
            description="Egress rules are properly restricted",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CUSTOM: Sensitive ports open to public
# ---------------------------------------------------------------------------

def check_sensitive_ports(sg: dict, config: dict = None, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    sensitive = config.get("sensitive_ports", []) if config else []
    public_allowed = config.get("public_allowed_ports", [80, 443]) if config else [80, 443]
    found_issue = False

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)

        for sp in sensitive:
            port = sp["port"]
            if _port_in_range(port, from_port, to_port) and port not in public_allowed:
                for ip_range in rule.get("IpRanges", []):
                    if _is_open_cidr(ip_range.get("CidrIp", "")):
                        found_issue = True
                        findings.append(Finding(
                            rule_id="CUSTOM-SENSITIVE-PORTS",
                            rule_title="No sensitive ports open to public",
                            status=Status.FAIL,
                            severity=Severity(sp.get("severity", "HIGH")),
                            resource_id=sg_id,
                            resource_name=sg_name,
                            description=f"{sp['name']} (port {port}) is open to 0.0.0.0/0",
                            remediation=f"Restrict {sp['name']} (port {port}) to specific CIDR blocks",
                            details=f"Rule: port {from_port}-{to_port}"
                        ))

    if not found_issue:
        findings.append(Finding(
            rule_id="CUSTOM-SENSITIVE-PORTS",
            rule_title="No sensitive ports open to public",
            status=Status.PASS,
            severity=Severity.HIGH,
            resource_id=sg_id,
            resource_name=sg_name,
            description="No sensitive ports open to public",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# CUSTOM: Required tags present
# ---------------------------------------------------------------------------

def check_required_tags(sg: dict, config: dict = None, **kwargs) -> List[Finding]:
    findings = []
    sg_id = sg["GroupId"]
    sg_name = _get_sg_name(sg)

    required = config.get("required_tags", ["Name", "Environment"]) if config else ["Name", "Environment"]
    existing_keys = {tag["Key"] for tag in sg.get("Tags", [])}
    missing = [t for t in required if t not in existing_keys]

    if missing:
        findings.append(Finding(
            rule_id="CUSTOM-TAGS",
            rule_title="Required tags present",
            status=Status.FAIL,
            severity=Severity.LOW,
            resource_id=sg_id,
            resource_name=sg_name,
            description=f"Missing required tags: {', '.join(missing)}",
            remediation=f"Add the following tags: {', '.join(missing)}"
        ))
    else:
        findings.append(Finding(
            rule_id="CUSTOM-TAGS",
            rule_title="Required tags present",
            status=Status.PASS,
            severity=Severity.LOW,
            resource_id=sg_id,
            resource_name=sg_name,
            description="All required tags are present",
            remediation="N/A"
        ))

    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

ALL_RULES = [
    CISRule("CIS-5.1", "No unrestricted SSH", "Ensure no SG allows ingress from 0.0.0.0/0 to port 22", Severity.HIGH, "5.1", check_cis_5_1),
    CISRule("CIS-5.2", "No unrestricted RDP", "Ensure no SG allows ingress from 0.0.0.0/0 to port 3389", Severity.HIGH, "5.2", check_cis_5_2),
    CISRule("CIS-5.3", "No unrestricted ingress", "Ensure no SG allows unrestricted ingress (all ports from 0.0.0.0/0)", Severity.CRITICAL, "5.3", check_cis_5_3),
    CISRule("CIS-5.4", "Default SG restricts all", "Ensure the default SG of every VPC restricts all traffic", Severity.HIGH, "5.4", check_cis_5_4),
    CISRule("CUSTOM-BROAD-CIDR", "No broad CIDRs", "Ensure no overly broad CIDR ranges (prefix <= /8)", Severity.MEDIUM, "custom", check_broad_cidrs),
    CISRule("CUSTOM-DESCRIPTION", "SG has description", "Ensure all SGs have a meaningful description", Severity.LOW, "custom", check_description),
    CISRule("CUSTOM-EGRESS", "Restricted egress", "Ensure egress is not open to 0.0.0.0/0 all traffic", Severity.MEDIUM, "custom", check_unrestricted_egress),
    CISRule("CUSTOM-SENSITIVE-PORTS", "No sensitive ports public", "Ensure no sensitive ports are open to 0.0.0.0/0", Severity.HIGH, "custom", check_sensitive_ports),
    CISRule("CUSTOM-TAGS", "Required tags", "Ensure all required tags are present on SGs", Severity.LOW, "custom", check_required_tags),
]
