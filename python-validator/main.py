#!/usr/bin/env python3
"""
CIS Benchmark Validator for AWS Security Groups.

Usage:
    python main.py --region us-east-1
    python main.py --region us-east-1 --profile myprofile
    python main.py --sg-ids sg-xxx sg-yyy --region us-east-1
    python main.py --region us-east-1 --output reports/ --format html
"""

import sys
import os
import yaml
import click
from validators.sg_validator import SGValidator
from validators.report_generator import ReportGenerator


def load_config(config_path: str = "config.yaml") -> dict:
    """Load validation configuration from YAML file."""
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    print(f"⚠️  Config file not found at {config_path}, using defaults")
    return {}


@click.command()
@click.option("--region", required=True, help="AWS region (e.g., us-east-1)")
@click.option("--profile", default=None, help="AWS CLI profile name")
@click.option("--sg-ids", multiple=True, help="Specific security group IDs to validate")
@click.option("--output", default="reports", help="Output directory for reports")
@click.option("--format", "fmt", default="both", type=click.Choice(["json", "html", "both"]), help="Report format")
@click.option("--config", "config_path", default="config.yaml", help="Path to config YAML")
def main(region: str, profile: str, sg_ids: tuple, output: str, fmt: str, config_path: str):
    """
    Validate AWS Security Groups against CIS Benchmarks.

    Connects to your AWS account, fetches all (or specified) security groups,
    and runs CIS AWS Foundations Benchmark checks plus custom security rules.
    """
    print("=" * 60)
    print("  CIS AWS Benchmark — Security Group Validator")
    print("=" * 60)
    print(f"  Region:  {region}")
    print(f"  Profile: {profile or 'default'}")
    print(f"  SG IDs:  {', '.join(sg_ids) if sg_ids else 'all'}")
    print(f"  Output:  {output}")
    print(f"  Format:  {fmt}")
    print("=" * 60)

    # Load configuration
    config = load_config(config_path)

    # Initialize validator
    try:
        validator = SGValidator(region=region, profile=profile, config=config)
    except Exception as e:
        print(f"\n❌ Failed to initialize AWS session: {e}")
        print("   Check your AWS credentials and region.")
        sys.exit(1)

    # Run validation
    try:
        sg_id_list = list(sg_ids) if sg_ids else None
        findings = validator.validate(sg_ids=sg_id_list)
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        sys.exit(1)

    # Get summary
    summary = validator.get_summary()

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total Checks:  {summary['total_checks']}")
    print(f"  ✅ Passed:     {summary['passed']}")
    print(f"  ❌ Failed:     {summary['failed']}")
    print(f"  ⚠️  Warnings:  {summary['warnings']}")
    print(f"  📊 Pass Rate:  {summary['pass_rate']}")
    print("=" * 60)

    # Generate reports
    if findings:
        report_gen = ReportGenerator(findings=findings, summary=summary, output_dir=output)
        report_format = config.get("report", {}).get("format", fmt)
        files = report_gen.generate(fmt=report_format)
        print(f"\n📁 Reports generated:")
        for f in files:
            print(f"   → {f}")

    # Exit with non-zero code if there are failures
    if summary["failed"] > 0:
        print(f"\n🚨 {summary['failed']} check(s) FAILED — review the report for remediation steps.")
        sys.exit(2)
    elif summary["warnings"] > 0:
        print(f"\n⚠️  {summary['warnings']} warning(s) — review recommendations.")
        sys.exit(0)
    else:
        print("\n✅ All checks passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
