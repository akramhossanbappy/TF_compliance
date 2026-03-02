#!/bin/bash
###############################################################################
# validate.sh — Run CIS validation after Terraform deploy
# Usage: ./scripts/validate.sh [dev|prod] [region]
###############################################################################
set -euo pipefail

ENV="${1:-dev}"
REGION="${2:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "  CIS Validation — Environment: ${ENV}"
echo "=========================================="

# Step 1: Get SG IDs from Terraform output
echo ""
echo "1. Reading Terraform outputs..."
cd "${PROJECT_DIR}/terraform/environments/${ENV}"

SG_IDS=$(terraform output -json all_security_group_ids 2>/dev/null | python3 -c "
import sys, json
ids = json.load(sys.stdin)
print(' '.join(['--sg-ids ' + sid for sid in ids]))
" 2>/dev/null || echo "")

if [ -z "$SG_IDS" ]; then
    echo "   ⚠ Could not read Terraform outputs. Validating ALL security groups."
    SG_IDS=""
fi

# Step 2: Activate Python venv
echo ""
echo "2. Activating Python environment..."
cd "${PROJECT_DIR}/python-validator"
if [ -d ".venv" ]; then
    source .venv/bin/activate
else
    echo "   Setting up venv first..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt -q
fi

# Step 3: Run validation
echo ""
echo "3. Running CIS benchmark validation..."
echo ""

# shellcheck disable=SC2086
python main.py --region "${REGION}" ${SG_IDS} --output "reports/${ENV}" --format both

echo ""
echo "=========================================="
echo "  Reports saved to: python-validator/reports/${ENV}/"
echo "=========================================="
