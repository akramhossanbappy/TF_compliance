#!/bin/bash
###############################################################################
# setup.sh — One-click setup for the CIS Benchmark Validation project
###############################################################################
set -euo pipefail

echo "=========================================="
echo "  AWS SG CIS Benchmark — Project Setup"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found: $($1 --version 2>&1 | head -1)"
    else
        echo -e "  ${RED}✗${NC} $1 NOT found — please install it"
        return 1
    fi
}

echo ""
echo "1. Checking prerequisites..."
check_tool terraform
check_tool python3
check_tool aws
check_tool pip3

echo ""
echo "2. Setting up Python virtual environment..."
cd "$(dirname "$0")/../python-validator"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "  ${GREEN}✓${NC} Python dependencies installed"

echo ""
echo "3. Creating report directories..."
mkdir -p reports
echo -e "  ${GREEN}✓${NC} reports/ directory ready"

echo ""
echo "4. Verifying AWS credentials..."
if aws sts get-caller-identity &> /dev/null; then
    ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
    echo -e "  ${GREEN}✓${NC} AWS credentials valid (Account: ${ACCOUNT_ID})"
else
    echo -e "  ${YELLOW}⚠${NC} AWS credentials not configured"
    echo "    Run: aws configure"
fi

echo ""
echo "=========================================="
echo -e "  ${GREEN}Setup complete!${NC}"
echo ""
echo "  Next steps:"
echo "    1. Update terraform/environments/dev/terraform.tfvars"
echo "    2. cd terraform/environments/dev && terraform init && terraform plan"
echo "    3. terraform apply"
echo "    4. cd ../../../python-validator"
echo "    5. source .venv/bin/activate"
echo "    6. python main.py --region us-east-1"
echo "=========================================="
