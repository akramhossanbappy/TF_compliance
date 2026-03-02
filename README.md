# AWS EC2 Security Group — Terraform + CIS Benchmark Validator

A complete repository that provisions AWS EC2 Security Groups with Terraform and validates them against **CIS AWS Foundations Benchmark v3.0** controls using a Python validation tool.

---

## Repository Structure

```
TF_compliance/
├── README.md                          # This file
├── terraform/
│   ├── modules/
│   │   └── security-group/
│   │       ├── main.tf                # Security group resource definitions
│   │       ├── variables.tf           # Input variables
│   │       ├── outputs.tf             # Output values
│   │       └── rules.tf              # Ingress/egress rule definitions
│   └── environments/
│       ├── dev/
│       │   ├── main.tf
│       │   ├── variables.tf
│       │   ├── outputs.tf
│       │   ├── terraform.tfvars
│       │   ├── providers.tf
│       │   └── backend.tf
│       └── prod/
│           ├── main.tf
│           ├── variables.tf
│           ├── outputs.tf
│           ├── terraform.tfvars
│           ├── providers.tf
│           └── backend.tf
├── python-validator/
│   ├── requirements.txt
│   ├── config.yaml                    # Validation rules config
│   ├── main.py                        # Entry point
│   └── validators/
│       ├── __init__.py
│       ├── sg_validator.py            # Security group CIS checks
│       ├── cis_rules.py              # CIS rule definitions
│       └── report_generator.py        # HTML/JSON report output
├── scripts/
│   ├── setup.sh                       # One-click setup script
│   └── validate.sh                    # Run validation after deploy
└── .github/
    └── workflows/
        └── ci.yml                     # GitHub Actions CI pipeline
```

---

## Prerequisites

| Tool       | Version  | Purpose                         |
|------------|----------|---------------------------------|
| Terraform  | >= 1.5   | Infrastructure provisioning     |
| Python     | >= 3.9   | CIS benchmark validation        |
| AWS CLI    | >= 2.x   | AWS authentication              |
| pip        | latest   | Python dependency management    |

---

## Step-by-Step Procedure

### Step 1 — Clone and Setup

```bash
git clone <your-repo-url>
cd TF_compliance
chmod +x scripts/*.sh
./scripts/setup.sh
```

### Step 2 — Configure AWS Credentials

```bash
# Option A: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Option B: AWS CLI profile
aws configure --profile dev
```

### Step 3 — Review and Customize Terraform Variables

Edit `terraform/environments/dev/terraform.tfvars` to match your requirements:

```hcl
vpc_id      = "vpc-xxxxxxxx"
environment = "dev"
project     = "my-app"
```

### Step 4 — Deploy Security Groups with Terraform

```bash
cd terraform/environments/dev

terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

### Step 5 — Validate Against CIS Benchmarks

```bash
cd ../../../python-validator

# Install dependencies
pip install -r requirements.txt

# Run the validator
python main.py --region us-east-1 --profile default --output reports/

# Or target specific security groups
python main.py --sg-ids sg-xxxxxxxx sg-yyyyyyyy --region us-east-1
```

### Step 6 — Review Reports

The validator generates reports in `python-validator/reports/`:
- `cis_report_<timestamp>.json` — Machine-readable results
- `cis_report_<timestamp>.html` — Human-readable HTML report

---

## CIS Benchmark Controls Covered

| CIS Control | Description                                           | Severity |
|-------------|-------------------------------------------------------|----------|
| 5.1         | No security groups allow ingress 0.0.0.0/0 to port 22  | HIGH     |
| 5.2         | No security groups allow ingress 0.0.0.0/0 to port 3389| HIGH     |
| 5.3         | No security groups allow unrestricted ingress (0.0.0.0/0 all ports) | CRITICAL |
| 5.4         | Default security group restricts all traffic          | HIGH     |
| Custom      | No overly permissive CIDR ranges (/0 through /8)     | MEDIUM   |
| Custom      | All security groups have descriptions                 | LOW      |
| Custom      | No unused security groups                             | LOW      |
| Custom      | Egress is restricted (not open to 0.0.0.0/0 all)     | MEDIUM   |
| Custom      | SSH restricted to known CIDR blocks                   | HIGH     |
| Custom      | No sensitive ports open to public                     | HIGH     |

---

## Terraform Module Usage

```hcl
module "web_sg" {
  source = "../../modules/security-group"

  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = var.vpc_id
  environment = var.environment
  project     = var.project

  ingress_rules = [
    {
      description = "HTTPS from anywhere"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "SSH from corporate VPN"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }
  ]
}
```

---

## License

MIT
