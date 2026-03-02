###############################################################################
# Prod Environment — terraform.tfvars
# Production values: stricter CIDRs, tighter controls.
###############################################################################

aws_region  = "us-east-1"
vpc_id      = "vpc-xxxxxxxxxxxxxxxxx"   # <-- Replace with your prod VPC ID
environment = "prod"
project     = "myapp"

# CIS-compliant: SSH restricted to bastion host only
allowed_ssh_cidrs = ["10.0.1.50/32"]

# Database subnet CIDRs (prod private subnets)
database_cidrs = ["10.1.100.0/24", "10.1.101.0/24"]

tags = {
  Team        = "platform"
  CostCenter  = "engineering"
  Compliance  = "cis-benchmark"
}
