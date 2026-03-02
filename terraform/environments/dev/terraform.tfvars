###############################################################################
# Dev Environment — terraform.tfvars
# Update these values for your AWS environment.
###############################################################################

aws_region  = "us-east-1"
vpc_id      = "vpc-03ac66a6763c81947"   # <-- Replace with your VPC ID
environment = "dev"
project     = "myapp"

# CIS-compliant: SSH restricted to corporate VPN/bastion only
allowed_ssh_cidrs = ["172.31.0.0/16"]

# Database subnet CIDRs
database_cidrs = ["172.31.100.0/24", "172.31.101.0/24"]


tags = {
  Team      = "platform"
  CostCenter = "engineering"
}
