###############################################################################
# Dev Environment — main.tf
# Deploys security groups for a typical web application stack.
###############################################################################

# ---------- Web Server Security Group ----------
module "web_sg" {
  source = "../../modules/security-group"

  name        = "web-server"
  description = "Security group for web server EC2 instances - allows HTTPS/HTTP inbound"
  vpc_id      = var.vpc_id
  environment = var.environment
  project     = var.project

  ingress_rules = [
    {
      description = "HTTPS from internet"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTP from internet (redirect to HTTPS)"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "SSH from corporate VPN only"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_ssh_cidrs
    }
  ]

  egress_rules = [
    {
      description = "HTTPS outbound"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "HTTP outbound"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "DNS outbound"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]

  tags = var.tags
}

# ---------- Application Server Security Group ----------
module "app_sg" {
  source = "../../modules/security-group"

  name        = "app-server"
  description = "Security group for application server EC2 instances - internal traffic only"
  vpc_id      = var.vpc_id
  environment = var.environment
  project     = var.project

  ingress_rules = [
    {
      description              = "Traffic from web tier"
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      source_security_group_id = module.web_sg.security_group_id
    },
    {
      description = "SSH from bastion only"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.allowed_ssh_cidrs
    }
  ]

  egress_rules = [
    {
      description = "HTTPS outbound for API calls"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    },
    {
      description = "Database access"
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = var.database_cidrs
    }
  ]

  tags = var.tags
}

# ---------- Database Security Group ----------
module "db_sg" {
  source = "../../modules/security-group"

  name        = "database"
  description = "Security group for RDS/database instances - app tier access only"
  vpc_id      = var.vpc_id
  environment = var.environment
  project     = var.project

  ingress_rules = [
    {
      description              = "PostgreSQL from app tier"
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      source_security_group_id = module.app_sg.security_group_id
    }
  ]

  egress_rules = [
    {
      description = "DNS outbound"
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]

  tags = var.tags
}
