###############################################################################
# Dev Environment — variables.tf
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID for security groups"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH (corporate VPN, bastion, etc.)"
  type        = list(string)

  validation {
    condition = alltrue([
      for cidr in var.allowed_ssh_cidrs :
      !contains(["0.0.0.0/0", "::/0"], cidr)
    ])
    error_message = "CIS 5.1: SSH must NOT be open to 0.0.0.0/0 or ::/0."
  }
}

variable "database_cidrs" {
  description = "CIDR blocks for database subnet access"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
