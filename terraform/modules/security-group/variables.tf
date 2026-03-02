###############################################################################
# Security Group Module — variables.tf
###############################################################################

variable "name" {
  description = "Name suffix for the security group"
  type        = string

  validation {
    condition     = length(var.name) > 0 && length(var.name) <= 64
    error_message = "Security group name must be between 1 and 64 characters."
  }
}

variable "description" {
  description = "Description of the security group (CIS requires non-empty)"
  type        = string

  validation {
    condition     = length(var.description) > 0
    error_message = "CIS Benchmark requires all security groups to have a description."
  }
}

variable "vpc_id" {
  description = "VPC ID where the security group will be created"
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-z0-9]+$", var.vpc_id))
    error_message = "VPC ID must be a valid vpc-xxxx format."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project" {
  description = "Project name for tagging"
  type        = string
}

variable "ingress_rules" {
  description = "List of ingress rule objects"
  type = list(object({
    description              = string
    from_port                = number
    to_port                  = number
    protocol                 = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.description != "" && rule.description != null
    ])
    error_message = "Every ingress rule must have a non-empty description (CIS requirement)."
  }
}

variable "egress_rules" {
  description = "List of egress rule objects"
  type = list(object({
    description              = string
    from_port                = number
    to_port                  = number
    protocol                 = string
    cidr_blocks              = optional(list(string))
    source_security_group_id = optional(string)
  }))
  default = [
    {
      description              = "Allow HTTPS outbound"
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    },
    {
      description              = "Allow HTTP outbound"
      from_port                = 80
      to_port                  = 80
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    },
    {
      description              = "Allow DNS outbound"
      from_port                = 53
      to_port                  = 53
      protocol                 = "udp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    }
  ]
}

variable "tags" {
  description = "Additional tags to apply"
  type        = map(string)
  default     = {}
}
