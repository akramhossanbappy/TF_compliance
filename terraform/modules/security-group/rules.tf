###############################################################################
# Security Group Module — rules.tf
# Pre-defined rule sets for common use-cases, all CIS-compliant.
###############################################################################

locals {
  # Common CIS-compliant rule templates
  # Use these in your environment configs for safe defaults.

  web_server_ingress = [
    {
      description              = "Allow HTTPS from internet"
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    },
    {
      description              = "Allow HTTP from internet (redirect to HTTPS)"
      from_port                = 80
      to_port                  = 80
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    }
  ]

  restricted_egress = [
    {
      description              = "Allow HTTPS outbound"
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    },
    {
      description              = "Allow DNS outbound (UDP)"
      from_port                = 53
      to_port                  = 53
      protocol                 = "udp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    },
    {
      description              = "Allow DNS outbound (TCP)"
      from_port                = 53
      to_port                  = 53
      protocol                 = "tcp"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
    }
  ]

  # Sensitive ports that should NEVER be open to 0.0.0.0/0
  sensitive_ports = [22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 5601]
}
