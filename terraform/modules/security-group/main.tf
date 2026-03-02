###############################################################################
# Security Group Module — main.tf
# Creates an AWS Security Group with configurable ingress/egress rules.
# Follows CIS AWS Foundations Benchmark best practices.
###############################################################################

resource "aws_security_group" "this" {
  name        = "${var.project}-${var.environment}-${var.name}"
  description = var.description
  vpc_id      = var.vpc_id

  tags = merge(
    var.tags,
    {
      Name        = "${var.project}-${var.environment}-${var.name}"
      Environment = var.environment
      Project     = var.project
      ManagedBy   = "terraform"
      CISCompliant = "true"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

###############################################################################
# Ingress Rules
###############################################################################

resource "aws_security_group_rule" "ingress" {
  count = length(var.ingress_rules)

  type              = "ingress"
  security_group_id = aws_security_group.this.id

  description = var.ingress_rules[count.index].description
  from_port   = var.ingress_rules[count.index].from_port
  to_port     = var.ingress_rules[count.index].to_port
  protocol    = var.ingress_rules[count.index].protocol

  # Use cidr_blocks OR source_security_group_id, not both
  cidr_blocks = lookup(var.ingress_rules[count.index], "cidr_blocks", null)

  source_security_group_id = lookup(
    var.ingress_rules[count.index], "source_security_group_id", null
  )
}

###############################################################################
# Egress Rules
###############################################################################

resource "aws_security_group_rule" "egress" {
  count = length(var.egress_rules)

  type              = "egress"
  security_group_id = aws_security_group.this.id

  description = var.egress_rules[count.index].description
  from_port   = var.egress_rules[count.index].from_port
  to_port     = var.egress_rules[count.index].to_port
  protocol    = var.egress_rules[count.index].protocol

  cidr_blocks = lookup(var.egress_rules[count.index], "cidr_blocks", null)

  source_security_group_id = lookup(
    var.egress_rules[count.index], "source_security_group_id", null
  )
}
