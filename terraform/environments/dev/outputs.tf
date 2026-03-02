###############################################################################
# Dev Environment — outputs.tf
###############################################################################

output "web_sg_id" {
  description = "Web server security group ID"
  value       = module.web_sg.security_group_id
}

output "app_sg_id" {
  description = "App server security group ID"
  value       = module.app_sg.security_group_id
}

output "db_sg_id" {
  description = "Database security group ID"
  value       = module.db_sg.security_group_id
}

output "all_security_group_ids" {
  description = "All security group IDs for validation"
  value = [
    module.web_sg.security_group_id,
    module.app_sg.security_group_id,
    module.db_sg.security_group_id,
  ]
}
