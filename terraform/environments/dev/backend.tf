###############################################################################
# Dev Environment — backend.tf
# Uncomment and configure for remote state storage.
###############################################################################

# terraform {
#   backend "s3" {
#     bucket         = "my-terraform-state-bucket"
#     key            = "dev/security-groups/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-lock"
#   }
# }
