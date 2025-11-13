variable "prefix" {
  description = "Prefix for all resources (e.g., 'iam-poc')"
  type        = string
  default     = "iam-poc"

  validation {
    condition     = length(var.prefix) <= 20 && can(regex("^[a-z0-9-]+$", var.prefix))
    error_message = "Prefix must be <= 20 characters and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "location" {
  description = "Azure region for resources (e.g., 'switzerlandnorth')"
  type        = string
  default     = "switzerlandnorth"
}

variable "rg_name" {
  description = "Resource Group name (if empty, will be auto-generated from prefix)"
  type        = string
  default     = ""
}

variable "tenant_id" {
  description = "Azure AD Tenant ID for Key Vault access policies"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for Private Endpoints (to be created in phase C3)"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project   = "IAM-POC"
    ManagedBy = "Terraform"
  }
}
