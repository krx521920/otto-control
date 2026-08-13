variable "region" {
  description = "Alibaba Cloud control-plane region."
  type        = string
  default     = "cn-hangzhou"
}

variable "esa_plan_instance_id" {
  description = "Existing ESA plan instance. Purchasing a plan is deliberately outside this module."
  type        = string
  sensitive   = false
  validation {
    condition     = can(regex("^[A-Za-z0-9._:-]{6,128}$", var.esa_plan_instance_id))
    error_message = "esa_plan_instance_id must identify an existing ESA plan."
  }
}

variable "site_name" {
  description = "Verified registrable domain owned by the deployment operator."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.site_name))
    error_message = "site_name must be a lower-case DNS domain."
  }
}

variable "edge_hostname" {
  description = "Dedicated public hostname for Otto Edge Gateway."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.edge_hostname))
    error_message = "edge_hostname must be a lower-case FQDN."
  }
}

variable "coverage" {
  description = "ESA coverage; it must match the purchased plan."
  type        = string
  default     = "domestic"
  validation {
    condition     = contains(["domestic", "global", "overseas"], var.coverage)
    error_message = "coverage must be domestic, global or overseas."
  }
}

variable "routine_name" {
  description = "Globally unique ESA Routine name for this deployment."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,62}$", var.routine_name))
    error_message = "routine_name must be 3-63 lower-case letters, digits or hyphens and start with a letter."
  }
}

variable "worker_bundle_path" {
  description = "Path to the reviewed, immutable ESA worker JavaScript bundle."
  type        = string
}

variable "worker_bundle_sha256" {
  description = "Expected lower-case SHA-256 of worker_bundle_path."
  type        = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.worker_bundle_sha256))
    error_message = "worker_bundle_sha256 must be a lower-case SHA-256 digest."
  }
}

variable "signed_policy_path" {
  description = "Path to a Control-signed policy envelope. Policy values are not secrets."
  type        = string
}

variable "signed_policy_sha256" {
  description = "Expected SHA-256 of signed_policy_path."
  type        = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.signed_policy_sha256))
    error_message = "signed_policy_sha256 must be a lower-case SHA-256 digest."
  }
}

variable "control_keyring_path" {
  description = "Path to the public Control signing keyring JSON. Private keys are forbidden."
  type        = string
}

variable "control_keyring_sha256" {
  description = "Expected SHA-256 of control_keyring_path."
  type        = string
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.control_keyring_sha256))
    error_message = "control_keyring_sha256 must be a lower-case SHA-256 digest."
  }
}

variable "policy_key" {
  description = "EdgeKV key used by the worker to read the signed policy."
  type        = string
  default     = "otto_edge_policy_v1"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.policy_key))
    error_message = "policy_key may contain only letters, digits, underscore and hyphen."
  }
}

variable "keyring_key" {
  description = "EdgeKV key used by the worker to read public Control keys."
  type        = string
  default     = "otto_control_keyring_v1"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,128}$", var.keyring_key))
    error_message = "keyring_key may contain only letters, digits, underscore and hyphen."
  }
}

variable "release_evidence_id" {
  description = "Immutable external release evidence ID proving Secret binding, code deployment and health gates."
  type        = string
  default     = ""
}

variable "activate_public_route" {
  description = "Fail-closed switch. Keep false until external Secret and canary evidence is archived."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Non-sensitive resource tags."
  type        = map(string)
  default = {
    managed_by = "terraform"
    service    = "otto-edge-gateway"
  }
}
