output "site_id" {
  description = "ESA site identifier."
  value       = alicloud_esa_site.edge.id
}

output "routine_name" {
  description = "ESA Routine name."
  value       = alicloud_esa_routine.edge.name
}

output "edge_hostname" {
  description = "Public hostname whose DNS ownership and certificate must be verified."
  value       = var.edge_hostname
}

output "edge_kv_namespace" {
  description = "Namespace containing signed, non-secret runtime configuration."
  value       = alicloud_esa_kv_namespace.edge.id
}

output "public_route_enabled" {
  description = "Whether Terraform requested activation after external gates passed."
  value       = var.activate_public_route
}

output "release_identity" {
  description = "Content-addressed release identity safe to archive in deployment evidence."
  value = {
    worker_sha256  = local.worker_digest
    policy_sha256  = local.policy_digest
    keyring_sha256 = local.keyring_digest
    evidence_id    = var.release_evidence_id
  }
}
