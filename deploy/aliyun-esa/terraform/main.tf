locals {
  worker_digest  = filesha256(var.worker_bundle_path)
  policy_digest  = filesha256(var.signed_policy_path)
  keyring_digest = filesha256(var.control_keyring_path)
}

resource "alicloud_esa_site" "edge" {
  site_name                           = var.site_name
  instance_id                        = var.esa_plan_instance_id
  coverage                           = var.coverage
  access_type                        = "CNAME"
  paused                             = false
  development_mode                   = "off"
  site_name_exclusive                = "on"
  version_management                 = true
  add_real_client_ip_header          = "off"
  add_client_geolocation_header      = "off"
  automatic_frequency_control_enable = "on"
  automatic_frequency_control_level  = "normal"
  automatic_frequency_control_action_type = "deny"
  tags = var.tags

  site_waf_settings {
    add_security_headers { enable = "on" }
    security_level { value = "medium" }
    client_ip_identifier { mode = "connection_ip" }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = (
        local.worker_digest == var.worker_bundle_sha256 &&
        local.policy_digest == var.signed_policy_sha256 &&
        local.keyring_digest == var.control_keyring_sha256
      )
      error_message = "Worker, signed policy or public keyring digest differs from the reviewed release manifest."
    }
  }
}

resource "alicloud_esa_kv_namespace" "edge" {
  kv_namespace = "${replace(var.routine_name, "-", "_")}_config"
  description  = "Otto Edge signed policy and public Control keyring; never store provider secrets"
  lifecycle { prevent_destroy = true }
}

resource "alicloud_esa_kv" "signed_policy" {
  namespace = alicloud_esa_kv_namespace.edge.id
  key       = var.policy_key
  value     = file(var.signed_policy_path)
  isbase    = "false"
}

resource "alicloud_esa_kv" "control_keyring" {
  namespace = alicloud_esa_kv_namespace.edge.id
  key       = var.keyring_key
  value     = file(var.control_keyring_path)
  isbase    = "false"
}

resource "alicloud_esa_routine" "edge" {
  name        = var.routine_name
  description = "Otto Edge Gateway; reviewed worker sha256:${var.worker_bundle_sha256}"

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.worker_digest == var.worker_bundle_sha256
      error_message = "Refusing to upload an unreviewed worker bundle."
    }
  }
}

resource "alicloud_esa_certificate" "edge" {
  site_id      = alicloud_esa_site.edge.id
  domains      = var.edge_hostname
  created_type = "free"
  type         = "lets_encrypt"
  lifecycle { prevent_destroy = true }
}

resource "alicloud_esa_https_basic_configuration" "edge" {
  site_id           = alicloud_esa_site.edge.id
  https             = "on"
  tls10             = "off"
  tls11             = "off"
  tls12             = "on"
  tls13             = "on"
  ciphersuite_group = "strict"
  http2             = "on"
  http3             = "on"
  ocsp_stapling      = "on"
  rule              = "(http.host eq \"${var.edge_hostname}\")"
  rule_name         = "otto-edge-strict-tls"
  rule_enable       = "on"
}

resource "alicloud_esa_routine_route" "edge" {
  site_id      = alicloud_esa_site.edge.id
  routine_name = alicloud_esa_routine.edge.name
  route_name   = "otto-edge-production"
  rule         = "(http.host eq \"${var.edge_hostname}\")"
  sequence     = 1
  bypass       = "off"
  route_enable = var.activate_public_route ? "on" : "off"

  depends_on = [
    alicloud_esa_certificate.edge,
    alicloud_esa_https_basic_configuration.edge,
    alicloud_esa_kv.signed_policy,
    alicloud_esa_kv.control_keyring,
  ]

  lifecycle {
    precondition {
      condition     = !var.activate_public_route || can(regex("^esa-release-[a-f0-9]{32,64}$", var.release_evidence_id))
      error_message = "Public routing requires an immutable esa-release evidence ID from the external Secret/canary gate."
    }
  }
}
