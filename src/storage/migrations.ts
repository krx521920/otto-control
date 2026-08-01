import type { PoolClient } from 'pg';

interface Migration {
  id: string;
  statements: string[];
}

const MIGRATIONS: Migration[] = [
  {
    id: '001_commercial_control',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_customers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_deployments (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        organization_id TEXT NOT NULL,
        machine_fingerprint TEXT NOT NULL,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (organization_id, machine_fingerprint)
      )`,
      `CREATE TABLE IF NOT EXISTS control_licenses (
        id TEXT PRIMARY KEY,
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        customer_name TEXT NOT NULL,
        organization_id TEXT NOT NULL,
        machine_fingerprint TEXT NOT NULL,
        plan TEXT NOT NULL,
        issued_at_ms BIGINT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        seat_limit INTEGER NOT NULL CHECK (seat_limit > 0),
        modules JSONB NOT NULL,
        offline BOOLEAN NOT NULL,
        telemetry_allowed BOOLEAN NOT NULL,
        lease_endpoint TEXT,
        token_version INTEGER NOT NULL DEFAULT 1,
        signature TEXT NOT NULL,
        signing_key_id TEXT NOT NULL,
        revoked_at_ms BIGINT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK (expires_at_ms > issued_at_ms),
        CHECK ((offline AND lease_endpoint IS NULL) OR (NOT offline AND lease_endpoint IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_licenses_deployment
       ON control_licenses(deployment_id, created_at DESC)`,
      `CREATE TABLE IF NOT EXISTS control_lease_nonces (
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        nonce TEXT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (deployment_id, nonce)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_lease_nonces_expiry
       ON control_lease_nonces(expires_at_ms)`,
      `CREATE TABLE IF NOT EXISTS control_audit_events (
        id BIGSERIAL PRIMARY KEY,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        detail JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_target
       ON control_audit_events(target_type, target_id, created_at DESC)`,
    ],
  },
  {
    id: '002_telemetry_health',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_telemetry_nonces (
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        nonce TEXT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (deployment_id, nonce)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_telemetry_nonces_expiry
       ON control_telemetry_nonces(expires_at_ms)`,
      `CREATE TABLE IF NOT EXISTS control_telemetry_events (
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        event_id TEXT NOT NULL,
        license_id TEXT NOT NULL REFERENCES control_licenses(id),
        organization_id TEXT,
        event_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        integrity TEXT NOT NULL,
        source_created_at_ms BIGINT NOT NULL,
        received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (deployment_id, event_id)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_telemetry_received
       ON control_telemetry_events(deployment_id, received_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_telemetry_retention
       ON control_telemetry_events(received_at)`,
      `CREATE INDEX IF NOT EXISTS idx_control_telemetry_type
       ON control_telemetry_events(deployment_id, event_type, source_created_at_ms DESC)`,
    ],
  },
  {
    id: '003_update_policy',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_update_distributions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_update_releases (
        id TEXT PRIMARY KEY,
        distribution_id TEXT NOT NULL REFERENCES control_update_distributions(id),
        version TEXT NOT NULL,
        source_commit TEXT NOT NULL,
        channel TEXT NOT NULL CHECK (channel IN ('canary', 'stable', 'required')),
        rollout_percent INTEGER NOT NULL CHECK (rollout_percent BETWEEN 1 AND 100),
        state TEXT NOT NULL DEFAULT 'draft'
          CHECK (state IN ('draft', 'active', 'paused', 'rolled_back')),
        notes TEXT NOT NULL DEFAULT '',
        full_manifest_url TEXT,
        full_manifest_sha256 TEXT,
        incremental_manifest_url TEXT,
        incremental_manifest_sha256 TEXT,
        previous_release_id TEXT REFERENCES control_update_releases(id),
        published_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (distribution_id, version, channel),
        CHECK (full_manifest_url IS NOT NULL OR incremental_manifest_url IS NOT NULL),
        CHECK ((full_manifest_url IS NULL) = (full_manifest_sha256 IS NULL)),
        CHECK ((incremental_manifest_url IS NULL) = (incremental_manifest_sha256 IS NULL)),
        CHECK (channel = 'canary' OR rollout_percent = 100),
        CHECK (state <> 'active' OR published_at IS NOT NULL)
      )`,
      `CREATE TABLE IF NOT EXISTS control_deployment_update_assignments (
        deployment_id TEXT PRIMARY KEY REFERENCES control_deployments(id),
        distribution_id TEXT NOT NULL REFERENCES control_update_distributions(id),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_deployment_update_distribution
       ON control_deployment_update_assignments(distribution_id)`,
      `CREATE INDEX IF NOT EXISTS idx_control_update_release_lookup
       ON control_update_releases(distribution_id, state, channel, published_at DESC)`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_update_release_active_channel
       ON control_update_releases(distribution_id, channel) WHERE state = 'active'`,
      `CREATE TABLE IF NOT EXISTS control_update_policy_nonces (
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        nonce TEXT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (deployment_id, nonce)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_update_policy_nonces_expiry
       ON control_update_policy_nonces(expires_at_ms)`,
    ],
  },
  {
    id: '004_multi_distribution_assignments',
    statements: [
      `ALTER TABLE control_deployment_update_assignments
       DROP CONSTRAINT IF EXISTS control_deployment_update_assignments_pkey`,
      `ALTER TABLE control_deployment_update_assignments
       ADD PRIMARY KEY (deployment_id, distribution_id)`,
    ],
  },
  {
    id: '005_signing_keyring',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_signing_keys (
        key_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL DEFAULT 'ed25519' CHECK (algorithm = 'ed25519'),
        public_key_pem TEXT NOT NULL,
        provider TEXT NOT NULL CHECK (provider IN ('local', 'kms', 'hsm')),
        state TEXT NOT NULL DEFAULT 'standby'
          CHECK (state IN ('standby', 'active', 'retired', 'revoked')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        activated_at TIMESTAMPTZ,
        retired_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        revocation_reason TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
        CHECK ((state = 'revoked') = (revocation_reason IS NOT NULL))
      )`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_signing_keys_one_active
       ON control_signing_keys ((state)) WHERE state = 'active'`,
      `CREATE INDEX IF NOT EXISTS idx_control_signing_keys_state
       ON control_signing_keys(state, updated_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_licenses_signing_key
       ON control_licenses(signing_key_id, created_at DESC)`,
    ],
  },
  {
    id: '006_admin_identity',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_admin_permissions (
        id TEXT PRIMARY KEY
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_roles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        system BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_role_permissions (
        role_id TEXT NOT NULL REFERENCES control_admin_roles(id) ON DELETE CASCADE,
        permission_id TEXT NOT NULL REFERENCES control_admin_permissions(id) ON DELETE CASCADE,
        PRIMARY KEY (role_id, permission_id)
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_accounts (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret_ciphertext TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'active', 'disabled')),
        failed_login_count INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
        locked_until TIMESTAMPTZ,
        mfa_confirmed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_account_roles (
        account_id TEXT NOT NULL REFERENCES control_admin_accounts(id) ON DELETE CASCADE,
        role_id TEXT NOT NULL REFERENCES control_admin_roles(id),
        PRIMARY KEY (account_id, role_id)
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_enrollments (
        account_id TEXT PRIMARY KEY REFERENCES control_admin_accounts(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_recovery_codes (
        account_id TEXT NOT NULL REFERENCES control_admin_accounts(id) ON DELETE CASCADE,
        code_hash TEXT NOT NULL,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (account_id, code_hash)
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_sessions (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES control_admin_accounts(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        mfa_verified_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_admin_sessions_account
       ON control_admin_sessions(account_id, expires_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_admin_sessions_expiry
       ON control_admin_sessions(expires_at) WHERE revoked_at IS NULL`,
      `CREATE TABLE IF NOT EXISTS control_admin_approvals (
        id TEXT PRIMARY KEY,
        requester_account_id TEXT NOT NULL REFERENCES control_admin_accounts(id),
        operation TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'expired')),
        required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals BETWEEN 1 AND 10),
        expires_at TIMESTAMPTZ NOT NULL,
        executed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS control_admin_approval_decisions (
        approval_id TEXT NOT NULL REFERENCES control_admin_approvals(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL REFERENCES control_admin_accounts(id),
        decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
        reason TEXT,
        decided_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (approval_id, account_id)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_admin_approvals_status
       ON control_admin_approvals(status, expires_at, created_at DESC)`,
      `INSERT INTO control_admin_permissions (id) VALUES
        ('customer.create'), ('deployment.create'), ('license.issue'), ('license.read'),
        ('license.revoke'), ('signing_key.read'), ('signing_key.manage'), ('telemetry.read'),
        ('update_distribution.manage'), ('update_release.create'), ('update_release.read'),
        ('update_release.publish'), ('identity.read'), ('identity.manage'),
        ('approval.request'), ('approval.read'), ('approval.decide')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_roles (id, name) VALUES
        ('super_admin', 'Super administrator'),
        ('security_admin', 'Security administrator'),
        ('license_admin', 'License administrator'),
        ('release_admin', 'Release administrator'),
        ('auditor', 'Read-only auditor')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'super_admin', id FROM control_admin_permissions
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'security_admin', id FROM control_admin_permissions
       WHERE id IN ('signing_key.read', 'signing_key.manage', 'identity.read', 'identity.manage',
                    'approval.request', 'approval.read', 'approval.decide')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'license_admin', id FROM control_admin_permissions
       WHERE id IN ('customer.create', 'deployment.create', 'license.issue', 'license.read',
                    'license.revoke', 'telemetry.read', 'approval.request', 'approval.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'release_admin', id FROM control_admin_permissions
       WHERE id IN ('update_distribution.manage', 'update_release.create', 'update_release.read',
                    'update_release.publish', 'approval.request', 'approval.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'auditor', id FROM control_admin_permissions
       WHERE id IN ('license.read', 'signing_key.read', 'telemetry.read',
                    'update_release.read', 'identity.read', 'approval.read')
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '007_license_lifecycle',
    statements: [
      `ALTER TABLE control_licenses
       ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1
         CHECK (revision > 0)`,
      `ALTER TABLE control_licenses
       ADD COLUMN IF NOT EXISTS grace_period_ms BIGINT NOT NULL DEFAULT 604800000
         CHECK (grace_period_ms >= 0 AND grace_period_ms <= 2592000000)`,
      `ALTER TABLE control_licenses
       ADD COLUMN IF NOT EXISTS seat_enforcement TEXT NOT NULL DEFAULT 'monitor'
         CHECK (seat_enforcement IN ('monitor', 'enforce'))`,
      `CREATE TABLE IF NOT EXISTS control_license_lifecycle_events (
        id BIGSERIAL PRIMARY KEY,
        license_id TEXT NOT NULL REFERENCES control_licenses(id) ON DELETE CASCADE,
        revision INTEGER NOT NULL CHECK (revision > 1),
        change_type TEXT NOT NULL
          CHECK (change_type IN ('renewed', 'expanded', 'downgraded',
                                 'terms_changed', 'machine_transferred',
                                 'deployment_rebound')),
        actor_id TEXT NOT NULL,
        detail JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (license_id, revision)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_license_lifecycle_events_license
       ON control_license_lifecycle_events(license_id, created_at DESC)`,
      `CREATE TABLE IF NOT EXISTS control_license_seat_usage (
        license_id TEXT PRIMARY KEY REFERENCES control_licenses(id) ON DELETE CASCADE,
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        active_seats INTEGER NOT NULL CHECK (active_seats >= 0),
        seat_limit INTEGER NOT NULL CHECK (seat_limit > 0),
        status TEXT NOT NULL
          CHECK (status IN ('unreported', 'within_limit', 'over_limit_monitor',
                            'overage_grace', 'blocked')),
        overage_started_at_ms BIGINT,
        grace_expires_at_ms BIGINT,
        last_reported_at_ms BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `INSERT INTO control_admin_permissions (id) VALUES
        ('license.manage'), ('license.transfer'), ('license.usage.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'super_admin', id FROM control_admin_permissions
       WHERE id IN ('license.manage', 'license.transfer', 'license.usage.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'license_admin', id FROM control_admin_permissions
       WHERE id IN ('license.manage', 'license.transfer', 'license.usage.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'auditor', id FROM control_admin_permissions
       WHERE id = 'license.usage.read'
      ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '008_credit_billing',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_credit_accounts (
        customer_id TEXT PRIMARY KEY REFERENCES control_customers(id),
        available_balance BIGINT NOT NULL DEFAULT 0
          CHECK (available_balance BETWEEN 0 AND 9000000000000000),
        frozen_balance BIGINT NOT NULL DEFAULT 0
          CHECK (frozen_balance BETWEEN 0 AND 9000000000000000),
        total_topped_up BIGINT NOT NULL DEFAULT 0
          CHECK (total_topped_up BETWEEN 0 AND 9000000000000000),
        total_consumed BIGINT NOT NULL DEFAULT 0
          CHECK (total_consumed BETWEEN 0 AND 9000000000000000),
        total_refunded BIGINT NOT NULL DEFAULT 0
          CHECK (total_refunded BETWEEN 0 AND 9000000000000000),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE TABLE IF NOT EXISTS control_billing_rates (
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        module TEXT NOT NULL CHECK (module IN (
          'model_gateway', 'meeting_agent', 'park_service', 'atoa', 'feishu',
          'enterprise_knowledge', 'skill_market', 'data_visualization',
          'document_generation'
        )),
        unit_size BIGINT NOT NULL CHECK (unit_size > 0),
        credits_per_unit BIGINT NOT NULL CHECK (credits_per_unit > 0),
        updated_by TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (customer_id, module)
      )`,
      `CREATE TABLE IF NOT EXISTS control_credit_holds (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        organization_id TEXT NOT NULL,
        deployment_id TEXT NOT NULL,
        module TEXT NOT NULL CHECK (module IN (
          'model_gateway', 'meeting_agent', 'park_service', 'atoa', 'feishu',
          'enterprise_knowledge', 'skill_market', 'data_visualization',
          'document_generation'
        )),
        amount BIGINT NOT NULL CHECK (amount > 0),
        status TEXT NOT NULL CHECK (status IN ('active', 'captured', 'released', 'expired')),
        idempotency_key TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE (customer_id, idempotency_key)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_credit_holds_expiry
       ON control_credit_holds(status, expires_at) WHERE status = 'active'`,
      `CREATE TABLE IF NOT EXISTS control_credit_transactions (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        organization_id TEXT,
        deployment_id TEXT,
        module TEXT CHECK (module IS NULL OR module IN (
          'model_gateway', 'meeting_agent', 'park_service', 'atoa', 'feishu',
          'enterprise_knowledge', 'skill_market', 'data_visualization',
          'document_generation'
        )),
        type TEXT NOT NULL CHECK (type IN (
          'topup', 'freeze', 'capture', 'release', 'consume', 'refund'
        )),
        available_delta BIGINT NOT NULL,
        frozen_delta BIGINT NOT NULL,
        billed_amount BIGINT NOT NULL DEFAULT 0 CHECK (billed_amount >= 0),
        available_after BIGINT NOT NULL CHECK (available_after >= 0),
        frozen_after BIGINT NOT NULL CHECK (frozen_after >= 0),
        idempotency_key TEXT NOT NULL,
        reference_id TEXT,
        related_transaction_id TEXT REFERENCES control_credit_transactions(id),
        description TEXT NOT NULL DEFAULT '',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        occurred_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (customer_id, idempotency_key)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_credit_transactions_customer_time
       ON control_credit_transactions(customer_id, occurred_at DESC, id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_credit_transactions_statement
       ON control_credit_transactions(customer_id, organization_id, module, occurred_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_credit_transactions_related
       ON control_credit_transactions(related_transaction_id)
       WHERE related_transaction_id IS NOT NULL`,
      `INSERT INTO control_admin_permissions (id) VALUES
        ('billing.read'), ('billing.topup'), ('billing.manage'), ('billing.refund')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'super_admin', id FROM control_admin_permissions
       WHERE id IN ('billing.read', 'billing.topup', 'billing.manage', 'billing.refund')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'license_admin', id FROM control_admin_permissions
       WHERE id IN ('billing.read', 'billing.topup', 'billing.manage', 'billing.refund')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'auditor', id FROM control_admin_permissions
       WHERE id = 'billing.read'
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '009_release_artifacts',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_release_artifacts (
        id TEXT PRIMARY KEY,
        release_id TEXT NOT NULL REFERENCES control_update_releases(id) ON DELETE CASCADE,
        distribution_id TEXT NOT NULL REFERENCES control_update_distributions(id),
        release_version TEXT NOT NULL,
        source_commit TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN (
          'windows_installer', 'macos_dmg', 'linux_archive', 'enterprise_server',
          'update_manifest', 'incremental_manifest', 'skills_component',
          'renderer_patch', 'server_runtime'
        )),
        platform TEXT NOT NULL CHECK (platform IN (
          'windows-x64', 'windows-arm64', 'macos-x64', 'macos-arm64',
          'macos-universal', 'linux-x64', 'linux-arm64', 'any'
        )),
        url TEXT NOT NULL,
        sha256 TEXT NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
        size_bytes BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 9007199254740991),
        signing_key_id TEXT NOT NULL REFERENCES control_signing_keys(key_id),
        signature TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
        revoked_at TIMESTAMPTZ,
        revoked_by TEXT,
        revocation_reason TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE (release_id, kind, platform),
        CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
        CHECK ((state = 'revoked') = (revoked_by IS NOT NULL)),
        CHECK ((state = 'revoked') = (revocation_reason IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_release_artifacts_release
       ON control_release_artifacts(release_id, state, kind, platform)`,
      `CREATE INDEX IF NOT EXISTS idx_control_release_artifacts_signing_key
       ON control_release_artifacts(signing_key_id, state)`,
    ],
  },
  {
    id: '010_backup_status_permission',
    statements: [
      `INSERT INTO control_admin_permissions (id) VALUES ('backup.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, 'backup.read'
       FROM (VALUES ('super_admin'), ('security_admin'), ('auditor')) AS roles(role_id)
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '011_alert_delivery',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_alert_deliveries (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL CHECK (source IN ('backup_status')),
        event_type TEXT NOT NULL CHECK (event_type IN ('backup.recovery.alert')),
        fingerprint TEXT NOT NULL UNIQUE CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
        severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
        payload JSONB NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'delivering', 'retrying', 'delivered', 'failed')),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
        next_attempt_at TIMESTAMPTZ NOT NULL,
        lease_until TIMESTAMPTZ,
        last_error TEXT,
        delivered_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK ((status = 'delivering') = (lease_until IS NOT NULL)),
        CHECK ((status = 'delivered') = (delivered_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_alert_deliveries_due
       ON control_alert_deliveries(next_attempt_at, created_at)
       WHERE status IN ('pending', 'retrying', 'delivering')`,
      `CREATE INDEX IF NOT EXISTS idx_control_alert_deliveries_history
       ON control_alert_deliveries(created_at DESC, id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_alert_deliveries_retention
       ON control_alert_deliveries(updated_at)
       WHERE status IN ('delivered', 'failed')`,
      `INSERT INTO control_admin_permissions (id) VALUES ('alert.read'), ('alert.manage')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, permission_id
       FROM (VALUES
         ('super_admin', 'alert.read'), ('super_admin', 'alert.manage'),
         ('security_admin', 'alert.read'), ('security_admin', 'alert.manage'),
         ('auditor', 'alert.read')
       ) AS assignments(role_id, permission_id)
      ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '012_operator_console_permission',
    statements: [
      `INSERT INTO control_admin_permissions (id) VALUES ('commercial.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, 'commercial.read'
       FROM (VALUES ('super_admin'), ('license_admin'), ('auditor')) AS roles(role_id)
      ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '013_license_export_permission',
    statements: [
      `INSERT INTO control_admin_permissions (id) VALUES ('license.export')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, 'license.export'
       FROM (VALUES ('super_admin'), ('license_admin')) AS roles(role_id)
      ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '014_approval_request_snapshot',
    statements: [
      `ALTER TABLE control_admin_approvals
       ADD COLUMN IF NOT EXISTS request_payload JSONB NOT NULL DEFAULT '{}'::jsonb`,
    ],
  },
  {
    id: '015_alert_delivery_channels',
    statements: [
      `ALTER TABLE control_alert_deliveries
       ADD COLUMN IF NOT EXISTS channel_id TEXT NOT NULL DEFAULT 'legacy-webhook'`,
      `ALTER TABLE control_alert_deliveries
       ADD CONSTRAINT control_alert_deliveries_channel_id_check
       CHECK (channel_id ~ '^[a-z][a-z0-9_-]{1,63}$') NOT VALID`,
      `ALTER TABLE control_alert_deliveries
       VALIDATE CONSTRAINT control_alert_deliveries_channel_id_check`,
      `ALTER TABLE control_alert_deliveries
       DROP CONSTRAINT IF EXISTS control_alert_deliveries_fingerprint_key`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_alert_deliveries_fingerprint_channel
       ON control_alert_deliveries(fingerprint, channel_id)`,
      `CREATE INDEX IF NOT EXISTS idx_control_alert_deliveries_channel_history
       ON control_alert_deliveries(channel_id, created_at DESC)`,
    ],
  },
  {
    id: '016_tamper_evident_audit',
    statements: [
      `ALTER TABLE control_audit_events
       ADD COLUMN IF NOT EXISTS chain_sequence BIGINT,
       ADD COLUMN IF NOT EXISTS previous_hash TEXT,
       ADD COLUMN IF NOT EXISTS event_hash TEXT`,
      `ALTER TABLE control_audit_events
       ADD CONSTRAINT control_audit_events_chain_fields_check CHECK (
         (chain_sequence IS NULL AND previous_hash IS NULL AND event_hash IS NULL)
         OR (chain_sequence > 0
           AND previous_hash ~ '^[a-f0-9]{64}$'
           AND event_hash ~ '^[a-f0-9]{64}$')
       ) NOT VALID`,
      `ALTER TABLE control_audit_events
       VALIDATE CONSTRAINT control_audit_events_chain_fields_check`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_audit_chain_sequence
       ON control_audit_events(chain_sequence) WHERE chain_sequence IS NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_actor_created
       ON control_audit_events(actor_id, created_at DESC, id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_action_created
       ON control_audit_events(action, created_at DESC, id DESC)`,
      `CREATE TABLE IF NOT EXISTS control_audit_chain_state (
        singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
        last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
        head_hash TEXT NOT NULL DEFAULT repeat('0', 64)
          CHECK (head_hash ~ '^[a-f0-9]{64}$'),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `INSERT INTO control_audit_chain_state (singleton) VALUES (TRUE)
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_permissions (id)
       VALUES ('audit.read'), ('audit.export'), ('audit.verify')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, permission_id
       FROM (VALUES
         ('super_admin', 'audit.read'), ('super_admin', 'audit.export'), ('super_admin', 'audit.verify'),
         ('security_admin', 'audit.read'), ('security_admin', 'audit.export'), ('security_admin', 'audit.verify'),
         ('auditor', 'audit.read'), ('auditor', 'audit.export'), ('auditor', 'audit.verify')
       ) AS assignments(role_id, permission_id)
       ON CONFLICT DO NOTHING`,
    ],
  },
];

export async function runMigrations(client: PoolClient): Promise<void> {
  await client.query(`CREATE TABLE IF NOT EXISTS control_schema_migrations (
    id TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);

  await client.query("SELECT pg_advisory_lock(hashtext('otto_control_migrations'))");
  try {
    for (const migration of MIGRATIONS) {
      const existing = await client.query<{ id: string }>(
        'SELECT id FROM control_schema_migrations WHERE id = $1',
        [migration.id],
      );
      if (existing.rowCount) continue;
      await client.query('BEGIN');
      try {
        for (const statement of migration.statements) await client.query(statement);
        await client.query(
          'INSERT INTO control_schema_migrations (id) VALUES ($1)',
          [migration.id],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query("SELECT pg_advisory_unlock(hashtext('otto_control_migrations'))");
  }
}
