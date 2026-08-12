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
  {
    id: '017_external_audit_anchors',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_audit_anchors (
        id TEXT PRIMARY KEY CHECK (id ~ '^anchor_[a-f0-9]{32}$'),
        fingerprint TEXT NOT NULL UNIQUE CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
        payload JSONB NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'delivering', 'retrying', 'delivered', 'failed')),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
        next_attempt_at TIMESTAMPTZ NOT NULL,
        lease_until TIMESTAMPTZ,
        last_error TEXT,
        delivered_at TIMESTAMPTZ,
        remote_reference TEXT CHECK (remote_reference IS NULL OR length(remote_reference) <= 200),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK ((status = 'delivering') = (lease_until IS NOT NULL)),
        CHECK ((status = 'delivered') = (delivered_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_anchors_due
       ON control_audit_anchors(next_attempt_at, created_at)
       WHERE status IN ('pending', 'retrying', 'delivering')`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_anchors_history
       ON control_audit_anchors(created_at DESC, id DESC)`,
      `INSERT INTO control_admin_permissions (id) VALUES ('audit.anchor.manage')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT role_id, 'audit.anchor.manage'
       FROM (VALUES ('super_admin'), ('security_admin')) AS roles(role_id)
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '018_audit_witness_receipts',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_audit_witness_receipts (
        id TEXT PRIMARY KEY CHECK (id ~ '^witness_[a-f0-9]{32}$'),
        source_id TEXT NOT NULL CHECK (source_id ~ '^[a-z][a-z0-9_-]{1,63}$'),
        anchor_id TEXT NOT NULL CHECK (anchor_id ~ '^anchor_[a-f0-9]{32}$'),
        fingerprint TEXT NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
        issuer TEXT NOT NULL,
        chain_sequence BIGINT NOT NULL CHECK (chain_sequence >= 0),
        head_hash TEXT NOT NULL CHECK (head_hash ~ '^[a-f0-9]{64}$'),
        signing_key_id TEXT NOT NULL,
        payload JSONB NOT NULL,
        received_at TIMESTAMPTZ NOT NULL,
        UNIQUE (source_id, anchor_id),
        UNIQUE (source_id, fingerprint)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_witness_source_sequence
       ON control_audit_witness_receipts(source_id, chain_sequence DESC, received_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_witness_received
       ON control_audit_witness_receipts(received_at DESC, id DESC)`,
    ],
  },
  {
    id: '019_license_billing_enforcement',
    statements: [
      `ALTER TABLE control_licenses
       ADD COLUMN IF NOT EXISTS billing_enforcement TEXT NOT NULL DEFAULT 'disabled'`,
      `ALTER TABLE control_licenses
       ADD CONSTRAINT control_licenses_billing_enforcement_check
       CHECK (billing_enforcement IN ('disabled', 'enforce')) NOT VALID`,
      `ALTER TABLE control_licenses
       VALIDATE CONSTRAINT control_licenses_billing_enforcement_check`,
      `ALTER TABLE control_licenses
       ADD CONSTRAINT control_licenses_offline_billing_check
       CHECK (NOT offline OR billing_enforcement = 'disabled') NOT VALID`,
      `ALTER TABLE control_licenses
       VALIDATE CONSTRAINT control_licenses_offline_billing_check`,
    ],
  },
  {
    id: '020_managed_release_artifacts',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_release_artifact_evidence (
        artifact_id TEXT PRIMARY KEY REFERENCES control_release_artifacts(id) ON DELETE CASCADE,
        object_key TEXT NOT NULL UNIQUE,
        object_version_id TEXT,
        verified_at TIMESTAMPTZ NOT NULL,
        server_side_encryption TEXT,
        object_lock_mode TEXT,
        object_lock_retain_until TIMESTAMPTZ,
        code_signing JSONB,
        created_at TIMESTAMPTZ NOT NULL,
        CHECK (length(object_key) BETWEEN 1 AND 1024)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_release_artifact_evidence_verified
       ON control_release_artifact_evidence(verified_at)`,
    ],
  },
  {
    id: '021_audit_witness_worm_evidence',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_audit_witness_evidence (
        receipt_id TEXT PRIMARY KEY REFERENCES control_audit_witness_receipts(id) ON DELETE CASCADE,
        source_id TEXT NOT NULL CHECK (source_id ~ '^[a-z][a-z0-9_-]{1,63}$'),
        chain_sequence BIGINT NOT NULL CHECK (chain_sequence >= 0),
        object_key TEXT NOT NULL UNIQUE CHECK (length(object_key) BETWEEN 1 AND 1024),
        content_sha256 TEXT NOT NULL CHECK (content_sha256 ~ '^[a-f0-9]{64}$'),
        size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'storing', 'retrying', 'stored', 'failed')),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100),
        next_attempt_at TIMESTAMPTZ NOT NULL,
        lease_until TIMESTAMPTZ,
        last_error TEXT,
        object_version_id TEXT,
        server_side_encryption TEXT,
        object_lock_mode TEXT,
        object_lock_retain_until TIMESTAMPTZ,
        stored_at TIMESTAMPTZ,
        verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        UNIQUE (source_id, chain_sequence),
        CHECK ((status = 'storing') = (lease_until IS NOT NULL)),
        CHECK ((status = 'stored') = (stored_at IS NOT NULL AND verified_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_witness_evidence_due
       ON control_audit_witness_evidence(next_attempt_at, created_at)
       WHERE status IN ('pending', 'retrying', 'storing')`,
      `CREATE INDEX IF NOT EXISTS idx_control_audit_witness_evidence_status
       ON control_audit_witness_evidence(status, updated_at DESC)`,
    ],
  },
  {
    id: '022_data_governance',
    statements: [
      `ALTER TABLE control_customers
       ADD COLUMN IF NOT EXISTS data_region TEXT NOT NULL DEFAULT 'CN-BJ'`,
      `ALTER TABLE control_customers
       ADD COLUMN IF NOT EXISTS erased_at TIMESTAMPTZ`,
      `CREATE TABLE IF NOT EXISTS control_data_governance_state (
        singleton SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
        data_region TEXT NOT NULL,
        allowed_regions JSONB NOT NULL,
        cross_border_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        cross_border_assessment_id TEXT,
        policy_version TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
        policy_effective_at TIMESTAMPTZ NOT NULL,
        controller_name TEXT NOT NULL,
        privacy_contact TEXT NOT NULL,
        initialized_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK (jsonb_typeof(allowed_regions) = 'array'),
        CHECK (NOT cross_border_enabled OR cross_border_assessment_id IS NOT NULL)
      )`,
      `CREATE TABLE IF NOT EXISTS control_data_governance_requests (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        type TEXT NOT NULL CHECK (type IN (
          'customer_export', 'customer_erasure', 'forensic_export'
        )),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'completed', 'blocked', 'failed')),
        reason TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        earliest_execution_at TIMESTAMPTZ,
        manifest_sha256 TEXT CHECK (
          manifest_sha256 IS NULL OR manifest_sha256 ~ '^[a-f0-9]{64}$'
        ),
        result JSONB,
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK ((status = 'pending') = (completed_at IS NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_governance_requests_customer
       ON control_data_governance_requests(customer_id, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_governance_requests_pending
       ON control_data_governance_requests(earliest_execution_at, created_at)
       WHERE status = 'pending'`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_customer_pending_erasure
       ON control_data_governance_requests(customer_id)
       WHERE type = 'customer_erasure' AND status = 'pending'`,
      `CREATE TABLE IF NOT EXISTS control_legal_holds (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        scope JSONB NOT NULL,
        reason TEXT NOT NULL,
        created_by TEXT NOT NULL,
        expires_at TIMESTAMPTZ,
        released_at TIMESTAMPTZ,
        released_by TEXT,
        release_reason TEXT,
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK (jsonb_typeof(scope) = 'array'),
        CHECK ((released_at IS NULL) = (released_by IS NULL)),
        CHECK ((released_at IS NULL) = (release_reason IS NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_legal_holds_active
       ON control_legal_holds(customer_id, expires_at)
       WHERE released_at IS NULL`,
      `CREATE TABLE IF NOT EXISTS control_privacy_acceptances (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        policy_version TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
        accepted_by TEXT NOT NULL,
        accepted_at TIMESTAMPTZ NOT NULL,
        UNIQUE (customer_id, policy_version, accepted_by)
      )`,
      `INSERT INTO control_admin_permissions (id) VALUES
        ('data_governance.read'), ('data_governance.manage'), ('data_export.create'),
        ('customer_erasure.manage'), ('legal_hold.manage'), ('forensic_export.create')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'super_admin', id FROM control_admin_permissions
       WHERE id IN ('data_governance.read', 'data_governance.manage', 'data_export.create',
                    'customer_erasure.manage', 'legal_hold.manage', 'forensic_export.create')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'security_admin', id FROM control_admin_permissions
       WHERE id IN ('data_governance.read', 'data_governance.manage',
                    'customer_erasure.manage', 'legal_hold.manage', 'forensic_export.create')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT 'auditor', id FROM control_admin_permissions
       WHERE id = 'data_governance.read'
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '023_federation_gateway',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_federation_deployments (
        id TEXT PRIMARY KEY CHECK (id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$'),
        display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 160),
        origin TEXT NOT NULL UNIQUE CHECK (origin ~ '^https://'),
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (status IN ('active', 'blocked', 'disabled')),
        capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
        max_pending_messages INTEGER NOT NULL DEFAULT 10000
          CHECK (max_pending_messages BETWEEN 100 AND 1000000),
        created_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        CHECK (jsonb_typeof(capabilities) = 'array')
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_deployments_status
       ON control_federation_deployments(status, updated_at DESC)`,
      `CREATE TABLE IF NOT EXISTS control_federation_keys (
        deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id) ON DELETE CASCADE,
        key_id TEXT NOT NULL CHECK (key_id ~ '^[a-f0-9]{16}$'),
        public_key_pem TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
        not_before TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (deployment_id, key_id),
        CHECK (expires_at IS NULL OR expires_at > not_before),
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_keys_active
       ON control_federation_keys(deployment_id, not_before, expires_at)
       WHERE status = 'active'`,
      `CREATE TABLE IF NOT EXISTS control_federation_nonces (
        deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id) ON DELETE CASCADE,
        nonce TEXT NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (deployment_id, nonce)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_nonces_expiry
       ON control_federation_nonces(expires_at)`,
      `CREATE TABLE IF NOT EXISTS control_federation_blocks (
        blocker_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id) ON DELETE CASCADE,
        blocked_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id) ON DELETE CASCADE,
        reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
        created_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (blocker_deployment_id, blocked_deployment_id),
        CHECK (blocker_deployment_id <> blocked_deployment_id)
      )`,
      `CREATE TABLE IF NOT EXISTS control_federation_a2a_grants (
        id TEXT PRIMARY KEY CHECK (id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$'),
        owner_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        requester_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        owner_principal_id TEXT NOT NULL,
        requester_principal_id TEXT NOT NULL,
        scopes JSONB NOT NULL,
        max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 10),
        used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count BETWEEN 0 AND 10),
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        CHECK (owner_deployment_id <> requester_deployment_id),
        CHECK (used_count <= max_uses),
        CHECK (jsonb_typeof(scopes) = 'array')
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_grants_active
       ON control_federation_a2a_grants(owner_deployment_id, requester_deployment_id, expires_at)
       WHERE revoked_at IS NULL`,
      `CREATE TABLE IF NOT EXISTS control_federation_messages (
        message_id TEXT PRIMARY KEY CHECK (message_id ~ '^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,127}$'),
        version SMALLINT NOT NULL CHECK (version = 1),
        message_type TEXT NOT NULL CHECK (message_type IN (
          'chat.message', 'chat.receipt', 'a2a.request', 'a2a.response'
        )),
        sender_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        recipient_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        issued_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        nonce TEXT NOT NULL,
        content_type TEXT NOT NULL CHECK (content_type = 'application/otto-e2ee+json'),
        ciphertext TEXT NOT NULL,
        ciphertext_sha256 TEXT NOT NULL CHECK (ciphertext_sha256 ~ '^[a-f0-9]{64}$'),
        size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 10485760),
        routing JSONB NOT NULL,
        signing_key_id TEXT NOT NULL,
        signature TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'claimed', 'delivered', 'expired')),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1000),
        claimed_until TIMESTAMPTZ,
        claim_token_hash TEXT CHECK (claim_token_hash IS NULL OR claim_token_hash ~ '^[a-f0-9]{64}$'),
        delivered_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        UNIQUE (sender_deployment_id, nonce),
        CHECK (sender_deployment_id <> recipient_deployment_id),
        CHECK (jsonb_typeof(routing) = 'object'),
        CHECK ((status = 'claimed') = (claimed_until IS NOT NULL AND claim_token_hash IS NOT NULL)),
        CHECK ((status = 'delivered') = (delivered_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_messages_inbox
       ON control_federation_messages(recipient_deployment_id, status, created_at)
       WHERE status IN ('pending', 'claimed')`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_messages_expiry
       ON control_federation_messages(expires_at)
       WHERE status IN ('pending', 'claimed')`,
      `CREATE TABLE IF NOT EXISTS control_federation_audit_events (
        id BIGSERIAL PRIMARY KEY,
        actor_deployment_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        details JSONB NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        CHECK (jsonb_typeof(details) = 'object')
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_audit_events_time
       ON control_federation_audit_events(occurred_at DESC, id DESC)`,
    ],
  },
  {
    id: '024_recovery_assurance_alerts',
    statements: [
      `ALTER TABLE control_alert_deliveries
       DROP CONSTRAINT IF EXISTS control_alert_deliveries_source_check`,
      `ALTER TABLE control_alert_deliveries
       ADD CONSTRAINT control_alert_deliveries_source_check
       CHECK (source IN ('backup_status', 'audit_integrity', 'audit_witness')) NOT VALID`,
      `ALTER TABLE control_alert_deliveries
       VALIDATE CONSTRAINT control_alert_deliveries_source_check`,
      `ALTER TABLE control_alert_deliveries
       DROP CONSTRAINT IF EXISTS control_alert_deliveries_event_type_check`,
      `ALTER TABLE control_alert_deliveries
       ADD CONSTRAINT control_alert_deliveries_event_type_check CHECK (event_type IN (
         'backup.recovery.alert', 'audit.integrity.alert', 'audit.witness.alert'
       )) NOT VALID`,
      `ALTER TABLE control_alert_deliveries
       VALIDATE CONSTRAINT control_alert_deliveries_event_type_check`,
    ],
  },
  {
    id: '025_signed_execution_receipts',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_execution_receipt_keys (
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id) ON DELETE CASCADE,
        key_id TEXT NOT NULL CHECK (key_id ~ '^[a-f0-9]{16}$'),
        public_key_pem TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
        not_before TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (deployment_id, key_id),
        CHECK (expires_at IS NULL OR expires_at > not_before),
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_execution_receipt_keys_active
       ON control_execution_receipt_keys(deployment_id, not_before, expires_at)
       WHERE status = 'active'`,
      `CREATE TABLE IF NOT EXISTS control_execution_receipt_sequences (
        deployment_id TEXT PRIMARY KEY REFERENCES control_deployments(id) ON DELETE CASCADE,
        last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
        updated_at TIMESTAMPTZ NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS control_execution_receipts (
        receipt_id TEXT PRIMARY KEY CHECK (receipt_id ~ '^exec_[a-f0-9]{32}$'),
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        deployment_id TEXT NOT NULL REFERENCES control_deployments(id),
        organization_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        module TEXT NOT NULL CHECK (module IN (
          'model_gateway', 'meeting_agent', 'park_service', 'atoa', 'feishu',
          'enterprise_knowledge', 'skill_market', 'data_visualization',
          'document_generation'
        )),
        units BIGINT NOT NULL CHECK (units > 0),
        model TEXT,
        issued_at_ms BIGINT NOT NULL CHECK (issued_at_ms > 0),
        expires_at_ms BIGINT NOT NULL CHECK (expires_at_ms > issued_at_ms),
        sequence BIGINT NOT NULL CHECK (sequence > 0),
        policy_version TEXT NOT NULL,
        signing_key_id TEXT NOT NULL,
        signature TEXT NOT NULL,
        payload JSONB NOT NULL,
        transaction_id TEXT NOT NULL UNIQUE REFERENCES control_credit_transactions(id),
        verification_status TEXT NOT NULL DEFAULT 'verified'
          CHECK (verification_status = 'verified'),
        received_at TIMESTAMPTZ NOT NULL,
        UNIQUE (deployment_id, sequence),
        UNIQUE (deployment_id, task_id),
        FOREIGN KEY (deployment_id, signing_key_id)
          REFERENCES control_execution_receipt_keys(deployment_id, key_id),
        CHECK (jsonb_typeof(payload) = 'object')
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_execution_receipts_customer_time
       ON control_execution_receipts(customer_id, received_at DESC, receipt_id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_control_execution_receipts_dispute
       ON control_execution_receipts(customer_id, organization_id, module, received_at DESC)`,
    ],
  },
  {
    id: '026_commercial_delivery_and_privacy_sla',
    statements: [
      `ALTER TABLE control_data_governance_requests
       ADD COLUMN IF NOT EXISTS due_at TIMESTAMPTZ`,
      `UPDATE control_data_governance_requests
       SET due_at = created_at + INTERVAL '15 days'
       WHERE due_at IS NULL`,
      `ALTER TABLE control_data_governance_requests
       ALTER COLUMN due_at SET NOT NULL`,
      `CREATE INDEX IF NOT EXISTS idx_control_data_governance_requests_sla
       ON control_data_governance_requests(status, due_at)
       WHERE status = 'pending'`,
      `INSERT INTO control_admin_permissions (id) VALUES ('customer_delivery.read')
       ON CONFLICT DO NOTHING`,
      `INSERT INTO control_admin_role_permissions (role_id, permission_id)
       SELECT id, 'customer_delivery.read'
       FROM control_admin_roles
       WHERE id IN ('super_admin', 'license_admin', 'auditor')
       ON CONFLICT DO NOTHING`,
    ],
  },
  {
    id: '027_federation_production_limits',
    statements: [
      `ALTER TABLE control_federation_deployments
       ADD COLUMN IF NOT EXISTS max_pending_bytes BIGINT NOT NULL DEFAULT 536870912
       CHECK (max_pending_bytes BETWEEN 1048576 AND 1099511627776)`,
      `ALTER TABLE control_federation_deployments
       ADD COLUMN IF NOT EXISTS max_requests_per_minute INTEGER NOT NULL DEFAULT 1200
       CHECK (max_requests_per_minute BETWEEN 60 AND 1000000)`,
      `CREATE TABLE IF NOT EXISTS control_federation_rate_windows (
        deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id) ON DELETE CASCADE,
        window_started_at TIMESTAMPTZ NOT NULL,
        request_count INTEGER NOT NULL CHECK (request_count BETWEEN 1 AND 1000000),
        PRIMARY KEY (deployment_id, window_started_at)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_rate_windows_expiry
       ON control_federation_rate_windows(window_started_at)`,
    ],
  },
  {
    id: '028_enterprise_credit_accounts',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_enterprise_credit_accounts (
        customer_id TEXT NOT NULL REFERENCES control_customers(id),
        organization_id TEXT NOT NULL,
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
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (customer_id, organization_id)
      )`,
      `CREATE TABLE IF NOT EXISTS control_legacy_credit_accounts (
        customer_id TEXT PRIMARY KEY REFERENCES control_customers(id),
        available_balance BIGINT NOT NULL,
        frozen_balance BIGINT NOT NULL,
        total_topped_up BIGINT NOT NULL,
        total_consumed BIGINT NOT NULL,
        total_refunded BIGINT NOT NULL,
        source_version INTEGER NOT NULL,
        migration_reason TEXT NOT NULL,
        quarantined_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `WITH organization_candidates AS (
         SELECT customer_id, MIN(organization_id) AS organization_id
         FROM (
           SELECT customer_id, organization_id FROM control_deployments
           UNION
           SELECT customer_id, organization_id
           FROM control_credit_transactions WHERE organization_id IS NOT NULL
           UNION
           SELECT customer_id, organization_id FROM control_credit_holds
         ) candidates
         GROUP BY customer_id
         HAVING COUNT(DISTINCT organization_id) = 1
       )
       INSERT INTO control_enterprise_credit_accounts
         (customer_id, organization_id, available_balance, frozen_balance,
          total_topped_up, total_consumed, total_refunded, version, created_at, updated_at)
       SELECT account.customer_id, candidate.organization_id, account.available_balance,
              account.frozen_balance, account.total_topped_up, account.total_consumed,
              account.total_refunded, account.version, account.created_at, account.updated_at
       FROM control_credit_accounts account
       JOIN organization_candidates candidate ON candidate.customer_id = account.customer_id
       ON CONFLICT (customer_id, organization_id) DO NOTHING`,
      `WITH organization_candidates AS (
         SELECT customer_id
         FROM (
           SELECT customer_id, organization_id FROM control_deployments
           UNION
           SELECT customer_id, organization_id
           FROM control_credit_transactions WHERE organization_id IS NOT NULL
           UNION
           SELECT customer_id, organization_id FROM control_credit_holds
         ) candidates
         GROUP BY customer_id
         HAVING COUNT(DISTINCT organization_id) = 1
       )
       INSERT INTO control_legacy_credit_accounts
         (customer_id, available_balance, frozen_balance, total_topped_up,
          total_consumed, total_refunded, source_version, migration_reason)
       SELECT account.customer_id, account.available_balance, account.frozen_balance,
              account.total_topped_up, account.total_consumed, account.total_refunded,
              account.version, 'organization_ownership_ambiguous'
       FROM control_credit_accounts account
       LEFT JOIN organization_candidates candidate ON candidate.customer_id = account.customer_id
       WHERE candidate.customer_id IS NULL
         AND (account.available_balance > 0 OR account.frozen_balance > 0
              OR account.total_topped_up > 0 OR account.total_consumed > 0
              OR account.total_refunded > 0)
       ON CONFLICT (customer_id) DO NOTHING`,
      `WITH organizations AS (
         SELECT DISTINCT customer_id, organization_id
         FROM (
           SELECT customer_id, organization_id FROM control_deployments
           UNION
           SELECT customer_id, organization_id
           FROM control_credit_transactions WHERE organization_id IS NOT NULL
           UNION
           SELECT customer_id, organization_id FROM control_credit_holds
         ) candidates
       ), hold_totals AS (
         SELECT customer_id, organization_id, COALESCE(SUM(amount), 0) AS frozen_balance
         FROM control_credit_holds
         WHERE status = 'active'
         GROUP BY customer_id, organization_id
       ), transaction_totals AS (
         SELECT customer_id, organization_id,
                COALESCE(SUM(billed_amount)
                  FILTER (WHERE type IN ('consume', 'capture')), 0) AS total_consumed,
                COALESCE(SUM(billed_amount)
                  FILTER (WHERE type = 'refund'), 0) AS total_refunded
         FROM control_credit_transactions
         WHERE organization_id IS NOT NULL
         GROUP BY customer_id, organization_id
       )
       INSERT INTO control_enterprise_credit_accounts
         (customer_id, organization_id, available_balance, frozen_balance,
          total_topped_up, total_consumed, total_refunded, version)
       SELECT organizations.customer_id, organizations.organization_id, 0,
              COALESCE(hold_totals.frozen_balance, 0), 0,
              COALESCE(transaction_totals.total_consumed, 0),
              COALESCE(transaction_totals.total_refunded, 0), 1
       FROM organizations
       JOIN control_credit_accounts legacy
         ON legacy.customer_id = organizations.customer_id
       LEFT JOIN hold_totals
         ON hold_totals.customer_id = organizations.customer_id
        AND hold_totals.organization_id = organizations.organization_id
       LEFT JOIN transaction_totals
         ON transaction_totals.customer_id = organizations.customer_id
        AND transaction_totals.organization_id = organizations.organization_id
       ON CONFLICT (customer_id, organization_id) DO NOTHING`,
      `ALTER TABLE control_credit_transactions
       DROP CONSTRAINT IF EXISTS control_credit_transactions_customer_id_idempotency_key_key`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_credit_transactions_enterprise_idempotency
       ON control_credit_transactions(customer_id, organization_id, idempotency_key)`,
      `ALTER TABLE control_credit_holds
       DROP CONSTRAINT IF EXISTS control_credit_holds_customer_id_idempotency_key_key`,
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_control_credit_holds_enterprise_idempotency
       ON control_credit_holds(customer_id, organization_id, idempotency_key)`,
      `CREATE INDEX IF NOT EXISTS idx_control_enterprise_credit_accounts_customer
       ON control_enterprise_credit_accounts(customer_id, organization_id)`,
    ],
  },
  {
    id: '029_federation_attachment_relay',
    statements: [
      `CREATE TABLE IF NOT EXISTS control_federation_attachments (
        id TEXT PRIMARY KEY,
        sender_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        recipient_deployment_id TEXT NOT NULL REFERENCES control_federation_deployments(id),
        object_key TEXT NOT NULL UNIQUE,
        ciphertext_bytes BIGINT NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 5368709120),
        ciphertext_sha256 TEXT NOT NULL CHECK (ciphertext_sha256 ~ '^[a-f0-9]{64}$'),
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'expired')),
        expires_at TIMESTAMPTZ NOT NULL,
        ready_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_attachments_recipient
       ON control_federation_attachments(recipient_deployment_id, status, expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_control_federation_attachments_expiry
       ON control_federation_attachments(status, expires_at)`,
    ],
  },
];

export const CONTROL_SCHEMA_MIGRATION_IDS = Object.freeze(
  MIGRATIONS.map((migration) => migration.id),
);

export async function runMigrations(client: PoolClient): Promise<void> {
  await client.query("SELECT pg_advisory_lock(hashtext('otto_control_migrations'))");
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS control_schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);

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
