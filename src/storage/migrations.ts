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
