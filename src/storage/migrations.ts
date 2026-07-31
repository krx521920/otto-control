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
