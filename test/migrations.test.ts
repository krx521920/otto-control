import type { PoolClient, QueryResult } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import { runMigrations } from '../src/storage/migrations.js';

function result(rowCount = 0): QueryResult<never> {
  return {
    command: '',
    rowCount,
    oid: 0,
    fields: [],
    rows: [],
  };
}

describe('PostgreSQL migrations', () => {
  it('serializes migration runners with an advisory lock', async () => {
    const statements: string[] = [];
    const query = vi.fn(async (statement: string) => {
      statements.push(statement);
      return result();
    });
    await runMigrations({ query } as unknown as PoolClient);

    const lock = statements.findIndex((statement) => statement.includes('pg_advisory_lock'));
    const ledger = statements.findIndex((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_schema_migrations')
    ));
    const begin = statements.indexOf('BEGIN');
    const commit = statements.indexOf('COMMIT');
    const unlock = statements.findIndex((statement) => statement.includes('pg_advisory_unlock'));
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(ledger).toBeGreaterThan(lock);
    expect(begin).toBeGreaterThan(ledger);
    expect(begin).toBeGreaterThan(lock);
    expect(commit).toBeGreaterThan(begin);
    expect(unlock).toBeGreaterThan(commit);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_admin_accounts')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_admin_approvals')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_credit_accounts')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_credit_transactions')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_execution_receipts')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_execution_receipt_keys')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('ALTER TABLE control_data_governance_requests')
      && statement.includes('ADD COLUMN IF NOT EXISTS due_at')
    ))).toBe(true);
    expect(statements.some((statement) => statement.includes("VALUES ('customer_delivery.read')")))
      .toBe(true);
    const customerDeliveryGrant = statements.find((statement) => (
      statement.includes("SELECT id, 'customer_delivery.read'")
    ));
    expect(customerDeliveryGrant).toContain("WHERE id IN ('super_admin', 'license_admin', 'auditor')");
    expect(customerDeliveryGrant).not.toContain('SELECT role_id');
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_federation_rate_windows')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_release_artifacts')
    ))).toBe(true);
    expect(statements.some((statement) => statement.includes("VALUES ('backup.read')"))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_alert_deliveries')
    ))).toBe(true);
    expect(statements.some((statement) => statement.includes("('alert.read')"))).toBe(true);
    expect(statements.some((statement) => statement.includes("VALUES ('commercial.read')"))).toBe(true);
    expect(statements.some((statement) => statement.includes("VALUES ('license.export')"))).toBe(true);
    expect(statements.some((statement) => statement.includes('request_payload JSONB'))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('idx_control_alert_deliveries_fingerprint_channel')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_audit_chain_state')
    ))).toBe(true);
    expect(statements.some((statement) => statement.includes("('audit.read')"))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_audit_anchors')
    ))).toBe(true);
    expect(statements.some((statement) => statement.includes("('audit.anchor.manage')"))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_audit_witness_receipts')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_audit_witness_evidence')
    ))).toBe(true);
  });

  it('rolls back a failed migration and always releases the lock', async () => {
    const statements: string[] = [];
    const query = vi.fn(async (statement: string) => {
      statements.push(statement);
      if (statement.includes('CREATE TABLE IF NOT EXISTS control_customers')) {
        throw new Error('database failure');
      }
      return result();
    });
    await expect(runMigrations({ query } as unknown as PoolClient)).rejects.toThrow(
      'database failure',
    );
    expect(statements).toContain('ROLLBACK');
    expect(statements.some((statement) => statement.includes('pg_advisory_unlock'))).toBe(true);
  });
});
