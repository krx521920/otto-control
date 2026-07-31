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
    const begin = statements.indexOf('BEGIN');
    const commit = statements.indexOf('COMMIT');
    const unlock = statements.findIndex((statement) => statement.includes('pg_advisory_unlock'));
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(begin).toBeGreaterThan(lock);
    expect(commit).toBeGreaterThan(begin);
    expect(unlock).toBeGreaterThan(commit);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_admin_accounts')
    ))).toBe(true);
    expect(statements.some((statement) => (
      statement.includes('CREATE TABLE IF NOT EXISTS control_admin_approvals')
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
