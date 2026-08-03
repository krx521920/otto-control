import { randomBytes } from 'node:crypto';

import pg, { type PoolClient } from 'pg';

import type {
  FederationA2aGrantRecord,
  FederationAuditEventInput,
  FederationBlockRecord,
  FederationClaimedMessage,
  FederationDeploymentKeyRecord,
  FederationDeploymentRecord,
  FederationDeploymentUsage,
  FederationMessageStatus,
  FederationQueueStats,
  FederationStoredMessage,
} from '../../contracts/federation.js';
import { capacityExceeded, conflict, forbidden } from '../../errors.js';
import { runMigrations } from '../../storage/migrations.js';
import { claimTokenHash } from './crypto.js';
import {
  messageFromEnvelope,
  type CreateFederationGrantInput,
  type EnqueueFederationMessageInput,
  type EnqueueFederationMessageResult,
  type FederationStore,
  type RegisterFederationDeploymentInput,
  type RegisterFederationKeyInput,
} from './store.js';

const { Pool } = pg;

interface PostgresFederationStoreOptions {
  connectionString: string;
  ssl: boolean;
  onPoolError?: (error: Error) => void;
}

interface DeploymentRow {
  id: string;
  display_name: string;
  origin: string;
  status: FederationDeploymentRecord['status'];
  capabilities: string[];
  max_pending_messages: number;
  max_pending_bytes: string;
  max_requests_per_minute: number;
  created_at: Date;
  updated_at: Date;
}

interface KeyRow {
  deployment_id: string;
  key_id: string;
  public_key_pem: string;
  status: FederationDeploymentKeyRecord['status'];
  not_before: Date;
  expires_at: Date | null;
  revoked_at: Date | null;
  created_at: Date;
}

interface GrantRow {
  id: string;
  owner_deployment_id: string;
  requester_deployment_id: string;
  owner_principal_id: string;
  requester_principal_id: string;
  scopes: string[];
  max_uses: number;
  used_count: number;
  expires_at: Date;
  revoked_at: Date | null;
  created_at: Date;
}

interface MessageRow {
  message_id: string;
  version: 1;
  message_type: FederationStoredMessage['type'];
  sender_deployment_id: string;
  recipient_deployment_id: string;
  issued_at: Date;
  expires_at: Date;
  nonce: string;
  content_type: FederationStoredMessage['contentType'];
  ciphertext: string;
  ciphertext_sha256: string;
  size_bytes: number;
  routing: FederationStoredMessage['routing'];
  signing_key_id: string;
  signature: string;
  status: FederationMessageStatus;
  attempts: number;
  claimed_until: Date | null;
  delivered_at: Date | null;
  created_at: Date;
}

function deploymentFromRow(row: DeploymentRow): FederationDeploymentRecord {
  return {
    id: row.id,
    displayName: row.display_name,
    origin: row.origin,
    status: row.status,
    capabilities: row.capabilities,
    maxPendingMessages: row.max_pending_messages,
    maxPendingBytes: Number(row.max_pending_bytes),
    maxRequestsPerMinute: row.max_requests_per_minute,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function keyFromRow(row: KeyRow): FederationDeploymentKeyRecord {
  return {
    deploymentId: row.deployment_id,
    keyId: row.key_id,
    publicKeyPem: row.public_key_pem,
    status: row.status,
    notBefore: row.not_before,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

function grantFromRow(row: GrantRow): FederationA2aGrantRecord {
  return {
    id: row.id,
    ownerDeploymentId: row.owner_deployment_id,
    requesterDeploymentId: row.requester_deployment_id,
    ownerPrincipalId: row.owner_principal_id,
    requesterPrincipalId: row.requester_principal_id,
    scopes: row.scopes,
    maxUses: row.max_uses,
    usedCount: row.used_count,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

function messageFromRow(row: MessageRow): FederationStoredMessage {
  return {
    version: row.version,
    messageId: row.message_id,
    type: row.message_type,
    senderDeploymentId: row.sender_deployment_id,
    recipientDeploymentId: row.recipient_deployment_id,
    issuedAt: row.issued_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    nonce: row.nonce,
    contentType: row.content_type,
    ciphertext: row.ciphertext,
    routing: row.routing,
    signingKeyId: row.signing_key_id,
    signature: row.signature,
    ciphertextSha256: row.ciphertext_sha256,
    sizeBytes: row.size_bytes,
    status: row.status,
    attempts: row.attempts,
    claimedUntil: row.claimed_until,
    deliveredAt: row.delivered_at,
    createdAt: row.created_at,
  };
}

export class PostgresFederationStore implements FederationStore {
  readonly #pool: pg.Pool;

  private constructor(pool: pg.Pool) {
    this.#pool = pool;
  }

  static async connect(options: PostgresFederationStoreOptions): Promise<PostgresFederationStore> {
    const pool = new Pool({
      connectionString: options.connectionString,
      ssl: options.ssl ? { rejectUnauthorized: true } : undefined,
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      statement_timeout: 30_000,
      application_name: 'otto-federation',
    });
    if (options.onPoolError) pool.on('error', options.onPoolError);
    const client = await pool.connect();
    try {
      await runMigrations(client);
    } catch (error) {
      client.release();
      await pool.end();
      throw error;
    }
    client.release();
    return new PostgresFederationStore(pool);
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async ready(): Promise<boolean> {
    try {
      const result = await this.#pool.query<{ ready: number }>('SELECT 1 AS ready');
      return result.rows[0]?.ready === 1;
    } catch {
      return false;
    }
  }

  async registerDeployment(input: RegisterFederationDeploymentInput): Promise<FederationDeploymentRecord> {
    const result = await this.#pool.query<DeploymentRow>(
      `INSERT INTO control_federation_deployments
       (id, display_name, origin, capabilities, max_pending_messages, max_pending_bytes,
        max_requests_per_minute, created_at, updated_at)
       VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $8)
       ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name,
         origin = EXCLUDED.origin, capabilities = EXCLUDED.capabilities,
         max_pending_messages = EXCLUDED.max_pending_messages,
         max_pending_bytes = EXCLUDED.max_pending_bytes,
         max_requests_per_minute = EXCLUDED.max_requests_per_minute,
         updated_at = EXCLUDED.updated_at
       RETURNING *`,
      [input.id, input.displayName, input.origin, JSON.stringify(input.capabilities),
        input.maxPendingMessages, input.maxPendingBytes, input.maxRequestsPerMinute, input.now],
    );
    return deploymentFromRow(result.rows[0]!);
  }

  async setDeploymentStatus(
    deploymentId: string,
    status: FederationDeploymentRecord['status'],
    now: Date,
  ): Promise<FederationDeploymentRecord | null> {
    return this.#transaction(async (client) => {
      const result = await client.query<DeploymentRow>(
        `UPDATE control_federation_deployments SET status = $2, updated_at = $3
         WHERE id = $1 RETURNING *`,
        [deploymentId, status, now],
      );
      if (result.rows[0] && status !== 'active') {
        await client.query(
          `UPDATE control_federation_messages
           SET status = 'expired', claimed_until = NULL, claim_token_hash = NULL
           WHERE status IN ('pending', 'claimed')
             AND (sender_deployment_id = $1 OR recipient_deployment_id = $1)`,
          [deploymentId],
        );
      }
      return result.rows[0] ? deploymentFromRow(result.rows[0]) : null;
    });
  }

  async getDeployment(deploymentId: string): Promise<FederationDeploymentRecord | null> {
    const result = await this.#pool.query<DeploymentRow>(
      'SELECT * FROM control_federation_deployments WHERE id = $1',
      [deploymentId],
    );
    return result.rows[0] ? deploymentFromRow(result.rows[0]) : null;
  }

  async listDeployments(limit: number): Promise<FederationDeploymentRecord[]> {
    const result = await this.#pool.query<DeploymentRow>(
      'SELECT * FROM control_federation_deployments ORDER BY updated_at DESC, id LIMIT $1',
      [limit],
    );
    return result.rows.map(deploymentFromRow);
  }

  async registerKey(input: RegisterFederationKeyInput): Promise<FederationDeploymentKeyRecord> {
    const result = await this.#pool.query<KeyRow>(
      `INSERT INTO control_federation_keys
       (deployment_id, key_id, public_key_pem, status, not_before, expires_at, created_at)
       VALUES ($1, $2, $3, 'active', $4, $5, $6)
       ON CONFLICT (deployment_id, key_id) DO UPDATE SET
         public_key_pem = EXCLUDED.public_key_pem, status = 'active',
         not_before = EXCLUDED.not_before, expires_at = EXCLUDED.expires_at, revoked_at = NULL
       WHERE control_federation_keys.status = 'active'
       RETURNING *`,
      [input.deploymentId, input.keyId, input.publicKeyPem, input.notBefore, input.expiresAt, input.now],
    );
    if (!result.rows[0]) throw conflict('a revoked federation key id cannot be reused');
    return keyFromRow(result.rows[0]);
  }

  async revokeKey(deploymentId: string, keyId: string, now: Date): Promise<boolean> {
    return this.#transaction(async (client) => {
      const result = await client.query(
        `UPDATE control_federation_keys SET status = 'revoked', revoked_at = $3
         WHERE deployment_id = $1 AND key_id = $2 AND status = 'active'`,
        [deploymentId, keyId, now],
      );
      if ((result.rowCount ?? 0) === 0) return false;
      await client.query(
        `UPDATE control_federation_messages
         SET status = 'expired', claimed_until = NULL, claim_token_hash = NULL
         WHERE sender_deployment_id = $1 AND signing_key_id = $2
           AND status IN ('pending', 'claimed')`,
        [deploymentId, keyId],
      );
      return true;
    });
  }

  async getActiveKey(
    deploymentId: string,
    keyId: string,
    now: Date,
  ): Promise<FederationDeploymentKeyRecord | null> {
    const result = await this.#pool.query<KeyRow>(
      `SELECT * FROM control_federation_keys
       WHERE deployment_id = $1 AND key_id = $2 AND status = 'active'
         AND not_before <= $3 AND (expires_at IS NULL OR expires_at > $3)`,
      [deploymentId, keyId, now],
    );
    return result.rows[0] ? keyFromRow(result.rows[0]) : null;
  }

  async getVerificationKey(
    deploymentId: string,
    keyId: string,
  ): Promise<FederationDeploymentKeyRecord | null> {
    const result = await this.#pool.query<KeyRow>(
      `SELECT * FROM control_federation_keys
       WHERE deployment_id = $1 AND key_id = $2 AND status = 'active'`,
      [deploymentId, keyId],
    );
    return result.rows[0] ? keyFromRow(result.rows[0]) : null;
  }

  async consumeNonce(deploymentId: string, nonce: string, expiresAt: Date, now: Date): Promise<boolean> {
    await this.#pool.query('DELETE FROM control_federation_nonces WHERE expires_at <= $1', [now]);
    const result = await this.#pool.query(
      `INSERT INTO control_federation_nonces (deployment_id, nonce, expires_at, created_at)
       VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
      [deploymentId, nonce, expiresAt, now],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async isBlocked(senderDeploymentId: string, recipientDeploymentId: string): Promise<boolean> {
    const result = await this.#pool.query(
      `SELECT 1 FROM control_federation_blocks
       WHERE (blocker_deployment_id = $1 AND blocked_deployment_id = $2)
          OR (blocker_deployment_id = $2 AND blocked_deployment_id = $1)
       LIMIT 1`,
      [senderDeploymentId, recipientDeploymentId],
    );
    return Boolean(result.rowCount);
  }

  async setBlock(input: FederationBlockRecord): Promise<void> {
    await this.#transaction(async (client) => {
      await client.query(
        `SELECT id FROM control_federation_deployments
         WHERE id IN ($1, $2) ORDER BY id FOR UPDATE`,
        [input.blockerDeploymentId, input.blockedDeploymentId],
      );
      await client.query(
        `INSERT INTO control_federation_blocks
         (blocker_deployment_id, blocked_deployment_id, reason, created_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (blocker_deployment_id, blocked_deployment_id)
         DO UPDATE SET reason = EXCLUDED.reason, created_at = EXCLUDED.created_at`,
        [input.blockerDeploymentId, input.blockedDeploymentId, input.reason, input.createdAt],
      );
      await client.query(
        `UPDATE control_federation_messages
         SET status = 'expired', claimed_until = NULL, claim_token_hash = NULL
         WHERE status IN ('pending', 'claimed') AND (
           (sender_deployment_id = $1 AND recipient_deployment_id = $2)
           OR (sender_deployment_id = $2 AND recipient_deployment_id = $1)
         )`,
        [input.blockerDeploymentId, input.blockedDeploymentId],
      );
    });
  }

  async removeBlock(blockerDeploymentId: string, blockedDeploymentId: string): Promise<boolean> {
    const result = await this.#pool.query(
      `DELETE FROM control_federation_blocks
       WHERE blocker_deployment_id = $1 AND blocked_deployment_id = $2`,
      [blockerDeploymentId, blockedDeploymentId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async consumeRateLimit(deploymentId: string, now: Date): Promise<boolean> {
    const windowStartedAt = new Date(Math.floor(now.getTime() / 60_000) * 60_000);
    const result = await this.#pool.query(
      `INSERT INTO control_federation_rate_windows
       (deployment_id, window_started_at, request_count)
       SELECT id, $2, 1 FROM control_federation_deployments
       WHERE id = $1 AND status = 'active'
       ON CONFLICT (deployment_id, window_started_at) DO UPDATE
       SET request_count = control_federation_rate_windows.request_count + 1
       WHERE control_federation_rate_windows.request_count < (
         SELECT max_requests_per_minute FROM control_federation_deployments WHERE id = $1
       )
       RETURNING request_count`,
      [deploymentId, windowStartedAt],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async createGrant(input: CreateFederationGrantInput): Promise<FederationA2aGrantRecord> {
    const result = await this.#pool.query<GrantRow>(
      `INSERT INTO control_federation_a2a_grants
       (id, owner_deployment_id, requester_deployment_id, owner_principal_id,
        requester_principal_id, scopes, max_uses, used_count, expires_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, 0, $8, $9)
       RETURNING *`,
      [input.id, input.ownerDeploymentId, input.requesterDeploymentId,
        input.ownerPrincipalId, input.requesterPrincipalId, JSON.stringify(input.scopes),
        input.maxUses, input.expiresAt, input.now],
    );
    return grantFromRow(result.rows[0]!);
  }

  async revokeGrant(ownerDeploymentId: string, grantId: string, now: Date): Promise<boolean> {
    const result = await this.#pool.query(
      `UPDATE control_federation_a2a_grants SET revoked_at = $3
       WHERE id = $1 AND owner_deployment_id = $2 AND revoked_at IS NULL`,
      [grantId, ownerDeploymentId, now],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async enqueueMessage(input: EnqueueFederationMessageInput): Promise<EnqueueFederationMessageResult> {
    return this.#transaction(async (client) => {
      const envelope = input.signed.envelope;
      const existing = await client.query<MessageRow>(
        'SELECT * FROM control_federation_messages WHERE message_id = $1 FOR UPDATE',
        [envelope.messageId],
      );
      if (existing.rows[0]) {
        const message = messageFromRow(existing.rows[0]);
        if (
          message.senderDeploymentId !== envelope.senderDeploymentId
          || message.ciphertextSha256 !== input.ciphertextSha256
        ) {
          throw conflict('messageId already belongs to a different federation envelope');
        }
        return { message, duplicate: true };
      }

      // Serialize capacity checks per recipient so concurrent gateway instances
      // cannot collectively exceed the deployment's pending-message limit.
      const deployments = await client.query<{
        id: string;
        status: FederationDeploymentRecord['status'];
        max_pending_messages: number;
        max_pending_bytes: string;
      }>(
        `SELECT id, status, max_pending_messages, max_pending_bytes
         FROM control_federation_deployments
         WHERE id IN ($1, $2) ORDER BY id FOR UPDATE`,
        [envelope.senderDeploymentId, envelope.recipientDeploymentId],
      );
      const sender = deployments.rows.find((row) => row.id === envelope.senderDeploymentId);
      const recipient = deployments.rows.find((row) => row.id === envelope.recipientDeploymentId);
      if (!sender || !recipient || sender.status !== 'active' || recipient.status !== 'active') {
        throw forbidden('federation deployment is not active');
      }
      const signingKey = await client.query(
        `SELECT 1 FROM control_federation_keys
         WHERE deployment_id = $1 AND key_id = $2 AND status = 'active'
           AND not_before <= $3 AND (expires_at IS NULL OR expires_at > $3)
         FOR SHARE`,
        [envelope.senderDeploymentId, input.signed.signingKeyId, input.now],
      );
      if (!signingKey.rowCount) throw forbidden('federation signing key is no longer active');
      const blocked = await client.query(
        `SELECT 1 FROM control_federation_blocks
         WHERE (blocker_deployment_id = $1 AND blocked_deployment_id = $2)
            OR (blocker_deployment_id = $2 AND blocked_deployment_id = $1)
         LIMIT 1`,
        [envelope.senderDeploymentId, envelope.recipientDeploymentId],
      );
      if (blocked.rowCount) throw forbidden('federation route is blocked');
      const capacity = await client.query<{ pending: string; pending_bytes: string }>(
        `SELECT COUNT(*)::text AS pending, COALESCE(SUM(size_bytes), 0)::text AS pending_bytes
         FROM control_federation_messages
         WHERE recipient_deployment_id = $1 AND status IN ('pending', 'claimed')`,
        [envelope.recipientDeploymentId],
      );
      if (
        Number(capacity.rows[0]?.pending ?? 0) >= recipient.max_pending_messages
        || Number(capacity.rows[0]?.pending_bytes ?? 0) + input.sizeBytes
          > Number(recipient.max_pending_bytes)
      ) {
        throw capacityExceeded('recipient federation inbox capacity is exhausted');
      }

      const nonce = await client.query(
        `INSERT INTO control_federation_nonces (deployment_id, nonce, expires_at, created_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [envelope.senderDeploymentId, envelope.nonce, envelope.expiresAt, input.now],
      );
      if ((nonce.rowCount ?? 0) === 0) {
        throw conflict('federation envelope nonce has already been used');
      }

      if (envelope.type === 'a2a.request') {
        const grant = await client.query<GrantRow>(
          `UPDATE control_federation_a2a_grants SET used_count = used_count + 1
           WHERE id = $1
             AND owner_deployment_id = $2
             AND requester_deployment_id = $3
             AND owner_principal_id = $4
             AND requester_principal_id = $5
             AND scopes ? $6
             AND revoked_at IS NULL AND expires_at > $7 AND used_count < max_uses
           RETURNING *`,
          [envelope.routing.a2aGrantId, envelope.recipientDeploymentId,
            envelope.senderDeploymentId, envelope.routing.recipientPrincipalId,
            envelope.routing.senderPrincipalId, envelope.routing.a2aScope, input.now],
        );
        if (!grant.rows[0]) throw forbidden('A2A grant is invalid, expired, revoked, or already consumed');
      }

      if (envelope.type === 'a2a.response') {
        const parent = await client.query<MessageRow>(
          `SELECT * FROM control_federation_messages
           WHERE message_id = $1 AND message_type = 'a2a.request'`,
          [envelope.routing.inReplyTo],
        );
        const request = parent.rows[0] ? messageFromRow(parent.rows[0]) : null;
        if (
          !request
          || request.senderDeploymentId !== envelope.recipientDeploymentId
          || request.recipientDeploymentId !== envelope.senderDeploymentId
          || request.routing.senderPrincipalId !== envelope.routing.recipientPrincipalId
          || request.routing.recipientPrincipalId !== envelope.routing.senderPrincipalId
        ) {
          throw forbidden('A2A response does not match an authorized request');
        }
      }

      if (envelope.type === 'chat.receipt') {
        const parent = await client.query<MessageRow>(
          `SELECT * FROM control_federation_messages
           WHERE message_id = $1 AND message_type = 'chat.message'`,
          [envelope.routing.inReplyTo],
        );
        const message = parent.rows[0] ? messageFromRow(parent.rows[0]) : null;
        if (
          !message
          || message.senderDeploymentId !== envelope.recipientDeploymentId
          || message.recipientDeploymentId !== envelope.senderDeploymentId
          || message.routing.senderPrincipalId !== envelope.routing.recipientPrincipalId
          || message.routing.recipientPrincipalId !== envelope.routing.senderPrincipalId
        ) {
          throw forbidden('chat receipt does not match a delivered message route');
        }
      }

      const pending = messageFromEnvelope({
        envelope,
        signingKeyId: input.signed.signingKeyId,
        signature: input.signed.signature,
        ciphertextSha256: input.ciphertextSha256,
        sizeBytes: input.sizeBytes,
        now: input.now,
      });
      const result = await client.query<MessageRow>(
        `INSERT INTO control_federation_messages
         (message_id, version, message_type, sender_deployment_id, recipient_deployment_id,
          issued_at, expires_at, nonce, content_type, ciphertext, ciphertext_sha256,
          size_bytes, routing, signing_key_id, signature, status, attempts, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb,
                 $14, $15, 'pending', 0, $16)
         RETURNING *`,
        [pending.messageId, pending.version, pending.type, pending.senderDeploymentId,
          pending.recipientDeploymentId, pending.issuedAt, pending.expiresAt, pending.nonce,
          pending.contentType, pending.ciphertext, pending.ciphertextSha256, pending.sizeBytes,
          JSON.stringify(pending.routing), pending.signingKeyId, pending.signature, pending.createdAt],
      );
      return { message: messageFromRow(result.rows[0]!), duplicate: false };
    });
  }

  async claimMessages(input: {
    recipientDeploymentId: string;
    limit: number;
    maximumBytes: number;
    claimTtlMs: number;
    now: Date;
  }): Promise<FederationClaimedMessage[]> {
    return this.#transaction(async (client) => {
      const claimedUntil = new Date(input.now.getTime() + input.claimTtlMs);
      const candidates = await client.query<MessageRow>(
        `SELECT * FROM control_federation_messages
         WHERE recipient_deployment_id = $1 AND expires_at > $2
           AND (status = 'pending' OR (status = 'claimed' AND claimed_until <= $2))
         ORDER BY created_at, message_id
         FOR UPDATE SKIP LOCKED LIMIT $3`,
        [input.recipientDeploymentId, input.now, input.limit],
      );
      const output: FederationClaimedMessage[] = [];
      let claimedBytes = 0;
      for (const row of candidates.rows) {
        if (output.length > 0 && claimedBytes + row.size_bytes > input.maximumBytes) break;
        const claimToken = randomBytes(32).toString('base64url');
        const updated = await client.query<MessageRow>(
          `UPDATE control_federation_messages
           SET status = 'claimed', attempts = attempts + 1,
             claimed_until = $2, claim_token_hash = $3
           WHERE message_id = $1 RETURNING *`,
          [row.message_id, claimedUntil, claimTokenHash(claimToken)],
        );
        output.push({ message: messageFromRow(updated.rows[0]!), claimToken });
        claimedBytes += row.size_bytes;
      }
      return output;
    });
  }

  async acknowledgeMessage(input: {
    recipientDeploymentId: string;
    messageId: string;
    claimToken: string;
    now: Date;
  }): Promise<boolean> {
    const result = await this.#pool.query(
      `UPDATE control_federation_messages
       SET status = 'delivered', delivered_at = $4,
         claimed_until = NULL, claim_token_hash = NULL
       WHERE message_id = $1 AND recipient_deployment_id = $2
         AND status = 'claimed' AND claimed_until > $4 AND claim_token_hash = $3`,
      [input.messageId, input.recipientDeploymentId, claimTokenHash(input.claimToken), input.now],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async getMessage(messageId: string): Promise<FederationStoredMessage | null> {
    const result = await this.#pool.query<MessageRow>(
      'SELECT * FROM control_federation_messages WHERE message_id = $1',
      [messageId],
    );
    return result.rows[0] ? messageFromRow(result.rows[0]) : null;
  }

  async appendAuditEvent(input: FederationAuditEventInput): Promise<void> {
    await this.#pool.query(
      `INSERT INTO control_federation_audit_events
       (actor_deployment_id, action, target_type, target_id, details, occurred_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6)`,
      [input.actorDeploymentId, input.action, input.targetType, input.targetId,
        JSON.stringify(input.details), input.occurredAt],
    );
  }

  async listAuditEvents(limit: number): Promise<FederationAuditEventInput[]> {
    const result = await this.#pool.query<{
      actor_deployment_id: string;
      action: string;
      target_type: string;
      target_id: string;
      details: Record<string, unknown>;
      occurred_at: Date;
    }>(
      `SELECT actor_deployment_id, action, target_type, target_id, details, occurred_at
       FROM control_federation_audit_events
       ORDER BY occurred_at DESC, id DESC LIMIT $1`,
      [limit],
    );
    return result.rows.map((row) => ({
      actorDeploymentId: row.actor_deployment_id,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      details: row.details,
      occurredAt: row.occurred_at,
    }));
  }

  async queueStats(): Promise<FederationQueueStats> {
    const result = await this.#pool.query<{ status: FederationMessageStatus; count: string }>(
      'SELECT status, COUNT(*)::text AS count FROM control_federation_messages GROUP BY status',
    );
    const stats: FederationQueueStats = { pending: 0, claimed: 0, delivered: 0, expired: 0 };
    for (const row of result.rows) stats[row.status] = Number(row.count);
    return stats;
  }

  async queueBytes(): Promise<FederationQueueStats> {
    const result = await this.#pool.query<{
      status: FederationMessageStatus;
      bytes: string;
    }>(
      `SELECT status, COALESCE(SUM(size_bytes), 0)::text AS bytes
       FROM control_federation_messages GROUP BY status`,
    );
    const stats: FederationQueueStats = { pending: 0, claimed: 0, delivered: 0, expired: 0 };
    for (const row of result.rows) stats[row.status] = Number(row.bytes);
    return stats;
  }

  async deploymentUsage(deploymentId: string): Promise<FederationDeploymentUsage> {
    const result = await this.#pool.query<{
      pending_messages: string;
      claimed_messages: string;
      pending_bytes: string;
      claimed_bytes: string;
    }>(
      `SELECT
         COUNT(*) FILTER (WHERE status = 'pending')::text AS pending_messages,
         COUNT(*) FILTER (WHERE status = 'claimed')::text AS claimed_messages,
         COALESCE(SUM(size_bytes) FILTER (WHERE status = 'pending'), 0)::text AS pending_bytes,
         COALESCE(SUM(size_bytes) FILTER (WHERE status = 'claimed'), 0)::text AS claimed_bytes
       FROM control_federation_messages
       WHERE recipient_deployment_id = $1`,
      [deploymentId],
    );
    const row = result.rows[0]!;
    return {
      pendingMessages: Number(row.pending_messages),
      claimedMessages: Number(row.claimed_messages),
      pendingBytes: Number(row.pending_bytes),
      claimedBytes: Number(row.claimed_bytes),
    };
  }

  async expireMessages(now: Date, deliveredBefore: Date): Promise<{ expired: number; purged: number }> {
    const result = await this.#pool.query(
      `UPDATE control_federation_messages
       SET status = 'expired', claimed_until = NULL, claim_token_hash = NULL
       WHERE status IN ('pending', 'claimed') AND expires_at <= $1`,
      [now],
    );
    await this.#pool.query('DELETE FROM control_federation_nonces WHERE expires_at <= $1', [now]);
    await this.#pool.query(
      `DELETE FROM control_federation_rate_windows
       WHERE window_started_at < $1 - INTERVAL '2 minutes'`,
      [now],
    );
    const purged = await this.#pool.query(
      `DELETE FROM control_federation_messages
       WHERE (status = 'delivered' AND delivered_at <= $1)
          OR (status = 'expired' AND expires_at <= $1)`,
      [deliveredBefore],
    );
    return { expired: result.rowCount ?? 0, purged: purged.rowCount ?? 0 };
  }

  async #transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
