import { generateKeyPairSync, verify } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { canonicalJson, LocalEd25519Signer } from '../src/crypto/signed-envelope.js';
import { AuditAnchorService } from '../src/modules/audit-anchor/service.js';
import { AuditService } from '../src/modules/audit/service.js';
import { MemoryControlStore } from './helpers/memory-store.js';

function fixture(): {
  directory: string;
  tokenFile: string;
  token: string;
  store: MemoryControlStore;
  audit: AuditService;
  signer: LocalEd25519Signer;
} {
  const directory = mkdtempSync(join(tmpdir(), 'otto-control-audit-anchor-'));
  const tokenFile = join(directory, 'anchor-token');
  const token = 'external-audit-anchor-token-with-enough-entropy';
  writeFileSync(tokenFile, token);
  const keys = generateKeyPairSync('ed25519');
  const signer = new LocalEd25519Signer(
    keys.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  );
  const store = new MemoryControlStore();
  return {
    directory,
    tokenFile,
    token,
    store,
    signer,
    audit: new AuditService({ store, signer, issuer: 'https://control.example.test' }),
  };
}

describe('external audit receipt anchoring', () => {
  it('persists, signs, delivers, and deduplicates an audit chain head', async () => {
    const files = fixture();
    const now = Date.parse('2026-08-01T12:00:00.000Z');
    try {
      await files.store.appendAuditEvent({
        actorId: 'admin_alpha', action: 'license.issue', targetType: 'license',
        targetId: 'lic_1', detail: { plan: 'enterprise' },
      });
      const fetcher = vi.fn(async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        void input;
        void init;
        return new Response(null, {
          status: 201,
          headers: { 'x-otto-audit-anchor-reference': 'witness/object/0001' },
        });
      });
      const service = new AuditAnchorService({
        store: files.store,
        audit: files.audit,
        url: 'https://witness.example.test/v1/anchors',
        tokenFile: files.tokenFile,
        now: () => now,
        fetcher: fetcher as unknown as typeof fetch,
      });

      await expect(service.pollOnce('admin_alpha', true)).resolves.toMatchObject({
        enabled: true,
        destinationOrigin: 'https://witness.example.test',
        enqueued: true,
        chainValid: true,
        processed: 1,
        delivered: 1,
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
      const [url, request] = fetcher.mock.calls[0]!;
      expect(String(url)).toBe('https://witness.example.test/v1/anchors');
      const headers = new Headers(request?.headers);
      expect(headers.get('authorization')).toBe(`Bearer ${files.token}`);
      const payload = JSON.parse(String(request?.body));
      expect(payload.evidence.receipt).toMatchObject({
        issuer: 'https://control.example.test',
        valid: true,
        lastSequence: 1,
      });
      expect(verify(
        null,
        Buffer.from(canonicalJson(payload.evidence.receipt)),
        files.signer.publicKey,
        Buffer.from(payload.evidence.signature.slice('ed25519:'.length), 'base64url'),
      )).toBe(true);
      expect(JSON.stringify(payload)).not.toContain(files.token);

      await expect(service.pollOnce()).resolves.toMatchObject({ enqueued: false, processed: 0 });
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect((await service.list()).anchors[0]).toMatchObject({
        status: 'delivered',
        attempts: 1,
        remoteReference: 'witness/object/0001',
      });
    } finally {
      rmSync(files.directory, { recursive: true, force: true });
    }
  });

  it('retries with backoff and supports an audited manual retry after terminal failure', async () => {
    const files = fixture();
    let now = Date.parse('2026-08-01T12:00:00.000Z');
    try {
      await files.store.appendAuditEvent({
        actorId: 'admin_alpha', action: 'customer.create', targetType: 'customer',
        targetId: 'cus_1', detail: {},
      });
      const fetcher = vi.fn(async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        void input;
        void init;
        return new Response(null, { status: 503 });
      });
      const service = new AuditAnchorService({
        store: files.store,
        audit: files.audit,
        url: 'https://witness.example.test/private-token',
        tokenFile: files.tokenFile,
        maxAttempts: 2,
        now: () => now,
        fetcher: fetcher as unknown as typeof fetch,
      });

      await expect(service.pollOnce('admin_alpha', true)).resolves.toMatchObject({ retrying: 1 });
      now += 31_000;
      await expect(service.pollOnce()).resolves.toMatchObject({ failed: 1 });
      let anchor = (await service.list()).anchors[0]!;
      expect(anchor).toMatchObject({ status: 'failed', attempts: 2 });
      expect(anchor.lastError).toBe('audit anchor endpoint returned HTTP 503');
      expect(JSON.stringify(anchor)).not.toContain('private-token');
      expect(JSON.stringify(anchor)).not.toContain(files.token);

      await expect(service.retry(anchor.id, 'admin_security')).resolves.toMatchObject({
        status: 'pending', attempts: 0, lastError: null,
      });
      expect(files.store.audits.at(-1)).toMatchObject({ action: 'audit.anchor.retried' });
      fetcher.mockResolvedValueOnce(new Response(null, { status: 204 }));
      await expect(service.pollOnce()).resolves.toMatchObject({ delivered: 1 });
      anchor = (await service.list()).anchors[0]!;
      expect(anchor).toMatchObject({ status: 'delivered', attempts: 1 });
    } finally {
      rmSync(files.directory, { recursive: true, force: true });
    }
  });

  it('refuses to endorse a broken chain and remains inert without a destination', async () => {
    const files = fixture();
    try {
      await files.store.appendAuditEvent({
        actorId: 'admin_alpha', action: 'deployment.create', targetType: 'deployment',
        targetId: 'dep_1', detail: { customerId: 'cus_1' },
      });
      files.store.auditRecords[0]!.detail = { customerId: 'tampered' };
      const fetcher = vi.fn(async (
        input: string | URL | Request,
        init?: RequestInit,
      ) => {
        void input;
        void init;
        return new Response(null, { status: 204 });
      });
      const service = new AuditAnchorService({
        store: files.store,
        audit: files.audit,
        url: 'https://witness.example.test/v1/anchors',
        tokenFile: files.tokenFile,
        fetcher: fetcher as unknown as typeof fetch,
      });
      await expect(service.pollOnce('admin_alpha', true)).resolves.toMatchObject({
        chainValid: false,
        enqueued: false,
        processed: 0,
      });
      expect(fetcher).not.toHaveBeenCalled();

      const disabled = new AuditAnchorService({ store: files.store, audit: files.audit });
      await expect(disabled.pollOnce()).resolves.toMatchObject({
        enabled: false,
        destinationOrigin: null,
      });
    } finally {
      rmSync(files.directory, { recursive: true, force: true });
    }
  });
});
