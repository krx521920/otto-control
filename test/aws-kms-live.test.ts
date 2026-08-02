import { describe, expect, it } from 'vitest';

import { AwsKmsEd25519Signer } from '../src/crypto/aws-kms-ed25519-signer.js';

const keyArns = (process.env.CONTROL_TEST_AWS_KMS_KEY_ARNS ?? '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const required = process.env.CONTROL_REQUIRE_AWS_KMS_TEST === 'true';

if (required && keyArns.length === 0) {
  throw new Error('CONTROL_TEST_AWS_KMS_KEY_ARNS is required for the live AWS KMS test');
}

const liveDescribe = keyArns.length > 0 ? describe : describe.skip;

liveDescribe('live AWS KMS Ed25519 integration', () => {
  it('validates metadata and returns a locally verified production signature', async () => {
    const signer = await AwsKmsEd25519Signer.create({ keyArns, timeoutMs: 10_000 });
    await expect(signer.sign({
      version: 1,
      purpose: 'otto-control-live-aws-kms-test',
      runId: process.env.GITHUB_RUN_ID ?? 'manual',
      issuedAt: new Date().toISOString(),
    })).resolves.toMatch(/^ed25519:[A-Za-z0-9_-]{86}$/u);
    expect(signer.health()).toMatchObject({
      state: 'available',
      backend: 'aws_kms',
      consecutiveFailures: 0,
    });
  }, 60_000);
});
