import { createHmac, timingSafeEqual } from 'node:crypto';

export type ControlTokenPurpose = 'lease' | 'telemetry';

export class ControlTokenIssuer {
  readonly #secret: Buffer;

  constructor(secret: string) {
    if (Buffer.byteLength(secret, 'utf8') < 32) {
      throw new Error('control token secret must contain at least 32 bytes');
    }
    this.#secret = Buffer.from(secret, 'utf8');
  }

  issue(input: {
    purpose: ControlTokenPurpose;
    licenseId: string;
    deploymentId: string;
    version: number;
  }): string {
    return createHmac('sha256', this.#secret)
      .update(
        `otto-control\0${input.purpose}\0${input.version}\0${input.licenseId}\0${input.deploymentId}`,
        'utf8',
      )
      .digest('base64url');
  }

  matches(candidate: string, expected: string): boolean {
    const left = Buffer.from(candidate, 'utf8');
    const right = Buffer.from(expected, 'utf8');
    return left.length === right.length && timingSafeEqual(left, right);
  }
}
