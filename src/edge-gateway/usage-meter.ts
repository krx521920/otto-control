import type { EdgeModelUsageV1 } from '../contracts/edge-gateway.js';

const MAX_USAGE_OBJECT_BYTES = 16_384;
const MAX_TOKENS = 9_000_000_000_000;

function tokenCount(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= MAX_TOKENS
    ? Number(value)
    : null;
}

function normalizeUsage(body: Record<string, unknown>): EdgeModelUsageV1 | null {
  const hasResponsesFields = 'input_tokens' in body || 'output_tokens' in body;
  const hasChatFields = 'prompt_tokens' in body || 'completion_tokens' in body;
  if (hasResponsesFields === hasChatFields) return null;
  const inputTokens = tokenCount(hasResponsesFields ? body.input_tokens : body.prompt_tokens);
  const outputTokens = tokenCount(hasResponsesFields ? body.output_tokens : body.completion_tokens);
  const totalTokens = tokenCount(body.total_tokens);
  if (inputTokens === null || outputTokens === null || totalTokens === null
    || inputTokens + outputTokens !== totalTokens) return null;
  return { inputTokens, outputTokens, totalTokens };
}

/**
 * Streaming JSON scanner that retains only a bounded `usage` object. It never
 * buffers provider prompt/response content and works for both JSON responses
 * and `data: {...}` SSE frames, including arbitrary UTF-8 chunk boundaries.
 */
export interface OpenAiUsageMeterOptions {
  allowResponseEnvelope?: boolean;
}

type TrustedUsageKey = 'usage' | 'response';

export class OpenAiUsageMeter {
  readonly #decoder = new TextDecoder('utf-8', { fatal: true });
  readonly #encoder = new TextEncoder();
  readonly #allowResponseEnvelope: boolean;
  #inString = false;
  #escaped = false;
  #string = '';
  #stringOverflow = false;
  #pendingKey: TrustedUsageKey | null = null;
  #waitingValueFor: TrustedUsageKey | null = null;
  #objectDepth = 0;
  #responseObjectDepth: number | null = null;
  #capture: string | null = null;
  #captureDepth = 0;
  #captureInString = false;
  #captureEscaped = false;
  #captureOverflow = false;
  #captureBytes = 0;
  #usage: EdgeModelUsageV1 | null = null;
  #finished = false;

  constructor(options: OpenAiUsageMeterOptions = {}) {
    this.#allowResponseEnvelope = options.allowResponseEnvelope === true;
  }

  push(bytes: Uint8Array): void {
    if (this.#finished) throw new Error('usage meter is already finished');
    this.#scan(this.#decoder.decode(bytes, { stream: true }));
  }

  finish(): EdgeModelUsageV1 | null {
    if (this.#finished) return this.#usage;
    this.#finished = true;
    this.#scan(this.#decoder.decode());
    if (this.#captureDepth !== 0 || this.#objectDepth !== 0 || this.#inString) {
      this.#usage = null;
    }
    return this.#usage;
  }

  #scan(text: string): void {
    for (const character of text) this.#character(character);
  }

  #character(character: string): void {
    if (this.#captureDepth > 0) {
      if (!this.#captureOverflow) {
        this.#capture += character;
        this.#captureBytes += this.#encoder.encode(character).byteLength;
        if (this.#captureBytes > MAX_USAGE_OBJECT_BYTES) {
          this.#capture = null;
          this.#captureOverflow = true;
        }
      }
      if (this.#captureInString) {
        if (this.#captureEscaped) this.#captureEscaped = false;
        else if (character === '\\') this.#captureEscaped = true;
        else if (character === '"') this.#captureInString = false;
      } else if (character === '"') {
        this.#captureInString = true;
      } else if (character === '{') {
        this.#captureDepth += 1;
      } else if (character === '}') {
        this.#captureDepth -= 1;
        if (this.#captureDepth === 0) this.#completeCapture();
      }
      return;
    }

    if (this.#waitingValueFor) {
      if (/\s/u.test(character)) return;
      const valueFor = this.#waitingValueFor;
      this.#waitingValueFor = null;
      if (character === '{') {
        if (valueFor === 'usage') this.#startCapture();
        else {
          this.#objectDepth += 1;
          this.#responseObjectDepth = this.#objectDepth;
        }
      } else this.#structuralCharacter(character);
      return;
    }

    if (this.#pendingKey) {
      if (/\s/u.test(character)) return;
      const pending = this.#pendingKey;
      this.#pendingKey = null;
      if (character === ':') this.#waitingValueFor = pending;
      else this.#structuralCharacter(character);
      return;
    }

    if (this.#inString) {
      if (this.#escaped) {
        this.#escaped = false;
        this.#stringOverflow = true;
      } else if (character === '\\') {
        this.#escaped = true;
      } else if (character === '"') {
        this.#inString = false;
        this.#pendingKey = this.#trustedKey(
          this.#stringOverflow ? '' : this.#string,
        );
      } else if (!this.#stringOverflow) {
        if (this.#string.length < 32) this.#string += character;
        else this.#stringOverflow = true;
      }
      return;
    }

    this.#structuralCharacter(character);
  }

  #trustedKey(value: string): TrustedUsageKey | null {
    if (value === 'usage'
      && (this.#objectDepth === 1
        || (this.#allowResponseEnvelope
          && this.#responseObjectDepth === this.#objectDepth))) {
      return 'usage';
    }
    if (value === 'response' && this.#allowResponseEnvelope && this.#objectDepth === 1) {
      return 'response';
    }
    return null;
  }

  #structuralCharacter(character: string): void {
    if (character === '"') {
      this.#inString = true;
      this.#escaped = false;
      this.#string = '';
      this.#stringOverflow = false;
      return;
    }
    if (character === '{') {
      this.#objectDepth += 1;
      return;
    }
    if (character === '}' && this.#objectDepth > 0) {
      const closingDepth = this.#objectDepth;
      this.#objectDepth -= 1;
      if (this.#responseObjectDepth === closingDepth) this.#responseObjectDepth = null;
    }
  }

  #startCapture(): void {
    this.#capture = '{';
    this.#captureDepth = 1;
    this.#captureInString = false;
    this.#captureEscaped = false;
    this.#captureOverflow = false;
    this.#captureBytes = 1;
  }

  #completeCapture(): void {
    if (!this.#captureOverflow && this.#capture !== null) {
      try {
        const normalized = normalizeUsage(
          JSON.parse(this.#capture) as Record<string, unknown>,
        );
        if (normalized) this.#usage = normalized;
      } catch {
        // A malformed provider usage object is unavailable, never partially trusted.
      }
    }
    this.#capture = null;
    this.#captureInString = false;
    this.#captureEscaped = false;
    this.#captureOverflow = false;
    this.#captureBytes = 0;
  }
}
