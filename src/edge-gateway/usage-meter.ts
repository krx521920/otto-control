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
export class OpenAiUsageMeter {
  readonly #decoder = new TextDecoder('utf-8', { fatal: true });
  readonly #encoder = new TextEncoder();
  #inString = false;
  #escaped = false;
  #string = '';
  #stringOverflow = false;
  #pendingUsageKey = false;
  #waitingUsageValue = false;
  #capture: string | null = null;
  #captureDepth = 0;
  #captureInString = false;
  #captureEscaped = false;
  #captureOverflow = false;
  #captureBytes = 0;
  #usage: EdgeModelUsageV1 | null = null;
  #finished = false;

  push(bytes: Uint8Array): void {
    if (this.#finished) throw new Error('usage meter is already finished');
    this.#scan(this.#decoder.decode(bytes, { stream: true }));
  }

  finish(): EdgeModelUsageV1 | null {
    if (this.#finished) return this.#usage;
    this.#finished = true;
    this.#scan(this.#decoder.decode());
    return this.#captureDepth === 0 ? this.#usage : null;
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
    if (this.#waitingUsageValue) {
      if (/\s/u.test(character)) return;
      this.#waitingUsageValue = false;
      if (character === '{') this.#startCapture();
      return;
    }
    if (this.#pendingUsageKey) {
      if (/\s/u.test(character)) return;
      this.#pendingUsageKey = false;
      if (character === ':') this.#waitingUsageValue = true;
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
        this.#pendingUsageKey = !this.#stringOverflow && this.#string === 'usage';
      } else if (!this.#stringOverflow) {
        if (this.#string.length < 32) this.#string += character;
        else this.#stringOverflow = true;
      }
      return;
    }
    if (character === '"') {
      this.#inString = true;
      this.#escaped = false;
      this.#string = '';
      this.#stringOverflow = false;
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
