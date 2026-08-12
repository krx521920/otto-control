import { describe, expect, it } from 'vitest';

import { OpenAiUsageMeter } from '../src/edge-gateway/usage-meter.js';

const encoder = new TextEncoder();

function measure(parts: Array<string | Uint8Array>) {
  const meter = new OpenAiUsageMeter();
  for (const part of parts) meter.push(typeof part === 'string' ? encoder.encode(part) : part);
  return meter.finish();
}

describe('OpenAI-compatible streaming usage meter', () => {
  it('extracts chat completion usage across arbitrary chunks without retaining content', () => {
    const body = JSON.stringify({
      choices: [{ message: { content: 'private reply' } }],
      usage: {
        prompt_tokens: 17,
        completion_tokens: 5,
        total_tokens: 22,
        prompt_tokens_details: { cached_tokens: 3 },
      },
    });
    const bytes = encoder.encode(body);
    const meter = new OpenAiUsageMeter();
    for (const byte of bytes) meter.push(Uint8Array.of(byte));

    expect(meter.finish()).toEqual({ inputTokens: 17, outputTokens: 5, totalTokens: 22 });
    expect(meter.finish()).toEqual({ inputTokens: 17, outputTokens: 5, totalTokens: 22 });
  });

  it('accepts usage as the first property with whitespace around the separator', () => {
    expect(measure([
      '{"usage" \r\n : \t {"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}',
    ])).toEqual({ inputTokens: 2, outputTokens: 3, totalTokens: 5 });
  });

  it('ignores interim null usage and extracts the final SSE usage frame', () => {
    expect(measure([
      'data: {"choices":[{"delta":{"content":"private"}}],"usage":null}\n\n',
      'data: {"choices":[],"usage":{"prompt_tokens":12,',
      '"completion_tokens":4,"total_tokens":16}}\n\n',
      'data: [DONE]\n\n',
    ])).toEqual({ inputTokens: 12, outputTokens: 4, totalTokens: 16 });
  });

  it('normalizes Responses API token names and UTF-8 chunk boundaries', () => {
    const bytes = encoder.encode(JSON.stringify({
      output: [{ content: [{ text: '机密内容' }] }],
      usage: { input_tokens: 101, output_tokens: 9, total_tokens: 110 },
    }));
    const splitInsideMultibyteCharacter = bytes.findIndex((value) => value >= 0x80) + 1;
    expect(measure([
      bytes.slice(0, splitInsideMultibyteCharacter),
      bytes.slice(splitInsideMultibyteCharacter),
    ])).toEqual({ inputTokens: 101, outputTokens: 9, totalTokens: 110 });
  });

  it('does not treat escaped JSON embedded in model content as provider usage', () => {
    expect(measure([JSON.stringify({
      choices: [{ message: { content: '{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}' } }],
    })])).toBeNull();
  });

  it('does not treat a string value named usage as a key for the following object', () => {
    expect(measure([JSON.stringify({
      labels: [
        'usage',
        { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 },
      ],
    })])).toBeNull();
  });

  it('tracks braces, quotes, and escapes inside nested usage detail strings', () => {
    expect(measure([JSON.stringify({
      usage: {
        prompt_tokens: 8,
        completion_tokens: 2,
        total_tokens: 10,
        details: { provider: 'text with } { and an escaped "quote" plus \\\\ slash' },
      },
    })])).toEqual({ inputTokens: 8, outputTokens: 2, totalTokens: 10 });
  });

  it('keeps the last valid usage when a later candidate is malformed', () => {
    expect(measure([
      '{"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5},',
      '"metadata":{"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":99}}}',
    ])).toEqual({ inputTokens: 4, outputTokens: 1, totalTokens: 5 });
  });

  it.each([
    { prompt_tokens: 1, completion_tokens: 2, total_tokens: 4 },
    { prompt_tokens: -1, completion_tokens: 2, total_tokens: 1 },
    { prompt_tokens: 1.5, completion_tokens: 2, total_tokens: 3.5 },
    { prompt_tokens: 9_000_000_000_001, completion_tokens: 0, total_tokens: 9_000_000_000_001 },
    { prompt_tokens: 1, completion_tokens: 2 },
    { prompt_tokens: 1, total_tokens: 1 },
    { completion_tokens: 1, total_tokens: 1 },
    { prompt_tokens: 1, completion_tokens: 0, total_tokens: null },
    { input_tokens: 1, completion_tokens: 2, total_tokens: 3 },
  ])('rejects inconsistent or untrusted usage values: $prompt_tokens', (usage) => {
    expect(measure([JSON.stringify({ usage })])).toBeNull();
  });

  it('accepts the exact maximum trusted token count', () => {
    expect(measure([JSON.stringify({
      usage: {
        prompt_tokens: 9_000_000_000_000,
        completion_tokens: 0,
        total_tokens: 9_000_000_000_000,
      },
    })])).toEqual({
      inputTokens: 9_000_000_000_000,
      outputTokens: 0,
      totalTokens: 9_000_000_000_000,
    });
  });

  it('rejects incomplete and oversized usage objects', () => {
    expect(measure(['{"usage":{"prompt_tokens":1'])).toBeNull();
    expect(measure([JSON.stringify({
      usage: {
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
        details: 'x'.repeat(17 * 1024),
      },
    })])).toBeNull();
  });

  it('accepts exactly 16 KiB and rejects the first byte beyond the capture limit', () => {
    const base = {
      prompt_tokens: 1,
      completion_tokens: 1,
      total_tokens: 2,
      details: '',
    };
    const baseBytes = encoder.encode(JSON.stringify(base)).byteLength;
    const exact = { ...base, details: 'x'.repeat(16 * 1024 - baseBytes) };
    expect(encoder.encode(JSON.stringify(exact))).toHaveLength(16 * 1024);
    expect(measure([JSON.stringify({ usage: exact })])).toEqual({
      inputTokens: 1, outputTokens: 1, totalTokens: 2,
    });
    expect(measure([JSON.stringify({
      usage: { ...exact, details: `${exact.details}x` },
    })])).toBeNull();
  });

  it('discards earlier valid usage if a later usage object is truncated', () => {
    expect(measure([
      '{"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5},',
      '"later":{"usage":{"prompt_tokens":9',
    ])).toBeNull();
  });

  it('fails closed on malformed UTF-8 and rejects writes after completion', () => {
    const meter = new OpenAiUsageMeter();
    expect(() => meter.push(Uint8Array.of(0xff))).toThrow();

    const completed = new OpenAiUsageMeter();
    completed.push(encoder.encode('{"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}'));
    expect(completed.finish()).toEqual({ inputTokens: 0, outputTokens: 0, totalTokens: 0 });
    expect(() => completed.push(encoder.encode('{}'))).toThrow('already finished');
  });
});
