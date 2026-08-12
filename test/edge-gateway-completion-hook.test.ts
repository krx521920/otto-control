import { describe, expect, it, vi } from 'vitest';

import {
  createOnceEdgeCompletionHook,
  runEdgeCompletionHook,
} from '../src/edge-gateway/completion-hook.js';

describe('edge gateway completion hooks', () => {
  it('runs a healthy completion hook', () => {
    const hook = vi.fn();
    runEdgeCompletionHook(hook);
    expect(hook).toHaveBeenCalledOnce();
  });

  it('contains a completion hook failure', () => {
    const hook = vi.fn(() => { throw new Error('completion backend unavailable'); });
    expect(() => runEdgeCompletionHook(hook)).not.toThrow();
    expect(hook).toHaveBeenCalledOnce();
  });

  it('runs an idempotent completion hook at most once even when it fails', () => {
    const hook = vi.fn(() => { throw new Error('completion backend unavailable'); });
    const complete = createOnceEdgeCompletionHook(hook);

    expect(() => complete()).not.toThrow();
    expect(() => complete()).not.toThrow();
    expect(() => complete()).not.toThrow();
    expect(hook).toHaveBeenCalledOnce();
  });
});
