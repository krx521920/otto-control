export interface EdgeConcurrencySnapshot {
  activeRequests: number;
  globalLimit: number;
  trackedSubjects: number;
  subjectsAtLimit: number;
  perSubjectLimit: number;
}

export interface EdgeConcurrencyLease {
  release(): void;
}

export interface EdgeConcurrencyLimiter {
  acquire(subjectKey: string): EdgeConcurrencyLease | null;
  snapshot(): EdgeConcurrencySnapshot;
}

function positiveLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
    throw new Error(`${name} must be an integer between 1 and 1000000`);
  }
  return value;
}

/**
 * Process-local admission guard for the supported single-Node deployment.
 * A lease remains active until the downstream response stream terminates, so
 * slow streams consume capacity just like requests that have not received
 * response headers yet.
 */
export class InMemoryEdgeConcurrencyLimiter implements EdgeConcurrencyLimiter {
  readonly #globalLimit: number;
  readonly #perSubjectLimit: number;
  readonly #subjects = new Map<string, number>();
  #activeRequests = 0;

  constructor(globalLimit = 256, perSubjectLimit = 8) {
    this.#globalLimit = positiveLimit(globalLimit, 'global concurrency limit');
    this.#perSubjectLimit = positiveLimit(perSubjectLimit, 'per-subject concurrency limit');
    if (this.#perSubjectLimit > this.#globalLimit) {
      throw new Error('per-subject concurrency limit cannot exceed the global limit');
    }
  }

  acquire(subjectKey: string): EdgeConcurrencyLease | null {
    if (!subjectKey || subjectKey.length > 1_024) {
      throw new Error('concurrency subject key must contain 1 to 1024 characters');
    }
    const subjectActive = this.#subjects.get(subjectKey) ?? 0;
    if (this.#activeRequests >= this.#globalLimit
      || subjectActive >= this.#perSubjectLimit) return null;
    this.#activeRequests += 1;
    this.#subjects.set(subjectKey, subjectActive + 1);
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        const current = this.#subjects.get(subjectKey)!;
        this.#activeRequests -= 1;
        if (current === 1) this.#subjects.delete(subjectKey);
        else this.#subjects.set(subjectKey, current - 1);
      },
    };
  }

  snapshot(): EdgeConcurrencySnapshot {
    let subjectsAtLimit = 0;
    for (const active of this.#subjects.values()) {
      if (active >= this.#perSubjectLimit) subjectsAtLimit += 1;
    }
    return {
      activeRequests: this.#activeRequests,
      globalLimit: this.#globalLimit,
      trackedSubjects: this.#subjects.size,
      subjectsAtLimit,
      perSubjectLimit: this.#perSubjectLimit,
    };
  }
}
