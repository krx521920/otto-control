export interface EdgeUpstreamResponseLimits {
  maximumBytes: number;
  maximumDurationMs: number;
}

export function defaultEdgeUpstreamResponseLimits(): EdgeUpstreamResponseLimits {
  return { maximumBytes: 67_108_864, maximumDurationMs: 900_000 };
}

function boundedInteger(value: unknown, name: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return Number(value);
}

function environmentInteger(
  name: string,
  environment: NodeJS.ProcessEnv,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const raw = environment[name]?.trim();
  return boundedInteger(raw ? Number(raw) : fallback, name, minimum, maximum);
}

export function normalizeEdgeUpstreamResponseLimits(
  limits: EdgeUpstreamResponseLimits = defaultEdgeUpstreamResponseLimits(),
): EdgeUpstreamResponseLimits {
  return {
    maximumBytes: boundedInteger(
      limits.maximumBytes,
      'edge upstream maximum response bytes',
      1_024,
      256 * 1_024 * 1_024,
    ),
    maximumDurationMs: boundedInteger(
      limits.maximumDurationMs,
      'edge upstream maximum response duration',
      1_000,
      60 * 60 * 1_000,
    ),
  };
}

export function loadEdgeUpstreamResponseLimits(
  environment: NodeJS.ProcessEnv = process.env,
): EdgeUpstreamResponseLimits {
  const defaults = defaultEdgeUpstreamResponseLimits();
  return normalizeEdgeUpstreamResponseLimits({
    maximumBytes: environmentInteger(
      'OTTO_EDGE_UPSTREAM_MAX_RESPONSE_BYTES',
      environment,
      defaults.maximumBytes,
      1_024,
      256 * 1_024 * 1_024,
    ),
    maximumDurationMs: environmentInteger(
      'OTTO_EDGE_UPSTREAM_MAX_RESPONSE_DURATION_MS',
      environment,
      defaults.maximumDurationMs,
      1_000,
      60 * 60 * 1_000,
    ),
  });
}
