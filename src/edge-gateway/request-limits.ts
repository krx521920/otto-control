export interface EdgeRequestLimits {
  maximumBytes: number;
}

const MINIMUM_REQUEST_BYTES = 1_024;
const MAXIMUM_REQUEST_BYTES = 20_971_520;

export function defaultEdgeRequestLimits(): EdgeRequestLimits {
  return { maximumBytes: 4 * 1_024 * 1_024 };
}

function boundedRequestBytes(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value)
    || Number(value) < MINIMUM_REQUEST_BYTES
    || Number(value) > MAXIMUM_REQUEST_BYTES) {
    throw new Error(
      `${name} must be an integer between ${MINIMUM_REQUEST_BYTES} and ${MAXIMUM_REQUEST_BYTES}`,
    );
  }
  return Number(value);
}

export function normalizeEdgeRequestLimits(
  limits: EdgeRequestLimits = defaultEdgeRequestLimits(),
): EdgeRequestLimits {
  return {
    maximumBytes: boundedRequestBytes(
      limits.maximumBytes,
      'edge maximum request bytes',
    ),
  };
}

export function loadEdgeRequestLimits(
  environment: NodeJS.ProcessEnv = process.env,
): EdgeRequestLimits {
  const raw = environment.OTTO_EDGE_MAX_REQUEST_BYTES?.trim();
  return normalizeEdgeRequestLimits({
    maximumBytes: raw ? Number(raw) : defaultEdgeRequestLimits().maximumBytes,
  });
}
