export interface OttoTelemetryEvent {
  id: string;
  organizationId: string | null;
  eventType: string;
  createdAtMs: number;
  payload: Record<string, unknown>;
  integrity: string;
}

export interface OttoTelemetryBatch {
  version: 1;
  deploymentId: string;
  machineFingerprint: string;
  licenseId: string;
  events: OttoTelemetryEvent[];
}

export interface OttoTelemetryReceipt {
  accepted: number;
  duplicates: number;
}

export interface TelemetryRequestAuthentication {
  authorization: string | undefined;
  timestamp: string | undefined;
  nonce: string | undefined;
  signature: string | undefined;
}

export interface DeploymentTelemetrySummary {
  deploymentId: string;
  since: string;
  totalEvents: number;
  lastSeenAt: string | null;
  eventCounts: Record<string, number>;
  latestRuntimeHealth: {
    createdAt: string;
    receivedAt: string;
    payload: Record<string, unknown>;
  } | null;
}
