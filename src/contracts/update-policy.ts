export const UPDATE_CHANNELS = ['canary', 'stable', 'required'] as const;
export type UpdateChannel = (typeof UPDATE_CHANNELS)[number];

export const UPDATE_RELEASE_STATES = ['draft', 'active', 'paused', 'rolled_back'] as const;
export type UpdateReleaseState = (typeof UPDATE_RELEASE_STATES)[number];

export interface UpdateManifestReference {
  url: string;
  sha256: string;
}

export interface OttoUpdatePolicyPayload {
  version: 1;
  deploymentId: string;
  distributionId: string;
  currentVersion: string;
  decision: 'update' | 'none';
  reason: 'update_available' | 'up_to_date' | 'outside_rollout' | 'no_active_release';
  release: {
    id: string;
    version: string;
    sourceCommit: string;
    channel: UpdateChannel;
    mandatory: boolean;
    rolloutPercent: number;
    notes: string;
    fullManifest: UpdateManifestReference | null;
    incrementalManifest: UpdateManifestReference | null;
    publishedAt: string;
  } | null;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface OttoSignedUpdatePolicyEnvelope {
  policy: OttoUpdatePolicyPayload;
  signingKeyId: string;
  signature: string;
}
