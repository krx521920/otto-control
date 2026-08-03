export interface ExpectedSigningAuditEvent {
  action: string;
  targetType: string;
  targetId: string;
}

export interface SigningAuditEvidence {
  verified: true;
  events: Array<{
    id: number;
    action: string;
    targetType: string;
    targetId: string;
    chainSequence: number;
    eventHash: string;
    createdAt: string;
  }>;
  integrity: {
    checkedEvents: number;
    lastSequence: number;
    headHash: string;
    signingKeyId: string;
    signatureSha256: string;
    generatedAt: string;
  };
}

export function collectSigningAuditEvidence(input: {
  controlUrl: URL;
  auditorToken: string;
  startedAt: string;
  expectedEvents: ExpectedSigningAuditEvent[];
}): Promise<SigningAuditEvidence>;
