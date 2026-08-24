import type { SignedExecutionReceiptV2 } from '../contracts/billing.js';
import type {
  EdgeGatewayEndpoint,
  EdgeModelUsageV1,
} from '../contracts/edge-gateway.js';

export interface EdgeBillingReservation {
  reservationId: string;
}

export interface EdgeBillingRequestIdentity {
  requestId: string;
  tokenId: string;
  deploymentId: string;
  organizationId: string;
  subjectId: string;
  endpoint: EdgeGatewayEndpoint;
  publicModel: string;
  policyVersion: string;
}

export interface EdgeBillingReservationRequest extends EdgeBillingRequestIdentity {
  reserveUnits: number;
  recoveringNotSentRequest?: boolean;
}

export interface EdgeBillingSettlementRequest extends EdgeBillingRequestIdentity {
  reservation: EdgeBillingReservation;
  routeId: string;
  usage: EdgeModelUsageV1;
  occurredAtMs: number;
  /** Shared outbox callers provide their PostgreSQL-allocated receipt sequence. */
  sequence?: number;
}

export type EdgeBillingReleaseReason =
  | 'no_usable_route'
  | 'unmetered_route'
  | 'upstream_rejected'
  | 'zero_usage';

export interface EdgeBillingReleaseRequest extends EdgeBillingRequestIdentity {
  reservation: EdgeBillingReservation;
  reason: EdgeBillingReleaseReason;
  occurredAtMs: number;
}

export type EdgeBillingUncertainReason =
  | 'client_cancelled'
  | 'provider_error'
  | 'response_limit_exceeded'
  | 'stream_timed_out'
  | 'usage_unavailable';

export interface EdgeBillingUncertainRequest extends EdgeBillingRequestIdentity {
  reservation: EdgeBillingReservation;
  routeId: string;
  reason: EdgeBillingUncertainReason;
  occurredAtMs: number;
}

export type EdgeBillingOutboxAction =
  | { type: 'settle'; request: EdgeBillingSettlementRequest }
  | { type: 'release'; request: EdgeBillingReleaseRequest }
  | { type: 'uncertain'; request: EdgeBillingUncertainRequest };
export interface PreparedEdgeBillingSettlementDelivery {
  version: 1;
  action: 'settle';
  requestId: string;
  reservationId: string;
  occurredAtMs: number;
  sequence: number;
  path: string;
  body:
    | {
        licenseId: string;
        machineFingerprint: string;
        envelope: SignedExecutionReceiptV2;
      }
    | {
        licenseId: string;
        deploymentId: string;
        organizationId: string;
        machineFingerprint: string;
        eventId: string;
        nodeId: string;
        nodeSequence: number;
        holdId: string;
        envelope: SignedExecutionReceiptV2;
      };
}

export interface PreparedEdgeBillingReleaseDelivery {
  version: 1;
  action: 'release';
  requestId: string;
  reservationId: string;
  occurredAtMs: number;
  reason: EdgeBillingReleaseReason;
  path: string;
  body: {
    licenseId: string;
    deploymentId: string;
    organizationId: string;
    machineFingerprint: string;
    idempotencyKey: string;
  };
}

export interface PreparedEdgeBillingUncertainDelivery {
  version: 1;
  action: 'uncertain';
  requestId: string;
  reservationId: string;
  routeId: string;
  reason: EdgeBillingUncertainReason;
  occurredAtMs: number;
}

export type PreparedEdgeBillingDelivery =
  | PreparedEdgeBillingSettlementDelivery
  | PreparedEdgeBillingReleaseDelivery
  | PreparedEdgeBillingUncertainDelivery;

export type EdgeBillingOperationalState = 'ready' | 'degraded' | 'unavailable';

export interface EdgeBillingOperationalStatus {
  state: EdgeBillingOperationalState;
  activeReservations: number;
  recoveredReservations: number;
  pendingSettlements: number;
  pendingReleases: number;
  uncertainReservations: number;
  journalEntries: number;
  lastReceiptSequence: number;
}

/**
 * The implementation must durably persist settle/release/uncertain operations
 * before resolving. A gateway response can finish after the client disconnects,
 * so an in-memory-only implementation is not production safe.
 */
export interface EdgeBillingCoordinator {
  reserve(request: EdgeBillingReservationRequest): Promise<EdgeBillingReservation>;
  settle(request: EdgeBillingSettlementRequest): Promise<void>;
  release(request: EdgeBillingReleaseRequest): Promise<void>;
  markUncertain(request: EdgeBillingUncertainRequest): Promise<void>;
  prepareSettlementDelivery?(
    request: EdgeBillingSettlementRequest,
    sequence: number,
  ): Promise<PreparedEdgeBillingSettlementDelivery>;
  prepareReleaseDelivery?(
    request: EdgeBillingReleaseRequest,
  ): PreparedEdgeBillingReleaseDelivery;
  prepareUncertainDelivery?(
    request: EdgeBillingUncertainRequest,
  ): PreparedEdgeBillingUncertainDelivery;
  deliverPrepared?(
    delivery: PreparedEdgeBillingDelivery,
  ): Promise<void>;
  operationalStatus?(): EdgeBillingOperationalStatus;
  flushPending?(): Promise<void>;
}

export type EdgeBillingAdmissionCode =
  | 'EDGE_CREDIT_REQUIRED'
  | 'EDGE_REQUEST_REPLAYED'
  | 'EDGE_BILLING_UNAVAILABLE';

export class EdgeBillingAdmissionError extends Error {
  constructor(
    readonly status: 402 | 409 | 503,
    readonly code: EdgeBillingAdmissionCode,
    message: string,
  ) {
    super(message);
    this.name = 'EdgeBillingAdmissionError';
  }
}
