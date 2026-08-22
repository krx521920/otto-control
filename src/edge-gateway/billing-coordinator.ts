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
}

export interface EdgeBillingSettlementRequest extends EdgeBillingRequestIdentity {
  reservation: EdgeBillingReservation;
  routeId: string;
  usage: EdgeModelUsageV1;
  occurredAtMs: number;
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
