export interface DatabasePoolSnapshot {
  totalConnections: number;
  idleConnections: number;
  waitingRequests: number;
  errorsTotal: number;
  maximumConnections: number;
}

export interface DatabaseRelationCapacity {
  bytes: number;
  estimatedRows: number;
}

export interface DatabaseCapacitySnapshot {
  sampledAtMs: number;
  databaseBytes: number;
  relations: Record<string, DatabaseRelationCapacity>;
}

export interface DatabaseObservabilitySource {
  poolSnapshot(): DatabasePoolSnapshot;
  sampleCapacity(): Promise<DatabaseCapacitySnapshot>;
}
