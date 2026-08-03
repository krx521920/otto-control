export type AlertSeverity = 'warning' | 'critical';
export type AlertDeliveryStatus = 'pending' | 'delivering' | 'retrying' | 'delivered' | 'failed';
export type AlertSource = 'backup_status' | 'audit_integrity' | 'audit_witness';
export type AlertEventType =
  | 'backup.recovery.alert'
  | 'audit.integrity.alert'
  | 'audit.witness.alert';

export interface AlertDeliveryPayload {
  version: 1;
  eventId: string;
  eventType: AlertEventType;
  source: AlertSource;
  severity: AlertSeverity;
  fingerprint: string;
  observedAt: string;
  condition: {
    status: string;
    reason: string;
    ageHours: number | null;
    backupName: string | null;
    backupRecordedAt: string | null;
    chainSequence?: number | null;
    brokenAtSequence?: number | null;
    pendingCount?: number | null;
    failedCount?: number | null;
    alerts: Array<{ severity: AlertSeverity; code: string; message: string }>;
  };
}

export interface AlertDeliveryRecord {
  id: string;
  channelId: string;
  source: AlertSource;
  eventType: AlertEventType;
  fingerprint: string;
  severity: AlertSeverity;
  payload: AlertDeliveryPayload;
  status: AlertDeliveryStatus;
  attempts: number;
  nextAttemptAt: Date;
  leaseUntil: Date | null;
  lastError: string | null;
  deliveredAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface AlertDeliveryView extends Omit<
  AlertDeliveryRecord,
  'nextAttemptAt' | 'leaseUntil' | 'deliveredAt' | 'createdAt' | 'updatedAt'
> {
  nextAttemptAt: string;
  leaseUntil: string | null;
  deliveredAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AlertPollResult {
  enabled: boolean;
  observedStatus: string | null;
  enqueued: boolean;
  enqueuedCount: number;
  processed: number;
  delivered: number;
  retrying: number;
  failed: number;
}
