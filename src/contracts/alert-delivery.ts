export type AlertSeverity = 'warning' | 'critical';
export type AlertDeliveryStatus = 'pending' | 'delivering' | 'retrying' | 'delivered' | 'failed';

export interface AlertDeliveryPayload {
  version: 1;
  eventId: string;
  eventType: 'backup.recovery.alert';
  source: 'backup_status';
  severity: AlertSeverity;
  fingerprint: string;
  observedAt: string;
  condition: {
    status: string;
    reason: string;
    ageHours: number | null;
    backupName: string | null;
    backupRecordedAt: string | null;
    alerts: Array<{ severity: AlertSeverity; code: string; message: string }>;
  };
}

export interface AlertDeliveryRecord {
  id: string;
  source: 'backup_status';
  eventType: 'backup.recovery.alert';
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
  processed: number;
  delivered: number;
  retrying: number;
  failed: number;
}
