export type BackupOffsiteStatus = 'disabled' | 'verified' | 'failed';
export type BackupHealthStatus = 'healthy' | 'degraded' | 'failed' | 'missing' | 'not_configured';

export interface BackupRunReport {
  version: 1;
  backup: {
    name: string;
    sha256: string;
    sizeBytes: number;
    createdAt: string;
    localVerifiedAt: string;
  };
  offsite: {
    status: BackupOffsiteStatus;
    required: boolean;
    target: {
      provider: 's3';
      endpoint: string;
      bucket: string;
      prefix: string;
      addressingStyle: 'path' | 'virtual';
    } | null;
    objects: string[];
    attempts: number;
    verifiedAt: string | null;
    error: string | null;
  };
  recordedAt: string;
}

export interface BackupStatusAlert {
  severity: 'warning' | 'critical';
  code: string;
  message: string;
}

export interface BackupInventoryStatus {
  status: BackupHealthStatus;
  reason: string;
  maximumAgeHours: number;
  ageHours: number | null;
  latest: BackupRunReport | null;
  history: BackupRunReport[];
  invalidHistoryCount: number;
  alerts: BackupStatusAlert[];
  checkedAt: string;
}
